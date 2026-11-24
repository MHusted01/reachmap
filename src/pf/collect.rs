//! Bounded collection protocol for macOS `pfctl` status, rules, interfaces,
//! and anchors.
//!
//! Pure and cross-platform: [`collect_with`] drives any [`PfRunner`] so both
//! live `/sbin/pfctl` collection and unit tests over recorded fixtures run the
//! same parser, validation, and resource limits.

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use thiserror::Error;

use crate::collect::CollectError;
use crate::errors::render_chain;
use crate::sanitize::sanitize;

use super::model::is_group_name;
use super::{AnchorRulesets, Ruleset};

/// Timeout for each individual `/sbin/pfctl` invocation.
pub(crate) const PFCTL_TIMEOUT: Duration = Duration::from_secs(3);

/// Total time budget across all `pfctl` calls for one scan.
const PF_TOTAL_TIMEOUT: Duration = Duration::from_secs(10);

/// Stdout/stderr limit for `pfctl -s info`.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) const PFCTL_INFO_LIMIT: (u64, u64) = (64 * 1024, 64 * 1024);

/// Stdout/stderr limit for `pfctl -sr` and `pfctl -a <anchor> -sr`.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) const PFCTL_RULES_LIMIT: (u64, u64) = (512 * 1024, 64 * 1024);

/// Stdout/stderr limit for `pfctl -sA` and `pfctl -a <anchor> -sA`.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) const PFCTL_ANCHORS_LIMIT: (u64, u64) = (128 * 1024, 64 * 1024);

/// Stdout/stderr limit for `pfctl -v -s Interfaces`.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) const PFCTL_IFACES_LIMIT: (u64, u64) = (128 * 1024, 64 * 1024);

/// Combined byte budget across all `pfctl` outputs in one scan.
const PF_MAX_TOTAL_BYTES: usize = 2 * 1024 * 1024;

/// Maximum anchor nesting depth collected from `pfctl -sA`.
const MAX_ANCHOR_DEPTH: usize = 8;

/// Maximum number of distinct anchors collected in one scan.
const MAX_ANCHORS: usize = 64;

/// One read-only `pfctl` query issued by [`collect_with`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PfCommand<'a> {
    /// `pfctl -s info`
    Info,
    /// `pfctl -sr`
    MainRules,
    /// `pfctl -v -s Interfaces`
    Interfaces,
    /// `pfctl -sA`
    RootAnchors,
    /// `pfctl -a <anchor> -sr`
    AnchorRules(&'a str),
    /// `pfctl -a <anchor> -sA`
    AnchorChildren(&'a str),
}

/// Runs one [`PfCommand`] within `timeout` and returns its stdout.
pub trait PfRunner {
    /// Executes `command` with at most `timeout` remaining.
    fn run(&mut self, command: PfCommand<'_>, timeout: Duration) -> Result<String, CollectError>;
}

/// Why `pfctl` collection could not complete.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PfCollectError {
    /// Reading `/dev/pf` failed for lack of root privileges.
    #[error("reading pf status and rules requires root privileges (run with sudo): {detail}")]
    PermissionDenied {
        /// Sanitised cause from `pfctl`.
        detail: String,
    },
    /// One command or the overall pf collection exceeded its time budget.
    #[error("{detail}")]
    TimedOut {
        /// Sanitised timeout message.
        detail: String,
    },
    /// Output from `pfctl` exceeded a single-command or total byte bound.
    #[error("{detail}")]
    OutputTooLarge {
        /// Sanitised size limit message.
        detail: String,
    },
    /// More anchors were listed than the collection bound allows.
    #[error("pf anchor count exceeded the {limit}-anchor limit")]
    AnchorCountLimit {
        /// Maximum anchors collected per scan.
        limit: usize,
    },
    /// Anchor nesting went deeper than the collection bound allows.
    #[error("pf anchor nesting exceeded the {limit}-level limit at \"{anchor}\"")]
    AnchorDepthLimit {
        /// Maximum depth collected per scan.
        limit: usize,
        /// Sanitised anchor path where the limit was hit.
        anchor: String,
    },
    /// `pfctl -sA` returned an anchor path that failed safety validation.
    #[error("pfctl returned an invalid anchor name \"{name}\"")]
    InvalidAnchorName {
        /// Sanitised offending name.
        name: String,
    },
    /// `pfctl -s info` did not contain a recognisable `Status:` line.
    #[error("could not recognise pfctl -s info status output")]
    UnrecognisedInfo,
    /// Any other failure running `pfctl`.
    #[error("{detail}")]
    Command {
        /// Sanitised command error chain.
        detail: String,
    },
}

/// Parsed pf state and ruleset collected in memory (raw text is discarded).
#[derive(Debug)]
pub enum CollectedPf {
    /// pf is disabled and does not filter inbound packets.
    Disabled,
    /// pf is enabled and its main ruleset and anchors were parsed.
    Enabled {
        /// Parsed main ruleset with concrete `set skip` interfaces merged in.
        rules: Ruleset,
        /// Parsed rulesets for all listed anchors and wildcard completeness markers.
        anchors: AnchorRulesets,
        /// Interface and group names returned by `pfctl -v -s Interfaces`.
        listed_interfaces: BTreeSet<String>,
        /// Interface group names marked `(skip)` by `pfctl -v -s Interfaces`.
        skipped_groups: BTreeSet<String>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PfStatus {
    Enabled,
    Disabled,
}

struct Collector<'a, R: PfRunner> {
    runner: &'a mut R,
    deadline: Instant,
    total_bytes: usize,
}

impl<R: PfRunner> Collector<'_, R> {
    fn run_checked(&mut self, command: PfCommand<'_>) -> Result<String, PfCollectError> {
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(PfCollectError::TimedOut {
                detail: format!(
                    "pf collection did not finish within {}s",
                    PF_TOTAL_TIMEOUT.as_secs()
                ),
            });
        }
        let timeout = remaining.min(PFCTL_TIMEOUT);
        let output = self
            .runner
            .run(command, timeout)
            .map_err(map_collect_error)?;
        self.total_bytes = self.total_bytes.saturating_add(output.len());
        if self.total_bytes > PF_MAX_TOTAL_BYTES {
            return Err(PfCollectError::OutputTooLarge {
                detail: format!("pfctl output exceeded the {PF_MAX_TOTAL_BYTES}-byte total limit"),
            });
        }
        Ok(output)
    }

    fn collect_anchor_tree(
        &mut self,
        anchors: &mut AnchorRulesets,
        visited: &mut BTreeSet<String>,
        path: &str,
        depth: usize,
    ) -> Result<(), PfCollectError> {
        let effective_depth = depth.max(path.split('/').count());
        if effective_depth > MAX_ANCHOR_DEPTH {
            return Err(PfCollectError::AnchorDepthLimit {
                limit: MAX_ANCHOR_DEPTH,
                anchor: sanitize(path),
            });
        }
        if !visited.insert(path.to_owned()) {
            return Ok(());
        }
        if visited.len() > MAX_ANCHORS {
            return Err(PfCollectError::AnchorCountLimit { limit: MAX_ANCHORS });
        }
        let rules_text = self.run_checked(PfCommand::AnchorRules(path))?;
        anchors.insert(path.to_owned(), Ruleset::parse(&rules_text));
        drop(rules_text);

        let children_text = self.run_checked(PfCommand::AnchorChildren(path))?;
        let children = parse_anchors(&children_text, Some(path))?;
        drop(children_text);
        if !children.is_empty() && effective_depth >= MAX_ANCHOR_DEPTH {
            return Err(PfCollectError::AnchorDepthLimit {
                limit: MAX_ANCHOR_DEPTH,
                anchor: sanitize(path),
            });
        }
        for child in children {
            self.collect_anchor_tree(anchors, visited, &child, effective_depth + 1)?;
        }
        anchors.insert(format!("{path}/*"), Ruleset::default());
        Ok(())
    }
}

/// Collects pf status, main rules, skipped interfaces, and listed anchors using
/// `runner`, enforcing time, size, anchor-count, and anchor-depth bounds.
pub fn collect_with(runner: &mut impl PfRunner) -> Result<CollectedPf, PfCollectError> {
    let mut collector = Collector {
        runner,
        deadline: Instant::now() + PF_TOTAL_TIMEOUT,
        total_bytes: 0,
    };
    let info_text = collector.run_checked(PfCommand::Info)?;
    let status = parse_info(&info_text)?;
    drop(info_text);
    if status == PfStatus::Disabled {
        return Ok(CollectedPf::Disabled);
    }

    let rules_text = collector.run_checked(PfCommand::MainRules)?;
    let mut rules = Ruleset::parse(&rules_text);
    drop(rules_text);

    let ifaces_text = collector.run_checked(PfCommand::Interfaces)?;
    let (listed_interfaces, skipped_concrete, skipped_groups) = parse_interfaces(&ifaces_text);
    drop(ifaces_text);
    rules.add_skipped_interfaces(skipped_concrete);

    let root_text = collector.run_checked(PfCommand::RootAnchors)?;
    let root_anchors = parse_anchors(&root_text, None)?;
    drop(root_text);

    let mut anchors = AnchorRulesets::new();
    let mut visited = BTreeSet::new();
    for root in root_anchors {
        collector.collect_anchor_tree(&mut anchors, &mut visited, &root, 1)?;
    }
    anchors.entry("*".to_owned()).or_default();

    Ok(CollectedPf::Enabled {
        rules,
        anchors,
        listed_interfaces,
        skipped_groups,
    })
}

fn map_collect_error(error: CollectError) -> PfCollectError {
    let detail = sanitize(&render_chain(&error));
    match &error {
        CollectError::CommandFailed { stderr, .. } => {
            let lower = stderr.to_ascii_lowercase();
            if lower.contains("permission denied") || lower.contains("operation not permitted") {
                PfCollectError::PermissionDenied { detail }
            } else {
                PfCollectError::Command { detail }
            }
        }
        CollectError::TimedOut { .. } => PfCollectError::TimedOut { detail },
        CollectError::OutputTooLarge { .. } => PfCollectError::OutputTooLarge { detail },
        CollectError::Read { .. }
        | CollectError::UnsupportedOs { .. }
        | CollectError::SockDiag { .. }
        | CollectError::Run { .. }
        | CollectError::NotUtf8 { .. } => PfCollectError::Command { detail },
    }
}

fn parse_info(text: &str) -> Result<PfStatus, PfCollectError> {
    for line in text.lines() {
        let Some(rest) = line.trim_start().strip_prefix("Status:") else {
            continue;
        };
        let Some(word) = rest.split_whitespace().next() else {
            return Err(PfCollectError::UnrecognisedInfo);
        };
        if word.eq_ignore_ascii_case("enabled") {
            return Ok(PfStatus::Enabled);
        }
        if word.eq_ignore_ascii_case("disabled") {
            return Ok(PfStatus::Disabled);
        }
        return Err(PfCollectError::UnrecognisedInfo);
    }
    Err(PfCollectError::UnrecognisedInfo)
}

fn parse_interfaces(text: &str) -> (BTreeSet<String>, BTreeSet<String>, BTreeSet<String>) {
    let mut listed = BTreeSet::new();
    let mut skipped_concrete = BTreeSet::new();
    let mut skipped_groups = BTreeSet::new();
    for line in text.lines() {
        if line.is_empty() || line.starts_with(|ch: char| ch.is_ascii_whitespace()) {
            continue;
        }
        let Some(name) = line.split_whitespace().next() else {
            continue;
        };
        if name.is_empty() || sanitize(name) != name {
            continue;
        }
        listed.insert(name.to_owned());
        let rest = &line[name.len()..];
        let is_skipped = rest
            .split(['(', ')', ',', ' ', '\t'])
            .any(|token| token == "skip");
        if is_skipped {
            if is_group_name(name) {
                skipped_groups.insert(name.to_owned());
            } else {
                skipped_concrete.insert(name.to_owned());
            }
        }
    }
    (listed, skipped_concrete, skipped_groups)
}

fn parse_anchors(text: &str, parent: Option<&str>) -> Result<Vec<String>, PfCollectError> {
    let mut anchors = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let stripped = trimmed.trim_start_matches('/');
        let path = match parent {
            Some(prefix) => {
                if stripped == prefix || stripped.starts_with(&format!("{prefix}/")) {
                    stripped.to_owned()
                } else {
                    format!("{prefix}/{stripped}")
                }
            }
            None => stripped.to_owned(),
        };
        validate_anchor_name(&path)?;
        anchors.push(path);
    }
    Ok(anchors)
}

fn validate_anchor_name(name: &str) -> Result<(), PfCollectError> {
    let invalid = || PfCollectError::InvalidAnchorName {
        name: sanitize(name),
    };
    if name.is_empty()
        || name.starts_with('-')
        || name.contains('*')
        || sanitize(name) != name
        || name
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(invalid());
    }
    Ok(())
}
