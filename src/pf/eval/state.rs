//! Evaluation state, verdict formatting and wildcard anchor child lookup.

use std::collections::BTreeSet;
use std::fmt;

use super::super::model::{AnchorName, Construct};
use super::super::{AnchorRulesets, Ruleset, Verdict};

/// A rule's place: its line, and the anchor it is in, if any.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Origin {
    line: usize,
    anchor: Option<String>,
}

impl Origin {
    pub(super) fn new(line: usize, anchor: Option<&AnchorName>) -> Self {
        Self {
            line,
            anchor: anchor.map(|name| name.display().to_string()),
        }
    }
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}", self.line)?;
        match &self.anchor {
            Some(anchor) => write!(f, " of anchor \"{anchor}\""),
            None => Ok(()),
        }
    }
}

/// Why a verdict is in doubt: an unmodeled construct in a rule. The origin
/// comes first so that the earliest rule orders first.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Uncertain {
    pub(super) origin: Origin,
    pub(super) construct: Construct,
}

impl fmt::Display for Uncertain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} in rule at {}", self.construct, self.origin)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Cause {
    Default,
    Skip,
    Rule(Origin),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Outcome {
    Pass(Cause),
    Block(Cause),
    Unknown(Uncertain),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Stop {
    None,
    /// A `quick` anchor call matched at the end of its enclosing anchor;
    /// cleared if unwinding through a non-quick outer anchor.
    Anchor,
    /// A `quick` filter rule, `set skip`, `unknown`, or a `quick` anchor
    /// with following sibling rules ended the entire walk.
    Full,
}

/// One state the packet could be in after the rules read so far.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Path {
    /// Whether evaluation stopped on this path, and how far it unwinds.
    pub(super) stop: Stop,
    /// Whether any rule inside the current evaluation scope matched on this path.
    pub(super) matched: bool,
    pub(super) outcome: Outcome,
    /// The most recent rule that only *might* have put the path here.
    pub(super) uncertain: Option<Uncertain>,
    /// The earliest rule whose TCP flags condition distinguishes bare SYN from
    /// ECN-capable SYN on this path.
    pub(super) ecn_origin: Option<Origin>,
}

pub(super) type Paths = BTreeSet<Path>;

impl Path {
    pub(super) fn is_done(&self) -> bool {
        self.stop != Stop::None
    }

    pub(super) fn tagged(mut self, uncertain: Option<&Uncertain>) -> Self {
        if self.uncertain.is_none() {
            self.uncertain = uncertain.cloned();
        }
        self
    }

    pub(super) fn with_ecn(mut self, origin: Option<&Origin>) -> Self {
        if self.ecn_origin.is_none() {
            self.ecn_origin = origin.cloned();
        }
        self
    }
}

pub(super) fn unknown(construct: Construct, origin: &Origin) -> Paths {
    Paths::from([Path {
        stop: Stop::Full,
        matched: false,
        outcome: Outcome::Unknown(Uncertain {
            construct,
            origin: origin.clone(),
        }),
        uncertain: None,
        ecn_origin: None,
    }])
}

pub(super) fn verdict(paths: &Paths) -> Verdict {
    let unknown_verdict = |reason: String| Verdict::Unknown { reason };
    if let Some(uncertain) = paths.iter().find_map(|path| match &path.outcome {
        Outcome::Unknown(uncertain) => Some(uncertain),
        Outcome::Pass(_) | Outcome::Block(_) => None,
    }) {
        return unknown_verdict(uncertain.to_string());
    }
    // A path that no uncertain rule touched explains the verdict best.
    let first = paths.iter().min_by_key(|path| path.uncertain.is_some());
    let all_pass = paths
        .iter()
        .all(|path| matches!(path.outcome, Outcome::Pass(_)));
    let all_block = paths
        .iter()
        .all(|path| matches!(path.outcome, Outcome::Block(_)));
    match first.map(|path| &path.outcome) {
        Some(Outcome::Pass(cause)) if all_pass => Verdict::Pass {
            reason: describe("pass", cause),
        },
        Some(Outcome::Block(cause)) if all_block => Verdict::Block {
            reason: describe("block", cause),
        },
        _ => unknown_verdict(
            paths
                .iter()
                .filter_map(|path| path.uncertain.as_ref())
                .min()
                .map_or_else(|| "conflicting rules".to_string(), ToString::to_string),
        ),
    }
}

pub(super) fn combine_tcp_verdicts(plain: &Paths, ecn: &Paths) -> Verdict {
    let v_plain = verdict(plain);
    let v_ecn = verdict(ecn);
    match (&v_plain, &v_ecn) {
        (Verdict::Unknown { .. }, _) => v_plain,
        (_, Verdict::Unknown { .. }) => v_ecn,
        (Verdict::Pass { .. }, Verdict::Pass { .. })
        | (Verdict::Block { .. }, Verdict::Block { .. }) => v_plain,
        (Verdict::Pass { .. }, Verdict::Block { .. })
        | (Verdict::Block { .. }, Verdict::Pass { .. }) => {
            let reason = plain
                .iter()
                .chain(ecn.iter())
                .filter_map(|path| path.ecn_origin.as_ref())
                .min()
                .map_or_else(
                    || "tcp flags (ECN) changed verdict".to_string(),
                    |origin| {
                        Uncertain {
                            origin: origin.clone(),
                            construct: Construct::TcpEcnFlags,
                        }
                        .to_string()
                    },
                );
            Verdict::Unknown { reason }
        }
    }
}

/// Returns direct child rulesets for a wildcard anchor (`*` or `prefix/*`),
/// ordered lexicographically as PF evaluates them.
pub(super) fn direct_children<'a>(
    anchors: &'a AnchorRulesets,
    wildcard: &str,
) -> Vec<(&'a str, &'a Ruleset)> {
    if wildcard == "*" {
        return anchors
            .iter()
            .filter(|(key, _)| !key.is_empty() && !key.contains('/') && key.as_str() != "*")
            .map(|(key, rules)| (key.as_str(), rules))
            .collect();
    }
    let Some(prefix) = wildcard.strip_suffix('*') else {
        return Vec::new();
    };
    anchors
        .iter()
        .filter_map(|(key, rules)| {
            let rest = key.strip_prefix(prefix)?;
            (!rest.is_empty() && !rest.contains('/') && rest != "*")
                .then_some((key.as_str(), rules))
        })
        .collect()
}

fn describe(action: &str, cause: &Cause) -> String {
    match cause {
        Cause::Default => "no rule matched, and pf passes by default".to_string(),
        Cause::Skip => "the interface is excluded by set skip".to_string(),
        Cause::Rule(origin) => format!("matched {action} rule at {origin}"),
    }
}
