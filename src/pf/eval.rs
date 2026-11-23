//! Applying pf's "last matching rule wins, unless it is `quick`" to a packet.
//!
//! A rule can match, not match, or depend on something unmodeled. The walk
//! keeps every state the packet could be in (a *path*) and forks at each rule
//! that might match. The verdict is certain only when all paths agree.

use std::collections::BTreeSet;
use std::fmt;

use super::matching::Match;
use super::model::{Action, AnchorName, Construct, Kind, Ruleset, is_group_name};
use super::{AnchorRulesets, Traffic, Verdict};

/// Anchors may contain anchors. Deeper than this the walk gives up.
const MAX_ANCHOR_DEPTH: usize = 8;

/// A rule's place: its line, and the anchor it is in, if any.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Origin {
    line: usize,
    anchor: Option<String>,
}

impl Origin {
    fn new(line: usize, anchor: Option<&AnchorName>) -> Self {
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
struct Uncertain {
    origin: Origin,
    construct: Construct,
}

impl fmt::Display for Uncertain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} in rule at {}", self.construct, self.origin)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Cause {
    Default,
    Skip,
    Rule(Origin),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Outcome {
    Pass(Cause),
    Block(Cause),
    Unknown(Uncertain),
}

/// One state the packet could be in after the rules read so far.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Path {
    /// A `quick` rule (or `set skip`) ended the walk on this path.
    done: bool,
    /// Whether any rule inside the current evaluation scope matched on this path.
    matched: bool,
    outcome: Outcome,
    /// The most recent rule that only *might* have put the path here.
    uncertain: Option<Uncertain>,
}

type Paths = BTreeSet<Path>;

impl Path {
    fn tagged(mut self, uncertain: Option<&Uncertain>) -> Self {
        if self.uncertain.is_none() {
            self.uncertain = uncertain.cloned();
        }
        self
    }
}

pub(super) fn evaluate(
    rules: &Ruleset,
    anchors: &AnchorRulesets,
    traffic: &Traffic<'_>,
) -> Verdict {
    let walker = Walker { anchors, traffic };
    let start = walker.skipped(rules);
    if start.iter().all(|path| path.done) {
        return verdict(&start);
    }
    if let Some(translation) = walker.translation(rules, None, 0) {
        let (finished, _): (Paths, Paths) = start.into_iter().partition(|path| path.done);
        let paths = finished
            .into_iter()
            .chain(unknown(translation.construct, &translation.origin))
            .collect();
        return verdict(&paths);
    }
    verdict(&walker.run(rules, None, 0, start))
}

struct Walker<'a> {
    anchors: &'a AnchorRulesets,
    traffic: &'a Traffic<'a>,
}

impl Walker<'_> {
    /// Translation rules run before filtering, whatever their position, so
    /// one that could match makes the verdict unknown.
    fn translation(
        &self,
        rules: &Ruleset,
        anchor: Option<&AnchorName>,
        depth: usize,
    ) -> Option<Uncertain> {
        rules.entries.iter().find_map(|entry| match &entry.kind {
            Kind::Translation { criteria, target }
                if criteria.matches_translation(target, self.traffic) != Match::No =>
            {
                Some(Uncertain {
                    origin: Origin::new(entry.line, anchor),
                    construct: Construct::Translation,
                })
            }
            Kind::Anchor { name, criteria }
                if depth < MAX_ANCHOR_DEPTH && criteria.matches(self.traffic) != Match::No =>
            {
                let resolved = name.resolve(anchor);
                let body = self.anchors.get(resolved.lookup())?;
                self.translation(body, Some(&resolved), depth + 1)
            }
            _ => None,
        })
    }

    /// Packets on an interface named by `set skip on` are not filtered.
    fn skipped(&self, rules: &Ruleset) -> Paths {
        let mut paths = Paths::from([Path {
            done: false,
            matched: false,
            outcome: Outcome::Pass(Cause::Default),
            uncertain: None,
        }]);
        for skip in &rules.skip {
            let matched = if is_group_name(&skip.name) {
                Match::Maybe(Construct::InterfaceGroup)
            } else {
                Match::of(skip.name == self.traffic.interface)
            };
            let origin = Origin::new(skip.line, None);
            paths = branch(paths, matched, &origin, |live, uncertain| {
                live.iter()
                    .map(|_| Path {
                        done: true,
                        matched: false,
                        outcome: Outcome::Pass(Cause::Skip),
                        uncertain: uncertain.cloned(),
                    })
                    .collect()
            });
        }
        paths
    }

    fn run(
        &self,
        rules: &Ruleset,
        anchor: Option<&AnchorName>,
        depth: usize,
        start: Paths,
    ) -> Paths {
        rules.entries.iter().fold(start, |paths, entry| {
            let origin = Origin::new(entry.line, anchor);
            match &entry.kind {
                Kind::Filter { action, criteria } => {
                    let outcome = if let Some(construct) = criteria.effect_construct() {
                        Outcome::Unknown(Uncertain {
                            origin: origin.clone(),
                            construct,
                        })
                    } else {
                        let cause = Cause::Rule(origin.clone());
                        match action {
                            Action::Pass => Outcome::Pass(cause),
                            Action::Block => Outcome::Block(cause),
                        }
                    };
                    branch(
                        paths,
                        criteria.matches(self.traffic),
                        &origin,
                        |live, uncertain| {
                            live.iter()
                                .map(|_| Path {
                                    done: criteria.quick,
                                    matched: true,
                                    outcome: outcome.clone(),
                                    uncertain: uncertain.cloned(),
                                })
                                .collect()
                        },
                    )
                }
                Kind::Anchor { name, criteria } => branch(
                    paths,
                    criteria.matches(self.traffic),
                    &origin,
                    |live, uncertain| {
                        self.enter(name, anchor, criteria.quick, &origin, depth, live)
                            .into_iter()
                            .map(|path| path.tagged(uncertain))
                            .collect()
                    },
                ),
                Kind::Unparseable => branch(
                    paths,
                    Match::Maybe(Construct::UnparseableRule),
                    &origin,
                    |_, _| unknown(Construct::UnparseableRule, &origin),
                ),
                Kind::Translation { .. } => paths,
            }
        })
    }

    /// Runs the supplied rules of an anchor in place of its `anchor` line.
    /// Without them nothing can be said, and a `quick` rule inside could have
    /// ended the walk, so the path stops there as unknown.
    fn enter(
        &self,
        name: &AnchorName,
        parent: Option<&AnchorName>,
        anchor_quick: bool,
        origin: &Origin,
        depth: usize,
        live: Paths,
    ) -> Paths {
        let resolved = name.resolve(parent);
        let Some(body) = self.anchors.get(resolved.lookup()) else {
            return unknown(Construct::MissingAnchor, origin);
        };
        if depth >= MAX_ANCHOR_DEPTH {
            return unknown(Construct::AnchorTooDeep, origin);
        }
        let (prev_matched, prev_unmatched): (Paths, Paths) =
            live.into_iter().partition(|path| path.matched);
        let mut out = Paths::new();
        for (was_matched, bucket) in [(false, prev_unmatched), (true, prev_matched)] {
            if bucket.is_empty() {
                continue;
            }
            let reset: Paths = bucket
                .into_iter()
                .map(|mut path| {
                    path.matched = false;
                    path
                })
                .collect();
            for mut path in self.run(body, Some(&resolved), depth + 1, reset) {
                if anchor_quick && path.matched {
                    path.done = true;
                }
                path.matched = path.matched || was_matched;
                out.insert(path);
            }
        }
        out
    }
}

fn unknown(construct: Construct, origin: &Origin) -> Paths {
    Paths::from([Path {
        done: true,
        matched: false,
        outcome: Outcome::Unknown(Uncertain {
            construct,
            origin: origin.clone(),
        }),
        uncertain: None,
    }])
}

/// Applies one rule to the paths that are still running. `taken` builds the
/// paths where the rule matched; a rule that only might match keeps the old
/// paths too.
fn branch(
    paths: Paths,
    matched: Match,
    origin: &Origin,
    taken: impl FnOnce(Paths, Option<&Uncertain>) -> Paths,
) -> Paths {
    let (finished, live): (Paths, Paths) = paths.into_iter().partition(|path| path.done);
    if live.is_empty() {
        return finished;
    }
    let next = match matched {
        Match::No => live,
        Match::Yes => taken(live, None),
        Match::Maybe(construct) => {
            let uncertain = Uncertain {
                construct,
                origin: origin.clone(),
            };
            let moved = taken(live.clone(), Some(&uncertain));
            live.into_iter().chain(moved).collect()
        }
    };
    finished.into_iter().chain(next).collect()
}

fn verdict(paths: &Paths) -> Verdict {
    let unknown = |reason: String| Verdict::Unknown { reason };
    if let Some(uncertain) = paths.iter().find_map(|path| match &path.outcome {
        Outcome::Unknown(uncertain) => Some(uncertain),
        Outcome::Pass(_) | Outcome::Block(_) => None,
    }) {
        return unknown(uncertain.to_string());
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
        _ => unknown(
            paths
                .iter()
                .filter_map(|path| path.uncertain.as_ref())
                .min()
                .map_or_else(|| "conflicting rules".to_string(), ToString::to_string),
        ),
    }
}

fn describe(action: &str, cause: &Cause) -> String {
    match cause {
        Cause::Default => "no rule matched, and pf passes by default".to_string(),
        Cause::Skip => "the interface is excluded by set skip".to_string(),
        Cause::Rule(origin) => format!("matched {action} rule at {origin}"),
    }
}
