//! Applying pf's "last matching rule wins, unless it is `quick`" to a packet.
//!
//! A rule can match, not match, or depend on something unmodeled. The walk
//! keeps every state the packet could be in (a *path*) and forks at each rule
//! that might match. The verdict is certain only when all paths agree.

use crate::socket::Protocol;

use super::fields::{SYN, SYN_ECN, TcpFlags};
use super::matching::Match;
use super::model::{Action, AnchorName, Construct, Kind, Ruleset, is_group_name};
use super::{AnchorRulesets, Traffic, Verdict};

mod state;

use state::{
    Cause, Origin, Outcome, Path, Paths, Uncertain, combine_tcp_verdicts, direct_children, unknown,
    verdict,
};

/// Anchors may contain anchors. Deeper than this the walk gives up.
const MAX_ANCHOR_DEPTH: usize = 8;

pub(super) fn evaluate(
    rules: &Ruleset,
    anchors: &AnchorRulesets,
    traffic: &Traffic<'_>,
) -> Verdict {
    if traffic.protocol == Protocol::Tcp {
        let plain = Walker {
            anchors,
            traffic,
            opening_flags: SYN,
        }
        .evaluate(rules);
        let ecn = Walker {
            anchors,
            traffic,
            opening_flags: SYN_ECN,
        }
        .evaluate(rules);
        combine_tcp_verdicts(&plain, &ecn)
    } else {
        let paths = Walker {
            anchors,
            traffic,
            opening_flags: SYN,
        }
        .evaluate(rules);
        verdict(&paths)
    }
}

struct Walker<'a> {
    anchors: &'a AnchorRulesets,
    traffic: &'a Traffic<'a>,
    opening_flags: u8,
}

impl Walker<'_> {
    fn evaluate(&self, rules: &Ruleset) -> Paths {
        let start = self.skipped(rules);
        if start.iter().all(|path| path.done) {
            return start;
        }
        if let Some(translation) = self.translation(rules, None, 0) {
            let (finished, _): (Paths, Paths) = start.into_iter().partition(|path| path.done);
            return finished
                .into_iter()
                .chain(unknown(translation.construct, &translation.origin))
                .collect();
        }
        self.run(rules, None, 0, start)
    }

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
                if criteria.matches_translation(target, self.traffic, self.opening_flags)
                    != Match::No =>
            {
                Some(Uncertain {
                    origin: Origin::new(entry.line, anchor),
                    construct: Construct::Translation,
                })
            }
            Kind::Anchor { name, criteria }
                if depth < MAX_ANCHOR_DEPTH
                    && criteria.matches(self.traffic, self.opening_flags) != Match::No =>
            {
                let resolved = name.resolve(anchor)?;
                if resolved.is_wildcard() {
                    direct_children(self.anchors, resolved.lookup())
                        .into_iter()
                        .find_map(|(key, body)| {
                            self.translation(body, Some(&AnchorName::new(key)), depth + 1)
                        })
                } else {
                    let body = self.anchors.get(resolved.lookup())?;
                    self.translation(body, Some(&resolved), depth + 1)
                }
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
            ecn_origin: None,
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
                        ecn_origin: None,
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
                    let ecn_origin = criteria
                        .flags
                        .is_some_and(TcpFlags::depends_on_ecn)
                        .then(|| origin.clone());
                    branch(
                        paths,
                        criteria.matches(self.traffic, self.opening_flags),
                        &origin,
                        |live, uncertain| {
                            live.into_iter()
                                .map(|prev| Path {
                                    done: criteria.quick,
                                    matched: true,
                                    outcome: outcome.clone(),
                                    uncertain: uncertain.cloned(),
                                    ecn_origin: prev.ecn_origin.or_else(|| ecn_origin.clone()),
                                })
                                .collect()
                        },
                    )
                }
                Kind::Anchor { name, criteria } => {
                    let ecn_origin = criteria
                        .flags
                        .is_some_and(TcpFlags::depends_on_ecn)
                        .then(|| origin.clone());
                    branch(
                        paths,
                        criteria.matches(self.traffic, self.opening_flags),
                        &origin,
                        |live, uncertain| {
                            self.enter(name, anchor, criteria.quick, &origin, depth, live)
                                .into_iter()
                                .map(|path| path.tagged(uncertain).with_ecn(ecn_origin.as_ref()))
                                .collect()
                        },
                    )
                }
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
        let Some(resolved) = name.resolve(parent) else {
            return unknown(Construct::MissingAnchor, origin);
        };
        if resolved.is_wildcard() {
            let complete = self.anchors.contains_key(resolved.lookup());
            let children = direct_children(self.anchors, resolved.lookup());
            if !complete && children.is_empty() {
                return unknown(Construct::MissingAnchor, origin);
            }
            if depth >= MAX_ANCHOR_DEPTH {
                return unknown(Construct::AnchorTooDeep, origin);
            }
            let mut out = self.run_bodies(&children, anchor_quick, depth, live);
            if !complete {
                out.extend(unknown(Construct::MissingAnchor, origin));
            }
            return out;
        }
        let Some(body) = self.anchors.get(resolved.lookup()) else {
            return unknown(Construct::MissingAnchor, origin);
        };
        if depth >= MAX_ANCHOR_DEPTH {
            return unknown(Construct::AnchorTooDeep, origin);
        }
        self.run_bodies(&[(resolved.lookup(), body)], anchor_quick, depth, live)
    }

    fn run_bodies(
        &self,
        bodies: &[(&str, &Ruleset)],
        anchor_quick: bool,
        depth: usize,
        live: Paths,
    ) -> Paths {
        let (prev_matched, prev_unmatched): (Paths, Paths) =
            live.into_iter().partition(|path| path.matched);
        let mut out = Paths::new();
        for (was_matched, bucket) in [(false, prev_unmatched), (true, prev_matched)] {
            if bucket.is_empty() {
                continue;
            }
            let mut current: Paths = bucket
                .into_iter()
                .map(|mut path| {
                    path.matched = false;
                    path
                })
                .collect();
            for &(key, body) in bodies {
                let scope = AnchorName::new(key);
                current = self.run(body, Some(&scope), depth + 1, current);
            }
            for mut path in current {
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
