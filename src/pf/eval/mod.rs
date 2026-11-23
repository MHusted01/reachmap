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

mod scrub;
mod state;

use scrub::{Reassembly, evaluate_scrub};
use state::{
    Cause, Origin, Outcome, Path, Paths, Stop, Uncertain, combine_fragment_verdicts,
    combine_tcp_verdicts, direct_children, has_filter_entries, promote_anchor_stops, unknown,
    verdict,
};

/// Anchors may contain anchors. Deeper than this the walk gives up.
const MAX_ANCHOR_DEPTH: usize = 8;

#[derive(Clone, Copy)]
struct AnchorQuick {
    is_quick: bool,
    has_more: bool,
}

pub(super) fn evaluate(
    rules: &Ruleset,
    anchors: &AnchorRulesets,
    traffic: &Traffic<'_>,
) -> Verdict {
    let base = Walker {
        anchors,
        traffic,
        opening_flags: SYN,
        fragment: false,
    };
    let skipped = base.skipped(rules);
    if skipped.iter().all(Path::is_done) {
        return verdict(&skipped);
    }
    let reassembled = match evaluate_scrub(rules, anchors, traffic) {
        Reassembly::Unknown(uncertain) => {
            let (finished, _): (Paths, Paths) = skipped.into_iter().partition(Path::is_done);
            let paths: Paths = finished
                .into_iter()
                .chain(unknown(uncertain.construct, &uncertain.origin))
                .collect();
            return verdict(&paths);
        }
        Reassembly::Reassembled => true,
        Reassembly::MaybeUnreassembled => false,
    };
    if traffic.protocol == Protocol::Tcp {
        let plain = base.evaluate_after_skip(rules, skipped.clone());
        let ecn = Walker {
            opening_flags: SYN_ECN,
            ..base
        }
        .evaluate_after_skip(rules, skipped);
        combine_tcp_verdicts(&plain, &ecn)
    } else if traffic.destination.is_ipv4() && !reassembled {
        let full = base.evaluate_after_skip(rules, skipped.clone());
        let frag = Walker {
            fragment: true,
            ..base
        }
        .evaluate_after_skip(rules, skipped);
        combine_fragment_verdicts(&full, &frag)
    } else {
        verdict(&base.evaluate_after_skip(rules, skipped))
    }
}

struct Walker<'a> {
    anchors: &'a AnchorRulesets,
    traffic: &'a Traffic<'a>,
    opening_flags: u8,
    fragment: bool,
}

impl Walker<'_> {
    fn evaluate_after_skip(&self, rules: &Ruleset, start: Paths) -> Paths {
        if let Some(found) = self.translation(rules, None, 0) {
            let (finished, _): (Paths, Paths) = start.into_iter().partition(Path::is_done);
            return finished
                .into_iter()
                .chain(unknown(found.construct, &found.origin))
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
                    && criteria.matches(self.traffic, self.opening_flags, false) != Match::No =>
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
            stop: Stop::None,
            matched: false,
            outcome: Outcome::Pass(Cause::Default),
            uncertain: None,
            ecn_origin: None,
            port_origin: None,
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
                        stop: Stop::Full,
                        matched: false,
                        outcome: Outcome::Pass(Cause::Skip),
                        uncertain: uncertain.cloned(),
                        ecn_origin: None,
                        port_origin: None,
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
        rules
            .entries
            .iter()
            .enumerate()
            .fold(start, |paths, (idx, entry)| {
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
                        let port_origin = (!self.fragment && criteria.has_port_condition())
                            .then(|| origin.clone());
                        let stop = if criteria.quick {
                            Stop::Full
                        } else {
                            Stop::None
                        };
                        branch(
                            paths,
                            criteria.matches(self.traffic, self.opening_flags, self.fragment),
                            &origin,
                            |live, uncertain| {
                                live.into_iter()
                                    .map(|prev| Path {
                                        stop,
                                        matched: true,
                                        outcome: outcome.clone(),
                                        uncertain: uncertain.cloned(),
                                        ecn_origin: prev.ecn_origin.or_else(|| ecn_origin.clone()),
                                        port_origin: prev
                                            .port_origin
                                            .or_else(|| port_origin.clone()),
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
                        let port_origin = (!self.fragment && criteria.has_port_condition())
                            .then(|| origin.clone());
                        let quick = AnchorQuick {
                            is_quick: criteria.quick,
                            has_more: has_filter_entries(&rules.entries[idx + 1..]),
                        };
                        branch(
                            paths,
                            criteria.matches(self.traffic, self.opening_flags, self.fragment),
                            &origin,
                            |live, uncertain| {
                                self.enter(name, anchor, quick, &origin, depth, live)
                                    .into_iter()
                                    .map(|path| {
                                        path.tagged(uncertain)
                                            .with_ecn(ecn_origin.as_ref())
                                            .with_port(port_origin.as_ref())
                                    })
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
                    Kind::Translation { .. }
                    | Kind::ScrubReassemble { .. }
                    | Kind::NoScrub { .. }
                    | Kind::ScrubOther { .. }
                    | Kind::ScrubAnchor { .. } => paths,
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
        quick: AnchorQuick,
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
            let mut out = self.run_bodies(&children, quick, depth, live);
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
        self.run_bodies(&[(resolved.lookup(), body)], quick, depth, live)
    }

    fn run_bodies(
        &self,
        bodies: &[(&str, &Ruleset)],
        quick: AnchorQuick,
        depth: usize,
        live: Paths,
    ) -> Paths {
        let mut current: Paths = live
            .into_iter()
            .map(|mut path| {
                path.matched = false;
                path
            })
            .collect();
        for (body_idx, &(key, body)) in bodies.iter().enumerate() {
            let scope = AnchorName::new(key);
            current = self.run(body, Some(&scope), depth + 1, current);
            let more_children = bodies[body_idx + 1..]
                .iter()
                .any(|(_, child)| has_filter_entries(&child.entries));
            if more_children {
                current = promote_anchor_stops(current);
            }
        }
        current
            .into_iter()
            .map(|mut path| {
                match path.stop {
                    Stop::Full => {}
                    Stop::Anchor | Stop::None => {
                        if quick.is_quick && path.matched {
                            path.stop = if quick.has_more {
                                Stop::Full
                            } else {
                                Stop::Anchor
                            };
                        } else {
                            path.stop = Stop::None;
                        }
                    }
                }
                path
            })
            .collect()
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
    let (finished, live): (Paths, Paths) = paths.into_iter().partition(Path::is_done);
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
