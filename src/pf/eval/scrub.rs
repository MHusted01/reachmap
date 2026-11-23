//! Normalization (`scrub` and `scrub-anchor`) pre-pass.
//!
//! Tracks whether IPv4 packets are guaranteed to be fragment-reassembled before
//! filter evaluation, and turns unmodeled scrub options or unresolved
//! `scrub-anchor` targets into explicit `Unknown` reasons.

use std::collections::BTreeSet;

use super::super::matching::Match;
use super::super::model::{AnchorName, Construct, Kind, Ruleset};
use super::super::{AnchorRulesets, Traffic};
use super::MAX_ANCHOR_DEPTH;
use super::state::{Origin, Uncertain, direct_children};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum ScrubState {
    None,
    Reassembled,
    Unknown(Uncertain),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ScrubPath {
    done: bool,
    state: ScrubState,
    uncertain: Option<Uncertain>,
}

type ScrubPaths = BTreeSet<ScrubPath>;

pub(super) enum Reassembly {
    Reassembled,
    MaybeUnreassembled(Option<Uncertain>),
    Unknown(Uncertain),
}

pub(super) fn evaluate_scrub(
    rules: &Ruleset,
    anchors: &AnchorRulesets,
    traffic: &Traffic<'_>,
) -> Reassembly {
    let start = ScrubPaths::from([ScrubPath {
        done: false,
        state: ScrubState::None,
        uncertain: None,
    }]);
    let paths = walk_scrub(rules, anchors, traffic, None, 0, start);
    if let Some(uncertain) = paths.iter().find_map(|path| match &path.state {
        ScrubState::Unknown(uncertain) => Some(uncertain.clone()),
        ScrubState::None | ScrubState::Reassembled => None,
    }) {
        return Reassembly::Unknown(uncertain);
    }
    if paths
        .iter()
        .all(|path| matches!(path.state, ScrubState::Reassembled))
    {
        Reassembly::Reassembled
    } else {
        let any_reassembled = paths
            .iter()
            .any(|path| matches!(path.state, ScrubState::Reassembled));
        let all_non_reassembled_uncertain = paths
            .iter()
            .filter(|path| !matches!(path.state, ScrubState::Reassembled))
            .all(|path| path.uncertain.is_some());
        let uncertain = if any_reassembled && all_non_reassembled_uncertain {
            paths
                .iter()
                .filter(|path| !matches!(path.state, ScrubState::Reassembled))
                .filter_map(|path| path.uncertain.as_ref())
                .min()
                .cloned()
        } else {
            None
        };
        Reassembly::MaybeUnreassembled(uncertain)
    }
}

fn walk_scrub(
    rules: &Ruleset,
    anchors: &AnchorRulesets,
    traffic: &Traffic<'_>,
    anchor: Option<&AnchorName>,
    depth: usize,
    start: ScrubPaths,
) -> ScrubPaths {
    rules.entries.iter().fold(start, |paths, entry| {
        let origin = Origin::new(entry.line, anchor);
        match &entry.kind {
            Kind::ScrubReassemble { criteria } => branch_scrub(
                paths,
                criteria.matches_scrub(traffic),
                &origin,
                |live, uncertain| {
                    live.into_iter()
                        .map(|path| ScrubPath {
                            done: true,
                            state: ScrubState::Reassembled,
                            uncertain: path.uncertain.or_else(|| uncertain.cloned()),
                        })
                        .collect()
                },
            ),
            Kind::NoScrub { criteria } => branch_scrub(
                paths,
                criteria.matches_scrub(traffic),
                &origin,
                |live, uncertain| {
                    live.into_iter()
                        .map(|path| ScrubPath {
                            done: true,
                            state: ScrubState::None,
                            uncertain: path.uncertain.or_else(|| uncertain.cloned()),
                        })
                        .collect()
                },
            ),
            Kind::ScrubOther { criteria } => branch_scrub(
                paths,
                criteria.matches_scrub(traffic),
                &origin,
                |_, uncertain| {
                    let construct = uncertain
                        .map(|u| u.construct)
                        .or(criteria.unsupported)
                        .unwrap_or(Construct::Normalization);
                    unknown_scrub(construct, &origin)
                },
            ),
            Kind::ScrubAnchor { name, criteria } => branch_scrub(
                paths,
                criteria.matches_scrub(traffic),
                &origin,
                |live, uncertain| {
                    enter_scrub_anchor(name, anchor, anchors, traffic, &origin, depth, live)
                        .into_iter()
                        .map(|mut path| {
                            path.uncertain = path.uncertain.or_else(|| uncertain.cloned());
                            path
                        })
                        .collect()
                },
            ),
            _ => paths,
        }
    })
}

fn enter_scrub_anchor(
    name: &AnchorName,
    parent: Option<&AnchorName>,
    anchors: &AnchorRulesets,
    traffic: &Traffic<'_>,
    origin: &Origin,
    depth: usize,
    live: ScrubPaths,
) -> ScrubPaths {
    let Some(resolved) = name.resolve(parent) else {
        return unknown_scrub(Construct::MissingAnchor, origin);
    };
    if resolved.is_wildcard() {
        let complete = anchors.contains_key(resolved.lookup());
        let children = direct_children(anchors, resolved.lookup());
        if !complete && children.is_empty() {
            return unknown_scrub(Construct::MissingAnchor, origin);
        }
        if depth >= MAX_ANCHOR_DEPTH {
            return unknown_scrub(Construct::AnchorTooDeep, origin);
        }
        let mut out = children.into_iter().fold(live, |acc, (key, body)| {
            walk_scrub(
                body,
                anchors,
                traffic,
                Some(&AnchorName::new(key)),
                depth + 1,
                acc,
            )
        });
        if !complete {
            out.extend(unknown_scrub(Construct::MissingAnchor, origin));
        }
        return out;
    }
    let Some(body) = anchors.get(resolved.lookup()) else {
        return unknown_scrub(Construct::MissingAnchor, origin);
    };
    if depth >= MAX_ANCHOR_DEPTH {
        return unknown_scrub(Construct::AnchorTooDeep, origin);
    }
    walk_scrub(body, anchors, traffic, Some(&resolved), depth + 1, live)
}

fn unknown_scrub(construct: Construct, origin: &Origin) -> ScrubPaths {
    ScrubPaths::from([ScrubPath {
        done: true,
        state: ScrubState::Unknown(Uncertain {
            origin: origin.clone(),
            construct,
        }),
        uncertain: None,
    }])
}

fn branch_scrub(
    paths: ScrubPaths,
    matched: Match,
    origin: &Origin,
    taken: impl FnOnce(ScrubPaths, Option<&Uncertain>) -> ScrubPaths,
) -> ScrubPaths {
    let (finished, live): (ScrubPaths, ScrubPaths) = paths.into_iter().partition(|path| path.done);
    if live.is_empty() {
        return finished;
    }
    let next = match matched {
        Match::No => live,
        Match::Yes => taken(live, None),
        Match::Maybe(construct) => {
            let uncertain = Uncertain {
                origin: origin.clone(),
                construct,
            };
            let stayed: ScrubPaths = live
                .iter()
                .cloned()
                .map(|mut path| {
                    if path.uncertain.is_none() {
                        path.uncertain = Some(uncertain.clone());
                    }
                    path
                })
                .collect();
            let moved = taken(live, Some(&uncertain));
            stayed.into_iter().chain(moved).collect()
        }
    };
    finished.into_iter().chain(next).collect()
}
