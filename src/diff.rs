//! `reachmap diff`: what changed between two scans. The comparison is pure;
//! [`crate::baseline`] prepares both sides and [`report`] formats the result.

pub mod report;

use std::collections::BTreeSet;
use std::iter;
use std::str::FromStr;

use serde::Serialize;
use thiserror::Error;

use crate::baseline::{Exposure, LoadError, RowKey, Snapshot, Tolerant};
use crate::json::Collector;
use crate::parse::probe_args::{PortList, PortListError};
use crate::scan::{Listener, ScanError};
use crate::socket::Protocol;

/// Ports to leave out of a diff, optionally limited to one transport protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IgnoreFilter {
    ports: PortList,
    protocol: Option<Protocol>,
}

/// Why a `--ignore` value was refused.
#[derive(Debug, Error)]
pub enum IgnoreFilterError {
    /// The protocol prefix is neither `tcp` nor `udp`.
    #[error("unknown protocol {protocol:?} (expected tcp or udp)")]
    UnknownProtocol {
        /// The prefix that was given.
        protocol: String,
    },
    /// The port list did not parse.
    #[error(transparent)]
    Ports(#[from] PortListError),
}

impl FromStr for IgnoreFilter {
    type Err = IgnoreFilterError;

    /// Reads a port list, optionally prefixed with `tcp:` or `udp:`.
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let (protocol, ports) = match text.split_once(':') {
            Some(("tcp", ports)) => (Some(Protocol::Tcp), ports),
            Some(("udp", ports)) => (Some(Protocol::Udp), ports),
            Some((protocol, _)) => {
                return Err(IgnoreFilterError::UnknownProtocol {
                    protocol: protocol.to_string(),
                });
            }
            None => (None, text),
        };
        Ok(Self {
            ports: ports.parse()?,
            protocol,
        })
    }
}

/// What happened to one row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Change {
    /// The row is not in the baseline.
    New {
        /// What the current scan says.
        now: Exposure,
    },
    /// The row is gone.
    Removed {
        /// What the baseline says.
        was: Exposure,
    },
    /// The row says something else.
    Changed {
        /// What the baseline says.
        was: Exposure,
        /// What the current scan says.
        now: Exposure,
    },
    /// The row is not in the current scan, but that scan could not have seen
    /// it, so it may still be there.
    Unverified {
        /// What the baseline says.
        was: Exposure,
    },
}

/// One difference between two scans.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Difference {
    /// The row.
    #[serde(flatten)]
    pub key: RowKey,
    /// What happened to it.
    #[serde(flatten)]
    pub change: Change,
}

/// The result of comparing two scans.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diff {
    /// The differences, by port, then protocol, then address.
    pub differences: Vec<Difference>,
    /// The collectors that failed in the baseline.
    pub baseline_missing: BTreeSet<Tolerant<Collector>>,
    /// The collectors that failed in the current scan.
    pub current_missing: BTreeSet<Tolerant<Collector>>,
    /// Whether only one of the scans lacked the privileges to name every
    /// owner, so owners can differ for that reason alone.
    pub privileges_differ: bool,
    /// How many differences [`Diff::ignoring`] left out. `None` without a
    /// filter, so a filter that matched nothing still shows that it ran.
    pub ignored: Option<usize>,
}

impl Diff {
    /// Whether nothing needs attention. `false` as well when the current scan
    /// lacks facts the baseline has: identical rows then prove nothing. Facts
    /// missing from both are fine, or a host without Docker would never pass.
    pub fn is_clean(&self) -> bool {
        self.differences.is_empty() && self.current_missing.is_subset(&self.baseline_missing)
    }

    /// Leaves out the differences on `ports`, on any protocol, and counts them.
    /// Facts a scan lacks are not tied to a port, so they still count.
    #[must_use]
    pub fn ignoring(self, ports: &PortList) -> Self {
        self.ignoring_ports(ports, None)
    }

    /// Leaves out and counts differences matching the filter. A protocol prefix
    /// matches only rows with that known protocol, across both IP families.
    #[must_use]
    pub fn ignoring_filter(self, filter: &IgnoreFilter) -> Self {
        self.ignoring_ports(&filter.ports, filter.protocol)
    }

    fn ignoring_ports(self, ports: &PortList, protocol: Option<Protocol>) -> Self {
        let (ignored, differences): (Vec<_>, Vec<_>) =
            self.differences.into_iter().partition(|difference| {
                ports.contains(difference.key.port)
                    && protocol
                        .is_none_or(|protocol| difference.key.protocol.known() == Some(protocol))
            });
        Diff {
            differences,
            ignored: Some(ignored.len()),
            ..self
        }
    }
}

/// Why two scans could not be compared.
#[derive(Debug, Error)]
pub enum DiffError {
    /// A saved scan could not be used.
    #[error(transparent)]
    Load(#[from] LoadError),
    /// The current scan failed.
    #[error(transparent)]
    Scan(#[from] ScanError),
}

impl DiffError {
    /// A suggestion for the user, when there is one beyond the message.
    pub fn hint(&self) -> Option<String> {
        match self {
            DiffError::Load(_) => None,
            DiffError::Scan(error) => error.hint(),
        }
    }
}

/// Compares `current` with `baseline`.
pub fn compare(baseline: &Snapshot, current: &Snapshot) -> Diff {
    let none = BTreeSet::new();
    let keys: BTreeSet<&RowKey> = baseline.rows.keys().chain(current.rows.keys()).collect();
    let differences = keys
        .into_iter()
        .flat_map(|key| {
            let was = baseline.rows.get(key).unwrap_or(&none);
            let now = current.rows.get(key).unwrap_or(&none);
            changes_at(key, was, now, current)
        })
        .collect();
    Diff {
        differences,
        baseline_missing: baseline.missing.clone(),
        current_missing: current.missing.clone(),
        privileges_differ: baseline.needs_root != current.needs_root,
        ignored: None,
    }
}

/// What differs on one row. Rows both sides have cancel out, and the rest are
/// paired in order: nearly always one on each side, or one on one side only.
fn changes_at(
    key: &RowKey,
    was: &BTreeSet<Exposure>,
    now: &BTreeSet<Exposure>,
    current: &Snapshot,
) -> Vec<Difference> {
    let mut gone = was.difference(now).cloned();
    let mut came = now.difference(was).cloned();
    iter::from_fn(|| match (gone.next(), came.next()) {
        (Some(was), Some(now)) => Some(Change::Changed { was, now }),
        (Some(was), None) => Some(missing_now(key, was, current)),
        (None, Some(now)) => Some(Change::New { now }),
        (None, None) => None,
    })
    .map(|change| Difference { key: *key, change })
    .collect()
}

/// The facts a row with this listener needs, besides the sockets. A forwarded
/// port without a socket is only known from Docker, and a port Tailscale shares
/// from its config and the address of its interface.
fn facts_behind(listener: &Tolerant<Listener>) -> &'static [Collector] {
    match listener {
        Tolerant::Known(Listener::DockerForward) => &[Collector::Docker],
        Tolerant::Known(Listener::TailscaleShare) => &[Collector::Tailscale, Collector::Interfaces],
        Tolerant::Known(Listener::HostSocket) | Tolerant::Unknown => &[],
    }
}

/// A row the current scan does not have: removed, unless that scan could not
/// have seen it, because it lacks a fact the row needs. This version cannot
/// produce a row it cannot read either.
fn missing_now(key: &RowKey, was: Exposure, current: &Snapshot) -> Change {
    let silent = facts_behind(&was.listener)
        .iter()
        .any(|collector| current.missing.contains(&Tolerant::Known(*collector)));
    let unreadable = key.protocol == Tolerant::Unknown || was.listener == Tolerant::Unknown;
    if silent || unreadable {
        Change::Unverified { was }
    } else {
        Change::Removed { was }
    }
}

#[cfg(test)]
mod tests;
