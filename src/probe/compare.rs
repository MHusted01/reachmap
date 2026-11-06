//! `reachmap probe --scan`: where a probe and a saved scan disagree. Pure, so
//! every case is tested without a network.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use super::claims::{Claim, ScanClaims};
use super::{Outcome, ProbedPort};
use crate::network::Network;

/// How a probe and a scan disagree about a port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Disagreement {
    /// The scan says this network cannot reach the port, but it connected.
    /// This is the more serious kind, so it sorts first.
    UnexpectedConnection,
    /// The scan says this network can reach the port, but no connection
    /// succeeded. A firewall can cause this: `reach` is decided before
    /// firewall rules.
    MissingConnection,
}

/// One port and network where the probe and the scan disagree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Difference {
    /// How they disagree.
    pub kind: Disagreement,
    /// The TCP port.
    pub port: u16,
    /// The network the probe came from.
    pub from: Network,
}

/// How a probe compares with a saved scan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Comparison {
    /// The networks the probe came from, narrowest first.
    pub from: BTreeSet<Network>,
    /// Whether they were worked out from the addresses, not given with `--from`.
    pub guessed: bool,
    /// The differences, most serious first, then by port.
    pub differences: Vec<Difference>,
    /// Probed ports the scan has no verdict for: only the probe result counts.
    pub unknown_ports: BTreeSet<u16>,
    /// Ports of rows that are not TCP, left out of the comparison.
    pub skipped_ports: BTreeSet<u16>,
}

/// What the attempts on one port from one network add up to. Ordered so that
/// the strongest evidence wins: one connection proves the port answers, and a
/// failed attempt leaves open what the closed ones suggest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Evidence {
    NotConnected,
    NotTested,
    Connected,
}

impl From<&Outcome> for Evidence {
    fn from(outcome: &Outcome) -> Self {
        match outcome {
            Outcome::Open => Evidence::Connected,
            Outcome::Failed { .. } => Evidence::NotTested,
            Outcome::Closed | Outcome::NoAnswer | Outcome::Unreachable => Evidence::NotConnected,
        }
    }
}

/// The evidence for each port and network. Without `from`, each address
/// counts for the network it suggests.
fn gather(results: &[ProbedPort], from: Option<Network>) -> BTreeMap<(u16, Network), Evidence> {
    let mut gathered = BTreeMap::new();
    for probed in results {
        let network = from.unwrap_or_else(|| Network::of_target(probed.address.ip()));
        let evidence = Evidence::from(&probed.result);
        gathered
            .entry((probed.port, network))
            .and_modify(|strongest: &mut Evidence| *strongest = evidence.max(*strongest))
            .or_insert(evidence);
    }
    gathered
}

/// How `evidence` disagrees with `claim`, if it does.
fn disagreement(claim: Claim, evidence: Evidence) -> Option<Disagreement> {
    match (claim, evidence) {
        (Claim::CannotReach, Evidence::Connected) => Some(Disagreement::UnexpectedConnection),
        (Claim::CanReach, Evidence::NotConnected) => Some(Disagreement::MissingConnection),
        _ => None,
    }
}

/// Compares `results` with what `claims` say. `from` is the network the probe
/// came from; without it, each address decides for itself.
pub fn compare(claims: &ScanClaims, results: &[ProbedPort], from: Option<Network>) -> Comparison {
    let gathered = gather(results, from);
    let mut differences: Vec<_> = gathered
        .iter()
        .filter_map(|(&(port, from), &evidence)| {
            let kind = disagreement(claims.claim(port, from), evidence)?;
            Some(Difference { kind, port, from })
        })
        .collect();
    differences.sort_unstable();
    Comparison {
        from: gathered.keys().map(|&(_, network)| network).collect(),
        guessed: from.is_none(),
        differences,
        unknown_ports: gathered
            .keys()
            .filter(|&&(port, network)| claims.claim(port, network) == Claim::Unknown)
            .map(|&(port, _)| port)
            .collect(),
        skipped_ports: claims.skipped().clone(),
    }
}

#[cfg(test)]
mod tests;
