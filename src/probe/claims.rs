//! What a saved `reachmap scan --json` document says about a host's TCP ports,
//! in the form `reachmap probe --scan` compares a probe with.
//!
//! The file is not trusted, so this reads numbers and enum values and nothing
//! else: no text from it can reach the terminal. Like [`crate::baseline`], the
//! reader is tolerant: unknown fields are ignored, and a value this version
//! cannot read counts as unknown.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use clap::ValueEnum;
use serde::Deserialize;

use crate::baseline::{self, LoadError, ParseError, Tolerant};
use crate::network::Network;
use crate::parse::probe_args::PortList;
use crate::reach::Reach;
use crate::socket::Protocol;

/// The networks Tailscale adds to a row it forwards to. Clients there connect
/// to the port Tailscale shares, which is usually another one, so the row
/// cannot say whether its own port answers them.
const FORWARDED_NETWORKS: [Network; 2] = [Network::Tailnet, Network::Internet];

/// What a scan says about one port from one network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Claim {
    /// Clients on the network can connect.
    CanReach,
    /// Clients on the network cannot connect.
    CannotReach,
    /// The scan cannot say.
    Unknown,
}

/// What the TCP rows of one port say together.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct PortClaim {
    /// The networks a row says can connect.
    can_reach: BTreeSet<Network>,
    /// The networks a row cannot speak for.
    unsure: BTreeSet<Network>,
}

impl PortClaim {
    /// Adds what one row says.
    fn add(&mut self, reach: Reach, forwarded: bool) {
        match reach {
            Reach::From { networks } => {
                let (unsure, sure): (BTreeSet<_>, BTreeSet<_>) = networks
                    .into_iter()
                    .partition(|network| forwarded && FORWARDED_NETWORKS.contains(network));
                self.can_reach.extend(sure);
                self.unsure.extend(unsure);
            }
            Reach::Unknown => self.unsure.extend(Network::value_variants()),
        }
    }

    /// What the rows say together: one that vouches for `network` settles it.
    fn claim(&self, network: Network) -> Claim {
        if self.can_reach.contains(&network) {
            Claim::CanReach
        } else if self.unsure.contains(&network) {
            Claim::Unknown
        } else {
            Claim::CannotReach
        }
    }
}

/// What a scan says about the ports of its host.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScanClaims {
    ports: BTreeMap<u16, PortClaim>,
    skipped: BTreeSet<u16>,
}

impl ScanClaims {
    /// The TCP ports to probe, or `None` when the scan has none.
    pub fn ports(&self) -> Option<PortList> {
        PortList::from_ports(self.ports.keys().copied())
    }

    /// The ports of rows that are not TCP, which a connect probe cannot confirm.
    pub fn skipped(&self) -> &BTreeSet<u16> {
        &self.skipped
    }

    /// What the scan says about `port` from `network`.
    pub fn claim(&self, port: u16, network: Network) -> Claim {
        self.ports
            .get(&port)
            .map_or(Claim::Unknown, |claim| claim.claim(network))
    }

    /// Adds what one row says.
    fn add(&mut self, row: SavedRow) {
        match row.protocol {
            Tolerant::Known(Protocol::Tcp) => {
                let forwarded = row.reason.kind == Tolerant::Known(ReasonKind::TailscaleShared);
                let reach = row.reach.known().unwrap_or(Reach::Unknown);
                self.ports
                    .entry(row.port)
                    .or_default()
                    .add(reach, forwarded);
            }
            Tolerant::Known(Protocol::Udp) | Tolerant::Unknown => {
                self.skipped.insert(row.port);
            }
        }
    }
}

/// The parts of a saved scan a comparison uses.
#[derive(Deserialize)]
struct SavedScan {
    ports: Vec<SavedRow>,
}

/// One row of a saved scan. Its text fields are left out on purpose.
#[derive(Deserialize)]
struct SavedRow {
    port: u16,
    protocol: Tolerant<Protocol>,
    reach: Tolerant<Reach>,
    reason: SavedReason,
}

/// A row's reason, by kind alone.
#[derive(Deserialize)]
struct SavedReason {
    kind: Tolerant<ReasonKind>,
}

/// The one kind of reason a comparison treats differently.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ReasonKind {
    TailscaleShared,
}

/// Reads the text of a saved scan. Pure, so it is tested on any OS.
pub fn parse(text: &str) -> Result<ScanClaims, ParseError> {
    baseline::check_version(text)?;
    let saved: SavedScan = serde_json::from_str(text)?;
    let mut claims = ScanClaims::default();
    saved.ports.into_iter().for_each(|row| claims.add(row));
    Ok(claims)
}

/// Reads a saved scan from `path`.
pub fn load(path: &Path) -> Result<ScanClaims, LoadError> {
    baseline::load_with(path, parse)
}

#[cfg(test)]
mod tests;
