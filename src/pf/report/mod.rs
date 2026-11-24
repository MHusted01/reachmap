//! Building and rendering per-socket macOS `pf` verdicts.
//!
//! Pure and cross-platform: parses `ifconfig -a` output and joins listening
//! sockets with [`CollectedPf`] into [`PfReport`].

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::sanitize::sanitize;
use crate::socket::{AddressFamily, Endpoint, Protocol};

use super::{CollectedPf, PfCollectError, Verdict};

mod eval;
mod ifconfig;

use eval::EvalContext;
pub use ifconfig::{MacosInterfaces, parse_ifconfig};

/// macOS `pf` status and per-socket input verdicts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum PfReport {
    /// pf is disabled and does not filter inbound traffic.
    Disabled,
    /// pf is enabled and rules were evaluated for listening sockets.
    Enabled {
        /// Per-socket verdicts, sorted by port, protocol, address, and family.
        ports: Vec<PfPort>,
    },
    /// pf status or rules could not be read.
    Unknown {
        /// Why pf could not be evaluated.
        reason: String,
    },
}

/// pf input verdicts for one listening socket and packet IP family.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PfPort {
    /// Listening port number.
    pub port: u16,
    /// Transport protocol (`tcp` or `udp`).
    pub protocol: Protocol,
    /// Local bind address.
    pub address: IpAddr,
    /// Packet IP family (`ipv4` or `ipv6`).
    pub family: AddressFamily,
    /// Verdict per applicable incoming interface, or one unknown entry when
    /// no interface could be determined.
    pub interfaces: Vec<PfInterfaceVerdict>,
}

/// Verdict for one incoming interface (or an unresolved target).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PfInterfaceVerdict {
    /// Incoming interface name, omitted when no interface applies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interface: Option<String>,
    /// What pf does with inbound traffic, and why.
    #[serde(flatten)]
    pub outcome: Verdict,
}

/// A listening socket input for [`PfReport::evaluate`].
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct SocketTarget {
    /// Listening endpoint (port, protocol, local address).
    pub endpoint: Endpoint,
    /// Link-local zone identifier from `lsof`, if any.
    pub zone: Option<String>,
}

impl PfReport {
    /// Evaluates collected pf state against listening `sockets` and
    /// `interfaces`.
    #[must_use]
    pub fn evaluate(
        pf: Result<CollectedPf, PfCollectError>,
        sockets: &[SocketTarget],
        interfaces: Result<&MacosInterfaces, &str>,
    ) -> Self {
        let (rules, anchors, listed_interfaces, skipped_groups) = match pf {
            Ok(CollectedPf::Disabled) => return Self::Disabled,
            Ok(CollectedPf::Enabled {
                rules,
                anchors,
                listed_interfaces,
                skipped_groups,
            }) => (rules, anchors, listed_interfaces, skipped_groups),
            Err(error) => {
                return Self::Unknown {
                    reason: sanitize(&error.to_string()),
                };
            }
        };
        let ctx = EvalContext {
            rules: &rules,
            anchors: &anchors,
            listed_interfaces: &listed_interfaces,
            skipped_groups: &skipped_groups,
            interfaces,
        };
        let unique: BTreeSet<&SocketTarget> = sockets.iter().collect();
        let mut grouped: BTreeMap<(u16, Protocol, IpAddr, AddressFamily), Vec<PfInterfaceVerdict>> =
            BTreeMap::new();
        for socket in unique {
            for (family, verdicts) in ctx.evaluate_socket(socket) {
                let key = (
                    socket.endpoint.port,
                    socket.endpoint.protocol,
                    socket.endpoint.address,
                    family,
                );
                grouped.entry(key).or_default().extend(verdicts);
            }
        }
        let ports = grouped
            .into_iter()
            .map(|((port, protocol, address, family), mut ifaces)| PfPort {
                port,
                protocol,
                address,
                family,
                interfaces: {
                    ifaces.sort_by(|a, b| a.interface.cmp(&b.interface));
                    ifaces.dedup();
                    ifaces
                },
            })
            .collect();
        Self::Enabled { ports }
    }
}

impl fmt::Display for PfReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Disabled => {
                writeln!(f, "macOS pf: disabled (pf does not filter inbound traffic)")
            }
            Self::Unknown { reason } => writeln!(f, "macOS pf: unknown ({reason})"),
            Self::Enabled { ports } if ports.is_empty() => {
                writeln!(f, "macOS pf: enabled (no listening sockets to check)")
            }
            Self::Enabled { ports } => {
                writeln!(f, "macOS pf: enabled")?;
                for entry in ports {
                    let family = match entry.family {
                        AddressFamily::Ipv4 => "IPv4",
                        AddressFamily::Ipv6 => "IPv6",
                    };
                    let interfaces = entry
                        .interfaces
                        .iter()
                        .map(|check| match &check.interface {
                            Some(name) => format!("{name} {}", check.outcome),
                            None => check.outcome.to_string(),
                        })
                        .collect::<Vec<_>>()
                        .join(", ");
                    writeln!(
                        f,
                        "  {}/{} {} ({family}): {interfaces}",
                        entry.port, entry.protocol, entry.address
                    )?;
                }
                Ok(())
            }
        }
    }
}
