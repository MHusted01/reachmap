//! Input-chain checks for host sockets.

use std::collections::BTreeSet;
use std::fmt;
use std::io::ErrorKind;

use serde::Serialize;

use crate::collect::CollectError;
use crate::errors::render_chain;
use crate::parse::nftables::parse_ruleset;
use crate::sanitize::sanitize;
use crate::scan::{Listener, ScannedPort};
use crate::service::Service;
use crate::socket::{AddressFamily, Protocol};

/// The result of inspecting the nftables input hook for host socket ports.
#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum NftablesReport {
    /// The ruleset and interfaces were read. Individual checks can be unknown.
    Checked {
        /// One entry per transport, port number and IP family.
        ports: Vec<PortInput>,
    },
    /// The data needed for the check could not be read.
    Unknown {
        /// Why no checks could be made.
        reason: String,
    },
}

/// Input verdicts for a port and one packet family.
#[derive(Debug, Serialize)]
pub struct PortInput {
    port: u16,
    protocol: Protocol,
    family: AddressFamily,
    interfaces: Vec<InterfaceInput>,
}

#[derive(Debug, Serialize)]
struct InterfaceInput {
    interface: String,
    #[serde(flatten)]
    outcome: InputVerdict,
}

/// What the selected input chain does for a packet matching the check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub(crate) enum InputVerdict {
    Accept { reason: &'static str },
    Drop { reason: &'static str },
    Unknown { reason: &'static str },
}

impl NftablesReport {
    pub(crate) fn check(
        raw: Result<String, CollectError>,
        interfaces: &BTreeSet<String>,
        ports: &[ScannedPort],
    ) -> Self {
        let raw = match raw {
            Ok(raw) => raw,
            Err(CollectError::Run { source, .. }) if source.kind() == ErrorKind::NotFound => {
                return Self::Unknown {
                    reason: "nft is missing from the standard system paths".to_string(),
                };
            }
            Err(error) => {
                return Self::Unknown {
                    reason: render_chain(&error),
                };
            }
        };
        let rules = match parse_ruleset(&raw) {
            Ok(rules) => rules,
            Err(error) => {
                return Self::Unknown {
                    reason: sanitize(&render_chain(&error)),
                };
            }
        };
        if interfaces.is_empty() {
            return Self::Unknown {
                reason: "no interface names available".to_string(),
            };
        }

        let targets: BTreeSet<_> = ports
            .iter()
            .filter(|row| {
                row.listener == Listener::HostSocket
                    && !matches!(row.service, Service::Container(_))
            })
            .map(|row| {
                let endpoint = row.endpoint;
                (
                    endpoint.port,
                    endpoint.protocol,
                    endpoint.address.to_canonical().is_ipv6(),
                )
            })
            .collect();
        let v4 = rules.input(AddressFamily::Ipv4);
        let v6 = rules.input(AddressFamily::Ipv6);
        if let (Err(v4_reason), Err(v6_reason)) = (&v4, &v6)
            && v4_reason == v6_reason
        {
            return Self::Unknown {
                reason: (*v4_reason).to_string(),
            };
        }
        let ports = targets
            .into_iter()
            .map(|(port, protocol, ipv6)| {
                let (family, chain) = if ipv6 {
                    (AddressFamily::Ipv6, &v6)
                } else {
                    (AddressFamily::Ipv4, &v4)
                };
                let interfaces = interfaces
                    .iter()
                    .map(|name| InterfaceInput {
                        interface: sanitize(name),
                        outcome: chain.as_ref().map_or_else(
                            |reason| InputVerdict::Unknown { reason },
                            |input| input.evaluate(protocol, port, name),
                        ),
                    })
                    .collect();
                PortInput {
                    port,
                    protocol,
                    family,
                    interfaces,
                }
            })
            .collect();
        Self::Checked { ports }
    }
}

impl fmt::Display for NftablesReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown { reason } => writeln!(f, "nftables input: unknown ({reason})"),
            Self::Checked { ports } if ports.is_empty() => Ok(()),
            Self::Checked { ports } => {
                writeln!(f, "nftables input for host socket ports:")?;
                for entry in ports {
                    let family = match entry.family {
                        AddressFamily::Ipv4 => "IPv4",
                        AddressFamily::Ipv6 => "IPv6",
                    };
                    let interfaces = entry
                        .interfaces
                        .iter()
                        .map(|check| format!("{} {}", check.interface, check.outcome))
                        .collect::<Vec<_>>()
                        .join(", ");
                    writeln!(
                        f,
                        "  {}/{} {family}: {interfaces}",
                        entry.port, entry.protocol
                    )?;
                }
                Ok(())
            }
        }
    }
}

impl fmt::Display for InputVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (verdict, reason) = match self {
            Self::Accept { reason } => ("accept", reason),
            Self::Drop { reason } => ("drop", reason),
            Self::Unknown { reason } => ("unknown", reason),
        };
        write!(f, "{verdict} ({reason})")
    }
}

#[cfg(test)]
mod tests;
