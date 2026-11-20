//! Input-chain checks for host sockets.

use std::fmt;
use std::io::ErrorKind;
use std::net::IpAddr;

use serde::Serialize;

use crate::collect::CollectError;
use crate::errors::render_chain;
use crate::network::HostInterfaces;
use crate::parse::nftables::{InputChain, InputChainError, Ruleset, parse_ruleset};
use crate::sanitize::sanitize;
use crate::scan::{ScanReport, ScannedPort};
use crate::socket::{AddressFamily, Protocol};

mod docker;
mod targets;
pub use docker::DockerPublish;
use targets::targets;

const NO_INTERFACES: &str = "no interface addresses available";

struct InputChains<'a> {
    ipv4: Result<InputChain<'a>, InputChainError>,
    ipv6: Result<InputChain<'a>, InputChainError>,
}

impl<'a> InputChains<'a> {
    fn new(rules: &'a Ruleset) -> Self {
        Self {
            ipv4: rules.input(AddressFamily::Ipv4),
            ipv6: rules.input(AddressFamily::Ipv6),
        }
    }
}

pub(crate) fn check_scan(
    raw: Result<String, CollectError>,
    host: Option<&HostInterfaces>,
    report: &mut ScanReport,
) {
    let rules = read_rules(raw);
    let chains = rules.as_ref().map(InputChains::new);
    let evidence = chains.as_ref().map_err(|reason| reason.as_str());
    let host = host.filter(|host| !host.addresses.is_empty());
    report.nftables = Some(NftablesReport::check(evidence, host, &report.ports));
    report
        .warnings
        .extend(docker::check(&mut report.docker_publishes, evidence, host));
}

fn read_rules(raw: Result<String, CollectError>) -> Result<Ruleset, String> {
    let raw = raw.map_err(|error| collect_reason(&error))?;
    parse_ruleset(&raw).map_err(|error| sanitize(&render_chain(&error)))
}

/// The result of inspecting the nftables input hook for host socket ports.
#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum NftablesReport {
    /// The ruleset and interfaces were read. Individual checks can be unknown.
    Checked {
        /// One entry per transport, port, bind address and IP family.
        ports: Vec<PortInput>,
    },
    /// The data needed for the check could not be read.
    Unknown {
        /// Why no checks could be made.
        reason: String,
    },
}

/// Input verdicts for a socket's port and bind address, seen as one IP family.
#[derive(Debug, Serialize)]
pub struct PortInput {
    port: u16,
    protocol: Protocol,
    address: IpAddr,
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
    fn check(
        chains: Result<&InputChains<'_>, &str>,
        host: Option<&HostInterfaces>,
        ports: &[ScannedPort],
    ) -> Self {
        let chains = match chains {
            Ok(chains) => chains,
            Err(reason) => {
                return Self::Unknown {
                    reason: reason.to_string(),
                };
            }
        };
        let Some(host) = host.filter(|host| !host.addresses.is_empty()) else {
            return Self::Unknown {
                reason: NO_INTERFACES.to_string(),
            };
        };

        if let (Err(v4_reason), Err(v6_reason)) = (&chains.ipv4, &chains.ipv6)
            && v4_reason == v6_reason
        {
            return Self::Unknown {
                reason: v4_reason.reason().to_string(),
            };
        }
        let ports = targets(ports, host)
            .into_iter()
            .map(|target| {
                let chain = match target.family {
                    AddressFamily::Ipv4 => &chains.ipv4,
                    AddressFamily::Ipv6 => &chains.ipv6,
                };
                let interfaces = target
                    .interfaces
                    .iter()
                    .map(|name| InterfaceInput {
                        interface: sanitize(name),
                        outcome: chain.as_ref().map_or_else(
                            |error| InputVerdict::Unknown {
                                reason: error.reason(),
                            },
                            |input| input.evaluate(target.protocol, target.port, name),
                        ),
                    })
                    .collect();
                PortInput {
                    port: target.port,
                    protocol: target.protocol,
                    address: target.address,
                    family: target.family,
                    interfaces,
                }
            })
            .collect();
        Self::Checked { ports }
    }
}

/// Why the ruleset could not be read. A failed `nft` run most often means the
/// scan lacks the privilege, so the reason says what to try.
fn collect_reason(error: &CollectError) -> String {
    match error {
        CollectError::Run { source, .. } if source.kind() == ErrorKind::NotFound => {
            "nft is missing from the standard system paths".to_string()
        }
        CollectError::CommandFailed { .. } => format!(
            "{}; reading the nftables ruleset usually needs root or CAP_NET_ADMIN",
            sanitize(&render_chain(error))
        ),
        _ => sanitize(&render_chain(error)),
    }
}

impl fmt::Display for NftablesReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown { reason } => writeln!(f, "nftables input: unknown ({reason})"),
            Self::Checked { ports } if ports.is_empty() => {
                writeln!(f, "nftables input: no host socket ports to check")
            }
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
                        "  {}/{} {} ({family}): {interfaces}",
                        entry.port, entry.protocol, entry.address
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
