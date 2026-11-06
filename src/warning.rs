//! Warnings about ports a firewall does not cover. Docker forwards a published
//! port before UFW's rules are consulted, so UFW never applies to one. See
//! `docs/docker-and-ufw.md`.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::docker::{DockerError, PublishedPort};
use crate::firewall::{DockerUserChain, Firewall, UfwState};
use crate::scan::ScannedPort;

/// What is wrong with one published port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Warning {
    /// UFW is active, and Docker forwards this port past it.
    UfwBypassed,
    /// UFW's state is unknown; if it is active, Docker forwards this port past it.
    UfwUnknown,
}

/// One line of the summary under the table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ScanWarning {
    /// UFW is active, and these ports are forwarded past it.
    UfwBypassed {
        /// The port numbers.
        ports: BTreeSet<u16>,
    },
    /// UFW's state is unknown, and these ports would be forwarded past it.
    UfwUnknown {
        /// The port numbers.
        ports: BTreeSet<u16>,
        /// Why the state is unknown.
        reason: String,
    },
    /// Docker could not be asked, so ports that bypass UFW may be missing.
    DockerUnknown {
        /// Why UFW's state is unknown too, when it is.
        ufw_reason: Option<String>,
    },
    /// `DOCKER-USER` holds rules that may filter these ports.
    DockerUserRules,
    /// `DOCKER-USER` could not be read.
    DockerUserUnchecked {
        /// Why not.
        reason: String,
    },
}

/// The warning for one published port, if it deserves one. Every address but
/// loopback counts: Docker forwards a port published on one LAN address past
/// UFW just like one published on all of them.
pub fn docker_ufw_bypass(published: &PublishedPort, ufw: &UfwState) -> Option<Warning> {
    let warning = match ufw {
        UfwState::Active => Some(Warning::UfwBypassed),
        UfwState::Unknown(_) => Some(Warning::UfwUnknown),
        UfwState::Inactive => None,
    };
    warning.filter(|_| !published.address.to_canonical().is_loopback())
}

/// The summary lines for a finished scan.
pub fn summarise(
    ports: &[ScannedPort],
    docker_error: Option<&DockerError>,
    firewall: &Firewall,
) -> Vec<ScanWarning> {
    let chain = firewall
        .docker_user
        .as_ref()
        .and_then(DockerUserChain::warning);
    [
        ports_warning(ports, &firewall.ufw),
        docker_warning(docker_error, &firewall.ufw),
        chain,
    ]
    .into_iter()
    .flatten()
    .collect()
}

/// The line for the rows that carry a warning, if any does.
fn ports_warning(rows: &[ScannedPort], ufw: &UfwState) -> Option<ScanWarning> {
    let ports: BTreeSet<u16> = rows
        .iter()
        .filter(|row| row.warning.is_some())
        .map(|row| row.endpoint.port)
        .collect();
    if ports.is_empty() {
        return None;
    }
    match ufw {
        UfwState::Active => Some(ScanWarning::UfwBypassed { ports }),
        UfwState::Unknown(reason) => Some(ScanWarning::UfwUnknown {
            ports,
            reason: reason.clone(),
        }),
        UfwState::Inactive => None,
    }
}

/// The line for a Docker that could not be asked. Without Docker installed,
/// nothing can bypass UFW, so that is no warning.
fn docker_warning(docker_error: Option<&DockerError>, ufw: &UfwState) -> Option<ScanWarning> {
    docker_error
        .filter(|error| !matches!(error, DockerError::NotInstalled))
        .and_then(|_| match ufw {
            UfwState::Active => Some(ScanWarning::DockerUnknown { ufw_reason: None }),
            UfwState::Unknown(reason) => Some(ScanWarning::DockerUnknown {
                ufw_reason: Some(reason.clone()),
            }),
            UfwState::Inactive => None,
        })
}

impl DockerUserChain {
    /// The line for this chain, if it adds anything.
    fn warning(&self) -> Option<ScanWarning> {
        match self {
            DockerUserChain::NoRules => None,
            DockerUserChain::HasRules => Some(ScanWarning::DockerUserRules),
            DockerUserChain::Unchecked(reason) => Some(ScanWarning::DockerUserUnchecked {
                reason: reason.clone(),
            }),
        }
    }
}

impl fmt::Display for Warning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Warning::UfwBypassed => "Docker port: UFW does not apply",
            Warning::UfwUnknown => "Docker port: UFW would not apply, its state is unknown",
        })
    }
}

impl fmt::Display for ScanWarning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScanWarning::UfwBypassed { ports } => write!(
                f,
                "UFW is active, but it does not apply to these Docker ports: {}",
                joined(ports)
            ),
            ScanWarning::UfwUnknown { ports, reason } => write!(
                f,
                "could not tell whether UFW is active ({reason}); if it is, it does not apply \
                 to these Docker ports: {}",
                joined(ports)
            ),
            ScanWarning::DockerUnknown { ufw_reason: None } => f.write_str(
                "UFW is active and Docker could not be asked, so it is unknown which published \
                 ports bypass UFW",
            ),
            ScanWarning::DockerUnknown {
                ufw_reason: Some(reason),
            } => write!(
                f,
                "could not tell whether UFW is active ({reason}) and Docker could not be asked, \
                 so it is unknown which published ports bypass UFW"
            ),
            ScanWarning::DockerUserRules => {
                f.write_str("DOCKER-USER has rules, so filtering may apply, not verified")
            }
            ScanWarning::DockerUserUnchecked { reason } => {
                write!(f, "DOCKER-USER rules were not checked: {reason}")
            }
        }
    }
}

/// The port numbers separated by `", "`.
fn joined(ports: &BTreeSet<u16>) -> String {
    ports
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests;
