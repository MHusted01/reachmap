//! What is known about this host's firewall: whether UFW is active, and
//! whether Docker's `DOCKER-USER` chain holds rules of its own. Missing facts
//! stay unknown, with the reason; they never count as "off" or "empty".

use std::io::ErrorKind;

use crate::collect::{self, CollectError};
use crate::errors::render_chain;
use crate::parse::iptables::parse_docker_user;
use crate::parse::ufw::parse_ufw_conf;

/// What `iptables` prints when a chain does not exist.
const NO_SUCH_CHAIN: &str = "no chain/target/match";

/// Why a missing chain is reported. It does not mean nothing filters: Docker
/// may use nftables, or another `iptables` backend than this command.
const NO_CHAIN_REASON: &str =
    "there is no such chain in iptables, Docker may use another firewall backend";

/// Whether UFW filters this host's traffic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UfwState {
    /// UFW's configuration says it is enabled.
    Active,
    /// UFW's configuration says it is disabled, or UFW is not installed.
    Inactive,
    /// UFW's configuration could not be read or understood, for this reason.
    Unknown(String),
}

impl From<CollectError> for UfwState {
    /// A missing configuration file means UFW is not installed. Any other
    /// failure says nothing about UFW.
    fn from(error: CollectError) -> Self {
        match error {
            CollectError::Read { source, .. } if source.kind() == ErrorKind::NotFound => {
                UfwState::Inactive
            }
            other => UfwState::Unknown(render_chain(&other)),
        }
    }
}

/// What `DOCKER-USER`, the chain for filtering Docker's traffic, holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DockerUserChain {
    /// The chain exists and holds at most Docker's default rule.
    NoRules,
    /// The chain holds rules. reachmap does not evaluate them.
    HasRules,
    /// The chain is missing or could not be read, for this reason.
    Unchecked(String),
}

impl From<CollectError> for DockerUserChain {
    fn from(error: CollectError) -> Self {
        match error {
            CollectError::CommandFailed { stderr, .. }
                if stderr.to_lowercase().contains(NO_SUCH_CHAIN) =>
            {
                DockerUserChain::Unchecked(NO_CHAIN_REASON.to_string())
            }
            CollectError::CommandFailed { stderr, .. }
                if stderr.to_lowercase().contains("permission denied") =>
            {
                DockerUserChain::Unchecked("run with sudo".to_string())
            }
            other => DockerUserChain::Unchecked(render_chain(&other)),
        }
    }
}

/// The firewall facts a scan bases its warnings on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Firewall {
    /// Whether UFW is active.
    pub ufw: UfwState,
    /// The `DOCKER-USER` chain, or `None` when no port made it matter.
    pub docker_user: Option<DockerUserChain>,
}

/// Reads whether UFW is active from its configuration file.
pub fn read_ufw_state() -> UfwState {
    collect::read_ufw_conf().map_or_else(UfwState::from, |text| parse_ufw_conf(&text))
}

/// Reads the rules of the `DOCKER-USER` chain. Needs root.
pub fn read_docker_user_chain() -> DockerUserChain {
    collect::read_docker_user_rules()
        .map_or_else(DockerUserChain::from, |rules| parse_docker_user(&rules))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use std::process::{Command, ExitStatus};

    fn failure_status() -> ExitStatus {
        Command::new("sh").args(["-c", "exit 1"]).status().unwrap()
    }

    fn read_failed(kind: ErrorKind) -> CollectError {
        CollectError::Read {
            path: "/etc/ufw/ufw.conf".into(),
            source: io::Error::new(kind, "refused"),
        }
    }

    fn iptables_failed(stderr: &str) -> CollectError {
        CollectError::CommandFailed {
            command: "iptables -S DOCKER-USER".to_string(),
            status: failure_status(),
            stderr: stderr.to_string(),
        }
    }

    #[test]
    fn a_missing_ufw_config_means_ufw_is_not_installed() {
        assert_eq!(
            UfwState::from(read_failed(ErrorKind::NotFound)),
            UfwState::Inactive
        );
    }

    #[test]
    fn an_unreadable_ufw_config_leaves_the_state_unknown() {
        assert_eq!(
            UfwState::from(read_failed(ErrorKind::PermissionDenied)),
            UfwState::Unknown("could not read /etc/ufw/ufw.conf: refused".to_string())
        );
    }

    #[test]
    fn a_missing_chain_is_a_gap_not_an_empty_chain() {
        let error = iptables_failed("iptables: No chain/target/match by that name.");
        assert_eq!(
            DockerUserChain::from(error),
            DockerUserChain::Unchecked(
                "there is no such chain in iptables, Docker may use another firewall backend"
                    .to_string()
            )
        );
    }

    #[test]
    fn iptables_without_root_asks_for_sudo() {
        let error = iptables_failed("iptables: Permission denied (you must be root).");
        assert_eq!(
            DockerUserChain::from(error),
            DockerUserChain::Unchecked("run with sudo".to_string())
        );
    }

    #[test]
    fn any_other_iptables_failure_is_reported_as_it_is() {
        let error = CollectError::Run {
            command: "iptables -S DOCKER-USER".to_string(),
            source: io::Error::new(ErrorKind::NotFound, "not found"),
        };
        assert_eq!(
            DockerUserChain::from(error),
            DockerUserChain::Unchecked(
                "could not run `iptables -S DOCKER-USER`: not found".to_string()
            )
        );
    }
}
