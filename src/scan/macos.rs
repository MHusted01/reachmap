//! macOS socket inventory and application firewall status.

use std::fmt;

use serde::Serialize;

#[cfg(target_os = "macos")]
use super::{HostCollector, ScanError};
#[cfg(any(target_os = "macos", test))]
use super::{Listener, ScanReport, ScannedPort};
#[cfg(target_os = "macos")]
use crate::collect::macos as collect;
#[cfg(target_os = "macos")]
use crate::parse::lsof;
#[cfg(any(target_os = "macos", test))]
use crate::{
    reach::{Reason, classify},
    service::{Process, Service},
    socket::Endpoint,
};

/// Scope of a scan on macOS.
#[derive(Debug, Serialize)]
pub struct MacosReport {
    /// Why a socket may be missing from the inventory.
    pub socket_visibility: &'static str,
    /// The global application firewall setting.
    pub application_firewall: ApplicationFirewall,
}

/// The global application firewall setting, independent of individual sockets.
#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ApplicationFirewall {
    /// The application firewall is enabled.
    Enabled,
    /// The application firewall is disabled.
    Disabled,
    /// The setting could not be determined.
    Unknown {
        /// Why the setting could not be determined.
        reason: String,
    },
}

impl fmt::Display for ApplicationFirewall {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Enabled => f.write_str("enabled"),
            Self::Disabled => f.write_str("disabled"),
            Self::Unknown { reason } => write!(f, "unknown ({reason})"),
        }
    }
}

#[cfg(target_os = "macos")]
pub(super) struct Macos;

#[cfg(target_os = "macos")]
impl HostCollector for Macos {
    fn scan(&self) -> Result<ScanReport, ScanError> {
        let output = collect::read_sockets()?;
        let sockets = lsof::parse(&output).map_err(|error| ScanError::SocketInventory {
            record: error.record,
        })?;
        let firewall = collect::read_firewall().map_or_else(
            |error| ApplicationFirewall::Unknown {
                reason: crate::errors::render_chain(&error),
            },
            |text| parse_firewall(&text),
        );
        Ok(report(sockets, firewall))
    }
}

#[cfg(any(target_os = "macos", test))]
fn parse_firewall(text: &str) -> ApplicationFirewall {
    let state = text
        .trim()
        .rsplit_once(" (State = ")
        .and_then(|(_, state)| state.strip_suffix(')'));
    match state {
        Some("0") => ApplicationFirewall::Disabled,
        Some("1" | "2") => ApplicationFirewall::Enabled,
        _ => ApplicationFirewall::Unknown {
            reason: "unrecognised socketfilterfw output".to_owned(),
        },
    }
}

#[cfg(any(target_os = "macos", test))]
fn report(
    sockets: Vec<(Endpoint, Process)>,
    application_firewall: ApplicationFirewall,
) -> ScanReport {
    let ports = sockets
        .into_iter()
        .map(|(endpoint, process)| {
            let mut verdict = classify(endpoint.address, None, None);
            if verdict.reason == Reason::InterfacesUnknown {
                verdict.reason = Reason::MacosInventory;
            }
            ScannedPort {
                endpoint,
                listener: Listener::HostSocket,
                service: Service::Process(process),
                verdict,
                warning: None,
            }
        })
        .collect();
    ScanReport {
        ports,
        interfaces_error: None,
        docker_error: None,
        socket_options_error: None,
        tailscale_error: None,
        nftables: None,
        docker_publishes: Vec::new(),
        macos: Some(MacosReport {
            socket_visibility: "Inventory covers processes lsof can inspect. Other listeners may be missing.",
            application_firewall,
        }),
        warnings: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reach::Reach;

    #[test]
    fn recognises_global_firewall_states_and_reports_unexpected_output() {
        for (text, state) in [
            (
                "Firewall is disabled. (State = 0)\n",
                ApplicationFirewall::Disabled,
            ),
            (
                "Firewall is enabled. (State = 1) \n",
                ApplicationFirewall::Enabled,
            ),
            (
                "Firewall is blocking all incoming connections. (State = 2)\n",
                ApplicationFirewall::Enabled,
            ),
        ] {
            assert_eq!(parse_firewall(text), state);
        }
        assert!(matches!(
            parse_firewall(""),
            ApplicationFirewall::Unknown { .. }
        ));
        assert!(matches!(
            parse_firewall("Firewall is enabled. (State = 7)"),
            ApplicationFirewall::Unknown { .. }
        ));
    }

    #[test]
    fn a_disabled_firewall_does_not_make_a_wildcard_port_reachable() {
        let sockets =
            crate::parse::lsof::parse("p42\0cfixture\0\nf3\0tIPv6\0PUDP\0n*:31001\0\n").unwrap();
        let report = report(sockets, ApplicationFirewall::Disabled);
        assert_eq!(report.ports[0].verdict.reach, Reach::Unknown);
        assert_eq!(report.ports[0].verdict.reason, Reason::MacosInventory);
    }
}
