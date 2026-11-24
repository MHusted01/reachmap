//! macOS socket inventory, application firewall status, and pf input verdicts.

use std::fmt;

use serde::{Deserialize, Serialize};

#[cfg(target_os = "macos")]
use super::{HostCollector, ScanError};
use super::{Listener, ScanReport, ScannedPort};
#[cfg(target_os = "macos")]
use crate::collect::macos as collect;
#[cfg(target_os = "macos")]
use crate::errors::render_chain;
#[cfg(target_os = "macos")]
use crate::parse::lsof;
use crate::pf::PfReport;
#[cfg(target_os = "macos")]
use crate::pf::{CollectedPf, SocketTarget, parse_ifconfig};
use crate::{
    reach::{Reason, classify},
    service::{Process, Service},
    socket::Endpoint,
};

/// Scope of a scan on macOS.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacosReport {
    /// Why a socket may be missing from the inventory.
    pub socket_visibility: String,
    /// The global application firewall setting.
    pub application_firewall: ApplicationFirewall,
    /// Packet filter (`pf`) status and per-socket input verdicts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pf: Option<PfReport>,
}

impl MacosReport {
    /// Builds a macOS [`ScanReport`] from parsed sockets, application firewall
    /// status, optional [`PfReport`], and optional `lsof` diagnostic.
    #[must_use]
    pub fn scan_report(
        sockets: Vec<(Endpoint, Process)>,
        application_firewall: ApplicationFirewall,
        pf: Option<PfReport>,
        diagnostic: Option<&str>,
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
        let mut socket_visibility =
            "Inventory covers processes lsof can inspect. Other listeners may be missing."
                .to_owned();
        if let Some(diagnostic) = diagnostic {
            socket_visibility.push(' ');
            socket_visibility.push_str(diagnostic);
        }
        ScanReport {
            ports,
            interfaces_error: None,
            docker_error: None,
            socket_options_error: None,
            tailscale_error: None,
            nftables: None,
            docker_publishes: Vec::new(),
            macos: Some(Self {
                socket_visibility,
                application_firewall,
                pf,
            }),
            warnings: Vec::new(),
        }
    }
}

/// The global application firewall setting, independent of individual sockets.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
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
        let (output, diagnostic) = collect::read_sockets()?;
        let sockets_with_zones =
            lsof::parse_with_zones(&output).map_err(|error| ScanError::SocketInventory {
                record: error.record,
            })?;
        let firewall = collect::read_firewall().map_or_else(
            |error| ApplicationFirewall::Unknown {
                reason: render_chain(&error),
            },
            |text| parse_firewall(&text),
        );
        let pf_result = collect::read_pf();
        let targets: Vec<SocketTarget> = sockets_with_zones
            .iter()
            .map(|(endpoint, _, zone)| SocketTarget {
                endpoint: *endpoint,
                zone: zone.clone(),
            })
            .collect();
        let pf = match pf_result {
            Ok(CollectedPf::Enabled { .. }) => {
                let interfaces = collect::read_interfaces()
                    .map(|text| parse_ifconfig(&text))
                    .map_err(|error| render_chain(&error));
                PfReport::evaluate(
                    pf_result,
                    &targets,
                    interfaces.as_ref().map_err(String::as_str),
                )
            }
            other => PfReport::evaluate(other, &targets, Err("interfaces were not read")),
        };
        let sockets = sockets_with_zones
            .into_iter()
            .map(|(endpoint, process, _)| (endpoint, process))
            .collect();
        Ok(MacosReport::scan_report(
            sockets,
            firewall,
            Some(pf),
            diagnostic.as_deref(),
        ))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pf::{PfInterfaceVerdict, PfPort, Verdict};
    use crate::reach::Reach;
    use crate::socket::{AddressFamily, Protocol};

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
        let report = MacosReport::scan_report(sockets, ApplicationFirewall::Disabled, None, None);
        assert_eq!(report.ports[0].verdict.reach, Reach::Unknown);
        assert_eq!(report.ports[0].verdict.reason, Reason::MacosInventory);
    }

    #[test]
    fn a_partial_inventory_diagnostic_appears_in_both_formats() {
        let diagnostic = "Partial inventory (exit status 1): access denied";
        let report = MacosReport::scan_report(
            Vec::new(),
            ApplicationFirewall::Disabled,
            Some(PfReport::Disabled),
            Some(diagnostic),
        );
        let rendered = crate::table::Report(&report).to_string();
        assert!(rendered.contains(diagnostic));
        assert!(rendered.contains("macOS pf: disabled"));
        let json: serde_json::Value =
            serde_json::from_str(&crate::json::render(&report).unwrap()).unwrap();
        assert!(
            json["macos"]["socket_visibility"]
                .as_str()
                .is_some_and(|text| text.ends_with(diagnostic))
        );
        assert_eq!(json["macos"]["pf"]["status"], "disabled");
    }

    #[test]
    fn legacy_macos_json_without_pf_deserializes_with_none() {
        let legacy = r#"{
            "socket_visibility": "Inventory covers processes lsof can inspect.",
            "application_firewall": { "state": "enabled" }
        }"#;
        let parsed: MacosReport = serde_json::from_str(legacy).unwrap();
        assert_eq!(parsed.pf, None);
        assert_eq!(parsed.application_firewall, ApplicationFirewall::Enabled);
    }

    #[test]
    fn pf_and_application_firewall_stay_distinct_in_table_and_json() {
        let pf = PfReport::Enabled {
            ports: vec![PfPort {
                port: 8080,
                protocol: Protocol::Tcp,
                address: "192.0.2.10".parse().unwrap(),
                family: AddressFamily::Ipv4,
                interfaces: vec![PfInterfaceVerdict {
                    interface: Some("en0".to_owned()),
                    outcome: Verdict::Block {
                        reason: "matched block rule at line 3".to_owned(),
                    },
                }],
            }],
        };
        let report =
            MacosReport::scan_report(Vec::new(), ApplicationFirewall::Disabled, Some(pf), None);
        let text = crate::table::Report(&report).to_string();
        assert!(text.contains("macOS application firewall: disabled"));
        assert!(text.contains("macOS pf: enabled"));
        assert!(
            text.contains("8080/tcp 192.0.2.10 (IPv4): en0 block (matched block rule at line 3)")
        );
    }
}
