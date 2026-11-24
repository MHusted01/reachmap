//! macOS socket inventory, application firewall status, and pf input verdicts.

#[cfg(any(target_os = "macos", test))]
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
#[cfg(any(target_os = "macos", test))]
use std::net::{IpAddr, Ipv6Addr};

use serde::{Deserialize, Serialize};

#[cfg(target_os = "macos")]
use super::HostCollector;
#[cfg(any(target_os = "macos", test))]
use super::ScanError;
use super::{Listener, ScanReport, ScannedPort};
#[cfg(target_os = "macos")]
use crate::collect::macos as collect;
#[cfg(target_os = "macos")]
use crate::errors::render_chain;
#[cfg(any(target_os = "macos", test))]
use crate::parse::lsof;
use crate::pf::PfReport;
#[cfg(any(target_os = "macos", test))]
use crate::pf::{CollectedPf, PfCollectError, SocketTarget, parse_ifconfig};
#[cfg(any(target_os = "macos", test))]
use crate::socket::Protocol;
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
        let firewall = collect::read_firewall().map_err(|error| render_chain(&error));
        let pf_result = collect::read_pf();
        assemble_scan(&output, diagnostic.as_deref(), firewall, pf_result, || {
            collect::read_interfaces().map_err(|error| render_chain(&error))
        })
    }
}

#[cfg(any(target_os = "macos", test))]
fn assemble_scan(
    lsof_output: &str,
    diagnostic: Option<&str>,
    firewall_output: Result<String, String>,
    pf_result: Result<CollectedPf, PfCollectError>,
    read_interfaces: impl FnOnce() -> Result<String, String>,
) -> Result<ScanReport, ScanError> {
    let sockets = lsof::parse(lsof_output).map_err(|error| ScanError::SocketInventory {
        record: error.record,
    })?;
    let firewall = firewall_output.map_or_else(
        |reason| ApplicationFirewall::Unknown { reason },
        |text| parse_firewall(&text),
    );
    let zone_map = extract_lsof_zones(lsof_output);
    let unique_endpoints: BTreeSet<Endpoint> =
        sockets.iter().map(|(endpoint, _)| *endpoint).collect();
    let mut targets = Vec::new();
    for endpoint in unique_endpoints {
        if let Some(zones) = zone_map.get(&endpoint)
            && !zones.is_empty()
        {
            for zone in zones {
                targets.push(SocketTarget {
                    endpoint,
                    zone: zone.clone(),
                });
            }
        } else {
            targets.push(SocketTarget {
                endpoint,
                zone: None,
            });
        }
    }
    let pf = match pf_result {
        Ok(CollectedPf::Enabled { .. }) => {
            let interfaces = read_interfaces().map(|text| parse_ifconfig(&text));
            PfReport::evaluate(
                pf_result,
                &targets,
                interfaces.as_ref().map_err(String::as_str),
            )
        }
        other => PfReport::evaluate(other, &targets, Err("interfaces were not read")),
    };
    Ok(MacosReport::scan_report(
        sockets,
        firewall,
        Some(pf),
        diagnostic,
    ))
}

#[cfg(any(target_os = "macos", test))]
fn extract_lsof_zones(text: &str) -> BTreeMap<Endpoint, BTreeSet<Option<String>>> {
    let mut zones: BTreeMap<Endpoint, BTreeSet<Option<String>>> = BTreeMap::new();
    let Some(stripped) = text.strip_suffix("\0\n") else {
        return zones;
    };
    for record in stripped.split("\0\n") {
        let mut fields = record.split('\0');
        let Some(header) = fields.next() else {
            continue;
        };
        if !header.starts_with('f') {
            continue;
        }
        let mut protocol = "";
        let mut family = "";
        let mut name = "";
        let mut listening = false;
        for field in fields {
            match field.as_bytes().first() {
                Some(b'P') => protocol = &field[1..],
                Some(b't') => family = &field[1..],
                Some(b'n') => name = &field[1..],
                Some(b'T') if field == "TST=LISTEN" => listening = true,
                _ => {}
            }
        }
        if family != "IPv6" {
            continue;
        }
        let protocol = match protocol {
            "TCP" if listening => Protocol::Tcp,
            "UDP" if !name.contains("->") => Protocol::Udp,
            _ => continue,
        };
        let Some((host, port_str)) = name.rsplit_once(':') else {
            continue;
        };
        if port_str == "*" || port_str == "0" {
            continue;
        }
        let Ok(port) = port_str.parse::<u16>() else {
            continue;
        };
        let Some(inner) = host.strip_prefix('[').and_then(|s| s.strip_suffix(']')) else {
            continue;
        };
        let (addr_str, zone) = inner.split_once('%').map_or((inner, None), |(addr, z)| {
            (addr, (!z.is_empty()).then(|| z.to_owned()))
        });
        let Ok(ip) = addr_str.parse::<Ipv6Addr>() else {
            continue;
        };
        zones
            .entry(Endpoint {
                port,
                protocol,
                address: IpAddr::V6(ip),
            })
            .or_default()
            .insert(zone);
    }
    zones
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

    #[test]
    fn assemble_scan_connects_lsof_firewall_and_pf_fixtures_end_to_end() {
        use std::time::Duration;

        use crate::collect::CollectError;
        use crate::pf::{PfCommand, PfRunner, collect_with};

        struct FixtureRunner {
            denied: bool,
        }

        impl PfRunner for FixtureRunner {
            fn run(
                &mut self,
                command: PfCommand<'_>,
                _timeout: Duration,
            ) -> Result<String, CollectError> {
                if self.denied {
                    return Err(CollectError::CommandFailed {
                        command: "/sbin/pfctl -s info".to_owned(),
                        status: std::process::ExitStatus::default(),
                        stderr: "pfctl: /dev/pf: Operation not permitted".to_owned(),
                    });
                }
                match command {
                    PfCommand::Info => Ok(include_str!(
                        "../../tests/fixtures/pf/pfctl_info_enabled.txt"
                    )
                    .to_owned()),
                    PfCommand::MainRules => {
                        Ok(include_str!("../../tests/fixtures/pf/default_block.txt").to_owned())
                    }
                    PfCommand::Interfaces => Ok(include_str!(
                        "../../tests/fixtures/pf/pfctl_interfaces_skip_lo0.txt"
                    )
                    .to_owned()),
                    PfCommand::RootAnchors => Ok(include_str!(
                        "../../tests/fixtures/pf/pfctl_anchors_default.txt"
                    )
                    .to_owned()),
                    PfCommand::AnchorChildren("com.apple") => Ok(include_str!(
                        "../../tests/fixtures/pf/pfctl_anchors_com_apple.txt"
                    )
                    .to_owned()),
                    PfCommand::AnchorRules(_) | PfCommand::AnchorChildren(_) => Ok(String::new()),
                }
            }
        }

        let lsof_text = concat!(
            "p42\0cworker\0\n",
            "f3\0tIPv4\0PTCP\0n192.0.2.10:8443\0TST=LISTEN\0\n",
        );
        let enabled = assemble_scan(
            lsof_text,
            None,
            Ok("Firewall is disabled. (State = 0)\n".to_owned()),
            collect_with(&mut FixtureRunner { denied: false }),
            || Ok(include_str!("../../tests/fixtures/pf/ifconfig_macos.txt").to_owned()),
        )
        .unwrap();
        let enabled_table = crate::table::Report(&enabled).to_string();
        assert!(enabled_table.contains("macOS application firewall: disabled"));
        assert!(enabled_table.contains(
            "8443/tcp 192.0.2.10 (IPv4): en0 block (matched block rule at line 3), \
             lo0 pass (the interface is excluded by set skip)"
        ));
        let enabled_json: serde_json::Value =
            serde_json::from_str(&crate::json::render(&enabled).unwrap()).unwrap();
        assert_eq!(enabled_json["macos"]["pf"]["status"], "enabled");
        assert_eq!(
            enabled_json["macos"]["pf"]["ports"][0]["interfaces"][0]["verdict"],
            "block"
        );
        assert_eq!(
            enabled_json["macos"]["pf"]["ports"][0]["interfaces"][0]["reason"],
            "matched block rule at line 3"
        );

        let denied = assemble_scan(
            lsof_text,
            None,
            Ok("Firewall is enabled. (State = 1)\n".to_owned()),
            collect_with(&mut FixtureRunner { denied: true }),
            || unreachable!("interfaces must not be read when pf collection fails"),
        )
        .unwrap();
        let denied_table = crate::table::Report(&denied).to_string();
        assert!(denied_table.contains("macOS pf: unknown (reading pf status and rules requires root privileges (run with sudo)"));
        let denied_json: serde_json::Value =
            serde_json::from_str(&crate::json::render(&denied).unwrap()).unwrap();
        assert_eq!(denied_json["macos"]["pf"]["status"], "unknown");
        assert!(
            denied_json["macos"]["pf"]["reason"]
                .as_str()
                .is_some_and(|reason| reason.contains("sudo"))
        );
    }

    #[test]
    fn assemble_scan_preserves_lsof_zone_for_duplicate_link_local_addresses() {
        use std::time::Duration;

        use crate::collect::CollectError;
        use crate::pf::{PfCommand, PfRunner, collect_with};

        struct RuleRunner;
        impl PfRunner for RuleRunner {
            fn run(
                &mut self,
                command: PfCommand<'_>,
                _timeout: Duration,
            ) -> Result<String, CollectError> {
                match command {
                    PfCommand::Info => Ok(include_str!(
                        "../../tests/fixtures/pf/pfctl_info_enabled.txt"
                    )
                    .to_owned()),
                    PfCommand::MainRules => Ok(concat!(
                        "scrub in all fragment reassemble\n",
                        "block drop in on en0 all\n",
                        "pass in on en1 all\n",
                    )
                    .to_owned()),
                    PfCommand::Interfaces => Ok("en0\nen1\n".to_owned()),
                    PfCommand::RootAnchors => Ok(String::new()),
                    PfCommand::AnchorRules(_) | PfCommand::AnchorChildren(_) => Ok(String::new()),
                }
            }
        }

        let lsof_text = concat!(
            "p42\0cworker\0\n",
            "f3\0tIPv6\0PUDP\0n[fe80::1234%en0]:5353\0\n",
        );
        let ifconfig_both = concat!(
            "en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n",
            "\tinet6 fe80::1234%en0 prefixlen 64 scopeid 0x4\n",
            "\tstatus: active\n",
            "en1: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n",
            "\tinet6 fe80::1234%en1 prefixlen 64 scopeid 0x5\n",
            "\tstatus: active\n",
        );
        let report = assemble_scan(
            lsof_text,
            None,
            Ok("Firewall is disabled. (State = 0)\n".to_owned()),
            collect_with(&mut RuleRunner),
            || Ok(ifconfig_both.to_owned()),
        )
        .unwrap();
        let PfReport::Enabled { ports } = report.macos.as_ref().unwrap().pf.as_ref().unwrap()
        else {
            panic!("expected enabled pf report");
        };
        assert_eq!(ports.len(), 1);
        assert_eq!(ports[0].interfaces.len(), 1);
        assert_eq!(ports[0].interfaces[0].interface.as_deref(), Some("en0"));
        assert!(matches!(
            ports[0].interfaces[0].outcome,
            Verdict::Block { .. }
        ));
    }

    #[test]
    fn assemble_scan_decodes_embedded_lsof_ipv6_scope_against_ifconfig_scopeid() {
        use std::time::Duration;

        use crate::collect::CollectError;
        use crate::pf::{PfCommand, PfRunner, collect_with};

        struct RuleRunner;
        impl PfRunner for RuleRunner {
            fn run(
                &mut self,
                command: PfCommand<'_>,
                _timeout: Duration,
            ) -> Result<String, CollectError> {
                match command {
                    PfCommand::Info => Ok(include_str!(
                        "../../tests/fixtures/pf/pfctl_info_enabled.txt"
                    )
                    .to_owned()),
                    PfCommand::MainRules => Ok(concat!(
                        "scrub in all fragment reassemble\n",
                        "block drop in all\n",
                        "pass in on en0 inet6 proto udp from any to fe80::1234 port = 5353 keep state\n",
                    )
                    .to_owned()),
                    PfCommand::Interfaces => Ok("en0\nen1\n".to_owned()),
                    PfCommand::RootAnchors => Ok(String::new()),
                    PfCommand::AnchorRules(_) | PfCommand::AnchorChildren(_) => Ok(String::new()),
                }
            }
        }

        let lsof_text = concat!(
            "p42\0cworker\0\n",
            "f3\0tIPv6\0PUDP\0n[fe80:4::1234]:5353\0\n",
        );
        let ifconfig_both = concat!(
            "en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n",
            "\tinet6 fe80::1234%en0 prefixlen 64 scopeid 0x4\n",
            "\tstatus: active\n",
            "en1: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n",
            "\tinet6 fe80::1234%en1 prefixlen 64 scopeid 0x5\n",
            "\tstatus: active\n",
        );
        let report = assemble_scan(
            lsof_text,
            None,
            Ok("Firewall is disabled. (State = 0)\n".to_owned()),
            collect_with(&mut RuleRunner),
            || Ok(ifconfig_both.to_owned()),
        )
        .unwrap();
        let PfReport::Enabled { ports } = report.macos.as_ref().unwrap().pf.as_ref().unwrap()
        else {
            panic!("expected enabled pf report");
        };
        assert_eq!(ports.len(), 1);
        assert_eq!(ports[0].interfaces.len(), 1);
        assert_eq!(ports[0].interfaces[0].interface.as_deref(), Some("en0"));
        assert!(matches!(
            ports[0].interfaces[0].outcome,
            Verdict::Pass { .. }
        ));
    }
}
