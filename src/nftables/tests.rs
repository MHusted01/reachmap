use std::io;

use serde_json::{Value, json};

use crate::collect::CollectError;
use crate::json::render;
use crate::network::{HostAddress, HostInterfaces};
use crate::parse::nftables::parse_ruleset;
use crate::reach::{SocketScope, classify};
use crate::scan::{Listener, ScanReport, ScannedPort};
use crate::service::{Container, Service, UnknownReason};
use crate::socket::{AddressFamily, Endpoint, Protocol};
use crate::table::Report;

use super::{InputChains, InputVerdict, NftablesReport, read_rules};

const RULESET: &str = include_str!("../../tests/fixtures/nftables_input.json");

#[test]
fn matches_protocol_port_and_interface_in_rule_order() {
    let rules = parse_ruleset(RULESET).unwrap();
    let input = rules.input(AddressFamily::Ipv4).unwrap();
    assert_eq!(
        input.evaluate(Protocol::Tcp, 8443, "eth0"),
        InputVerdict::Accept {
            reason: "matching rule"
        }
    );
    assert_eq!(
        input.evaluate(Protocol::Tcp, 8443, "lo"),
        InputVerdict::Drop {
            reason: "matching rule"
        }
    );
    assert_eq!(
        input.evaluate(Protocol::Udp, 8443, "eth0"),
        InputVerdict::Drop {
            reason: "chain policy"
        }
    );
    assert_eq!(
        input.evaluate(Protocol::Udp, 5353, "eth0"),
        InputVerdict::Accept {
            reason: "matching rule"
        }
    );
}

#[test]
fn unsupported_rule_only_matters_if_reached_and_could_match() {
    let rules = parse_ruleset(RULESET).unwrap();
    let input = rules.input(AddressFamily::Ipv6).unwrap();
    assert_eq!(
        input.evaluate(Protocol::Tcp, 9090, "eth0"),
        InputVerdict::Unknown {
            reason: "unsupported input rule"
        }
    );
    assert_eq!(
        input.evaluate(Protocol::Tcp, 9090, "lo"),
        InputVerdict::Drop {
            reason: "chain policy"
        }
    );
    assert_eq!(
        input.evaluate(Protocol::Tcp, 8443, "eth0"),
        InputVerdict::Accept {
            reason: "matching rule"
        }
    );
}

#[test]
fn only_input_chains_of_the_packet_family_count() {
    let json = RULESET.replace(
        r#"{"chain": {"family": "inet", "table": "sample", "name": "output", "type": "filter", "hook": "output", "prio": 0, "policy": "drop"}}"#,
        r#"{"table": {"family": "ip", "name": "other"}},
        {"chain": {"family": "ip", "table": "other", "name": "inbound", "type": "filter", "hook": "input", "prio": 10, "policy": "accept"}}"#,
    );
    let rules = parse_ruleset(&json).unwrap();
    assert_eq!(
        rules.input(AddressFamily::Ipv4).unwrap_err().reason(),
        "multiple applicable input chains"
    );
    assert!(rules.input(AddressFamily::Ipv6).is_ok());
}

#[test]
fn a_dormant_table_does_not_filter_packets() {
    let json = RULESET.replace(
        r#""name": "sample", "handle": 1"#,
        r#""name": "sample", "handle": 1, "flags": ["dormant"]"#,
    );
    let rules = parse_ruleset(&json).unwrap();
    assert_eq!(
        rules.input(AddressFamily::Ipv4).unwrap_err().reason(),
        "no applicable input chain"
    );
}

#[test]
fn wildcard_interface_matches_are_unverified() {
    let json = RULESET.replace(r#""right": "eth0""#, r#""right": "eth*""#);
    let rules = parse_ruleset(&json).unwrap();
    assert_eq!(
        rules
            .input(AddressFamily::Ipv4)
            .unwrap()
            .evaluate(Protocol::Tcp, 8443, "eth0"),
        InputVerdict::Unknown {
            reason: "unsupported input rule"
        }
    );
}

#[test]
fn missing_chain_and_malformed_ruleset_are_unverified() {
    let rules = parse_ruleset(r#"{"nftables": []}"#).unwrap();
    assert_eq!(
        rules.input(AddressFamily::Ipv4).unwrap_err().reason(),
        "no applicable input chain"
    );
    assert!(parse_ruleset(r#"{"nftables": [{"rule": {"expr": []}}]}"#).is_err());
    assert!(parse_ruleset(r#"{"nftables": [{"metainfo": {"json_schema_version": 2}}]}"#).is_err());
}

fn host() -> HostInterfaces {
    let address = |interface: &str, ip: &str| HostAddress {
        interface: interface.to_string(),
        ip: ip.parse().unwrap(),
        broadcast: None,
    };
    HostInterfaces {
        addresses: vec![
            address("lo", "127.0.0.1"),
            address("lo", "::1"),
            address("eth0", "192.168.1.20"),
            address("eth0", "2001:db8::20"),
        ],
        names: Default::default(),
    }
}

fn row_with_scope(
    port: u16,
    address: &str,
    scope: Option<SocketScope<'_>>,
    listener: Listener,
    service: Service,
) -> ScannedPort {
    let address = address.parse().unwrap();
    ScannedPort {
        endpoint: Endpoint {
            port,
            protocol: Protocol::Tcp,
            address,
        },
        listener,
        service,
        verdict: classify(address, scope, Some(&host().addresses)),
        warning: None,
    }
}

fn row(port: u16, address: &str, listener: Listener, service: Service) -> ScannedPort {
    row_with_scope(port, address, None, listener, service)
}

fn host_row(port: u16, address: &str) -> ScannedPort {
    row(
        port,
        address,
        Listener::HostSocket,
        Service::Unknown {
            reason: UnknownReason::NeedsRoot,
        },
    )
}

fn report_of(ports: Vec<ScannedPort>, nftables: NftablesReport) -> ScanReport {
    ScanReport {
        ports,
        interfaces_error: None,
        docker_error: None,
        socket_options_error: None,
        tailscale_error: None,
        nftables: Some(nftables),
        docker_publishes: Vec::new(),
        macos: None,
        warnings: Vec::new(),
    }
}

fn check(
    raw: Result<String, CollectError>,
    host: Option<&HostInterfaces>,
    ports: &[ScannedPort],
) -> NftablesReport {
    let rules = read_rules(raw);
    let chains = rules.as_ref().map(InputChains::new);
    NftablesReport::check(
        chains.as_ref().map_err(|reason| reason.as_str()),
        host,
        ports,
    )
}

/// The `(address, family, interfaces)` of every entry in the JSON report.
fn entries(report: &NftablesReport) -> Vec<(String, String, Vec<String>)> {
    let json = serde_json::to_value(report).unwrap();
    json["ports"]
        .as_array()
        .unwrap()
        .iter()
        .map(|port| {
            let names = port["interfaces"]
                .as_array()
                .unwrap()
                .iter()
                .map(|check| check["interface"].as_str().unwrap().to_string())
                .collect();
            (
                port["address"].as_str().unwrap().to_string(),
                port["family"].as_str().unwrap().to_string(),
                names,
            )
        })
        .collect()
}

#[test]
fn scan_output_checks_each_socket_on_the_interfaces_it_can_receive_on() {
    let container = Service::Container(Container {
        name: "web".to_string(),
        compose_service: None,
    });
    let ports = vec![
        host_row(8443, "0.0.0.0"),
        host_row(8443, "127.0.0.1"),
        host_row(7000, "10.9.9.9"),
        row(9443, "0.0.0.0", Listener::DockerForward, container.clone()),
        row(9444, "0.0.0.0", Listener::HostSocket, container),
        row(
            443,
            "100.64.0.1",
            Listener::TailscaleShare,
            Service::Tailscale,
        ),
    ];
    let nftables = check(Ok(RULESET.to_string()), Some(&host()), &ports);
    let report = report_of(ports, nftables);

    let text = Report(&report).to_string();
    assert!(text.ends_with(
        "nftables input for host socket ports:\n  \
         8443/tcp 0.0.0.0 (IPv4): eth0 accept (matching rule), lo drop (matching rule)\n  \
         8443/tcp 127.0.0.1 (IPv4): lo drop (matching rule)\n"
    ));
    let json: Value = serde_json::from_str(&render(&report).unwrap()).unwrap();
    assert_eq!(
        json["ports"][1]["reach"],
        json!({"kind": "from", "networks": ["this_host"]})
    );
    assert_eq!(
        json["nftables"],
        json!({
            "status": "checked",
            "ports": [
                {
                    "port": 8443, "protocol": "tcp", "address": "0.0.0.0", "family": "ipv4",
                    "interfaces": [
                        {"interface": "eth0", "verdict": "accept", "reason": "matching rule"},
                        {"interface": "lo", "verdict": "drop", "reason": "matching rule"}
                    ]
                },
                {
                    "port": 8443, "protocol": "tcp", "address": "127.0.0.1", "family": "ipv4",
                    "interfaces": [
                        {"interface": "lo", "verdict": "drop", "reason": "matching rule"}
                    ]
                }
            ]
        })
    );
}

#[test]
fn a_dual_stack_wildcard_is_checked_as_ipv4_and_ipv6() {
    let ports = vec![host_row(8443, "::")];
    let report = check(Ok(RULESET.to_string()), Some(&host()), &ports);
    assert_eq!(
        entries(&report),
        vec![
            (
                "::".to_string(),
                "ipv4".to_string(),
                vec!["eth0".to_string(), "lo".to_string()]
            ),
            (
                "::".to_string(),
                "ipv6".to_string(),
                vec!["eth0".to_string(), "lo".to_string()]
            ),
        ]
    );
    assert!(
        Report(&report_of(ports, report))
            .to_string()
            .contains("8443/tcp :: (IPv4): eth0 accept (matching rule), lo drop (matching rule)")
    );
}

#[test]
fn an_ipv6_only_wildcard_is_checked_as_ipv6_alone() {
    let scope = SocketScope {
        device: None,
        ipv6_only: true,
    };
    let ports = vec![row_with_scope(
        8443,
        "::",
        Some(scope),
        Listener::HostSocket,
        Service::Unknown {
            reason: UnknownReason::NeedsRoot,
        },
    )];
    let report = check(Ok(RULESET.to_string()), Some(&host()), &ports);
    assert_eq!(
        entries(&report),
        vec![(
            "::".to_string(),
            "ipv6".to_string(),
            vec!["eth0".to_string(), "lo".to_string()]
        )]
    );
}

#[test]
fn a_specific_ipv6_address_uses_only_its_interface() {
    let ports = vec![host_row(8443, "2001:db8::20"), host_row(8443, "::1")];
    let report = check(Ok(RULESET.to_string()), Some(&host()), &ports);
    assert_eq!(
        entries(&report),
        vec![
            (
                "::1".to_string(),
                "ipv6".to_string(),
                vec!["lo".to_string()]
            ),
            (
                "2001:db8::20".to_string(),
                "ipv6".to_string(),
                vec!["eth0".to_string()]
            ),
        ]
    );
}

#[test]
fn no_host_socket_ports_is_said_explicitly_without_a_stray_blank_line() {
    let nftables = check(Ok(RULESET.to_string()), Some(&host()), &[]);
    let report = report_of(Vec::new(), nftables);
    let text = Report(&report).to_string();
    assert!(text.ends_with("\nnftables input: no host socket ports to check\n"));
    assert!(!text.ends_with("\n\n"));
}

#[test]
fn unlisted_interfaces_make_the_check_unknown() {
    let ports = vec![host_row(8443, "0.0.0.0")];
    for host in [None, Some(&HostInterfaces::default())] {
        let report = check(Ok(RULESET.to_string()), host, &ports);
        assert_eq!(
            serde_json::to_value(report).unwrap(),
            json!({"status": "unknown", "reason": "no interface addresses available"})
        );
    }
}

#[test]
fn failed_collection_keeps_an_unknown_result_with_a_reason() {
    let error = CollectError::Run {
        command: "/usr/sbin/nft -j list ruleset".to_string(),
        source: io::Error::from(io::ErrorKind::NotFound),
    };
    let report = check(Err(error), None, &[]);
    assert_eq!(
        serde_json::to_value(report).unwrap(),
        json!({
            "status": "unknown",
            "reason": "nft is missing from the standard system paths"
        })
    );
}

#[cfg(unix)]
#[test]
fn a_failed_nft_run_points_at_the_privilege_it_needs() {
    use std::os::unix::process::ExitStatusExt;

    let error = CollectError::CommandFailed {
        command: "/usr/sbin/nft -j list ruleset".to_string(),
        status: std::process::ExitStatus::from_raw(1 << 8),
        stderr: "Operation not permitted".to_string(),
    };
    let report = check(Err(error), None, &[]);
    let json = serde_json::to_value(report).unwrap();
    let reason = json["reason"].as_str().unwrap();
    assert!(reason.contains("Operation not permitted"), "{reason}");
    assert!(reason.contains("root or CAP_NET_ADMIN"), "{reason}");
}
