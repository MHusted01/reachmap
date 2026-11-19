use std::collections::BTreeSet;
use std::io;

use serde_json::{Value, json};

use crate::collect::CollectError;
use crate::json::render;
use crate::parse::nftables::parse_ruleset;
use crate::reach::classify;
use crate::scan::{Listener, ScanReport, ScannedPort};
use crate::service::{Container, Service, UnknownReason};
use crate::socket::{AddressFamily, Endpoint, Protocol};
use crate::table::Report;

use super::{InputVerdict, NftablesReport};

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
        rules.input(AddressFamily::Ipv4).unwrap_err(),
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
        rules.input(AddressFamily::Ipv4).unwrap_err(),
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
        rules.input(AddressFamily::Ipv4).unwrap_err(),
        "no applicable input chain"
    );
    assert!(parse_ruleset(r#"{"nftables": [{"rule": {"expr": []}}]}"#).is_err());
    assert!(parse_ruleset(r#"{"nftables": [{"metainfo": {"json_schema_version": 2}}]}"#).is_err());
}

fn row(port: u16, address: &str, listener: Listener, service: Service) -> ScannedPort {
    let address = address.parse().unwrap();
    ScannedPort {
        endpoint: Endpoint {
            port,
            protocol: Protocol::Tcp,
            address,
        },
        listener,
        service,
        verdict: classify(address, None, None),
        warning: None,
    }
}

#[test]
fn scan_output_checks_native_socket_ports_per_interface_and_preserves_reach() {
    let unknown_owner = Service::Unknown {
        reason: UnknownReason::NeedsRoot,
    };
    let container = Service::Container(Container {
        name: "web".to_string(),
        compose_service: None,
    });
    let ports = vec![
        row(8443, "0.0.0.0", Listener::HostSocket, unknown_owner.clone()),
        row(8443, "127.0.0.1", Listener::HostSocket, unknown_owner),
        row(9443, "0.0.0.0", Listener::DockerForward, container.clone()),
        row(9444, "0.0.0.0", Listener::HostSocket, container),
        row(
            443,
            "100.64.0.1",
            Listener::TailscaleShare,
            Service::Tailscale,
        ),
    ];
    let nftables = NftablesReport::check(
        Ok(RULESET.to_string()),
        &BTreeSet::from(["lo".to_string(), "eth0".to_string()]),
        &ports,
    );
    let report = ScanReport {
        ports,
        interfaces_error: None,
        docker_error: None,
        socket_options_error: None,
        tailscale_error: None,
        nftables: Some(nftables),
        warnings: Vec::new(),
    };

    let text = Report(&report).to_string();
    assert!(text.ends_with("nftables input for host socket ports:\n  8443/tcp IPv4: eth0 accept (matching rule), lo drop (matching rule)\n"));
    let json: Value = serde_json::from_str(&render(&report).unwrap()).unwrap();
    assert_eq!(
        json["ports"][1]["reach"],
        json!({"kind": "from", "networks": ["this_host"]})
    );
    assert_eq!(
        json["nftables"],
        json!({
            "status": "checked",
            "ports": [{
                "port": 8443, "protocol": "tcp", "family": "ipv4",
                "interfaces": [
                    {"interface": "eth0", "verdict": "accept", "reason": "matching rule"},
                    {"interface": "lo", "verdict": "drop", "reason": "matching rule"}
                ]
            }]
        })
    );
}

#[test]
fn failed_collection_keeps_an_unknown_result_with_a_reason() {
    let error = CollectError::Run {
        command: "/usr/sbin/nft -j list ruleset".to_string(),
        source: io::Error::from(io::ErrorKind::NotFound),
    };
    let report = NftablesReport::check(Err(error), &BTreeSet::new(), &[]);
    assert_eq!(
        serde_json::to_value(report).unwrap(),
        json!({
            "status": "unknown",
            "reason": "nft is missing from the standard system paths"
        })
    );
}
