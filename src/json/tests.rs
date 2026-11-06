//! Every variant in its JSON form. Tagged enums only fail at run time when a
//! variant cannot be written, so each one is exercised here.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde_json::{Value, json};

use super::*;
use crate::network::Network;
use crate::reach::{Coverage, Reach, Reason, Verdict};
use crate::scan::Listener;
use crate::service::{Container, Process, Service, UnknownReason};
use crate::socket::{Endpoint, Protocol};
use crate::warning::Warning;

fn to_json(value: impl Serialize) -> Value {
    serde_json::to_value(value).unwrap()
}

fn ports(numbers: [u16; 2]) -> BTreeSet<u16> {
    BTreeSet::from(numbers)
}

fn report(ports: Vec<ScannedPort>, warnings: Vec<ScanWarning>) -> ScanReport {
    ScanReport {
        ports,
        interfaces_error: None,
        docker_error: None,
        socket_options_error: None,
        tailscale_error: None,
        warnings,
    }
}

#[test]
fn every_service_has_a_kind() {
    let process = Service::Process(Process {
        pid: 812,
        name: "sshd".to_string(),
    });
    let container = Service::Container(Container {
        name: "shop-web-1".to_string(),
        compose_service: Some("web".to_string()),
    });
    let needs_root = Service::Unknown {
        reason: UnknownReason::NeedsRoot,
    };
    let no_process = Service::Unknown {
        reason: UnknownReason::NoProcess,
    };

    assert_eq!(
        to_json(process),
        json!({"kind": "process", "pid": 812, "name": "sshd"})
    );
    assert_eq!(
        to_json(container),
        json!({"kind": "container", "name": "shop-web-1", "compose_service": "web"})
    );
    assert_eq!(
        to_json(needs_root),
        json!({"kind": "unknown", "reason": "needs_root"})
    );
    assert_eq!(
        to_json(no_process),
        json!({"kind": "unknown", "reason": "no_process"})
    );
}

#[test]
fn every_network_has_a_stable_name() {
    let networks = Reach::From {
        networks: BTreeSet::from([
            Network::ThisHost,
            Network::Docker,
            Network::Tailnet,
            Network::Lan,
            Network::Internet,
        ]),
    };
    assert_eq!(
        to_json(networks),
        json!({
            "kind": "from",
            "networks": ["this_host", "docker", "tailnet", "lan", "internet"],
        })
    );
    assert_eq!(to_json(Reach::Unknown), json!({"kind": "unknown"}));
}

#[test]
fn every_reason_has_a_kind() {
    let cases = [
        (Reason::Loopback, json!({"kind": "loopback"})),
        (
            Reason::OnInterfaces {
                interfaces: BTreeSet::from(["eth0".to_string()]),
            },
            json!({"kind": "on_interfaces", "interfaces": ["eth0"]}),
        ),
        (
            Reason::AllAddresses {
                covers: Coverage::Ipv4,
                checked: true,
            },
            json!({"kind": "all_addresses", "covers": "ipv4", "checked": true}),
        ),
        (
            Reason::AllAddresses {
                covers: Coverage::Ipv6,
                checked: true,
            },
            json!({"kind": "all_addresses", "covers": "ipv6", "checked": true}),
        ),
        (
            Reason::Broadcast {
                interfaces: BTreeSet::from(["eth0".to_string()]),
            },
            json!({"kind": "broadcast", "interfaces": ["eth0"]}),
        ),
        (
            Reason::LimitedBroadcast,
            json!({"kind": "limited_broadcast"}),
        ),
        (Reason::NotOnHost, json!({"kind": "not_on_host"})),
        (
            Reason::NoAddresses {
                covers: Coverage::Ipv4AndIpv6,
            },
            json!({"kind": "no_addresses", "covers": "ipv4_and_ipv6"}),
        ),
        (
            Reason::NoAddressesOnDevice {
                interface: "eth1".to_string(),
            },
            json!({"kind": "no_addresses_on_device", "interface": "eth1"}),
        ),
        (
            Reason::InterfacesUnknown,
            json!({"kind": "interfaces_unknown"}),
        ),
    ];
    for (reason, expected) in cases {
        assert_eq!(to_json(reason), expected);
    }
}

#[test]
fn every_summary_warning_has_a_kind() {
    let cases = [
        (
            ScanWarning::UfwBypassed {
                ports: ports([80, 443]),
            },
            json!({"kind": "ufw_bypassed", "ports": [80, 443]}),
        ),
        (
            ScanWarning::UfwUnknown {
                ports: ports([80, 443]),
                reason: "no access".to_string(),
            },
            json!({"kind": "ufw_unknown", "ports": [80, 443], "reason": "no access"}),
        ),
        (
            ScanWarning::DockerUnknown { ufw_reason: None },
            json!({"kind": "docker_unknown", "ufw_reason": null}),
        ),
        (
            ScanWarning::DockerUnknown {
                ufw_reason: Some("no access".to_string()),
            },
            json!({"kind": "docker_unknown", "ufw_reason": "no access"}),
        ),
        (
            ScanWarning::DockerUserRules,
            json!({"kind": "docker_user_rules"}),
        ),
        (
            ScanWarning::DockerUserUnchecked {
                reason: "run with sudo".to_string(),
            },
            json!({"kind": "docker_user_unchecked", "reason": "run with sudo"}),
        ),
    ];
    for (warning, expected) in cases {
        assert_eq!(to_json(warning), expected);
    }
}

#[test]
fn a_port_is_one_flat_object_with_its_row_warning() {
    let port = ScannedPort {
        endpoint: Endpoint {
            port: 9000,
            protocol: Protocol::Tcp,
            address: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        },
        listener: Listener::DockerForward,
        service: Service::Unknown {
            reason: UnknownReason::NoProcess,
        },
        verdict: Verdict {
            reach: Reach::Unknown,
            reason: Reason::NotOnHost,
        },
        warning: Some(Warning::UfwUnknown),
    };

    assert_eq!(
        to_json(port),
        json!({
            "port": 9000,
            "protocol": "tcp",
            "address": "::",
            "listener": "docker_forward",
            "service": {"kind": "unknown", "reason": "no_process"},
            "reach": {"kind": "unknown"},
            "reason": {"kind": "not_on_host"},
            "warning": "ufw_unknown",
        })
    );
}

#[test]
fn an_empty_scan_keeps_every_key() {
    let text = render(&report(Vec::new(), Vec::new())).unwrap();

    assert_eq!(
        serde_json::from_str::<Value>(&text).unwrap(),
        json!({
            "schema_version": SCHEMA_VERSION,
            "ports": [],
            "warnings": [],
            "collector_errors": [],
        })
    );
    assert!(text.ends_with("}\n"), "no final newline: {text:?}");
}

#[test]
fn text_that_could_upset_a_terminal_stays_escaped() {
    let port = ScannedPort {
        endpoint: Endpoint {
            port: 80,
            protocol: Protocol::Tcp,
            address: IpAddr::V4(Ipv4Addr::LOCALHOST),
        },
        listener: Listener::HostSocket,
        service: Service::Process(Process {
            pid: 1,
            name: "a\"b\u{1b}".to_string(),
        }),
        verdict: Verdict {
            reach: Reach::Unknown,
            reason: Reason::NotOnHost,
        },
        warning: None,
    };

    let text = render(&report(vec![port], Vec::new())).unwrap();

    assert!(text.contains(r#""name": "a\"b\u001b""#), "{text}");
}
