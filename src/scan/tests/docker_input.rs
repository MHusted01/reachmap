use super::*;
use crate::json::render;
use crate::nftables::check_scan;
use crate::parse::docker::parse_docker_inspect;
use crate::table::Report;
use serde_json::{Value, json};

const DOCKER: &str = include_str!("../../../tests/fixtures/docker_inspect.json");
const INPUT: &str = include_str!("../../../tests/fixtures/nftables_input.json");

fn run(raw: Result<String, CollectError>) -> (ScanReport, Value) {
    let mut host = lan_host();
    host.addresses.push(HostAddress {
        interface: "eth0".to_string(),
        ip: "2001:db8::20".parse().unwrap(),
        broadcast: None,
    });
    host.addresses.push(HostAddress {
        interface: "lo".to_string(),
        ip: Ipv6Addr::LOCALHOST.into(),
        broadcast: None,
    });
    let mut published = parse_docker_inspect(DOCKER).unwrap();
    published.push(PublishedPort {
        protocol: Protocol::Udp,
        address: Ipv6Addr::LOCALHOST.into(),
        port: 8053,
        container: Container {
            name: "dns".to_string(),
            compose_service: None,
        },
    });
    let mut report = join_without_ufw(
        vec![ListeningSocket {
            address: Ipv6Addr::UNSPECIFIED.into(),
            ..socket(8443, 100)
        }],
        &open_files(false),
        Ok(host.clone()),
        Ok(published),
    );
    check_scan(raw, Some(&host), &mut report);
    let document = serde_json::from_str(&render(&report).unwrap()).unwrap();
    (report, document)
}

fn publish(document: &Value, port: u16, address: &str) -> Value {
    document["docker_publishes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|binding| binding["port"] == port && binding["address"] == address)
        .unwrap_or_else(|| panic!("missing Docker binding {address} port {port}"))
        .clone()
}

#[test]
fn ipv4_only_input_flags_ipv6_docker_bindings_even_when_one_socket_serves_both() {
    let (report, document) = run(Ok(INPUT.replace(r#""inet""#, r#""ip""#)));
    assert_eq!(
        report
            .ports
            .iter()
            .filter(|row| row.endpoint.port == 8443)
            .count(),
        1
    );
    assert_eq!(publish(&document, 8443, "0.0.0.0")["protocol"], "tcp");
    assert_eq!(publish(&document, 8443, "::")["protocol"], "tcp");
    assert_eq!(publish(&document, 8053, "::1")["protocol"], "udp");
    assert!(
        publish(&document, 8443, "0.0.0.0")
            .get("host_input")
            .is_none()
    );
    assert_eq!(
        publish(&document, 8443, "::")["host_input"],
        json!({"status": "ipv4_only"})
    );
    assert_eq!(
        document["warnings"],
        json!([{"kind": "docker_ipv6_input_gap", "bindings": [
            {"port": 8053, "protocol": "udp", "address": "::1"},
            {"port": 8443, "protocol": "tcp", "address": "::"},
            {"port": 9100, "protocol": "tcp", "address": "::1"}
        ]}])
    );
    let text = Report(&report).to_string();
    assert!(text.contains(
        "warning: nftables has IPv4-only host input coverage for these IPv6 Docker publishes"
    ));
    for binding in ["8443/tcp 0.0.0.0", "8443/tcp ::", "8053/udp ::1"] {
        assert!(text.contains(binding), "missing {binding} in {text}");
    }
}

#[test]
fn applicable_ipv6_and_dual_family_input_evidence_do_not_warn() {
    for rules in [INPUT.to_string(), INPUT.replace(r#""inet""#, r#""ip6""#)] {
        let (report, document) = run(Ok(rules));
        assert!(report.warnings.is_empty());
        assert_eq!(
            publish(&document, 8443, "::")["host_input"],
            json!({"status": "ipv6_evidence"})
        );
    }
}

#[test]
fn an_ipv6_wildcard_publish_without_a_socket_does_not_include_ipv4_interfaces() {
    let mut host = lan_host();
    host.addresses.push(HostAddress {
        interface: "lo".to_string(),
        ip: Ipv6Addr::LOCALHOST.into(),
        broadcast: None,
    });
    let published = parse_docker_inspect(DOCKER).unwrap();
    let report = join_without_ufw(Vec::new(), &open_files(false), Ok(host), Ok(published));
    let row = report
        .ports
        .iter()
        .find(|row| row.endpoint.port == 8443 && row.endpoint.address.is_ipv6())
        .unwrap();
    assert_eq!(row.listener, Listener::DockerForward);
    assert_eq!(
        row.verdict.reach,
        Reach::From {
            networks: BTreeSet::from([Network::ThisHost])
        }
    );
    assert_eq!(
        row.verdict.reason,
        Reason::AllAddresses {
            covers: Coverage::Ipv6,
            checked: false
        }
    );
}

#[test]
fn unavailable_or_ambiguous_input_evidence_is_unknown_with_its_cause() {
    let permission_denied = CollectError::Run {
        command: "nft -j list ruleset".to_string(),
        source: io::Error::from(io::ErrorKind::PermissionDenied),
    };
    let cases = [
        (Err(permission_denied), "permission denied"),
        (
            Ok(r#"{"nftables":[]}"#.to_string()),
            "no applicable input chain",
        ),
        (Ok("not JSON".to_string()), "could not understand the JSON"),
        (
            Ok(INPUT.replace(r#""type": "filter""#, r#""type": "nat""#)),
            "unsupported input chain type",
        ),
        (
            Ok(INPUT.replace(r#""hook": "output""#, r#""hook": "input""#)),
            "multiple applicable input chains",
        ),
        (
            Ok(INPUT
                .replace("9090", "8443")
                .replace(r#"{"accept": null}"#, r#"{"jump": {"target": "extra"}}"#)),
            "unsupported input rule",
        ),
    ];
    for (raw, reason) in cases {
        let (report, document) = run(raw);
        assert!(report.warnings.is_empty());
        let binding = publish(&document, 8443, "::");
        let outcome = &binding["host_input"];
        assert_eq!(outcome["status"], "unknown");
        assert!(
            outcome["reason"].as_str().unwrap().contains(reason),
            "{outcome:?}"
        );
    }
}
