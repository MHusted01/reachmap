use serde_json::{Value, json};

use crate::parse::nftables::parse_ruleset;
use crate::socket::{AddressFamily, Protocol};

use super::outcome;

// Output of `nft -j list ruleset` from nftables 1.0.9, reformatted for readability.
const RULESET: &str = include_str!("../../../../../tests/fixtures/nftables_input_matches.json");
const ACCEPT: &str = "accept (matching rule)";
const DROP: &str = "drop (chain policy in inet sample input)";
const UNKNOWN: &str = "unknown (unsupported input rule in ip filter INPUT)";
const SAMPLE_UNKNOWN: &str = "unknown (unsupported input rule in inet sample input)";

#[test]
fn port_sets_and_ranges_match_and_negate_membership() {
    let rules = parse_ruleset(RULESET).unwrap();
    let input = rules.input(AddressFamily::Ipv4).unwrap();
    for (interface, protocol, port, verdict) in [
        ("set0", Protocol::Tcp, 24001, ACCEPT),
        ("set0", Protocol::Tcp, 24002, DROP),
        ("set1", Protocol::Udp, 24003, DROP),
        ("set1", Protocol::Udp, 24002, ACCEPT),
        ("set1", Protocol::Tcp, 24002, DROP),
        ("range0", Protocol::Tcp, 24099, DROP),
        ("range0", Protocol::Tcp, 24100, ACCEPT),
        ("range0", Protocol::Tcp, 24102, ACCEPT),
        ("range0", Protocol::Tcp, 24103, DROP),
        ("range1", Protocol::Tcp, 24101, DROP),
        ("range1", Protocol::Tcp, 24103, ACCEPT),
        ("mixed0", Protocol::Tcp, 24600, ACCEPT),
        ("mixed0", Protocol::Tcp, 24611, ACCEPT),
        ("mixed0", Protocol::Tcp, 24613, DROP),
        ("named0", Protocol::Tcp, 24300, ACCEPT),
        ("named0", Protocol::Tcp, 24312, ACCEPT),
        ("named0", Protocol::Tcp, 24313, DROP),
        ("named1", Protocol::Tcp, 24310, DROP),
        ("named1", Protocol::Tcp, 24313, ACCEPT),
    ] {
        assert_eq!(
            input.evaluate(protocol, port, interface).to_string(),
            verdict,
            "{protocol}/{port} on {interface}"
        );
    }
}

#[test]
fn interface_sets_and_negation_match_exact_names() {
    let rules = parse_ruleset(RULESET).unwrap();
    let input = rules.input(AddressFamily::Ipv6).unwrap();
    for (port, interface, verdict) in [
        (24200, "edge0", ACCEPT),
        (24200, "edge1", ACCEPT),
        (24200, "edge2", DROP),
        (24201, "edge0", DROP),
        (24201, "edge1", ACCEPT),
        (24202, "edge1", DROP),
        (24202, "edge2", ACCEPT),
        (24203, "edge0", SAMPLE_UNKNOWN),
    ] {
        assert_eq!(
            input.evaluate(Protocol::Tcp, port, interface).to_string(),
            verdict,
            "tcp/{port} on {interface}"
        );
    }
}

#[test]
fn an_interface_set_reference_and_literal_must_agree() {
    let rules = parse_ruleset(RULESET).unwrap();
    let input = rules.input(AddressFamily::Ipv6).unwrap();
    // `iifname @ingress` and `iifname "@ingress"` have the same JSON representation.
    for (port, interface, verdict) in [
        (24400, "edge1", SAMPLE_UNKNOWN),
        (24400, "@ingress", SAMPLE_UNKNOWN),
        (24400, "edge2", DROP),
        (24401, "edge1", SAMPLE_UNKNOWN),
        (24401, "edge2", ACCEPT),
    ] {
        assert_eq!(
            input.evaluate(Protocol::Tcp, port, interface).to_string(),
            verdict
        );
    }

    let includes_literal = RULESET.replace(
        r#""elem":["edge0","edge1"]"#,
        r#""elem":["edge0","@ingress"]"#,
    );
    let rules = parse_ruleset(&includes_literal).unwrap();
    let input = rules.input(AddressFamily::Ipv6).unwrap();
    assert_eq!(
        input.evaluate(Protocol::Tcp, 24400, "@ingress").to_string(),
        ACCEPT
    );
    assert_eq!(
        input.evaluate(Protocol::Tcp, 24401, "@ingress").to_string(),
        DROP
    );
}

#[test]
fn transport_header_ports_use_the_l4proto_match() {
    let rules = parse_ruleset(RULESET).unwrap();
    let input = rules.input(AddressFamily::Ipv4).unwrap();
    for (interface, protocol, port, verdict) in [
        ("transport0", Protocol::Tcp, 24500, ACCEPT),
        ("transport0", Protocol::Udp, 24500, DROP),
        ("transport1", Protocol::Tcp, 24500, DROP),
        ("transport1", Protocol::Udp, 24500, ACCEPT),
        ("transport2", Protocol::Tcp, 24500, ACCEPT),
        ("transport2", Protocol::Udp, 24502, ACCEPT),
        ("transport2", Protocol::Udp, 24501, DROP),
        ("transport3", Protocol::Tcp, 24500, ACCEPT),
        ("transport3", Protocol::Udp, 24500, DROP),
    ] {
        assert_eq!(
            input.evaluate(protocol, port, interface).to_string(),
            verdict,
            "{protocol}/{port} on {interface}"
        );
    }
}

fn port_rule(op: &str, right: Value) -> Value {
    json!({"rule": {"family": "ip", "table": "filter", "chain": "INPUT", "expr": [
        {"match": {"op": op, "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": right}},
        {"accept": null}
    ]}})
}

#[test]
fn named_sets_are_resolved_only_within_the_rules_family_and_table() {
    let named = |family, table, port| json!({"set": {"family": family, "table": table, "name": "ports", "type": "inet_service", "elem": [port]}});
    let matched = port_rule("==", json!("@ports"));
    assert_eq!(
        outcome([
            named("ip", "filter", 8443),
            named("ip6", "filter", 8444),
            matched.clone(),
            named("ip", "other", 8445),
        ]),
        ACCEPT
    );
    assert_eq!(
        outcome([
            named("ip6", "filter", 8443),
            named("ip", "other", 8443),
            matched
        ]),
        UNKNOWN
    );
}

#[test]
fn absent_elements_in_a_supported_named_set_mean_empty() {
    let set = json!({"set": {"family": "ip", "table": "filter", "name": "ports", "type": "inet_service"}});
    assert_eq!(
        outcome([set.clone(), port_rule("==", json!("@ports"))]),
        "drop (chain policy in ip filter INPUT)"
    );
    assert_eq!(outcome([set, port_rule("!=", json!("@ports"))]), ACCEPT);
}

#[test]
fn unsupported_match_shapes_and_named_set_elements_stay_unknown() {
    for right in [
        json!({"set": [8443, {"concat": [8443, 2]}]}),
        json!({"set": [8443], "extra": true}),
        json!({"range": [8443, 8444], "extra": true}),
        json!({"range": [8444, 8442]}),
    ] {
        for op in ["==", "!="] {
            assert_eq!(
                outcome([port_rule(op, right.clone())]),
                UNKNOWN,
                "{op} {right}"
            );
        }
    }
    for set_properties in [
        json!({"type": "inet_service", "elem": [8443, "unresolved"]}),
        json!({"type": "inet_service", "elem": [8443, {"elem": {"val": 8444, "expires": 5}}]}),
        json!({"type": "inet_service", "elem": {"unexpected": 8443}}),
        json!({"type": "inet_service", "elem": null}),
        json!({"type": "inet_service", "flags": ["timeout"], "timeout": 60}),
        json!({"type": "ipv4_addr", "elem": [8443]}),
        json!({"type": ["inet_service", "ifname"], "elem": [{"concat": [8443, "eth0"]}]}),
        json!({"elem": [8443]}),
    ] {
        let mut set = json!({"family": "ip", "table": "filter", "name": "ports"});
        set.as_object_mut()
            .unwrap()
            .extend(set_properties.as_object().unwrap().clone());
        assert_eq!(
            outcome([json!({"set": set}), port_rule("!=", json!("@ports"))]),
            UNKNOWN
        );
    }
}
