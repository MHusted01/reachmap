use std::net::IpAddr;

use super::*;
use crate::probe::Outcome;
use crate::probe::claims;

const LAN_V4: &str = "10.0.0.10";
const LAN_V6: &str = "fd12::10";
const PUBLIC_V6: &str = "2001:db8::10";
const TAILNET_V4: &str = "100.101.102.103";

/// A scan with a TCP row per port, reachable from `networks` (in JSON).
fn scan(rows: &[(u16, &str)]) -> ScanClaims {
    let rows: Vec<_> = rows
        .iter()
        .map(|(port, networks)| {
            format!(
                r#"{{"port": {port}, "protocol": "tcp",
                    "reach": {{"kind": "from", "networks": [{networks}]}},
                    "reason": {{"kind": "all_addresses"}}}}"#
            )
        })
        .collect();
    claims::parse(&format!(
        r#"{{"schema_version": 1, "ports": [{}], "collector_errors": []}}"#,
        rows.join(",")
    ))
    .unwrap()
}

fn probed(port: u16, address: &str, result: Outcome) -> ProbedPort {
    ProbedPort {
        port,
        address: address.parse::<IpAddr>().unwrap().into(),
        result,
    }
}

fn failed() -> Outcome {
    Outcome::Failed {
        message: "too many open files".to_string(),
    }
}

fn difference(kind: Disagreement, port: u16, from: Network) -> Difference {
    Difference { kind, port, from }
}

#[test]
fn a_connection_the_scan_rules_out_is_a_difference() {
    let results = [probed(5432, LAN_V4, Outcome::Open)];
    let comparison = compare(&scan(&[(5432, r#""this_host""#)]), &results, None);
    assert_eq!(
        comparison.differences,
        [difference(
            Disagreement::UnexpectedConnection,
            5432,
            Network::Lan
        )]
    );
}

#[test]
fn every_failed_connection_the_scan_expects_is_a_difference() {
    for result in [Outcome::Closed, Outcome::NoAnswer, Outcome::Unreachable] {
        let results = [probed(80, LAN_V4, result.clone())];
        let comparison = compare(&scan(&[(80, r#""lan""#)]), &results, None);
        assert_eq!(
            comparison.differences,
            [difference(
                Disagreement::MissingConnection,
                80,
                Network::Lan
            )],
            "{result}"
        );
    }
}

#[test]
fn a_probe_that_matches_the_scan_has_no_differences() {
    let results = [
        probed(22, LAN_V4, Outcome::Open),
        probed(5432, LAN_V4, Outcome::Closed),
        probed(6379, LAN_V4, Outcome::NoAnswer),
    ];
    let scan = scan(&[
        (22, r#""lan""#),
        (5432, r#""this_host""#),
        (6379, r#""this_host""#),
    ]);
    assert_eq!(compare(&scan, &results, None).differences, []);
}

#[test]
fn a_port_the_scan_cannot_speak_for_only_shows_the_probe_result() {
    let unknown = claims::parse(
        r#"{"schema_version": 1, "collector_errors": [], "ports": [
            {"port": 53, "protocol": "tcp", "reach": {"kind": "unknown"},
             "reason": {"kind": "not_on_host"}}]}"#,
    )
    .unwrap();
    for result in [Outcome::Open, Outcome::Closed] {
        let results = [probed(53, LAN_V4, result)];
        let comparison = compare(&unknown, &results, None);
        assert_eq!(comparison.differences, []);
        assert_eq!(comparison.unknown_ports, BTreeSet::from([53]));
    }
}

#[test]
fn the_network_comes_from_the_address() {
    let results = [probed(22, TAILNET_V4, Outcome::Open)];
    let comparison = compare(&scan(&[(22, r#""lan""#)]), &results, None);
    assert_eq!(comparison.from, BTreeSet::from([Network::Tailnet]));
    assert!(comparison.guessed);
    assert_eq!(
        comparison.differences,
        [difference(
            Disagreement::UnexpectedConnection,
            22,
            Network::Tailnet
        )]
    );
}

#[test]
fn from_overrides_the_address() {
    // A private address reached over a VPN, from outside the LAN.
    let results = [probed(22, LAN_V4, Outcome::Open)];
    let comparison = compare(
        &scan(&[(22, r#""lan""#)]),
        &results,
        Some(Network::Internet),
    );
    assert_eq!(comparison.from, BTreeSet::from([Network::Internet]));
    assert!(!comparison.guessed);
    assert_eq!(
        comparison.differences,
        [difference(
            Disagreement::UnexpectedConnection,
            22,
            Network::Internet
        )]
    );
}

#[test]
fn one_open_address_of_a_network_is_enough() {
    // A service on IPv4 only, on a host that also has an IPv6 address.
    let results = [
        probed(22, LAN_V4, Outcome::Open),
        probed(22, LAN_V6, Outcome::Closed),
    ];
    let comparison = compare(&scan(&[(22, r#""lan""#)]), &results, None);
    assert_eq!(comparison.differences, []);
}

#[test]
fn every_address_of_a_network_must_fail_for_a_missing_connection() {
    let results = [
        probed(22, LAN_V4, Outcome::Closed),
        probed(22, LAN_V6, Outcome::NoAnswer),
    ];
    let comparison = compare(&scan(&[(22, r#""lan""#)]), &results, None);
    assert_eq!(
        comparison.differences,
        [difference(
            Disagreement::MissingConnection,
            22,
            Network::Lan
        )]
    );
}

#[test]
fn addresses_on_different_networks_are_compared_apart() {
    let results = [
        probed(22, LAN_V4, Outcome::Open),
        probed(22, PUBLIC_V6, Outcome::Open),
    ];
    let comparison = compare(&scan(&[(22, r#""lan""#)]), &results, None);
    assert_eq!(
        comparison.from,
        BTreeSet::from([Network::Lan, Network::Internet])
    );
    assert_eq!(
        comparison.differences,
        [difference(
            Disagreement::UnexpectedConnection,
            22,
            Network::Internet
        )]
    );
}

#[test]
fn from_puts_every_address_on_one_network() {
    let results = [
        probed(22, LAN_V4, Outcome::Open),
        probed(22, PUBLIC_V6, Outcome::Closed),
    ];
    let comparison = compare(&scan(&[(22, r#""lan""#)]), &results, Some(Network::Lan));
    assert_eq!(comparison.from, BTreeSet::from([Network::Lan]));
    assert_eq!(comparison.differences, []);
}

#[test]
fn a_failed_attempt_is_no_evidence_of_a_missing_connection() {
    let results = [probed(22, LAN_V4, failed())];
    let comparison = compare(&scan(&[(22, r#""lan""#)]), &results, None);
    assert_eq!(comparison.differences, []);
}

#[test]
fn a_failed_attempt_beside_a_closed_one_is_still_no_evidence() {
    let results = [
        probed(22, LAN_V4, Outcome::Closed),
        probed(22, LAN_V6, failed()),
    ];
    let comparison = compare(&scan(&[(22, r#""lan""#)]), &results, None);
    assert_eq!(comparison.differences, []);
}

#[test]
fn a_connection_counts_even_beside_a_failed_attempt() {
    let results = [
        probed(22, LAN_V4, failed()),
        probed(22, LAN_V6, Outcome::Open),
    ];
    let comparison = compare(&scan(&[(22, r#""this_host""#)]), &results, None);
    assert_eq!(
        comparison.differences,
        [difference(
            Disagreement::UnexpectedConnection,
            22,
            Network::Lan
        )]
    );
}

#[test]
fn the_more_serious_differences_come_first_then_by_port() {
    let results = [
        probed(80, LAN_V4, Outcome::Closed),
        probed(5432, LAN_V4, Outcome::Open),
        probed(6379, LAN_V4, Outcome::Open),
    ];
    let scan = scan(&[
        (80, r#""lan""#),
        (5432, r#""this_host""#),
        (6379, r#""this_host""#),
    ]);
    let kinds: Vec<_> = compare(&scan, &results, None)
        .differences
        .iter()
        .map(|found| (found.kind, found.port))
        .collect();
    assert_eq!(
        kinds,
        [
            (Disagreement::UnexpectedConnection, 5432),
            (Disagreement::UnexpectedConnection, 6379),
            (Disagreement::MissingConnection, 80),
        ]
    );
}

#[test]
fn skipped_ports_are_passed_on() {
    let claims = claims::parse(
        r#"{"schema_version": 1, "collector_errors": [], "ports": [
            {"port": 22, "protocol": "tcp", "reach": {"kind": "from", "networks": ["lan"]},
             "reason": {"kind": "all_addresses"}},
            {"port": 5353, "protocol": "udp", "reach": {"kind": "from", "networks": ["lan"]},
             "reason": {"kind": "all_addresses"}}]}"#,
    )
    .unwrap();
    let results = [probed(22, LAN_V4, Outcome::Open)];
    assert_eq!(
        compare(&claims, &results, None).skipped_ports,
        BTreeSet::from([5353])
    );
}
