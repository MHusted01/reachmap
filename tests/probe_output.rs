//! Snapshot tests of `reachmap probe`'s output. A failure of the JSON test means
//! the documented shape in `docs/probe.md` changed: update both on purpose, and
//! raise `schema_version` if scripts would break.

// Test helpers may panic: a failed test should stop loudly.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use reachmap::network::Network;
use reachmap::probe::compare::{Comparison, Difference, Disagreement};
use reachmap::probe::report::{Report, render_json};
use reachmap::probe::{Outcome, ProbeReport, ProbedPort};

const EXPECTED_JSON: &str = include_str!("fixtures/probe_report.json");
const EXPECTED_COMPARED_JSON: &str = include_str!("fixtures/probe_report_compared.json");

const V4: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
const V6: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x10));

fn probed(port: u16, address: IpAddr, result: Outcome) -> ProbedPort {
    ProbedPort {
        port,
        address: address.into(),
        result,
    }
}

fn report() -> ProbeReport {
    ProbeReport {
        host: "server.example".to_string(),
        results: vec![
            probed(22, V4, Outcome::Open),
            probed(22, V6, Outcome::Unreachable),
            probed(80, V4, Outcome::Closed),
            probed(443, V4, Outcome::NoAnswer),
            probed(
                8080,
                V4,
                Outcome::Failed {
                    message: "too many open files".to_string(),
                },
            ),
        ],
        comparison: None,
    }
}

const LAN_HOST: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10));

fn compared(comparison: Comparison) -> ProbeReport {
    ProbeReport {
        host: "10.0.0.10".to_string(),
        results: vec![
            probed(22, LAN_HOST, Outcome::Open),
            probed(3000, LAN_HOST, Outcome::Closed),
            probed(5432, LAN_HOST, Outcome::Open),
            probed(8080, LAN_HOST, Outcome::NoAnswer),
        ],
        comparison: Some(comparison),
    }
}

fn differences() -> Comparison {
    Comparison {
        from: BTreeSet::from([Network::Lan]),
        guessed: true,
        differences: vec![
            Difference {
                kind: Disagreement::UnexpectedConnection,
                port: 5432,
                from: Network::Lan,
            },
            Difference {
                kind: Disagreement::MissingConnection,
                port: 8080,
                from: Network::Lan,
            },
        ],
        unknown_ports: BTreeSet::from([3000]),
        skipped_ports: BTreeSet::from([53, 5353]),
    }
}

fn no_differences(from: Network, guessed: bool) -> Comparison {
    Comparison {
        from: BTreeSet::from([from]),
        guessed,
        differences: vec![],
        unknown_ports: BTreeSet::new(),
        skipped_ports: BTreeSet::new(),
    }
}

#[test]
fn json_matches_the_documented_shape() {
    assert_eq!(render_json(&report()).unwrap(), EXPECTED_JSON);
}

#[test]
fn the_table_has_one_row_per_result_and_explains_no_answer() {
    let expected = "\
PORT  ADDRESS       RESULT
22    192.0.2.10    open
22    2001:db8::10  unreachable
80    192.0.2.10    closed
443   192.0.2.10    no answer
8080  192.0.2.10    failed: too many open files

note: no answer means the connection timed out; a firewall and a host that is down look the same from here
";
    assert_eq!(Report(&report()).to_string(), expected);
}

#[test]
fn the_note_only_appears_when_a_port_gave_no_answer() {
    let report = ProbeReport {
        host: "server.example".to_string(),
        results: vec![probed(22, V4, Outcome::Open)],
        comparison: None,
    };
    assert_eq!(
        Report(&report).to_string(),
        "PORT  ADDRESS     RESULT\n22    192.0.2.10  open\n"
    );
}

#[test]
fn a_comparison_adds_to_the_json_without_changing_the_rest() {
    assert_eq!(
        render_json(&compared(differences())).unwrap(),
        EXPECTED_COMPARED_JSON
    );
}

#[test]
fn the_table_of_a_comparison_lists_the_differences_and_explains_the_gaps() {
    let expected = "\
PORT  ADDRESS    RESULT
22    10.0.0.10  open
3000  10.0.0.10  closed
5432  10.0.0.10  open
8080  10.0.0.10  no answer

compared with the scan from LAN (worked out from the address; --from overrides it)
PORT  FROM  DIFFERENCE
5432  LAN   connected, but the scan says this network cannot reach it
8080  LAN   did not connect, but the scan says this network can reach it; a firewall can cause that

note: no answer means the connection timed out; a firewall and a host that is down look the same from here
note: the scan has no verdict for these ports, so only the probe result counts: 3000
note: rows that are not TCP are left out, because a connect probe cannot confirm them: 53, 5353
";
    assert_eq!(Report(&compared(differences())).to_string(), expected);
}

#[test]
fn a_comparison_without_differences_says_so() {
    let report = ProbeReport {
        results: vec![probed(22, LAN_HOST, Outcome::Open)],
        ..compared(no_differences(Network::Lan, true))
    };
    let expected = "\
PORT  ADDRESS    RESULT
22    10.0.0.10  open

compared with the scan from LAN (worked out from the address; --from overrides it): no differences
";
    assert_eq!(Report(&report).to_string(), expected);
}

#[test]
fn a_network_chosen_with_from_is_not_called_worked_out() {
    let report = ProbeReport {
        results: vec![probed(22, LAN_HOST, Outcome::Open)],
        ..compared(no_differences(Network::Tailnet, false))
    };
    assert!(
        Report(&report)
            .to_string()
            .ends_with("\ncompared with the scan from tailnet: no differences\n")
    );
}

#[test]
fn the_internet_is_named_shortly_where_the_probe_came_from() {
    let report = ProbeReport {
        results: vec![probed(22, LAN_HOST, Outcome::Open)],
        ..compared(Comparison {
            from: BTreeSet::from([Network::Lan, Network::Internet]),
            guessed: false,
            differences: vec![Difference {
                kind: Disagreement::UnexpectedConnection,
                port: 22,
                from: Network::Internet,
            }],
            unknown_ports: BTreeSet::new(),
            skipped_ports: BTreeSet::new(),
        })
    };
    let expected = "\
PORT  ADDRESS    RESULT
22    10.0.0.10  open

compared with the scan from LAN, internet
PORT  FROM      DIFFERENCE
22    internet  connected, but the scan says this network cannot reach it
";
    assert_eq!(Report(&report).to_string(), expected);
}
