//! Snapshot tests of `reachmap probe`'s output. A failure of the JSON test means
//! the documented shape in `docs/probe.md` changed: update both on purpose, and
//! raise `schema_version` if scripts would break.

// Test helpers may panic: a failed test should stop loudly.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use reachmap::probe::report::{Report, render_json};
use reachmap::probe::{Outcome, ProbeReport, ProbedPort};

const EXPECTED_JSON: &str = include_str!("fixtures/probe_report.json");

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
    };
    assert_eq!(
        Report(&report).to_string(),
        "PORT  ADDRESS     RESULT\n22    192.0.2.10  open\n"
    );
}
