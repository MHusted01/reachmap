// Test helpers may panic: a failed test should stop loudly.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr};

use super::*;
use crate::docker::DockerError;
use crate::json::render;
use crate::network::Network;
use crate::parse::tailscale::TailscaleParseError;
use crate::reach::{Coverage, Reason, Verdict};
use crate::tailscale::TailscaleError;

const ADDRESS: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);

/// A document with one row, built from the JSON of its `service`, `reach` and
/// the rest, so each test shows only what it is about.
fn document(row: &str) -> String {
    format!(r#"{{"schema_version": 1, "ports": [{row}], "warnings": [], "collector_errors": []}}"#)
}

fn row_with(protocol: &str, listener: &str, service: &str, reach: &str, warning: &str) -> String {
    format!(
        r#"{{"port": 22, "protocol": {protocol}, "address": "0.0.0.0", "listener": {listener},
            "service": {service}, "reach": {reach},
            "reason": {{"kind": "loopback"}}, "warning": {warning}}}"#
    )
}

const SSHD: &str = r#"{"kind": "process", "pid": 812, "name": "sshd"}"#;
const LAN: &str = r#"{"kind": "from", "networks": ["this_host", "lan"]}"#;

fn plain_row() -> String {
    row_with(r#""tcp""#, r#""host_socket""#, SSHD, LAN, "null")
}

/// The only exposure of a one-row document.
fn only_exposure(snapshot: &Snapshot) -> &Exposure {
    let mut exposures = snapshot.rows.values().flatten();
    let exposure = exposures.next().unwrap();
    assert!(exposures.next().is_none());
    exposure
}

#[test]
fn reads_the_facts_of_a_row() {
    let snapshot = parse(&document(&plain_row())).unwrap();

    let key = RowKey {
        port: 22,
        protocol: Tolerant::Known(Protocol::Tcp),
        address: ADDRESS,
    };
    let exposure = Exposure {
        listener: Tolerant::Known(Listener::HostSocket),
        service: Owner::Process {
            name: "sshd".to_string(),
        },
        reach: Reach::From {
            networks: BTreeSet::from([Network::ThisHost, Network::Lan]),
        },
        warning: None,
    };
    assert_eq!(snapshot.rows[&key], BTreeSet::from([exposure]));
    assert!(snapshot.missing.is_empty());
    assert!(!snapshot.needs_root);
}

#[test]
fn identical_rows_on_one_endpoint_count_once() {
    let row = plain_row();
    let snapshot = parse(&document(&format!("{row}, {row}"))).unwrap();

    assert_eq!(snapshot.rows.values().flatten().count(), 1);
}

#[test]
fn another_schema_version_is_refused_before_the_shape_is_read() {
    let error = parse(r#"{"schema_version": 2, "rows": "another shape"}"#).unwrap_err();

    assert_eq!(error, ParseError::UnsupportedVersion { found: 2 });
    assert_eq!(
        error.to_string(),
        "schema_version 2 is not supported, this reachmap reads version 1; \
         save it again with `reachmap scan --json`"
    );
}

#[test]
fn text_that_is_no_scan_document_is_refused() {
    for text in [
        "not json",
        "{}",
        r#"{"schema_version": "1"}"#,
        r#"{"schema_version": 1, "host": "a probe report", "results": []}"#,
    ] {
        let error = parse(text).unwrap_err();
        assert!(matches!(error, ParseError::NotAScan { .. }), "{text}");
    }
}

#[test]
fn a_port_outside_the_range_or_a_bad_address_is_refused() {
    let wrong_port = plain_row().replace(r#""port": 22"#, r#""port": 70000"#);
    let wrong_address = plain_row().replace("0.0.0.0", "not an address");

    assert!(parse(&document(&wrong_port)).is_err());
    assert!(parse(&document(&wrong_address)).is_err());
}

#[test]
fn unknown_fields_are_ignored() {
    let row = plain_row().replacen('{', r#"{"added_later": [1, 2], "#, 1);
    let text = document(&row).replacen('{', r#"{"also_new": {"a": 1}, "#, 1);

    assert_eq!(
        parse(&text).unwrap(),
        parse(&document(&plain_row())).unwrap()
    );
}

#[test]
fn unknown_values_become_unknown_instead_of_errors() {
    let row = row_with(
        r#""sctp""#,
        r#""some_new_listener""#,
        r#"{"kind": "some_new_owner", "id": 7}"#,
        r#"{"kind": "some_new_reach"}"#,
        r#""some_new_warning""#,
    );

    let snapshot = parse(&document(&row)).unwrap();

    assert_eq!(
        snapshot.rows.keys().next().unwrap().protocol,
        Tolerant::Unknown
    );
    assert_eq!(
        *only_exposure(&snapshot),
        Exposure {
            listener: Tolerant::Unknown,
            service: Owner::Unknown,
            reach: Reach::Unknown,
            warning: Some(Tolerant::Unknown),
        }
    );
}

#[test]
fn an_unknown_network_makes_the_whole_reach_unknown() {
    let reach = r#"{"kind": "from", "networks": ["lan", "some_new_network"]}"#;
    let row = row_with(r#""tcp""#, r#""host_socket""#, SSHD, reach, "null");

    let snapshot = parse(&document(&row)).unwrap();

    assert_eq!(only_exposure(&snapshot).reach, Reach::Unknown);
}

#[test]
fn names_are_sanitised() {
    let service = r#"{"kind": "container", "name": "web\u001b[2J",
                      "compose_service": "svc\u202e"}"#;
    let row = row_with(r#""tcp""#, r#""host_socket""#, service, LAN, "null");

    let snapshot = parse(&document(&row)).unwrap();

    assert_eq!(
        only_exposure(&snapshot).service,
        Owner::Container(Container {
            name: "web\\u{1b}[2J".to_string(),
            compose_service: Some("svc\\u{202e}".to_string()),
        })
    );
}

#[test]
fn a_parse_error_cannot_carry_terminal_escapes_from_the_file() {
    let quoted_from_file = <serde_json::Error as serde::de::Error>::custom("bad \u{1b}[2J");

    let error = ParseError::from(quoted_from_file);

    assert_eq!(
        error,
        ParseError::NotAScan {
            message: "bad \\u{1b}[2J".to_string()
        }
    );
}

#[test]
fn the_process_id_is_not_part_of_a_row() {
    let other_pid = SSHD.replace("812", "4000");
    let restarted = row_with(r#""tcp""#, r#""host_socket""#, &other_pid, LAN, "null");

    assert_eq!(
        parse(&document(&restarted)).unwrap(),
        parse(&document(&plain_row())).unwrap()
    );
}

#[test]
fn reads_which_collectors_failed_and_ignores_their_text() {
    let text = r#"{"schema_version": 1, "ports": [], "warnings": [], "collector_errors": [
        {"collector": "docker", "message": "any text", "hint": null},
        {"collector": "some_new_collector", "message": "", "hint": null}
    ]}"#;

    assert_eq!(
        parse(text).unwrap().missing,
        BTreeSet::from([Tolerant::Known(Collector::Docker), Tolerant::Unknown])
    );
}

#[test]
fn notices_an_owner_only_root_could_name() {
    let service = r#"{"kind": "unknown", "reason": "needs_root"}"#;
    let row = row_with(r#""tcp""#, r#""host_socket""#, service, LAN, "null");

    let snapshot = parse(&document(&row)).unwrap();

    assert!(snapshot.needs_root);
    assert_eq!(only_exposure(&snapshot).service, Owner::Unknown);
}

fn scanned(port: u16, service: Service) -> ScannedPort {
    ScannedPort {
        endpoint: Endpoint {
            port,
            protocol: Protocol::Tcp,
            address: ADDRESS,
        },
        listener: Listener::HostSocket,
        service,
        verdict: Verdict {
            reach: Reach::From {
                networks: BTreeSet::from([Network::Internet]),
            },
            reason: Reason::AllAddresses {
                covers: Coverage::Ipv4,
                checked: true,
            },
        },
        warning: Some(Warning::UfwBypassed),
    }
}

#[test]
fn a_saved_scan_reads_back_as_the_scan_it_came_from() {
    let report = ScanReport {
        ports: vec![
            scanned(
                22,
                Service::Process(Process {
                    pid: 812,
                    name: "sshd".to_string(),
                }),
            ),
            scanned(
                80,
                Service::Container(Container {
                    name: "shop-web-1".to_string(),
                    compose_service: Some("web".to_string()),
                }),
            ),
            scanned(
                443,
                Service::Unknown {
                    reason: UnknownReason::NeedsRoot,
                },
            ),
        ],
        interfaces_error: None,
        docker_error: Some(DockerError::NotInstalled),
        socket_options_error: None,
        tailscale_error: Some(TailscaleError::Parse(TailscaleParseError::HostPort(
            "host".to_string(),
        ))),
        warnings: Vec::new(),
    };

    assert_eq!(
        parse(&render(&report).unwrap()).unwrap(),
        Snapshot::from(&report)
    );
}

#[test]
fn the_table_name_of_a_protocol_follows_the_address() {
    let key = |protocol, address| RowKey {
        port: 53,
        protocol,
        address,
    };

    assert_eq!(
        key(Tolerant::Known(Protocol::Udp), ADDRESS).protocol_name(),
        "udp"
    );
    assert_eq!(
        key(Tolerant::Known(Protocol::Tcp), "::1".parse().unwrap()).protocol_name(),
        "tcp6"
    );
    assert_eq!(key(Tolerant::Unknown, ADDRESS).protocol_name(), "unknown");
}

#[test]
fn a_missing_file_names_the_path() {
    let error = load(Path::new("/nonexistent/baseline.json")).unwrap_err();

    assert!(matches!(error, LoadError::Read { .. }));
    assert_eq!(
        error.to_string(),
        "could not read /nonexistent/baseline.json"
    );
}

#[test]
fn text_up_to_the_limit_is_read() {
    assert_eq!(
        read_limited("12345".as_bytes(), 5).unwrap(),
        Some("12345".to_string())
    );
}

#[test]
fn text_over_the_limit_is_refused_without_reading_the_rest() {
    let mut endless = io::repeat(b'x');

    assert_eq!(read_limited(&mut endless, 5).unwrap(), None);
}

#[test]
fn a_limit_that_cuts_a_character_still_says_too_large() {
    assert_eq!(read_limited("1234\u{e6}".as_bytes(), 5).unwrap(), None);
}

#[test]
fn bytes_that_are_no_text_are_an_error() {
    let error = read_limited([0xff, 0xfe].as_slice(), 5).unwrap_err();

    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
}

#[cfg(unix)]
#[test]
fn an_endless_file_is_too_large() {
    let error = load(Path::new("/dev/zero")).unwrap_err();

    assert_eq!(
        error.to_string(),
        "/dev/zero is over 64 MiB, too large to be a scan"
    );
}

#[test]
fn reads_a_row_tailscale_accepts() {
    let row = row_with(
        r#""tcp""#,
        r#""tailscale_share""#,
        r#"{"kind": "tailscale"}"#,
        r#"{"kind": "from", "networks": ["tailnet"]}"#,
        "null",
    );

    let snapshot = parse(&document(&row)).unwrap();

    let exposure = only_exposure(&snapshot);
    assert_eq!(exposure.listener, Tolerant::Known(Listener::TailscaleShare));
    assert_eq!(exposure.service, Owner::Tailscale);
}
