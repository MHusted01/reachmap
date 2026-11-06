use super::*;

/// A document with `rows`, in the shape `reachmap scan --json` prints.
fn document(rows: &[&str]) -> String {
    format!(
        r#"{{"schema_version": 1, "ports": [{}], "collector_errors": []}}"#,
        rows.join(",")
    )
}

/// A row for `port` over `protocol`, reachable from `networks`.
fn row(port: u16, protocol: &str, networks: &str) -> String {
    format!(
        r#"{{"port": {port}, "protocol": "{protocol}",
            "reach": {{"kind": "from", "networks": [{networks}]}},
            "reason": {{"kind": "all_addresses"}}}}"#
    )
}

fn claims(rows: &[&str]) -> ScanClaims {
    parse(&document(rows)).unwrap()
}

fn tcp_ports(claims: &ScanClaims) -> Vec<u16> {
    claims.ports().unwrap().iter().collect()
}

#[test]
fn says_which_networks_can_reach_a_port() {
    let claims = claims(&[&row(22, "tcp", r#""this_host", "lan""#)]);
    assert_eq!(claims.claim(22, Network::Lan), Claim::CanReach);
    assert_eq!(claims.claim(22, Network::ThisHost), Claim::CanReach);
    assert_eq!(claims.claim(22, Network::Tailnet), Claim::CannotReach);
    assert_eq!(claims.claim(22, Network::Internet), Claim::CannotReach);
}

#[test]
fn the_rows_of_a_port_count_together() {
    let claims = claims(&[
        &row(80, "tcp", r#""this_host""#),
        &row(80, "tcp", r#""tailnet""#),
    ]);
    assert_eq!(claims.claim(80, Network::ThisHost), Claim::CanReach);
    assert_eq!(claims.claim(80, Network::Tailnet), Claim::CanReach);
    assert_eq!(claims.claim(80, Network::Lan), Claim::CannotReach);
    assert_eq!(tcp_ports(&claims), [80]);
}

#[test]
fn a_port_the_scan_does_not_list_is_unknown() {
    assert_eq!(claims(&[]).claim(22, Network::Lan), Claim::Unknown);
}

#[test]
fn a_row_with_unknown_reach_makes_the_port_unknown() {
    let unknown = r#"{"port": 53, "protocol": "tcp", "reach": {"kind": "unknown"},
        "reason": {"kind": "not_on_host"}}"#;
    let claims = claims(&[unknown]);
    assert_eq!(claims.claim(53, Network::Lan), Claim::Unknown);
    assert_eq!(claims.claim(53, Network::Internet), Claim::Unknown);
}

#[test]
fn a_row_that_says_yes_outweighs_one_that_cannot_say() {
    let unknown = r#"{"port": 53, "protocol": "tcp", "reach": {"kind": "unknown"},
        "reason": {"kind": "not_on_host"}}"#;
    let claims = claims(&[unknown, &row(53, "tcp", r#""lan""#)]);
    assert_eq!(claims.claim(53, Network::Lan), Claim::CanReach);
    assert_eq!(claims.claim(53, Network::Tailnet), Claim::Unknown);
}

#[test]
fn a_reach_from_a_newer_reachmap_counts_as_unknown() {
    let newer = r#"{"port": 53, "protocol": "tcp", "reach": {"kind": "from_somewhere_new"},
        "reason": {"kind": "all_addresses"}}"#;
    assert_eq!(claims(&[newer]).claim(53, Network::Lan), Claim::Unknown);
}

#[test]
fn a_network_from_a_newer_reachmap_counts_as_unknown() {
    let claims = claims(&[&row(53, "tcp", r#""lan", "mesh""#)]);
    assert_eq!(claims.claim(53, Network::Lan), Claim::Unknown);
}

/// A row Tailscale forwards to, reachable from `networks`.
fn shared_row(port: u16, networks: &str) -> String {
    format!(
        r#"{{"port": {port}, "protocol": "tcp",
            "reach": {{"kind": "from", "networks": [{networks}]}},
            "reason": {{"kind": "tailscale_shared", "served_on": [443], "funnel_on": [],
                        "direct": {{"kind": "loopback"}}}}}}"#
    )
}

#[test]
fn a_shared_row_cannot_speak_for_the_networks_tailscale_adds() {
    // Clients use the port Tailscale shares, so this port may not answer them.
    let claims = claims(&[&shared_row(3000, r#""this_host", "tailnet", "internet""#)]);
    assert_eq!(claims.claim(3000, Network::Tailnet), Claim::Unknown);
    assert_eq!(claims.claim(3000, Network::Internet), Claim::Unknown);
}

#[test]
fn a_shared_row_still_speaks_for_the_other_networks() {
    let claims = claims(&[&shared_row(3000, r#""this_host", "lan", "tailnet""#)]);
    assert_eq!(claims.claim(3000, Network::ThisHost), Claim::CanReach);
    assert_eq!(claims.claim(3000, Network::Lan), Claim::CanReach);
    assert_eq!(claims.claim(3000, Network::Docker), Claim::CannotReach);
}

#[test]
fn a_shared_row_says_nothing_new_about_a_network_it_does_not_list() {
    let claims = claims(&[&shared_row(3000, r#""this_host", "tailnet""#)]);
    assert_eq!(claims.claim(3000, Network::Internet), Claim::CannotReach);
}

#[test]
fn a_direct_row_of_the_same_port_outweighs_a_shared_one() {
    let claims = claims(&[
        &shared_row(3000, r#""this_host", "tailnet""#),
        &row(3000, "tcp", r#""tailnet""#),
    ]);
    assert_eq!(claims.claim(3000, Network::Tailnet), Claim::CanReach);
}

#[test]
fn rows_that_are_not_tcp_are_skipped() {
    let newer = row(7000, "quic", r#""lan""#);
    let claims = claims(&[
        &row(22, "tcp", r#""lan""#),
        &row(5353, "udp", r#""lan""#),
        &newer,
    ]);
    assert_eq!(tcp_ports(&claims), [22]);
    assert_eq!(
        claims.skipped().iter().copied().collect::<Vec<_>>(),
        [5353, 7000]
    );
    assert_eq!(claims.claim(5353, Network::Lan), Claim::Unknown);
}

#[test]
fn a_port_with_tcp_and_udp_rows_is_probed_and_its_udp_row_noted() {
    let claims = claims(&[&row(53, "tcp", r#""lan""#), &row(53, "udp", r#""lan""#)]);
    assert_eq!(tcp_ports(&claims), [53]);
    assert!(claims.skipped().contains(&53));
}

#[test]
fn a_scan_without_tcp_rows_has_no_ports_to_probe() {
    assert_eq!(claims(&[&row(5353, "udp", r#""lan""#)]).ports(), None);
    assert_eq!(claims(&[]).ports(), None);
}

#[test]
fn port_zero_is_not_probed() {
    assert_eq!(claims(&[&row(0, "tcp", r#""lan""#)]).ports(), None);
}

#[test]
fn unknown_fields_are_ignored() {
    let text = r#"{"schema_version": 1, "new_field": true, "collector_errors": [],
        "ports": [{"port": 22, "protocol": "tcp", "new_field": [1, 2],
                   "reach": {"kind": "from", "networks": ["lan"], "new_field": 1},
                   "reason": {"kind": "all_addresses", "new_field": 1}}]}"#;
    assert_eq!(
        parse(text).unwrap().claim(22, Network::Lan),
        Claim::CanReach
    );
}

#[test]
fn a_reason_from_a_newer_reachmap_leaves_the_reach_as_it_is() {
    let text = document(&[r#"{"port": 22, "protocol": "tcp",
        "reach": {"kind": "from", "networks": ["lan"]},
        "reason": {"kind": "something_new"}}"#]);
    assert_eq!(
        parse(&text).unwrap().claim(22, Network::Lan),
        Claim::CanReach
    );
}

#[test]
fn text_in_the_rows_is_never_read() {
    // A value of the wrong type in a text field would fail if it were read.
    let text = document(&[r#"{"port": 22, "protocol": "tcp",
        "reach": {"kind": "from", "networks": ["lan"]},
        "reason": {"kind": "all_addresses"},
        "service": 7, "address": "not an address", "listener": []}"#]);
    assert_eq!(
        parse(&text).unwrap().claim(22, Network::Lan),
        Claim::CanReach
    );
}

#[test]
fn another_schema_version_is_refused() {
    let text = r#"{"schema_version": 2, "rows": []}"#;
    assert_eq!(
        parse(text).unwrap_err(),
        ParseError::UnsupportedVersion { found: 2 }
    );
}

#[test]
fn text_that_is_not_a_scan_is_refused_without_the_text_in_the_error() {
    let error = parse("\u{1b}[2J not json").unwrap_err();
    assert!(matches!(error, ParseError::NotAScan { .. }), "{error}");
    assert!(!error.to_string().contains('\u{1b}'), "{error}");
}

#[test]
fn a_document_without_ports_is_refused() {
    let error = parse(r#"{"schema_version": 1}"#).unwrap_err();
    assert!(matches!(error, ParseError::NotAScan { .. }), "{error}");
}

#[test]
fn a_port_out_of_range_is_refused() {
    let text = document(&[r#"{"port": 70000, "protocol": "tcp",
        "reach": {"kind": "from", "networks": ["lan"]},
        "reason": {"kind": "all_addresses"}}"#]);
    let error = parse(&text).unwrap_err();
    assert!(matches!(error, ParseError::NotAScan { .. }), "{error}");
}

#[test]
fn a_missing_file_is_an_error_naming_it() {
    let error = load(Path::new("/no/such/scan.json")).unwrap_err();
    assert!(error.to_string().contains("/no/such/scan.json"), "{error}");
}

/// The pinned output of `reachmap scan --json`, so this reader and the real
/// document cannot drift apart.
const REAL_SCAN: &str = include_str!("../../../tests/fixtures/scan_report.json");
const REAL_SHARED_SCAN: &str = include_str!("../../../tests/fixtures/scan_report_tailscale.json");

#[test]
fn reads_the_ports_of_a_real_scan_document() {
    let claims = parse(REAL_SCAN).unwrap();
    assert_eq!(tcp_ports(&claims), [22, 53, 3306, 8080, 8443, 9100]);
    assert_eq!(
        claims.skipped().iter().copied().collect::<Vec<_>>(),
        [53, 68, 514, 1900, 5353, 47918]
    );
}

#[test]
fn reads_the_verdicts_of_a_real_scan_document() {
    let claims = parse(REAL_SCAN).unwrap();
    assert_eq!(claims.claim(22, Network::Lan), Claim::CanReach);
    assert_eq!(claims.claim(22, Network::Internet), Claim::CannotReach);
    assert_eq!(claims.claim(3306, Network::Lan), Claim::CannotReach);
    // Two rows: one on loopback, one on a LAN address.
    assert_eq!(claims.claim(8080, Network::ThisHost), Claim::CanReach);
    assert_eq!(claims.claim(8080, Network::Lan), Claim::CanReach);
}

#[test]
fn recognises_a_shared_row_in_a_real_scan_document() {
    let claims = parse(REAL_SHARED_SCAN).unwrap();
    assert_eq!(claims.claim(22, Network::Lan), Claim::CanReach);
    assert_eq!(claims.claim(22, Network::Tailnet), Claim::Unknown);
    assert_eq!(claims.claim(22, Network::Internet), Claim::Unknown);
}
