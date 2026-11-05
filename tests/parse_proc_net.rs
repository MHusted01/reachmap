//! Fixture tests: parse `/proc/net/tcp{,6}` files through the public library
//! API. The fixtures are hand-written in the kernel's exact format (header,
//! column layout, trailing fields), with documentation addresses.

// Test helpers may panic: a failed test should stop loudly.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use reachmap::collect::RawTable;
use reachmap::errors::render_chain;
use reachmap::parse::proc_net::parse_proc_net_tcp;
use reachmap::scan::{ScanError, parse_tables};
use reachmap::socket::AddressFamily;

const TCP: &str = include_str!("fixtures/proc_net_tcp.txt");
const TCP6: &str = include_str!("fixtures/proc_net_tcp6.txt");

/// (port, address, inode) for each socket, easy to compare.
fn summary(text: &str, family: AddressFamily) -> Vec<(u16, String, u64)> {
    parse_proc_net_tcp(text, family)
        .unwrap()
        .into_iter()
        .map(|s| (s.port, s.address.to_string(), s.inode))
        .collect()
}

fn table(family: AddressFamily, path: &str, text: &str) -> RawTable {
    RawTable {
        family,
        path: path.into(),
        text: text.to_string(),
    }
}

#[test]
fn ipv4_fixture_yields_only_listening_sockets_in_file_order() {
    assert_eq!(
        summary(TCP, AddressFamily::Ipv4),
        vec![
            (22, "0.0.0.0".to_string(), 21345),
            (53, "127.0.0.53".to_string(), 19876),
            (3306, "127.0.0.1".to_string(), 23456),
            (8080, "192.168.1.20".to_string(), 34567),
        ]
    );
}

#[test]
fn ipv6_fixture_decodes_any_loopback_mapped_and_global_addresses() {
    assert_eq!(
        summary(TCP6, AddressFamily::Ipv6),
        vec![
            (22, "::".to_string(), 21347),
            (631, "::1".to_string(), 31337),
            (8080, "::ffff:127.0.0.1".to_string(), 41000),
            (443, "2001:db8::1".to_string(), 52000),
        ]
    );
}

#[test]
fn parse_tables_merges_both_tables_sorted_by_port_ipv4_first() {
    let tables = [
        table(AddressFamily::Ipv4, "/proc/net/tcp", TCP),
        table(AddressFamily::Ipv6, "/proc/net/tcp6", TCP6),
    ];

    let rows: Vec<(u16, String)> = parse_tables(&tables)
        .unwrap()
        .iter()
        .map(|s| (s.port, s.endpoint().protocol_name()))
        .collect();

    let ports: Vec<u16> = rows.iter().map(|row| row.0).collect();
    assert_eq!(ports, vec![22, 22, 53, 443, 631, 3306, 8080, 8080]);
    assert_eq!(rows[0], (22, "tcp".to_string()));
    assert_eq!(rows[1], (22, "tcp6".to_string()));
}

#[test]
fn a_bad_row_names_the_file_and_line_and_suggests_reporting_it() {
    let tables = [table(
        AddressFamily::Ipv4,
        "/proc/net/tcp",
        "  sl  local_address\n   0: 0100007F:0CEA 00000000:0000 0A\n",
    )];

    let error = parse_tables(&tables).unwrap_err();

    assert!(matches!(error, ScanError::Parse { .. }));
    assert_eq!(
        render_chain(&error),
        "could not understand /proc/net/tcp: line 2: expected at least 10 fields, found 4"
    );
    let hint = error.hint().unwrap();
    assert!(
        hint.contains("github.com/MHusted01/reachmap/issues"),
        "{hint}"
    );
    assert!(hint.contains("line 2 of /proc/net/tcp"), "{hint}");
}
