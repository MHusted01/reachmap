//! Fixture tests: parse captured `/proc/net/tcp{,6}` files through the
//! public library API.

// Test helpers may panic: a failed test should stop loudly.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::net::IpAddr;

use reachmap::errors::render_chain;
use reachmap::parse::proc_net::parse_proc_net_tcp;
use reachmap::scan::{RawTable, ScanError, parse_tables};
use reachmap::socket::Protocol;

const TCP: &str = include_str!("fixtures/proc_net_tcp.txt");
const TCP6: &str = include_str!("fixtures/proc_net_tcp6.txt");

/// (port, address, inode) for each socket, easy to compare.
fn summary(text: &str, protocol: Protocol) -> Vec<(u16, String, u64)> {
    parse_proc_net_tcp(text, protocol)
        .unwrap()
        .into_iter()
        .map(|s| (s.port, s.address.to_string(), s.inode))
        .collect()
}

#[test]
fn ipv4_fixture_yields_only_listening_sockets_in_file_order() {
    assert_eq!(
        summary(TCP, Protocol::Tcp),
        vec![
            (22, "0.0.0.0".to_string(), 21345),
            (53, "127.0.0.53".to_string(), 19876),
            (3306, "127.0.0.1".to_string(), 23456),
            (8080, "192.168.0.87".to_string(), 34567),
        ]
    );
}

#[test]
fn ipv6_fixture_decodes_any_loopback_mapped_and_global_addresses() {
    assert_eq!(
        summary(TCP6, Protocol::Tcp6),
        vec![
            (22, "::".to_string(), 21347),
            (631, "::1".to_string(), 31337),
            (8080, "::ffff:127.0.0.1".to_string(), 41000),
            (443, "2001:db8::1".to_string(), 52000),
        ]
    );
}

#[test]
fn parse_tables_merges_both_tables_sorted_by_port() {
    let tables = [
        RawTable {
            protocol: Protocol::Tcp,
            path: "/proc/net/tcp",
            text: TCP.to_string(),
        },
        RawTable {
            protocol: Protocol::Tcp6,
            path: "/proc/net/tcp6",
            text: TCP6.to_string(),
        },
    ];

    let rows: Vec<(u16, Protocol, IpAddr)> = parse_tables(&tables)
        .unwrap()
        .into_iter()
        .map(|s| (s.port, s.protocol, s.address))
        .collect();

    let ports: Vec<u16> = rows.iter().map(|row| row.0).collect();
    assert_eq!(ports, vec![22, 22, 53, 443, 631, 3306, 8080, 8080]);
    assert_eq!(
        rows[0].1,
        Protocol::Tcp,
        "tcp sorts before tcp6 on the same port"
    );
    assert_eq!(rows[1].1, Protocol::Tcp6);
}

#[test]
fn parse_tables_names_the_file_with_the_bad_row() {
    let tables = [RawTable {
        protocol: Protocol::Tcp,
        path: "/proc/net/tcp",
        text: "  sl  local_address\n   0: 0100007F:0CEA 00000000:0000 0A\n".to_string(),
    }];

    let error = parse_tables(&tables).unwrap_err();

    assert!(matches!(error, ScanError::Parse { .. }));
    assert_eq!(error.to_string(), "could not understand /proc/net/tcp");
    assert_eq!(
        render_chain(&error),
        "could not understand /proc/net/tcp: line 2: expected at least 10 fields, found 4"
    );
}
