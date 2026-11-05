//! Unit tests for the `/proc/net/{tcp,udp}` parser: decoding and every error kind.

use super::*;

const HEADER: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode";

/// Builds a file with the header and one row; the row is line 2.
fn file_with_row(local: &str, state: &str, inode: &str) -> String {
    format!(
        "{HEADER}\n   0: {local} 00000000:0000 {state} 00000000:00000000 00:00000000 00000000     0        0 {inode} 1 0000000000000000 100 0 0 10 0\n"
    )
}

fn error_kind(text: &str, family: AddressFamily) -> ParseErrorKind {
    match parse_proc_net(text, family, Protocol::Tcp) {
        Err(error) => {
            assert_eq!(error.line, 2, "the bad row is line 2");
            error.kind
        }
        Ok(sockets) => panic!("expected an error, got {sockets:?}"),
    }
}

#[test]
fn decodes_an_ipv4_listen_row() {
    let text = file_with_row("0100007F:0CEA", "0A", "23456");
    let sockets = parse_proc_net(&text, AddressFamily::Ipv4, Protocol::Tcp).unwrap();
    assert_eq!(
        sockets,
        vec![ListeningSocket {
            protocol: Protocol::Tcp,
            address: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            port: 3306,
            inode: 23456,
            options: None,
        }]
    );
}

#[test]
fn an_unconnected_udp_socket_is_kept_and_a_tcp_state_is_not() {
    let udp = |state| {
        parse_proc_net(
            &file_with_row("0100007F:0035", state, "9"),
            AddressFamily::Ipv4,
            Protocol::Udp,
        )
        .unwrap()
    };

    assert_eq!(udp("07")[0].protocol, Protocol::Udp);
    assert_eq!(udp("07")[0].port, 53);
    assert_eq!(udp("01"), []);
    assert_eq!(udp("0A"), []);
}

#[test]
fn a_closed_tcp_socket_is_not_listening() {
    let text = file_with_row("0100007F:0035", "07", "9");

    let sockets = parse_proc_net(&text, AddressFamily::Ipv4, Protocol::Tcp).unwrap();

    assert_eq!(sockets, []);
}

#[test]
fn decodes_an_ipv6_address_word_by_word() {
    // 2001:db8::1 as four little-endian words.
    let text = file_with_row("B80D0120000000000000000001000000:01BB", "0A", "7");
    let sockets = parse_proc_net(&text, AddressFamily::Ipv6, Protocol::Tcp).unwrap();
    let expected: Ipv6Addr = "2001:db8::1".parse().unwrap();
    assert_eq!(sockets[0].address, IpAddr::V6(expected));
    assert_eq!(sockets[0].port, 443);
}

#[test]
fn skips_rows_that_are_not_listening() {
    let text = file_with_row("0100007F:0CEA", "01", "0");
    assert_eq!(
        parse_proc_net(&text, AddressFamily::Ipv4, Protocol::Tcp),
        Ok(Vec::new())
    );
}

#[test]
fn header_only_and_blank_lines_give_no_sockets() {
    let text = format!("{HEADER}\n\n   \n");
    assert_eq!(
        parse_proc_net(&text, AddressFamily::Ipv4, Protocol::Tcp),
        Ok(Vec::new())
    );
    assert_eq!(
        parse_proc_net("", AddressFamily::Ipv4, Protocol::Tcp),
        Ok(Vec::new())
    );
}

#[test]
fn a_short_row_is_an_error_with_its_line_number() {
    let text = format!("{HEADER}\n   0: 0100007F:0CEA 00000000:0000 0A\n");
    assert_eq!(
        error_kind(&text, AddressFamily::Ipv4),
        ParseErrorKind::TooFewFields {
            expected: 10,
            found: 4
        }
    );
}

#[test]
fn a_local_address_without_port_is_an_error() {
    let text = file_with_row("0100007F", "0A", "1");
    assert_eq!(
        error_kind(&text, AddressFamily::Ipv4),
        ParseErrorKind::MissingPort("0100007F".to_string())
    );
}

#[test]
fn a_non_hex_ipv4_address_is_an_error() {
    let text = file_with_row("0100007G:0CEA", "0A", "1");
    assert_eq!(
        error_kind(&text, AddressFamily::Ipv4),
        ParseErrorKind::BadAddress {
            value: "0100007G".to_string(),
            digits: 8
        }
    );
}

#[test]
fn an_ipv4_address_in_the_ipv6_table_is_an_error() {
    let text = file_with_row("0100007F:0CEA", "0A", "1");
    assert_eq!(
        error_kind(&text, AddressFamily::Ipv6),
        ParseErrorKind::BadAddress {
            value: "0100007F".to_string(),
            digits: 32
        }
    );
}

#[test]
fn a_signed_address_is_an_error() {
    // `u32::from_str_radix` would accept a leading `+`; the parser must not.
    let text = file_with_row("+100007F:0CEA", "0A", "1");
    assert!(matches!(
        error_kind(&text, AddressFamily::Ipv4),
        ParseErrorKind::BadAddress { .. }
    ));
}

#[test]
fn a_bad_port_is_an_error() {
    let text = file_with_row("0100007F:CEA", "0A", "1");
    assert_eq!(
        error_kind(&text, AddressFamily::Ipv4),
        ParseErrorKind::BadPort("CEA".to_string())
    );
}

#[test]
fn a_bad_state_is_an_error() {
    let text = file_with_row("0100007F:0CEA", "ZZ", "1");
    assert_eq!(
        error_kind(&text, AddressFamily::Ipv4),
        ParseErrorKind::BadState("ZZ".to_string())
    );
}

#[test]
fn a_bad_inode_is_an_error() {
    let text = file_with_row("0100007F:0CEA", "0A", "-3");
    assert_eq!(
        error_kind(&text, AddressFamily::Ipv4),
        ParseErrorKind::BadInode("-3".to_string())
    );
}

#[test]
fn accepts_lowercase_hex_and_the_extreme_values() {
    let text = file_with_row("0100007f:0000", "0a", &u64::MAX.to_string());
    let sockets = parse_proc_net(&text, AddressFamily::Ipv4, Protocol::Tcp).unwrap();
    assert_eq!(sockets[0].port, 0);
    assert_eq!(sockets[0].inode, u64::MAX);
}

#[test]
fn accepts_windows_line_endings() {
    let text = file_with_row("0100007F:0CEA", "0A", "1").replace('\n', "\r\n");
    assert_eq!(
        parse_proc_net(&text, AddressFamily::Ipv4, Protocol::Tcp)
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn skips_non_listening_ipv6_rows() {
    let text = file_with_row("00000000000000000000000001000000:0277", "01", "0");
    assert_eq!(
        parse_proc_net(&text, AddressFamily::Ipv6, Protocol::Tcp),
        Ok(Vec::new())
    );
}

#[test]
fn a_non_ascii_ipv6_address_is_an_error_not_a_panic() {
    // 32 bytes long, but `é` is two bytes and would split a word.
    let address = format!("{}é{}", "0".repeat(7), "0".repeat(23));
    assert_eq!(address.len(), 32);
    let text = file_with_row(&format!("{address}:0277"), "0A", "1");
    assert!(matches!(
        error_kind(&text, AddressFamily::Ipv6),
        ParseErrorKind::BadAddress { digits: 32, .. }
    ));
}

#[test]
fn a_non_hex_ipv6_word_is_an_error() {
    let text = file_with_row("000000000000000000000000010000ZZ:0277", "0A", "1");
    assert!(matches!(
        error_kind(&text, AddressFamily::Ipv6),
        ParseErrorKind::BadAddress { digits: 32, .. }
    ));
}

#[test]
fn errors_read_like_sentences() {
    let error = ParseError {
        line: 7,
        kind: ParseErrorKind::BadPort("CEA".to_string()),
    };
    assert_eq!(
        error.to_string(),
        "line 7: port \"CEA\" is not 4 hex digits"
    );
}
