//! Parser for the kernel's TCP socket tables, `/proc/net/tcp` and `/proc/net/tcp6`.
//!
//! Each row after the header describes one socket, for example:
//!
//! ```text
//!   sl  local_address rem_address   st tx_queue ... uid  timeout inode
//!    0: 0100007F:0CEA 00000000:0000 0A 00000000 ...  112        0 23456 ...
//! ```
//!
//! `0100007F:0CEA` is the local address and port in hex, `0A` is the state
//! (LISTEN) and `23456` is the socket's inode. Addresses are printed as 32-bit
//! words in the machine's byte order, which is little-endian on every platform
//! reachmap supports (x86_64 and aarch64), so `0100007F` means 127.0.0.1.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use thiserror::Error;

use crate::socket::{ListeningSocket, Protocol};

/// A row that could not be understood, with its 1-based line number.
#[derive(Debug, Error, PartialEq, Eq)]
#[error("line {line}: {kind}")]
pub struct ParseError {
    pub line: usize,
    pub kind: ParseErrorKind,
}

/// What was wrong with a row.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ParseErrorKind {
    #[error("expected at least {expected} fields, found {found}")]
    TooFewFields { expected: usize, found: usize },
    #[error("local address {0:?} is not in ADDRESS:PORT form")]
    MissingPort(String),
    #[error("address {value:?} is not {digits} hex digits")]
    BadAddress { value: String, digits: usize },
    #[error("port {0:?} is not 4 hex digits")]
    BadPort(String),
    #[error("state {0:?} is not 2 hex digits")]
    BadState(String),
    #[error("inode {0:?} is not a whole number")]
    BadInode(String),
}

/// The kernel's code for the LISTEN state (`TCP_LISTEN` in `include/net/tcp_states.h`).
const LISTEN_STATE: u8 = 0x0A;
/// Rows have more fields, but we only need the first ten (up to the inode).
const MIN_FIELDS: usize = 10;
const LOCAL_ADDRESS_FIELD: usize = 1;
const STATE_FIELD: usize = 3;
const INODE_FIELD: usize = 9;
/// Hex digits in one 32-bit word: an IPv4 address is one word, IPv6 four.
const WORD_DIGITS: usize = 8;
const IPV6_DIGITS: usize = 4 * WORD_DIGITS;
const PORT_DIGITS: usize = 4;
const STATE_DIGITS: usize = 2;

/// Parses the text of `/proc/net/tcp` (IPv4) or `/proc/net/tcp6` (IPv6) and
/// returns the sockets in the LISTEN state, in file order.
///
/// Stops at the first malformed row and reports its 1-based line number.
pub fn parse_proc_net_tcp(
    text: &str,
    protocol: Protocol,
) -> Result<Vec<ListeningSocket>, ParseError> {
    text.lines()
        .enumerate()
        .filter_map(|(index, line)| {
            parse_line(line, protocol)
                .map_err(|kind| ParseError {
                    line: index + 1,
                    kind,
                })
                .transpose()
        })
        .collect()
}

/// Parses one line. `Ok(None)` means "nothing to report": a blank line, the
/// header, or a socket that is not listening.
fn parse_line(line: &str, protocol: Protocol) -> Result<Option<ListeningSocket>, ParseErrorKind> {
    // Only the first MIN_FIELDS fields matter; a fixed array avoids a heap
    // allocation per line.
    let mut fields = [""; MIN_FIELDS];
    let mut found = 0;
    for (slot, field) in fields.iter_mut().zip(line.split_whitespace()) {
        *slot = field;
        found += 1;
    }

    match (found, fields[0]) {
        (0, _) | (_, "sl") => return Ok(None),
        (found, _) if found < MIN_FIELDS => {
            return Err(ParseErrorKind::TooFewFields {
                expected: MIN_FIELDS,
                found,
            });
        }
        _ => {}
    }

    let state_hex = fields[STATE_FIELD];
    let state = parse_hex(state_hex, STATE_DIGITS, u8::from_str_radix)
        .ok_or_else(|| ParseErrorKind::BadState(state_hex.to_string()))?;
    if state != LISTEN_STATE {
        return Ok(None);
    }

    let (address, port) = parse_endpoint(fields[LOCAL_ADDRESS_FIELD], protocol)?;
    let inode_text = fields[INODE_FIELD];
    let inode: u64 = inode_text
        .parse()
        .map_err(|_| ParseErrorKind::BadInode(inode_text.to_string()))?;

    Ok(Some(ListeningSocket {
        protocol,
        address,
        port,
        inode,
    }))
}

/// Splits `ADDRESS:PORT` and decodes both halves.
fn parse_endpoint(field: &str, protocol: Protocol) -> Result<(IpAddr, u16), ParseErrorKind> {
    let (address_hex, port_hex) = field
        .split_once(':')
        .ok_or_else(|| ParseErrorKind::MissingPort(field.to_string()))?;

    let address = match protocol {
        Protocol::Tcp => IpAddr::V4(decode_ipv4(address_hex)?),
        Protocol::Tcp6 => IpAddr::V6(decode_ipv6(address_hex)?),
    };
    let port = parse_hex(port_hex, PORT_DIGITS, u16::from_str_radix)
        .ok_or_else(|| ParseErrorKind::BadPort(port_hex.to_string()))?;

    Ok((address, port))
}

/// `0100007F` -> 127.0.0.1: read one word, then lay its bytes out little-endian.
fn decode_ipv4(hex: &str) -> Result<Ipv4Addr, ParseErrorKind> {
    let word = parse_word(hex).ok_or_else(|| bad_address(hex, WORD_DIGITS))?;
    Ok(Ipv4Addr::from(word.to_le_bytes()))
}

/// Four words, each decoded like an IPv4 address, give the 16 address bytes.
fn decode_ipv6(hex: &str) -> Result<Ipv6Addr, ParseErrorKind> {
    if !is_hex_digits(hex, IPV6_DIGITS) {
        return Err(bad_address(hex, IPV6_DIGITS));
    }
    let mut bytes = [0u8; 16];
    let (groups, _) = bytes.as_chunks_mut::<4>();
    for (index, group) in groups.iter_mut().enumerate() {
        // Slicing by byte offset is safe: the check above proved every
        // character is a one-byte ASCII hex digit.
        let start = index * WORD_DIGITS;
        let word = parse_word(&hex[start..start + WORD_DIGITS])
            .ok_or_else(|| bad_address(hex, IPV6_DIGITS))?;
        *group = word.to_le_bytes();
    }
    Ok(Ipv6Addr::from(bytes))
}

fn bad_address(hex: &str, digits: usize) -> ParseErrorKind {
    ParseErrorKind::BadAddress {
        value: hex.to_string(),
        digits,
    }
}

fn parse_word(hex: &str) -> Option<u32> {
    parse_hex(hex, WORD_DIGITS, u32::from_str_radix)
}

/// Parses exactly `digits` hex digits with the given integer parser, e.g.
/// `parse_hex("0CEA", 4, u16::from_str_radix)`. The length and digit check
/// matters: `from_str_radix` alone also accepts a leading `+` and short input.
fn parse_hex<T, E>(
    text: &str,
    digits: usize,
    from_str_radix: fn(&str, u32) -> Result<T, E>,
) -> Option<T> {
    if !is_hex_digits(text, digits) {
        return None;
    }
    from_str_radix(text, 16).ok()
}

fn is_hex_digits(text: &str, digits: usize) -> bool {
    text.len() == digits && text.bytes().all(|b| b.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEADER: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode";

    /// Builds a file with the header and one row; the row is line 2.
    fn file_with_row(local: &str, state: &str, inode: &str) -> String {
        format!(
            "{HEADER}\n   0: {local} 00000000:0000 {state} 00000000:00000000 00:00000000 00000000     0        0 {inode} 1 0000000000000000 100 0 0 10 0\n"
        )
    }

    fn error_kind(text: &str, protocol: Protocol) -> ParseErrorKind {
        match parse_proc_net_tcp(text, protocol) {
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
        let sockets = parse_proc_net_tcp(&text, Protocol::Tcp).unwrap();
        assert_eq!(
            sockets,
            vec![ListeningSocket {
                protocol: Protocol::Tcp,
                address: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                port: 3306,
                inode: 23456,
            }]
        );
    }

    #[test]
    fn decodes_an_ipv6_address_word_by_word() {
        // 2001:db8::1 as four little-endian words.
        let text = file_with_row("B80D0120000000000000000001000000:01BB", "0A", "7");
        let sockets = parse_proc_net_tcp(&text, Protocol::Tcp6).unwrap();
        let expected: Ipv6Addr = "2001:db8::1".parse().unwrap();
        assert_eq!(sockets[0].address, IpAddr::V6(expected));
        assert_eq!(sockets[0].port, 443);
    }

    #[test]
    fn skips_rows_that_are_not_listening() {
        let text = file_with_row("0100007F:0CEA", "01", "0");
        assert_eq!(parse_proc_net_tcp(&text, Protocol::Tcp), Ok(Vec::new()));
    }

    #[test]
    fn header_only_and_blank_lines_give_no_sockets() {
        let text = format!("{HEADER}\n\n   \n");
        assert_eq!(parse_proc_net_tcp(&text, Protocol::Tcp), Ok(Vec::new()));
        assert_eq!(parse_proc_net_tcp("", Protocol::Tcp), Ok(Vec::new()));
    }

    #[test]
    fn a_short_row_is_an_error_with_its_line_number() {
        let text = format!("{HEADER}\n   0: 0100007F:0CEA 00000000:0000 0A\n");
        assert_eq!(
            error_kind(&text, Protocol::Tcp),
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
            error_kind(&text, Protocol::Tcp),
            ParseErrorKind::MissingPort("0100007F".to_string())
        );
    }

    #[test]
    fn a_non_hex_ipv4_address_is_an_error() {
        let text = file_with_row("0100007G:0CEA", "0A", "1");
        assert_eq!(
            error_kind(&text, Protocol::Tcp),
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
            error_kind(&text, Protocol::Tcp6),
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
            error_kind(&text, Protocol::Tcp),
            ParseErrorKind::BadAddress { .. }
        ));
    }

    #[test]
    fn a_bad_port_is_an_error() {
        let text = file_with_row("0100007F:CEA", "0A", "1");
        assert_eq!(
            error_kind(&text, Protocol::Tcp),
            ParseErrorKind::BadPort("CEA".to_string())
        );
    }

    #[test]
    fn a_bad_state_is_an_error() {
        let text = file_with_row("0100007F:0CEA", "ZZ", "1");
        assert_eq!(
            error_kind(&text, Protocol::Tcp),
            ParseErrorKind::BadState("ZZ".to_string())
        );
    }

    #[test]
    fn a_bad_inode_is_an_error() {
        let text = file_with_row("0100007F:0CEA", "0A", "-3");
        assert_eq!(
            error_kind(&text, Protocol::Tcp),
            ParseErrorKind::BadInode("-3".to_string())
        );
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
}
