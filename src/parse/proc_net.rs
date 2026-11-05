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

use crate::socket::{AddressFamily, ListeningSocket, Protocol};

/// A row that could not be understood, with its 1-based line number.
#[derive(Debug, Error, PartialEq, Eq)]
#[error("line {line}: {kind}")]
pub struct ParseError {
    /// 1-based line number in the file (the header is line 1).
    pub line: usize,
    /// What was wrong with the row.
    pub kind: ParseErrorKind,
}

/// What was wrong with a row.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ParseErrorKind {
    /// The row ends before the inode column.
    #[error("expected at least {expected} fields, found {found}")]
    TooFewFields {
        /// Fields needed, up to and including the inode.
        expected: usize,
        /// Fields present.
        found: usize,
    },
    /// The local address has no `:PORT` part.
    #[error("local address {0:?} is not in ADDRESS:PORT form")]
    MissingPort(String),
    /// The address is not the expected number of hex digits.
    #[error("address {value:?} is not {digits} hex digits")]
    BadAddress {
        /// The text found.
        value: String,
        /// Hex digits expected: 8 for IPv4, 32 for IPv6.
        digits: usize,
    },
    /// The port is not 4 hex digits.
    #[error("port {0:?} is not 4 hex digits")]
    BadPort(String),
    /// The connection state is not 2 hex digits.
    #[error("state {0:?} is not 2 hex digits")]
    BadState(String),
    /// The inode is not a non-negative decimal number.
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
    family: AddressFamily,
) -> Result<Vec<ListeningSocket>, ParseError> {
    text.lines()
        .enumerate()
        .filter_map(|(index, line)| {
            parse_line(line, family)
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
fn parse_line(
    line: &str,
    family: AddressFamily,
) -> Result<Option<ListeningSocket>, ParseErrorKind> {
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

    let (address, port) = parse_endpoint(fields[LOCAL_ADDRESS_FIELD], family)?;
    let inode_text = fields[INODE_FIELD];
    let inode: u64 = inode_text
        .parse()
        .map_err(|_| ParseErrorKind::BadInode(inode_text.to_string()))?;

    Ok(Some(ListeningSocket {
        protocol: Protocol::Tcp,
        address,
        port,
        inode,
        options: None,
    }))
}

/// Splits `ADDRESS:PORT` and decodes both halves.
fn parse_endpoint(field: &str, family: AddressFamily) -> Result<(IpAddr, u16), ParseErrorKind> {
    let (address_hex, port_hex) = field
        .split_once(':')
        .ok_or_else(|| ParseErrorKind::MissingPort(field.to_string()))?;

    let address = match family {
        AddressFamily::Ipv4 => IpAddr::V4(decode_ipv4(address_hex)?),
        AddressFamily::Ipv6 => IpAddr::V6(decode_ipv6(address_hex)?),
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
    let bad = || bad_address(hex, IPV6_DIGITS);
    if hex.len() != IPV6_DIGITS {
        return Err(bad());
    }
    let mut bytes = [0u8; 16];
    let (groups, _) = bytes.as_chunks_mut::<4>();
    for (index, group) in groups.iter_mut().enumerate() {
        let start = index * WORD_DIGITS;
        // `get` returns None instead of panicking if the range would split a
        // multi-byte character; `parse_word` rejects anything but hex digits.
        let word = hex
            .get(start..start + WORD_DIGITS)
            .and_then(parse_word)
            .ok_or_else(bad)?;
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
/// Taking the parser as a function pointer gives one checked path for every
/// integer width without a custom trait.
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
mod tests;
