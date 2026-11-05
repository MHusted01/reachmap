//! The kernel's socket diagnostics (`NETLINK_SOCK_DIAG`), as bytes: the
//! request that asks for every listening TCP socket, and the parser for the
//! reply. `ss` reads the same interface. It reports two things `/proc/net/tcp`
//! does not: the device a socket is bound to, and its IPv6-only flag.
//!
//! A reply is a run of netlink messages. Each starts with its own length, and
//! the next one starts at the following multiple of 4; the attributes after a
//! socket's fixed fields are framed the same way. All numbers are in the
//! host's byte order, as this interface never leaves the machine.

use std::io;

use thiserror::Error;

use crate::socket::{AddressFamily, SocketOptions};

/// The length of [`dump_request`]'s result.
pub const REQUEST_LEN: usize = HEADER_LEN + REQUEST_BODY_LEN;

/// `struct nlmsghdr`: length, type, flags, sequence number, sender.
const HEADER_LEN: usize = 16;
const TYPE_OFFSET: usize = 4;
const FLAGS_OFFSET: usize = 6;
const SEQUENCE_OFFSET: usize = 8;

/// `struct inet_diag_req_v2`, which holds a `struct inet_diag_sockid` that
/// stays zero in a dump.
const REQUEST_BODY_LEN: usize = 56;
const REQUEST_PROTOCOL_OFFSET: usize = HEADER_LEN + 1;
const REQUEST_STATES_OFFSET: usize = HEADER_LEN + 4;

/// `struct inet_diag_msg`: the fixed fields of a socket, before its attributes.
const SOCKET_LEN: usize = 72;
const SOCKET_DEVICE_OFFSET: usize = 40;
const SOCKET_INODE_OFFSET: usize = 68;

/// `struct nlattr`: length and type, before the attribute's value.
const ATTRIBUTE_HEADER_LEN: usize = 4;
const ATTRIBUTE_TYPE_OFFSET: usize = 2;

/// Messages and attributes start at multiples of this.
const ALIGNMENT: usize = 4;

const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const SOCK_DIAG_BY_FAMILY: u16 = 20;
const NLM_F_REQUEST: u16 = 0x001;
const NLM_F_DUMP: u16 = 0x300;
const INET_DIAG_SKV6ONLY: u16 = 11;
const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;
const IPPROTO_TCP: u8 = 6;
const TCP_LISTEN: u32 = 10;

/// Sequence number of the requests. One request is in flight at a time.
const SEQUENCE: u32 = 1;

/// Why a reply could not be used.
#[derive(Debug, Error)]
pub enum SockDiagError {
    /// A message or attribute is cut off or claims an impossible length.
    #[error("the reply is malformed")]
    Malformed,
    /// The kernel answered with an error code instead of sockets.
    #[error("the kernel refused the request")]
    Refused(#[source] io::Error),
}

/// What one datagram of a reply holds.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Dump {
    /// Inode and options of each socket. A socket lacking a fact is left out,
    /// so it stays unchecked.
    pub sockets: Vec<(u64, SocketOptions)>,
    /// Whether this was the last datagram of the reply.
    pub done: bool,
}

/// The request for every listening TCP socket of one address family.
pub fn dump_request(family: AddressFamily) -> [u8; REQUEST_LEN] {
    let mut request = [0; REQUEST_LEN];
    write(&mut request, 0, &(REQUEST_LEN as u32).to_ne_bytes());
    write(
        &mut request,
        TYPE_OFFSET,
        &SOCK_DIAG_BY_FAMILY.to_ne_bytes(),
    );
    write(
        &mut request,
        FLAGS_OFFSET,
        &(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes(),
    );
    write(&mut request, SEQUENCE_OFFSET, &SEQUENCE.to_ne_bytes());
    write(&mut request, HEADER_LEN, &[family_number(family)]);
    write(&mut request, REQUEST_PROTOCOL_OFFSET, &[IPPROTO_TCP]);
    write(
        &mut request,
        REQUEST_STATES_OFFSET,
        &(1u32 << TCP_LISTEN).to_ne_bytes(),
    );
    request
}

/// Copies `value` into `request` at `offset`.
fn write(request: &mut [u8; REQUEST_LEN], offset: usize, value: &[u8]) {
    request[offset..offset + value.len()].copy_from_slice(value);
}

/// The kernel's number for an address family.
fn family_number(family: AddressFamily) -> u8 {
    match family {
        AddressFamily::Ipv4 => AF_INET,
        AddressFamily::Ipv6 => AF_INET6,
    }
}

/// Parses one datagram of a reply. An empty one is an error, because the
/// kernel never sends one and waiting for more could then go on for ever.
pub fn parse_dump(datagram: &[u8]) -> Result<Dump, SockDiagError> {
    if datagram.is_empty() {
        return Err(SockDiagError::Malformed);
    }
    let mut dump = Dump::default();
    let mut rest = datagram;
    while !rest.is_empty() {
        let (kind, payload, next) = split_message(rest)?;
        match kind {
            SOCK_DIAG_BY_FAMILY => dump.sockets.extend(parse_socket(payload)?),
            NLMSG_ERROR => check_status(payload)?,
            NLMSG_DONE => {
                check_status(payload)?;
                dump.done = true;
                break;
            }
            _ => {}
        }
        rest = next;
    }
    Ok(dump)
}

/// Splits off the first message: its type, its payload, and what follows it.
fn split_message(bytes: &[u8]) -> Result<(u16, &[u8], &[u8]), SockDiagError> {
    let len = read_u32(bytes, 0)? as usize;
    let kind = read_u16(bytes, TYPE_OFFSET)?;
    let (message, rest) = split_framed(bytes, len, HEADER_LEN)?;
    Ok((kind, message, rest))
}

/// Splits `len` framed bytes off `bytes`: what follows a header of
/// `header_len`, and what follows the padding. The last item may lack padding.
fn split_framed(
    bytes: &[u8],
    len: usize,
    header_len: usize,
) -> Result<(&[u8], &[u8]), SockDiagError> {
    if len < header_len {
        return Err(SockDiagError::Malformed);
    }
    let body = bytes.get(header_len..len).ok_or(SockDiagError::Malformed)?;
    let rest = bytes
        .get(len.next_multiple_of(ALIGNMENT)..)
        .unwrap_or_default();
    Ok((body, rest))
}

/// The status in an error or done message: zero, or a negated `errno`.
fn check_status(payload: &[u8]) -> Result<(), SockDiagError> {
    match read_i32(payload, 0)? {
        0 => Ok(()),
        status => Err(SockDiagError::Refused(io::Error::from_raw_os_error(
            status.saturating_neg(),
        ))),
    }
}

/// The inode and options of one socket, or `None` when an IPv6 socket came
/// without its flag.
fn parse_socket(message: &[u8]) -> Result<Option<(u64, SocketOptions)>, SockDiagError> {
    let family = *message.first().ok_or(SockDiagError::Malformed)?;
    let device = read_u32(message, SOCKET_DEVICE_OFFSET)?;
    let inode = read_u32(message, SOCKET_INODE_OFFSET)?;
    let attributes = message.get(SOCKET_LEN..).ok_or(SockDiagError::Malformed)?;
    let ipv6_only = match family {
        AF_INET6 => ipv6_only_attribute(attributes)?,
        _ => Some(false),
    };
    Ok(ipv6_only.map(|ipv6_only| {
        let options = SocketOptions {
            bound_device: (device != 0).then_some(device),
            ipv6_only,
        };
        (u64::from(inode), options)
    }))
}

/// The value of the IPv6-only attribute, if the attributes hold it.
fn ipv6_only_attribute(attributes: &[u8]) -> Result<Option<bool>, SockDiagError> {
    let mut rest = attributes;
    while !rest.is_empty() {
        let len = usize::from(read_u16(rest, 0)?);
        let kind = read_u16(rest, ATTRIBUTE_TYPE_OFFSET)?;
        let (value, next) = split_framed(rest, len, ATTRIBUTE_HEADER_LEN)?;
        if kind == INET_DIAG_SKV6ONLY {
            let flag = value.first().ok_or(SockDiagError::Malformed)?;
            return Ok(Some(*flag != 0));
        }
        rest = next;
    }
    Ok(None)
}

/// The `N` bytes at `offset`.
fn read_bytes<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], SockDiagError> {
    bytes
        .get(offset..)
        .and_then(<[u8]>::first_chunk)
        .copied()
        .ok_or(SockDiagError::Malformed)
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, SockDiagError> {
    read_bytes(bytes, offset).map(u16::from_ne_bytes)
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, SockDiagError> {
    read_bytes(bytes, offset).map(u32::from_ne_bytes)
}

fn read_i32(bytes: &[u8], offset: usize) -> Result<i32, SockDiagError> {
    read_bytes(bytes, offset).map(i32::from_ne_bytes)
}

#[cfg(test)]
mod tests;
