//! Asks the kernel for the options of every open TCP and UDP socket. A scan
//! works without them: verdicts then assume the widest case and say so.

use std::collections::HashMap;

use thiserror::Error;

use crate::collect::{self, CollectError, SockDiagChannel};
use crate::parse::sock_diag::{SockDiagError, dump_request, parse_dump};
use crate::scan::ISSUES_URL;
use crate::socket::{AddressFamily, Protocol, SocketOptions};

/// Room for one datagram. The kernel fills up to 32 KiB when the reader
/// offers that much; a larger one is reported instead of cut off.
const RECEIVE_BUFFER_LEN: usize = 64 * 1024;

/// The requests of a scan. TCP comes first: UDP diagnostics are a separate
/// kernel option (`INET_UDP_DIAG`), so a kernel may answer for TCP alone.
const DUMPS: [(Protocol, AddressFamily); 4] = [
    (Protocol::Tcp, AddressFamily::Ipv4),
    (Protocol::Tcp, AddressFamily::Ipv6),
    (Protocol::Udp, AddressFamily::Ipv4),
    (Protocol::Udp, AddressFamily::Ipv6),
];

/// The options of each socket the kernel reported, by inode.
pub type OptionsByInode = HashMap<u64, SocketOptions>;

/// What the kernel reported. Every option is a fact on its own, so what was
/// read before a failure stays usable; the other sockets stay unchecked.
#[derive(Debug, Default)]
pub struct OptionsReport {
    /// The sockets the kernel reported on.
    pub by_inode: OptionsByInode,
    /// Why the kernel's report ended early, if it did.
    pub error: Option<SocketOptionsError>,
}

/// Why some options are unknown. The scan still finishes.
#[derive(Debug, Error)]
pub enum SocketOptionsError {
    /// The channel to the kernel could not be opened.
    #[error("could not read socket options")]
    Open(#[source] CollectError),
    /// The kernel could not be asked about one protocol.
    #[error("could not read {protocol} socket options")]
    Collect {
        /// The protocol being asked about.
        protocol: Protocol,
        /// What went wrong.
        #[source]
        source: CollectError,
    },
    /// The kernel refused, or answered with something unusable.
    #[error("could not read {protocol} socket options")]
    Reply {
        /// The protocol being asked about.
        protocol: Protocol,
        /// What went wrong.
        #[source]
        source: SockDiagError,
    },
}

impl SocketOptionsError {
    /// A suggestion for the user, when there is one beyond the message.
    pub fn hint(&self) -> Option<String> {
        match self {
            SocketOptionsError::Reply {
                source: SockDiagError::Malformed,
                ..
            } => Some(format!(
                "this is likely a reachmap bug or a new kernel format; please report it at \
                 {ISSUES_URL}"
            )),
            _ => None,
        }
    }
}

/// Reads the options of this host's open sockets.
pub fn read_socket_options() -> OptionsReport {
    match collect::open_sock_diag() {
        Ok(channel) => options_from(channel.as_ref()),
        Err(error) => OptionsReport {
            error: Some(SocketOptionsError::Open(error)),
            ..OptionsReport::default()
        },
    }
}

/// Asks for each dump in turn and stops at the first failure: after a timeout
/// or a malformed reply, what arrives next may belong to the failed request.
fn options_from(channel: &dyn SockDiagChannel) -> OptionsReport {
    let mut buffer = vec![0; RECEIVE_BUFFER_LEN];
    let mut by_inode = OptionsByInode::new();
    let error = DUMPS
        .into_iter()
        .try_for_each(|(protocol, family)| {
            read_dump(channel, protocol, family, &mut buffer, &mut by_inode)
        })
        .err();
    OptionsReport { by_inode, error }
}

/// Sends one request and reads its reply to the end into `options`.
fn read_dump(
    channel: &dyn SockDiagChannel,
    protocol: Protocol,
    family: AddressFamily,
    buffer: &mut [u8],
    options: &mut OptionsByInode,
) -> Result<(), SocketOptionsError> {
    let collect_error = |source| SocketOptionsError::Collect { protocol, source };
    channel
        .send(&dump_request(protocol, family))
        .map_err(collect_error)?;
    loop {
        let len = channel.receive(buffer).map_err(collect_error)?;
        let dump = parse_dump(&buffer[..len])
            .map_err(|source| SocketOptionsError::Reply { protocol, source })?;
        options.extend(dump.sockets);
        if dump.done {
            return Ok(());
        }
    }
}

#[cfg(test)]
mod tests;
