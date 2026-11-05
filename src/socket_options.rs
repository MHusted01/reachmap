//! Asks the kernel for the options of every listening TCP socket. A scan
//! works without them: verdicts then assume the widest case and say so.

use std::collections::HashMap;

use thiserror::Error;

use crate::collect::{self, CollectError, SockDiagChannel};
use crate::parse::sock_diag::{SockDiagError, dump_request, parse_dump};
use crate::scan::ISSUES_URL;
use crate::socket::{AddressFamily, SocketOptions};

/// Room for one datagram. The kernel fills up to 32 KiB when the reader
/// offers that much; a larger one is reported instead of cut off.
const RECEIVE_BUFFER_LEN: usize = 64 * 1024;

/// The options of each socket the kernel reported, by inode.
pub type OptionsByInode = HashMap<u64, SocketOptions>;

/// Why the options are unknown. The scan still finishes.
#[derive(Debug, Error)]
pub enum SocketOptionsError {
    /// The kernel could not be asked.
    #[error("could not read socket options")]
    Collect(#[source] CollectError),
    /// The kernel refused, or answered with something unusable.
    #[error("could not read socket options")]
    Reply(#[source] SockDiagError),
}

impl SocketOptionsError {
    /// A suggestion for the user, when there is one beyond the message.
    pub fn hint(&self) -> Option<String> {
        match self {
            SocketOptionsError::Reply(SockDiagError::Malformed) => Some(format!(
                "this is likely a reachmap bug or a new kernel format; please report it at \
                 {ISSUES_URL}"
            )),
            _ => None,
        }
    }
}

/// Reads the options of this host's listening TCP sockets.
pub fn read_socket_options() -> Result<OptionsByInode, SocketOptionsError> {
    let channel = collect::open_sock_diag().map_err(SocketOptionsError::Collect)?;
    options_from(channel.as_ref())
}

/// Asks for one dump per address family and reads each to its end.
fn options_from(channel: &dyn SockDiagChannel) -> Result<OptionsByInode, SocketOptionsError> {
    let mut buffer = vec![0; RECEIVE_BUFFER_LEN];
    let mut options = OptionsByInode::new();
    for family in [AddressFamily::Ipv4, AddressFamily::Ipv6] {
        channel
            .send(&dump_request(family))
            .map_err(SocketOptionsError::Collect)?;
        loop {
            let len = channel
                .receive(&mut buffer)
                .map_err(SocketOptionsError::Collect)?;
            let dump = parse_dump(&buffer[..len]).map_err(SocketOptionsError::Reply)?;
            options.extend(dump.sockets);
            if dump.done {
                break;
            }
        }
    }
    Ok(options)
}

#[cfg(test)]
mod tests;
