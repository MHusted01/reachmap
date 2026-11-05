//! The netlink socket that talks to the kernel's socket diagnostics. It needs
//! no root, and like `/proc/net/tcp` it shows the current network namespace.
//! Only the kernel can send to it, and the requests only read.

use std::io;
use std::os::fd::OwnedFd;

use rustix::io::{Errno, retry_on_intr};
use rustix::net::netlink::{self, SocketAddrNetlink};
use rustix::net::sockopt::{Timeout, set_socket_timeout};
use rustix::net::{
    AddressFamily, RecvFlags, SendFlags, SocketFlags, SocketType, recv, sendto, socket_with,
};

use super::linux::COMMAND_TIMEOUT;
use super::{CollectError, SockDiagChannel};

/// The kernel's netlink address.
const KERNEL: SocketAddrNetlink = SocketAddrNetlink::new(0, 0);

/// A netlink socket for `NETLINK_SOCK_DIAG`.
struct NetlinkChannel {
    socket: OwnedFd,
}

/// Opens the channel. Waiting for a reply takes at most [`COMMAND_TIMEOUT`], so
/// the scan cannot hang here.
pub(super) fn open() -> Result<Box<dyn SockDiagChannel>, CollectError> {
    let socket = socket_with(
        AddressFamily::NETLINK,
        SocketType::RAW,
        SocketFlags::CLOEXEC,
        Some(netlink::SOCK_DIAG),
    )
    .map_err(failed("open"))?;
    set_socket_timeout(&socket, Timeout::Recv, Some(COMMAND_TIMEOUT)).map_err(failed("open"))?;
    Ok(Box::new(NetlinkChannel { socket }))
}

impl SockDiagChannel for NetlinkChannel {
    fn send(&self, request: &[u8]) -> Result<(), CollectError> {
        retry_on_intr(|| sendto(&self.socket, request, SendFlags::empty(), &KERNEL))
            .map(|_| ())
            .map_err(failed("query"))
    }

    fn receive(&self, buffer: &mut [u8]) -> Result<usize, CollectError> {
        // With `TRUNC` the second length is the datagram's real size.
        let (received, size) = retry_on_intr(|| recv(&self.socket, &mut *buffer, RecvFlags::TRUNC))
            .map_err(failed("read"))?;
        if size > received {
            return Err(failed("read")(Errno::MSGSIZE));
        }
        Ok(received)
    }
}

/// Turns an error code into a [`CollectError`] that names what failed.
fn failed(action: &'static str) -> impl Fn(Errno) -> CollectError {
    move |errno| CollectError::SockDiag {
        action,
        source: io::Error::from(errno),
    }
}
