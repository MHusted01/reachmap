//! The data reachmap collects about one listening socket.

use std::fmt;
use std::net::IpAddr;

use serde::Serialize;

/// Transport protocol of a socket. The IP version is not part of it: that
/// comes from the socket's address (see [`Endpoint::protocol_name`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    /// Transmission Control Protocol.
    Tcp,
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Protocol::Tcp => "tcp",
        })
    }
}

/// IP version of a kernel socket table: `/proc/net/tcp` holds IPv4 sockets,
/// `/proc/net/tcp6` IPv6 sockets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AddressFamily {
    /// IPv4: addresses are one 32-bit word.
    Ipv4,
    /// IPv6: addresses are four 32-bit words.
    Ipv6,
}

/// Where a host accepts connections. Ordered by port, then protocol, then
/// address (IPv4 before IPv6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct Endpoint {
    /// The local port.
    pub port: u16,
    /// Transport protocol.
    pub protocol: Protocol,
    /// The local address, e.g. `0.0.0.0` (all IPv4 interfaces) or `127.0.0.1`
    /// (this host only).
    pub address: IpAddr,
}

impl Endpoint {
    /// The name `ss` and `netstat` use: `tcp` for IPv4, `tcp6` for IPv6.
    pub fn protocol_name(&self) -> String {
        match self.address {
            IpAddr::V4(_) => self.protocol.to_string(),
            IpAddr::V6(_) => format!("{}6", self.protocol),
        }
    }
}

/// What the kernel's socket diagnostics report beyond `/proc/net/tcp`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SocketOptions {
    /// Index of the interface the socket is bound to (`SO_BINDTODEVICE`, or
    /// the scope of a link-local address), if any. Such a socket only accepts
    /// traffic arriving on that interface.
    pub bound_device: Option<u32>,
    /// Whether a `tcp6` socket refuses IPv4 (`IPV6_V6ONLY`). Always false for
    /// an IPv4 socket.
    pub ipv6_only: bool,
}

/// One socket in the LISTEN state: a service waiting for connections.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListeningSocket {
    /// Transport protocol.
    pub protocol: Protocol,
    /// The local address the socket is bound to, e.g. `0.0.0.0` (all IPv4
    /// interfaces) or `127.0.0.1` (this host only).
    pub address: IpAddr,
    /// The local port.
    pub port: u16,
    /// Kernel ID of the socket. Later used to find the owning process.
    pub inode: u64,
    /// `None` until read from the kernel, or when it could not be.
    pub options: Option<SocketOptions>,
}

impl ListeningSocket {
    /// Whether the socket is known to refuse IPv4.
    pub fn is_ipv6_only(&self) -> bool {
        self.options.is_some_and(|options| options.ipv6_only)
    }

    /// Where this socket accepts connections.
    pub fn endpoint(&self) -> Endpoint {
        Endpoint {
            port: self.port,
            protocol: self.protocol,
            address: self.address,
        }
    }
}

/// Returns the sockets ordered by port, then protocol, then address (IPv4
/// before IPv6).
pub fn sort_by_port(mut sockets: Vec<ListeningSocket>) -> Vec<ListeningSocket> {
    sockets.sort_unstable_by_key(|s| (s.port, s.protocol, s.address, s.inode));
    sockets
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    const ANY_V4: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
    const LOCAL_V4: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
    const ANY_V6: IpAddr = IpAddr::V6(Ipv6Addr::UNSPECIFIED);

    fn socket(address: IpAddr, port: u16) -> ListeningSocket {
        ListeningSocket {
            protocol: Protocol::Tcp,
            address,
            port,
            inode: 1,
            options: None,
        }
    }

    #[test]
    fn only_a_socket_with_the_flag_is_known_to_be_ipv6_only() {
        let options = |ipv6_only| {
            Some(SocketOptions {
                bound_device: None,
                ipv6_only,
            })
        };
        let with = |options| ListeningSocket {
            options,
            ..socket(ANY_V6, 22)
        };

        assert!(with(options(true)).is_ipv6_only());
        assert!(!with(options(false)).is_ipv6_only());
        assert!(!with(None).is_ipv6_only());
    }

    #[test]
    fn protocol_name_adds_6_for_ipv6_addresses() {
        assert_eq!(socket(ANY_V4, 22).endpoint().protocol_name(), "tcp");
        assert_eq!(socket(ANY_V6, 22).endpoint().protocol_name(), "tcp6");
    }

    #[test]
    fn sort_by_port_orders_by_port_then_address_with_ipv4_first() {
        let input = vec![
            socket(ANY_V4, 8080),
            socket(ANY_V6, 22),
            socket(LOCAL_V4, 22),
            socket(ANY_V4, 22),
        ];

        let sorted: Vec<(u16, IpAddr)> = sort_by_port(input)
            .into_iter()
            .map(|s| (s.port, s.address))
            .collect();

        assert_eq!(
            sorted,
            vec![(22, ANY_V4), (22, LOCAL_V4), (22, ANY_V6), (8080, ANY_V4)]
        );
    }
}
