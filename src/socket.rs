//! The data reachmap collects about one listening socket.

use std::fmt;
use std::net::IpAddr;

/// Transport protocol of a socket. The IP version is not part of it: that
/// comes from the socket's address (see [`Endpoint::protocol_name`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AddressFamily {
    /// IPv4: addresses are one 32-bit word.
    Ipv4,
    /// IPv6: addresses are four 32-bit words.
    Ipv6,
}

/// Where a host accepts connections. Ordered by port, then protocol, then
/// address (IPv4 before IPv6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
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
}

impl ListeningSocket {
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
        }
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
