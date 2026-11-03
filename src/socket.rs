//! The data reachmap collects about one listening socket.

use std::fmt;
use std::net::IpAddr;

/// Which kernel table a socket came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Protocol {
    /// TCP over IPv4, from `/proc/net/tcp`.
    Tcp,
    /// TCP over IPv6, from `/proc/net/tcp6`. Also carries IPv4 clients
    /// through IPv4-mapped addresses such as `::ffff:127.0.0.1`.
    Tcp6,
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Protocol::Tcp => "tcp",
            Protocol::Tcp6 => "tcp6",
        };
        f.write_str(name)
    }
}

/// One socket in the LISTEN state: a service waiting for connections.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListeningSocket {
    pub protocol: Protocol,
    /// The local address the socket is bound to, e.g. `0.0.0.0` (all IPv4
    /// interfaces) or `127.0.0.1` (this host only).
    pub address: IpAddr,
    pub port: u16,
    /// Kernel ID of the socket. Later used to find the owning process.
    pub inode: u64,
}

/// Returns the sockets ordered by port, then protocol, then address.
pub fn sort_by_port(sockets: Vec<ListeningSocket>) -> Vec<ListeningSocket> {
    let mut sorted = sockets;
    sorted.sort_by_key(|s| (s.port, s.protocol, s.address, s.inode));
    sorted
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn socket(protocol: Protocol, address: IpAddr, port: u16) -> ListeningSocket {
        ListeningSocket {
            protocol,
            address,
            port,
            inode: 1,
        }
    }

    #[test]
    fn protocol_displays_as_the_kernel_table_name() {
        assert_eq!(Protocol::Tcp.to_string(), "tcp");
        assert_eq!(Protocol::Tcp6.to_string(), "tcp6");
    }

    #[test]
    fn sort_by_port_orders_by_port_then_protocol_then_address() {
        let any_v4 = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
        let local_v4 = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let any_v6 = IpAddr::V6(Ipv6Addr::UNSPECIFIED);
        let input = vec![
            socket(Protocol::Tcp, any_v4, 8080),
            socket(Protocol::Tcp6, any_v6, 22),
            socket(Protocol::Tcp, local_v4, 22),
            socket(Protocol::Tcp, any_v4, 22),
        ];

        let sorted: Vec<(u16, Protocol, IpAddr)> = sort_by_port(input)
            .into_iter()
            .map(|s| (s.port, s.protocol, s.address))
            .collect();

        assert_eq!(
            sorted,
            vec![
                (22, Protocol::Tcp, any_v4),
                (22, Protocol::Tcp, local_v4),
                (22, Protocol::Tcp6, any_v6),
                (8080, Protocol::Tcp, any_v4),
            ]
        );
    }
}
