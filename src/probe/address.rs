//! The address of a probed port, as people and scripts see it.

use std::fmt;
use std::net::{IpAddr, SocketAddr};

use serde::{Serialize, Serializer};

/// An IP address with the scope a link-local IPv6 address needs. `fe80::1` can
/// exist on several interfaces, and only the scope tells them apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ProbedAddress {
    ip: IpAddr,
    scope: u32,
}

impl From<IpAddr> for ProbedAddress {
    fn from(ip: IpAddr) -> Self {
        ProbedAddress { ip, scope: 0 }
    }
}

impl From<SocketAddr> for ProbedAddress {
    fn from(target: SocketAddr) -> Self {
        let scope = match target {
            SocketAddr::V4(_) => 0,
            SocketAddr::V6(target) => target.scope_id(),
        };
        ProbedAddress {
            ip: target.ip(),
            scope,
        }
    }
}

impl fmt::Display for ProbedAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.scope {
            0 => write!(f, "{}", self.ip),
            scope => write!(f, "{}%{scope}", self.ip),
        }
    }
}

impl Serialize for ProbedAddress {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV6};

    const LINK_LOCAL: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);

    fn scoped(scope: u32) -> ProbedAddress {
        SocketAddr::V6(SocketAddrV6::new(LINK_LOCAL, 22, 0, scope)).into()
    }

    #[test]
    fn an_ipv4_address_reads_as_itself() {
        let target = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 22);
        assert_eq!(ProbedAddress::from(target).to_string(), "192.0.2.1");
    }

    #[test]
    fn an_ipv6_address_without_a_scope_reads_as_itself() {
        assert_eq!(scoped(0).to_string(), "fe80::1");
    }

    #[test]
    fn a_scope_is_shown_so_the_address_can_be_connected_to() {
        assert_eq!(scoped(3).to_string(), "fe80::1%3");
    }

    #[test]
    fn the_same_address_on_two_interfaces_stays_two_addresses() {
        assert_ne!(scoped(3), scoped(4));
    }

    #[test]
    fn json_holds_the_same_text() {
        assert_eq!(serde_json::to_string(&scoped(3)).unwrap(), "\"fe80::1%3\"");
    }
}
