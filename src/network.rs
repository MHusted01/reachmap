//! The networks a client can connect from, and which one each address of this
//! host belongs to.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// One address assigned to one of this host's network interfaces, e.g.
/// `192.168.1.20` on `enp1s0`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostAddress {
    /// Interface name as the kernel reports it, e.g. `enp1s0` or `tailscale0`.
    pub interface: String,
    /// The address.
    pub ip: IpAddr,
}

/// Where a client must be to reach an address of this host. Ordered from the
/// narrowest to the widest audience, so a sorted set reads naturally.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Network {
    /// Only programs on this host, through the loopback interface.
    ThisHost,
    /// Containers on this host's Docker networks.
    Docker,
    /// Devices on the Tailscale network (the tailnet).
    Tailnet,
    /// Devices on the local network: private and link-local addresses.
    Lan,
    /// Anyone on the internet, unless a router or firewall in front of this
    /// host filters the traffic. reachmap cannot see such filters.
    Internet,
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Network::ThisHost => "this host",
            Network::Docker => "Docker",
            Network::Tailnet => "tailnet",
            Network::Lan => "LAN",
            Network::Internet => "internet (if not filtered upstream)",
        })
    }
}

impl HostAddress {
    /// The network this address is reached from, decided by its interface
    /// and its address range, checked in this order:
    ///
    /// 1. loopback address or the `lo` interface: [`Network::ThisHost`]
    /// 2. Tailscale's ranges or the `tailscale0` interface: [`Network::Tailnet`]
    /// 3. a Docker interface (`docker0`, `br-<12 hex>`, `veth*`): [`Network::Docker`]
    /// 4. private or link-local address: [`Network::Lan`]
    /// 5. anything else: [`Network::Internet`]
    pub fn network(&self) -> Network {
        let ip = self.ip.to_canonical();
        if self.interface == LOOPBACK_INTERFACE || ip.is_loopback() {
            Network::ThisHost
        } else if self.interface == TAILSCALE_INTERFACE || TAILNET.iter().any(|p| p.contains(ip)) {
            Network::Tailnet
        } else if is_docker_interface(&self.interface) {
            Network::Docker
        } else if is_private_or_link_local(ip) {
            Network::Lan
        } else {
            Network::Internet
        }
    }
}

/// The loopback interface on Linux.
const LOOPBACK_INTERFACE: &str = "lo";

/// The interface Tailscale creates on Linux (its default `--tun` name).
const TAILSCALE_INTERFACE: &str = "tailscale0";

/// The interface of Docker's default bridge network.
const DOCKER_DEFAULT_BRIDGE: &str = "docker0";

/// Docker names the bridge of a user-defined network `br-` plus the first 12
/// hex digits of the network ID.
const DOCKER_BRIDGE_PREFIX: &str = "br-";
const DOCKER_BRIDGE_ID_LEN: usize = 12;

/// The host end of a container's virtual cable is named `veth` plus 7 hex digits.
const VETH_PREFIX: &str = "veth";

/// Tailscale gives each device an address from these ranges: the shared
/// address space 100.64.0.0/10 (RFC 6598) and its own IPv6 prefix.
const TAILNET: [Prefix; 2] = [
    Prefix {
        network: IpAddr::V4(Ipv4Addr::new(100, 64, 0, 0)),
        len: 10,
    },
    Prefix {
        network: IpAddr::V6(Ipv6Addr::new(0xfd7a, 0x115c, 0xa1e0, 0, 0, 0, 0, 0)),
        len: 48,
    },
];

/// An address range in CIDR notation, e.g. `100.64.0.0/10`: every address
/// whose first `len` bits equal those of `network`.
struct Prefix {
    network: IpAddr,
    len: u32,
}

impl Prefix {
    /// Whether `ip` is in this range. An address of the other IP version
    /// never is.
    fn contains(&self, ip: IpAddr) -> bool {
        // XOR leaves a 1 bit wherever the two addresses differ; shifting out
        // the host bits leaves only differences in the prefix. A shift by the
        // full width (len 0) is `None`: every address matches.
        match (self.network, ip) {
            (IpAddr::V4(network), IpAddr::V4(ip)) => (u32::from(network) ^ u32::from(ip))
                .checked_shr(u32::BITS - self.len)
                .is_none_or(|diff| diff == 0),
            (IpAddr::V6(network), IpAddr::V6(ip)) => (u128::from(network) ^ u128::from(ip))
                .checked_shr(u128::BITS - self.len)
                .is_none_or(|diff| diff == 0),
            _ => false,
        }
    }
}

/// Whether `name` is an interface Docker creates: its default bridge, the
/// bridge of a user-defined network, or a container's veth link.
fn is_docker_interface(name: &str) -> bool {
    name == DOCKER_DEFAULT_BRIDGE
        || name.starts_with(VETH_PREFIX)
        || name.strip_prefix(DOCKER_BRIDGE_PREFIX).is_some_and(|id| {
            id.len() == DOCKER_BRIDGE_ID_LEN
                && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        })
}

/// Private ranges (10/8, 172.16/12, 192.168/16, IPv6 unique local fc00::/7)
/// and link-local ones (169.254/16, fe80::/10): not routed on the internet.
fn is_private_or_link_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_private() || ip.is_link_local(),
        IpAddr::V6(ip) => ip.is_unique_local() || ip.is_unicast_link_local(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn on(interface: &str, ip: &str) -> Network {
        HostAddress {
            interface: interface.to_string(),
            ip: ip.parse().unwrap(),
        }
        .network()
    }

    #[test]
    fn loopback_addresses_and_the_lo_interface_are_this_host() {
        for (interface, ip) in [
            ("lo", "127.0.0.1"),
            ("lo", "127.0.0.53"),
            ("lo", "::1"),
            // An extra address on lo is still only reachable from this host.
            ("lo", "10.53.0.1"),
        ] {
            assert_eq!(on(interface, ip), Network::ThisHost, "{interface} {ip}");
        }
    }

    #[test]
    fn tailscale_ranges_and_interface_are_the_tailnet() {
        for (interface, ip) in [
            ("tailscale0", "100.101.102.103"),
            ("tailscale0", "fd7a:115c:a1e0::1"),
            ("tailscale0", "fe80::1:2:3:4"),
            // First and last address of 100.64.0.0/10.
            ("tun0", "100.64.0.0"),
            ("tun0", "100.127.255.255"),
            ("tun0", "fd7a:115c:a1e0:ffff::1"),
        ] {
            assert_eq!(on(interface, ip), Network::Tailnet, "{interface} {ip}");
        }
    }

    #[test]
    fn addresses_just_outside_the_tailscale_ranges_are_not_the_tailnet() {
        assert_eq!(on("eth0", "100.63.255.255"), Network::Internet);
        assert_eq!(on("eth0", "100.128.0.0"), Network::Internet);
        assert_eq!(on("eth0", "fd7a:115c:a1e1::1"), Network::Lan);
    }

    #[test]
    fn docker_interfaces_are_docker() {
        for (interface, ip) in [
            ("docker0", "172.17.0.1"),
            ("br-0123456789ab", "172.18.0.1"),
            ("br-0123456789ab", "fe80::42:ff:fe00:5"),
            ("veth1a2b3c4", "fe80::42:ff:fe00:9"),
        ] {
            assert_eq!(on(interface, ip), Network::Docker, "{interface} {ip}");
        }
    }

    #[test]
    fn bridges_not_named_like_docker_ones_are_not_docker() {
        // br0 is a common name for a LAN bridge on VM hosts.
        assert_eq!(on("br0", "192.168.1.10"), Network::Lan);
        assert_eq!(on("br-lan", "192.168.1.10"), Network::Lan);
        assert_eq!(on("br-0123456789AB", "172.18.0.1"), Network::Lan);
        assert_eq!(on("br-0123456789a", "172.18.0.1"), Network::Lan);
    }

    #[test]
    fn private_and_link_local_addresses_are_the_lan() {
        for ip in [
            "10.0.0.5",
            "172.16.0.1",
            "172.31.255.254",
            "192.168.1.20",
            "169.254.1.1",
            "fd12:3456:789a::1",
            "fe80::42:ff:fe00:2",
        ] {
            assert_eq!(on("enp1s0", ip), Network::Lan, "{ip}");
        }
    }

    #[test]
    fn public_addresses_are_the_internet() {
        for ip in ["203.0.113.7", "172.32.0.1", "8.8.8.8", "2001:db8::7"] {
            assert_eq!(on("enp1s0", ip), Network::Internet, "{ip}");
        }
    }

    #[test]
    fn networks_sort_from_narrowest_to_widest_audience() {
        let mut networks = vec![
            Network::Internet,
            Network::Lan,
            Network::ThisHost,
            Network::Tailnet,
            Network::Docker,
        ];
        networks.sort();
        assert_eq!(
            networks,
            [
                Network::ThisHost,
                Network::Docker,
                Network::Tailnet,
                Network::Lan,
                Network::Internet,
            ]
        );
    }

    #[test]
    fn displays_each_network_for_the_table() {
        assert_eq!(Network::ThisHost.to_string(), "this host");
        assert_eq!(Network::Docker.to_string(), "Docker");
        assert_eq!(Network::Tailnet.to_string(), "tailnet");
        assert_eq!(Network::Lan.to_string(), "LAN");
        assert_eq!(
            Network::Internet.to_string(),
            "internet (if not filtered upstream)"
        );
    }
}
