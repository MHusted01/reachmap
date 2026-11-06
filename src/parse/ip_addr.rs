//! Parser for the JSON that `ip -j addr` prints: one object per network
//! interface, each with a list of assigned addresses.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};

use serde::Deserialize;

use crate::network::{HostAddress, HostInterfaces};

/// One interface as `ip -j addr` prints it. Fields reachmap does not use
/// (MTU, MAC address, flags, ...) are ignored.
#[derive(Deserialize)]
struct Link {
    ifindex: u32,
    ifname: String,
    /// Missing or empty for an interface without addresses.
    #[serde(default)]
    addr_info: Vec<AddrInfo>,
}

/// One address of an interface.
#[derive(Deserialize)]
struct AddrInfo {
    /// The address itself, e.g. `"192.168.1.20"`. serde parses the text
    /// into an `IpAddr`.
    local: IpAddr,
    /// The other end of a point-to-point link, for an address configured
    /// with `peer`. The link has an `address` key too, holding a MAC address;
    /// [`Link`] does not read it.
    address: Option<IpAddr>,
    /// The length of the subnet prefix, e.g. `24`.
    prefixlen: Option<u8>,
    /// The broadcast address of the subnet, e.g. `"192.168.1.255"`. Missing
    /// for IPv6 and for addresses configured without one. The link has a
    /// `broadcast` key too, holding a MAC address; [`Link`] does not read it.
    broadcast: Option<Ipv4Addr>,
}

impl AddrInfo {
    /// The broadcast address `ip` lists, or failing that, the one the kernel
    /// adds for the subnet. With a peer, the subnet is the peer's.
    fn subnet_broadcast(&self) -> Option<Ipv4Addr> {
        self.broadcast
            .or_else(|| computed_broadcast(self.address.unwrap_or(self.local), self.prefixlen?))
    }
}

/// The first prefix length whose subnet has no broadcast address: the kernel
/// adds none for `/31` (RFC 3021) and `/32`.
const FIRST_PREFIX_WITHOUT_BROADCAST: u8 = 31;

/// The address of the subnet of `ip` with every host bit set.
fn computed_broadcast(ip: IpAddr, prefix: u8) -> Option<Ipv4Addr> {
    let IpAddr::V4(ip) = ip else {
        return None;
    };
    (prefix < FIRST_PREFIX_WITHOUT_BROADCAST)
        .then(|| Ipv4Addr::from(u32::from(ip) | (u32::MAX >> prefix)))
}

/// Turns `ip -j addr` output into one [`HostAddress`] per assigned address,
/// in the order the command printed them, and the name of every interface.
pub fn parse_ip_addr(json: &str) -> Result<HostInterfaces, serde_json::Error> {
    let links: Vec<Link> = serde_json::from_str(json)?;
    let names: HashMap<u32, String> = links
        .iter()
        .map(|link| (link.ifindex, link.ifname.clone()))
        .collect();
    let addresses = links
        .into_iter()
        .flat_map(|link| {
            let Link {
                ifname, addr_info, ..
            } = link;
            addr_info.into_iter().map(move |addr| HostAddress {
                interface: ifname.clone(),
                ip: addr.local,
                broadcast: addr.subnet_broadcast(),
            })
        })
        .collect();
    Ok(HostInterfaces { addresses, names })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pairs(json: &str) -> Vec<(String, String)> {
        parse_ip_addr(json)
            .unwrap()
            .addresses
            .into_iter()
            .map(|a| (a.interface, a.ip.to_string()))
            .collect()
    }

    #[test]
    fn yields_every_address_of_every_interface_in_order() {
        let json = r#"[
            {"ifindex": 1, "ifname": "lo", "addr_info": [
                {"family": "inet", "local": "127.0.0.1", "prefixlen": 8},
                {"family": "inet6", "local": "::1", "prefixlen": 128}
            ]},
            {"ifindex": 2, "ifname": "enp1s0", "mtu": 1500, "addr_info": [
                {"family": "inet", "local": "192.168.1.20", "prefixlen": 24, "dynamic": true}
            ]}
        ]"#;

        assert_eq!(
            pairs(json),
            [
                ("lo".to_string(), "127.0.0.1".to_string()),
                ("lo".to_string(), "::1".to_string()),
                ("enp1s0".to_string(), "192.168.1.20".to_string()),
            ]
        );
    }

    #[test]
    fn interfaces_without_addresses_yield_nothing() {
        let json = r#"[
            {"ifindex": 3, "ifname": "wlp2s0", "addr_info": []},
            {"ifindex": 4, "ifname": "dummy0"}
        ]"#;
        assert!(pairs(json).is_empty());
    }

    #[test]
    fn every_interface_is_named_by_its_index_even_without_addresses() {
        let json = r#"[
            {"ifindex": 1, "ifname": "lo", "addr_info": [{"local": "127.0.0.1"}]},
            {"ifindex": 4, "ifname": "vrf-blue"}
        ]"#;
        assert_eq!(
            parse_ip_addr(json).unwrap().names,
            HashMap::from([(1, "lo".to_string()), (4, "vrf-blue".to_string())])
        );
    }

    #[test]
    fn no_interfaces_yield_nothing() {
        assert!(pairs("[]").is_empty());
    }

    #[test]
    fn output_that_is_not_json_is_an_error() {
        assert!(parse_ip_addr("Object \"addr\" is unknown").is_err());
    }

    #[test]
    fn an_address_that_is_not_an_ip_is_an_error() {
        let json = r#"[{"ifindex": 2, "ifname": "eth0", "addr_info": [{"local": "not-an-ip"}]}]"#;
        assert!(parse_ip_addr(json).is_err());
    }

    fn broadcasts(json: &str) -> Vec<Option<Ipv4Addr>> {
        parse_ip_addr(json)
            .unwrap()
            .addresses
            .into_iter()
            .map(|a| a.broadcast)
            .collect()
    }

    #[test]
    fn keeps_the_broadcast_address_of_each_address() {
        let json = r#"[{"ifindex": 2, "ifname": "eth0", "addr_info": [
            {"family": "inet", "local": "192.0.2.20", "broadcast": "192.0.2.255"},
            {"family": "inet", "local": "198.51.100.20", "broadcast": "198.51.100.127"}
        ]}]"#;

        assert_eq!(
            broadcasts(json),
            [
                Some(Ipv4Addr::new(192, 0, 2, 255)),
                Some(Ipv4Addr::new(198, 51, 100, 127))
            ]
        );
    }

    #[test]
    fn an_address_without_a_broadcast_address_has_none() {
        let json = r#"[{"ifindex": 2, "ifname": "eth0", "addr_info": [
            {"family": "inet", "local": "192.0.2.20", "prefixlen": 32},
            {"family": "inet6", "local": "fe80::1", "prefixlen": 64}
        ]}]"#;

        assert_eq!(broadcasts(json), [None, None]);
    }

    #[test]
    fn a_subnet_without_a_listed_broadcast_address_gets_a_computed_one() {
        let json = r#"[{"ifindex": 2, "ifname": "eth0", "addr_info": [
            {"family": "inet", "local": "192.0.2.20", "prefixlen": 24},
            {"family": "inet", "local": "198.51.100.1", "prefixlen": 30},
            {"family": "inet", "local": "10.1.2.3", "prefixlen": 8}
        ]}]"#;

        assert_eq!(
            broadcasts(json),
            [
                Some(Ipv4Addr::new(192, 0, 2, 255)),
                Some(Ipv4Addr::new(198, 51, 100, 3)),
                Some(Ipv4Addr::new(10, 255, 255, 255))
            ]
        );
    }

    #[test]
    fn a_listed_broadcast_address_wins_over_the_computed_one() {
        let json = r#"[{"ifindex": 2, "ifname": "eth0", "addr_info": [
            {"family": "inet", "local": "192.0.2.20", "prefixlen": 24,
             "broadcast": "192.0.2.127"}
        ]}]"#;

        assert_eq!(broadcasts(json), [Some(Ipv4Addr::new(192, 0, 2, 127))]);
    }

    #[test]
    fn a_prefix_of_31_or_longer_has_no_computed_broadcast_address() {
        // 33 and up never come from a real `ip`, and must not panic either.
        for prefix in [31, 32, 33, 255] {
            let json = format!(
                r#"[{{"ifindex": 2, "ifname": "eth0", "addr_info":
                    [{{"family": "inet", "local": "192.0.2.20", "prefixlen": {prefix}}}]}}]"#
            );
            assert_eq!(broadcasts(&json), [None], "/{prefix}");
        }
    }

    #[test]
    fn the_subnet_of_a_peer_address_is_the_peers() {
        // `ip addr add 10.9.0.1 peer 10.9.1.2/24`: the kernel adds the broadcast
        // route of `address`, and `local` can be outside that subnet.
        let json = r#"[{"ifindex": 2, "ifname": "eth0", "addr_info": [
            {"family": "inet", "local": "10.9.0.1", "address": "10.9.1.2", "prefixlen": 24}
        ]}]"#;

        assert_eq!(broadcasts(json), [Some(Ipv4Addr::new(10, 9, 1, 255))]);
    }

    #[test]
    fn a_peer_address_that_is_not_an_ip_is_an_error() {
        let json = r#"[{"ifindex": 2, "ifname": "eth0", "addr_info":
            [{"local": "10.9.0.1", "address": "not-an-ip", "prefixlen": 24}]}]"#;

        assert!(parse_ip_addr(json).is_err());
    }

    #[test]
    fn the_hardware_broadcast_address_of_the_link_is_not_an_ip_broadcast() {
        // The same key one level up holds a MAC address.
        let json = r#"[{"ifindex": 2, "ifname": "eth0", "broadcast": "ff:ff:ff:ff:ff:ff",
            "addr_info": [{"family": "inet", "local": "192.0.2.20"}]}]"#;

        assert_eq!(broadcasts(json), [None]);
    }

    #[test]
    fn a_broadcast_address_that_is_not_an_ipv4_address_is_an_error() {
        for broadcast in ["not-an-ip", "2001:db8::ff"] {
            let json = format!(
                r#"[{{"ifindex": 2, "ifname": "eth0", "addr_info":
                    [{{"local": "192.0.2.20", "broadcast": "{broadcast}"}}]}}]"#
            );
            assert!(parse_ip_addr(&json).is_err(), "{broadcast}");
        }
    }

    #[test]
    fn an_interface_without_a_name_is_an_error() {
        assert!(parse_ip_addr(r#"[{"ifindex": 2, "addr_info": []}]"#).is_err());
    }

    #[test]
    fn an_interface_without_an_index_is_an_error() {
        assert!(parse_ip_addr(r#"[{"ifname": "eth0", "addr_info": []}]"#).is_err());
    }
}
