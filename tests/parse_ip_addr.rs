//! Fixture test: parse `ip -j addr` output through the public library API and
//! classify each address. The fixture follows the exact format of iproute2 6.x
//! on a host with Docker and Tailscale, one link of each kind; every value
//! (names, addresses, MACs) is made up.

// Test helpers may panic: a failed test should stop loudly.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use reachmap::network::Network;
use reachmap::parse::ip_addr::parse_ip_addr;

const IP_ADDR: &str = include_str!("fixtures/ip_addr.json");

#[test]
fn fixture_yields_each_address_with_its_interface_and_network() {
    let summary: Vec<(String, String, Network)> = parse_ip_addr(IP_ADDR)
        .unwrap()
        .addresses
        .into_iter()
        .map(|a| {
            let network = a.network();
            (a.interface, a.ip.to_string(), network)
        })
        .collect();

    let expected = [
        ("lo", "127.0.0.1", Network::ThisHost),
        ("lo", "::1", Network::ThisHost),
        ("enp1s0", "192.168.1.20", Network::Lan),
        ("enp1s0", "fe80::42:ff:fe00:2", Network::Lan),
        // wlp2s0 is down and has no addresses.
        ("tailscale0", "100.101.102.103", Network::Tailnet),
        ("tailscale0", "fd7a:115c:a1e0::1", Network::Tailnet),
        ("tailscale0", "fe80::1:2:3:4", Network::Tailnet),
        ("br-0123456789ab", "172.18.0.1", Network::Docker),
        ("br-0123456789ab", "fe80::42:ff:fe00:5", Network::Docker),
        ("docker0", "172.17.0.1", Network::Docker),
        ("veth1a2b3c4", "fe80::42:ff:fe00:9", Network::Docker),
    ]
    .map(|(interface, ip, network)| (interface.to_string(), ip.to_string(), network));

    assert_eq!(summary, expected);
}

#[test]
fn fixture_names_interfaces_by_index() {
    let names = parse_ip_addr(IP_ADDR).unwrap().names;

    assert_eq!(names[&4], "tailscale0");
    // Interfaces without addresses count too: a socket can be bound to one.
    assert_eq!(names[&3], "wlp2s0");
}
