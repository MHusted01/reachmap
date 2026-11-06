use super::*;

/// A typical host with Docker and Tailscale, one address of each kind.
fn example_host() -> Vec<HostAddress> {
    host(&[
        ("lo", "127.0.0.1"),
        ("lo", "::1"),
        ("enp1s0", "192.168.1.20"),
        ("enp1s0", "fe80::42:ff:fe00:2"),
        ("tailscale0", "100.101.102.103"),
        ("tailscale0", "fd7a:115c:a1e0::1"),
        ("br-0123456789ab", "172.18.0.1"),
        ("docker0", "172.17.0.1"),
    ])
}

/// A host with a public IPv6 address but only a private IPv4 one.
fn public_ipv6() -> Vec<HostAddress> {
    host(&[
        ("lo", "127.0.0.1"),
        ("lo", "::1"),
        ("eth0", "192.168.1.20"),
        ("eth0", "2001:db8:1::20"),
    ])
}

fn host(pairs: &[(&str, &str)]) -> Vec<HostAddress> {
    pairs
        .iter()
        .map(|&(interface, ip)| HostAddress {
            interface: interface.to_string(),
            ip: ip.parse().unwrap(),
            broadcast: None,
        })
        .collect()
}

fn from(networks: &[Network]) -> Reach {
    Reach::From {
        networks: networks.iter().copied().collect(),
    }
}

fn only_on(interface: &str) -> Reason {
    Reason::OnInterfaces {
        interfaces: BTreeSet::from([interface.to_string()]),
    }
}

fn verdict(reach: Reach, reason: Reason) -> Verdict {
    Verdict { reach, reason }
}

use Network::{Docker, Internet, Lan, Tailnet, ThisHost};

/// Asserts that a socket bound to `address` on `host` is reachable from
/// exactly `networks`, for `reason`.
#[track_caller]
fn check(host: &[HostAddress], address: &str, networks: &[Network], reason: Reason) {
    assert_eq!(
        classify(address.parse().unwrap(), None, Some(host)),
        verdict(from(networks), reason),
        "{address}"
    );
}

#[test]
fn loopback_addresses_are_this_host_only() {
    let host = example_host();
    for address in ["127.0.0.1", "127.0.0.53", "::1", "::ffff:127.0.0.1"] {
        check(&host, address, &[ThisHost], Reason::Loopback);
    }
}

#[test]
fn wildcards_reach_every_network_with_an_address_of_their_family() {
    let all_v4 = || Reason::AllAddresses {
        covers: Coverage::Ipv4,
        checked: false,
    };
    let all_v6 = || Reason::AllAddresses {
        covers: Coverage::Ipv4AndIpv6,
        checked: false,
    };
    let everywhere = [ThisHost, Docker, Tailnet, Lan];

    check(&example_host(), "0.0.0.0", &everywhere, all_v4());
    check(&example_host(), "::", &everywhere, all_v6());
    // Only `::` covers the public IPv6 address.
    check(&public_ipv6(), "0.0.0.0", &[ThisHost, Lan], all_v4());
    check(&public_ipv6(), "::", &[ThisHost, Lan, Internet], all_v6());
}

#[test]
fn one_address_reaches_the_network_of_its_interface() {
    let host = example_host();
    check(&host, "192.168.1.20", &[Lan], only_on("enp1s0"));
    check(&host, "::ffff:192.168.1.20", &[Lan], only_on("enp1s0"));
    check(&host, "fe80::42:ff:fe00:2", &[Lan], only_on("enp1s0"));
    check(&host, "100.101.102.103", &[Tailnet], only_on("tailscale0"));
    check(
        &host,
        "fd7a:115c:a1e0::1",
        &[Tailnet],
        only_on("tailscale0"),
    );
    check(&host, "172.18.0.1", &[Docker], only_on("br-0123456789ab"));
    check(&host, "172.17.0.1", &[Docker], only_on("docker0"));
}

#[test]
fn a_public_address_is_the_internet_never_safe() {
    check(
        &public_ipv6(),
        "2001:db8:1::20",
        &[Internet],
        only_on("eth0"),
    );
}

#[test]
fn a_wildcard_without_addresses_of_its_family_is_unknown() {
    let ipv6_only = host(&[("lo", "::1"), ("eth0", "fd12:3456:789a::1")]);
    assert_eq!(
        classify("0.0.0.0".parse().unwrap(), None, Some(&ipv6_only)),
        verdict(
            Reach::Unknown,
            Reason::NoAddresses {
                covers: Coverage::Ipv4
            }
        )
    );
    assert_eq!(
        classify("::".parse().unwrap(), None, Some(&[])),
        verdict(
            Reach::Unknown,
            Reason::NoAddresses {
                covers: Coverage::Ipv4AndIpv6
            }
        )
    );
}

#[test]
fn an_address_no_interface_has_is_unknown() {
    assert_eq!(
        classify("10.9.9.9".parse().unwrap(), None, Some(&example_host())),
        verdict(Reach::Unknown, Reason::NotOnHost)
    );
}

#[test]
fn an_address_on_several_interfaces_lists_them_all() {
    let host = host(&[
        ("eth0", "10.0.0.1"),
        ("br0", "10.0.0.1"),
        ("eth0", "10.0.0.2"),
    ]);
    assert_eq!(
        classify("10.0.0.1".parse().unwrap(), None, Some(&host)),
        verdict(
            from(&[Lan]),
            Reason::OnInterfaces {
                interfaces: BTreeSet::from(["br0".to_string(), "eth0".to_string()]),
            }
        )
    );
}

#[test]
fn without_interfaces_only_loopback_is_known() {
    assert_eq!(
        classify("127.0.0.1".parse().unwrap(), None, None),
        verdict(from(&[ThisHost]), Reason::Loopback)
    );
    for address in ["0.0.0.0", "::", "192.168.1.20"] {
        assert_eq!(
            classify(address.parse().unwrap(), None, None),
            verdict(Reach::Unknown, Reason::InterfacesUnknown),
            "{address}"
        );
    }
}

/// Asserts the verdict for a socket with these checked facts.
#[track_caller]
fn check_scoped(
    host: &[HostAddress],
    address: &str,
    scope: SocketScope<'_>,
    networks: &[Network],
    reason: Reason,
) {
    assert_eq!(
        classify(address.parse().unwrap(), Some(scope), Some(host)),
        verdict(from(networks), reason),
        "{address}"
    );
}

const UNRESTRICTED: SocketScope<'static> = SocketScope {
    device: None,
    ipv6_only: false,
};
const IPV6_ONLY: SocketScope<'static> = SocketScope {
    device: None,
    ipv6_only: true,
};

fn on_device(device: &str) -> SocketScope<'_> {
    SocketScope {
        device: Some(device),
        ipv6_only: false,
    }
}

#[test]
fn a_checked_wildcard_says_so() {
    let everywhere = [ThisHost, Docker, Tailnet, Lan];
    let checked = |covers| Reason::AllAddresses {
        covers,
        checked: true,
    };

    let host = example_host();
    check_scoped(
        &host,
        "0.0.0.0",
        UNRESTRICTED,
        &everywhere,
        checked(Coverage::Ipv4),
    );
    check_scoped(
        &host,
        "::",
        UNRESTRICTED,
        &everywhere,
        checked(Coverage::Ipv4AndIpv6),
    );
}

#[test]
fn an_ipv6_only_wildcard_counts_ipv6_addresses_only() {
    // Docker's bridges and the host's IPv4 LAN address do not count.
    let host = host(&[
        ("lo", "127.0.0.1"),
        ("lo", "::1"),
        ("eth0", "203.0.113.20"),
        ("eth0", "fe80::42:ff:fe00:2"),
        ("docker0", "172.17.0.1"),
    ]);
    check_scoped(
        &host,
        "::",
        IPV6_ONLY,
        &[ThisHost, Lan],
        Reason::AllAddresses {
            covers: Coverage::Ipv6,
            checked: true,
        },
    );
}

#[test]
fn an_ipv6_only_wildcard_without_ipv6_addresses_is_unknown() {
    let ipv4_only = host(&[("lo", "127.0.0.1"), ("eth0", "192.168.1.20")]);
    assert_eq!(
        classify("::".parse().unwrap(), Some(IPV6_ONLY), Some(&ipv4_only)),
        verdict(
            Reach::Unknown,
            Reason::NoAddresses {
                covers: Coverage::Ipv6
            }
        )
    );
}

#[test]
fn a_wildcard_bound_to_a_device_reaches_only_that_interfaces_network() {
    let host = example_host();
    let tailnet = on_device("tailscale0");
    check_scoped(&host, "0.0.0.0", tailnet, &[Tailnet], only_on("tailscale0"));
    check_scoped(&host, "::", tailnet, &[Tailnet], only_on("tailscale0"));
    check_scoped(
        &host,
        "0.0.0.0",
        on_device("lo"),
        &[ThisHost],
        only_on("lo"),
    );
}

#[test]
fn a_bound_wildcard_only_counts_addresses_of_its_family() {
    let host = host(&[("eth0", "192.168.1.20"), ("eth0", "2001:db8:1::20")]);
    check_scoped(&host, "0.0.0.0", on_device("eth0"), &[Lan], only_on("eth0"));
    check_scoped(
        &host,
        "::",
        SocketScope {
            device: Some("eth0"),
            ipv6_only: true,
        },
        &[Internet],
        only_on("eth0"),
    );
    check_scoped(
        &host,
        "::",
        on_device("eth0"),
        &[Lan, Internet],
        only_on("eth0"),
    );
}

#[test]
fn a_device_without_a_usable_address_is_unknown_never_empty() {
    let host = host(&[("eth0", "192.168.1.20"), ("vrf-blue", "fe80::1")]);
    let unknown = verdict(
        Reach::Unknown,
        Reason::NoAddressesOnDevice {
            interface: "vrf-blue".to_string(),
        },
    );
    let scope = Some(on_device("vrf-blue"));

    assert_eq!(
        classify("0.0.0.0".parse().unwrap(), scope, Some(&host)),
        unknown
    );
    assert_eq!(
        classify("192.168.1.20".parse().unwrap(), scope, Some(&host)),
        unknown
    );
}

#[test]
fn an_address_on_its_bound_device_keeps_the_addresss_own_network() {
    // The kernel binds a link-local socket to its interface by itself; the
    // public address on the same interface must not widen the verdict.
    check_scoped(
        &host(&[("eth0", "fe80::1"), ("eth0", "2001:db8:1::20")]),
        "fe80::1",
        on_device("eth0"),
        &[Lan],
        only_on("eth0"),
    );
}

#[test]
fn an_address_on_several_interfaces_is_narrowed_to_the_bound_device() {
    check_scoped(
        &host(&[("eth0", "10.0.0.1"), ("br0", "10.0.0.1")]),
        "10.0.0.1",
        on_device("eth0"),
        &[Lan],
        only_on("eth0"),
    );
}

#[test]
fn an_address_of_another_interface_arrives_through_the_bound_device() {
    // Linux accepts traffic for any local address on any interface.
    check_scoped(
        &example_host(),
        "100.101.102.103",
        on_device("enp1s0"),
        &[Lan],
        only_on("enp1s0"),
    );
}

#[test]
fn a_bound_socket_on_a_foreign_address_is_not_on_this_host() {
    assert_eq!(
        classify(
            "10.9.9.9".parse().unwrap(),
            Some(on_device("enp1s0")),
            Some(&example_host())
        ),
        verdict(Reach::Unknown, Reason::NotOnHost)
    );
}

#[test]
fn a_loopback_address_stays_loopback_on_any_device() {
    check_scoped(
        &example_host(),
        "127.0.0.53",
        on_device("lo"),
        &[ThisHost],
        Reason::Loopback,
    );
}

#[test]
fn a_scope_resolves_the_device_index_to_its_name() {
    let names = HashMap::from([(2, "eth0".to_string())]);
    let options = |bound_device| SocketOptions {
        bound_device,
        ipv6_only: true,
    };

    assert_eq!(
        SocketScope::resolve(options(Some(2)), &names),
        Some(SocketScope {
            device: Some("eth0"),
            ipv6_only: true,
        })
    );
    assert_eq!(SocketScope::resolve(options(None), &names), Some(IPV6_ONLY));
}

#[test]
fn an_unknown_device_index_leaves_the_socket_unchecked() {
    let options = SocketOptions {
        bound_device: Some(9),
        ipv6_only: false,
    };
    assert_eq!(SocketScope::resolve(options, &HashMap::new()), None);
}

#[test]
fn displays_reach_as_a_list_from_narrowest_to_widest() {
    assert_eq!(
        from(&[Lan, ThisHost, Tailnet]).to_string(),
        "this host, tailnet, LAN"
    );
    assert_eq!(
        from(&[Internet]).to_string(),
        "internet (if not filtered upstream)"
    );
    assert_eq!(Reach::Unknown.to_string(), "unknown");
}

#[test]
fn displays_each_reason() {
    assert_eq!(Reason::Loopback.to_string(), "loopback address");
    assert_eq!(only_on("enp1s0").to_string(), "only on enp1s0");
    assert_eq!(
        Reason::OnInterfaces {
            interfaces: BTreeSet::from(["eth0".to_string(), "br0".to_string()]),
        }
        .to_string(),
        "only on br0, eth0"
    );
    let all = |covers, checked| Reason::AllAddresses { covers, checked }.to_string();
    assert_eq!(
        all(Coverage::Ipv4, false),
        "all IPv4 addresses (bound device not checked)"
    );
    assert_eq!(
        all(Coverage::Ipv4AndIpv6, false),
        "all IPv6 and IPv4 addresses (IPv6-only and bound device not checked)"
    );
    assert_eq!(all(Coverage::Ipv4, true), "all IPv4 addresses");
    assert_eq!(all(Coverage::Ipv6, true), "all IPv6 addresses");
    assert_eq!(
        all(Coverage::Ipv4AndIpv6, true),
        "all IPv6 and IPv4 addresses"
    );
    let none = |covers| Reason::NoAddresses { covers }.to_string();
    assert_eq!(none(Coverage::Ipv4), "no interface has an IPv4 address");
    assert_eq!(none(Coverage::Ipv6), "no interface has an IPv6 address");
    assert_eq!(none(Coverage::Ipv4AndIpv6), "no interface has an address");
    assert_eq!(
        Reason::NoAddressesOnDevice {
            interface: "eth1".to_string()
        }
        .to_string(),
        "bound to eth1, which has no address it can use"
    );
    assert_eq!(
        Reason::NotOnHost.to_string(),
        "no interface has this address"
    );
    assert_eq!(
        Reason::InterfacesUnknown.to_string(),
        "could not list interfaces"
    );
}

#[test]
fn a_multicast_address_is_unknown_and_says_why() {
    for address in ["239.255.255.250", "ff02::fb"] {
        let verdict = classify(address.parse().unwrap(), None, Some(&[]));

        assert_eq!(verdict.reach, Reach::Unknown, "{address}");
        assert_eq!(verdict.reason, Reason::Multicast, "{address}");
    }
}

#[test]
fn a_multicast_address_needs_no_interface_facts() {
    let verdict = classify("239.255.255.250".parse().unwrap(), None, None);

    assert_eq!(verdict.reason, Reason::Multicast);
    assert_eq!(
        verdict.reason.to_string(),
        "multicast address, group membership not checked"
    );
}

#[test]
fn a_multicast_address_seen_through_an_ipv6_socket_counts_too() {
    let verdict = classify("::ffff:239.255.255.250".parse().unwrap(), None, Some(&[]));

    assert_eq!(verdict.reason, Reason::Multicast);
}

/// A host whose LAN and Docker subnets have broadcast addresses, as `ip -j
/// addr` reports them.
fn broadcast_host() -> Vec<HostAddress> {
    vec![
        with_broadcast("enp1s0", "192.168.1.20", "192.168.1.255"),
        with_broadcast("eth1", "203.0.113.5", "203.0.113.255"),
        with_broadcast("docker0", "172.17.0.1", "172.17.255.255"),
    ]
}

fn with_broadcast(interface: &str, ip: &str, broadcast: &str) -> HostAddress {
    HostAddress {
        interface: interface.to_string(),
        ip: ip.parse().unwrap(),
        broadcast: Some(broadcast.parse().unwrap()),
    }
}

fn broadcast_of(interfaces: &[&str]) -> Reason {
    Reason::Broadcast {
        interfaces: interfaces.iter().map(ToString::to_string).collect(),
    }
}

#[test]
fn a_broadcast_address_is_reached_from_the_network_of_its_interface() {
    let host = broadcast_host();

    check(&host, "192.168.1.255", &[Lan], broadcast_of(&["enp1s0"]));
    check(&host, "203.0.113.255", &[Internet], broadcast_of(&["eth1"]));
    check(
        &host,
        "172.17.255.255",
        &[Docker],
        broadcast_of(&["docker0"]),
    );
}

#[test]
fn a_broadcast_address_seen_through_an_ipv6_socket_is_recognised() {
    check(
        &broadcast_host(),
        "::ffff:192.168.1.255",
        &[Lan],
        broadcast_of(&["enp1s0"]),
    );
}

#[test]
fn a_broadcast_address_shared_by_two_interfaces_names_both() {
    let host = [
        with_broadcast("enp1s0", "192.168.1.20", "192.168.1.255"),
        with_broadcast("docker0", "192.168.1.30", "192.168.1.255"),
    ];

    check(
        &host,
        "192.168.1.255",
        &[Docker, Lan],
        broadcast_of(&["docker0", "enp1s0"]),
    );
}

#[test]
fn two_addresses_in_one_subnet_name_their_interface_once() {
    let host = [
        with_broadcast("enp1s0", "192.168.1.20", "192.168.1.255"),
        with_broadcast("enp1s0", "192.168.1.21", "192.168.1.255"),
    ];

    check(&host, "192.168.1.255", &[Lan], broadcast_of(&["enp1s0"]));
}

#[test]
fn an_address_of_this_host_is_not_treated_as_a_broadcast_address() {
    // Odd but legal: one interface has as its address what another calls its
    // broadcast address. The interface that has it decides.
    let host = [
        with_broadcast("enp1s0", "192.168.1.20", "192.168.1.255"),
        HostAddress {
            interface: "eth1".to_string(),
            ip: "192.168.1.255".parse().unwrap(),
            broadcast: None,
        },
    ];

    check(&host, "192.168.1.255", &[Lan], only_on("eth1"));
}

#[test]
fn a_broadcast_socket_bound_to_the_device_with_that_broadcast_says_so() {
    check_scoped(
        &broadcast_host(),
        "192.168.1.255",
        on_device("enp1s0"),
        &[Lan],
        broadcast_of(&["enp1s0"]),
    );
}

#[test]
fn a_broadcast_socket_bound_to_another_device_is_only_on_that_device() {
    // Linux delivers what arrives on the device, not what arrives on the
    // interface the broadcast address belongs to.
    check_scoped(
        &broadcast_host(),
        "192.168.1.255",
        on_device("eth1"),
        &[Internet],
        only_on("eth1"),
    );
}

#[test]
fn an_address_that_is_no_broadcast_address_is_still_not_on_this_host() {
    assert_eq!(
        classify(
            "192.168.2.255".parse().unwrap(),
            None,
            Some(&broadcast_host())
        ),
        verdict(Reach::Unknown, Reason::NotOnHost)
    );
}

#[test]
fn a_broadcast_address_needs_the_interfaces() {
    assert_eq!(
        classify("192.168.1.255".parse().unwrap(), None, None),
        verdict(Reach::Unknown, Reason::InterfacesUnknown)
    );
}

#[test]
fn displays_the_interfaces_of_a_broadcast_address() {
    assert_eq!(
        broadcast_of(&["enp1s0"]).to_string(),
        "broadcast address of enp1s0"
    );
    assert_eq!(
        broadcast_of(&["enp1s0", "eth1"]).to_string(),
        "broadcast address of enp1s0, eth1"
    );
}

/// `255.255.255.255`, the broadcast address of no subnet in particular.
const LIMITED_BROADCAST: &str = "255.255.255.255";

#[test]
fn the_limited_broadcast_address_is_reached_from_every_ipv4_network() {
    check(
        &example_host(),
        LIMITED_BROADCAST,
        &[ThisHost, Docker, Tailnet, Lan],
        Reason::LimitedBroadcast,
    );
}

#[test]
fn the_limited_broadcast_address_seen_through_an_ipv6_socket_is_recognised() {
    check(
        &example_host(),
        "::ffff:255.255.255.255",
        &[ThisHost, Docker, Tailnet, Lan],
        Reason::LimitedBroadcast,
    );
}

#[test]
fn ipv6_addresses_add_nothing_to_the_limited_broadcast_address() {
    // The public address is IPv6, so the internet is not on the list.
    check(
        &public_ipv6(),
        LIMITED_BROADCAST,
        &[ThisHost, Lan],
        Reason::LimitedBroadcast,
    );
}

#[test]
fn the_limited_broadcast_address_is_recognised_when_an_interface_lists_it() {
    // `ip addr add ... brd 255.255.255.255` prints it as the broadcast address.
    let host = [
        with_broadcast("enp1s0", "192.168.1.20", LIMITED_BROADCAST),
        with_broadcast("eth1", "203.0.113.5", "203.0.113.255"),
    ];

    check(
        &host,
        LIMITED_BROADCAST,
        &[Lan, Internet],
        Reason::LimitedBroadcast,
    );
}

#[test]
fn a_limited_broadcast_socket_bound_to_a_device_is_only_on_that_device() {
    check_scoped(
        &example_host(),
        LIMITED_BROADCAST,
        on_device("enp1s0"),
        &[Lan],
        only_on("enp1s0"),
    );
}

#[test]
fn a_limited_broadcast_socket_on_a_device_without_ipv4_has_no_address_to_use() {
    let host = host(&[("eth0", "192.168.1.20"), ("eth1", "2001:db8:1::20")]);

    assert_eq!(
        classify(
            LIMITED_BROADCAST.parse().unwrap(),
            Some(on_device("eth1")),
            Some(&host)
        ),
        verdict(
            Reach::Unknown,
            Reason::NoAddressesOnDevice {
                interface: "eth1".to_string()
            }
        )
    );
}

#[test]
fn the_limited_broadcast_address_on_a_host_without_ipv4_reaches_nothing_known() {
    let host = host(&[("eth0", "2001:db8:1::20")]);

    assert_eq!(
        classify(LIMITED_BROADCAST.parse().unwrap(), None, Some(&host)),
        verdict(
            Reach::Unknown,
            Reason::NoAddresses {
                covers: Coverage::Ipv4
            }
        )
    );
}

#[test]
fn the_limited_broadcast_address_needs_the_interfaces() {
    assert_eq!(
        classify(LIMITED_BROADCAST.parse().unwrap(), None, None),
        verdict(Reach::Unknown, Reason::InterfacesUnknown)
    );
}

#[test]
fn the_limited_broadcast_reason_says_what_the_address_is() {
    assert_eq!(
        Reason::LimitedBroadcast.to_string(),
        "limited broadcast address, every IPv4 interface"
    );
}
