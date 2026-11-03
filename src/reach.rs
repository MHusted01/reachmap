//! The verdict for one socket: which networks can reach it, and why.

use std::collections::BTreeSet;
use std::fmt;
use std::net::IpAddr;

use crate::network::{HostAddress, Network};
use crate::socket::AddressFamily;

/// Which networks can connect to a socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reach {
    /// Clients on these networks can connect. Never empty.
    From(BTreeSet<Network>),
    /// reachmap lacks the facts to decide; the [`Reason`] says which.
    Unknown,
}

/// Why a socket got its [`Reach`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reason {
    /// Bound to a loopback address, such as `127.0.0.1` or `::1`.
    Loopback,
    /// Bound to one address of this host, carried by these interfaces
    /// (almost always one).
    OnInterfaces(BTreeSet<String>),
    /// Bound to the wildcard address of this family: `0.0.0.0` (every IPv4
    /// address) or `::` (every IPv6 address, and IPv4 as well unless the
    /// socket is IPv6-only). Whether the socket is restricted to one device
    /// or is IPv6-only is not visible in `/proc/net/tcp`, so the widest
    /// case is assumed.
    AllAddresses(AddressFamily),
    /// Bound to an address that no interface has (any more).
    NotOnHost,
    /// The host's interfaces could not be listed.
    InterfacesUnknown,
}

/// Where a socket can be reached from, with the reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    /// The networks that can connect.
    pub reach: Reach,
    /// Why.
    pub reason: Reason,
}

impl fmt::Display for Reach {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Reach::From(networks) => write_joined(f, networks),
            Reach::Unknown => f.write_str("unknown"),
        }
    }
}

impl fmt::Display for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Reason::Loopback => f.write_str("loopback address"),
            Reason::OnInterfaces(interfaces) => {
                f.write_str("only on ")?;
                write_joined(f, interfaces)
            }
            Reason::AllAddresses(AddressFamily::Ipv4) => {
                f.write_str("all IPv4 addresses (bound device not checked)")
            }
            Reason::AllAddresses(AddressFamily::Ipv6) => {
                f.write_str("all IPv6 and IPv4 addresses (IPv6-only and bound device not checked)")
            }
            Reason::NotOnHost => f.write_str("no interface has this address"),
            Reason::InterfacesUnknown => f.write_str("could not list interfaces"),
        }
    }
}

/// Writes the items separated by `", "`.
fn write_joined<T: fmt::Display>(
    f: &mut fmt::Formatter<'_>,
    items: impl IntoIterator<Item = T>,
) -> fmt::Result {
    for (i, item) in items.into_iter().enumerate() {
        if i > 0 {
            f.write_str(", ")?;
        }
        write!(f, "{item}")?;
    }
    Ok(())
}

/// Decides where a socket bound to `address` can be reached from, given the
/// addresses of this host's interfaces (`None` when they could not be
/// listed). Loopback addresses need no interface facts.
pub fn classify(address: IpAddr, host: Option<&[HostAddress]>) -> Verdict {
    // `::ffff:192.168.1.20` is an IPv4 address seen through an IPv6 socket.
    let address = address.to_canonical();
    if address.is_loopback() {
        return Verdict {
            reach: Reach::From(BTreeSet::from([Network::ThisHost])),
            reason: Reason::Loopback,
        };
    }
    let Some(host) = host else {
        return Verdict {
            reach: Reach::Unknown,
            reason: Reason::InterfacesUnknown,
        };
    };
    if address.is_unspecified() {
        let family = match address {
            IpAddr::V4(_) => AddressFamily::Ipv4,
            IpAddr::V6(_) => AddressFamily::Ipv6,
        };
        // `0.0.0.0` accepts on IPv4 addresses only; `::` on all of them.
        let covered = host
            .iter()
            .filter(|a| family == AddressFamily::Ipv6 || a.ip.to_canonical().is_ipv4());
        return Verdict {
            reach: reach_of(covered),
            reason: Reason::AllAddresses(family),
        };
    }
    let matching: Vec<&HostAddress> = host
        .iter()
        .filter(|a| a.ip.to_canonical() == address)
        .collect();
    if matching.is_empty() {
        return Verdict {
            reach: Reach::Unknown,
            reason: Reason::NotOnHost,
        };
    }
    Verdict {
        reach: reach_of(matching.iter().copied()),
        reason: Reason::OnInterfaces(matching.iter().map(|a| a.interface.clone()).collect()),
    }
}

/// The networks of the given addresses; [`Reach::Unknown`] when there are none.
fn reach_of<'a>(addresses: impl Iterator<Item = &'a HostAddress>) -> Reach {
    let networks: BTreeSet<Network> = addresses.map(HostAddress::network).collect();
    if networks.is_empty() {
        Reach::Unknown
    } else {
        Reach::From(networks)
    }
}

#[cfg(test)]
mod tests {
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
            })
            .collect()
    }

    fn from(networks: &[Network]) -> Reach {
        Reach::From(networks.iter().copied().collect())
    }

    fn only_on(interface: &str) -> Reason {
        Reason::OnInterfaces(BTreeSet::from([interface.to_string()]))
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
            classify(address.parse().unwrap(), Some(host)),
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
        let all_v4 = || Reason::AllAddresses(AddressFamily::Ipv4);
        let all_v6 = || Reason::AllAddresses(AddressFamily::Ipv6);
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
    fn an_address_no_interface_has_is_unknown() {
        assert_eq!(
            classify("10.9.9.9".parse().unwrap(), Some(&example_host())),
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
            classify("10.0.0.1".parse().unwrap(), Some(&host)),
            verdict(
                from(&[Lan]),
                Reason::OnInterfaces(BTreeSet::from(["br0".to_string(), "eth0".to_string()]))
            )
        );
    }

    #[test]
    fn without_interfaces_only_loopback_is_known() {
        assert_eq!(
            classify("127.0.0.1".parse().unwrap(), None),
            verdict(from(&[ThisHost]), Reason::Loopback)
        );
        for address in ["0.0.0.0", "::", "192.168.1.20"] {
            assert_eq!(
                classify(address.parse().unwrap(), None),
                verdict(Reach::Unknown, Reason::InterfacesUnknown),
                "{address}"
            );
        }
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
            Reason::OnInterfaces(BTreeSet::from(["eth0".to_string(), "br0".to_string()]))
                .to_string(),
            "only on br0, eth0"
        );
        assert_eq!(
            Reason::AllAddresses(AddressFamily::Ipv4).to_string(),
            "all IPv4 addresses (bound device not checked)"
        );
        assert_eq!(
            Reason::AllAddresses(AddressFamily::Ipv6).to_string(),
            "all IPv6 and IPv4 addresses (IPv6-only and bound device not checked)"
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
}
