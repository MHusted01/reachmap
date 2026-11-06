//! The verdict for one socket: which networks can reach it, and why.

use std::collections::{BTreeSet, HashMap};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr};

use serde::{Deserialize, Serialize};

use crate::network::{HostAddress, Network};
use crate::socket::SocketOptions;
use crate::tailscale::Sharing;

/// Which networks can reach a socket.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Reach {
    /// Clients on these networks can connect, or for UDP send to it.
    From {
        /// The networks. Never empty.
        networks: BTreeSet<Network>,
    },
    /// reachmap lacks the facts to decide; the [`Reason`] says which.
    Unknown,
}

/// The addresses a wildcard socket accepts traffic on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Coverage {
    /// IPv4 addresses: `0.0.0.0`.
    Ipv4,
    /// IPv6 addresses: `::` on an IPv6-only socket.
    Ipv6,
    /// Both: `::` on any other socket.
    Ipv4AndIpv6,
}

impl Coverage {
    /// Whether a socket with this coverage accepts connections on `ip`.
    fn includes(self, ip: IpAddr) -> bool {
        match self {
            Coverage::Ipv4 => ip.to_canonical().is_ipv4(),
            Coverage::Ipv6 => ip.to_canonical().is_ipv6(),
            Coverage::Ipv4AndIpv6 => true,
        }
    }

    /// The coverage of the wildcard `address`, widest when `scope` is unknown.
    fn of_wildcard(address: IpAddr, scope: Option<SocketScope<'_>>) -> Self {
        match address {
            IpAddr::V4(_) => Coverage::Ipv4,
            IpAddr::V6(_) if scope.is_some_and(|scope| scope.ipv6_only) => Coverage::Ipv6,
            IpAddr::V6(_) => Coverage::Ipv4AndIpv6,
        }
    }
}

/// What the kernel reports about a socket, with its device named.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SocketScope<'a> {
    /// The interface the socket is bound to, if any.
    pub device: Option<&'a str>,
    /// Whether the socket refuses IPv4.
    pub ipv6_only: bool,
}

impl<'a> SocketScope<'a> {
    /// Names the bound device using the interface `names` by index. `None`
    /// when no interface has that index: the facts then cannot be used.
    pub fn resolve(options: SocketOptions, names: &'a HashMap<u32, String>) -> Option<Self> {
        let device = match options.bound_device {
            Some(index) => Some(names.get(&index)?.as_str()),
            None => None,
        };
        Some(SocketScope {
            device,
            ipv6_only: options.ipv6_only,
        })
    }
}

/// Why a socket got its [`Reach`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Reason {
    /// Bound to a loopback address, such as `127.0.0.1` or `::1`.
    Loopback,
    /// Bound to one address of this host, or to one device.
    OnInterfaces {
        /// The interfaces that carry it (almost always one).
        interfaces: BTreeSet<String>,
    },
    /// Bound to the broadcast address of a subnet: the socket receives what is
    /// broadcast there, not what is sent to this host's own address.
    Broadcast {
        /// The interfaces with that broadcast address (almost always one).
        interfaces: BTreeSet<String>,
    },
    /// Bound to `255.255.255.255`: the socket receives what is broadcast on
    /// any link with IPv4, and no router forwards that.
    LimitedBroadcast,
    /// Bound to a wildcard address: `0.0.0.0` (every IPv4 address) or `::`
    /// (every IPv6 address, and IPv4 as well unless the socket is IPv6-only).
    AllAddresses {
        /// The addresses it accepts connections on.
        covers: Coverage,
        /// Whether the kernel confirmed that no device restricts the socket,
        /// and whether it is IPv6-only. If not, the widest case is assumed.
        checked: bool,
    },
    /// Bound to an address that no interface has (any more).
    NotOnHost,
    /// Bound to a multicast address: the socket receives what is sent to that
    /// group, not what is sent to this host. Which networks those senders are
    /// on depends on the groups the host joined, which reachmap does not read.
    Multicast,
    /// Bound to a wildcard address, but no interface has an address it covers
    /// (e.g. `0.0.0.0` on an IPv6-only host).
    NoAddresses {
        /// The addresses it would accept connections on.
        covers: Coverage,
    },
    /// Bound to a device that has no address the socket can use, such as a
    /// VRF device whose addresses are on other interfaces.
    NoAddressesOnDevice {
        /// The device.
        interface: String,
    },
    /// The host's interfaces could not be listed.
    InterfacesUnknown,
    /// Tailscale forwards connections to this socket, on top of what the
    /// socket's own address allows.
    TailscaleShared {
        /// The ports Tailscale shares with the tailnet.
        served_on: BTreeSet<u16>,
        /// The ports Tailscale shares with the internet through Funnel.
        funnel_on: BTreeSet<u16>,
        /// The reason the socket has by itself.
        direct: Box<Reason>,
    },
    /// Tailscale accepts connections on this port, and they end up at no port
    /// of this host that has a row.
    TailscaleAccepts {
        /// Who Tailscale shares the port with.
        sharing: Sharing,
    },
}

/// Where a socket can be reached from, with the reason.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Verdict {
    /// The networks that can connect.
    pub reach: Reach,
    /// Why.
    pub reason: Reason,
}

impl fmt::Display for Reach {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Reach::From { networks } => write_joined(f, networks),
            Reach::Unknown => f.write_str("unknown"),
        }
    }
}

impl fmt::Display for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Reason::Loopback => f.write_str("loopback address"),
            Reason::OnInterfaces { interfaces } => {
                f.write_str("only on ")?;
                write_joined(f, interfaces)
            }
            Reason::Broadcast { interfaces } => {
                f.write_str("broadcast address of ")?;
                write_joined(f, interfaces)
            }
            Reason::LimitedBroadcast => {
                f.write_str("limited broadcast address, every IPv4 interface")
            }
            Reason::AllAddresses { covers, checked } => f.write_str(match (covers, checked) {
                (Coverage::Ipv4, true) => "all IPv4 addresses",
                (Coverage::Ipv4, false) => "all IPv4 addresses (bound device not checked)",
                (Coverage::Ipv6, _) => "all IPv6 addresses",
                (Coverage::Ipv4AndIpv6, true) => "all IPv6 and IPv4 addresses",
                (Coverage::Ipv4AndIpv6, false) => {
                    "all IPv6 and IPv4 addresses (IPv6-only and bound device not checked)"
                }
            }),
            Reason::NotOnHost => f.write_str("no interface has this address"),
            Reason::Multicast => f.write_str("multicast address, group membership not checked"),
            Reason::NoAddresses { covers } => f.write_str(match covers {
                Coverage::Ipv4 => "no interface has an IPv4 address",
                Coverage::Ipv6 => "no interface has an IPv6 address",
                Coverage::Ipv4AndIpv6 => "no interface has an address",
            }),
            Reason::NoAddressesOnDevice { interface } => {
                write!(f, "bound to {interface}, which has no address it can use")
            }
            Reason::InterfacesUnknown => f.write_str("could not list interfaces"),
            Reason::TailscaleShared {
                served_on,
                funnel_on,
                direct,
            } => {
                write!(f, "{direct}; shared by Tailscale ")?;
                if !served_on.is_empty() {
                    f.write_str("Serve on ")?;
                    write_joined(f, served_on)?;
                }
                if !served_on.is_empty() && !funnel_on.is_empty() {
                    f.write_str(" and ")?;
                }
                if !funnel_on.is_empty() {
                    f.write_str("Funnel on ")?;
                    write_joined(f, funnel_on)?;
                }
                Ok(())
            }
            Reason::TailscaleAccepts { sharing } => {
                write!(
                    f,
                    "accepted by Tailscale {sharing}; no listening port behind it"
                )
            }
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

/// Decides where a socket bound to `address` can be reached from, given what
/// the kernel reports about it (`None` when that is not known, so the widest
/// case is assumed) and the addresses of this host's interfaces (`None` when
/// they could not be listed). Loopback and multicast addresses need no other
/// facts.
pub fn classify(
    address: IpAddr,
    scope: Option<SocketScope<'_>>,
    host: Option<&[HostAddress]>,
) -> Verdict {
    // `::ffff:192.168.1.20` is an IPv4 address seen through an IPv6 socket.
    let address = address.to_canonical();
    if address.is_loopback() {
        return Verdict {
            reach: Reach::From {
                networks: BTreeSet::from([Network::ThisHost]),
            },
            reason: Reason::Loopback,
        };
    }
    if address.is_multicast() {
        return Verdict::unknown(Reason::Multicast);
    }
    let Some(host) = host else {
        return Verdict::unknown(Reason::InterfacesUnknown);
    };
    let device = scope.and_then(|scope| scope.device);
    if address.is_unspecified() {
        let covers = Coverage::of_wildcard(address, scope);
        let checked = scope.is_some();
        classify_covered(
            covers,
            device,
            host,
            Reason::AllAddresses { covers, checked },
        )
    } else if address == IpAddr::V4(Ipv4Addr::BROADCAST) {
        // It belongs to no interface: Linux delivers it from every link.
        classify_covered(Coverage::Ipv4, device, host, Reason::LimitedBroadcast)
    } else {
        classify_address(address, device, host)
    }
}

/// The verdict for a socket that takes traffic for every address in `covers`,
/// for `reason`: the networks of those addresses, on the bound device if there
/// is one.
fn classify_covered(
    covers: Coverage,
    device: Option<&str>,
    host: &[HostAddress],
    reason: Reason,
) -> Verdict {
    if let Some(device) = device {
        return only_on_device(device, covers, host);
    }
    match networks_of(host.iter().filter(|a| covers.includes(a.ip))) {
        Some(networks) => Verdict {
            reach: Reach::From { networks },
            reason,
        },
        None => Verdict::unknown(Reason::NoAddresses { covers }),
    }
}

/// The verdict for one address: the network of the interface that has it, or
/// failing that, of the interface it is the broadcast address of.
fn classify_address(address: IpAddr, device: Option<&str>, host: &[HostAddress]) -> Verdict {
    let owners: Vec<&HostAddress> = host
        .iter()
        .filter(|a| a.ip.to_canonical() == address)
        .collect();
    if !owners.is_empty() {
        return classify_holders(&owners, address, device, host, |interfaces| {
            Reason::OnInterfaces { interfaces }
        });
    }
    let broadcasters: Vec<&HostAddress> =
        host.iter().filter(|a| a.has_broadcast(address)).collect();
    classify_holders(&broadcasters, address, device, host, |interfaces| {
        Reason::Broadcast { interfaces }
    })
}

/// The verdict for an address that `holders` have, with `reason` naming their
/// interfaces. A bound device narrows that. If only another interface holds
/// the address, traffic for it still arrives through the device, because Linux
/// accepts traffic for any local or broadcast address on any interface.
fn classify_holders(
    holders: &[&HostAddress],
    address: IpAddr,
    device: Option<&str>,
    host: &[HostAddress],
    reason: impl FnOnce(BTreeSet<String>) -> Reason,
) -> Verdict {
    let matching: Vec<&HostAddress> = holders
        .iter()
        .copied()
        .filter(|a| device.is_none_or(|device| a.interface == device))
        .collect();
    match (networks_of(matching.iter().copied()), device) {
        (Some(networks), _) => Verdict {
            reach: Reach::From { networks },
            reason: reason(matching.iter().map(|a| a.interface.clone()).collect()),
        },
        (None, Some(device)) if !holders.is_empty() => {
            let family = if address.is_ipv4() {
                Coverage::Ipv4
            } else {
                Coverage::Ipv6
            };
            only_on_device(device, family, host)
        }
        (None, _) => Verdict::unknown(Reason::NotOnHost),
    }
}

/// The verdict for a socket that takes traffic from `device` alone: the
/// networks of that interface's addresses in `covers`.
fn only_on_device(device: &str, covers: Coverage, host: &[HostAddress]) -> Verdict {
    let on_device = host
        .iter()
        .filter(|a| a.interface == device && covers.includes(a.ip));
    match networks_of(on_device) {
        Some(networks) => Verdict {
            reach: Reach::From { networks },
            reason: Reason::OnInterfaces {
                interfaces: BTreeSet::from([device.to_string()]),
            },
        },
        None => Verdict::unknown(Reason::NoAddressesOnDevice {
            interface: device.to_string(),
        }),
    }
}

impl Verdict {
    /// A verdict without reach, for the given reason.
    fn unknown(reason: Reason) -> Self {
        Verdict {
            reach: Reach::Unknown,
            reason,
        }
    }
}

/// The networks of the given addresses, or `None` when there are none, so a
/// [`Reach::From`] is never empty.
fn networks_of<'a>(
    addresses: impl IntoIterator<Item = &'a HostAddress>,
) -> Option<BTreeSet<Network>> {
    let networks: BTreeSet<Network> = addresses.into_iter().map(HostAddress::network).collect();
    (!networks.is_empty()).then_some(networks)
}

#[cfg(test)]
mod tests;
