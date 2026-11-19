//! Which packets each host socket can receive: its address, IP family and the
//! interfaces they could arrive on.

use std::collections::BTreeSet;
use std::net::IpAddr;

use crate::network::{HostAddress, HostInterfaces};
use crate::reach::{Coverage, Reason};
use crate::scan::{Listener, ScannedPort};
use crate::service::Service;
use crate::socket::{AddressFamily, Protocol};

/// One group of packets to check: a socket's port and bind address, seen as
/// one IP family on a set of interfaces.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Target {
    pub(super) port: u16,
    pub(super) protocol: Protocol,
    pub(super) address: IpAddr,
    pub(super) family: AddressFamily,
    pub(super) interfaces: BTreeSet<String>,
}

/// The targets of every native host socket. Docker publishes, Tailscale shares
/// and sockets that no packet can reach (an address no interface has, a
/// multicast group) are left out.
pub(super) fn targets(ports: &[ScannedPort], host: &HostInterfaces) -> BTreeSet<Target> {
    ports
        .iter()
        .filter(|row| {
            row.listener == Listener::HostSocket && !matches!(row.service, Service::Container(_))
        })
        .flat_map(|row| {
            let endpoint = row.endpoint;
            families(&row.verdict.reason, endpoint.address)
                .into_iter()
                .filter_map(move |(family, source)| {
                    let interfaces = source.interfaces(family, host);
                    (!interfaces.is_empty()).then_some(Target {
                        port: endpoint.port,
                        protocol: endpoint.protocol,
                        address: endpoint.address,
                        family,
                        interfaces,
                    })
                })
        })
        .collect()
}

/// Where a socket's packets can come in.
#[derive(Clone, Copy)]
enum Source<'a> {
    /// The loopback address: the interfaces that carry loopback addresses.
    Loopback,
    /// The interfaces that carry the bind address.
    Named(&'a BTreeSet<String>),
    /// A wildcard: every interface with an address of the family.
    Wildcard,
}

impl Source<'_> {
    fn interfaces(self, family: AddressFamily, host: &HostInterfaces) -> BTreeSet<String> {
        let names = |keep: &dyn Fn(&HostAddress) -> bool| {
            host.addresses
                .iter()
                .filter(|address| keep(address))
                .map(|address| address.interface.clone())
                .collect()
        };
        match self {
            Self::Loopback => names(&|address| address.ip.is_loopback()),
            Self::Named(interfaces) => interfaces.clone(),
            Self::Wildcard => names(&|address| family_of(address.ip) == family),
        }
    }
}

/// The IP families a socket's packets arrive as, with where they arrive. A
/// wildcard `::` socket that is not IPv6-only takes IPv4 packets too.
fn families(reason: &Reason, bound: IpAddr) -> Vec<(AddressFamily, Source<'_>)> {
    match reason {
        Reason::Loopback => vec![(family_of(bound), Source::Loopback)],
        Reason::OnInterfaces { interfaces } | Reason::Broadcast { interfaces } => {
            vec![(family_of(bound), Source::Named(interfaces))]
        }
        Reason::LimitedBroadcast => vec![(AddressFamily::Ipv4, Source::Wildcard)],
        Reason::AllAddresses { covers, .. } => match covers {
            Coverage::Ipv4 => vec![(AddressFamily::Ipv4, Source::Wildcard)],
            Coverage::Ipv6 => vec![(AddressFamily::Ipv6, Source::Wildcard)],
            Coverage::Ipv4AndIpv6 => vec![
                (AddressFamily::Ipv4, Source::Wildcard),
                (AddressFamily::Ipv6, Source::Wildcard),
            ],
        },
        Reason::TailscaleShared { direct, .. } => families(direct, bound),
        _ => Vec::new(),
    }
}

/// An IPv4-mapped IPv6 address is an IPv4 address seen through an IPv6 socket.
fn family_of(ip: IpAddr) -> AddressFamily {
    if ip.to_canonical().is_ipv6() {
        AddressFamily::Ipv6
    } else {
        AddressFamily::Ipv4
    }
}
