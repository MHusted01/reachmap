//! Does one rule match one packet? Yes, no, or "it depends on something the
//! evaluator does not know".

use std::net::IpAddr;

use crate::socket::{AddressFamily, Protocol};

use super::Traffic;
use super::model::{Address, Construct, Criteria, Direction, Endpoint, RuleProtocol};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Match {
    No,
    Yes,
    Maybe(Construct),
}

impl Match {
    /// Every condition must hold. A condition that is certainly false decides
    /// the answer even when another one is unknown.
    fn and(self, other: Self) -> Self {
        match (self, other) {
            (Self::No, _) | (_, Self::No) => Self::No,
            (Self::Maybe(construct), _) | (_, Self::Maybe(construct)) => Self::Maybe(construct),
            (Self::Yes, Self::Yes) => Self::Yes,
        }
    }

    pub(super) fn of(holds: bool) -> Self {
        if holds { Self::Yes } else { Self::No }
    }
}

fn family(ip: IpAddr) -> AddressFamily {
    match ip {
        IpAddr::V4(_) => AddressFamily::Ipv4,
        IpAddr::V6(_) => AddressFamily::Ipv6,
    }
}

impl Criteria {
    /// Matches one new inbound connection or datagram.
    pub(super) fn matches(&self, traffic: &Traffic<'_>) -> Match {
        [
            Match::of(self.direction != Some(Direction::Out)),
            self.interface.as_ref().map_or(Match::Yes, |interface| {
                Match::of((interface.name == traffic.interface) != interface.negated)
            }),
            self.family.map_or(Match::Yes, |wanted| {
                Match::of(wanted == family(traffic.destination))
            }),
            self.protocol.map_or(Match::Yes, |wanted| {
                Match::of(match (wanted, traffic.protocol) {
                    (RuleProtocol::Tcp, Protocol::Tcp) | (RuleProtocol::Udp, Protocol::Udp) => true,
                    (RuleProtocol::Tcp | RuleProtocol::Udp | RuleProtocol::Other, _) => false,
                })
            }),
            source(&self.source, traffic),
            destination(&self.destination, traffic),
            self.flags.map_or(Match::Yes, |flags| {
                Match::of(traffic.protocol != Protocol::Tcp || flags.matches_new_connection())
            }),
            self.unsupported.map_or(Match::Yes, Match::Maybe),
        ]
        .into_iter()
        .fold(Match::Yes, Match::and)
    }
}

/// The peer is not known for a listening socket, so a restriction on it is
/// unknown unless the caller named a source.
fn source(endpoint: &Endpoint, traffic: &Traffic<'_>) -> Match {
    let port = endpoint
        .port
        .map_or(Match::Yes, |_| Match::Maybe(Construct::SourcePort));
    let address = match (&endpoint.address, traffic.source) {
        (Address::Any, _) => Match::Yes,
        (Address::SelfHost, _) | (Address::Net { .. }, None) => {
            Match::Maybe(Construct::SourceAddress)
        }
        (Address::Net { net, negated }, Some(ip)) => net_match(*net, *negated, ip),
    };
    address.and(port)
}

fn destination(endpoint: &Endpoint, traffic: &Traffic<'_>) -> Match {
    let address = match &endpoint.address {
        Address::Any | Address::SelfHost => Match::Yes,
        Address::Net { net, negated } => net_match(*net, *negated, traffic.destination),
    };
    let port = endpoint.port.map_or(Match::Yes, |wanted| {
        Match::of(wanted.contains(traffic.port))
    });
    address.and(port)
}

/// A network of the other family never matches, not even when negated: pf
/// gives the rule that family.
fn net_match(net: super::fields::Cidr, negated: bool, ip: IpAddr) -> Match {
    if net.is_ipv4() != ip.is_ipv4() {
        return Match::No;
    }
    Match::of(net.contains(ip) != negated)
}
