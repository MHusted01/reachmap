//! Validated `listen` addresses of a Caddy server.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};

use super::UncertaintyKind;
use super::address::{Host, Network, classify_host, parse_port, split_host_port, split_network};

/// A TCP listen address Caddy binds without name resolution, e.g. `:443`,
/// `127.0.0.1:8080` or `tcp6/[::]:8000-8010`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListenAddress {
    network: ListenNetwork,
    host: ListenHost,
    ports: PortRange,
}

impl ListenAddress {
    /// Network the address binds on.
    pub fn network(&self) -> ListenNetwork {
        self.network
    }

    /// Bound interface address.
    pub fn host(&self) -> ListenHost {
        self.host
    }

    /// Bound ports.
    pub fn ports(&self) -> PortRange {
        self.ports
    }

    /// Parses one `listen` entry, or says why it is not statically understood.
    pub(crate) fn parse(text: &str) -> Result<Self, ListenProblem> {
        if text.contains('{') {
            return Err(ListenProblem::Placeholder);
        }
        let (network, address) = split_network(text);
        let network = match network {
            Network::Default | Network::Tcp => ListenNetwork::Tcp,
            Network::Tcp4 => ListenNetwork::Tcp4,
            Network::Tcp6 => ListenNetwork::Tcp6,
            Network::Other => return Err(ListenProblem::Transport),
        };
        let (host, port) = split_host_port(address).ok_or(ListenProblem::Invalid)?;
        let ports = match port {
            None | Some("") => return Err(ListenProblem::NoPort),
            Some(port) => PortRange::parse(port).ok_or(ListenProblem::Invalid)?,
        };
        let host = match classify_host(host) {
            Host::Empty => ListenHost::Any {},
            Host::Ip(IpAddr::V4(ip)) => ListenHost::Ipv4 { ip },
            Host::Ip(IpAddr::V6(ip)) => ListenHost::Ipv6 { ip },
            Host::Name(_) => return Err(ListenProblem::Hostname),
        };
        Ok(Self {
            network,
            host,
            ports,
        })
    }
}

/// Network of a [`ListenAddress`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ListenNetwork {
    /// `tcp`, the default: IPv4 and IPv6.
    Tcp,
    /// `tcp4`: IPv4 only.
    Tcp4,
    /// `tcp6`: IPv6 only.
    Tcp6,
}

/// Interface address of a [`ListenAddress`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ListenHost {
    /// No host: every interface of the network.
    Any {},
    /// A specific IPv4 address.
    Ipv4 {
        /// Bound address.
        ip: Ipv4Addr,
    },
    /// A specific IPv6 address.
    Ipv6 {
        /// Bound address.
        ip: Ipv6Addr,
    },
}

/// An inclusive, non-empty range of nonzero ports, e.g. `8000-8010`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "UncheckedPortRange")]
pub struct PortRange {
    first: u16,
    last: u16,
}

impl PortRange {
    /// A range from `first` to `last`, or `None` when it is empty or holds 0.
    pub fn new(first: u16, last: u16) -> Option<Self> {
        (first != 0 && first <= last).then_some(Self { first, last })
    }

    /// Lowest port.
    pub fn first(&self) -> u16 {
        self.first
    }

    /// Highest port.
    pub fn last(&self) -> u16 {
        self.last
    }

    /// Whether `port` lies in the range.
    pub fn contains(&self, port: u16) -> bool {
        (self.first..=self.last).contains(&port)
    }

    /// `443` or `8000-8010`.
    fn parse(text: &str) -> Option<Self> {
        match text.split_once('-') {
            None => parse_port(text).and_then(|port| Self::new(port, port)),
            Some((first, last)) => Self::new(parse_port(first)?, parse_port(last)?),
        }
    }
}

/// The shape of [`PortRange`] before its invariant is checked.
#[derive(Deserialize)]
struct UncheckedPortRange {
    first: u16,
    last: u16,
}

impl TryFrom<UncheckedPortRange> for PortRange {
    type Error = &'static str;

    fn try_from(range: UncheckedPortRange) -> Result<Self, Self::Error> {
        Self::new(range.first, range.last).ok_or("port range must be nonzero and ascending")
    }
}

/// Why a `listen` entry is not a [`ListenAddress`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ListenProblem {
    /// Contains a `{...}` placeholder.
    Placeholder,
    /// Not a TCP network.
    Transport,
    /// Names a host that needs resolution.
    Hostname,
    /// States no port.
    NoPort,
    /// Not a valid address.
    Invalid,
}

impl ListenProblem {
    /// Uncertainty category of the problem.
    pub(crate) fn kind(self) -> UncertaintyKind {
        match self {
            Self::Placeholder => UncertaintyKind::Placeholder,
            Self::Transport => UncertaintyKind::UnsupportedTransport,
            Self::Hostname => UncertaintyKind::UnresolvedHost,
            Self::NoPort => UncertaintyKind::ImplicitListen,
            Self::Invalid => UncertaintyKind::Malformed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn listen(text: &str) -> ListenAddress {
        ListenAddress::parse(text).expect("valid listen address")
    }

    #[test]
    fn parses_wildcard_and_specific_addresses() {
        let any = listen(":443");
        assert_eq!(any.network(), ListenNetwork::Tcp);
        assert_eq!(any.host(), ListenHost::Any {});
        assert_eq!(any.ports(), PortRange::new(443, 443).expect("range"));

        assert_eq!(
            listen("127.0.0.1:8080").host(),
            ListenHost::Ipv4 {
                ip: Ipv4Addr::LOCALHOST
            }
        );
        let v6 = listen("tcp6/[::]:8000-8010");
        assert_eq!(v6.network(), ListenNetwork::Tcp6);
        assert_eq!(
            v6.host(),
            ListenHost::Ipv6 {
                ip: Ipv6Addr::UNSPECIFIED
            }
        );
        assert_eq!((v6.ports().first(), v6.ports().last()), (8000, 8010));
        assert!(v6.ports().contains(8005) && !v6.ports().contains(8011));
        assert_eq!(listen("tcp4/0.0.0.0:80").network(), ListenNetwork::Tcp4);
    }

    #[test]
    fn reports_what_it_cannot_resolve_statically() {
        let problem = |text| ListenAddress::parse(text).expect_err(text);
        assert_eq!(problem("{env.ADDR}:80"), ListenProblem::Placeholder);
        assert_eq!(problem("udp/:443"), ListenProblem::Transport);
        assert_eq!(problem("unix//run/caddy.sock"), ListenProblem::Transport);
        assert_eq!(problem("app.example.test:80"), ListenProblem::Hostname);
        assert_eq!(problem("localhost:80"), ListenProblem::Hostname);
        assert_eq!(problem(":"), ListenProblem::NoPort);
        assert_eq!(problem("127.0.0.1"), ListenProblem::NoPort);
        assert_eq!(problem("::1:80"), ListenProblem::Invalid);
        assert_eq!(problem(":0"), ListenProblem::Invalid);
        assert_eq!(problem(":90-80"), ListenProblem::Invalid);
        assert_eq!(problem(":http"), ListenProblem::Invalid);
    }

    #[test]
    fn port_ranges_round_trip_and_reject_invalid_json() {
        let range = PortRange::new(80, 90).expect("range");
        let json = serde_json::to_string(&range).expect("serialize");
        assert_eq!(json, r#"{"first":80,"last":90}"#);
        assert_eq!(
            serde_json::from_str::<PortRange>(&json).expect("parse"),
            range
        );
        assert!(serde_json::from_str::<PortRange>(r#"{"first":90,"last":80}"#).is_err());
        assert!(serde_json::from_str::<PortRange>(r#"{"first":0,"last":0}"#).is_err());
    }
}
