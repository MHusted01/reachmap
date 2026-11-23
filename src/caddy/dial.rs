//! Validated `reverse_proxy` upstream dial targets.

use std::fmt;
use std::net::{IpAddr, SocketAddr};

use serde::{Deserialize, Serialize};

use super::UncertaintyKind;
use super::address::{Host, Network, classify_host, parse_port, split_host_port, split_network};

/// Longest host name DNS allows, in characters.
const MAX_HOST_NAME_CHARS: usize = 253;

/// A static TCP upstream of a `reverse_proxy`, e.g. `127.0.0.1:3000`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DialTarget {
    /// A literal IP address and port.
    Socket {
        /// Dialed address.
        address: SocketAddr,
    },
    /// `localhost`, which may resolve to `127.0.0.1`, `::1` or both.
    Localhost {
        /// Dialed port.
        port: u16,
    },
    /// A host name that needs DNS to become an address.
    Hostname {
        /// Validated, lowercase host name.
        host: HostName,
        /// Dialed port.
        port: u16,
    },
}

impl DialTarget {
    /// Parses one `dial` value, or says why it is not a static TCP target.
    pub(crate) fn parse(text: &str) -> Result<Self, DialProblem> {
        if text.contains('{') {
            return Err(DialProblem::Placeholder);
        }
        let (network, address) = split_network(text);
        if network == Network::Other {
            return Err(DialProblem::Transport);
        }
        let (host, port) = split_host_port(address).ok_or(DialProblem::Invalid)?;
        let port = port.and_then(parse_port).ok_or(DialProblem::Invalid)?;
        match classify_host(host) {
            Host::Empty => Err(DialProblem::Invalid),
            Host::Ip(ip) => Ok(Self::Socket {
                address: SocketAddr::new(ip, port),
            }),
            Host::Name(name) if name.eq_ignore_ascii_case("localhost") => {
                Ok(Self::Localhost { port })
            }
            Host::Name(name) => HostName::new(name)
                .map(|host| Self::Hostname { host, port })
                .ok_or(DialProblem::Invalid),
        }
    }

    /// Dialed port.
    pub fn port(&self) -> u16 {
        match self {
            Self::Socket { address } => address.port(),
            Self::Localhost { port } | Self::Hostname { port, .. } => *port,
        }
    }

    /// Whether the target stays on this host: a loopback IP or `localhost`.
    pub fn is_loopback(&self) -> bool {
        match self {
            Self::Socket { address } => address.ip().is_loopback(),
            Self::Localhost { .. } => true,
            Self::Hostname { .. } => false,
        }
    }

    /// The literal IP, when the target names one.
    pub fn ip(&self) -> Option<IpAddr> {
        match self {
            Self::Socket { address } => Some(address.ip()),
            Self::Localhost { .. } | Self::Hostname { .. } => None,
        }
    }
}

/// A lowercase DNS host name of letters, digits, `-` and `_` labels.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct HostName(String);

impl HostName {
    /// A validated host name, or `None` when `name` is not one.
    pub fn new(name: &str) -> Option<Self> {
        let name = name.strip_suffix('.').unwrap_or(name);
        let valid = !name.is_empty()
            && name.len() <= MAX_HOST_NAME_CHARS
            && name.split('.').all(|label| {
                !label.is_empty()
                    && label
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            });
        valid.then(|| Self(name.to_ascii_lowercase()))
    }

    /// The name as text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for HostName {
    type Error = &'static str;

    fn try_from(name: String) -> Result<Self, Self::Error> {
        Self::new(&name).ok_or("not a valid host name")
    }
}

impl From<HostName> for String {
    fn from(name: HostName) -> Self {
        name.0
    }
}

impl fmt::Display for HostName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Why a `dial` value is not a [`DialTarget`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DialProblem {
    /// Contains a `{...}` placeholder.
    Placeholder,
    /// Not a TCP network, e.g. a Unix socket.
    Transport,
    /// Not a valid host and single port.
    Invalid,
}

impl DialProblem {
    /// Uncertainty category of the problem.
    pub(crate) fn kind(self) -> UncertaintyKind {
        match self {
            Self::Placeholder => UncertaintyKind::Placeholder,
            Self::Transport => UncertaintyKind::UnsupportedTransport,
            Self::Invalid => UncertaintyKind::Malformed,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    fn dial(text: &str) -> DialTarget {
        DialTarget::parse(text).expect("valid dial target")
    }

    #[test]
    fn parses_static_targets() {
        let v4 = dial("127.0.0.1:3000");
        assert_eq!(
            v4,
            DialTarget::Socket {
                address: SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 3000)
            }
        );
        assert!(v4.is_loopback());
        assert_eq!(v4.ip(), Some(IpAddr::V4(Ipv4Addr::LOCALHOST)));

        let v6 = dial("tcp6/[::1]:3001");
        assert_eq!(v6.ip(), Some(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert_eq!(v6.port(), 3001);

        let remote = dial("tcp/192.0.2.10:8443");
        assert!(!remote.is_loopback());

        let local = dial("LocalHost:4000");
        assert_eq!(local, DialTarget::Localhost { port: 4000 });
        assert!(local.is_loopback() && local.ip().is_none());

        let named = dial("Auth.Example.Test.:9091");
        let DialTarget::Hostname { host, port } = &named else {
            panic!("expected a host name, got {named:?}");
        };
        assert_eq!((host.as_str(), *port), ("auth.example.test", 9091));
        assert!(!named.is_loopback());
        assert_eq!(named.port(), 9091);
    }

    #[test]
    fn reports_what_it_cannot_resolve_statically() {
        let problem = |text| DialTarget::parse(text).expect_err(text);
        assert_eq!(problem("{http.request.host}:80"), DialProblem::Placeholder);
        assert_eq!(problem("unix//run/app.sock"), DialProblem::Transport);
        assert_eq!(problem("udp/127.0.0.1:53"), DialProblem::Transport);
        assert_eq!(problem("127.0.0.1"), DialProblem::Invalid);
        assert_eq!(problem(":8080"), DialProblem::Invalid);
        assert_eq!(problem("127.0.0.1:8000-8001"), DialProblem::Invalid);
        assert_eq!(problem("\u{1b}[31mhost:80"), DialProblem::Invalid);
        assert_eq!(problem("a..b:80"), DialProblem::Invalid);
    }

    #[test]
    fn host_names_are_validated_when_deserialized() {
        let host: HostName = serde_json::from_str(r#""app.test""#).expect("valid");
        assert_eq!(host.to_string(), "app.test");
        assert_eq!(
            serde_json::to_string(&host).expect("serialize"),
            r#""app.test""#
        );
        assert!(serde_json::from_str::<HostName>(r#""bad host""#).is_err());
        assert!(HostName::new(&"a".repeat(254)).is_none());
    }
}
