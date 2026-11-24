//! Splitting Caddy network addresses (`[network/]host[:port]`), shared by
//! listen addresses and upstream dial targets.

use std::net::IpAddr;

/// The network prefix of an address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Network {
    /// No prefix: Caddy's default, `tcp`.
    Default,
    /// `tcp/`.
    Tcp,
    /// `tcp4/`.
    Tcp4,
    /// `tcp6/`.
    Tcp6,
    /// Anything else: `udp/`, `unix/`, `fd/`, `ip/` or unknown.
    Other,
}

/// Splits off the network prefix, which Caddy matches case-insensitively.
pub(super) fn split_network(address: &str) -> (Network, &str) {
    let Some((network, rest)) = address.split_once('/') else {
        return (Network::Default, address);
    };
    let network = match network.trim().to_ascii_lowercase().as_str() {
        "tcp" => Network::Tcp,
        "tcp4" => Network::Tcp4,
        "tcp6" => Network::Tcp6,
        _ => Network::Other,
    };
    (network, rest)
}

/// The host and the optional port of `host:port`, `[v6]:port`, `:port`,
/// `host` or `[v6]`, following Go's `net.SplitHostPort`. `None` when the
/// form is invalid, e.g. an IPv6 address without brackets.
pub(super) fn split_host_port(address: &str) -> Option<(&str, Option<&str>)> {
    if let Some(bracketed) = address.strip_prefix('[') {
        let (host, after) = bracketed.split_once(']')?;
        return match after {
            "" => Some((host, None)),
            _ => Some((host, Some(after.strip_prefix(':')?))),
        };
    }
    match address.split_once(':') {
        None => Some((address, None)),
        Some((_, port)) if port.contains(':') => None,
        Some((host, port)) => Some((host, Some(port))),
    }
}

/// What the host part of an address names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Host<'a> {
    /// Empty: every interface when listening.
    Empty,
    /// A literal IP address.
    Ip(IpAddr),
    /// Anything else, which would need name resolution.
    Name(&'a str),
}

/// Classifies the host part returned by [`split_host_port`].
pub(super) fn classify_host(host: &str) -> Host<'_> {
    if host.is_empty() {
        Host::Empty
    } else if let Ok(ip) = host.parse() {
        Host::Ip(ip)
    } else {
        Host::Name(host)
    }
}

/// A port written in decimal, from 1 to 65535.
pub(super) fn parse_port(port: &str) -> Option<u16> {
    port.parse().ok().filter(|&port| port != 0)
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    #[test]
    fn splits_network_prefixes() {
        assert_eq!(split_network(":80"), (Network::Default, ":80"));
        assert_eq!(split_network("TCP4/:80"), (Network::Tcp4, ":80"));
        assert_eq!(split_network("tcp6/[::]:80"), (Network::Tcp6, "[::]:80"));
        assert_eq!(split_network("tcp/:80"), (Network::Tcp, ":80"));
        assert_eq!(
            split_network("unix//run/x.sock"),
            (Network::Other, "/run/x.sock")
        );
    }

    #[test]
    fn splits_hosts_and_ports_like_go() {
        assert_eq!(split_host_port(":443"), Some(("", Some("443"))));
        assert_eq!(split_host_port("[::1]:80"), Some(("::1", Some("80"))));
        assert_eq!(split_host_port("[::1]"), Some(("::1", None)));
        assert_eq!(split_host_port("host"), Some(("host", None)));
        assert_eq!(split_host_port("host:"), Some(("host", Some(""))));
        assert_eq!(split_host_port("::1"), None);
        assert_eq!(split_host_port("[::1]x"), None);
        assert_eq!(split_host_port("[::1"), None);
    }

    #[test]
    fn classifies_hosts() {
        assert_eq!(classify_host(""), Host::Empty);
        assert_eq!(
            classify_host("192.0.2.1"),
            Host::Ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)))
        );
        assert_eq!(
            classify_host("::1"),
            Host::Ip(IpAddr::V6(Ipv6Addr::LOCALHOST))
        );
        assert_eq!(classify_host("app.test"), Host::Name("app.test"));
    }

    #[test]
    fn ports_are_nonzero_decimal() {
        assert_eq!(parse_port("443"), Some(443));
        assert_eq!(parse_port("0"), None);
        assert_eq!(parse_port("65536"), None);
        assert_eq!(parse_port("http"), None);
    }
}
