//! Linking Caddy listen addresses and proxy upstreams to local TCP listeners
//! through the shared matcher in [`crate::local_tcp`].
//!
//! Caddy listens through Go's `net.Listen`. With the default `tcp` network a
//! wildcard host (none, `0.0.0.0` or `[::]`) opens one dual-stack `[::]`
//! socket, or `0.0.0.0` on a host without IPv6; `tcp4` opens `0.0.0.0`, and
//! `tcp6` opens `[::]` with `IPV6_V6ONLY` set. A specific address is bound
//! exactly.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::caddy::{
    CaddyConfig, DialTarget, Handler, ListenAddress, ListenHost, ListenNetwork, PortRange,
    ReverseProxy, Route,
};
use crate::local_tcp::{Listener, TargetMatch, candidate, exact_candidate, match_listeners};

/// Most ports of one listen range that are linked one by one.
pub(super) const MAX_LINKED_PORTS: u16 = 64;

/// The ports of `range`, or `None` when it holds more than [`MAX_LINKED_PORTS`].
pub(super) fn linked_ports(range: PortRange) -> Option<std::ops::RangeInclusive<u16>> {
    (range.last() - range.first() < MAX_LINKED_PORTS).then(|| range.first()..=range.last())
}

/// Every listen address of every server that opens TCP listeners. The
/// addresses of an HTTP/3-only server are UDP sockets, which are not linked.
pub(super) fn listens(config: &CaddyConfig) -> impl Iterator<Item = &ListenAddress> {
    config
        .servers
        .iter()
        .filter(|server| server.tcp)
        .flat_map(|server| &server.listen)
}

/// Every `reverse_proxy` handler, subroutes included, in configuration order.
pub(super) fn proxies(config: &CaddyConfig) -> Vec<&ReverseProxy> {
    let mut found = Vec::new();
    for server in &config.servers {
        collect_proxies(&server.routes, &mut found);
    }
    found
}

fn collect_proxies<'a>(routes: &'a [Route], found: &mut Vec<&'a ReverseProxy>) {
    for handler in routes.iter().flat_map(|route| &route.handlers) {
        match handler {
            Handler::ReverseProxy(proxy) => found.push(proxy),
            Handler::Subroute { routes } => collect_proxies(routes, found),
            Handler::Authentication { .. }
            | Handler::Respond { .. }
            | Handler::Middleware { .. }
            | Handler::Unmodeled {} => {}
        }
    }
}

/// Deepest route nesting: 1 for top-level routes only, 0 without routes.
pub(super) fn route_depth(routes: &[Route]) -> usize {
    routes
        .iter()
        .flat_map(|route| &route.handlers)
        .map(|handler| match handler {
            Handler::Subroute { routes } => route_depth(routes),
            _ => 0,
        })
        .max()
        .map_or(usize::from(!routes.is_empty()), |nested| nested + 1)
}

/// Whether any listen address or upstream can be linked to a local socket.
pub(super) fn needs_inventory(config: &CaddyConfig) -> bool {
    listens(config).any(|listen| linked_ports(listen.ports()).is_some())
        || proxies(config)
            .into_iter()
            .flat_map(|proxy| &proxy.upstreams)
            .any(|target| !upstream_addrs(target).is_empty())
}

/// Whether `listener` could serve a linked listen address or upstream.
pub(super) fn listener_is_relevant(listener: &Listener, config: &CaddyConfig) -> bool {
    let frontend = listens(config).any(|listen| {
        linked_ports(listen.ports()).is_some_and(|mut ports| {
            ports.any(|port| frontend_candidate(listener, listen, port).is_some())
        })
    });
    frontend
        || proxies(config)
            .into_iter()
            .flat_map(|proxy| &proxy.upstreams)
            .any(|target| upstream_candidate(listener, target).is_some())
}

/// Which listener serves `port` of `listen`.
pub(super) fn frontend_match(
    listeners: &[Listener],
    listen: &ListenAddress,
    port: u16,
) -> TargetMatch {
    match_listeners(listeners, |listener| {
        frontend_candidate(listener, listen, port)
    })
}

/// Which listener a dial of `target` reaches.
pub(super) fn upstream_match(listeners: &[Listener], target: &DialTarget) -> TargetMatch {
    match_listeners(listeners, |listener| upstream_candidate(listener, target))
}

/// Whether `listener` is the socket Caddy opens for `port` of `listen`:
/// `Some(true)` when certain, `Some(false)` when unknown socket options
/// leave it open, `None` when it is not.
pub(super) fn frontend_candidate(
    listener: &Listener,
    listen: &ListenAddress,
    port: u16,
) -> Option<bool> {
    let specific = match listen.host() {
        ListenHost::Any {} => None,
        ListenHost::Ipv4 { ip } => Some(IpAddr::V4(ip)),
        ListenHost::Ipv6 { ip } => Some(IpAddr::V6(ip)),
    }
    .filter(|ip| !ip.is_unspecified());
    if let Some(ip) = specific {
        return exact_candidate(listener, SocketAddr::new(ip, port));
    }
    let any_ipv4 = || {
        exact_candidate(
            listener,
            SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), port),
        )
    };
    match listen.network() {
        ListenNetwork::Tcp4 => any_ipv4(),
        ListenNetwork::Tcp6 => any_ipv6(listener, port, true),
        ListenNetwork::Tcp => any_ipv6(listener, port, false).or_else(any_ipv4),
    }
}

/// A `[::]` listener whose `IPV6_V6ONLY` setting is `ipv6_only`.
fn any_ipv6(listener: &Listener, port: u16, ipv6_only: bool) -> Option<bool> {
    let confirmed = exact_candidate(
        listener,
        SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), port),
    )?;
    match listener.options {
        Some(options) if options.ipv6_only == ipv6_only => Some(confirmed),
        Some(_) => None,
        None => Some(false),
    }
}

/// The local addresses a dial of `target` can reach: a literal IP, or both
/// loopback addresses for `localhost`. Host names and unspecified addresses
/// are not linked.
pub(super) fn upstream_addrs(target: &DialTarget) -> Vec<SocketAddr> {
    match target {
        DialTarget::Socket { address } if !address.ip().to_canonical().is_unspecified() => {
            vec![*address]
        }
        DialTarget::Localhost { port } => vec![
            SocketAddr::new(Ipv4Addr::LOCALHOST.into(), *port),
            SocketAddr::new(Ipv6Addr::LOCALHOST.into(), *port),
        ],
        DialTarget::Socket { .. } | DialTarget::Hostname { .. } => Vec::new(),
    }
}

/// Loopback targets also match wildcard listeners; any other address needs
/// a listener bound to exactly it, so a wildcard socket cannot make a
/// remote upstream look local.
fn upstream_candidate(listener: &Listener, target: &DialTarget) -> Option<bool> {
    upstream_addrs(target)
        .into_iter()
        .filter_map(|address| {
            if address.ip().to_canonical().is_loopback() {
                candidate(listener, address)
            } else {
                exact_candidate(listener, address)
            }
        })
        .max()
}
