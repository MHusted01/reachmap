//! Pure Caddy server, TLS mode and route resolution for one client request,
//! following Caddy's matching rules: servers by listen address, routes in
//! order, the first matching route of a group, subroutes, `terminal`.

use std::net::{IpAddr, SocketAddr};

use crate::caddy::{
    CaddyConfig, CaddyServer, Handler, HostMatcher, ListenAddress, ListenHost, ListenNetwork,
    MatcherSet, PathMatcher, Responder, ReverseProxy, Route,
};

/// Why a request could not be resolved to one route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RouteMatchError {
    TlsSchemeMismatch,
    AutomaticHttpsUnverified,
    NoMatchingServer,
    Ambiguous,
    PathNotNormalized,
}

/// The one server and listen address that accept the destination.
pub(super) struct ResolvedServer<'a> {
    pub(super) server: &'a CaddyServer,
    pub(super) listen: &'a ListenAddress,
    pub(super) tls: bool,
}

/// Finds the only server listening on `destination` and checks that its
/// TLS mode is known and matches the request scheme.
pub(super) fn resolve_server(
    config: &CaddyConfig,
    destination: SocketAddr,
    tls: bool,
) -> Result<ResolvedServer<'_>, RouteMatchError> {
    let mut candidates = config.servers.iter().flat_map(|server| {
        server
            .listen
            .iter()
            .filter(move |listen| covers(listen, destination))
            .map(move |listen| (server, listen))
    });
    let (server, listen) = candidates.next().ok_or(RouteMatchError::NoMatchingServer)?;
    if candidates.next().is_some() {
        return Err(RouteMatchError::Ambiguous);
    }
    let server_tls = tls_mode(server).ok_or(RouteMatchError::AutomaticHttpsUnverified)?;
    if server_tls != tls {
        return Err(RouteMatchError::TlsSchemeMismatch);
    }
    Ok(ResolvedServer {
        server,
        listen,
        tls: server_tls,
    })
}

/// Whether `listen` accepts connections to `destination`. A wildcard
/// address on plain `tcp` is dual-stack, as Go opens it.
fn covers(listen: &ListenAddress, destination: SocketAddr) -> bool {
    if !listen.ports().contains(destination.port()) {
        return false;
    }
    let ip = destination.ip().to_canonical();
    let specific = match listen.host() {
        ListenHost::Any {} => None,
        ListenHost::Ipv4 { ip } => Some(IpAddr::V4(ip)),
        ListenHost::Ipv6 { ip } => Some(IpAddr::V6(ip)),
    }
    .filter(|address| !address.is_unspecified());
    match (specific, listen.network()) {
        (Some(address), _) => address.to_canonical() == ip,
        (None, ListenNetwork::Tcp) => true,
        (None, ListenNetwork::Tcp4) => ip.is_ipv4(),
        (None, ListenNetwork::Tcp6) => ip.is_ipv6(),
    }
}

/// Whether the server speaks TLS: explicit connection policies turn it on,
/// and with automatic HTTPS disabled and none configured it is off.
/// Otherwise automatic HTTPS decides at runtime from the host names, so the
/// mode is unknown.
fn tls_mode(server: &CaddyServer) -> Option<bool> {
    if !server.tls_policies.is_empty() {
        Some(true)
    } else if server.automatic_https.disabled {
        Some(false)
    } else {
        None
    }
}

/// The request fields Caddy's `host` and `path` matchers compare, both in
/// lowercase.
pub(super) struct Request {
    host: String,
    path: String,
}

impl Request {
    /// Accepts a host without a trailing dot or IPv6 brackets, and a
    /// normalized ASCII path; Caddy's handling of anything else (path
    /// cleaning, escape matching, Unicode case folding) is not modeled.
    pub(super) fn new(host: &str, path: &str) -> Result<Self, RouteMatchError> {
        let unnormalized = !path.is_ascii()
            || path.contains("//")
            || path.contains('%')
            || path.split('/').any(|segment| matches!(segment, "." | ".."));
        if unnormalized {
            return Err(RouteMatchError::PathNotNormalized);
        }
        let host = host.trim();
        let host = match host.rsplit_once(':') {
            Some((name, port)) if port.bytes().all(|b| b.is_ascii_digit()) => name,
            _ => host,
        };
        if host.contains(['[', ']', ':']) || host.ends_with('.') {
            return Err(RouteMatchError::Ambiguous);
        }
        Ok(Self {
            host: host.to_ascii_lowercase(),
            path: path.to_ascii_lowercase(),
        })
    }
}

/// Where the handler chain ends for the request.
#[derive(Debug, Clone, Copy)]
pub(super) enum End<'a> {
    Proxy(&'a ReverseProxy),
    Respond(Responder),
    /// No handler answered; Caddy then sends an empty `200`.
    Nothing,
}

/// Proxy-layer authentication passed on the way to the end.
#[derive(Debug, Clone, Copy, Default)]
pub(super) struct AuthSeen {
    pub(super) http_basic: bool,
    pub(super) other_providers: bool,
    pub(super) forward_auth: bool,
}

/// The result of following a server's routes for one request.
pub(super) struct Walk<'a> {
    pub(super) end: End<'a>,
    pub(super) auth: AuthSeen,
}

/// The route groups already applied and the authentication seen so far.
/// Caddy keeps one group set per request, shared by all subroutes.
#[derive(Default)]
struct State {
    groups: Vec<usize>,
    auth: AuthSeen,
}

/// Follows `routes` for `request` the way Caddy's compiled handler chain
/// does. A matcher the model cannot evaluate or an unmodeled handler on the
/// path makes the result ambiguous.
pub(super) fn walk<'a>(
    routes: &'a [Route],
    request: &Request,
) -> Result<Walk<'a>, RouteMatchError> {
    let mut state = State::default();
    let end = walk_routes(routes, request, &mut state)?.unwrap_or(End::Nothing);
    Ok(Walk {
        end,
        auth: state.auth,
    })
}

fn walk_routes<'a>(
    routes: &'a [Route],
    request: &Request,
    state: &mut State,
) -> Result<Option<End<'a>>, RouteMatchError> {
    for route in routes {
        let group = route.group.as_ref().map(|group| group.id);
        if group.is_some_and(|id| state.groups.contains(&id)) {
            continue;
        }
        match route_matches(route, request) {
            Some(true) => {}
            Some(false) => continue,
            None => return Err(RouteMatchError::Ambiguous),
        }
        state.groups.extend(group);
        for handler in &route.handlers {
            if let Some(end) = walk_handler(handler, request, state)? {
                return Ok(Some(end));
            }
        }
        if route.terminal {
            break;
        }
    }
    Ok(None)
}

fn walk_handler<'a>(
    handler: &'a Handler,
    request: &Request,
    state: &mut State,
) -> Result<Option<End<'a>>, RouteMatchError> {
    match handler {
        Handler::ReverseProxy(proxy) if proxy.forward_auth => {
            state.auth.forward_auth = true;
            Ok(None)
        }
        Handler::ReverseProxy(proxy) => Ok(Some(End::Proxy(proxy))),
        Handler::Respond { responder } => Ok(Some(End::Respond(*responder))),
        Handler::Subroute { routes } => walk_routes(routes, request, state),
        Handler::Authentication {
            http_basic,
            other_providers,
        } => {
            state.auth.http_basic |= *http_basic;
            state.auth.other_providers |= *other_providers;
            Ok(None)
        }
        Handler::Middleware { .. } => Ok(None),
        Handler::Unmodeled {} => Err(RouteMatchError::Ambiguous),
    }
}

/// `Some(true)` when a matcher set certainly matches, `Some(false)` when
/// none can, `None` when an unmodeled matcher decides.
fn route_matches(route: &Route, request: &Request) -> Option<bool> {
    if route.matchers.is_empty() {
        return Some(true);
    }
    let mut unknown = false;
    for set in &route.matchers {
        match set_matches(set, request) {
            Some(true) => return Some(true),
            Some(false) => {}
            None => unknown = true,
        }
    }
    (!unknown).then_some(false)
}

/// Every matcher of a set must match, so a modeled matcher that fails
/// rejects the set even when another matcher is unmodeled.
fn set_matches(set: &MatcherSet, request: &Request) -> Option<bool> {
    let hosts = set.hosts.as_deref().is_none_or(|hosts| {
        hosts
            .iter()
            .any(|matcher| host_matches(matcher, &request.host))
    });
    let paths = set.paths.as_deref().is_none_or(|paths| {
        paths
            .iter()
            .any(|matcher| path_matches(matcher, &request.path))
    });
    if !(hosts && paths) {
        Some(false)
    } else if set.complete {
        Some(true)
    } else {
        None
    }
}

fn host_matches(matcher: &HostMatcher, host: &str) -> bool {
    match matcher {
        HostMatcher::Exact { host: pattern } => pattern == host,
        HostMatcher::LeadingWildcard { suffix } => host
            .strip_suffix(suffix.as_str())
            .and_then(|rest| rest.strip_suffix('.'))
            .is_some_and(|label| !label.is_empty() && !label.contains('.')),
    }
}

fn path_matches(matcher: &PathMatcher, path: &str) -> bool {
    match matcher {
        PathMatcher::Exact { path: pattern } => pattern == path,
        PathMatcher::Prefix { prefix } => path.starts_with(prefix.as_str()),
    }
}
