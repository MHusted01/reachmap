//! Pure Nginx server and location resolution for scoped client HTTP observations.

use std::net::{IpAddr, SocketAddr};

use crate::nginx::{
    ListenAddress, ListenEndpoint, LocationModifier, LocationRoute, NginxConfig, ServerBlock,
    ServerName,
};

pub(super) struct ResolvedServer<'a> {
    pub(super) server: &'a ServerBlock,
    pub(super) listen: &'a ListenEndpoint,
}

pub(super) enum RouteMatchError {
    TlsSchemeMismatch,
    NoMatchingServer,
    Ambiguous,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum ListenTier {
    UncertainIpv4ViaAnyIpv6,
    Wildcard,
    Exact,
}

fn classify_listen(listen: &ListenEndpoint, destination: SocketAddr) -> Option<ListenTier> {
    if listen.port != destination.port() {
        return None;
    }
    match (listen.address, destination.ip().to_canonical()) {
        (ListenAddress::Ipv4 { ip }, IpAddr::V4(dest)) if ip == dest => Some(ListenTier::Exact),
        (ListenAddress::Ipv6 { ip }, IpAddr::V6(dest)) if ip == dest => Some(ListenTier::Exact),
        (ListenAddress::AnyIpv4 {}, IpAddr::V4(_)) => Some(ListenTier::Wildcard),
        (ListenAddress::AnyIpv6 {}, IpAddr::V6(_)) => Some(ListenTier::Wildcard),
        (ListenAddress::AnyIpv6 {}, IpAddr::V4(_)) => match listen.ipv6only {
            Some(false) => Some(ListenTier::Wildcard),
            Some(true) => None,
            None => Some(ListenTier::UncertainIpv4ViaAnyIpv6),
        },
        _ => None,
    }
}

fn normalize_host(host: &str) -> String {
    let trimmed = host.trim().to_ascii_lowercase();
    trimmed.strip_suffix('.').unwrap_or(&trimmed).to_owned()
}

pub(super) fn resolve_server<'a>(
    config: &'a NginxConfig,
    destination: SocketAddr,
    host: &str,
    tls: bool,
) -> Result<ResolvedServer<'a>, RouteMatchError> {
    let mut matching_scheme: Vec<(&'a ServerBlock, &'a ListenEndpoint, ListenTier)> = Vec::new();
    let mut has_opposite_scheme = false;

    for server in &config.servers {
        let mut best_for_server: Option<(&'a ListenEndpoint, ListenTier)> = None;
        for listen in &server.listens {
            let Some(tier) = classify_listen(listen, destination) else {
                continue;
            };
            if listen.ssl != tls {
                has_opposite_scheme = true;
                continue;
            }
            match best_for_server {
                Some((prev_listen, prev_tier))
                    if tier < prev_tier
                        || (tier == prev_tier
                            && (prev_listen.default_server || !listen.default_server)) => {}
                _ => best_for_server = Some((listen, tier)),
            }
        }
        if let Some((listen, tier)) = best_for_server {
            matching_scheme.push((server, listen, tier));
        }
    }

    let Some(highest_tier) = matching_scheme.iter().map(|(_, _, tier)| *tier).max() else {
        return Err(if has_opposite_scheme {
            RouteMatchError::TlsSchemeMismatch
        } else {
            RouteMatchError::NoMatchingServer
        });
    };

    if highest_tier == ListenTier::UncertainIpv4ViaAnyIpv6 {
        return Err(RouteMatchError::Ambiguous);
    }

    let candidates: Vec<(&'a ServerBlock, &'a ListenEndpoint)> = matching_scheme
        .into_iter()
        .filter(|(_, _, tier)| *tier == highest_tier)
        .map(|(server, listen, _)| (server, listen))
        .collect();

    let normalized = normalize_host(host);
    select_server_by_name(&candidates, &normalized)
}

fn select_server_by_name<'a>(
    candidates: &[(&'a ServerBlock, &'a ListenEndpoint)],
    normalized_host: &str,
) -> Result<ResolvedServer<'a>, RouteMatchError> {
    let exact: Vec<_> = candidates
        .iter()
        .copied()
        .filter(|(server, _)| {
            server
                .server_names
                .iter()
                .any(|name| matches!(name, ServerName::Exact { host } if host == normalized_host))
        })
        .collect();
    if let Some(resolved) = single_or_ambiguous(&exact)? {
        return Ok(resolved);
    }

    if let Some(resolved) = longest_wildcard_match(candidates, |name| match name {
        ServerName::LeadingWildcard { suffix }
            if normalized_host
                .strip_suffix(suffix.as_str())
                .is_some_and(|head| head.len() > 1 && head.ends_with('.')) =>
        {
            Some(suffix.len())
        }
        _ => None,
    })? {
        return Ok(resolved);
    }

    if let Some(resolved) = longest_wildcard_match(candidates, |name| match name {
        ServerName::TrailingWildcard { prefix }
            if normalized_host
                .strip_prefix(prefix.as_str())
                .is_some_and(|tail| tail.len() > 1 && tail.starts_with('.')) =>
        {
            Some(prefix.len())
        }
        _ => None,
    })? {
        return Ok(resolved);
    }

    let defaults: Vec<_> = candidates
        .iter()
        .copied()
        .filter(|(_, listen)| listen.default_server)
        .collect();
    if let Some(resolved) = single_or_ambiguous(&defaults)? {
        return Ok(resolved);
    }

    candidates
        .first()
        .map(|&(server, listen)| ResolvedServer { server, listen })
        .ok_or(RouteMatchError::NoMatchingServer)
}

fn longest_wildcard_match<'a>(
    candidates: &[(&'a ServerBlock, &'a ListenEndpoint)],
    score_name: impl Fn(&ServerName) -> Option<usize>,
) -> Result<Option<ResolvedServer<'a>>, RouteMatchError> {
    let scored: Vec<_> = candidates
        .iter()
        .copied()
        .filter_map(|(server, listen)| {
            let best_len = server.server_names.iter().filter_map(&score_name).max()?;
            Some((server, listen, best_len))
        })
        .collect();
    let Some(max_len) = scored.iter().map(|(_, _, len)| *len).max() else {
        return Ok(None);
    };
    let winners: Vec<_> = scored
        .into_iter()
        .filter(|(_, _, len)| *len == max_len)
        .map(|(server, listen, _)| (server, listen))
        .collect();
    single_or_ambiguous(&winners)
}

fn single_or_ambiguous<'a>(
    matches: &[(&'a ServerBlock, &'a ListenEndpoint)],
) -> Result<Option<ResolvedServer<'a>>, RouteMatchError> {
    match matches {
        [] => Ok(None),
        [(server, listen)] => Ok(Some(ResolvedServer { server, listen })),
        _ => Err(RouteMatchError::Ambiguous),
    }
}

pub(super) fn resolve_location<'a>(
    server: &'a ServerBlock,
    path: &str,
) -> Result<Option<&'a LocationRoute>, RouteMatchError> {
    let exact: Vec<_> = server
        .locations
        .iter()
        .filter(|loc| loc.modifier == LocationModifier::Exact && loc.path == path)
        .collect();
    match exact.as_slice() {
        [] => {}
        [one] => return Ok(Some(one)),
        _ => return Err(RouteMatchError::Ambiguous),
    }

    let matching_prefix: Vec<_> = server
        .locations
        .iter()
        .filter(|loc| {
            matches!(
                loc.modifier,
                LocationModifier::PreferentialPrefix | LocationModifier::Prefix
            ) && path.starts_with(&loc.path)
        })
        .collect();
    let Some(max_len) = matching_prefix.iter().map(|loc| loc.path.len()).max() else {
        return Ok(None);
    };
    let longest: Vec<_> = matching_prefix
        .into_iter()
        .filter(|loc| loc.path.len() == max_len)
        .collect();
    let pref: Vec<_> = longest
        .iter()
        .copied()
        .filter(|loc| loc.modifier == LocationModifier::PreferentialPrefix)
        .collect();
    let winners = if pref.is_empty() { &longest } else { &pref };
    match winners.as_slice() {
        [one] => Ok(Some(one)),
        _ => Err(RouteMatchError::Ambiguous),
    }
}
