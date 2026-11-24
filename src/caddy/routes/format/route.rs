//! The route tree: matchers, handlers, upstreams and the proxy auth in
//! front of each `reverse_proxy`.

use std::fmt;

use crate::caddy::{
    DialTarget, Handler, HostMatcher, MatcherSet, Middleware, PathMatcher, Responder, ReverseProxy,
    Route,
};
use crate::local_tcp::TcpEvidence;
use crate::sanitize::sanitize;

use super::super::auth::AuthContext;
use super::super::link::{upstream_addrs, upstream_match};
use super::target_status;

pub(super) fn write_routes(
    f: &mut fmt::Formatter<'_>,
    routes: &[Route],
    inventory: &TcpEvidence,
    ahead: &AuthContext,
    level: usize,
) -> fmt::Result {
    let mut ahead = ahead.clone();
    for route in routes {
        write_route(f, route, inventory, &ahead, level)?;
        ahead.pass_route(route);
    }
    Ok(())
}

fn write_route(
    f: &mut fmt::Formatter<'_>,
    route: &Route,
    inventory: &TcpEvidence,
    ahead: &AuthContext,
    level: usize,
) -> fmt::Result {
    write!(f, "{:width$}route", "", width = level * 2)?;
    if let Some(group) = &route.group {
        write!(f, " [group {}]", sanitize(&group.label))?;
    }
    write!(f, " match ")?;
    write_matchers(f, &route.matchers)?;
    if route.terminal {
        f.write_str(" [terminal]")?;
    }
    writeln!(f)?;
    let mut context = ahead.clone();
    for handler in &route.handlers {
        write_handler(f, handler, inventory, &context, level + 1)?;
        context.pass_handler(handler);
    }
    Ok(())
}

fn write_matchers(f: &mut fmt::Formatter<'_>, sets: &[MatcherSet]) -> fmt::Result {
    if sets.is_empty() {
        return f.write_str("all requests");
    }
    for (index, set) in sets.iter().enumerate() {
        if index > 0 {
            f.write_str(" or ")?;
        }
        let mut parts = Vec::new();
        if let Some(hosts) = &set.hosts {
            parts.push(format!("host {}", join(hosts.iter().map(host_text))));
        }
        if let Some(paths) = &set.paths {
            parts.push(format!("path {}", join(paths.iter().map(path_text))));
        }
        if parts.is_empty() {
            parts.push("any request".to_owned());
        }
        if !set.complete {
            parts.push("+ unmodeled matchers".to_owned());
        }
        write!(f, "({})", parts.join(" "))?;
    }
    Ok(())
}

fn join(items: impl Iterator<Item = String>) -> String {
    items.collect::<Vec<_>>().join(", ")
}

fn host_text(host: &HostMatcher) -> String {
    match host {
        HostMatcher::Exact { host } => sanitize(host),
        HostMatcher::LeadingWildcard { suffix } => format!("*.{}", sanitize(suffix)),
    }
}

fn path_text(path: &PathMatcher) -> String {
    match path {
        PathMatcher::Exact { path } => sanitize(path),
        PathMatcher::Prefix { prefix } => format!("{}*", sanitize(prefix)),
    }
}

fn write_handler(
    f: &mut fmt::Formatter<'_>,
    handler: &Handler,
    inventory: &TcpEvidence,
    context: &AuthContext,
    level: usize,
) -> fmt::Result {
    let indent = level * 2;
    match handler {
        Handler::ReverseProxy(proxy) => write_proxy(f, proxy, inventory, context, level),
        Handler::Subroute { routes } => {
            writeln!(f, "{:indent$}subroute", "")?;
            write_routes(f, routes, inventory, context, level + 1)
        }
        Handler::Authentication {
            http_basic,
            other_providers,
        } => {
            let mut providers = Vec::new();
            if *http_basic {
                providers.push("http_basic");
            }
            if *other_providers {
                providers.push("other provider");
            }
            writeln!(f, "{:indent$}authentication: {}", "", providers.join(", "))
        }
        Handler::Respond { responder } => {
            writeln!(f, "{:indent$}respond: {}", "", responder_name(*responder))
        }
        Handler::Middleware { middleware } => {
            writeln!(f, "{:indent$}{}", "", middleware_name(*middleware))
        }
        Handler::Unmodeled {} => writeln!(
            f,
            "{:indent$}unmodeled handler (see configuration uncertainties)",
            ""
        ),
    }
}

fn write_proxy(
    f: &mut fmt::Formatter<'_>,
    proxy: &ReverseProxy,
    inventory: &TcpEvidence,
    context: &AuthContext,
    level: usize,
) -> fmt::Result {
    let indent = level * 2;
    let mut flags = Vec::new();
    if proxy.tls {
        flags.push("TLS to upstreams");
    }
    if proxy.forward_auth {
        flags.push("forward_auth");
    }
    if !proxy.complete {
        flags.push("upstreams incomplete");
    }
    write!(f, "{:indent$}reverse_proxy", "")?;
    if !flags.is_empty() {
        write!(f, " [{}]", flags.join(", "))?;
    }
    writeln!(f)?;
    if proxy.upstreams.is_empty() {
        writeln!(f, "{:indent$}  no static upstreams", "")?;
    }
    for target in &proxy.upstreams {
        writeln!(
            f,
            "{:indent$}  upstream {} ({})",
            "",
            target_text(target),
            upstream_status(target, inventory)
        )?;
    }
    writeln!(
        f,
        "{:indent$}  proxy auth: {context}; application auth: unverified",
        ""
    )
}

fn target_text(target: &DialTarget) -> String {
    match target {
        DialTarget::Socket { address } => address.to_string(),
        DialTarget::Localhost { port } => format!("localhost:{port}"),
        DialTarget::Hostname { host, port } => format!("{}:{port}", sanitize(host.as_str())),
    }
}

fn upstream_status(target: &DialTarget, inventory: &TcpEvidence) -> String {
    match target {
        DialTarget::Hostname { .. } => {
            return "host name requires DNS resolution; not linked".to_owned();
        }
        DialTarget::Socket { .. } if upstream_addrs(target).is_empty() => {
            return "unspecified address; not linked".to_owned();
        }
        DialTarget::Socket { .. } | DialTarget::Localhost { .. } => {}
    }
    let TcpEvidence::Collected { listeners } = inventory else {
        return "TCP socket inventory unavailable".to_owned();
    };
    let missing = if target.is_loopback() {
        "no matching TCP listener"
    } else {
        "non-loopback upstream (no exact local TCP listener; may be remote)"
    };
    target_status(upstream_match(listeners, target), missing)
}

fn responder_name(responder: Responder) -> &'static str {
    match responder {
        Responder::StaticResponse => "static_response",
        Responder::FileServer => "file_server",
        Responder::Error => "error",
    }
}

fn middleware_name(middleware: Middleware) -> &'static str {
    match middleware {
        Middleware::Headers => "headers",
        Middleware::Encode => "encode",
        Middleware::RequestBody => "request_body",
        Middleware::Vars => "vars",
        Middleware::Templates => "templates",
        Middleware::Tracing => "tracing",
        Middleware::LogAppend => "log_append",
        Middleware::EarlyHints => "early hints (103)",
    }
}
