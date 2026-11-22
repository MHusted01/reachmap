//! Human-readable formatting and local TCP correlation rendering for Nginx routes.

use std::fmt;
use std::net::{IpAddr, SocketAddr};

use crate::local_tcp::{TargetMatch, TcpEvidence, match_listeners};
use crate::nginx::{
    AuthSignals, ListenAddress, ListenEndpoint, LocationModifier, LocationRoute, NginxConfig,
    ProxyScheme, ProxyTarget, ServerBlock, ServerName, SslVerifyClient, Uncertainty,
    UnsupportedProxyReason,
};
use crate::sanitize::sanitize;

use super::{Collection, NginxRouteReport, backend_candidate, listen_candidate};

pub(super) fn write_report(report: &NginxRouteReport, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    writeln!(
        f,
        "Nginx routes (on-disk nginx -T config and local TCP sockets only; running master reload state, TCP connectivity, HTTP responses, upstream policy, and application authentication are unverified)"
    )?;
    if report.config.servers.is_empty()
        && matches!(report.collection, Collection::Complete)
        && report.config.uncertainties.is_empty()
    {
        writeln!(f, "No configured Nginx HTTP servers found.")?;
    }
    for server in &report.config.servers {
        write_server(f, server, &report.config, &report.inventory)?;
    }
    if !report.config.uncertainties.is_empty() {
        writeln!(f, "Configuration uncertainties:")?;
        for uncertainty in &report.config.uncertainties {
            write_uncertainty(f, uncertainty)?;
        }
    }
    if let Collection::Partial { notes } = &report.collection {
        writeln!(f, "Partial Nginx route collection:")?;
        for note in notes {
            writeln!(f, "  {note}")?;
        }
    }
    Ok(())
}

fn write_server(
    f: &mut fmt::Formatter<'_>,
    server: &ServerBlock,
    config: &NginxConfig,
    inventory: &TcpEvidence,
) -> fmt::Result {
    write!(f, "Server ")?;
    if server.server_names.is_empty() {
        f.write_str("<unnamed>")?;
    } else {
        for (idx, name) in server.server_names.iter().enumerate() {
            if idx > 0 {
                f.write_str(", ")?;
            }
            write_server_name(f, name)?;
        }
    }
    if let Some(source) = &server.source_file {
        write!(f, " ({})", sanitize(source))?;
    }
    writeln!(f)?;

    if server.listens.is_empty() {
        writeln!(f, "  listen: <none modeled>")?;
    } else {
        for listen in &server.listens {
            write_listen(f, listen, inventory)?;
        }
    }

    write!(f, "  proxy auth: ")?;
    write_auth(f, &server.auth)?;
    writeln!(f, "; application auth: unverified")?;

    for location in &server.locations {
        write_location(f, location, config, inventory)?;
    }
    Ok(())
}

fn write_server_name(f: &mut fmt::Formatter<'_>, name: &ServerName) -> fmt::Result {
    match name {
        ServerName::Exact { host } => f.write_str(&sanitize(host)),
        ServerName::LeadingWildcard { suffix } => write!(f, "*{}", sanitize(suffix)),
        ServerName::TrailingWildcard { prefix } => write!(f, "{}.*", sanitize(prefix)),
        ServerName::CatchAll {} => f.write_str("_"),
    }
}

fn write_listen(
    f: &mut fmt::Formatter<'_>,
    listen: &ListenEndpoint,
    inventory: &TcpEvidence,
) -> fmt::Result {
    let addr = match listen.address {
        ListenAddress::AnyIpv4 {} => {
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), listen.port)
        }
        ListenAddress::AnyIpv6 {} => {
            SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), listen.port)
        }
        ListenAddress::Ipv4 { ip } => SocketAddr::new(IpAddr::V4(ip), listen.port),
        ListenAddress::Ipv6 { ip } => SocketAddr::new(IpAddr::V6(ip), listen.port),
    };
    write!(f, "  listen: {addr}")?;
    let mut flags = Vec::new();
    if listen.ssl {
        flags.push("ssl");
    }
    if listen.default_server {
        flags.push("default_server");
    }
    match listen.ipv6only {
        Some(true) => flags.push("ipv6only=on"),
        Some(false) => flags.push("ipv6only=off"),
        None => {}
    }
    if !flags.is_empty() {
        write!(f, " [{}]", flags.join(", "))?;
    }
    let status = correlate_listen(listen, inventory);
    writeln!(f, " ({status})")
}

fn correlate_listen(listen: &ListenEndpoint, inventory: &TcpEvidence) -> String {
    let TcpEvidence::Collected { listeners } = inventory else {
        return "TCP socket inventory unavailable".to_owned();
    };
    format_target_match(
        match_listeners(listeners, |listener| listen_candidate(listener, listen)),
        "no matching TCP listener",
    )
}

fn write_location(
    f: &mut fmt::Formatter<'_>,
    location: &LocationRoute,
    config: &NginxConfig,
    inventory: &TcpEvidence,
) -> fmt::Result {
    let modifier = match location.modifier {
        LocationModifier::Exact => "= ",
        LocationModifier::PreferentialPrefix => "^~ ",
        LocationModifier::Prefix => "",
    };
    write!(f, "  location {modifier}{}", sanitize(&location.path))?;
    if let Some(source) = &location.source_file {
        write!(f, " ({})", sanitize(source))?;
    }
    writeln!(f)?;
    write!(f, "    proxy auth: ")?;
    write_auth(f, &location.auth)?;
    writeln!(f, "; application auth: unverified")?;

    match &location.target {
        None => writeln!(f, "    target: <none>"),
        Some(target) => write_target(f, target, config, inventory),
    }
}

fn write_target(
    f: &mut fmt::Formatter<'_>,
    target: &ProxyTarget,
    config: &NginxConfig,
    inventory: &TcpEvidence,
) -> fmt::Result {
    match target {
        ProxyTarget::StaticHttp {
            endpoint, targets, ..
        } => {
            let status = correlate_backend_targets(targets, inventory);
            writeln!(f, "    target: {} ({status})", sanitize(endpoint))
        }
        ProxyTarget::Upstream {
            scheme,
            name,
            targets,
            complete,
        } => {
            let scheme_str = format_scheme(*scheme);
            let group_note = if *complete {
                ""
            } else {
                "; upstream group incomplete"
            };
            writeln!(
                f,
                "    target: {scheme_str}://{} (upstream group{group_note})",
                sanitize(name)
            )?;
            if let Some(group) = config.upstreams.iter().find(|group| group.name == *name) {
                let active: Vec<_> = group.servers.iter().filter(|server| !server.down).collect();
                if active.is_empty() {
                    return writeln!(f, "      no active upstream servers");
                }
                for server in active {
                    let backup = if server.backup { " [backup]" } else { "" };
                    let addrs = format_addr_list(&server.targets);
                    let status = correlate_backend_targets(&server.targets, inventory);
                    writeln!(f, "      upstream server {addrs}{backup} ({status})")?;
                }
                Ok(())
            } else if targets.is_empty() {
                writeln!(f, "      no active upstream servers")
            } else {
                let addrs = format_addr_list(targets);
                let status = correlate_backend_targets(targets, inventory);
                writeln!(f, "      upstream target {addrs} ({status})")
            }
        }
        ProxyTarget::UnresolvedHost { scheme, host, port } => writeln!(
            f,
            "    target: {}://{}:{port} (hostname requires DNS resolution; not correlated locally)",
            format_scheme(*scheme),
            sanitize(host)
        ),
        ProxyTarget::Unsupported { reason } => {
            let reason_text = match reason {
                UnsupportedProxyReason::Variable => "dynamic $variable target",
                UnsupportedProxyReason::UnixSocket => "Unix socket target",
                UnsupportedProxyReason::UnsupportedScheme => "unsupported proxy scheme",
                UnsupportedProxyReason::InvalidTarget => "invalid proxy_pass target",
            };
            writeln!(f, "    target: unsupported ({reason_text})")
        }
    }
}

fn format_scheme(scheme: ProxyScheme) -> &'static str {
    match scheme {
        ProxyScheme::Http => "http",
        ProxyScheme::Https => "https",
    }
}

fn format_addr_list(addrs: &[SocketAddr]) -> String {
    addrs
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

fn correlate_backend_targets(targets: &[SocketAddr], inventory: &TcpEvidence) -> String {
    let valid: Vec<SocketAddr> = targets
        .iter()
        .copied()
        .filter(|target| !target.ip().to_canonical().is_unspecified())
        .collect();
    if valid.is_empty() {
        return "target is outside the supported local TCP scope".to_owned();
    }
    let TcpEvidence::Collected { listeners } = inventory else {
        return "TCP socket inventory unavailable".to_owned();
    };
    let all_loopback = valid
        .iter()
        .all(|target| target.ip().to_canonical().is_loopback());
    let missing_msg = if all_loopback {
        "no matching TCP listener"
    } else {
        "non-loopback target (no exact local TCP listener; may be remote)"
    };
    format_target_match(
        match_listeners(listeners, |listener| {
            valid
                .iter()
                .filter_map(|&target| backend_candidate(listener, target))
                .max()
        }),
        missing_msg,
    )
}

fn format_target_match(outcome: TargetMatch, missing_msg: &str) -> String {
    match outcome {
        TargetMatch::Matched(addr) => format!("TCP listener {addr}"),
        TargetMatch::Ambiguous => "multiple possible TCP listeners".to_owned(),
        TargetMatch::UncertainOptions => {
            "listener's socket options leave the match uncertain".to_owned()
        }
        TargetMatch::Missing => missing_msg.to_owned(),
    }
}

fn write_auth(f: &mut fmt::Formatter<'_>, auth: &AuthSignals) -> fmt::Result {
    let mut parts = Vec::new();
    match auth.auth_basic {
        Some(true) => parts.push("auth_basic=on"),
        Some(false) => parts.push("auth_basic=off"),
        None => {}
    }
    if auth.auth_request {
        parts.push("auth_request");
    }
    match auth.ssl_verify_client {
        Some(SslVerifyClient::On) => parts.push("ssl_verify_client=on"),
        Some(SslVerifyClient::Off) => parts.push("ssl_verify_client=off"),
        Some(SslVerifyClient::Optional) => parts.push("ssl_verify_client=optional"),
        Some(SslVerifyClient::OptionalNoCa) => parts.push("ssl_verify_client=optional_no_ca"),
        None => {}
    }
    if auth.access_control {
        parts.push("access_control (allow/deny)");
    }
    if parts.is_empty() {
        f.write_str("none configured")
    } else {
        f.write_str(&parts.join(", "))
    }
}

fn write_uncertainty(f: &mut fmt::Formatter<'_>, uncertainty: &Uncertainty) -> fmt::Result {
    write!(
        f,
        "  {} (`{}`)",
        uncertainty.kind,
        sanitize(&uncertainty.directive)
    )?;
    match (&uncertainty.source_file, uncertainty.line) {
        (Some(file), Some(line)) => writeln!(f, " at {}:{line}", sanitize(file)),
        (Some(file), None) => writeln!(f, " in {}", sanitize(file)),
        (None, Some(line)) => writeln!(f, " at line {line}"),
        (None, None) => writeln!(f),
    }
}
