//! Human-readable Caddy route report. Every configured string is sanitized
//! here, as a replayed snapshot is untrusted input.

use std::fmt;

use crate::caddy::{
    AutomaticHttps, CaddyServer, ListenAddress, ListenHost, ListenNetwork, Uncertainty,
};
use crate::local_tcp::{TargetMatch, TcpEvidence};
use crate::sanitize::sanitize;

use self::route::write_routes;
use super::auth::AuthContext;
use super::link::{frontend_match, linked_ports};
use super::{CaddyRouteReport, Collection};

mod route;

pub(super) fn write_report(report: &CaddyRouteReport, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    writeln!(
        f,
        "Caddy routes ({} and local TCP sockets only; whether a running Caddy loaded this configuration (it may not have been reloaded, or may have been changed through its admin API), TCP connectivity, HTTP responses, TLS certificates, and application authentication are unverified)",
        report.source
    )?;
    let config = &report.config;
    writeln!(
        f,
        "HTTP port: {}; HTTPS port: {}",
        port_or_redacted(config.http_port),
        port_or_redacted(config.https_port)
    )?;
    if config.servers.is_empty() && report.is_complete() {
        writeln!(f, "No configured Caddy HTTP servers found.")?;
    }
    for server in &config.servers {
        write_server(f, server, &report.inventory)?;
    }
    if !config.uncertainties.is_empty() || config.uncertainties_omitted > 0 {
        writeln!(f, "Configuration uncertainties:")?;
        for uncertainty in &config.uncertainties {
            write_uncertainty(f, uncertainty)?;
        }
        if config.uncertainties_omitted > 0 {
            writeln!(f, "  and {} more", config.uncertainties_omitted)?;
        }
    }
    if let Collection::Partial { notes } = &report.collection {
        writeln!(f, "Partial Caddy route collection:")?;
        for note in notes {
            writeln!(f, "  {note}")?;
        }
    }
    Ok(())
}

fn port_or_redacted(port: Option<u16>) -> String {
    port.map_or_else(
        || "<substituted value left out>".to_owned(),
        |port| port.to_string(),
    )
}

fn write_server(
    f: &mut fmt::Formatter<'_>,
    server: &CaddyServer,
    inventory: &TcpEvidence,
) -> fmt::Result {
    writeln!(f, "Server {}", sanitize(&server.name))?;
    if server.listen.is_empty() {
        writeln!(f, "  listen: <none modeled>")?;
    }
    for listen in &server.listen {
        if server.tcp_known {
            write_listen(f, listen, inventory)?;
        } else {
            writeln!(
                f,
                "  listen: {} (not linked: the protocols leave its TCP listener unknown)",
                ListenText(listen)
            )?;
        }
    }
    writeln!(
        f,
        "  automatic HTTPS: {}",
        automatic_https(server.automatic_https)
    )?;
    if server.http3 {
        writeln!(f, "  HTTP/3: enabled (its UDP sockets are not linked)")?;
    }
    if server.routes.is_empty() {
        writeln!(f, "  routes: <none>")?;
    }
    write_routes(
        f,
        &server.routes,
        inventory,
        &AuthContext::for_server(server),
        1,
    )
}

fn automatic_https(switches: AutomaticHttps) -> String {
    if switches.disabled {
        return "disabled".to_owned();
    }
    let mut text = "enabled".to_owned();
    if switches.redirects_disabled {
        text.push_str(", redirects disabled");
    }
    if switches.hosts_skipped {
        text.push_str(", some hosts skipped");
    }
    text
}

fn write_listen(
    f: &mut fmt::Formatter<'_>,
    listen: &ListenAddress,
    inventory: &TcpEvidence,
) -> fmt::Result {
    write!(f, "  listen: {}", ListenText(listen))?;
    let Some(ports) = linked_ports(listen.ports()) else {
        return writeln!(f, " (not linked: port range too wide)");
    };
    if ports.start() == ports.end() {
        return writeln!(
            f,
            " ({})",
            frontend_status(listen, *ports.start(), inventory)
        );
    }
    writeln!(f)?;
    for port in ports {
        writeln!(
            f,
            "    port {port} ({})",
            frontend_status(listen, port, inventory)
        )?;
    }
    Ok(())
}

/// `:443`, `127.0.0.1:8080` or `tcp6/[::]:8000-8010`.
struct ListenText<'a>(&'a ListenAddress);

impl fmt::Display for ListenText<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0.network() {
            ListenNetwork::Tcp => {}
            ListenNetwork::Tcp4 => f.write_str("tcp4/")?,
            ListenNetwork::Tcp6 => f.write_str("tcp6/")?,
        }
        match self.0.host() {
            ListenHost::Any {} => {}
            ListenHost::Ipv4 { ip } => write!(f, "{ip}")?,
            ListenHost::Ipv6 { ip } => write!(f, "[{ip}]")?,
        }
        let ports = self.0.ports();
        if ports.first() == ports.last() {
            write!(f, ":{}", ports.first())
        } else {
            write!(f, ":{}-{}", ports.first(), ports.last())
        }
    }
}

fn frontend_status(listen: &ListenAddress, port: u16, inventory: &TcpEvidence) -> String {
    match inventory {
        TcpEvidence::Collected { listeners } => target_status(
            frontend_match(listeners, listen, port),
            "no matching TCP listener",
        ),
        TcpEvidence::Unavailable | TcpEvidence::NotNeeded => {
            "TCP socket inventory unavailable".to_owned()
        }
    }
}

fn target_status(outcome: TargetMatch, missing: &str) -> String {
    match outcome {
        TargetMatch::Matched(address) => format!("TCP listener {address}"),
        TargetMatch::Ambiguous => "multiple possible TCP listeners".to_owned(),
        TargetMatch::UncertainOptions => {
            "listener's socket options leave the match uncertain".to_owned()
        }
        TargetMatch::Missing => missing.to_owned(),
    }
}

fn write_uncertainty(f: &mut fmt::Formatter<'_>, uncertainty: &Uncertainty) -> fmt::Result {
    writeln!(
        f,
        "  {} (`{}`) at {}",
        uncertainty.kind,
        sanitize(&uncertainty.construct),
        sanitize(&uncertainty.location)
    )
}
