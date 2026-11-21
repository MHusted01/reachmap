//! Correlate configured Serve and Funnel routes with the local TCP inventory.

use std::fmt;
use std::io::ErrorKind;
use std::net::SocketAddr;

use thiserror::Error;

use crate::collect::{self, CollectError};
use crate::errors::render_chain;
use crate::parse::tailscale::routes::{Backend, ConfiguredRoutes, Route, parse_routes};
use crate::scan::{ScanError, parse_tables};
use crate::socket::{ListeningSocket, Protocol, SocketOptions};
use crate::socket_options::{OptionsByInode, read_socket_options};

/// Why Tailscale route status was unavailable.
#[derive(Debug, Error)]
pub enum RouteScanError {
    /// The Tailscale CLI was not found.
    #[error("Tailscale route status is unavailable because `tailscale` was not found")]
    MissingCommand,
    /// The status command failed.
    #[error("could not collect Tailscale route status")]
    Collect(#[source] CollectError),
    /// The status command did not return a Serve configuration object or null.
    #[error("could not understand Tailscale route status")]
    Json(#[from] serde_json::Error),
}

/// Configured routes, local TCP evidence, and any limits in the collected data.
#[derive(Debug)]
pub struct RouteReport {
    configured: ConfiguredRoutes,
    inventory: Option<Inventory>,
}

impl RouteReport {
    /// Whether the status and the required inventory were collected in full.
    pub fn is_complete(&self) -> bool {
        self.configured.notes.is_empty()
    }
}

#[derive(Debug)]
struct Inventory {
    sockets: Vec<ListeningSocket>,
    options: OptionsByInode,
}

/// Reads local Tailscale status and the Linux socket inventory. Makes no
/// connections to backends and performs no name lookups.
pub fn scan() -> Result<RouteReport, RouteScanError> {
    collect_with(collect::read_serve_status(), || {
        let sockets = parse_tables(&collect::read_socket_tables()?)?;
        Ok(Inventory {
            sockets,
            options: read_socket_options().by_inode,
        })
    })
}

fn collect_with(
    status: Result<String, CollectError>,
    read_inventory: impl FnOnce() -> Result<Inventory, ScanError>,
) -> Result<RouteReport, RouteScanError> {
    let json = status.map_err(|error| match &error {
        CollectError::Run { source, .. } if source.kind() == ErrorKind::NotFound => {
            RouteScanError::MissingCommand
        }
        _ => RouteScanError::Collect(error),
    })?;
    let mut configured = parse_routes(&json)?;
    let needs_sockets = configured.routes.iter().any(
        |route| matches!(&route.backend, Backend::HttpProxy { targets, .. } if !targets.is_empty()),
    );
    let inventory = if needs_sockets {
        match read_inventory() {
            Ok(inventory) => Some(inventory),
            Err(error) => {
                configured.notes.push(format!(
                    "TCP socket inventory unavailable ({})",
                    render_chain(&error)
                ));
                None
            }
        }
    } else {
        None
    };
    Ok(RouteReport {
        configured,
        inventory,
    })
}

impl fmt::Display for RouteReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "Tailscale routes (configured evidence only, reachability and application authentication unverified)"
        )?;
        if self.is_complete() && self.configured.routes.is_empty() {
            writeln!(f, "No configured host-level Tailscale routes found.")?;
        }
        for route in &self.configured.routes {
            write_route(f, route, self.inventory.as_ref())?;
        }
        if self.configured.unsupported_services {
            writeln!(
                f,
                "Tailscale Services are outside the supported host-level route scope."
            )?;
        }
        if !self.is_complete() {
            writeln!(f, "Partial Tailscale route collection:")?;
            for note in &self.configured.notes {
                writeln!(f, "  {note}")?;
            }
        }
        Ok(())
    }
}

fn write_route(
    f: &mut fmt::Formatter<'_>,
    route: &Route,
    inventory: Option<&Inventory>,
) -> fmt::Result {
    let entry = &route.entry;
    write!(
        f,
        "{}:{}",
        entry.host.as_deref().unwrap_or("<hostname unavailable>"),
        entry.port
    )?;
    if let Some(mount) = &route.mount {
        write!(f, " {mount}")?;
    }
    match entry.sharing {
        Some(sharing) => write!(f, " [{sharing}]")?,
        None => f.write_str(" [unknown scope]")?,
    }
    let endpoint = match &route.backend {
        Backend::HttpProxy { endpoint, .. } => Some(endpoint),
        Backend::Unsupported { endpoint, .. } => endpoint.as_ref(),
    };
    if let Some(endpoint) = endpoint {
        write!(f, " -> {endpoint}")?;
    }
    match correlate(&route.backend, inventory) {
        Correlation::Matched(listener) => writeln!(f, " (TCP listener {listener})"),
        Correlation::Unresolved(reason) => writeln!(f, " ({reason})"),
        Correlation::Unsupported(handler) => writeln!(f, " (unsupported handler: {handler})"),
    }
}

enum Correlation {
    Matched(SocketAddr),
    Unresolved(&'static str),
    Unsupported(&'static str),
}

fn correlate(backend: &Backend, inventory: Option<&Inventory>) -> Correlation {
    let targets = match backend {
        Backend::Unsupported { handler, .. } => return Correlation::Unsupported(handler),
        Backend::HttpProxy { targets, .. } if targets.is_empty() => {
            return Correlation::Unresolved("target is outside the supported loopback TCP scope");
        }
        Backend::HttpProxy { targets, .. } => targets,
    };
    let Some(inventory) = inventory else {
        return Correlation::Unresolved("TCP socket inventory unavailable");
    };
    let mut candidates = inventory.sockets.iter().filter_map(|listener| {
        let options = inventory.options.get(&listener.inode);
        targets
            .iter()
            .filter_map(|&target| candidate(listener, target, options))
            .max()
            .map(|confirmed| (listener, confirmed))
    });
    match (candidates.next(), candidates.next()) {
        (_, Some(_)) => Correlation::Unresolved("multiple possible TCP listeners"),
        (Some((listener, true)), None) => {
            Correlation::Matched(SocketAddr::new(listener.address, listener.port))
        }
        (Some((_, false)), None) => {
            Correlation::Unresolved("listener's socket options leave the match uncertain")
        }
        (None, None) => Correlation::Unresolved("no matching TCP listener"),
    }
}

/// Returns whether an address match is conclusive. A device-bound socket
/// needs interface evidence, as does an IPv6 wildcard with unknown v6-only state.
fn candidate(
    listener: &ListeningSocket,
    target: SocketAddr,
    options: Option<&SocketOptions>,
) -> Option<bool> {
    if listener.protocol != Protocol::Tcp || listener.port != target.port() {
        return None;
    }
    let bound = listener.address.to_canonical();
    let target = target.ip().to_canonical();
    let bound_to_device = options.is_some_and(|options| options.bound_device.is_some());
    if bound == target || (bound.is_unspecified() && bound.is_ipv4() == target.is_ipv4()) {
        return Some(!bound_to_device);
    }
    if bound.is_unspecified() && bound.is_ipv6() && target.is_ipv4() {
        return match options {
            Some(options) if options.ipv6_only => None,
            Some(_) => Some(!bound_to_device),
            None => Some(false),
        };
    }
    None
}

#[cfg(test)]
mod tests;
