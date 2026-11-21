//! Correlate configured Serve and Funnel routes with the local TCP inventory.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::ErrorKind;
use std::net::SocketAddr;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::collect::{self, CollectError};
use crate::parse::tailscale::routes::{Backend, Route, UnsupportedHandler, parse_routes};
use crate::sanitize::sanitize;
use crate::scan::{ScanError, parse_tables};
use crate::socket::{ListeningSocket, Protocol};
use crate::socket_options::{OptionsReport, read_socket_options};

pub mod snapshot;

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
#[derive(Debug, Deserialize, Serialize)]
pub struct RouteReport {
    routes: Vec<Route>,
    unsupported_services: bool,
    collection: Collection,
    inventory: TcpEvidence,
}

impl RouteReport {
    /// Whether the status and the required inventory were collected in full.
    pub fn is_complete(&self) -> bool {
        matches!(self.collection, Collection::Complete)
    }

    fn validate(&self) -> Result<(), &'static str> {
        let mut targets = targets(&self.routes).peekable();
        let needs_inventory = targets.peek().is_some();
        if targets.any(|target| target.port() == 0 || !target.ip().to_canonical().is_loopback()) {
            return Err("expected a loopback TCP target with a nonzero port");
        }
        if needs_inventory == matches!(self.inventory, TcpEvidence::NotNeeded)
            || (self.is_complete() && matches!(self.inventory, TcpEvidence::Unavailable))
            || matches!(&self.collection, Collection::Partial { notes } if notes.is_empty())
        {
            return Err("inconsistent route collection status");
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum Collection {
    Complete,
    Partial { notes: Vec<String> },
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum TcpEvidence {
    NotNeeded,
    Unavailable,
    Collected { listeners: Vec<Listener> },
}

#[derive(Debug, Deserialize, Serialize)]
struct Listener {
    address: SocketAddr,
    options: Option<ListenerOptions>,
}

#[derive(Debug, Deserialize, Serialize)]
struct ListenerOptions {
    bound_to_device: bool,
    ipv6_only: bool,
}

#[derive(Debug)]
struct Inventory {
    sockets: Vec<ListeningSocket>,
    options: OptionsReport,
}

impl Inventory {
    fn relevant_listeners(self, targets: impl Iterator<Item = SocketAddr>) -> Vec<Listener> {
        let mut by_port = BTreeMap::<_, BTreeSet<_>>::new();
        for target in targets {
            by_port.entry(target.port()).or_default().insert(target);
        }
        self.sockets
            .into_iter()
            .filter(|socket| socket.protocol == Protocol::Tcp)
            .filter_map(|socket| {
                let targets = by_port.get(&socket.port)?;
                let listener = Listener {
                    address: SocketAddr::new(socket.address, socket.port),
                    options: self.options.by_inode.get(&socket.inode).map(|options| {
                        ListenerOptions {
                            bound_to_device: options.bound_device.is_some(),
                            ipv6_only: options.ipv6_only,
                        }
                    }),
                };
                targets
                    .iter()
                    .any(|&target| candidate(&listener, target).is_some())
                    .then_some(listener)
            })
            .collect()
    }
}

fn targets(routes: &[Route]) -> impl Iterator<Item = SocketAddr> + '_ {
    routes
        .iter()
        .flat_map(|route| match &route.backend {
            Backend::HttpProxy { targets, .. } => targets.as_slice(),
            Backend::Unsupported { .. } => &[],
        })
        .copied()
}

/// Reads local Tailscale status and the Linux socket inventory. Makes no
/// connections to backends and performs no name lookups.
pub fn scan() -> Result<RouteReport, RouteScanError> {
    collect_with(collect::read_serve_status(), || {
        let sockets = parse_tables(&collect::read_socket_tables()?)?;
        Ok(Inventory {
            sockets,
            options: read_socket_options(),
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
    let inventory = if targets(&configured.routes).next().is_some() {
        match read_inventory() {
            Ok(inventory) => {
                if inventory.options.error.is_some() {
                    configured
                        .notes
                        .push("TCP socket options incomplete".into());
                }
                TcpEvidence::Collected {
                    listeners: inventory.relevant_listeners(targets(&configured.routes)),
                }
            }
            Err(_) => {
                configured
                    .notes
                    .push("TCP socket inventory unavailable".into());
                TcpEvidence::Unavailable
            }
        }
    } else {
        TcpEvidence::NotNeeded
    };
    let collection = if configured.notes.is_empty() {
        Collection::Complete
    } else {
        Collection::Partial {
            notes: configured.notes,
        }
    };
    Ok(RouteReport {
        routes: configured.routes,
        unsupported_services: configured.unsupported_services,
        collection,
        inventory,
    })
}

impl fmt::Display for RouteReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "Tailscale routes (configured evidence only, reachability and application authentication unverified)"
        )?;
        if self.is_complete() && self.routes.is_empty() {
            writeln!(f, "No configured host-level Tailscale routes found.")?;
        }
        for route in &self.routes {
            write_route(f, route, &self.inventory)?;
        }
        if self.unsupported_services {
            writeln!(
                f,
                "Tailscale Services are outside the supported host-level route scope."
            )?;
        }
        if let Collection::Partial { notes } = &self.collection {
            writeln!(f, "Partial Tailscale route collection:")?;
            for note in notes {
                writeln!(f, "  {}", sanitize(note))?;
            }
        }
        Ok(())
    }
}

fn write_route(f: &mut fmt::Formatter<'_>, route: &Route, inventory: &TcpEvidence) -> fmt::Result {
    let entry = &route.entry;
    write!(
        f,
        "{}:{}",
        sanitize(entry.host.as_deref().unwrap_or("<hostname unavailable>")),
        entry.port
    )?;
    if let Some(mount) = &route.mount {
        write!(f, " {}", sanitize(mount))?;
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
        write!(f, " -> {}", sanitize(endpoint))?;
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
    Unsupported(UnsupportedHandler),
}

fn correlate(backend: &Backend, inventory: &TcpEvidence) -> Correlation {
    let targets = match backend {
        Backend::Unsupported { handler, .. } => return Correlation::Unsupported(*handler),
        Backend::HttpProxy { targets, .. } if targets.is_empty() => {
            return Correlation::Unresolved("target is outside the supported loopback TCP scope");
        }
        Backend::HttpProxy { targets, .. } => targets,
    };
    let TcpEvidence::Collected { listeners } = inventory else {
        return Correlation::Unresolved("TCP socket inventory unavailable");
    };
    let mut candidates = listeners.iter().filter_map(|listener| {
        targets
            .iter()
            .filter_map(|&target| candidate(listener, target))
            .max()
            .map(|confirmed| (listener, confirmed))
    });
    match (candidates.next(), candidates.next()) {
        (_, Some(_)) => Correlation::Unresolved("multiple possible TCP listeners"),
        (Some((listener, true)), None) => Correlation::Matched(listener.address),
        (Some((_, false)), None) => {
            Correlation::Unresolved("listener's socket options leave the match uncertain")
        }
        (None, None) => Correlation::Unresolved("no matching TCP listener"),
    }
}

/// Returns whether an address match is conclusive. Unknown socket options
/// leave device binding and IPv6 wildcard behavior uncertain.
fn candidate(listener: &Listener, target: SocketAddr) -> Option<bool> {
    if listener.address.port() != target.port() {
        return None;
    }
    let bound = listener.address.ip().to_canonical();
    let target = target.ip().to_canonical();
    let options = listener.options.as_ref();
    let unbound = options.is_some_and(|options| !options.bound_to_device);
    if bound == target || (bound.is_unspecified() && bound.is_ipv4() == target.is_ipv4()) {
        return Some(unbound);
    }
    if bound.is_unspecified() && bound.is_ipv6() && target.is_ipv4() {
        return match options {
            Some(options) if options.ipv6_only => None,
            _ => Some(unbound),
        };
    }
    None
}

#[cfg(test)]
mod tests;
