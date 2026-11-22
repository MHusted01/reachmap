//! Correlate configured Serve and Funnel routes with the local TCP inventory.

use std::fmt;
use std::io::ErrorKind;
use std::net::SocketAddr;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::collect::{self, CollectError};
use crate::local_tcp::{
    Inventory, TargetMatch, TcpEvidence, candidate, index_targets, match_listeners, read_inventory,
};
#[cfg(test)]
use crate::local_tcp::{Listener, ListenerOptions};
use crate::parse::tailscale::routes::{Backend, Route, UnsupportedHandler, parse_routes};
use crate::sanitize::sanitize;
use crate::scan::ScanError;

use self::diagnostic::Note;

mod diagnostic;
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
        if self.routes.iter().any(|route| route.entry.port == 0) {
            return Err("expected a nonzero route port");
        }
        let mut backend_targets = targets(&self.routes).peekable();
        let needs_inventory = backend_targets.peek().is_some();
        if backend_targets
            .any(|target| target.port() == 0 || !target.ip().to_canonical().is_loopback())
        {
            return Err("expected a loopback TCP target with a nonzero port");
        }
        if needs_inventory == matches!(self.inventory, TcpEvidence::NotNeeded)
            || (self.is_complete() && matches!(self.inventory, TcpEvidence::Unavailable))
            || matches!(&self.collection, Collection::Partial { notes } if notes.is_empty())
        {
            return Err("inconsistent route collection status");
        }
        if let TcpEvidence::Collected { listeners } = &self.inventory {
            let by_port = index_targets(targets(&self.routes));
            if listeners
                .iter()
                .any(|listener| !listener.could_match(&by_port))
            {
                return Err("unexpected TCP listener outside the captured route targets");
            }
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum Collection {
    Complete,
    Partial { notes: Vec<Note> },
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
    collect_with(collect::read_serve_status(), read_inventory)
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
    let configured = parse_routes(&json)?;
    let mut notes: Vec<_> = configured
        .notes
        .into_iter()
        .map(|detail| Note::RouteStatus { detail })
        .collect();
    let inventory = if targets(&configured.routes).next().is_some() {
        match read_inventory() {
            Ok(inventory) => {
                if let Some(error) = &inventory.options.error {
                    notes.push(Note::SocketOptionsIncomplete {
                        reason: error.into(),
                    });
                }
                let by_port = index_targets(targets(&configured.routes));
                TcpEvidence::Collected {
                    listeners: inventory
                        .relevant_listeners(|listener| listener.could_match(&by_port)),
                }
            }
            Err(error) => {
                notes.push(Note::SocketInventoryUnavailable {
                    reason: (&error).into(),
                });
                TcpEvidence::Unavailable
            }
        }
    } else {
        TcpEvidence::NotNeeded
    };
    let collection = if notes.is_empty() {
        Collection::Complete
    } else {
        Collection::Partial { notes }
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
                writeln!(f, "  {note}")?;
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
    match match_listeners(listeners, |listener| {
        targets
            .iter()
            .filter_map(|&target| candidate(listener, target))
            .max()
    }) {
        TargetMatch::Ambiguous => Correlation::Unresolved("multiple possible TCP listeners"),
        TargetMatch::Matched(address) => Correlation::Matched(address),
        TargetMatch::UncertainOptions => {
            Correlation::Unresolved("listener's socket options leave the match uncertain")
        }
        TargetMatch::Missing => Correlation::Unresolved("no matching TCP listener"),
    }
}

#[cfg(test)]
mod tests;
