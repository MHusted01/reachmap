//! Correlate on-disk Caddy configuration routes with local Linux TCP listeners.
//!
//! The configuration is what is on disk, which can differ from a running
//! Caddy that was not reloaded or was changed through its admin API; the
//! admin API is never queried. Nothing here verifies TCP connectivity, HTTP
//! responses, TLS certificates or application authentication.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::caddy::{
    CaddyConfig, CaddyServer, MAX_ROUTE_DEPTH, MAX_UNCERTAINTIES, Substitutions,
    parse_caddy_config_with,
};
use crate::local_tcp::{Inventory, TcpEvidence, read_inventory};
use crate::scan::ScanError;

use self::diagnostic::Note;
use self::link::{
    linked_ports, listener_is_relevant, listens, needs_inventory, proxies, route_depth,
};
use self::source::Adapted;

pub mod audit;
mod auth;
mod caddyfile;
mod collect;
mod diagnostic;
mod error;
mod format;
mod link;
mod program;
pub mod snapshot;
mod source;

pub use error::CaddyScanError;
pub use source::{ConfigSource, DEFAULT_CADDYFILE, SourceKind};

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum Collection {
    Complete,
    Partial { notes: Vec<Note> },
}

/// Minimized Caddy routes, local TCP listener evidence, and collection status.
#[derive(Debug, Deserialize, Serialize)]
pub struct CaddyRouteReport {
    source: SourceKind,
    config: CaddyConfig,
    collection: Collection,
    inventory: TcpEvidence,
}

impl CaddyRouteReport {
    /// The parsed, secret-minimized Caddy configuration.
    pub fn config(&self) -> &CaddyConfig {
        &self.config
    }

    /// The kind of configuration file the report was built from.
    pub fn source(&self) -> SourceKind {
        self.source
    }

    /// Whether the configuration and the local TCP socket evidence were
    /// collected without gaps.
    pub fn is_collection_complete(&self) -> bool {
        matches!(self.collection, Collection::Complete)
    }

    /// Whether collection was complete and the configuration has no
    /// unmodeled constructs. Anything else exits with status 1.
    pub fn is_complete(&self) -> bool {
        self.is_collection_complete()
            && self.config.uncertainties.is_empty()
            && self.config.uncertainties_omitted == 0
    }

    pub(crate) fn validate(&self) -> Result<(), &'static str> {
        validate_config(&self.config)?;
        let needs = needs_inventory(&self.config);
        if needs == matches!(self.inventory, TcpEvidence::NotNeeded)
            || (self.is_collection_complete() && matches!(self.inventory, TcpEvidence::Unavailable))
        {
            return Err("inconsistent Caddy route collection status");
        }
        let notes = match &self.collection {
            Collection::Complete => &[][..],
            Collection::Partial { notes } if notes.is_empty() => {
                return Err("expected a reason for the partial Caddy route collection");
            }
            Collection::Partial { notes } => notes.as_slice(),
        };
        for note in notes {
            self.validate_note(note)?;
        }
        self.validate_required_notes(notes)?;
        if let TcpEvidence::Collected { listeners } = &self.inventory
            && listeners.iter().any(|listener| {
                listener.address.port() == 0 || !listener_is_relevant(listener, &self.config)
            })
        {
            return Err("unexpected TCP listener outside the captured Caddy route endpoints");
        }
        Ok(())
    }

    /// The notes live collection always records for this evidence.
    fn validate_required_notes(&self, notes: &[Note]) -> Result<(), &'static str> {
        let unavailable_noted = notes
            .iter()
            .any(|note| matches!(note, Note::SocketInventoryUnavailable { .. }));
        if matches!(self.inventory, TcpEvidence::Unavailable) && !unavailable_noted {
            return Err("expected a note for the unavailable TCP socket inventory");
        }
        let unnoted_range = listens(&self.config)
            .map(|listen| listen.ports())
            .filter(|ports| linked_ports(*ports).is_none())
            .any(|ports| {
                !notes.contains(&Note::PortRangeNotLinked {
                    first: ports.first(),
                    last: ports.last(),
                })
            });
        if unnoted_range {
            return Err("expected a note for each listen port range that is not linked");
        }
        Ok(())
    }

    fn validate_note(&self, note: &Note) -> Result<(), &'static str> {
        let valid = match note {
            Note::SocketInventoryUnavailable { .. } => {
                matches!(self.inventory, TcpEvidence::Unavailable)
            }
            Note::SocketOptionsIncomplete { .. } => {
                matches!(self.inventory, TcpEvidence::Collected { .. })
            }
            Note::EnvironmentPlaceholders {} | Note::FileImportsNotChecked {} => {
                self.source == SourceKind::Caddyfile
            }
            Note::PortRangeNotLinked { first, last } => listens(&self.config).any(|listen| {
                let ports = listen.ports();
                (ports.first(), ports.last()) == (*first, *last) && linked_ports(ports).is_none()
            }),
        };
        if valid {
            Ok(())
        } else {
            Err("a collection note does not match the captured evidence")
        }
    }
}

fn validate_config(config: &CaddyConfig) -> Result<(), &'static str> {
    if config.uncertainties.len() > MAX_UNCERTAINTIES {
        return Err("too many configuration uncertainties");
    }
    let unexplained = config
        .servers
        .iter()
        .any(|server| !server.tcp_known && !protocols_noted(config, server));
    if unexplained {
        return Err("expected an uncertainty for each server whose TCP listeners are unknown");
    }
    if config.http_port == Some(0) || config.https_port == Some(0) {
        return Err("expected nonzero HTTP and HTTPS ports");
    }
    if config
        .servers
        .iter()
        .any(|server| route_depth(&server.routes) > MAX_ROUTE_DEPTH + 1)
    {
        return Err("routes nested deeper than the parser follows");
    }
    if proxies(config)
        .into_iter()
        .flat_map(|proxy| &proxy.upstreams)
        .any(|target| target.port() == 0)
    {
        return Err("expected a nonzero upstream port");
    }
    Ok(())
}

/// Whether an uncertainty names the `protocols` or `listen_protocols` field
/// of `server`, or uncertainties past the cap were dropped. The parser builds
/// the location from the same bounded name it stores as the server's name.
fn protocols_noted(config: &CaddyConfig, server: &CaddyServer) -> bool {
    let server_at = format!(
        "apps.http.servers[\"{}\"]",
        server.name.replace('"', "\\\"")
    );
    config.uncertainties_omitted > 0
        || config.uncertainties.iter().any(|uncertainty| {
            ["protocols", "listen_protocols"].iter().any(|field| {
                uncertainty.construct == *field
                    && uncertainty.location == format!("{server_at}.{field}")
            })
        })
}

impl fmt::Display for CaddyRouteReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        format::write_report(self, f)
    }
}

/// Reads the Caddy configuration in `source` from disk and the local Linux
/// TCP socket inventory. The raw JSON is discarded right after parsing.
///
/// # Errors
///
/// Returns [`CaddyScanError`] when the configuration cannot be read,
/// adapted or parsed; never an empty report in its place.
pub fn scan(source: &ConfigSource) -> Result<CaddyRouteReport, CaddyScanError> {
    collect_with(collect::read(source), read_inventory)
}

/// Builds the report from what was read. `caddy adapt` runs with an empty
/// environment, so no environment value reaches the JSON, and the parser
/// gets no substitutions to leave out.
fn collect_with(
    adapted: Result<Adapted, CaddyScanError>,
    read_inventory: impl FnOnce() -> Result<Inventory, ScanError>,
) -> Result<CaddyRouteReport, CaddyScanError> {
    let adapted = adapted?;
    let config = parse_caddy_config_with(&adapted.json, &Substitutions::none())?;
    drop(adapted.json);

    let mut notes = Vec::new();
    if adapted.env_placeholders {
        notes.push(Note::EnvironmentPlaceholders {});
    }
    if adapted.file_imports {
        notes.push(Note::FileImportsNotChecked {});
    }
    notes.extend(
        listens(&config)
            .map(|listen| listen.ports())
            .filter(|ports| linked_ports(*ports).is_none())
            .map(|ports| Note::PortRangeNotLinked {
                first: ports.first(),
                last: ports.last(),
            }),
    );
    let inventory = collect_inventory(&config, read_inventory, &mut notes);
    let collection = if notes.is_empty() {
        Collection::Complete
    } else {
        Collection::Partial { notes }
    };
    Ok(CaddyRouteReport {
        source: adapted.kind,
        config,
        collection,
        inventory,
    })
}

fn collect_inventory(
    config: &CaddyConfig,
    read_inventory: impl FnOnce() -> Result<Inventory, ScanError>,
    notes: &mut Vec<Note>,
) -> TcpEvidence {
    if !needs_inventory(config) {
        return TcpEvidence::NotNeeded;
    }
    match read_inventory() {
        Ok(inventory) => {
            if let Some(error) = &inventory.options.error {
                notes.push(Note::SocketOptionsIncomplete {
                    reason: error.into(),
                });
            }
            TcpEvidence::Collected {
                listeners: inventory
                    .relevant_listeners(|listener| listener_is_relevant(listener, config)),
            }
        }
        Err(error) => {
            notes.push(Note::SocketInventoryUnavailable {
                reason: (&error).into(),
            });
            TcpEvidence::Unavailable
        }
    }
}

#[cfg(test)]
mod tests;
