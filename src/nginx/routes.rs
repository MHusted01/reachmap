//! Correlate on-disk Nginx configuration routes with local Linux TCP listeners.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::collect::{self, CollectError};
use crate::local_tcp::{
    Inventory, Listener, TcpEvidence, candidate, exact_candidate, read_inventory,
};
use crate::nginx::{ListenAddress, ListenEndpoint, NginxConfig, ProxyTarget};
use crate::parse::nginx::{NginxParseError, parse_nginx_config};
use crate::scan::ScanError;

use self::diagnostic::{Note, classify_nginx_error};

mod diagnostic;
mod format;
pub mod snapshot;

/// Why Nginx route status could not be collected or parsed.
#[derive(Debug, Error)]
pub enum NginxScanError {
    /// The `nginx` binary was not found.
    #[error("Nginx route status is unavailable because `nginx` was not found")]
    MissingCommand,
    /// Reading the Nginx configuration was denied by file permissions.
    #[error(
        "could not read Nginx configuration (permission denied); retry with privileges to read Nginx config files (e.g. sudo)"
    )]
    PermissionDenied,
    /// `nginx -T` exited with a non-zero status; raw stderr is omitted so
    /// config lines or secrets cannot leak.
    #[error(
        "could not dump Nginx configuration (`nginx -T` failed{}); check Nginx config syntax and permissions (raw stderr omitted)",
        format_exit_code(*.exit_code)
    )]
    CommandFailed {
        /// Process exit code, when available.
        exit_code: Option<i32>,
    },
    /// `nginx -T` did not finish within the bounded timeout.
    #[error("`nginx -T` did not finish within {timeout:?}")]
    TimedOut {
        /// Timeout enforced by the collector.
        timeout: Duration,
    },
    /// `nginx -T` output exceeded the bounded safety limit.
    #[error("`nginx -T` output exceeded the {limit_bytes}-byte safety limit")]
    OutputTooLarge {
        /// Maximum accepted output length in bytes.
        limit_bytes: usize,
    },
    /// `nginx -T` produced non-UTF-8 output.
    #[error("`nginx -T` printed output that is not valid UTF-8")]
    NotUtf8,
    /// Nginx collection requires Linux.
    #[error("Nginx route collection requires Linux (unavailable on {os})")]
    UnsupportedOs {
        /// Current operating system identifier.
        os: &'static str,
    },
    /// Spawning or reading `nginx -T` failed with an unexpected I/O error kind.
    #[error("could not run `nginx -T` ({kind})")]
    RunFailed {
        /// Sanitized I/O error kind description.
        kind: String,
    },
    /// Expanded configuration text could not be parsed within safety bounds.
    #[error("could not parse Nginx configuration")]
    Parse(#[from] NginxParseError),
}

fn format_exit_code(code: Option<i32>) -> String {
    match code {
        Some(code) => format!(" with exit code {code}"),
        None => String::new(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum Collection {
    Complete,
    Partial { notes: Vec<Note> },
}

/// Minimized Nginx routes, local TCP listener evidence, and collection status.
#[derive(Debug, Deserialize, Serialize)]
pub struct NginxRouteReport {
    config: NginxConfig,
    collection: Collection,
    inventory: TcpEvidence,
}

impl NginxRouteReport {
    /// Whether collection was complete and the parsed configuration has no
    /// unmodeled or dynamic uncertainties.
    pub fn is_complete(&self) -> bool {
        matches!(self.collection, Collection::Complete) && self.config.uncertainties.is_empty()
    }

    pub(crate) fn validate(&self) -> Result<(), &'static str> {
        for server in &self.config.servers {
            if server.listens.iter().any(|listen| listen.port == 0) {
                return Err("expected a nonzero listen port");
            }
            for location in &server.locations {
                match &location.target {
                    Some(ProxyTarget::StaticHttp { targets, .. })
                    | Some(ProxyTarget::Upstream { targets, .. }) => {
                        if targets.iter().any(|target| target.port() == 0) {
                            return Err("expected a nonzero backend target port");
                        }
                    }
                    Some(ProxyTarget::UnresolvedHost { port, .. }) if *port == 0 => {
                        return Err("expected a nonzero backend target port");
                    }
                    Some(ProxyTarget::UnresolvedHost { .. } | ProxyTarget::Unsupported { .. })
                    | None => {}
                }
            }
        }
        for group in &self.config.upstreams {
            if group
                .servers
                .iter()
                .flat_map(|server| &server.targets)
                .any(|target| target.port() == 0)
            {
                return Err("expected a nonzero upstream target port");
            }
        }
        let needs = needs_inventory(&self.config);
        if needs == matches!(self.inventory, TcpEvidence::NotNeeded)
            || (matches!(self.collection, Collection::Complete)
                && matches!(self.inventory, TcpEvidence::Unavailable))
            || matches!(&self.collection, Collection::Partial { notes } if notes.is_empty())
        {
            return Err("inconsistent Nginx route collection status");
        }
        if let TcpEvidence::Collected { listeners } = &self.inventory
            && listeners.iter().any(|listener| {
                listener.address.port() == 0 || !listener_is_relevant(listener, &self.config)
            })
        {
            return Err("unexpected TCP listener outside the captured Nginx route endpoints");
        }
        Ok(())
    }
}

impl fmt::Display for NginxRouteReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        format::write_report(self, f)
    }
}

/// Reads the on-disk Nginx configuration (`nginx -T`) and the local Linux TCP
/// socket inventory. Discards raw config text immediately after parsing.
pub fn scan() -> Result<NginxRouteReport, NginxScanError> {
    collect_with(collect::read_nginx_config(), read_inventory)
}

fn collect_with(
    raw_config: Result<String, CollectError>,
    read_inventory: impl FnOnce() -> Result<Inventory, ScanError>,
) -> Result<NginxRouteReport, NginxScanError> {
    let raw = raw_config.map_err(classify_nginx_error)?;
    let config = parse_nginx_config(&raw)?;
    drop(raw);

    let mut notes = Vec::new();
    let inventory = if needs_inventory(&config) {
        match read_inventory() {
            Ok(inventory) => {
                if let Some(error) = &inventory.options.error {
                    notes.push(Note::SocketOptionsIncomplete {
                        reason: error.into(),
                    });
                }
                TcpEvidence::Collected {
                    listeners: inventory
                        .relevant_listeners(|listener| listener_is_relevant(listener, &config)),
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

    Ok(NginxRouteReport {
        config,
        collection,
        inventory,
    })
}

fn needs_inventory(config: &NginxConfig) -> bool {
    config
        .servers
        .iter()
        .any(|server| !server.listens.is_empty())
        || correlatable_backend_addrs(config).next().is_some()
}

fn listener_is_relevant(listener: &Listener, config: &NginxConfig) -> bool {
    let matches_listen = config
        .servers
        .iter()
        .flat_map(|server| &server.listens)
        .any(|listen| listen_candidate(listener, listen).is_some());
    matches_listen
        || correlatable_backend_addrs(config)
            .any(|target| backend_candidate(listener, target).is_some())
}

fn correlatable_backend_addrs(config: &NginxConfig) -> impl Iterator<Item = SocketAddr> + '_ {
    config
        .servers
        .iter()
        .flat_map(|server| &server.locations)
        .filter_map(|location| location.target.as_ref())
        .flat_map(move |target| {
            let (slice_targets, group_servers) = match target {
                ProxyTarget::StaticHttp { targets, .. } => (targets.as_slice(), None),
                ProxyTarget::Upstream { name, targets, .. } => {
                    if let Some(group) = config.upstreams.iter().find(|group| group.name == *name) {
                        (&[][..], Some(group.servers.as_slice()))
                    } else {
                        (targets.as_slice(), None)
                    }
                }
                ProxyTarget::UnresolvedHost { .. } | ProxyTarget::Unsupported { .. } => {
                    (&[][..], None)
                }
            };
            slice_targets.iter().copied().chain(
                group_servers
                    .into_iter()
                    .flatten()
                    .filter(|server| !server.down)
                    .flat_map(|server| server.targets.iter().copied()),
            )
        })
        .filter(|target| !target.ip().to_canonical().is_unspecified())
}

/// Match a local TCP listener against a configured Nginx frontend `listen` directive.
pub(super) fn listen_candidate(listener: &Listener, listen: &ListenEndpoint) -> Option<bool> {
    let target = match listen.address {
        ListenAddress::AnyIpv4 {} => {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), listen.port)
        }
        ListenAddress::AnyIpv6 {} => {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), listen.port)
        }
        ListenAddress::Ipv4 { ip } => SocketAddr::new(IpAddr::V4(ip), listen.port),
        ListenAddress::Ipv6 { ip } => SocketAddr::new(IpAddr::V6(ip), listen.port),
    };
    let confirmed = candidate(listener, target)?;
    if matches!(listen.address, ListenAddress::AnyIpv6 {})
        && let Some(expected_ipv6_only) = listen.ipv6only
    {
        return match listener.options {
            Some(options) if options.ipv6_only == expected_ipv6_only => Some(confirmed),
            Some(_) => None,
            None => Some(false),
        };
    }
    Some(confirmed)
}

/// Match a local TCP listener against a configured Nginx backend target.
///
/// Loopback targets match exact loopback or compatible wildcard listeners;
/// non-loopback IP targets require an exact local IP bind so a wildcard
/// `0.0.0.0`/`[::]` listener cannot falsely claim a remote backend is local.
pub(super) fn backend_candidate(listener: &Listener, target: SocketAddr) -> Option<bool> {
    let ip = target.ip().to_canonical();
    if ip.is_unspecified() {
        return None;
    }
    if ip.is_loopback() {
        candidate(listener, target)
    } else {
        exact_candidate(listener, target)
    }
}

#[cfg(test)]
mod tests;
