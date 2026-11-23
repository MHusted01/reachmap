//! Correlate on-disk Nginx configuration routes with local Linux TCP listeners.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[cfg(target_os = "linux")]
use crate::collect::{self, nginx_files::DiskFiles};
use crate::local_tcp::{
    Inventory, Listener, TcpEvidence, candidate, exact_candidate, read_inventory,
};
use crate::nginx::{ListenAddress, ListenEndpoint, NginxConfig, ProxyTarget};
#[cfg(target_os = "linux")]
use crate::parse::nginx::conf_path_from_build_info;
use crate::parse::nginx::{NginxParseError, parse_nginx_config};
use crate::scan::ScanError;

use self::diagnostic::Note;
#[cfg(target_os = "linux")]
use self::diagnostic::classify_nginx_error;

mod diagnostic;
mod files;
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
    /// `nginx -V` exited with a non-zero status; raw stderr is omitted.
    #[error(
        "could not read Nginx build information (`nginx -V` failed{}); check the Nginx installation (raw stderr omitted)",
        format_exit_code(*.exit_code)
    )]
    CommandFailed {
        /// Process exit code, when available.
        exit_code: Option<i32>,
    },
    /// `nginx -V` did not finish within the bounded timeout.
    #[error("`nginx -V` did not finish within {timeout:?}")]
    TimedOut {
        /// Timeout enforced by the collector.
        timeout: Duration,
    },
    /// `nginx -V` stdout or stderr exceeded its bounded safety limit.
    #[error("`nginx -V` {stream} output exceeded the {limit_bytes}-byte safety limit")]
    OutputTooLarge {
        /// Which stream overflowed (`"stdout"` or `"stderr"`).
        stream: &'static str,
        /// Maximum accepted output length in bytes for that stream.
        limit_bytes: u64,
    },
    /// `nginx -V` produced non-UTF-8 output.
    #[error("`nginx -V` printed output that is not valid UTF-8")]
    NotUtf8,
    /// Nginx collection requires Linux.
    #[error("Nginx route collection requires Linux (unavailable on {os})")]
    UnsupportedOs {
        /// Current operating system identifier.
        os: &'static str,
    },
    /// Spawning or reading `nginx -V` failed with an unexpected I/O error kind.
    #[error("could not run `nginx -V` ({kind})")]
    RunFailed {
        /// Sanitized I/O error kind description.
        kind: String,
    },
    /// `nginx -V` did not lead to an absolute main configuration path.
    #[error("could not determine the Nginx configuration file from `nginx -V`")]
    ConfigPathUnknown,
    /// The main configuration file named by `nginx -V` does not exist.
    #[error("Nginx configuration file {path} was not found")]
    ConfigNotFound {
        /// Sanitized path of the main configuration file.
        path: String,
    },
    /// A configuration path cannot be read safely.
    #[error("could not read Nginx configuration file {path} ({reason})")]
    UnreadableFile {
        /// Sanitized path that was refused.
        path: String,
        /// Why it was refused.
        reason: &'static str,
    },
    /// Reading a configuration file or directory failed.
    #[error("could not read Nginx configuration file {path} ({kind})")]
    ReadFailed {
        /// Sanitized path that failed.
        path: String,
        /// Sanitized I/O error kind description.
        kind: String,
    },
    /// The configuration files together exceed the parser's input limit.
    #[error("Nginx configuration files exceed the {limit_bytes}-byte input limit")]
    ConfigTooLarge {
        /// Maximum accepted total size in bytes.
        limit_bytes: usize,
    },
    /// The configuration includes more files than the collector reads.
    #[error("Nginx configuration includes more than {limit} files")]
    TooManyFiles {
        /// Maximum number of files read.
        limit: usize,
    },
    /// `include`s are nested deeper than the collector follows.
    #[error("Nginx configuration includes are nested more than {limit} levels deep")]
    IncludeTooDeep {
        /// Maximum include depth followed.
        limit: usize,
    },
    /// Configuration text could not be parsed within safety bounds.
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
    /// Returns the parsed, secret-minimized Nginx configuration.
    pub fn config(&self) -> &NginxConfig {
        &self.config
    }

    /// Whether collection of Nginx config and local TCP socket evidence completed cleanly.
    pub fn is_collection_complete(&self) -> bool {
        matches!(self.collection, Collection::Complete)
    }

    pub(in crate::nginx) fn inventory(&self) -> &TcpEvidence {
        &self.inventory
    }

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

/// Reads the on-disk Nginx configuration files and the local Linux TCP socket
/// inventory. Runs only `nginx -V`, never Nginx's configuration test, and
/// discards raw config text immediately after parsing.
pub fn scan() -> Result<NginxRouteReport, NginxScanError> {
    collect_with(read_config(), read_inventory)
}

/// Finds the main configuration file with `nginx -V` and reads it and its
/// includes from disk.
#[cfg(target_os = "linux")]
fn read_config() -> Result<String, NginxScanError> {
    let build_info = collect::read_nginx_build_info().map_err(classify_nginx_error)?;
    let main = conf_path_from_build_info(&build_info).ok_or(NginxScanError::ConfigPathUnknown)?;
    files::read_config(&main, &DiskFiles)
}

#[cfg(not(target_os = "linux"))]
fn read_config() -> Result<String, NginxScanError> {
    Err(NginxScanError::UnsupportedOs {
        os: std::env::consts::OS,
    })
}

pub(in crate::nginx) fn collect_with(
    raw_config: Result<String, NginxScanError>,
    read_inventory: impl FnOnce() -> Result<Inventory, ScanError>,
) -> Result<NginxRouteReport, NginxScanError> {
    let raw = raw_config?;
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
pub(in crate::nginx) fn listen_candidate(
    listener: &Listener,
    listen: &ListenEndpoint,
) -> Option<bool> {
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
pub(in crate::nginx) fn backend_candidate(listener: &Listener, target: SocketAddr) -> Option<bool> {
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
