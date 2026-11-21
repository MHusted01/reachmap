//! Versioned evidence for replaying the Linux host-socket input check.

use std::collections::BTreeSet;
use std::error::Error;
use std::fs::{self, File};
use std::io::{self, ErrorKind};
use std::path::Path;
use std::str::FromStr;
use std::time::{SystemTime, SystemTimeError, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::artifact::read_limited;
use crate::collect::CollectError;
use crate::docker::DockerError;
use crate::errors::render_chain;
use crate::network::HostInterfaces;
use crate::nftables::{self, NftablesReport, Target};
use crate::parse::nftables::parse_ruleset;
use crate::sanitize::sanitize;
use crate::scan::{self, InterfacesError, ScanError, ScanReport};
use crate::socket_options::OptionsReport;

const VERSION: u32 = 1;
const MAX_MIB: u64 = 64;
const MAX_BYTES: u64 = MAX_MIB * 1024 * 1024;

/// A short human-assigned label for the host that supplied the evidence.
#[derive(Debug, Clone)]
pub struct HostRef(String);

impl HostRef {
    pub(crate) fn into_string(self) -> String {
        self.0
    }
}

impl FromStr for HostRef {
    type Err = SnapshotError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        validate_host_ref(value)?;
        Ok(Self(value.to_owned()))
    }
}

pub(crate) fn validate_host_ref(value: &str) -> Result<(), SnapshotError> {
    if value.len() > 128 || value.trim().is_empty() || sanitize(value) != value {
        return Err(SnapshotError::HostRef);
    }
    Ok(())
}

/// Facts for one Linux host-input decision, independent of the scan report format.
#[derive(Debug, Serialize, Deserialize)]
pub struct HostInputSnapshot {
    snapshot_version: u32,
    host_ref: String,
    captured_at_unix_seconds: u64,
    scope: Scope,
    collectors: Collectors,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Scope {
    LinuxHostInput,
}

#[derive(Debug, Serialize, Deserialize)]
struct Collectors {
    socket_tables: Complete,
    interfaces: Evidence<InterfaceTargets>,
    socket_options: Status,
    docker: Status,
    nftables: Evidence<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Complete {
    Collected,
}

/// A successful interface read may find no addresses (null), or addresses
/// with zero or more applicable sockets (an array of evaluation targets).
#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
enum InterfaceTargets {
    WithAddresses(BTreeSet<Target>),
    NoAddresses(()),
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Status {
    Collected,
    Partial,
    Failed,
    Unavailable,
}

impl Status {
    pub(crate) fn socket_options(report: &OptionsReport) -> Self {
        if report.error.is_none() {
            Self::Collected
        } else if report.by_inode.is_empty() {
            Self::Failed
        } else {
            Self::Partial
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub(crate) enum Evidence<T> {
    Collected { data: T },
    Failed { reason: String },
    Unavailable { reason: String },
}

impl<T> Evidence<T> {
    pub(crate) fn as_result(&self) -> Result<&T, String> {
        match self {
            Self::Collected { data } => Ok(data),
            Self::Failed { reason } | Self::Unavailable { reason } => Err(sanitize(reason)),
        }
    }

    fn result(self) -> Result<T, String> {
        match self {
            Self::Collected { data } => Ok(data),
            Self::Failed { reason } | Self::Unavailable { reason } => Err(sanitize(&reason)),
        }
    }
}

fn command_missing(error: &CollectError) -> bool {
    matches!(error, CollectError::Run { source, .. } if source.kind() == ErrorKind::NotFound)
}

fn interface_evidence(
    host: Option<&HostInterfaces>,
    report: &ScanReport,
) -> Evidence<InterfaceTargets> {
    let Some(error) = &report.interfaces_error else {
        return Evidence::Collected {
            data: nftables::socket_targets(host, &report.ports).map_or(
                InterfaceTargets::NoAddresses(()),
                InterfaceTargets::WithAddresses,
            ),
        };
    };
    let reason = sanitize(&render_chain(error));
    if matches!(error, InterfacesError::Collect(error) if command_missing(error)) {
        Evidence::Unavailable { reason }
    } else {
        Evidence::Failed { reason }
    }
}

fn nftables_evidence(raw: Result<String, CollectError>) -> Evidence<String> {
    match raw {
        Ok(data) => match parse_ruleset(&data) {
            Ok(_) => Evidence::Collected { data },
            Err(error) => Evidence::Failed {
                reason: sanitize(&render_chain(&error)),
            },
        },
        Err(error) if command_missing(&error) => Evidence::Unavailable {
            reason: nftables::collect_reason(&error),
        },
        Err(error) => Evidence::Failed {
            reason: nftables::collect_reason(&error),
        },
    }
}

impl HostInputSnapshot {
    pub(crate) fn from_scan(
        host_ref: HostRef,
        captured_at_unix_seconds: u64,
        host: Option<&HostInterfaces>,
        report: &ScanReport,
        socket_options: Status,
        rules: Result<String, CollectError>,
    ) -> Self {
        Self {
            snapshot_version: VERSION,
            host_ref: host_ref.0,
            captured_at_unix_seconds,
            scope: Scope::LinuxHostInput,
            collectors: Collectors {
                socket_tables: Complete::Collected,
                interfaces: interface_evidence(host, report),
                socket_options,
                docker: match &report.docker_error {
                    None => Status::Collected,
                    Some(DockerError::NotInstalled) => Status::Unavailable,
                    Some(_) => Status::Failed,
                },
                nftables: nftables_evidence(rules),
            },
        }
    }

    /// Formats a snapshot as a JSON document that replay can read.
    pub fn render(&self) -> Result<String, SnapshotError> {
        render_document(self)
    }
}

/// Why a host-input snapshot could not be collected, saved or replayed.
#[derive(Debug, Error)]
pub enum SnapshotError {
    /// Host-input snapshot collection is Linux-specific.
    #[error("capture a host-input snapshot on Linux; replay is available on this system")]
    UnsupportedOs,
    /// The supplied host reference cannot be used as a label.
    #[error("use a nonblank host label of up to 128 bytes without control characters")]
    HostRef,
    /// The system clock cannot supply a Unix timestamp.
    #[error("cannot timestamp the snapshot; check the system clock")]
    Clock(#[source] SystemTimeError),
    /// The live scan failed to collect a required input.
    #[error("could not capture Linux host-input evidence")]
    Scan(#[from] ScanError),
    /// JSON serialization failed.
    #[error("could not serialize the host-input snapshot")]
    Encode(#[source] serde_json::Error),
    /// Only regular files can hold a snapshot for replay.
    #[error("give replay a regular file containing a snapshot")]
    NotRegular,
    /// The snapshot is larger than the supported read limit.
    #[error("snapshots are limited to {MAX_MIB} MiB")]
    TooLarge,
    /// A snapshot file could not be read.
    #[error("could not read the snapshot")]
    Read(#[from] io::Error),
    /// The format version requires a different reader.
    #[error("unsupported host-input snapshot version {0}; this build reads version {VERSION}")]
    Version(u32),
    /// The document or a required input is malformed.
    #[error("invalid host-input snapshot ({field}): {reason}")]
    Invalid {
        /// The part that could not be read.
        field: &'static str,
        /// A safe diagnostic describing the issue.
        reason: String,
    },
}

fn invalid(field: &'static str, error: &(dyn Error + 'static)) -> SnapshotError {
    let reason = sanitize(&render_chain(error));
    let reason = match reason.char_indices().nth(300) {
        Some((end, _)) => format!("{}…", &reason[..end]),
        None => reason,
    };
    SnapshotError::Invalid { field, reason }
}

/// Captures the facts used by the Linux scan's host-socket input evaluator.
pub fn capture(host_ref: HostRef) -> Result<HostInputSnapshot, SnapshotError> {
    if !cfg!(target_os = "linux") {
        return Err(SnapshotError::UnsupportedOs);
    }
    let captured_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(SnapshotError::Clock)?;
    Ok(scan::capture_linux(host_ref, captured_at.as_secs())?)
}

#[derive(Deserialize)]
struct Header {
    snapshot_version: u32,
}

pub(crate) fn replay_document(text: &str) -> Result<NftablesReport, SnapshotError> {
    let header: Header =
        serde_json::from_str(text).map_err(|error| invalid("version header", &error))?;
    if header.snapshot_version != VERSION {
        return Err(SnapshotError::Version(header.snapshot_version));
    }
    let snapshot: HostInputSnapshot =
        serde_json::from_str(text).map_err(|error| invalid("document", &error))?;
    validate_host_ref(&snapshot.host_ref)?;

    let rules = match snapshot.collectors.nftables.result() {
        Ok(rules) => {
            Ok(parse_ruleset(&rules).map_err(|error| invalid("nftables ruleset", &error))?)
        }
        Err(reason) => Err(reason),
    };
    let targets = snapshot
        .collectors
        .interfaces
        .result()
        .map(|data| match data {
            InterfaceTargets::WithAddresses(targets) => Some(targets),
            InterfaceTargets::NoAddresses(()) => None,
        });
    Ok(nftables::replay(
        rules.as_ref().map_err(String::as_str),
        targets,
    ))
}

/// Reads a bounded JSON file and reevaluates its captured evidence offline.
pub fn replay(path: &Path) -> Result<NftablesReport, SnapshotError> {
    replay_document(&read_document(path)?)
}

pub(crate) fn render_document(snapshot: &impl Serialize) -> Result<String, SnapshotError> {
    let mut text = serde_json::to_string_pretty(snapshot).map_err(SnapshotError::Encode)?;
    text.push('\n');
    if text.len() as u64 > MAX_BYTES {
        return Err(SnapshotError::TooLarge);
    }
    Ok(text)
}

pub(crate) fn read_document(path: &Path) -> Result<String, SnapshotError> {
    if !fs::metadata(path)?.is_file() {
        return Err(SnapshotError::NotRegular);
    }
    let file = File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(SnapshotError::NotRegular);
    }
    if metadata.len() > MAX_BYTES {
        return Err(SnapshotError::TooLarge);
    }
    read_limited(file, MAX_BYTES)?.ok_or(SnapshotError::TooLarge)
}

#[cfg(test)]
mod tests;
