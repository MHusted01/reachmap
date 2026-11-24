//! Versioned, offline evidence for the configured Caddy route report.

use std::fmt;
use std::time::{SystemTime, SystemTimeError, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::{CaddyRouteReport, CaddyScanError, ConfigSource, scan};
use crate::host_input_snapshot::{HostRef, SnapshotError, render_document, validate_host_ref};
use crate::sanitize::sanitize;

const VERSION: u32 = 1;
pub(crate) const SCOPE: &str = "caddy_routes";

/// Minimized Caddy route and local TCP listener evidence, with capture time
/// and host label. It holds no configuration path, raw configuration or
/// unrelated listener.
#[derive(Debug, Deserialize, Serialize)]
pub struct Snapshot {
    snapshot_version: u32,
    host_ref: String,
    captured_at_unix_seconds: u64,
    scope: Scope,
    evidence: CaddyRouteReport,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum Scope {
    CaddyRoutes,
}

impl Snapshot {
    pub(in crate::caddy) fn new(
        host_ref: HostRef,
        captured_at_unix_seconds: u64,
        evidence: CaddyRouteReport,
    ) -> Self {
        Self {
            snapshot_version: VERSION,
            host_ref: host_ref.into_string(),
            captured_at_unix_seconds,
            scope: Scope::CaddyRoutes,
            evidence,
        }
    }

    /// Descriptive host label attached to the snapshot.
    pub fn host_ref(&self) -> &str {
        &self.host_ref
    }

    /// Unix timestamp (seconds since epoch) when the snapshot was captured.
    pub fn captured_at_unix_seconds(&self) -> u64 {
        self.captured_at_unix_seconds
    }

    /// Captured Caddy configuration, local TCP listener evidence, and collection status.
    pub fn evidence(&self) -> &CaddyRouteReport {
        &self.evidence
    }

    /// Whether collection was complete and the captured configuration had no uncertainties.
    pub fn is_complete(&self) -> bool {
        self.evidence.is_complete()
    }
}

impl fmt::Display for Snapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "Captured Caddy route evidence for {} at Unix time {} (seconds since epoch)",
            sanitize(&self.host_ref),
            self.captured_at_unix_seconds
        )?;
        self.evidence.fmt(f)
    }
}

/// Why Caddy route evidence could not be captured.
#[derive(Debug, Error)]
pub enum CaptureError {
    /// Capture requires Linux collectors.
    #[error("capture Caddy route evidence on Linux; replay is available on this system")]
    UnsupportedOs,
    /// The system clock cannot supply a Unix timestamp.
    #[error("cannot timestamp the Caddy route snapshot; check the system clock")]
    Clock(#[source] SystemTimeError),
    /// Caddy route collection or parsing failed.
    #[error("could not capture Caddy route evidence")]
    Scan(#[from] CaddyScanError),
    /// The captured evidence could not be serialized.
    #[error("could not save the Caddy route snapshot")]
    Encode(#[source] SnapshotError),
}

/// Collects Caddy route evidence from `source` and returns its JSON and
/// whether it is complete.
///
/// # Errors
///
/// Returns [`CaptureError`] off Linux, when the clock is unusable, or when
/// collection or encoding fails.
pub fn capture(host_ref: HostRef, source: &ConfigSource) -> Result<(String, bool), CaptureError> {
    if !cfg!(target_os = "linux") {
        return Err(CaptureError::UnsupportedOs);
    }
    let captured_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(CaptureError::Clock)?;
    let snapshot = Snapshot::new(host_ref, captured_at.as_secs(), scan(source)?);
    let json = render_document(&snapshot).map_err(CaptureError::Encode)?;
    Ok((json, snapshot.is_complete()))
}

/// Why a saved Caddy route snapshot could not be replayed.
#[derive(Debug, Error)]
pub enum ReplayError {
    /// The format version requires another reader.
    #[error("unsupported Caddy route snapshot version {0}; this build reads version {VERSION}")]
    Version(u32),
    /// The saved document does not contain valid Caddy route evidence.
    #[error("invalid Caddy route snapshot: {0}")]
    Invalid(&'static str),
}

#[derive(Deserialize)]
struct Header {
    snapshot_version: u32,
}

/// Reads a saved snapshot: the version first, then the whole document, then
/// the rules the evidence must follow.
pub(crate) fn decode(text: &str) -> Result<Snapshot, ReplayError> {
    let header: Header = serde_json::from_str(text)
        .map_err(|_| ReplayError::Invalid("expected a snapshot version"))?;
    if header.snapshot_version != VERSION {
        return Err(ReplayError::Version(header.snapshot_version));
    }
    let snapshot: Snapshot = serde_json::from_str(text)
        .map_err(|_| ReplayError::Invalid("expected capture metadata and route evidence"))?;
    validate_host_ref(&snapshot.host_ref)
        .map_err(|_| ReplayError::Invalid("invalid host label"))?;
    snapshot.evidence.validate().map_err(ReplayError::Invalid)?;
    Ok(snapshot)
}
