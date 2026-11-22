//! Versioned, offline evidence for the configured Nginx route report.

use std::fmt;
use std::time::{SystemTime, SystemTimeError, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::{NginxRouteReport, NginxScanError, scan};
use crate::host_input_snapshot::{HostRef, SnapshotError, render_document, validate_host_ref};
use crate::sanitize::sanitize;

const VERSION: u32 = 1;
pub(crate) const SCOPE: &str = "nginx_routes";

/// Minimized Nginx route and local TCP listener evidence, with capture time and host label.
#[derive(Debug, Deserialize, Serialize)]
pub struct Snapshot {
    snapshot_version: u32,
    host_ref: String,
    captured_at_unix_seconds: u64,
    scope: Scope,
    evidence: NginxRouteReport,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum Scope {
    NginxRoutes,
}

impl Snapshot {
    pub(super) fn new(
        host_ref: HostRef,
        captured_at_unix_seconds: u64,
        evidence: NginxRouteReport,
    ) -> Self {
        Self {
            snapshot_version: VERSION,
            host_ref: host_ref.into_string(),
            captured_at_unix_seconds,
            scope: Scope::NginxRoutes,
            evidence,
        }
    }

    /// Whether collection was complete and the captured Nginx config had no uncertainties.
    pub fn is_complete(&self) -> bool {
        self.evidence.is_complete()
    }
}

impl fmt::Display for Snapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "Captured Nginx route evidence for {} at Unix time {} (seconds since epoch)",
            sanitize(&self.host_ref),
            self.captured_at_unix_seconds
        )?;
        self.evidence.fmt(f)
    }
}

/// Why Nginx route evidence could not be captured.
#[derive(Debug, Error)]
pub enum CaptureError {
    /// Capture requires Linux collectors.
    #[error("capture Nginx route evidence on Linux; replay is available on this system")]
    UnsupportedOs,
    /// The system clock cannot supply a Unix timestamp.
    #[error("cannot timestamp the Nginx route snapshot; check the system clock")]
    Clock(#[source] SystemTimeError),
    /// Nginx route collection or parsing failed.
    #[error("could not capture Nginx route evidence")]
    Scan(#[from] NginxScanError),
    /// The captured evidence could not be serialized.
    #[error("could not save the Nginx route snapshot")]
    Encode(#[source] SnapshotError),
}

/// Collect Nginx route evidence and return its JSON and completeness flag.
pub fn capture(host_ref: HostRef) -> Result<(String, bool), CaptureError> {
    if !cfg!(target_os = "linux") {
        return Err(CaptureError::UnsupportedOs);
    }
    let captured_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(CaptureError::Clock)?;
    let snapshot = Snapshot::new(host_ref, captured_at.as_secs(), scan()?);
    let json = render_document(&snapshot).map_err(CaptureError::Encode)?;
    Ok((json, snapshot.is_complete()))
}

/// Why a saved Nginx route snapshot could not be replayed.
#[derive(Debug, Error)]
pub enum ReplayError {
    /// The format version requires another reader.
    #[error("unsupported Nginx route snapshot version {0}; this build reads version {VERSION}")]
    Version(u32),
    /// The saved document does not contain valid Nginx route evidence.
    #[error("invalid Nginx route snapshot: {0}")]
    Invalid(&'static str),
}

#[derive(Deserialize)]
struct Header {
    snapshot_version: u32,
}

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
