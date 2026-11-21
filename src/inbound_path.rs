//! Predicts a scoped Linux inbound TCP path and saves evidence for offline replay.

use std::fmt;
use std::net::IpAddr;
use std::num::NonZeroU16;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::host_input_snapshot::{
    Evidence, SnapshotError, read_document, render_document, validate_host_ref,
};
use crate::socket::AddressFamily;

pub(crate) mod docker;
mod evaluate;

const VERSION: u32 = 1;
const SCOPE: &str = "linux_inbound_tcp";

/// A new inbound TCP connection to analyze.
#[derive(Debug, Serialize, Deserialize)]
pub struct Flow {
    pub(crate) source: IpAddr,
    pub(crate) ingress: String,
    pub(crate) destination: IpAddr,
    pub(crate) port: NonZeroU16,
}

impl Flow {
    /// Validates the addresses and ingress interface before live collection.
    pub fn new(
        source: IpAddr,
        ingress: String,
        destination: IpAddr,
        port: NonZeroU16,
    ) -> Result<Self, PathError> {
        let flow = Self {
            source,
            ingress,
            destination,
            port,
        };
        flow.validate()?;
        Ok(flow)
    }

    fn validate(&self) -> Result<(), PathError> {
        if self.source.is_ipv4() != self.destination.is_ipv4()
            || !unicast(self.source)
            || !unicast(self.destination)
        {
            return Err(PathError::Addresses);
        }
        if self.ingress.is_empty()
            || self.ingress.len() > 15
            || self.ingress.starts_with('-')
            || matches!(self.ingress.as_str(), "." | "..")
            || !self
                .ingress
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_.:-".contains(&byte))
        {
            return Err(PathError::Ingress);
        }
        Ok(())
    }

    pub(crate) fn family(&self) -> AddressFamily {
        match self.destination {
            IpAddr::V4(_) => AddressFamily::Ipv4,
            IpAddr::V6(_) => AddressFamily::Ipv6,
        }
    }
}

fn unicast(address: IpAddr) -> bool {
    !address.is_unspecified()
        && !address.is_multicast()
        && match address {
            IpAddr::V4(address) => !address.is_broadcast(),
            IpAddr::V6(address) => address.to_ipv4_mapped().is_none(),
        }
}

/// A versioned capture of the facts for one flow.
#[derive(Debug, Serialize, Deserialize)]
pub struct Snapshot {
    snapshot_version: u32,
    scope: String,
    host_ref: String,
    captured_at_unix_seconds: u64,
    flow: Flow,
    evidence: PathEvidence,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct PathEvidence {
    pub(crate) link: Evidence<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) ipv6_disabled: Option<Evidence<bool>>,
    pub(crate) legacy_tables: Evidence<String>,
    pub(crate) xfrm_policies: Evidence<String>,
    pub(crate) xfrm_defaults: Evidence<String>,
    pub(crate) nftables: Evidence<String>,
    pub(crate) routing_rules: Evidence<String>,
    pub(crate) route: Evidence<String>,
    pub(crate) listeners: Evidence<Vec<Listener>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) docker: Option<docker::DockerEvidence>,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Listener {
    pub(crate) address: IpAddr,
    pub(crate) inode: u64,
    pub(crate) options: Option<ListenerOptions>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ListenerOptions {
    // A field with a null value is a confirmed lack of device binding.
    #[serde(deserialize_with = "Deserialize::deserialize")]
    pub(crate) bound_device: Option<u32>,
    pub(crate) ipv6_only: bool,
}

impl Snapshot {
    /// Formats evidence as a bounded JSON document for offline replay.
    pub fn render(&self) -> Result<String, PathError> {
        Ok(render_document(self)?)
    }

    /// Evaluate only the captured evidence.
    pub fn predict(&self) -> Prediction<'_> {
        let (steps, verdict) = evaluate::evaluate(&self.flow, &self.evidence);
        Prediction {
            scope: SCOPE,
            host_ref: &self.host_ref,
            captured_at_unix_seconds: self.captured_at_unix_seconds,
            flow: &self.flow,
            steps,
            verdict,
        }
    }
}

/// Why a flow could not be captured or its snapshot could not be replayed.
#[derive(Debug, Error)]
pub enum PathError {
    /// Both endpoints must be usable addresses in the same IP family.
    #[error("use two unicast IP addresses of the same family")]
    Addresses,
    /// Linux interface names are passed to the kernel as literal values.
    #[error("use an ingress interface name of 1 to 15 letters, digits or _ . : - characters")]
    Ingress,
    /// Only Linux supports a live capture, and any platform can replay it.
    #[error("capture an inbound TCP path on Linux; replay is available on this system")]
    UnsupportedOs,
    /// A different workflow produced the supplied snapshot.
    #[error("use an inbound TCP snapshot from `reachmap path capture`")]
    Scope,
    /// The document requires a different reader.
    #[error("unsupported inbound TCP snapshot version {0}; this build reads version {VERSION}")]
    Version(u32),
    /// The snapshot JSON could not be decoded.
    #[error("invalid inbound TCP snapshot at line {line}, column {column}")]
    Invalid {
        /// Line of the decoding error.
        line: usize,
        /// Column of the decoding error.
        column: usize,
    },
    /// A shared snapshot file or host reference error.
    #[error(transparent)]
    Snapshot(#[from] SnapshotError),
}

/// Captures scoped local evidence for a single flow. Sends no packets.
pub fn capture(flow: Flow, host_ref: String) -> Result<Snapshot, PathError> {
    validate_host_ref(&host_ref)?;
    let captured_at_unix_seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(SnapshotError::Clock)?
        .as_secs();
    #[cfg(target_os = "linux")]
    let evidence: Result<_, PathError> = Ok(crate::collect::inbound_path::capture(&flow));
    #[cfg(not(target_os = "linux"))]
    let evidence = Err(PathError::UnsupportedOs);
    Ok(Snapshot {
        snapshot_version: VERSION,
        scope: SCOPE.to_owned(),
        host_ref,
        captured_at_unix_seconds,
        flow,
        evidence: evidence?,
    })
}

#[derive(Deserialize)]
struct Header {
    snapshot_version: u32,
    scope: String,
}

/// Reads a saved capture for replay without querying the host.
pub fn read(path: &Path) -> Result<Snapshot, PathError> {
    fn invalid(error: &serde_json::Error) -> PathError {
        PathError::Invalid {
            line: error.line(),
            column: error.column(),
        }
    }
    let text = read_document(path)?;
    let header: Header = serde_json::from_str(&text).map_err(|error| invalid(&error))?;
    if header.scope != SCOPE {
        return Err(PathError::Scope);
    }
    if header.snapshot_version != VERSION {
        return Err(PathError::Version(header.snapshot_version));
    }
    let snapshot: Snapshot = serde_json::from_str(&text).map_err(|error| invalid(&error))?;
    snapshot.flow.validate()?;
    validate_host_ref(&snapshot.host_ref)?;
    Ok(snapshot)
}

/// Ordered decisions for the stated flow, based on sampled host evidence.
#[derive(Debug, Serialize)]
pub struct Prediction<'a> {
    scope: &'static str,
    host_ref: &'a str,
    captured_at_unix_seconds: u64,
    flow: &'a Flow,
    steps: Vec<evaluate::Step<'a>>,
    verdict: evaluate::Verdict,
}

impl fmt::Display for Prediction<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use std::net::SocketAddr;

        let flow = self.flow;
        writeln!(
            f,
            "Inbound TCP prediction on {} at {} ({} through {} to {})",
            self.host_ref,
            self.captured_at_unix_seconds,
            flow.source,
            flow.ingress,
            SocketAddr::new(flow.destination, flow.port.get())
        )?;
        for step in &self.steps {
            writeln!(f, "{step}")?;
        }
        writeln!(f, "Prediction: {}", self.verdict)
    }
}
