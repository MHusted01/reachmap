//! A scan in the form `reachmap diff` compares: a saved `reachmap scan --json`
//! document or a finished scan, reduced to the facts that describe exposure.
//!
//! The reader is tolerant, because `docs/json.md` lets new fields and values
//! appear without a new `schema_version`: unknown fields are ignored and an
//! unknown value becomes [`Tolerant::Unknown`] rather than an error. Text in
//! the file is not trusted, so names are sanitised here.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::io;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

use crate::json::{Collector, SCHEMA_VERSION};
use crate::reach::Reach;
use crate::sanitize::sanitize;
use crate::scan::{Listener, ScanReport, ScannedPort};
use crate::service::{Container, Process, Service, UnknownReason};
use crate::socket::{Endpoint, Protocol};
use crate::warning::Warning;

/// A value from a document, or a value this version of reachmap cannot read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Tolerant<T> {
    /// A value this version understands.
    Known(T),
    /// Anything else, for example a value added by a newer reachmap.
    Unknown,
}

impl<T> Tolerant<T> {
    /// The value, if this version understands it.
    fn known(self) -> Option<T> {
        match self {
            Tolerant::Known(value) => Some(value),
            Tolerant::Unknown => None,
        }
    }
}

impl<'de, T: DeserializeOwned> Deserialize<'de> for Tolerant<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = serde_json::Value::deserialize(deserializer)?;
        Ok(serde_json::from_value(value).map_or(Tolerant::Unknown, Tolerant::Known))
    }
}

impl<T: Serialize> Serialize for Tolerant<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Tolerant::Known(value) => value.serialize(serializer),
            Tolerant::Unknown => serializer.serialize_str("unknown"),
        }
    }
}

impl<T: fmt::Display> fmt::Display for Tolerant<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Tolerant::Known(value) => value.fmt(f),
            Tolerant::Unknown => f.write_str("unknown"),
        }
    }
}

/// What identifies a row across two scans. Ordered by port, then protocol,
/// then address, like the rows of a scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct RowKey {
    /// The local port.
    pub port: u16,
    /// Transport protocol.
    pub protocol: Tolerant<Protocol>,
    /// The local address.
    pub address: IpAddr,
}

impl RowKey {
    /// The name the scan's table uses, such as `tcp6`.
    pub fn protocol_name(&self) -> String {
        match self.protocol {
            Tolerant::Known(protocol) => Endpoint {
                port: self.port,
                protocol,
                address: self.address,
            }
            .protocol_name(),
            Tolerant::Unknown => "unknown".to_string(),
        }
    }
}

impl From<Endpoint> for RowKey {
    fn from(endpoint: Endpoint) -> Self {
        RowKey {
            port: endpoint.port,
            protocol: Tolerant::Known(endpoint.protocol),
            address: endpoint.address,
        }
    }
}

/// Who connections end up with. A process has no ID here, because a restart
/// is no change in exposure.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Owner {
    /// A process, by its program name.
    Process {
        /// The program name.
        name: String,
    },
    /// A Docker container.
    Container(Container),
    /// No owner was found, or the document names one this version cannot read.
    Unknown,
}

impl fmt::Display for Owner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Owner::Process { name } => f.write_str(name),
            Owner::Container(container) => container.fmt(f),
            Owner::Unknown => f.write_str("unknown"),
        }
    }
}

/// Sanitises every name, so a hand-edited file cannot reach the terminal. Text
/// from a live scan is clean already, and cleaning it again changes nothing.
impl From<&Service> for Owner {
    fn from(service: &Service) -> Self {
        match service {
            Service::Process(Process { name, .. }) => Owner::Process {
                name: sanitize(name),
            },
            Service::Container(container) => Owner::Container(Container {
                name: sanitize(&container.name),
                compose_service: container.compose_service.as_deref().map(sanitize),
            }),
            Service::Unknown { .. } => Owner::Unknown,
        }
    }
}

/// What a row says about who can connect to what.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Exposure {
    /// What accepts connections.
    pub listener: Tolerant<Listener>,
    /// Who they end up with.
    pub service: Owner,
    /// Which networks can connect.
    pub reach: Reach,
    /// What the firewall facts add.
    pub warning: Option<Tolerant<Warning>>,
}

impl From<&ScannedPort> for Exposure {
    fn from(port: &ScannedPort) -> Self {
        Exposure {
            listener: Tolerant::Known(port.listener),
            service: Owner::from(&port.service),
            reach: port.verdict.reach.clone(),
            warning: port.warning.map(Tolerant::Known),
        }
    }
}

/// One scan, ready to compare.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    /// What each row says. Sockets can share a port, protocol and address (for
    /// example with `SO_REUSEPORT`), and identical rows count once, so eight
    /// workers instead of four change nothing.
    pub rows: BTreeMap<RowKey, BTreeSet<Exposure>>,
    /// The optional collectors that failed.
    pub missing: BTreeSet<Tolerant<Collector>>,
    /// Whether some owners are unknown for lack of privileges.
    pub needs_root: bool,
}

/// Groups rows by their key.
fn grouped(
    rows: impl IntoIterator<Item = (RowKey, Exposure)>,
) -> BTreeMap<RowKey, BTreeSet<Exposure>> {
    let mut grouped: BTreeMap<RowKey, BTreeSet<Exposure>> = BTreeMap::new();
    for (key, exposure) in rows {
        grouped.entry(key).or_default().insert(exposure);
    }
    grouped
}

/// Whether more privileges might name the owner.
fn lacks_privileges(service: &Service) -> bool {
    matches!(
        service,
        Service::Unknown {
            reason: UnknownReason::NeedsRoot
        }
    )
}

impl From<&ScanReport> for Snapshot {
    fn from(report: &ScanReport) -> Self {
        let failed = [
            (report.interfaces_error.is_some(), Collector::Interfaces),
            (report.docker_error.is_some(), Collector::Docker),
            (
                report.socket_options_error.is_some(),
                Collector::SocketOptions,
            ),
        ];
        Snapshot {
            rows: grouped(
                report
                    .ports
                    .iter()
                    .map(|port| (port.endpoint.into(), port.into())),
            ),
            missing: failed
                .into_iter()
                .filter_map(|(failed, collector)| failed.then_some(Tolerant::Known(collector)))
                .collect(),
            needs_root: report
                .ports
                .iter()
                .any(|port| lacks_privileges(&port.service)),
        }
    }
}

/// The version of a document, read first: another version may have another
/// shape, and the version is what the user needs to hear about.
#[derive(Deserialize)]
struct Header {
    schema_version: u32,
}

/// The parts of a saved scan `diff` uses.
#[derive(Deserialize)]
struct SavedScan {
    ports: Vec<SavedPort>,
    collector_errors: Vec<SavedCollectorError>,
}

/// One row of a saved scan. `reason` is left out: the same reach for another
/// reason is no new exposure.
#[derive(Deserialize)]
struct SavedPort {
    port: u16,
    protocol: Tolerant<Protocol>,
    address: IpAddr,
    listener: Tolerant<Listener>,
    service: Tolerant<Service>,
    reach: Tolerant<Reach>,
    warning: Option<Tolerant<Warning>>,
}

/// The one fact of a collector error that is not text for people.
#[derive(Deserialize)]
struct SavedCollectorError {
    collector: Tolerant<Collector>,
}

impl SavedPort {
    /// The row's key and what it says.
    fn into_row(self) -> (RowKey, Exposure) {
        let key = RowKey {
            port: self.port,
            protocol: self.protocol,
            address: self.address,
        };
        let exposure = Exposure {
            listener: self.listener,
            service: self
                .service
                .known()
                .map_or(Owner::Unknown, |service| Owner::from(&service)),
            reach: self.reach.known().unwrap_or(Reach::Unknown),
            warning: self.warning,
        };
        (key, exposure)
    }
}

/// Why a text is not a scan document reachmap can read.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ParseError {
    /// The document comes from a reachmap with another JSON format.
    #[error(
        "schema_version {found} is not supported, this reachmap reads version {SCHEMA_VERSION}; save it again with `reachmap scan --json`"
    )]
    UnsupportedVersion {
        /// The version in the document.
        found: u32,
    },
    /// The text is not JSON, or not the document `reachmap scan --json` prints.
    #[error("it is not a `reachmap scan --json` document ({message})")]
    NotAScan {
        /// What the JSON parser said, sanitised: it can quote the file.
        message: String,
    },
}

impl From<serde_json::Error> for ParseError {
    fn from(error: serde_json::Error) -> Self {
        ParseError::NotAScan {
            message: sanitize(&error.to_string()),
        }
    }
}

/// Why a saved scan could not be used.
#[derive(Debug, Error)]
pub enum LoadError {
    /// The file could not be read.
    #[error("could not read {}", path.display())]
    Read {
        /// The file.
        path: PathBuf,
        /// What went wrong.
        #[source]
        source: io::Error,
    },
    /// The file was read, but reachmap cannot use its content.
    #[error("could not use {}", path.display())]
    Parse {
        /// The file.
        path: PathBuf,
        /// What is wrong with it.
        #[source]
        source: ParseError,
    },
}

/// Reads the text of a saved scan. Pure, so it is tested on any OS.
pub fn parse(text: &str) -> Result<Snapshot, ParseError> {
    let Header { schema_version } = serde_json::from_str(text)?;
    if schema_version != SCHEMA_VERSION {
        return Err(ParseError::UnsupportedVersion {
            found: schema_version,
        });
    }
    let saved: SavedScan = serde_json::from_str(text)?;
    let needs_root = saved.ports.iter().any(|port| match &port.service {
        Tolerant::Known(service) => lacks_privileges(service),
        Tolerant::Unknown => false,
    });
    Ok(Snapshot {
        rows: grouped(saved.ports.into_iter().map(SavedPort::into_row)),
        missing: saved
            .collector_errors
            .into_iter()
            .map(|error| error.collector)
            .collect(),
        needs_root,
    })
}

/// Reads a saved scan from `path`.
pub fn load(path: &Path) -> Result<Snapshot, LoadError> {
    let text = fs::read_to_string(path).map_err(|source| LoadError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    parse(&text).map_err(|source| LoadError::Parse {
        path: path.to_path_buf(),
        source,
    })
}

#[cfg(test)]
mod tests;
