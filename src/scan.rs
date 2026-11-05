//! `reachmap scan`: read the kernel's socket tables, the open files of every
//! process, the host's interfaces and Docker's published ports, and turn them
//! into one sorted list of ports with the program or container behind each and
//! where it can be reached from. Data flows one way: [`crate::collect`] reads, [`crate::parse`]
//! decodes, this module joins them.

use std::io::ErrorKind;
use std::path::PathBuf;

use thiserror::Error;

use crate::collect::{self, CollectError, ProcessFds, RawTable};
use crate::docker::{self, DockerError, PublishedPort};
use crate::network::HostAddress;
use crate::parse::ip_addr::parse_ip_addr;
use crate::parse::proc_net::{ParseError, parse_proc_net_tcp};
use crate::parse::proc_pid::owners_by_inode;
use crate::reach::{Verdict, classify};
use crate::service::{Service, UnknownReason, service_of};
use crate::socket::{Endpoint, ListeningSocket, sort_by_port};

/// Where users report problems reachmap cannot handle.
pub(crate) const ISSUES_URL: &str = "https://github.com/MHusted01/reachmap/issues";

/// Why a scan could not finish. Each variant describes only itself; the
/// cause is reachable through `Error::source` (see [`crate::errors`]).
#[derive(Debug, Error)]
pub enum ScanError {
    /// The system could not be read.
    #[error(transparent)]
    Collect(#[from] CollectError),
    /// A table was read but its content is not in the expected format.
    #[error("could not understand {}", path.display())]
    Parse {
        /// The table that failed.
        path: PathBuf,
        /// The row and what was wrong with it.
        #[source]
        source: ParseError,
    },
}

impl ScanError {
    /// A suggestion for the user, when there is one beyond the message.
    pub fn hint(&self) -> Option<String> {
        match self {
            ScanError::Parse { path, source } => Some(format!(
                "this is likely a reachmap bug or a new kernel format; please report it at \
                 {ISSUES_URL} with line {} of {}",
                source.line,
                path.display()
            )),
            ScanError::Collect(_) => None,
        }
    }
}

/// Why the host's interfaces are unknown. The scan still finishes: sockets
/// that need interface facts get an unknown verdict.
#[derive(Debug, Error)]
pub enum InterfacesError {
    /// `ip -j addr` could not be run or failed.
    #[error("could not list interfaces")]
    Collect(#[source] CollectError),
    /// `ip -j addr` printed something reachmap does not understand.
    #[error("could not understand the output of `ip -j addr`")]
    Parse(#[source] serde_json::Error),
}

impl InterfacesError {
    /// A suggestion for the user, when there is one beyond the message.
    pub fn hint(&self) -> Option<String> {
        match self {
            InterfacesError::Collect(CollectError::Run { source, .. })
                if source.kind() == ErrorKind::NotFound =>
            {
                Some("install iproute2, the package that provides `ip`".to_string())
            }
            InterfacesError::Collect(_) => None,
            InterfacesError::Parse(_) => Some(format!(
                "this is likely a reachmap bug or a new iproute2 format; please report it at \
                 {ISSUES_URL} with the output of `ip -j addr`"
            )),
        }
    }
}

/// What accepts connections on a port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Listener {
    /// A socket in the kernel's tables.
    HostSocket,
    /// Docker publishes the port, but no socket listens on the host: only its
    /// firewall rules forward the traffic.
    DockerForward,
}

/// A port on this host with what is behind it and where it can be reached
/// from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScannedPort {
    /// Where connections are accepted.
    pub endpoint: Endpoint,
    /// What accepts them.
    pub listener: Listener,
    /// Who they end up with.
    pub service: Service,
    /// Which networks can connect, and why.
    pub verdict: Verdict,
}

/// The result of a scan: every port, plus the reasons when optional facts
/// could not be collected.
#[derive(Debug)]
pub struct ScanReport {
    /// The ports, sorted by port number.
    pub ports: Vec<ScannedPort>,
    /// Set when the interfaces could not be listed; the verdicts that needed
    /// them are unknown.
    pub interfaces_error: Option<InterfacesError>,
    /// Set when Docker could not be asked; published ports then show the
    /// process that holds their socket, and those without one are missing.
    pub docker_error: Option<DockerError>,
}

/// Reads this host's TCP tables, processes, interfaces and Docker containers
/// and returns its ports, sorted by port number.
pub fn scan() -> Result<ScanReport, ScanError> {
    let tables = collect::read_tcp_tables()?;
    let sockets = parse_tables(&tables)?;
    let open_files = collect::read_open_files()?;
    Ok(join(
        sockets,
        &open_files,
        read_host_addresses(),
        docker::read_published_ports(),
    ))
}

/// Lists the addresses of this host's interfaces.
fn read_host_addresses() -> Result<Vec<HostAddress>, InterfacesError> {
    let json = collect::read_interfaces().map_err(InterfacesError::Collect)?;
    parse_ip_addr(&json).map_err(InterfacesError::Parse)
}

/// Parses already-read tables into one list sorted by port. Pure, so it is
/// tested with fixture text on any OS.
pub fn parse_tables(tables: &[RawTable]) -> Result<Vec<ListeningSocket>, ScanError> {
    let mut sockets = Vec::new();
    for table in tables {
        let parsed =
            parse_proc_net_tcp(&table.text, table.family).map_err(|source| ScanError::Parse {
                path: table.path.clone(),
                source,
            })?;
        sockets.extend(parsed);
    }
    Ok(sort_by_port(sockets))
}

/// Pairs each socket with its container or else the process that has it open,
/// adds the published ports without a socket, and gives each its verdict. When
/// no process holds a socket, the reason depends on whether some processes
/// could not be inspected: then root might find the owner.
pub fn join(
    sockets: Vec<ListeningSocket>,
    open_files: &ProcessFds,
    host: Result<Vec<HostAddress>, InterfacesError>,
    published: Result<Vec<PublishedPort>, DockerError>,
) -> ScanReport {
    let owners = owners_by_inode(open_files.links());
    let missing = if open_files.permission_denied {
        UnknownReason::NeedsRoot
    } else {
        UnknownReason::NoProcess
    };
    let (host, interfaces_error) = split(host);
    let (published, docker_error) = split(published);
    let host = host.as_deref();
    let published = published.unwrap_or_default();

    let on_sockets = sockets.iter().map(|socket| ScannedPort {
        endpoint: socket.endpoint(),
        listener: Listener::HostSocket,
        service: docker::publisher_of(&published, socket).map_or_else(
            || service_of(socket.inode, &owners, missing),
            |port| Service::Container(port.container.clone()),
        ),
        verdict: classify(socket.address, host),
    });
    let forwarded = docker::without_socket(&published, &sockets).map(|port| ScannedPort {
        endpoint: port.endpoint(),
        listener: Listener::DockerForward,
        service: Service::Container(port.container.clone()),
        verdict: classify(port.address, host),
    });
    let mut ports: Vec<ScannedPort> = on_sockets.chain(forwarded).collect();
    ports.sort_by_key(|port| port.endpoint);
    ScanReport {
        ports,
        interfaces_error,
        docker_error,
    }
}

/// Separates a value from the error of an optional collector.
fn split<T, E>(result: Result<T, E>) -> (Option<T>, Option<E>) {
    match result {
        Ok(value) => (Some(value), None),
        Err(error) => (None, Some(error)),
    }
}

#[cfg(test)]
mod tests;
