//! `reachmap scan`: read the kernel's socket tables and socket options, the
//! open files of every process, the host's interfaces, Docker's published ports,
//! what Tailscale shares and the firewall facts, and turn them into one sorted list of ports with the program or
//! container behind each, where it can be reached from, and what deserves a
//! warning. Data flows one way: [`crate::collect`] reads, [`crate::parse`]
//! decodes, this module joins them.

use std::fmt;
use std::io::ErrorKind;
use std::net::IpAddr;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::collect::{self, CollectError, ProcessFds, RawTable};
use crate::docker::{self, DockerError, PublishedPort};
use crate::firewall::{self, DockerUserChain, Firewall, UfwState};
use crate::network::{HostAddress, HostInterfaces};
use crate::parse::ip_addr::parse_ip_addr;
use crate::parse::proc_net::{ParseError, parse_proc_net};
use crate::parse::proc_pid::owners_by_inode;
use crate::reach::{SocketScope, Verdict, classify};
use crate::service::{Service, UnknownReason, service_of};
use crate::socket::{Endpoint, ListeningSocket, sort_by_port};
use crate::socket_options::{
    OptionsByInode, OptionsReport, SocketOptionsError, read_socket_options,
};
use crate::tailscale::{self, SharedPort, TailscaleError};
use crate::warning::{
    ScanWarning, Warning, docker_ufw_bypass, summarise, tailscale_no_row, tailscale_warning,
};

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
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Listener {
    /// A socket in the kernel's tables.
    HostSocket,
    /// Docker publishes the port, but no socket listens on the host: only its
    /// firewall rules forward the traffic.
    DockerForward,
    /// Tailscale shares the port and forwards to no port with a row, so only
    /// its serve config shows it.
    TailscaleShare,
}

impl fmt::Display for Listener {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Listener::HostSocket => "host socket",
            Listener::DockerForward => "Docker forward",
            Listener::TailscaleShare => "Tailscale share",
        })
    }
}

/// A port on this host with what is behind it and where it can be reached
/// from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ScannedPort {
    /// Where connections are accepted.
    #[serde(flatten)]
    pub endpoint: Endpoint,
    /// What accepts them.
    pub listener: Listener,
    /// Who they end up with.
    pub service: Service,
    /// Which networks can connect, and why.
    #[serde(flatten)]
    pub verdict: Verdict,
    /// What the firewall facts add, for a published port.
    pub warning: Option<Warning>,
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
    /// Set when some socket options could not be read; the verdicts of those
    /// sockets then assume the widest case and say what was not checked.
    pub socket_options_error: Option<SocketOptionsError>,
    /// Set when Tailscale could not be asked; rows then show the reach of
    /// their socket alone.
    pub tailscale_error: Option<TailscaleError>,
    /// The summary under the table. Any entry makes the scan exit with 1.
    pub warnings: Vec<ScanWarning>,
}

/// Reads this host's socket tables, socket options, processes, interfaces, Docker
/// containers, Tailscale's shared ports and firewall facts and returns its ports,
/// sorted by port number.
pub fn scan() -> Result<ScanReport, ScanError> {
    let tables = collect::read_socket_tables()?;
    let sockets = parse_tables(&tables)?;
    let options = read_socket_options();
    let open_files = collect::read_open_files()?;
    let published = docker::read_published_ports();
    let firewall = firewall_facts(
        &published,
        firewall::read_ufw_state(),
        firewall::read_docker_user_chain,
    );
    Ok(join(
        sockets,
        &open_files,
        read_host_interfaces(),
        published,
        tailscale::read_shared_ports(),
        options,
        &firewall,
    ))
}

/// Combines UFW's state with the `DOCKER-USER` chain. `iptables` only runs
/// when a port makes the chain matter, because it is one more program to
/// start and most hosts have no such port.
fn firewall_facts(
    published: &Result<Vec<PublishedPort>, DockerError>,
    ufw: UfwState,
    read_chain: impl FnOnce() -> DockerUserChain,
) -> Firewall {
    let chain_matters = published.as_ref().is_ok_and(|ports| {
        ports
            .iter()
            .any(|port| docker_ufw_bypass(port, &ufw).is_some())
    });
    Firewall {
        ufw,
        docker_user: chain_matters.then(read_chain),
    }
}

/// Lists this host's interfaces and their addresses.
fn read_host_interfaces() -> Result<HostInterfaces, InterfacesError> {
    let json = collect::read_interfaces().map_err(InterfacesError::Collect)?;
    parse_ip_addr(&json).map_err(InterfacesError::Parse)
}

/// Parses already-read tables into one list sorted by port. Pure, so it is
/// tested with fixture text on any OS.
pub fn parse_tables(tables: &[RawTable]) -> Result<Vec<ListeningSocket>, ScanError> {
    let mut sockets = Vec::new();
    for table in tables {
        let parsed =
            parse_proc_net(&table.text, table.family, table.protocol).map_err(|source| {
                ScanError::Parse {
                    path: table.path.clone(),
                    source,
                }
            })?;
        sockets.extend(parsed);
    }
    Ok(sort_by_port(sockets))
}

/// Pairs each socket with its container or else the process that has it open,
/// adds the published ports without a socket, gives each its verdict and
/// warning, widens the verdicts of what Tailscale shares, and adds the shared
/// ports that forward to no row. When no process holds a socket, the reason
/// depends on whether some processes could not be inspected or may be hidden:
/// then root might find the owner. A socket the kernel reported no options for
/// stays unchecked.
pub fn join(
    sockets: Vec<ListeningSocket>,
    open_files: &ProcessFds,
    host: Result<HostInterfaces, InterfacesError>,
    published: Result<Vec<PublishedPort>, DockerError>,
    tailscale: Result<Vec<SharedPort>, TailscaleError>,
    options: OptionsReport,
    firewall: &Firewall,
) -> ScanReport {
    let owners = owners_by_inode(open_files.links());
    let missing = if open_files.incomplete() {
        UnknownReason::NeedsRoot
    } else {
        UnknownReason::NoProcess
    };
    let (host, interfaces_error) = split(host);
    let (published, docker_error) = split(published);
    let (shared, tailscale_error) = split(tailscale);
    let OptionsReport {
        by_inode,
        error: socket_options_error,
    } = options;
    let addresses = host.as_ref().map(|host| host.addresses.as_slice());
    let published = published.unwrap_or_default();
    let shared = shared.unwrap_or_default();
    let sockets = with_options(sockets, by_inode);

    let on_sockets = sockets.iter().map(|socket| {
        let publisher = docker::publisher_of(&published, socket);
        ScannedPort {
            endpoint: socket.endpoint(),
            listener: Listener::HostSocket,
            service: publisher.map_or_else(
                || service_of(socket.inode, &owners, missing),
                |port| Service::Container(port.container.clone()),
            ),
            verdict: classify(socket.address, scope_of(socket, host.as_ref()), addresses),
            warning: publisher.and_then(|port| docker_ufw_bypass(port, &firewall.ufw)),
        }
    });
    let forwarded = docker::without_socket(&published, &sockets).map(|port| ScannedPort {
        endpoint: port.endpoint(),
        listener: Listener::DockerForward,
        service: Service::Container(port.container.clone()),
        verdict: classify(port.address, None, addresses),
        warning: docker_ufw_bypass(port, &firewall.ufw),
    });
    let mut ports: Vec<ScannedPort> = on_sockets
        .chain(forwarded)
        .map(|port| ScannedPort {
            verdict: tailscale::widen(port.verdict, port.endpoint, &shared),
            ..port
        })
        .collect();
    let endpoints: Vec<Endpoint> = ports.iter().map(|port| port.endpoint).collect();
    let unjoined = tailscale::without_row(&shared, &endpoints);
    let tailnet = tailnet_addresses(addresses);
    ports.extend(share_rows(&unjoined, &tailnet));
    ports.sort_by_key(|port| port.endpoint);
    let warnings = summarise(&ports, docker_error.as_ref(), firewall)
        .into_iter()
        .chain(tailscale_warning(&shared, tailscale_error.as_ref()))
        .chain(tailscale_no_row(&unjoined, &tailnet))
        .collect();
    ScanReport {
        ports,
        interfaces_error,
        docker_error,
        socket_options_error,
        tailscale_error,
        warnings,
    }
}

/// The addresses clients on the tailnet connect to, if the interfaces are known.
fn tailnet_addresses(addresses: Option<&[HostAddress]>) -> Vec<IpAddr> {
    addresses
        .unwrap_or_default()
        .iter()
        .filter(|address| address.is_tailnet_address())
        .map(|address| address.ip)
        .collect()
}

/// A row for each of `shared` on each of `addresses`. The serve config names no
/// address, so these are the addresses of this host that Tailscale accepts on.
fn share_rows(shared: &[&SharedPort], addresses: &[IpAddr]) -> impl Iterator<Item = ScannedPort> {
    shared.iter().flat_map(move |port| {
        addresses.iter().map(move |&address| ScannedPort {
            endpoint: port.endpoint_on(address),
            listener: Listener::TailscaleShare,
            service: Service::Tailscale,
            verdict: port.verdict(),
            warning: None,
        })
    })
}

/// Gives each socket the options the kernel reported for its inode.
fn with_options(sockets: Vec<ListeningSocket>, options: OptionsByInode) -> Vec<ListeningSocket> {
    sockets
        .into_iter()
        .map(|socket| ListeningSocket {
            options: options.get(&socket.inode).copied(),
            ..socket
        })
        .collect()
}

/// What `classify` may rely on for this socket, if anything.
fn scope_of<'a>(
    socket: &ListeningSocket,
    host: Option<&'a HostInterfaces>,
) -> Option<SocketScope<'a>> {
    SocketScope::resolve(socket.options?, &host?.names)
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
