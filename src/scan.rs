//! `reachmap scan`: read the kernel's socket tables, the open files of every
//! process and the host's interfaces, and turn them into one sorted list of
//! listening sockets with the program behind each and where it can be reached
//! from. Data flows one way: [`crate::collect`] reads, [`crate::parse`]
//! decodes, this module joins them.

use std::io::ErrorKind;
use std::path::PathBuf;

use thiserror::Error;

use crate::collect::{self, CollectError, ProcessFds, RawTable};
use crate::network::HostAddress;
use crate::parse::ip_addr::parse_ip_addr;
use crate::parse::proc_net::{ParseError, parse_proc_net_tcp};
use crate::parse::proc_pid::owners_by_inode;
use crate::reach::{Verdict, classify};
use crate::service::{Service, UnknownReason, service_of};
use crate::socket::{ListeningSocket, sort_by_port};

/// Where users report problems reachmap cannot handle.
const ISSUES_URL: &str = "https://github.com/MHusted01/reachmap/issues";

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

/// A listening socket with the program behind it and where it can be
/// reached from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScannedSocket {
    /// What the kernel's socket table says.
    pub socket: ListeningSocket,
    /// Who owns the socket.
    pub service: Service,
    /// Which networks can connect, and why.
    pub verdict: Verdict,
}

/// The result of a scan: every socket, plus the reason the interfaces are
/// unknown when they could not be listed.
#[derive(Debug)]
pub struct ScanReport {
    /// The sockets, sorted by port.
    pub sockets: Vec<ScannedSocket>,
    /// Set when the interfaces could not be listed; the verdicts that needed
    /// them are unknown.
    pub interfaces_error: Option<InterfacesError>,
}

/// Reads this host's TCP tables, processes and interfaces and returns its
/// listening sockets, sorted by port.
pub fn scan() -> Result<ScanReport, ScanError> {
    let tables = collect::read_tcp_tables()?;
    let sockets = parse_tables(&tables)?;
    let open_files = collect::read_open_files()?;
    Ok(join(sockets, &open_files, read_host_addresses()))
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

/// Pairs each socket with the process that has it open and its verdict,
/// keeping their order. When no process holds a socket, the reason depends
/// on whether some processes could not be inspected: then root might find
/// the owner.
pub fn join(
    sockets: Vec<ListeningSocket>,
    open_files: &ProcessFds,
    host: Result<Vec<HostAddress>, InterfacesError>,
) -> ScanReport {
    let owners = owners_by_inode(open_files.links());
    let missing = if open_files.permission_denied {
        UnknownReason::NeedsRoot
    } else {
        UnknownReason::NoProcess
    };
    let (host, interfaces_error) = match host {
        Ok(host) => (Some(host), None),
        Err(error) => (None, Some(error)),
    };
    let sockets = sockets
        .into_iter()
        .map(|socket| ScannedSocket {
            service: service_of(socket.inode, &owners, missing),
            verdict: classify(socket.address, host.as_deref()),
            socket,
        })
        .collect();
    ScanReport {
        sockets,
        interfaces_error,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collect::RawProcess;
    use crate::errors::render_chain;
    use crate::network::Network;
    use crate::reach::{Reach, Reason};
    use crate::service::Process;
    use crate::socket::{AddressFamily, Protocol};
    use std::collections::BTreeSet;
    use std::io;
    use std::net::{IpAddr, Ipv4Addr};

    fn socket(port: u16, inode: u64) -> ListeningSocket {
        ListeningSocket {
            protocol: Protocol::Tcp,
            address: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            port,
            inode,
        }
    }

    fn open_files(permission_denied: bool) -> ProcessFds {
        ProcessFds {
            processes: vec![RawProcess {
                pid: 812,
                comm: "sshd\n".to_string(),
                fd_targets: vec!["/dev/null".to_string(), "socket:[100]".to_string()],
            }],
            permission_denied,
        }
    }

    fn lan_host() -> Vec<HostAddress> {
        vec![
            HostAddress {
                interface: "lo".to_string(),
                ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            },
            HostAddress {
                interface: "enp1s0".to_string(),
                ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20)),
            },
        ]
    }

    fn services(report: &ScanReport) -> Vec<(u16, Service)> {
        report
            .sockets
            .iter()
            .map(|s| (s.socket.port, s.service.clone()))
            .collect()
    }

    fn not_found() -> InterfacesError {
        InterfacesError::Collect(CollectError::Run {
            command: "ip -j addr".to_string(),
            source: io::Error::new(ErrorKind::NotFound, "No such file or directory"),
        })
    }

    #[test]
    fn names_the_owner_and_explains_the_rest_when_nothing_was_hidden() {
        let report = join(
            vec![socket(22, 100), socket(53, 999)],
            &open_files(false),
            Ok(lan_host()),
        );

        assert_eq!(
            services(&report),
            vec![
                (
                    22,
                    Service::Process(Process {
                        pid: 812,
                        name: "sshd".to_string()
                    })
                ),
                (53, Service::Unknown(UnknownReason::NoProcess)),
            ]
        );
    }

    #[test]
    fn suggests_root_for_unowned_sockets_when_processes_were_hidden() {
        let report = join(
            vec![socket(22, 100), socket(53, 999)],
            &open_files(true),
            Ok(lan_host()),
        );

        assert!(matches!(report.sockets[0].service, Service::Process(_)));
        assert_eq!(
            report.sockets[1].service,
            Service::Unknown(UnknownReason::NeedsRoot)
        );
    }

    #[test]
    fn classifies_each_socket_against_the_host_interfaces() {
        let report = join(vec![socket(22, 100)], &open_files(false), Ok(lan_host()));

        assert_eq!(
            report.sockets[0].verdict,
            Verdict {
                reach: Reach::From(BTreeSet::from([Network::ThisHost, Network::Lan])),
                reason: Reason::AllAddresses(AddressFamily::Ipv4),
            }
        );
        assert!(report.interfaces_error.is_none());
    }

    #[test]
    fn unknown_interfaces_give_unknown_verdicts_and_keep_the_error() {
        let report = join(vec![socket(22, 100)], &open_files(false), Err(not_found()));

        assert_eq!(report.sockets[0].verdict.reach, Reach::Unknown);
        assert_eq!(report.sockets[0].verdict.reason, Reason::InterfacesUnknown);
        let error = report.interfaces_error.unwrap();
        assert_eq!(
            render_chain(&error),
            "could not list interfaces: could not run `ip -j addr`: No such file or directory"
        );
    }

    #[test]
    fn a_missing_ip_command_suggests_installing_iproute2() {
        assert_eq!(
            not_found().hint().as_deref(),
            Some("install iproute2, the package that provides `ip`")
        );
    }

    #[test]
    fn other_command_errors_have_no_hint() {
        let error = InterfacesError::Collect(CollectError::Run {
            command: "ip -j addr".to_string(),
            source: io::Error::new(ErrorKind::PermissionDenied, "Permission denied"),
        });
        assert_eq!(error.hint(), None);
    }

    #[test]
    fn unreadable_ip_output_asks_for_a_bug_report() {
        let source = serde_json::from_str::<Vec<u8>>("nope").unwrap_err();
        let error = InterfacesError::Parse(source);

        assert!(
            render_chain(&error).starts_with("could not understand the output of `ip -j addr`: ")
        );
        assert!(error.hint().unwrap().contains(ISSUES_URL));
    }
}
