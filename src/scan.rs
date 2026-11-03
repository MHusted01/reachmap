//! `reachmap scan`: read the kernel's socket tables and the open files of
//! every process, and turn them into one sorted list of listening sockets with
//! the program behind each. Data flows one way: [`crate::collect`] reads,
//! [`crate::parse`] decodes, this module joins them.

use std::path::PathBuf;

use thiserror::Error;

use crate::collect::{self, CollectError, ProcessFds, RawTable};
use crate::parse::proc_net::{ParseError, parse_proc_net_tcp};
use crate::parse::proc_pid::owners_by_inode;
use crate::service::{ScannedSocket, UnknownReason, attach_services};
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

/// Reads this host's TCP tables and returns its listening sockets with the
/// program behind each, sorted by port.
pub fn scan() -> Result<Vec<ScannedSocket>, ScanError> {
    let tables = collect::read_tcp_tables()?;
    let sockets = parse_tables(&tables)?;
    let open_files = collect::read_open_files()?;
    Ok(identify_services(sockets, &open_files))
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

/// Pairs each socket with the process that has it open, keeping their order.
/// When no process holds a socket, the reason depends on whether some
/// processes could not be inspected: then root might find the owner.
pub fn identify_services(
    sockets: Vec<ListeningSocket>,
    open_files: &ProcessFds,
) -> Vec<ScannedSocket> {
    let owners = owners_by_inode(open_files.links());
    let missing = if open_files.permission_denied {
        UnknownReason::NeedsRoot
    } else {
        UnknownReason::NoProcess
    };
    attach_services(sockets, &owners, missing)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collect::RawProcess;
    use crate::service::{Process, Service};
    use crate::socket::Protocol;
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

    fn services(scanned: &[ScannedSocket]) -> Vec<(u16, Service)> {
        scanned
            .iter()
            .map(|s| (s.socket.port, s.service.clone()))
            .collect()
    }

    #[test]
    fn names_the_owner_and_explains_the_rest_when_nothing_was_hidden() {
        let scanned = identify_services(vec![socket(22, 100), socket(53, 999)], &open_files(false));

        assert_eq!(
            services(&scanned),
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
        let scanned = identify_services(vec![socket(22, 100), socket(53, 999)], &open_files(true));

        assert!(matches!(scanned[0].service, Service::Process(_)));
        assert_eq!(
            scanned[1].service,
            Service::Unknown(UnknownReason::NeedsRoot)
        );
    }
}
