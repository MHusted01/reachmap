//! Which program is behind a listening socket.

use std::collections::HashMap;
use std::fmt;

use crate::socket::ListeningSocket;

/// A running program, identified by its process ID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Process {
    /// Process ID.
    pub pid: u32,
    /// Short program name from `/proc/<pid>/comm`, e.g. `sshd` (the kernel
    /// cuts it to 15 bytes).
    pub name: String,
}

/// Why the program behind a socket is not known.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnknownReason {
    /// Some processes could not be inspected without more privileges; the
    /// owner is probably one of them.
    NeedsRoot,
    /// Every visible process was inspected and none holds the socket, e.g. a
    /// socket opened by the kernel or by a process that just exited. Processes
    /// hidden by mounting `/proc` with `hidepid=2` are not visible, so this
    /// does not prove that no process holds it.
    NoProcess,
}

/// The program behind one socket, or why it is not known.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Service {
    /// The process that has the socket open.
    Process(Process),
    /// No owner was found.
    Unknown(UnknownReason),
}

impl fmt::Display for Service {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Service::Process(Process { pid, name }) => write!(f, "{name} ({pid})"),
            Service::Unknown(UnknownReason::NeedsRoot) => {
                f.write_str("unknown (run with sudo for details)")
            }
            Service::Unknown(UnknownReason::NoProcess) => f.write_str("unknown"),
        }
    }
}

/// A listening socket together with the program behind it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScannedSocket {
    /// What the kernel's socket table says.
    pub socket: ListeningSocket,
    /// Who owns the socket.
    pub service: Service,
}

/// Pairs each socket with its owner from `owners` (keyed by socket inode),
/// keeping the order of `sockets`. A socket without an entry gets
/// `Service::Unknown(missing)`.
pub fn attach_services(
    sockets: Vec<ListeningSocket>,
    owners: &HashMap<u64, Process>,
    missing: UnknownReason,
) -> Vec<ScannedSocket> {
    sockets
        .into_iter()
        .map(|socket| {
            let service = owners
                .get(&socket.inode)
                .cloned()
                .map_or(Service::Unknown(missing), Service::Process);
            ScannedSocket { socket, service }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
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

    fn process(pid: u32, name: &str) -> Process {
        Process {
            pid,
            name: name.to_string(),
        }
    }

    #[test]
    fn displays_a_process_as_name_and_pid() {
        let service = Service::Process(process(812, "sshd"));
        assert_eq!(service.to_string(), "sshd (812)");
    }

    #[test]
    fn displays_why_an_owner_is_unknown() {
        assert_eq!(
            Service::Unknown(UnknownReason::NeedsRoot).to_string(),
            "unknown (run with sudo for details)"
        );
        assert_eq!(
            Service::Unknown(UnknownReason::NoProcess).to_string(),
            "unknown"
        );
    }

    #[test]
    fn attaches_owners_by_inode_and_keeps_socket_order() {
        let owners = HashMap::from([(200, process(2, "nginx")), (100, process(1, "sshd"))]);

        let scanned = attach_services(
            vec![socket(22, 100), socket(80, 200)],
            &owners,
            UnknownReason::NoProcess,
        );

        assert_eq!(
            scanned,
            vec![
                ScannedSocket {
                    socket: socket(22, 100),
                    service: Service::Process(process(1, "sshd")),
                },
                ScannedSocket {
                    socket: socket(80, 200),
                    service: Service::Process(process(2, "nginx")),
                },
            ]
        );
    }

    #[test]
    fn a_socket_without_an_owner_gets_the_given_reason() {
        let scanned = attach_services(
            vec![socket(5432, 300)],
            &HashMap::new(),
            UnknownReason::NeedsRoot,
        );

        assert_eq!(
            scanned[0].service,
            Service::Unknown(UnknownReason::NeedsRoot)
        );
    }
}
