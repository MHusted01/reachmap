//! Which program is behind a listening socket.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

/// A running program, identified by its process ID.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Process {
    /// Process ID.
    pub pid: u32,
    /// Short program name from `/proc/<pid>/comm`, e.g. `sshd` (the kernel
    /// cuts it to 15 bytes).
    pub name: String,
}

/// A running Docker container. Both names are sanitised when parsed.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Container {
    /// The container's name, e.g. `shop-web-1`.
    pub name: String,
    /// Its service in a Compose project, e.g. `web`.
    pub compose_service: Option<String>,
}

impl fmt::Display for Container {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.compose_service {
            Some(service) => write!(f, "{service} (container {})", self.name),
            None => write!(f, "container {}", self.name),
        }
    }
}

/// Why the program behind a socket is not known.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnknownReason {
    /// Some processes could not be inspected without more privileges, or
    /// `/proc` may hide them with `hidepid`; the owner is probably one of them.
    NeedsRoot,
    /// Every process was inspected and none holds the socket, e.g. a socket
    /// opened by the kernel or by a process that just exited.
    NoProcess,
}

/// The program behind one socket, or why it is not known.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Service {
    /// The process that has the socket open.
    Process(Process),
    /// The Docker container the port is published for.
    Container(Container),
    /// No owner was found.
    Unknown {
        /// Why not.
        reason: UnknownReason,
    },
}

impl fmt::Display for Service {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Service::Process(Process { pid, name }) => write!(f, "{name} ({pid})"),
            Service::Container(container) => container.fmt(f),
            Service::Unknown {
                reason: UnknownReason::NeedsRoot,
            } => f.write_str("unknown (run with sudo for details)"),
            Service::Unknown {
                reason: UnknownReason::NoProcess,
            } => f.write_str("unknown"),
        }
    }
}

/// The program that has the socket with this `inode` open, from `owners`
/// (keyed by socket inode). Without an entry the owner is
/// `Service::Unknown { reason: missing }`.
pub fn service_of(inode: u64, owners: &HashMap<u64, Process>, missing: UnknownReason) -> Service {
    owners
        .get(&inode)
        .cloned()
        .map_or(Service::Unknown { reason: missing }, Service::Process)
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn displays_a_compose_container_as_service_and_name() {
        let service = Service::Container(Container {
            name: "shop-web-1".to_string(),
            compose_service: Some("web".to_string()),
        });
        assert_eq!(service.to_string(), "web (container shop-web-1)");
    }

    #[test]
    fn displays_a_plain_container_by_name() {
        let service = Service::Container(Container {
            name: "metrics".to_string(),
            compose_service: None,
        });
        assert_eq!(service.to_string(), "container metrics");
    }

    #[test]
    fn displays_why_an_owner_is_unknown() {
        assert_eq!(
            Service::Unknown {
                reason: UnknownReason::NeedsRoot
            }
            .to_string(),
            "unknown (run with sudo for details)"
        );
        assert_eq!(
            Service::Unknown {
                reason: UnknownReason::NoProcess
            }
            .to_string(),
            "unknown"
        );
    }

    #[test]
    fn finds_the_owner_by_inode() {
        let owners = HashMap::from([(200, process(2, "nginx")), (100, process(1, "sshd"))]);

        assert_eq!(
            service_of(100, &owners, UnknownReason::NoProcess),
            Service::Process(process(1, "sshd"))
        );
        assert_eq!(
            service_of(200, &owners, UnknownReason::NoProcess),
            Service::Process(process(2, "nginx"))
        );
    }

    #[test]
    fn a_socket_without_an_owner_gets_the_given_reason() {
        assert_eq!(
            service_of(300, &HashMap::new(), UnknownReason::NeedsRoot),
            Service::Unknown {
                reason: UnknownReason::NeedsRoot
            }
        );
    }
}
