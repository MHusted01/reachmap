//! Collectors: the only code that reads from the running system. They gather
//! raw text and hand it to the pure parsers in [`crate::parse`].

// Only the Linux collectors run commands so far; tests run it everywhere.
#[cfg(any(target_os = "linux", test))]
mod command;
#[cfg(target_os = "linux")]
mod linux;
mod processes;
#[cfg(target_os = "linux")]
mod sock_diag;
#[cfg(test)]
mod test_support;

use std::fs;
use std::io::{self, ErrorKind};
use std::path::PathBuf;
use std::process::ExitStatus;
use std::string::FromUtf8Error;
use std::time::Duration;

pub use processes::{ProcessFds, RawProcess, processes_may_be_hidden, read_process_fds};

use thiserror::Error;

use crate::socket::AddressFamily;

/// A kernel table to read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableSource {
    /// IP version of the sockets in the table.
    pub family: AddressFamily,
    /// File to read.
    pub path: PathBuf,
    /// When true, a missing file means "no sockets of this kind" instead of
    /// an error (e.g. `/proc/net/tcp6` on a kernel without IPv6).
    pub optional: bool,
}

/// The raw text of one kernel table, as read from disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawTable {
    /// IP version of the sockets in the table.
    pub family: AddressFamily,
    /// Where the text came from, used in error messages.
    pub path: PathBuf,
    /// The file's content.
    pub text: String,
}

/// Why the system could not be read.
#[derive(Debug, Error)]
pub enum CollectError {
    /// A table file exists but could not be read, or a required one is missing.
    #[error("could not read {}", path.display())]
    Read {
        /// The file that failed.
        path: PathBuf,
        /// The operating system's reason.
        #[source]
        source: io::Error,
    },
    /// This operating system has no collector yet.
    #[error("reachmap scan is Linux only for now (this system is {os})")]
    UnsupportedOs {
        /// Value of `std::env::consts::OS`, e.g. `macos`.
        os: &'static str,
    },
    /// The kernel's socket diagnostics could not be used.
    #[error("could not {action} the kernel's socket diagnostics")]
    SockDiag {
        /// What failed: `open`, `query` or `read`.
        action: &'static str,
        /// The operating system's reason.
        #[source]
        source: io::Error,
    },
    /// A command could not be started, e.g. because it is not installed.
    #[error("could not run `{command}`")]
    Run {
        /// The command line, e.g. `ip -j addr`.
        command: String,
        /// The operating system's reason.
        #[source]
        source: io::Error,
    },
    /// A command ran but reported failure.
    #[error("`{command}` failed with {status}{}", detail(stderr))]
    CommandFailed {
        /// The command line.
        command: String,
        /// How it exited.
        status: ExitStatus,
        /// What it printed to standard error, trimmed and sanitised; may be
        /// empty.
        stderr: String,
    },
    /// A command was still running when its time was up.
    #[error("`{command}` did not finish within {timeout:?}")]
    TimedOut {
        /// The command line.
        command: String,
        /// How long it was given.
        timeout: Duration,
    },
    /// A command printed something that is not UTF-8 text.
    #[error("`{command}` printed text that is not UTF-8")]
    NotUtf8 {
        /// The command line.
        command: String,
        /// Where the invalid bytes start.
        #[source]
        source: FromUtf8Error,
    },
}

/// A way to exchange datagrams with the kernel's socket diagnostics. A trait,
/// so the code that reads a reply is tested on any OS.
pub trait SockDiagChannel {
    /// Sends one request.
    fn send(&self, request: &[u8]) -> Result<(), CollectError>;
    /// Reads one datagram into `buffer` and returns its length.
    fn receive(&self, buffer: &mut [u8]) -> Result<usize, CollectError>;
}

/// `": message"`, or nothing when the command printed no message.
fn detail(stderr: &str) -> String {
    if stderr.is_empty() {
        String::new()
    } else {
        format!(": {stderr}")
    }
}

/// Reads this host's TCP tables: `/proc/net/tcp` and, when IPv6 is enabled,
/// `/proc/net/tcp6`.
#[cfg(target_os = "linux")]
pub fn read_tcp_tables() -> Result<Vec<RawTable>, CollectError> {
    read_tables(&linux::tcp_sources())
}

/// Reads this host's TCP tables. Only Linux is supported for now.
#[cfg(not(target_os = "linux"))]
pub fn read_tcp_tables() -> Result<Vec<RawTable>, CollectError> {
    Err(CollectError::UnsupportedOs {
        os: std::env::consts::OS,
    })
}

/// Lists the open files of every process on this host, from `/proc`, and
/// notes whether `/proc` may leave some processes out.
#[cfg(target_os = "linux")]
pub fn read_open_files() -> Result<ProcessFds, CollectError> {
    let proc_root = std::path::Path::new(linux::PROC_ROOT);
    Ok(ProcessFds {
        processes_may_be_hidden: processes_may_be_hidden(proc_root),
        ..read_process_fds(proc_root)?
    })
}

/// Lists the open files of every process. Only Linux is supported for now.
#[cfg(not(target_os = "linux"))]
pub fn read_open_files() -> Result<ProcessFds, CollectError> {
    Err(CollectError::UnsupportedOs {
        os: std::env::consts::OS,
    })
}

/// Opens a channel to the kernel's socket diagnostics. Needs no root.
#[cfg(target_os = "linux")]
pub fn open_sock_diag() -> Result<Box<dyn SockDiagChannel>, CollectError> {
    sock_diag::open()
}

/// Opens a channel to the socket diagnostics. Only Linux has them.
#[cfg(not(target_os = "linux"))]
pub fn open_sock_diag() -> Result<Box<dyn SockDiagChannel>, CollectError> {
    Err(CollectError::UnsupportedOs {
        os: std::env::consts::OS,
    })
}

/// Lists this host's interfaces and their addresses: the JSON that
/// `ip -j addr` prints. Needs no root.
#[cfg(target_os = "linux")]
pub fn read_interfaces() -> Result<String, CollectError> {
    let program = command::locate(linux::IP_PATHS, linux::IP_PROGRAM);
    command::run(program, linux::IP_ADDR_ARGS, linux::COMMAND_TIMEOUT)
}

/// Lists this host's interfaces. Only Linux is supported for now.
#[cfg(not(target_os = "linux"))]
pub fn read_interfaces() -> Result<String, CollectError> {
    Err(CollectError::UnsupportedOs {
        os: std::env::consts::OS,
    })
}

/// Lists the IDs of the running containers: what `docker ps -q` prints.
#[cfg(target_os = "linux")]
pub fn list_containers() -> Result<String, CollectError> {
    let program = command::locate(linux::DOCKER_PATHS, linux::DOCKER_PROGRAM);
    command::run(program, linux::DOCKER_PS_ARGS, linux::COMMAND_TIMEOUT)
}

/// Lists the running containers. Only Linux is supported for now.
#[cfg(not(target_os = "linux"))]
pub fn list_containers() -> Result<String, CollectError> {
    Err(CollectError::UnsupportedOs {
        os: std::env::consts::OS,
    })
}

/// Describes the containers with these IDs: the JSON `docker inspect` prints.
#[cfg(target_os = "linux")]
pub fn inspect_containers(ids: &[&str]) -> Result<String, CollectError> {
    let program = command::locate(linux::DOCKER_PATHS, linux::DOCKER_PROGRAM);
    let args = [linux::DOCKER_INSPECT_ARGS, ids].concat();
    command::run(program, &args, linux::COMMAND_TIMEOUT)
}

/// Describes containers. Only Linux is supported for now.
#[cfg(not(target_os = "linux"))]
pub fn inspect_containers(_ids: &[&str]) -> Result<String, CollectError> {
    Err(CollectError::UnsupportedOs {
        os: std::env::consts::OS,
    })
}

/// Reads UFW's configuration file. Every user can read it on a default
/// install.
#[cfg(target_os = "linux")]
pub fn read_ufw_conf() -> Result<String, CollectError> {
    fs::read_to_string(linux::UFW_CONF).map_err(|source| CollectError::Read {
        path: PathBuf::from(linux::UFW_CONF),
        source,
    })
}

/// Reads UFW's configuration file. Only Linux is supported for now.
#[cfg(not(target_os = "linux"))]
pub fn read_ufw_conf() -> Result<String, CollectError> {
    Err(CollectError::UnsupportedOs {
        os: std::env::consts::OS,
    })
}

/// Lists the rules of the `DOCKER-USER` chain: what `iptables -S` prints for
/// it. Needs root.
#[cfg(target_os = "linux")]
pub fn read_docker_user_rules() -> Result<String, CollectError> {
    let program = command::locate(linux::IPTABLES_PATHS, linux::IPTABLES_PROGRAM);
    command::run(program, linux::IPTABLES_ARGS, linux::COMMAND_TIMEOUT)
}

/// Lists the `DOCKER-USER` rules. Only Linux is supported for now.
#[cfg(not(target_os = "linux"))]
pub fn read_docker_user_rules() -> Result<String, CollectError> {
    Err(CollectError::UnsupportedOs {
        os: std::env::consts::OS,
    })
}

/// Reads each source in order, skipping optional sources that do not exist.
pub fn read_tables(sources: &[TableSource]) -> Result<Vec<RawTable>, CollectError> {
    let mut tables = Vec::with_capacity(sources.len());
    for source in sources {
        match fs::read_to_string(&source.path) {
            Ok(text) => tables.push(RawTable {
                family: source.family,
                path: source.path.clone(),
                text,
            }),
            Err(error) if source.optional && error.kind() == ErrorKind::NotFound => {}
            Err(error) => {
                return Err(CollectError::Read {
                    path: source.path.clone(),
                    source: error,
                });
            }
        }
    }
    Ok(tables)
}

#[cfg(test)]
mod tests {
    use super::test_support::TempDir;
    use super::*;
    use crate::errors::render_chain;
    use std::path::Path;

    fn source(family: AddressFamily, path: &Path, optional: bool) -> TableSource {
        TableSource {
            family,
            path: path.to_path_buf(),
            optional,
        }
    }

    #[test]
    fn reads_every_source_in_order() {
        let dir = TempDir::new("in-order");
        let tcp = dir.file("tcp", "four");
        let tcp6 = dir.file("tcp6", "six");

        let tables = read_tables(&[
            source(AddressFamily::Ipv4, &tcp, false),
            source(AddressFamily::Ipv6, &tcp6, true),
        ])
        .unwrap();

        assert_eq!(
            tables,
            vec![
                RawTable {
                    family: AddressFamily::Ipv4,
                    path: tcp,
                    text: "four".to_string()
                },
                RawTable {
                    family: AddressFamily::Ipv6,
                    path: tcp6,
                    text: "six".to_string()
                },
            ]
        );
    }

    #[test]
    fn a_missing_optional_source_is_skipped() {
        let dir = TempDir::new("optional");
        let tcp = dir.file("tcp", "four");
        let missing = dir.path().join("tcp6");

        let tables = read_tables(&[
            source(AddressFamily::Ipv4, &tcp, false),
            source(AddressFamily::Ipv6, &missing, true),
        ])
        .unwrap();

        assert_eq!(tables.len(), 1);
        assert_eq!(tables[0].family, AddressFamily::Ipv4);
    }

    #[test]
    fn a_missing_required_source_is_an_error_naming_the_file() {
        let dir = TempDir::new("required");
        let missing = dir.path().join("tcp");

        let error = read_tables(&[source(AddressFamily::Ipv4, &missing, false)]).unwrap_err();

        assert!(matches!(error, CollectError::Read { .. }));
        assert!(
            render_chain(&error).starts_with(&format!("could not read {}: ", missing.display())),
            "got: {}",
            render_chain(&error)
        );
    }

    #[test]
    fn errors_other_than_not_found_fail_even_for_optional_sources() {
        // Reading a directory as a file fails with an error that is not NotFound.
        let dir = TempDir::new("not-a-file");

        let result = read_tables(&[source(AddressFamily::Ipv6, dir.path(), true)]);

        assert!(matches!(result, Err(CollectError::Read { .. })));
    }
}
