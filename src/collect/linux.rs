//! Linux sources: the kernel's TCP socket tables in `/proc`, the interface
//! list from iproute2's `ip` and the containers from `docker`. The first two
//! need no root; every user sees all sockets and interfaces of the current
//! network namespace. The open files of other users' processes, under
//! `/proc/<pid>/fd`, do need root, and `docker` needs access to its socket.

use std::path::PathBuf;
use std::time::Duration;

use super::TableSource;
use crate::socket::AddressFamily;

// The `/proc/net/tcp` parser decodes addresses as little-endian words, which
// is how the kernel prints them on little-endian hosts. Refuse to build
// rather than report wrong addresses on a big-endian one.
#[cfg(target_endian = "big")]
compile_error!("reachmap's /proc/net/tcp parser assumes a little-endian host");

/// Where the kernel lists one folder per process.
pub(super) const PROC_ROOT: &str = "/proc";

/// Where distributions install iproute2's `ip`, tried in order. Only root can
/// write to these directories.
pub(super) const IP_PATHS: &[&str] = &["/usr/sbin/ip", "/usr/bin/ip", "/sbin/ip", "/bin/ip"];

/// The name to look up through `PATH` when `ip` is in none of [`IP_PATHS`].
pub(super) const IP_PROGRAM: &str = "ip";

/// Makes `ip` print every interface with its addresses as JSON.
pub(super) const IP_ADDR_ARGS: &[&str] = &["-j", "addr"];

/// Where Docker's command-line client is installed, tried in order. Only root
/// can write to these directories.
pub(super) const DOCKER_PATHS: &[&str] = &[
    "/usr/bin/docker",
    "/usr/local/bin/docker",
    "/bin/docker",
    "/snap/bin/docker",
];

/// The name to look up through `PATH` when `docker` is in none of
/// [`DOCKER_PATHS`].
pub(super) const DOCKER_PROGRAM: &str = "docker";

/// Makes `docker` print the IDs of the running containers.
pub(super) const DOCKER_PS_ARGS: &[&str] = &["ps", "-q"];

/// Makes `docker` print details of the containers named after these arguments.
pub(super) const DOCKER_INSPECT_ARGS: &[&str] = &["inspect", "--type", "container"];

/// How long a command may run. All of them answer in well under a second on a
/// healthy host; a hung Docker daemon must not hang the scan.
pub(super) const COMMAND_TIMEOUT: Duration = Duration::from_secs(5);

/// `/proc/net/tcp` (required) and `/proc/net/tcp6`. The IPv6 table is
/// optional: it does not exist when IPv6 is disabled in the kernel, which
/// means there are no IPv6 sockets. It is also absent when `/proc/net` is
/// not mounted, but then `/proc/net/tcp` is missing too and reading fails.
pub(super) fn tcp_sources() -> [TableSource; 2] {
    [
        TableSource {
            family: AddressFamily::Ipv4,
            path: PathBuf::from("/proc/net/tcp"),
            optional: false,
        },
        TableSource {
            family: AddressFamily::Ipv6,
            path: PathBuf::from("/proc/net/tcp6"),
            optional: true,
        },
    ]
}
