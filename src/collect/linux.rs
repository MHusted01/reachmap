//! Linux sources: the kernel's socket tables in `/proc`, the interface
//! list from iproute2's `ip` and the containers from `docker`. The first two
//! need no root; every user sees all sockets and interfaces of the current
//! network namespace. The open files of other users' processes, under
//! `/proc/<pid>/fd`, do need root, and with `hidepid` those processes are not
//! listed at all without it. `docker` needs access to its socket.

use std::path::PathBuf;
use std::time::Duration;

use super::TableSource;
use crate::socket::{AddressFamily, Protocol};

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

/// UFW's configuration file.
pub(super) const UFW_CONF: &str = "/etc/ufw/ufw.conf";

/// Where distributions install `iptables`, tried in order. Only root can write
/// to these directories.
pub(super) const IPTABLES_PATHS: &[&str] = &[
    "/usr/sbin/iptables",
    "/sbin/iptables",
    "/usr/bin/iptables",
    "/bin/iptables",
];

/// The name to look up through `PATH` when `iptables` is in none of
/// [`IPTABLES_PATHS`].
pub(super) const IPTABLES_PROGRAM: &str = "iptables";

/// Makes `iptables` print the rules of the `DOCKER-USER` chain, waiting up to
/// two seconds if another program holds its lock.
pub(super) const IPTABLES_ARGS: &[&str] = &["-w", "2", "-S", "DOCKER-USER"];

/// How long a command may run. All of them answer in well under a second on a
/// healthy host; a hung Docker daemon must not hang the scan.
pub(super) const COMMAND_TIMEOUT: Duration = Duration::from_secs(5);

/// The tables of each protocol: `/proc/net/tcp` and `/proc/net/udp` (required),
/// `/proc/net/tcp6` and `/proc/net/udp6`. The IPv6 tables are optional: they do
/// not exist when IPv6 is disabled in the kernel, which means there are no IPv6
/// sockets. They are also absent when `/proc/net` is not mounted, but then the
/// IPv4 tables are missing too and reading fails.
pub(super) fn socket_sources() -> [TableSource; 4] {
    [
        table(Protocol::Tcp, AddressFamily::Ipv4, "/proc/net/tcp"),
        table(Protocol::Tcp, AddressFamily::Ipv6, "/proc/net/tcp6"),
        table(Protocol::Udp, AddressFamily::Ipv4, "/proc/net/udp"),
        table(Protocol::Udp, AddressFamily::Ipv6, "/proc/net/udp6"),
    ]
}

/// One table. Only the IPv6 tables may be missing.
fn table(protocol: Protocol, family: AddressFamily, path: &str) -> TableSource {
    TableSource {
        family,
        protocol,
        path: PathBuf::from(path),
        optional: family == AddressFamily::Ipv6,
    }
}
