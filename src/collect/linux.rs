//! Linux sources: the kernel's TCP socket tables in `/proc`. Reading them
//! needs no root; every user sees all sockets of the current network namespace.
//! The open files of other users' processes, under `/proc/<pid>/fd`, do need root.

use std::path::PathBuf;

use super::TableSource;
use crate::socket::AddressFamily;

// The `/proc/net/tcp` parser decodes addresses as little-endian words, which
// is how the kernel prints them on little-endian hosts. Refuse to build
// rather than report wrong addresses on a big-endian one.
#[cfg(target_endian = "big")]
compile_error!("reachmap's /proc/net/tcp parser assumes a little-endian host");

/// Where the kernel lists one folder per process.
pub(super) const PROC_ROOT: &str = "/proc";

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
