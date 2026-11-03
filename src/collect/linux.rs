//! Linux collector: reads the kernel's TCP socket tables from `/proc`.
//! Reading them needs no root; every user can see all sockets in the
//! current network namespace.

use std::fs;
use std::io::ErrorKind;

use crate::scan::{RawTable, ScanError};
use crate::socket::Protocol;

const TCP_TABLES: [(Protocol, &str); 2] = [
    (Protocol::Tcp, "/proc/net/tcp"),
    (Protocol::Tcp6, "/proc/net/tcp6"),
];

/// Reads `/proc/net/tcp` and `/proc/net/tcp6`.
///
/// When IPv6 is disabled in the kernel, `/proc/net/tcp6` does not exist. That
/// is not missing data: it means there are no IPv6 sockets, so the table is skipped.
pub fn read_tcp_tables() -> Result<Vec<RawTable>, ScanError> {
    let mut tables = Vec::new();
    for (protocol, path) in TCP_TABLES {
        match fs::read_to_string(path) {
            Ok(text) => tables.push(RawTable {
                protocol,
                path,
                text,
            }),
            Err(error) if protocol == Protocol::Tcp6 && error.kind() == ErrorKind::NotFound => {}
            Err(source) => return Err(ScanError::Read { path, source }),
        }
    }
    Ok(tables)
}
