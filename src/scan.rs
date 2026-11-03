//! `reachmap scan`: read the kernel's socket tables and turn them into one
//! sorted list of listening sockets.

use thiserror::Error;

use crate::collect;
use crate::parse::proc_net::{ParseError, parse_proc_net_tcp};
use crate::socket::{ListeningSocket, Protocol, sort_by_port};

/// The raw text of one kernel table, as read from disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawTable {
    pub protocol: Protocol,
    /// Where the text came from, used in error messages.
    pub path: &'static str,
    pub text: String,
}

/// Why a scan could not finish. Each variant describes only itself; the
/// underlying cause is reachable through `Error::source`, see `crate::errors`.
#[derive(Debug, Error)]
pub enum ScanError {
    #[error("could not read {path}")]
    Read {
        path: &'static str,
        #[source]
        source: std::io::Error,
    },
    #[error("could not understand {path}")]
    Parse {
        path: &'static str,
        #[source]
        source: ParseError,
    },
    #[error("reachmap scan is Linux only for now (this system is {os})")]
    UnsupportedOs { os: &'static str },
}

/// Reads this host's TCP tables and returns its listening sockets, sorted by port.
pub fn scan() -> Result<Vec<ListeningSocket>, ScanError> {
    let tables = collect::read_tcp_tables()?;
    parse_tables(&tables)
}

/// Parses already-read tables into one list sorted by port. Pure, so it is
/// tested with fixture text on any OS.
pub fn parse_tables(tables: &[RawTable]) -> Result<Vec<ListeningSocket>, ScanError> {
    let mut sockets = Vec::new();
    for table in tables {
        let parsed =
            parse_proc_net_tcp(&table.text, table.protocol).map_err(|source| ScanError::Parse {
                path: table.path,
                source,
            })?;
        sockets.extend(parsed);
    }
    Ok(sort_by_port(sockets))
}
