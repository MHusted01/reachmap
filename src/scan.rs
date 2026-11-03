//! `reachmap scan`: read the kernel's socket tables and turn them into one
//! sorted list of listening sockets. Data flows one way:
//! [`crate::collect`] reads, [`crate::parse`] decodes, this module joins them.

use std::path::PathBuf;

use thiserror::Error;

use crate::collect::{self, CollectError, RawTable};
use crate::parse::proc_net::{ParseError, parse_proc_net_tcp};
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
            parse_proc_net_tcp(&table.text, table.family).map_err(|source| ScanError::Parse {
                path: table.path.clone(),
                source,
            })?;
        sockets.extend(parsed);
    }
    Ok(sort_by_port(sockets))
}
