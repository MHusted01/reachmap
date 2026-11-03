//! Collectors: the only code that reads from the running system. They gather
//! raw text and hand it to the pure parsers in `crate::parse`.

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "linux")]
pub use linux::read_tcp_tables;

#[cfg(not(target_os = "linux"))]
use crate::scan::{RawTable, ScanError};

/// On systems other than Linux there is no `/proc/net/tcp` to read yet.
#[cfg(not(target_os = "linux"))]
pub fn read_tcp_tables() -> Result<Vec<RawTable>, ScanError> {
    Err(ScanError::UnsupportedOs {
        os: std::env::consts::OS,
    })
}
