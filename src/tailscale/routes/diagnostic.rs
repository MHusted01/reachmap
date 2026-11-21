//! Collection diagnostics that can be saved without raw kernel errors.

use std::fmt;
use std::io::{self, ErrorKind};

use serde::{Deserialize, Serialize};

use crate::collect::CollectError;
use crate::parse::sock_diag::SockDiagError;
use crate::sanitize::sanitize;
use crate::scan::ScanError;
use crate::socket_options::SocketOptionsError;

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(super) enum Note {
    RouteStatus { detail: String },
    SocketInventoryUnavailable { reason: SocketFailure },
    SocketOptionsIncomplete { reason: SocketFailure },
}

impl fmt::Display for Note {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RouteStatus { detail } => f.write_str(&sanitize(detail)),
            Self::SocketInventoryUnavailable { reason } => {
                write!(f, "TCP socket inventory unavailable ({reason})")
            }
            Self::SocketOptionsIncomplete { reason } => {
                write!(f, "TCP socket options incomplete ({reason})")
            }
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum SocketFailure {
    PermissionDenied,
    Unsupported,
    MissingLinuxData,
    InvalidKernelData,
    ReadFailed,
}

impl From<&ScanError> for SocketFailure {
    fn from(error: &ScanError) -> Self {
        match error {
            ScanError::Collect(source) => source.into(),
            ScanError::UnsupportedOs { .. } => Self::Unsupported,
            ScanError::Parse { .. } | ScanError::SocketInventory { .. } => Self::InvalidKernelData,
        }
    }
}

impl From<&SocketOptionsError> for SocketFailure {
    fn from(error: &SocketOptionsError) -> Self {
        match error {
            SocketOptionsError::Open(source) | SocketOptionsError::Collect { source, .. } => {
                source.into()
            }
            SocketOptionsError::Reply {
                source: SockDiagError::Refused(source),
                ..
            } => source.into(),
            SocketOptionsError::Reply {
                source: SockDiagError::Malformed,
                ..
            } => Self::InvalidKernelData,
        }
    }
}

impl From<&CollectError> for SocketFailure {
    fn from(error: &CollectError) -> Self {
        match error {
            CollectError::Read { source, .. } | CollectError::SockDiag { source, .. } => {
                source.into()
            }
            CollectError::UnsupportedOs { .. } => Self::Unsupported,
            _ => Self::ReadFailed,
        }
    }
}

impl From<&io::Error> for SocketFailure {
    fn from(error: &io::Error) -> Self {
        match error.kind() {
            ErrorKind::PermissionDenied => Self::PermissionDenied,
            ErrorKind::NotFound => Self::MissingLinuxData,
            ErrorKind::Unsupported => Self::Unsupported,
            ErrorKind::InvalidData => Self::InvalidKernelData,
            _ => Self::ReadFailed,
        }
    }
}

impl fmt::Display for SocketFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::PermissionDenied => "permission denied; check access to the Linux socket data",
            Self::Unsupported => "the required Linux collector is unavailable",
            Self::MissingLinuxData => {
                "required Linux socket data is missing; check the procfs mount and kernel support"
            }
            Self::InvalidKernelData => "unrecognized Linux socket data; report the kernel version",
            Self::ReadFailed => "Linux socket data could not be read; retry the scan on the host",
        })
    }
}
