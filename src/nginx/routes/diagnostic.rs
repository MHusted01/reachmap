//! Secret-safe diagnostics and error classification for Nginx route collection.

use std::fmt;
use std::io::ErrorKind;

use serde::{Deserialize, Serialize};

use super::NginxScanError;
use crate::collect::CollectError;
use crate::local_tcp::SocketFailure;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(super) enum Note {
    SocketInventoryUnavailable { reason: SocketFailure },
    SocketOptionsIncomplete { reason: SocketFailure },
}

impl fmt::Display for Note {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SocketInventoryUnavailable { reason } => {
                write!(f, "TCP socket inventory unavailable ({reason})")
            }
            Self::SocketOptionsIncomplete { reason } => {
                write!(f, "TCP socket options incomplete ({reason})")
            }
        }
    }
}

/// Convert a collector error into a secret-safe [`NginxScanError`].
///
/// Raw `stderr` from `nginx -V` is never embedded in error messages, so no
/// unexpected output can leak into reports.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(super) fn classify_nginx_error(error: CollectError) -> NginxScanError {
    match error {
        CollectError::UnsupportedOs { os } => NginxScanError::UnsupportedOs { os },
        CollectError::Run { source, .. } if source.kind() == ErrorKind::NotFound => {
            NginxScanError::MissingCommand
        }
        CollectError::Run { source, .. } if source.kind() == ErrorKind::PermissionDenied => {
            NginxScanError::PermissionDenied
        }
        CollectError::Run { source, .. } => NginxScanError::RunFailed {
            kind: source.kind().to_string(),
        },
        CollectError::OutputTooLarge {
            stream,
            limit_bytes,
            ..
        } => NginxScanError::OutputTooLarge {
            stream,
            limit_bytes,
        },
        CollectError::CommandFailed { status, stderr, .. } => {
            let lower = stderr.to_ascii_lowercase();
            if lower.contains("permission denied") || lower.contains("failed (13:") {
                NginxScanError::PermissionDenied
            } else {
                NginxScanError::CommandFailed {
                    exit_code: status.code(),
                }
            }
        }
        CollectError::TimedOut { timeout, .. } => NginxScanError::TimedOut { timeout },
        CollectError::NotUtf8 { .. } => NginxScanError::NotUtf8,
        CollectError::Read { .. } | CollectError::SockDiag { .. } => NginxScanError::RunFailed {
            kind: "unexpected collector error".to_owned(),
        },
    }
}
