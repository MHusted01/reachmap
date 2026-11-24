//! Why Caddy route status could not be collected, and the conversion from
//! collector failures that drops everything Caddy printed.

use std::io::{self, ErrorKind};
use std::time::Duration;

use thiserror::Error;

use crate::caddy::CaddyParseError;
use crate::collect::CollectError;
use crate::sanitize::sanitize;

/// Why Caddy route status could not be collected or parsed. None of these
/// means that no routes exist.
#[derive(Debug, Error)]
pub enum CaddyScanError {
    /// No `caddy` binary is installed at a fixed system path.
    #[error(
        "Caddy route status is unavailable because `caddy` was not found in /usr/bin, /usr/local/bin or /bin; pass a native JSON config ending in .json with --caddy-config instead"
    )]
    MissingCommand,
    /// The `caddy` binary is not owned by root or is writable by others.
    #[error("refusing to run {path}: it must be owned by root and not writable by group or others")]
    UntrustedCommand {
        /// Sanitized path of the binary.
        path: String,
    },
    /// The configuration file does not exist.
    #[error("Caddy configuration file {path} was not found; name it with --caddy-config")]
    ConfigNotFound {
        /// Sanitized path of the configuration file.
        path: String,
    },
    /// Reading the configuration, or a file it imports, was denied.
    #[error(
        "could not read Caddy configuration (permission denied); retry with privileges to read Caddy config files (e.g. sudo)"
    )]
    PermissionDenied,
    /// The configuration path is not a regular file that is safe to read.
    #[error("could not read Caddy configuration file {path} ({reason})")]
    UnreadableFile {
        /// Sanitized path that was refused.
        path: String,
        /// Why it was refused.
        reason: &'static str,
    },
    /// Reading the configuration file failed.
    #[error("could not read Caddy configuration file {path} ({kind})")]
    ReadFailed {
        /// Sanitized path that failed.
        path: String,
        /// Sanitized I/O error kind description.
        kind: String,
    },
    /// The configuration file is larger than the parser accepts.
    #[error("Caddy configuration file exceeds the {limit_bytes}-byte input limit")]
    ConfigTooLarge {
        /// Maximum accepted size in bytes.
        limit_bytes: usize,
    },
    /// The configuration file is not UTF-8 text.
    #[error("Caddy configuration file {path} is not UTF-8 text")]
    ConfigNotUtf8 {
        /// Sanitized path of the configuration file.
        path: String,
    },
    /// `caddy adapt` exited with a failure status; what it printed is omitted.
    #[error(
        "`caddy adapt` could not adapt the Caddyfile{}; run `caddy adapt` yourself to see why (its output is omitted here because it can quote configuration)",
        format_exit_code(*.exit_code)
    )]
    AdaptFailed {
        /// Process exit code, when available.
        exit_code: Option<i32>,
    },
    /// `caddy adapt` did not finish in time.
    #[error("`caddy adapt` did not finish within {timeout:?}")]
    TimedOut {
        /// Timeout enforced by the collector.
        timeout: Duration,
    },
    /// `caddy adapt` printed more than its bounded limit.
    #[error("`caddy adapt` {stream} output exceeded the {limit_bytes}-byte safety limit")]
    OutputTooLarge {
        /// Which stream overflowed (`"stdout"` or `"stderr"`).
        stream: &'static str,
        /// Maximum accepted output length in bytes for that stream.
        limit_bytes: u64,
    },
    /// `caddy adapt` printed output that is not UTF-8.
    #[error("`caddy adapt` printed output that is not valid UTF-8")]
    NotUtf8,
    /// Starting or reading `caddy adapt` failed.
    #[error("could not run `caddy adapt` ({kind})")]
    RunFailed {
        /// Sanitized I/O error kind description.
        kind: String,
    },
    /// Caddy route collection requires Linux.
    #[error(
        "Caddy route collection requires Linux (unavailable on {os}); replay a captured snapshot instead"
    )]
    UnsupportedOs {
        /// Current operating system identifier.
        os: &'static str,
    },
    /// The JSON configuration could not be parsed.
    #[error("could not parse Caddy configuration")]
    Parse(#[from] CaddyParseError),
}

fn format_exit_code(code: Option<i32>) -> String {
    code.map_or_else(String::new, |code| format!(" (exit code {code})"))
}

/// Converts a failure of `caddy adapt` into a [`CaddyScanError`]. Standard
/// error is only searched for a permission problem and then dropped: Caddy's
/// adapter errors quote the offending configuration line.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(super) fn classify_adapt_error(error: CollectError) -> CaddyScanError {
    match error {
        CollectError::UnsupportedOs { os } => CaddyScanError::UnsupportedOs { os },
        CollectError::Run { source, .. } if source.kind() == ErrorKind::NotFound => {
            CaddyScanError::MissingCommand
        }
        CollectError::Run { source, .. } => CaddyScanError::RunFailed {
            kind: source.kind().to_string(),
        },
        CollectError::CommandFailed { status, stderr, .. } => {
            if stderr.to_ascii_lowercase().contains("permission denied") {
                CaddyScanError::PermissionDenied
            } else {
                CaddyScanError::AdaptFailed {
                    exit_code: status.code(),
                }
            }
        }
        CollectError::TimedOut { timeout, .. } => CaddyScanError::TimedOut { timeout },
        CollectError::OutputTooLarge {
            stream,
            limit_bytes,
            ..
        } => CaddyScanError::OutputTooLarge {
            stream,
            limit_bytes,
        },
        CollectError::NotUtf8 { .. } => CaddyScanError::NotUtf8,
        CollectError::Read { .. } | CollectError::SockDiag { .. } => CaddyScanError::RunFailed {
            kind: "unexpected collector error".to_owned(),
        },
    }
}

/// Converts a failed read of the configuration file at `path`.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(super) fn classify_read_error(path: &str, error: &io::Error) -> CaddyScanError {
    match error.kind() {
        ErrorKind::PermissionDenied => CaddyScanError::PermissionDenied,
        ErrorKind::NotFound => CaddyScanError::ConfigNotFound {
            path: sanitize(path),
        },
        kind => CaddyScanError::ReadFailed {
            path: sanitize(path),
            kind: kind.to_string(),
        },
    }
}
