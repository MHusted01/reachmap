//! Finding a `caddy` binary that only root can have put in place.

use std::path::Path;

use super::error::CaddyScanError;
use crate::sanitize::sanitize;

/// Paths tried in order. `PATH` is never searched: under `sudo` a directory
/// early in it could supply its own `caddy`.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(super) const CADDY_PATHS: [&str; 3] = ["/usr/bin/caddy", "/usr/local/bin/caddy", "/bin/caddy"];

/// What is at a candidate path for the `caddy` binary.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Program {
    /// No file.
    Missing,
    /// A file only root can replace, at this symlink-free path.
    Trusted(String),
    /// A file that fails that check.
    Untrusted,
}

/// The symlink-free path of the first candidate that exists, when it is
/// safe to run.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(super) fn locate(
    candidates: &[&str],
    inspect: impl Fn(&str) -> Program,
) -> Result<String, CaddyScanError> {
    for &path in candidates {
        match inspect(path) {
            Program::Missing => {}
            Program::Trusted(resolved) => return Ok(resolved),
            Program::Untrusted => {
                return Err(CaddyScanError::UntrustedCommand {
                    path: sanitize(path),
                });
            }
        }
    }
    Err(CaddyScanError::MissingCommand)
}

/// Whether `path` and every directory above it are owned by root and not
/// writable by group or others, so no other user can replace the file.
/// `owner_mode` gives a path's owner and mode, or `None` when unknown.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(super) fn only_root_can_replace(
    path: &Path,
    owner_mode: impl Fn(&Path) -> Option<(u32, u32)>,
) -> bool {
    path.is_absolute()
        && path
            .ancestors()
            .all(|part| owner_mode(part).is_some_and(|(uid, mode)| uid == 0 && mode & 0o022 == 0))
}

/// Resolves every symlink first, so a packaged `/usr/bin/caddy` link to an
/// alternatives target is judged, and later run, by the file it points to.
#[cfg(target_os = "linux")]
pub(super) fn inspect_program(path: &str) -> Program {
    use std::io::ErrorKind;
    use std::os::unix::fs::MetadataExt;

    let resolved = match std::fs::canonicalize(path) {
        Ok(resolved) => resolved,
        Err(error) if error.kind() == ErrorKind::NotFound => return Program::Missing,
        Err(_) => return Program::Untrusted,
    };
    if !resolved.is_file() {
        return Program::Missing;
    }
    let owner_mode = |part: &Path| {
        std::fs::metadata(part)
            .ok()
            .map(|metadata| (metadata.uid(), metadata.mode()))
    };
    match resolved.to_str() {
        Some(text) if only_root_can_replace(&resolved, owner_mode) => {
            Program::Trusted(text.to_owned())
        }
        _ => Program::Untrusted,
    }
}
