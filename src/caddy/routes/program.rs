//! Finding a `caddy` binary that only root can have put in place.

use std::path::{Component, Path, PathBuf};

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

/// Most symlinks followed while resolving the `caddy` path, as the kernel's
/// own limit.
const MAX_SYMLINKS: usize = 40;

/// What `lstat` reports for one path, without following a final symlink.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Entry {
    /// Owner user ID.
    pub(super) uid: u32,
    /// Permission bits.
    pub(super) mode: u32,
    /// The link's target, when the entry is a symlink.
    pub(super) link: Option<PathBuf>,
}

/// Resolves `path` one component at a time, the way the kernel does, and
/// returns the symlink-free path only if no user but root can change where
/// it leads: every directory traversed and the final file are owned by root
/// and not writable by group or others, and every symlink on the way is
/// owned by root (a symlink's own mode bits mean nothing on Linux).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(super) fn resolve_trusted(
    path: &Path,
    lookup: &impl Fn(&Path) -> Option<Entry>,
) -> Option<PathBuf> {
    let mut budget = MAX_SYMLINKS;
    resolve(path, lookup, &mut budget)
}

fn resolve(
    path: &Path,
    lookup: &impl Fn(&Path) -> Option<Entry>,
    budget: &mut usize,
) -> Option<PathBuf> {
    if !path.is_absolute() {
        return None;
    }
    let root = PathBuf::from("/");
    trusted_entry(&lookup(&root)?)?;
    let mut resolved = root;
    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::ParentDir => {
                resolved.pop();
            }
            Component::Prefix(_) => return None,
            Component::Normal(name) => {
                let next = resolved.join(name);
                let entry = lookup(&next)?;
                if entry.uid != 0 {
                    return None;
                }
                match entry.link {
                    Some(target) => {
                        *budget = budget.checked_sub(1)?;
                        resolved = resolve(&resolved.join(target), lookup, budget)?;
                    }
                    None => {
                        trusted_entry(&entry)?;
                        resolved = next;
                    }
                }
            }
        }
    }
    Some(resolved)
}

/// A file or directory owned by root that group and others cannot write.
fn trusted_entry(entry: &Entry) -> Option<()> {
    (entry.uid == 0 && entry.mode & 0o022 == 0).then_some(())
}

/// Checks the whole way to the binary, then runs it by its resolved path so
/// nothing can be swapped in between.
#[cfg(target_os = "linux")]
pub(super) fn inspect_program(path: &str) -> Program {
    use std::os::unix::fs::MetadataExt;

    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Program::Missing,
        Err(_) => return Program::Untrusted,
        Ok(_) => {}
    }
    let lookup = |part: &Path| {
        let metadata = std::fs::symlink_metadata(part).ok()?;
        let link = if metadata.file_type().is_symlink() {
            Some(std::fs::read_link(part).ok()?)
        } else {
            None
        };
        Some(Entry {
            uid: metadata.uid(),
            mode: metadata.mode(),
            link,
        })
    };
    let Some(resolved) = resolve_trusted(Path::new(path), &lookup) else {
        return Program::Untrusted;
    };
    match resolved.to_str() {
        Some(text) if resolved.is_file() => Program::Trusted(text.to_owned()),
        Some(_) => Program::Missing,
        None => Program::Untrusted,
    }
}
