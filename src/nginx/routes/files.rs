//! Reads the Nginx configuration from disk into the text `nginx -T` would
//! print, without running Nginx: its configuration test can create log files
//! and temp directories, and reachmap never changes the system.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::collections::BTreeSet;
use std::io::{self, ErrorKind};
use std::os::unix::ffi::OsStrExt;

use super::NginxScanError;
use crate::collect::nginx_files::{ConfigFiles, DirList, FileRead};
use crate::parse::nginx::{
    MAX_INPUT_BYTES, include_patterns, is_glob_component, matches_glob_name,
    unescape_glob_component,
};
use crate::sanitize::sanitize;

/// Most configuration files one scan reads, and most paths one glob expands to.
pub(super) const MAX_FILES: usize = 1024;

/// Deepest chain of nested `include`s the walk recurses through to find new
/// files. Each file is read once, so this bounds the walk's recursion, not
/// every include chain: a file first found shallow is not walked again deeper.
pub(super) const MAX_INCLUDE_DEPTH: usize = 32;

/// Most directory entries one `include` pattern may scan while expanding.
pub(super) const MAX_GLOB_ENTRIES: usize = 64 * MAX_FILES;

/// Reads `main` and every file it includes, depth first in include order like
/// `nginx -T`, each once and after a `# configuration file <path>:` line.
///
/// Relative includes resolve against the directory of `main`, `*` and `?`
/// expand like `glob()` in sorted order, and a literal include that does not
/// exist is left for the route parser to report as unresolved.
pub(super) fn read_config(main: &str, files: &impl ConfigFiles) -> Result<String, NginxScanError> {
    let prefix = main.rsplit_once('/').map_or("", |(dir, _)| dir);
    let mut walk = Walk {
        files,
        prefix,
        dump: String::new(),
        seen: BTreeSet::new(),
    };
    if walk.visit(main, 0)? {
        Ok(walk.dump)
    } else {
        Err(NginxScanError::ConfigNotFound {
            path: sanitize(main),
        })
    }
}

struct Walk<'a, F> {
    files: &'a F,
    prefix: &'a str,
    dump: String,
    seen: BTreeSet<String>,
}

impl<F: ConfigFiles> Walk<'_, F> {
    /// Appends `path` and the files it includes. Returns `false` when nothing
    /// exists at `path`.
    fn visit(&mut self, path: &str, depth: usize) -> Result<bool, NginxScanError> {
        if depth > MAX_INCLUDE_DEPTH {
            return Err(NginxScanError::IncludeTooDeep {
                limit: MAX_INCLUDE_DEPTH,
            });
        }
        if !self.seen.insert(path.to_owned()) {
            return Ok(true);
        }
        if self.seen.len() > MAX_FILES {
            return Err(NginxScanError::TooManyFiles { limit: MAX_FILES });
        }
        if path.chars().any(char::is_control) {
            return Err(unreadable(path, "the path has control characters"));
        }
        let Some(text) = self.read(path)? else {
            return Ok(false);
        };
        let start = self.dump.len();
        self.dump.push_str("# configuration file ");
        self.dump.push_str(path);
        self.dump.push_str(":\n");
        self.dump.push_str(&text);
        if !text.ends_with('\n') {
            self.dump.push('\n');
        }
        if self.dump.len() > MAX_INPUT_BYTES {
            return Err(too_large());
        }
        for pattern in include_patterns(&self.dump[start..])? {
            for included in self.expand(&pattern)? {
                self.visit(&included, depth + 1)?;
            }
        }
        Ok(true)
    }

    /// Reads one file within the bytes the dump has left.
    fn read(&self, path: &str) -> Result<Option<String>, NginxScanError> {
        let limit = MAX_INPUT_BYTES.saturating_sub(self.dump.len());
        let limit = u64::try_from(limit).unwrap_or(u64::MAX);
        let bytes = match self.files.read(path, limit) {
            Ok(FileRead::Missing) => return Ok(None),
            Ok(FileRead::NotRegular) => return Err(unreadable(path, "not a regular file")),
            Ok(FileRead::KernelFile) => {
                return Err(unreadable(path, "a file on a kernel pseudo-filesystem"));
            }
            Ok(FileRead::TooLarge) => return Err(too_large()),
            Ok(FileRead::Bytes(bytes)) => bytes,
            Err(error) => return Err(read_error(path, &error)),
        };
        String::from_utf8(bytes)
            .map(Some)
            .map_err(|_| unreadable(path, "not valid UTF-8"))
    }

    /// The paths an `include` pattern names, in the order Nginx reads them.
    fn expand(&self, pattern: &str) -> Result<Vec<String>, NginxScanError> {
        let full = if pattern.starts_with('/') {
            pattern.to_owned()
        } else {
            format!("{}/{pattern}", self.prefix)
        };
        if !is_glob_component(&full) {
            return Ok(vec![full]);
        }
        let mut paths = vec![String::new()];
        let mut budget = MAX_GLOB_ENTRIES;
        // Like `glob()`, return only paths that exist: after the first wildcard,
        // literal components are looked up in their directory too.
        let mut expanding = false;
        for component in full.split('/').skip(1) {
            let glob = is_glob_component(component);
            expanding |= glob;
            let mut next = Vec::new();
            // `glob()` removes escapes from the literal parts of a pattern.
            let literal = unescape_glob_component(component);
            for base in &paths {
                let path = format!("{base}/{literal}");
                if glob {
                    self.extend_matches(base, component, &mut budget, &mut next)?;
                } else if !expanding || self.exists(&path)? {
                    next.push(path);
                }
            }
            paths = next;
        }
        if paths.len() > MAX_FILES {
            return Err(NginxScanError::TooManyFiles { limit: MAX_FILES });
        }
        paths.sort_unstable();
        Ok(paths)
    }

    fn exists(&self, path: &str) -> Result<bool, NginxScanError> {
        self.files
            .exists(path)
            .map_err(|error| read_error(path, &error))
    }

    /// Adds the entries of directory `base` that match `component`, scanning
    /// at most `budget` more entries.
    fn extend_matches(
        &self,
        base: &str,
        component: &str,
        budget: &mut usize,
        paths: &mut Vec<String>,
    ) -> Result<(), NginxScanError> {
        let dir = if base.is_empty() { "/" } else { base };
        let entries = match self.files.list(dir, *budget) {
            Ok(DirList::Entries(entries)) => entries,
            Ok(DirList::TooMany) => {
                return Err(NginxScanError::GlobTooWide {
                    limit: MAX_GLOB_ENTRIES,
                });
            }
            Err(error) => return Err(read_error(dir, &error)),
        };
        *budget -= entries.len();
        for entry in entries {
            if !matches_glob_name(component, entry.as_bytes()) {
                continue;
            }
            // A name that is not UTF-8 cannot be written in the text format;
            // fail rather than drop a file Nginx would include.
            let Some(name) = entry.to_str() else {
                return Err(unreadable(dir, "a matching file name is not valid UTF-8"));
            };
            paths.push(format!("{base}/{name}"));
        }
        Ok(())
    }
}

fn unreadable(path: &str, reason: &'static str) -> NginxScanError {
    NginxScanError::UnreadableFile {
        path: sanitize(path),
        reason,
    }
}

fn too_large() -> NginxScanError {
    NginxScanError::ConfigTooLarge {
        limit_bytes: MAX_INPUT_BYTES,
    }
}

fn read_error(path: &str, error: &io::Error) -> NginxScanError {
    match error.kind() {
        ErrorKind::PermissionDenied => NginxScanError::PermissionDenied,
        kind => NginxScanError::ReadFailed {
            path: sanitize(path),
            kind: kind.to_string(),
        },
    }
}

#[cfg(test)]
mod tests;
