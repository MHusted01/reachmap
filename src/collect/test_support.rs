//! Test helpers for collectors: throwaway directories that stand in for
//! `/proc`.

use std::fs;
use std::path::{Path, PathBuf};

/// A fresh directory per test, removed when the guard is dropped.
pub(super) struct TempDir(PathBuf);

impl TempDir {
    /// Creates an empty directory. `name` must be unique across all tests.
    pub(super) fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!("reachmap-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        TempDir(path)
    }

    pub(super) fn path(&self) -> &Path {
        &self.0
    }

    /// Writes a file at `relative`, creating missing parent directories.
    pub(super) fn file(&self, relative: &str, text: &str) -> PathBuf {
        let path = self.0.join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&path, text).unwrap();
        path
    }

    /// Creates the directory `relative` and its parents.
    pub(super) fn dir(&self, relative: &str) -> PathBuf {
        let path = self.0.join(relative);
        fs::create_dir_all(&path).unwrap();
        path
    }

    /// Creates a symbolic link at `relative` pointing to `target`. The target
    /// need not exist, just like the `socket:[INODE]` links in `/proc`.
    #[cfg(unix)]
    pub(super) fn symlink(&self, relative: &str, target: &str) -> PathBuf {
        let path = self.0.join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        std::os::unix::fs::symlink(target, &path).unwrap();
        path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
