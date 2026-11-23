//! Read-only access to Nginx configuration files. The include walk in
//! [`crate::nginx::routes`] stays pure and is tested with an in-memory
//! [`ConfigFiles`]; [`DiskFiles`] is the thin Linux shell over the filesystem.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::io;

/// What reading one configuration file found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FileRead {
    /// Nothing exists at the path.
    Missing,
    /// The path is a directory, FIFO, socket or device; it is never read.
    NotRegular,
    /// The file is longer than the byte limit it was read with.
    TooLarge,
    /// The whole file.
    Bytes(Vec<u8>),
}

/// Read-only filesystem operations the Nginx include walk needs.
pub(crate) trait ConfigFiles {
    /// Reads the regular file at `path` (following symlinks) if it holds at
    /// most `limit` bytes.
    fn read(&self, path: &str, limit: u64) -> io::Result<FileRead>;

    /// Lists the entry names of the directory `dir`. A missing path, or one
    /// that is not a directory, has no entries, as for `glob()`.
    fn list(&self, dir: &str) -> io::Result<Vec<String>>;
}

/// The real filesystem. Files are opened read-only and non-blocking, and only
/// regular files are read, so a FIFO cannot stall the scan and opening a
/// device has no side effect.
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy)]
pub(crate) struct DiskFiles;

#[cfg(target_os = "linux")]
impl ConfigFiles for DiskFiles {
    fn read(&self, path: &str, limit: u64) -> io::Result<FileRead> {
        use std::fs::{self, File};
        use std::io::Read;

        use rustix::fs::{Mode, OFlags, open};

        // Refuse non-regular files before opening them, then check the opened
        // file again in case the path changed in between.
        match fs::metadata(path) {
            Ok(metadata) if !metadata.is_file() => return Ok(FileRead::NotRegular),
            Ok(_) => {}
            Err(error) if is_missing(error.kind()) => return Ok(FileRead::Missing),
            Err(error) => return Err(error),
        }
        let flags = OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC;
        let file = match open(path, flags, Mode::empty()) {
            Ok(fd) => File::from(fd),
            Err(error) => {
                let error = io::Error::from(error);
                return if is_missing(error.kind()) {
                    Ok(FileRead::Missing)
                } else {
                    Err(error)
                };
            }
        };
        if !file.metadata()?.is_file() {
            return Ok(FileRead::NotRegular);
        }
        let mut bytes = Vec::new();
        file.take(limit.saturating_add(1)).read_to_end(&mut bytes)?;
        if u64::try_from(bytes.len()).map_or(true, |len| len > limit) {
            return Ok(FileRead::TooLarge);
        }
        Ok(FileRead::Bytes(bytes))
    }

    fn list(&self, dir: &str) -> io::Result<Vec<String>> {
        let entries = match std::fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(error) if is_missing(error.kind()) => return Ok(Vec::new()),
            Err(error) => return Err(error),
        };
        entries
            .map(|entry| {
                entry?.file_name().into_string().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "file name is not UTF-8")
                })
            })
            .collect()
    }
}

#[cfg(target_os = "linux")]
fn is_missing(kind: io::ErrorKind) -> bool {
    matches!(kind, io::ErrorKind::NotFound | io::ErrorKind::NotADirectory)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::os::unix::fs::symlink;

    use rustix::fs::{CWD, FileType, Mode, mknodat};

    use super::*;
    use crate::collect::test_support::TempDir;

    fn text(dir: &TempDir, name: &str) -> String {
        dir.path().join(name).to_string_lossy().into_owned()
    }

    #[test]
    fn reads_regular_files_and_symlinks_within_the_limit() {
        let dir = TempDir::new("nginx-files-read");
        dir.file("sites-available/app", "server {}\n");
        symlink(
            dir.path().join("sites-available/app"),
            dir.path().join("app-link"),
        )
        .unwrap();

        let expected = FileRead::Bytes(b"server {}\n".to_vec());
        let read = |name: &str, limit| DiskFiles.read(&text(&dir, name), limit).unwrap();
        assert_eq!(read("sites-available/app", 10), expected);
        assert_eq!(read("app-link", 10), expected);
        assert_eq!(read("app-link", 9), FileRead::TooLarge);
        assert_eq!(read("missing.conf", 10), FileRead::Missing);
        assert_eq!(read("sites-available/app/x", 10), FileRead::Missing);
    }

    #[test]
    fn never_reads_directories_fifos_or_devices() {
        let dir = TempDir::new("nginx-files-special");
        dir.file("conf.d/app.conf", "");
        let fifo = dir.path().join("pipe.conf");
        mknodat(CWD, &fifo, FileType::Fifo, Mode::from_raw_mode(0o600), 0).unwrap();

        for path in [
            text(&dir, "conf.d"),
            text(&dir, "pipe.conf"),
            "/dev/null".to_owned(),
        ] {
            assert_eq!(
                DiskFiles.read(&path, 1024).unwrap(),
                FileRead::NotRegular,
                "{path}"
            );
        }
    }

    #[test]
    fn lists_directories_and_treats_missing_ones_as_empty() {
        let dir = TempDir::new("nginx-files-list");
        dir.file("conf.d/b.conf", "");
        dir.file("conf.d/a.conf", "");

        let mut names = DiskFiles.list(&text(&dir, "conf.d")).unwrap();
        names.sort();
        assert_eq!(names, ["a.conf", "b.conf"]);
        assert!(DiskFiles.list(&text(&dir, "missing")).unwrap().is_empty());
        assert!(
            DiskFiles
                .list(&text(&dir, "conf.d/a.conf"))
                .unwrap()
                .is_empty()
        );
    }
}
