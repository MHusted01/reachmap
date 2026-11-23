//! Read-only access to Nginx configuration files. The include walk in
//! [`crate::nginx::routes`] stays pure and is tested with an in-memory
//! [`ConfigFiles`]; [`DiskFiles`] is the thin Linux shell over the filesystem.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::ffi::OsString;
use std::io;

/// What reading one configuration file found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FileRead {
    /// Nothing exists at the path.
    Missing,
    /// The path is a directory, FIFO, socket or device; it is never read.
    NotRegular,
    /// A regular file on a kernel pseudo-filesystem such as procfs or sysfs,
    /// where reading can have side effects (`/proc/kmsg` consumes kernel
    /// messages); it is never read.
    KernelFile,
    /// The file is longer than the byte limit it was read with.
    TooLarge,
    /// The whole file.
    Bytes(Vec<u8>),
}

/// What listing one directory found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DirList {
    /// Every entry name as stored, which need not be UTF-8, in no particular
    /// order. A missing path, or one that is not a directory, has none, as
    /// for `glob()`.
    Entries(Vec<OsString>),
    /// The directory has more entries than the limit it was listed with.
    TooMany,
}

/// Read-only filesystem operations the Nginx include walk needs.
pub(crate) trait ConfigFiles {
    /// Reads the regular file at `path` (following symlinks) if it holds at
    /// most `limit` bytes.
    fn read(&self, path: &str, limit: u64) -> io::Result<FileRead>;

    /// Lists the directory `dir` if it has at most `limit` entries.
    fn list(&self, dir: &str, limit: usize) -> io::Result<DirList>;

    /// Whether anything exists at `path`, without following a final symlink,
    /// as `glob()` checks the literal parts of a pattern.
    fn exists(&self, path: &str) -> io::Result<bool>;
}

/// The real filesystem. A file is first pinned with `O_PATH`, which opens
/// nothing, and only a regular file is then reopened for reading through
/// `/proc/self/fd`: a path swapped to a FIFO or device after the check still
/// reaches the checked file, so opening a device never happens.
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy)]
pub(crate) struct DiskFiles;

#[cfg(target_os = "linux")]
impl ConfigFiles for DiskFiles {
    fn read(&self, path: &str, limit: u64) -> io::Result<FileRead> {
        use std::fs::File;
        use std::io::Read;
        use std::os::fd::AsRawFd;

        use rustix::fs::{FileType, Mode, OFlags, fstat, fstatfs, open};

        let pinned = match open(path, OFlags::PATH | OFlags::CLOEXEC, Mode::empty()) {
            Ok(fd) => fd,
            Err(error) => {
                let error = io::Error::from(error);
                return if is_missing(error.kind()) {
                    Ok(FileRead::Missing)
                } else {
                    Err(error)
                };
            }
        };
        if FileType::from_raw_mode(fstat(&pinned)?.st_mode) != FileType::RegularFile {
            return Ok(FileRead::NotRegular);
        }
        if KERNEL_FILESYSTEMS.contains(&i128::from(fstatfs(&pinned)?.f_type)) {
            return Ok(FileRead::KernelFile);
        }
        let verified = format!("/proc/self/fd/{}", pinned.as_raw_fd());
        let flags = OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC;
        let file = File::from(open(verified.as_str(), flags, Mode::empty())?);
        let mut bytes = Vec::new();
        file.take(limit.saturating_add(1)).read_to_end(&mut bytes)?;
        if u64::try_from(bytes.len()).map_or(true, |len| len > limit) {
            return Ok(FileRead::TooLarge);
        }
        Ok(FileRead::Bytes(bytes))
    }

    fn list(&self, dir: &str, limit: usize) -> io::Result<DirList> {
        let entries = match std::fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(error) if is_missing(error.kind()) => return Ok(DirList::Entries(Vec::new())),
            Err(error) => return Err(error),
        };
        let mut names = Vec::new();
        for entry in entries {
            if names.len() == limit {
                return Ok(DirList::TooMany);
            }
            names.push(entry?.file_name());
        }
        Ok(DirList::Entries(names))
    }

    fn exists(&self, path: &str) -> io::Result<bool> {
        match std::fs::symlink_metadata(path) {
            Ok(_) => Ok(true),
            Err(error) if is_missing(error.kind()) => Ok(false),
            Err(error) => Err(error),
        }
    }
}

/// `statfs` magic numbers of kernel pseudo-filesystems whose regular files
/// can change state or block when read: proc, sysfs, debugfs, tracefs,
/// securityfs, cgroup, cgroup2, bpf, configfs, efivarfs and pstore.
#[cfg(target_os = "linux")]
const KERNEL_FILESYSTEMS: [i128; 11] = [
    0x9fa0,
    0x6265_6572,
    0x6462_6720,
    0x7472_6163,
    0x7363_6673,
    0x0027_e0eb,
    0x6367_7270,
    0xcafe_4a11,
    0x6265_6570,
    0xde5e_81e4,
    0x6165_676c,
];

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
    fn never_reads_regular_files_on_kernel_filesystems() {
        for path in ["/proc/self/status", "/sys/kernel/uevent_seqnum"] {
            if std::path::Path::new(path).is_file() {
                assert_eq!(
                    DiskFiles.read(path, 1024).unwrap(),
                    FileRead::KernelFile,
                    "{path}"
                );
            }
        }
    }

    #[test]
    fn exists_does_not_follow_a_final_symlink() {
        let dir = TempDir::new("nginx-files-exists");
        dir.file("conf.d/a.conf", "");
        symlink(dir.path().join("missing"), dir.path().join("dangling")).unwrap();
        assert!(DiskFiles.exists(&text(&dir, "conf.d/a.conf")).unwrap());
        assert!(DiskFiles.exists(&text(&dir, "dangling")).unwrap());
        assert!(!DiskFiles.exists(&text(&dir, "missing")).unwrap());
        assert!(!DiskFiles.exists(&text(&dir, "conf.d/a.conf/x")).unwrap());
    }

    #[test]
    fn lists_directories_within_a_limit_and_treats_missing_ones_as_empty() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        let dir = TempDir::new("nginx-files-list");
        dir.file("conf.d/b.conf", "");
        dir.file("conf.d/a.conf", "");
        std::fs::write(
            dir.path()
                .join("conf.d")
                .join(OsStr::from_bytes(b"c\xff.conf")),
            "",
        )
        .unwrap();

        let DirList::Entries(mut names) = DiskFiles.list(&text(&dir, "conf.d"), 3).unwrap() else {
            panic!("three entries fit a limit of three");
        };
        names.sort();
        let bytes: Vec<&[u8]> = names.iter().map(|name| name.as_bytes()).collect();
        assert_eq!(bytes, [&b"a.conf"[..], b"b.conf", b"c\xff.conf"]);
        assert_eq!(
            DiskFiles.list(&text(&dir, "conf.d"), 2).unwrap(),
            DirList::TooMany
        );
        let empty = DirList::Entries(Vec::new());
        assert_eq!(DiskFiles.list(&text(&dir, "missing"), 2).unwrap(), empty);
        assert_eq!(
            DiskFiles.list(&text(&dir, "conf.d/a.conf"), 2).unwrap(),
            empty
        );
    }
}
