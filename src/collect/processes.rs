//! Collector for socket owners: lists the open files of every process from
//! `/proc/<pid>/fd/` and reads `/proc/<pid>/comm`. The pure join happens in
//! [`crate::parse::proc_pid`].
//!
//! A normal user may only look inside the `fd` folders of their own
//! processes. Others fail with "permission denied"; that is recorded in
//! [`ProcessFds::permission_denied`], never treated as an error.

use std::ffi::OsStr;
use std::fs;
use std::io::{self, ErrorKind};
use std::path::Path;

use super::CollectError;
use crate::parse::proc_pid::FdLink;

/// The raw data of one process that has at least one open file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawProcess {
    /// Process ID, the name of its folder in `/proc`.
    pub pid: u32,
    /// Content of `/proc/<pid>/comm`, including the trailing newline.
    pub comm: String,
    /// Target of each link in `/proc/<pid>/fd/`, e.g. `socket:[23456]`.
    pub fd_targets: Vec<String>,
}

/// What a walk over `/proc` found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProcessFds {
    /// Every process whose open files could be listed.
    pub processes: Vec<RawProcess>,
    /// True when at least one process could not be inspected for lack of
    /// privileges, so a socket without a known owner may belong to it.
    pub permission_denied: bool,
}

impl ProcessFds {
    /// Every open file of every process, as input for
    /// [`crate::parse::proc_pid::owners_by_inode`].
    pub fn links(&self) -> impl Iterator<Item = FdLink<'_>> {
        self.processes.iter().flat_map(|process| {
            process.fd_targets.iter().map(move |target| FdLink {
                pid: process.pid,
                comm: &process.comm,
                target,
            })
        })
    }
}

/// Reads the open files of every process below `proc_root` (normally `/proc`).
///
/// Processes that cannot be inspected for lack of privileges set
/// [`ProcessFds::permission_denied`]; processes that exit during the walk are
/// skipped. Any other failure is an error naming the path.
pub fn read_process_fds(proc_root: &Path) -> Result<ProcessFds, CollectError> {
    let mut found = ProcessFds::default();
    for entry in fs::read_dir(proc_root).map_err(read_error(proc_root))? {
        let entry = entry.map_err(read_error(proc_root))?;
        let Some(pid) = pid_of(&entry.file_name()) else {
            continue;
        };
        match read_process(&entry.path(), pid) {
            Ok(Some(process)) => found.processes.push(process),
            Ok(None) => {}
            Err(CollectError::Read { source, .. })
                if source.kind() == ErrorKind::PermissionDenied =>
            {
                found.permission_denied = true;
            }
            // The process exited between listing `/proc` and reading it.
            Err(CollectError::Read { source, .. }) if source.kind() == ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Ok(found)
}

/// The pid a `/proc` entry stands for; `None` for `self`, `net`, `version`
/// and the other entries that are not processes.
fn pid_of(name: &OsStr) -> Option<u32> {
    name.to_str()?.parse().ok()
}

/// One process's open files and name. `None` when it has no open files
/// (kernel threads), so its name is not even read.
fn read_process(dir: &Path, pid: u32) -> Result<Option<RawProcess>, CollectError> {
    let fd_targets = read_fd_targets(&dir.join("fd"))?;
    if fd_targets.is_empty() {
        return Ok(None);
    }
    let comm_path = dir.join("comm");
    let comm = fs::read_to_string(&comm_path).map_err(read_error(&comm_path))?;
    Ok(Some(RawProcess {
        pid,
        comm,
        fd_targets,
    }))
}

/// The target of every link in one `fd` folder.
fn read_fd_targets(fd_dir: &Path) -> Result<Vec<String>, CollectError> {
    let mut targets = Vec::new();
    for entry in fs::read_dir(fd_dir).map_err(read_error(fd_dir))? {
        let link = entry.map_err(read_error(fd_dir))?.path();
        match fs::read_link(&link) {
            // Socket targets are always ASCII. A target that is not UTF-8 is
            // a file path, never a socket, so dropping it loses nothing.
            Ok(target) => targets.extend(target.into_os_string().into_string().ok()),
            // The file was closed between listing the folder and reading the link.
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => return Err(read_error(&link)(error)),
        }
    }
    Ok(targets)
}

/// Wraps an I/O error with the path it happened on, for `map_err`.
fn read_error(path: &Path) -> impl FnOnce(io::Error) -> CollectError {
    move |source| CollectError::Read {
        path: path.to_path_buf(),
        source,
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::collect::test_support::TempDir;
    use crate::errors::render_chain;
    use std::os::unix::fs::PermissionsExt;

    fn raw(pid: u32, comm: &str, targets: &[&str]) -> RawProcess {
        RawProcess {
            pid,
            comm: comm.to_string(),
            fd_targets: targets.iter().map(ToString::to_string).collect(),
        }
    }

    /// Sorts what `read_dir` returns in no particular order.
    fn sorted(mut fds: ProcessFds) -> ProcessFds {
        fds.processes.sort_by_key(|p| p.pid);
        for process in &mut fds.processes {
            process.fd_targets.sort();
        }
        fds
    }

    #[test]
    fn reads_the_fd_links_and_comm_of_every_process() {
        let proc = TempDir::new("procs-every");
        proc.file("812/comm", "sshd\n");
        proc.symlink("812/fd/0", "/dev/null");
        proc.symlink("812/fd/3", "socket:[100]");
        proc.file("950/comm", "nginx\n");
        proc.symlink("950/fd/4", "socket:[200]");
        // Not processes: names that are not numbers.
        proc.symlink("self", "812");
        proc.file("version", "Linux");
        proc.dir("net");

        let fds = read_process_fds(proc.path()).unwrap();

        assert_eq!(
            sorted(fds),
            ProcessFds {
                processes: vec![
                    raw(812, "sshd\n", &["/dev/null", "socket:[100]"]),
                    raw(950, "nginx\n", &["socket:[200]"]),
                ],
                permission_denied: false,
            }
        );
    }

    #[test]
    fn a_process_without_open_files_is_left_out() {
        let proc = TempDir::new("procs-no-files");
        proc.file("2/comm", "kthreadd\n");
        proc.dir("2/fd");

        let fds = read_process_fds(proc.path()).unwrap();

        assert_eq!(fds, ProcessFds::default());
    }

    #[test]
    fn a_process_that_exits_during_the_walk_is_skipped() {
        // Its folder is still listed, but `fd` and `comm` are gone.
        let proc = TempDir::new("procs-exited");
        proc.dir("77");

        let fds = read_process_fds(proc.path()).unwrap();

        assert_eq!(fds, ProcessFds::default());
    }

    #[test]
    fn an_fd_folder_without_permission_is_recorded_not_an_error() {
        let proc = TempDir::new("procs-denied");
        proc.file("1/comm", "systemd\n");
        let fd = proc.dir("1/fd");
        proc.file("500/comm", "me\n");
        proc.symlink("500/fd/3", "socket:[300]");
        fs::set_permissions(&fd, fs::Permissions::from_mode(0o000)).unwrap();
        // Root ignores folder permissions, so the denial cannot be staged.
        let running_as_root = fs::read_dir(&fd).is_ok();

        let result = read_process_fds(proc.path());
        fs::set_permissions(&fd, fs::Permissions::from_mode(0o755)).unwrap();

        if running_as_root {
            return;
        }
        assert_eq!(
            result.unwrap(),
            ProcessFds {
                processes: vec![raw(500, "me\n", &["socket:[300]"])],
                permission_denied: true,
            }
        );
    }

    #[test]
    fn a_missing_proc_root_is_an_error_naming_it() {
        let proc = TempDir::new("procs-missing-root");
        let missing = proc.path().join("proc");

        let error = read_process_fds(&missing).unwrap_err();

        assert!(
            render_chain(&error).starts_with(&format!("could not read {}: ", missing.display())),
            "got: {}",
            render_chain(&error)
        );
    }

    #[test]
    fn other_failures_inside_a_process_are_errors_naming_the_path() {
        // `fd` is a file instead of a folder: neither "denied" nor "gone".
        let proc = TempDir::new("procs-not-a-dir");
        proc.file("9/comm", "odd\n");
        let fd = proc.file("9/fd", "");

        let error = read_process_fds(proc.path()).unwrap_err();

        assert!(
            render_chain(&error).starts_with(&format!("could not read {}: ", fd.display())),
            "got: {}",
            render_chain(&error)
        );
    }

    #[test]
    fn links_lists_every_fd_link_with_its_process() {
        let fds = ProcessFds {
            processes: vec![
                raw(1, "a\n", &["socket:[1]", "/dev/null"]),
                raw(2, "b\n", &["socket:[2]"]),
            ],
            permission_denied: false,
        };

        let links: Vec<FdLink<'_>> = fds.links().collect();

        assert_eq!(
            links,
            vec![
                FdLink {
                    pid: 1,
                    comm: "a\n",
                    target: "socket:[1]"
                },
                FdLink {
                    pid: 1,
                    comm: "a\n",
                    target: "/dev/null"
                },
                FdLink {
                    pid: 2,
                    comm: "b\n",
                    target: "socket:[2]"
                },
            ]
        );
    }
}
