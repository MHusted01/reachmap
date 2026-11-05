//! Collector for socket owners: lists the open files of every process from
//! `/proc/<pid>/fd/` and reads `/proc/<pid>/comm`. The pure join happens in
//! [`crate::parse::proc_pid`].
//!
//! A normal user may only look inside the `fd` folders of their own
//! processes. Others fail with "permission denied"; that is recorded in
//! [`ProcessFds::permission_denied`], never treated as an error. With
//! `hidepid` they do not fail at all, because they are absent from `/proc`;
//! [`processes_may_be_hidden`] detects that.

use std::ffi::OsStr;
use std::fs;
use std::io::{self, ErrorKind};
use std::path::Path;

use super::CollectError;
use crate::parse::proc_pid::FdLink;
use crate::parse::proc_self::{effective_uid, may_hide_processes, proc_hidepid};

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
    /// True when `/proc` may leave out other users' processes, so a socket
    /// without a known owner may belong to one the walk never saw.
    pub processes_may_be_hidden: bool,
}

impl ProcessFds {
    /// True when the walk may have missed processes, so root might find the
    /// owner of a socket that has none here.
    #[must_use]
    pub fn incomplete(&self) -> bool {
        self.permission_denied || self.processes_may_be_hidden
    }

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
/// Processes or links that cannot be inspected for lack of privileges set
/// [`ProcessFds::permission_denied`]; processes that exit during the walk are
/// skipped. Any other failure is an error naming the path.
pub fn read_process_fds(proc_root: &Path) -> Result<ProcessFds, CollectError> {
    let mut found = ProcessFds::default();
    for entry in fs::read_dir(proc_root).map_err(read_error(proc_root))? {
        let entry = entry.map_err(read_error(proc_root))?;
        let Some(pid) = pid_of(&entry.file_name()) else {
            continue;
        };
        let dir = entry.path();
        let Some(fds) = found.tolerate(read_fd_targets(&dir.join("fd")))? else {
            continue;
        };
        found.permission_denied |= fds.denied;
        // No open files (kernel threads): skip without reading the name.
        if fds.targets.is_empty() {
            continue;
        }
        let comm_path = dir.join("comm");
        let comm = fs::read_to_string(&comm_path).map_err(read_error(&comm_path));
        let Some(comm) = found.tolerate(comm)? else {
            continue;
        };
        found.processes.push(RawProcess {
            pid,
            comm,
            fd_targets: fds.targets,
        });
    }
    Ok(found)
}

/// Whether `proc_root` (normally `/proc`) may leave out other users' processes
/// for the user running this scan. Files that cannot be read are not an error:
/// [`may_hide_processes`] then gives the cautious answer.
#[must_use]
pub fn processes_may_be_hidden(proc_root: &Path) -> bool {
    let read = |file: &str| fs::read_to_string(proc_root.join("self").join(file)).ok();
    may_hide_processes(
        read("mountinfo").as_deref().and_then(proc_hidepid),
        read("status").as_deref().and_then(effective_uid),
    )
}

impl ProcessFds {
    /// Turns the failures a walk expects into "skip this process": a denial
    /// is recorded, a process that is gone is ignored. Other failures stay
    /// errors.
    fn tolerate<T>(&mut self, result: Result<T, CollectError>) -> Result<Option<T>, CollectError> {
        match result {
            Ok(value) => Ok(Some(value)),
            Err(CollectError::Read { source, .. }) if classify(&source) == Failure::Denied => {
                self.permission_denied = true;
                Ok(None)
            }
            Err(CollectError::Read { source, .. }) if classify(&source) == Failure::Gone => {
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }
}

/// The kinds of failure a walk over `/proc` must tell apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Failure {
    /// Not allowed for this user (`EACCES` or `EPERM`): root would see more.
    Denied,
    /// The process exited, or the file was closed, while it was being read.
    Gone,
    /// Anything else: a real problem worth reporting.
    Other,
}

/// `ESRCH`, "no such process": what the kernel may return when a process
/// exits while one of its `/proc` files is read. Rust has no stable
/// `ErrorKind` for it, so it is matched by number (3 on Linux and macOS).
const ESRCH: i32 = 3;

fn classify(error: &io::Error) -> Failure {
    match error.kind() {
        ErrorKind::PermissionDenied => Failure::Denied,
        ErrorKind::NotFound => Failure::Gone,
        _ if error.raw_os_error() == Some(ESRCH) => Failure::Gone,
        _ => Failure::Other,
    }
}

/// The pid a `/proc` entry stands for; `None` for `self`, `net`, `version`
/// and the other entries that are not processes.
fn pid_of(name: &OsStr) -> Option<u32> {
    name.to_str()?.parse().ok()
}

/// The link targets found in one `fd` folder.
#[derive(Debug, Default)]
struct FdTargets {
    /// Every target that could be read.
    targets: Vec<String>,
    /// True when some links could not be read for lack of privileges.
    denied: bool,
}

/// Reads the target of every link in one `fd` folder. A link that cannot be
/// read is skipped, so the readable ones are still used.
fn read_fd_targets(fd_dir: &Path) -> Result<FdTargets, CollectError> {
    let mut found = FdTargets::default();
    for entry in fs::read_dir(fd_dir).map_err(read_error(fd_dir))? {
        let link = entry.map_err(read_error(fd_dir))?.path();
        match fs::read_link(&link) {
            // Socket targets are always ASCII. A target that is not UTF-8 is
            // a file path, never a socket, so dropping it loses nothing.
            Ok(target) => found
                .targets
                .extend(target.into_os_string().into_string().ok()),
            Err(error) => match classify(&error) {
                Failure::Denied => found.denied = true,
                // The file was closed between listing the folder and reading the link.
                Failure::Gone => {}
                Failure::Other => return Err(read_error(&link)(error)),
            },
        }
    }
    Ok(found)
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
                processes_may_be_hidden: false,
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
                processes_may_be_hidden: false,
            }
        );
    }

    #[test]
    fn links_that_cannot_be_read_are_recorded_not_an_error() {
        // Without the search (x) bit the folder can be listed, but the links
        // inside it cannot be read.
        let proc = TempDir::new("procs-link-denied");
        proc.file("1/comm", "systemd\n");
        let fd = proc.dir("1/fd");
        proc.symlink("1/fd/3", "socket:[100]");
        fs::set_permissions(&fd, fs::Permissions::from_mode(0o444)).unwrap();
        let running_as_root = fs::read_link(fd.join("3")).is_ok();

        let result = read_process_fds(proc.path());
        fs::set_permissions(&fd, fs::Permissions::from_mode(0o755)).unwrap();

        if running_as_root {
            return;
        }
        assert_eq!(
            result.unwrap(),
            ProcessFds {
                processes: vec![],
                permission_denied: true,
                processes_may_be_hidden: false,
            }
        );
    }

    #[test]
    fn classifies_failures_as_denied_gone_or_other() {
        let os_error = io::Error::from_raw_os_error;
        assert_eq!(classify(&os_error(13)), Failure::Denied, "EACCES");
        assert_eq!(classify(&os_error(1)), Failure::Denied, "EPERM");
        assert_eq!(classify(&os_error(2)), Failure::Gone, "ENOENT");
        assert_eq!(classify(&os_error(3)), Failure::Gone, "ESRCH");
        assert_eq!(classify(&os_error(20)), Failure::Other, "ENOTDIR");
        assert_eq!(classify(&io::Error::other("boom")), Failure::Other);
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

    /// A stand-in for `/proc` with the two files of `/proc/self` that matter.
    fn proc_self(name: &str, mount_options: &str, uid: u32) -> TempDir {
        let proc = TempDir::new(name);
        proc.file(
            "self/mountinfo",
            &format!("25 30 0:23 / /proc rw shared:14 - proc proc {mount_options}\n"),
        );
        proc.file(
            "self/status",
            &format!("Uid:\t{uid}\t{uid}\t{uid}\t{uid}\n"),
        );
        proc
    }

    #[test]
    fn hidepid_may_hide_processes_from_a_normal_user() {
        let proc = proc_self("hidden-user", "rw,hidepid=2", 1000);
        assert!(processes_may_be_hidden(proc.path()));
    }

    #[test]
    fn hidepid_hides_nothing_from_root() {
        let proc = proc_self("hidden-root", "rw,hidepid=2", 0);
        assert!(!processes_may_be_hidden(proc.path()));
    }

    #[test]
    fn a_plain_proc_mount_hides_nothing() {
        let proc = proc_self("hidden-plain", "rw", 1000);
        assert!(!processes_may_be_hidden(proc.path()));
    }

    #[test]
    fn an_unreadable_mountinfo_means_processes_may_be_hidden() {
        let proc = TempDir::new("hidden-no-mountinfo");
        proc.file("self/status", "Uid:\t1000\t1000\t1000\t1000\n");
        assert!(processes_may_be_hidden(proc.path()));
    }

    #[test]
    fn root_is_exempt_even_when_mountinfo_is_unreadable() {
        let proc = TempDir::new("hidden-root-no-mountinfo");
        proc.file("self/status", "Uid:\t0\t0\t0\t0\n");
        assert!(!processes_may_be_hidden(proc.path()));
    }

    #[test]
    fn an_unreadable_status_counts_as_not_root() {
        let proc = proc_self("hidden-no-status", "rw,hidepid=2", 0);
        fs::remove_file(proc.path().join("self/status")).unwrap();
        assert!(processes_may_be_hidden(proc.path()));
    }

    #[test]
    fn a_walk_is_incomplete_when_processes_were_denied_or_may_be_hidden() {
        let walk = |permission_denied, processes_may_be_hidden| ProcessFds {
            processes: vec![],
            permission_denied,
            processes_may_be_hidden,
        };
        assert!(!walk(false, false).incomplete());
        assert!(walk(true, false).incomplete());
        assert!(walk(false, true).incomplete());
        assert!(walk(true, true).incomplete());
    }

    #[test]
    fn links_lists_every_fd_link_with_its_process() {
        let fds = ProcessFds {
            processes: vec![
                raw(1, "a\n", &["socket:[1]", "/dev/null"]),
                raw(2, "b\n", &["socket:[2]"]),
            ],
            permission_denied: false,
            processes_may_be_hidden: false,
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
