//! Parsers for per-process files under `/proc/<pid>/`: the targets of the
//! links in `/proc/<pid>/fd/` and the program name in `/proc/<pid>/comm`.
//!
//! Every open file of a process is a link in its `fd` folder. For a socket the
//! link target is `socket:[INODE]`, where INODE is the same number the socket
//! has in `/proc/net/tcp`. That shared number joins sockets to processes.

use std::collections::HashMap;
use std::collections::hash_map::Entry;

use crate::sanitize::sanitize;
use crate::service::Process;

/// One open file of one process: the (pid, link target, comm) of a single
/// `/proc/<pid>/fd/<n>` link. Borrows its text from the collected data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FdLink<'a> {
    /// The process that has the file open.
    pub pid: u32,
    /// Raw content of `/proc/<pid>/comm`, e.g. `"sshd\n"`.
    pub comm: &'a str,
    /// Where the link points, e.g. `socket:[23456]`, `pipe:[789]` or `/dev/null`.
    pub target: &'a str,
}

/// The inode in a socket link target: `socket:[23456]` gives `Some(23456)`.
/// Any other target (files, pipes, `anon_inode:[eventfd]`) gives `None`.
pub fn socket_inode(target: &str) -> Option<u64> {
    target
        .strip_prefix("socket:[")?
        .strip_suffix(']')
        // `parse` alone would also accept a leading `+`.
        .filter(|digits| digits.bytes().all(|b| b.is_ascii_digit()))?
        .parse()
        .ok()
}

/// Maps each socket inode to the process that has it open. Links that are not
/// sockets are ignored. When several processes share a socket, [`precedence`]
/// picks the one shown.
pub fn owners_by_inode<'a>(links: impl IntoIterator<Item = FdLink<'a>>) -> HashMap<u64, Process> {
    let mut owners = HashMap::new();
    for link in links {
        let Some(inode) = socket_inode(link.target) else {
            continue;
        };
        match owners.entry(inode) {
            Entry::Vacant(slot) => {
                slot.insert(process(link));
            }
            Entry::Occupied(mut slot)
                if precedence(link.pid, name_of(link.comm)) < precedence_of(slot.get()) =>
            {
                slot.insert(process(link));
            }
            Entry::Occupied(_) => {}
        }
    }
    owners
}

/// The service manager that does socket activation, at pid 1 for the whole
/// system and at other pids as `systemd --user`.
const SERVICE_MANAGER: &str = "systemd";

/// Sort key for the processes sharing one socket; the smallest wins.
///
/// - The service manager comes last. With socket activation, systemd opens a
///   socket and hands it to the service (e.g. sshd), so both hold it, and the
///   service is the useful answer. systemd still wins when it is the only
///   holder: a socket unit whose service has not started yet. The check is by
///   name, not pid 1, because inside a container pid 1 is the application.
/// - Then the lowest pid: a server comes before the workers it forked.
///
/// Tuples compare field by field and `false < true`, so
/// `(is_service_manager, pid)` orders exactly that way.
fn precedence(pid: u32, name: &str) -> (bool, u32) {
    (name == SERVICE_MANAGER, pid)
}

fn precedence_of(process: &Process) -> (bool, u32) {
    precedence(process.pid, &process.name)
}

/// The program name in a `comm` file: its content without the trailing newline.
fn name_of(comm: &str) -> &str {
    comm.strip_suffix('\n').unwrap_or(comm)
}

/// The owned [`Process`] for a link. The name is copied out of the borrowed
/// `comm` only here, for links that are actually kept.
fn process(link: FdLink<'_>) -> Process {
    Process {
        pid: link.pid,
        name: sanitize(name_of(link.comm)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn link<'a>(pid: u32, comm: &'a str, target: &'a str) -> FdLink<'a> {
        FdLink { pid, comm, target }
    }

    fn process(pid: u32, name: &str) -> Process {
        Process {
            pid,
            name: name.to_string(),
        }
    }

    #[test]
    fn process_names_are_sanitised() {
        let owners = owners_by_inode([link(7, "evil\u{1b}[2J\n", "socket:[100]")]);
        assert_eq!(owners[&100].name, "evil\\u{1b}[2J");
    }

    #[test]
    fn reads_the_inode_of_a_socket_link() {
        assert_eq!(socket_inode("socket:[23456]"), Some(23456));
        assert_eq!(socket_inode("socket:[0]"), Some(0));
    }

    #[test]
    fn other_link_targets_have_no_socket_inode() {
        for target in [
            "/dev/null",
            "pipe:[789]",
            "anon_inode:[eventfd]",
            "socket:[]",
            "socket:[12a]",
            "socket:[-1]",
            "socket:[+1]",
            "socket:[123",
            "socket:123]",
            "/home/me/socket:[1]",
        ] {
            assert_eq!(socket_inode(target), None, "target {target:?}");
        }
    }

    #[test]
    fn maps_socket_inodes_to_their_process_and_trims_the_comm_newline() {
        let owners = owners_by_inode([
            link(812, "sshd\n", "/dev/null"),
            link(812, "sshd\n", "socket:[100]"),
            link(950, "nginx\n", "pipe:[5]"),
            link(950, "nginx\n", "socket:[200]"),
        ]);

        assert_eq!(
            owners,
            HashMap::from([(100, process(812, "sshd")), (200, process(950, "nginx"))])
        );
    }

    #[test]
    fn a_shared_socket_belongs_to_the_lowest_pid_in_any_order() {
        let worker_first = owners_by_inode([
            link(951, "nginx\n", "socket:[200]"),
            link(950, "nginx\n", "socket:[200]"),
            link(952, "nginx\n", "socket:[200]"),
        ]);

        assert_eq!(worker_first, HashMap::from([(200, process(950, "nginx"))]));
    }

    #[test]
    fn a_socket_systemd_hands_to_a_service_belongs_to_the_service() {
        // Socket activation, as seen for sshd on a real host: systemd (pid 1)
        // opened the socket and passed it on, so both hold it.
        for links in [
            [
                link(1, "systemd\n", "socket:[300]"),
                link(7748, "sshd\n", "socket:[300]"),
            ],
            [
                link(7748, "sshd\n", "socket:[300]"),
                link(1, "systemd\n", "socket:[300]"),
            ],
        ] {
            assert_eq!(
                owners_by_inode(links),
                HashMap::from([(300, process(7748, "sshd"))])
            );
        }
    }

    #[test]
    fn a_socket_only_systemd_holds_belongs_to_systemd() {
        // A socket unit whose service has not started yet.
        let owners = owners_by_inode([link(1, "systemd\n", "socket:[400]")]);
        assert_eq!(owners, HashMap::from([(400, process(1, "systemd"))]));
    }

    #[test]
    fn pid_1_that_is_not_systemd_keeps_the_lowest_pid_rule() {
        // Inside a container's PID namespace, pid 1 is the application.
        let owners = owners_by_inode([
            link(7, "nginx\n", "socket:[500]"),
            link(1, "nginx\n", "socket:[500]"),
        ]);
        assert_eq!(owners, HashMap::from([(500, process(1, "nginx"))]));
    }

    #[test]
    fn a_user_systemd_instance_also_yields_to_the_service() {
        // `systemd --user` does socket activation too, with a pid other than 1.
        let owners = owners_by_inode([
            link(1500, "systemd\n", "socket:[600]"),
            link(1600, "app\n", "socket:[600]"),
        ]);
        assert_eq!(owners, HashMap::from([(600, process(1600, "app"))]));
    }

    #[test]
    fn a_comm_without_newline_is_used_as_is() {
        let owners = owners_by_inode([link(7, "my server", "socket:[1]")]);
        assert_eq!(owners[&1], process(7, "my server"));
    }

    #[test]
    fn no_links_give_an_empty_map() {
        assert!(owners_by_inode([]).is_empty());
    }
}
