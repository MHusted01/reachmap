//! Parsers for two files about the running process itself:
//! `/proc/self/mountinfo` (how `/proc` is mounted) and `/proc/self/status`
//! (which user we run as). Together they tell whether other users' processes
//! may be missing from `/proc`.
//!
//! A line of `mountinfo` has a variable number of fields, ended by ` - `:
//!
//! ```text
//! 25 30 0:23 / /proc rw,nosuid shared:14 - proc proc rw,hidepid=2,gid=1500
//! ```
//!
//! The fifth field is the mount point. After the separator come the
//! filesystem type, the source and the options of the filesystem itself,
//! which is where `hidepid` lives.

/// The user ID of root.
const ROOT_UID: u32 = 0;

/// Where `/proc` is mounted.
const PROC_MOUNT_POINT: &str = "/proc";

/// The filesystem type of `/proc`.
const PROC_FILESYSTEM: &str = "proc";

/// The `hidepid` mode of a `/proc` mount: what it shows of other users'
/// processes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hidepid {
    /// `hidepid=0`: everything is visible. The default.
    Off,
    /// `hidepid=1`: the folders are visible, but their content is locked.
    NoAccess,
    /// `hidepid=2`: the folders are absent.
    Invisible,
    /// `hidepid=4`: only processes the user may trace are visible.
    Ptraceable,
}

impl Hidepid {
    /// True when other users' processes are absent from `/proc`, so a walk
    /// gets no permission error for them. With [`Hidepid::NoAccess`] they stay
    /// listed and the walk does get one.
    #[must_use]
    pub fn hides_processes(self) -> bool {
        match self {
            Hidepid::Off | Hidepid::NoAccess => false,
            Hidepid::Invisible | Hidepid::Ptraceable => true,
        }
    }

    /// The mode for the value of a `hidepid=` option. Kernels print the name
    /// or the number depending on their age.
    fn from_option(value: &str) -> Option<Self> {
        match value {
            "0" => Some(Hidepid::Off),
            "1" | "noaccess" => Some(Hidepid::NoAccess),
            "2" | "invisible" => Some(Hidepid::Invisible),
            "4" | "ptraceable" => Some(Hidepid::Ptraceable),
            _ => None,
        }
    }
}

/// The `hidepid` mode of `/proc`, from the text of `/proc/self/mountinfo`.
/// When several mounts sit on `/proc`, the last one is the one in use.
///
/// `None` when the answer cannot be told: no `/proc` mount is listed, or its
/// `hidepid` value is not one this version knows.
#[must_use]
pub fn proc_hidepid(mountinfo: &str) -> Option<Hidepid> {
    let options = mountinfo.lines().rev().find_map(proc_mount_options)?;
    match options
        .split(',')
        .find_map(|option| option.strip_prefix("hidepid="))
    {
        Some(value) => Hidepid::from_option(value),
        None => Some(Hidepid::Off),
    }
}

/// The filesystem options of a `mountinfo` line, if it is a `proc` filesystem
/// mounted on `/proc`.
fn proc_mount_options(line: &str) -> Option<&str> {
    let (mount, filesystem) = line.split_once(" - ")?;
    let mount_point = mount.split_whitespace().nth(4)?;
    let mut filesystem = filesystem.split_whitespace();
    let filesystem_type = filesystem.next()?;
    (mount_point == PROC_MOUNT_POINT && filesystem_type == PROC_FILESYSTEM)
        .then(|| filesystem.nth(1))
        .flatten()
}

/// The effective user ID, from the text of `/proc/self/status`. Its `Uid:`
/// line lists the real, effective, saved and filesystem IDs, in that order.
#[must_use]
pub fn effective_uid(status: &str) -> Option<u32> {
    status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()
}

/// Whether other users' processes may be missing from `/proc` for this user.
///
/// Root is exempt from `hidepid`. For anyone else, a mode that cannot be told
/// counts as hiding, and so does an unknown user unless `/proc` is known not
/// to hide: the cautious answer is that the owner of a socket may be hidden.
/// Members of the mount's `gid=` group are exempt too, but need no check here:
/// they see other users' processes without being able to read their open
/// files, so a walk reports those as denied anyway.
#[must_use]
pub fn may_hide_processes(hidepid: Option<Hidepid>, euid: Option<u32>) -> bool {
    euid != Some(ROOT_UID) && hidepid.is_none_or(Hidepid::hides_processes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mount_line(options: &str) -> String {
        format!("25 30 0:23 / /proc rw,nosuid shared:14 - proc proc {options}\n")
    }

    #[test]
    fn reads_every_hidepid_mode_by_number_and_by_name() {
        for (options, expected) in [
            ("rw,hidepid=0", Hidepid::Off),
            ("rw,hidepid=1", Hidepid::NoAccess),
            ("rw,hidepid=noaccess", Hidepid::NoAccess),
            ("rw,hidepid=2", Hidepid::Invisible),
            ("rw,hidepid=invisible", Hidepid::Invisible),
            ("rw,hidepid=4", Hidepid::Ptraceable),
            ("rw,hidepid=ptraceable", Hidepid::Ptraceable),
            ("rw,gid=1500,hidepid=2", Hidepid::Invisible),
        ] {
            assert_eq!(
                proc_hidepid(&mount_line(options)),
                Some(expected),
                "options {options:?}"
            );
        }
    }

    #[test]
    fn no_hidepid_option_means_off() {
        assert_eq!(proc_hidepid(&mount_line("rw")), Some(Hidepid::Off));
    }

    #[test]
    fn the_last_mount_on_proc_wins() {
        let hidden_on_top = mount_line("rw") + &mount_line("rw,hidepid=2");
        let plain_on_top = mount_line("rw,hidepid=2") + &mount_line("rw");

        assert_eq!(proc_hidepid(&hidden_on_top), Some(Hidepid::Invisible));
        assert_eq!(proc_hidepid(&plain_on_top), Some(Hidepid::Off));
    }

    #[test]
    fn mounts_elsewhere_or_of_another_type_are_ignored() {
        let text = "\
25 30 0:23 / /proc rw shared:14 - proc proc rw,hidepid=2
41 25 0:37 / /proc/sys/fs/binfmt_misc rw - binfmt_misc binfmt_misc rw
58 30 0:45 / /mnt/proc rw - proc proc rw
59 30 0:46 / /proc rw - tmpfs tmpfs rw
";
        assert_eq!(proc_hidepid(text), Some(Hidepid::Invisible));
    }

    #[test]
    fn optional_fields_do_not_shift_the_filesystem_part() {
        let text = "25 30 0:23 / /proc rw shared:14 master:2 - proc proc rw,hidepid=2\n";
        assert_eq!(proc_hidepid(text), Some(Hidepid::Invisible));
    }

    #[test]
    fn an_unknown_hidepid_value_cannot_be_told() {
        assert_eq!(proc_hidepid(&mount_line("rw,hidepid=9")), None);
    }

    #[test]
    fn text_without_a_proc_mount_cannot_be_told() {
        for text in ["", "garbage\n", "30 1 8:2 / / rw - ext4 /dev/sda2 rw\n"] {
            assert_eq!(proc_hidepid(text), None, "text {text:?}");
        }
    }

    #[test]
    fn only_some_modes_hide_processes() {
        assert!(!Hidepid::Off.hides_processes());
        assert!(!Hidepid::NoAccess.hides_processes());
        assert!(Hidepid::Invisible.hides_processes());
        assert!(Hidepid::Ptraceable.hides_processes());
    }

    #[test]
    fn reads_the_effective_uid_not_the_real_one() {
        // A setuid-root program started by a normal user.
        assert_eq!(effective_uid("Uid:\t1000\t0\t0\t0\n"), Some(0));
    }

    #[test]
    fn a_status_without_a_usable_uid_line_gives_none() {
        for text in [
            "",
            "Name:\tsshd\n",
            "Uid:\n",
            "Uid:\t1000\n",
            "Uid:\ta\tb\n",
        ] {
            assert_eq!(effective_uid(text), None, "text {text:?}");
        }
    }

    #[test]
    fn root_is_never_hidden_from() {
        for hidepid in [None, Some(Hidepid::Off), Some(Hidepid::Invisible)] {
            assert!(!may_hide_processes(hidepid, Some(0)), "mode {hidepid:?}");
        }
    }

    #[test]
    fn a_normal_user_is_hidden_from_when_the_mode_hides_or_is_unknown() {
        let user = Some(1000);
        assert!(may_hide_processes(Some(Hidepid::Invisible), user));
        assert!(may_hide_processes(Some(Hidepid::Ptraceable), user));
        assert!(may_hide_processes(None, user));
        assert!(!may_hide_processes(Some(Hidepid::Off), user));
        assert!(!may_hide_processes(Some(Hidepid::NoAccess), user));
    }

    #[test]
    fn an_unknown_user_counts_as_not_root() {
        assert!(may_hide_processes(Some(Hidepid::Invisible), None));
        assert!(may_hide_processes(None, None));
        assert!(!may_hide_processes(Some(Hidepid::Off), None));
    }
}
