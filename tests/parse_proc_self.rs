//! The `/proc/self` parsers against text in the format of real hosts.

use reachmap::parse::proc_self::{Hidepid, effective_uid, proc_hidepid};

#[test]
fn finds_the_hidepid_mode_among_the_mounts_of_a_host() {
    let text = include_str!("fixtures/proc_self_mountinfo.txt");
    assert_eq!(proc_hidepid(text), Some(Hidepid::Invisible));
}

#[test]
fn the_effective_uid_is_the_second_number_on_the_uid_line() {
    let text = include_str!("fixtures/proc_self_status.txt");
    assert_eq!(effective_uid(text), Some(1001));
}
