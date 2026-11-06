//! Tests of `reachmap diff`. The two-file form needs no live scan, so these run
//! on every OS. A failure of a snapshot test means the documented shape in
//! `docs/diff.md` changed: update both on purpose, and raise `schema_version`
//! if scripts would break.

// Test helpers may panic: a failed test should stop loudly.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::process::{Command, Output};

const BASELINE: &str = "tests/fixtures/diff_baseline.json";
const CURRENT: &str = "tests/fixtures/diff_current.json";
const BROADCAST_BEFORE: &str = "tests/fixtures/diff_broadcast_before.json";
const BROADCAST_AFTER: &str = "tests/fixtures/diff_broadcast_after.json";

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_reachmap"))
        .args(args)
        .output()
        .expect("the binary should start")
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
fn two_files_with_differences_print_the_table_and_exit_with_1() {
    let out = run(&["diff", BASELINE, CURRENT]);

    assert_eq!(stdout(&out), include_str!("fixtures/diff_report.txt"));
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn json_output_matches_the_documented_shape_and_exits_with_1() {
    let out = run(&["diff", BASELINE, CURRENT, "--json"]);

    assert_eq!(stdout(&out), include_str!("fixtures/diff_report.json"));
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn identical_files_report_no_differences_and_exit_with_0() {
    let out = run(&["diff", BASELINE, BASELINE]);

    assert_eq!(stdout(&out), "No differences.\n");
    assert_eq!(out.status.code(), Some(0));
}

#[test]
fn identical_files_as_json_have_an_empty_list() {
    let out = run(&["diff", BASELINE, BASELINE, "--json"]);
    let document: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();

    assert_eq!(document["differences"], serde_json::json!([]));
    assert_eq!(out.status.code(), Some(0));
}

#[test]
fn a_broadcast_row_recognised_since_the_baseline_is_reported_as_changed() {
    let out = run(&["diff", BROADCAST_BEFORE, BROADCAST_AFTER]);

    assert!(
        stdout(&out).contains("reachable from: unknown -> LAN"),
        "{}",
        stdout(&out)
    );
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn a_broadcast_row_is_quiet_once_the_baseline_is_saved_again() {
    let out = run(&["diff", BROADCAST_AFTER, BROADCAST_AFTER]);

    assert_eq!(stdout(&out), "No differences.\n");
    assert_eq!(out.status.code(), Some(0));
}

#[test]
fn ignored_ports_leave_the_table_and_a_note_says_how_many() {
    let out = run(&["diff", BASELINE, CURRENT, "--ignore", "3306,5000-6000"]);
    let text = stdout(&out);

    assert!(
        text.contains("note: --ignore left out 2 differences\n"),
        "{text}"
    );
    assert!(!text.contains("mysqld"), "{text}");
    assert!(!text.contains("5353"), "{text}");
    assert!(text.contains("changed "), "{text}");
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn the_udp_note_goes_with_the_last_udp_row() {
    let out = run(&["diff", BASELINE, CURRENT, "--ignore", "5353"]);
    let text = stdout(&out);

    assert!(text.contains("--ignore left out 1 difference\n"), "{text}");
    assert!(!text.contains("a UDP client"), "{text}");
}

#[test]
fn a_change_that_is_only_on_ignored_ports_exits_with_0() {
    let out = run(&[
        "diff",
        BROADCAST_BEFORE,
        BROADCAST_AFTER,
        "--ignore",
        "5137",
    ]);

    assert_eq!(
        stdout(&out),
        "No differences.\n\nnote: --ignore left out 1 difference\n"
    );
    assert_eq!(out.status.code(), Some(0));
}

#[test]
fn an_ignored_port_without_a_difference_is_not_counted_but_the_filter_shows() {
    let out = run(&["diff", BASELINE, BASELINE, "--ignore", "22"]);

    assert_eq!(
        stdout(&out),
        "No differences.\n\nnote: --ignore left out 0 differences\n"
    );
    assert_eq!(out.status.code(), Some(0));
}

#[test]
fn facts_lost_still_fail_when_every_row_is_ignored() {
    let out = run(&["diff", BASELINE, CURRENT, "--ignore", "22,3306,5353,8443"]);

    assert!(
        stdout(&out).starts_with("No differences in the rows.\n"),
        "{}",
        stdout(&out)
    );
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn json_counts_what_the_filter_left_out() {
    let out = run(&["diff", BASELINE, CURRENT, "--ignore", "5353", "--json"]);
    let document: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();

    assert_eq!(document["ignored"], 1);
    assert_eq!(document["differences"].as_array().unwrap().len(), 3);
}

#[test]
fn a_bad_ignore_value_exits_with_2_and_says_why() {
    let out = run(&["diff", BASELINE, CURRENT, "--ignore", "http"]);

    assert_eq!(stdout(&out), "");
    assert!(stderr(&out).contains("is not a port"), "{}", stderr(&out));
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn facts_lost_since_the_baseline_fail_even_with_identical_rows() {
    let out = run(&[
        "diff",
        "tests/fixtures/scan_report.json",
        "tests/fixtures/diff_same_rows_no_docker.json",
    ]);

    assert!(stdout(&out).starts_with("No differences in the rows.\n"));
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn a_missing_baseline_exits_with_2_and_names_the_file() {
    let out = run(&["diff", "/nonexistent/baseline.json", CURRENT]);

    assert_eq!(stdout(&out), "");
    assert!(
        stderr(&out).starts_with("error: could not read /nonexistent/baseline.json: "),
        "{}",
        stderr(&out)
    );
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn a_second_file_that_cannot_be_used_exits_with_2() {
    let out = run(&["diff", BASELINE, "tests/fixtures/probe_report.json"]);

    assert_eq!(stdout(&out), "");
    assert!(
        stderr(&out).contains("it is not a `reachmap scan --json` document"),
        "{}",
        stderr(&out)
    );
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn another_schema_version_exits_with_2_and_says_what_to_do() {
    let out = run(&["diff", "tests/fixtures/diff_schema_2.json", CURRENT]);

    assert_eq!(
        stderr(&out),
        "error: could not use tests/fixtures/diff_schema_2.json: schema_version 2 is not \
         supported, this reachmap reads version 1; save it again with `reachmap scan --json`\n"
    );
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn help_lists_the_diff_command() {
    assert!(stdout(&run(&["--help"])).contains("diff"));
}

#[cfg(not(target_os = "linux"))]
#[test]
fn one_file_needs_a_scan_so_it_exits_with_2_off_linux() {
    let out = run(&["diff", BASELINE]);

    assert_eq!(stdout(&out), "");
    assert!(stderr(&out).contains("Linux only"), "{}", stderr(&out));
    assert_eq!(out.status.code(), Some(2));
}

#[cfg(target_os = "linux")]
#[test]
fn one_file_compares_it_with_a_live_scan() {
    let out = run(&["diff", BASELINE, "--json"]);
    let document: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();

    assert_eq!(document["schema_version"], 1);
    assert!(document["differences"].is_array());
}
