//! End-to-end tests: run the compiled `reachmap` binary like a user would.

// Test helpers may panic: a failed test should stop loudly.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::process::{Command, Output};

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_reachmap"))
        .args(args)
        .output()
        .expect("the reachmap binary runs")
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
fn version_flag_prints_name_and_version() {
    let out = run(&["--version"]);
    assert!(out.status.success());
    assert_eq!(
        stdout(&out).trim(),
        format!("reachmap {}", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn help_lists_the_scan_command() {
    let out = run(&["--help"]);
    assert!(out.status.success());
    assert!(stdout(&out).contains("scan"), "help was: {}", stdout(&out));
}

#[test]
fn unknown_arguments_print_usage_and_exit_with_2() {
    let out = run(&["--nope"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("Usage: reachmap"));
}

#[test]
fn no_command_prints_usage_and_exits_with_2() {
    let out = run(&[]);
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("Usage: reachmap"));
}

#[cfg(target_os = "linux")]
#[test]
fn scan_prints_a_table_or_the_empty_message() {
    let out = run(&["scan"]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let output = stdout(&out);
    let first_line = output.lines().next().unwrap_or_default();
    // Compare words, not spacing: column widths depend on the ports found.
    let is_header = first_line
        .split_whitespace()
        .eq(["PORT", "PROTO", "ADDRESS", "SERVICE"]);
    assert!(
        is_header || first_line == reachmap::table::NO_SOCKETS,
        "unexpected first line: {first_line:?}"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn scan_finds_a_socket_the_test_is_listening_on_and_names_this_process() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    let out = run(&["scan"]);

    // The test process owns the socket, so no root is needed to see the
    // owner. Its name is the test binary's (cut to 15 bytes by the kernel),
    // so only the pid is compared exactly.
    let output = stdout(&out);
    let row = output
        .lines()
        .map(|line| line.split_whitespace().collect::<Vec<_>>())
        .find(|words| words.starts_with(&[port.to_string().as_str(), "tcp", "127.0.0.1"]))
        .unwrap_or_else(|| panic!("port {port} missing from:\n{output}"));
    assert_eq!(
        row.last().copied(),
        Some(format!("({})", std::process::id()).as_str()),
        "row for port {port}: {row:?}"
    );
}

#[cfg(not(target_os = "linux"))]
#[test]
fn scan_explains_it_is_linux_only_and_fails() {
    let out = run(&["scan"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains("Linux only for now"),
        "stderr: {}",
        stderr(&out)
    );
}
