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

#[test]
fn scan_help_lists_the_json_flag() {
    let out = run(&["scan", "--help"]);
    assert!(out.status.success());
    assert!(stdout(&out).contains("--json"), "help: {}", stdout(&out));
}

#[cfg(target_os = "linux")]
#[test]
fn scan_prints_a_table_or_the_empty_message() {
    let out = run(&["scan"]);
    // A host with UFW and Docker may exit with 1 and warnings; the table below
    // tells that apart from a scan that failed.
    assert!(
        matches!(out.status.code(), Some(0 | 1)),
        "stderr: {}",
        stderr(&out)
    );
    let output = stdout(&out);
    let first_line = output.lines().next().unwrap_or_default();
    // Compare words, not spacing: column widths depend on the ports found.
    let is_header = first_line.split_whitespace().eq([
        "PORT",
        "PROTO",
        "ADDRESS",
        "SERVICE",
        "REACHABLE",
        "FROM",
        "WHY",
    ]);
    assert!(
        is_header || first_line == reachmap::table::NO_SOCKETS,
        "unexpected first line: {first_line:?}"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn scan_finds_a_socket_the_test_is_listening_on_with_its_process_and_reach() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    let out = run(&["scan"]);

    // The test process owns the socket, so no root is needed to see the
    // owner. Its name is the test binary's (cut to 15 bytes by the kernel),
    // so only the pid is compared exactly. A loopback socket needs no
    // interface facts, so its verdict is known even without `ip`.
    let output = stdout(&out);
    let row = output
        .lines()
        .find(|line| {
            line.split_whitespace()
                .take(3)
                .eq([port.to_string().as_str(), "tcp", "127.0.0.1"])
        })
        .unwrap_or_else(|| panic!("port {port} missing from:\n{output}"));
    let pid = format!("({})", std::process::id());
    assert!(
        row.contains(&format!(" {pid}  ")),
        "no pid {pid} in row for port {port}: {row:?}"
    );
    // Columns are padded to the widest value on this host, so compare words.
    let words: Vec<&str> = row.split_whitespace().collect();
    assert!(
        words.ends_with(&["this", "host", "loopback", "address"]),
        "row for port {port}: {row:?}"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn scan_json_is_one_document_with_the_socket_the_test_is_listening_on() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    let out = run(&["scan", "--json"]);

    assert!(
        matches!(out.status.code(), Some(0 | 1)),
        "stderr: {}",
        stderr(&out)
    );
    let document: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(document["schema_version"], reachmap::json::SCHEMA_VERSION);
    // As in the table: a warning, and nothing else, makes a finished scan exit with 1.
    let has_warnings = !document["warnings"].as_array().unwrap().is_empty();
    assert_eq!(out.status.code(), Some(i32::from(has_warnings)));
    let row = document["ports"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["port"] == port && row["address"] == "127.0.0.1")
        .unwrap_or_else(|| panic!("port {port} missing from: {document}"));
    assert_eq!(row["service"]["pid"], std::process::id());
    assert_eq!(row["reason"]["kind"], "loopback");
}

#[cfg(not(target_os = "linux"))]
#[test]
fn scan_json_prints_nothing_on_stdout_when_the_scan_fails() {
    let out = run(&["scan", "--json"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty(), "stdout: {}", stdout(&out));
    assert!(stderr(&out).contains("Linux only for now"));
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
