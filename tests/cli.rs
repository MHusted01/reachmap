//! End-to-end tests: run the compiled `reachmap` binary like a user would.

// Test helpers may panic: a failed test should stop loudly.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::fs;
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener};
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::{Mutex, MutexGuard, PoisonError, TryLockError};

use socket2::{Domain, Protocol, Socket, Type};

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

#[test]
fn scan_help_lists_the_tailscale_routes_flag() {
    let out = run(&["scan", "--help"]);
    assert!(out.status.success());
    assert!(stdout(&out).contains("--tailscale-routes"));
}

#[test]
fn tailscale_routes_has_its_own_output_mode() {
    for extra in [&["--json"][..], &["--snapshot", "--host-ref", "test"][..]] {
        let args = [&["scan", "--tailscale-routes"][..], extra].concat();
        let out = run(&args);
        assert_eq!(out.status.code(), Some(2));
        assert!(stderr(&out).contains("cannot be used with"));
    }
}

#[test]
fn egress_requires_explicit_observers() {
    let out = run(&["egress", "app"]);
    assert_eq!(out.status.code(), Some(2));
    let error = stderr(&out);
    assert!(error.contains("--ip-host"), "{error}");
    assert!(error.contains("--dns-name"), "{error}");
}

#[test]
fn egress_rejects_non_dns_observer_names() {
    let out = run(&[
        "egress",
        "app",
        "--ip-host",
        "echo.example/path",
        "--dns-name",
        "resolver.example",
    ]);
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("DNS name"), "{}", stderr(&out));
}

#[test]
fn egress_rejects_a_container_name_that_is_an_api_path() {
    let out = run(&[
        "egress",
        "app/../../other",
        "--ip-host",
        "echo.example",
        "--dns-name",
        "resolver.example",
    ]);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        stderr(&out).contains("container name or ID"),
        "{}",
        stderr(&out)
    );
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
    let (port, _listener) = open_port();

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
fn scan_lists_a_udp_socket_with_its_owner_and_the_note() {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = socket.local_addr().unwrap().port();

    let out = run(&["scan"]);

    let output = stdout(&out);
    let row = output
        .lines()
        .find(|line| {
            line.split_whitespace()
                .take(3)
                .eq([port.to_string().as_str(), "udp", "127.0.0.1"])
        })
        .unwrap_or_else(|| panic!("port {port} missing from:\n{output}"));
    let pid = format!("({})", std::process::id());
    assert!(row.contains(&pid), "no pid {pid} in row: {row:?}");
    let notes = output
        .lines()
        .filter(|line| line.starts_with("note: UDP"))
        .count();
    assert_eq!(notes, 1, "output was:\n{output}");
}

#[cfg(target_os = "linux")]
#[test]
fn scan_json_is_one_document_with_the_socket_the_test_is_listening_on() {
    let (port, _listener) = open_port();

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

#[cfg(target_os = "macos")]
#[test]
fn macos_scan_reports_ipv4_and_ipv6_sockets_and_their_owner() {
    use std::net::UdpSocket;

    let tcp4 = TcpListener::bind("127.0.0.1:0").unwrap();
    let tcp6 = TcpListener::bind("[::1]:0").unwrap();
    let udp4 = UdpSocket::bind("127.0.0.1:0").unwrap();
    let udp6 = UdpSocket::bind("[::1]:0").unwrap();
    let sockets = [
        (tcp4.local_addr().unwrap(), "tcp", "tcp"),
        (tcp6.local_addr().unwrap(), "tcp", "tcp6"),
        (udp4.local_addr().unwrap(), "udp", "udp"),
        (udp6.local_addr().unwrap(), "udp", "udp6"),
    ];
    let pid = std::process::id();
    let out = run(&["scan", "--json"]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let ports = report["ports"].as_array().unwrap();
    assert!(matches!(
        report["macos"]["application_firewall"]["state"].as_str(),
        Some("enabled" | "disabled" | "unknown")
    ));
    assert!(report["macos"]["socket_visibility"].is_string());
    let out = run(&["scan"]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let table = stdout(&out);
    assert!(table.contains("macOS application firewall"));
    assert!(table.contains("processes lsof can inspect"));
    for (address, protocol, table_protocol) in sockets {
        let row = ports.iter().find(|row| {
            row["port"] == address.port()
                && row["address"] == address.ip().to_string()
                && row["protocol"] == protocol
                && row["service"]["pid"] == pid
        });
        let row = row.unwrap_or_else(|| panic!("missing {protocol} {address} for PID {pid}"));
        assert_eq!(row["service"]["kind"], "process");
        assert!(
            row["service"]["name"]
                .as_str()
                .is_some_and(|name| !name.is_empty() && name != "unknown")
        );
        assert_eq!(row["reach"]["networks"], serde_json::json!(["this_host"]));
        assert!(table.lines().any(|line| {
            line.split_whitespace().take(3).eq([
                address.port().to_string().as_str(),
                table_protocol,
                address.ip().to_string().as_str(),
            ]) && line.contains(&format!("({pid})"))
        }));
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
#[test]
fn scan_json_prints_nothing_on_stdout_when_the_scan_fails() {
    let out = run(&["scan", "--json"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty(), "stdout: {}", stdout(&out));
    assert!(stderr(&out).contains("supports Linux and macOS"));
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
#[test]
fn scan_explains_which_systems_it_supports_and_fails() {
    let out = run(&["scan"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains("supports Linux and macOS"),
        "stderr: {}",
        stderr(&out)
    );
}

#[test]
fn probe_needs_a_port_list_or_a_scan() {
    let out = run(&["probe", "192.0.2.1"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("--ports"), "stderr: {}", stderr(&out));
    assert!(stderr(&out).contains("--scan"), "stderr: {}", stderr(&out));
}

#[test]
fn probe_refuses_ports_and_scan_together() {
    let out = run(&["probe", "192.0.2.1", "--ports", "22", "--scan", "scan.json"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        stderr(&out).contains("cannot be used with"),
        "stderr: {}",
        stderr(&out)
    );
}

#[test]
fn probe_refuses_from_without_a_scan() {
    let out = run(&["probe", "192.0.2.1", "--ports", "22", "--from", "lan"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        stderr(&out).contains("cannot be used with"),
        "stderr: {}",
        stderr(&out)
    );
}

#[test]
fn probe_refuses_an_unknown_network_and_names_the_valid_ones() {
    let out = run(&["probe", "192.0.2.1", "--scan", "s.json", "--from", "moon"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("tailnet"), "stderr: {}", stderr(&out));
}

/// Writes a scan document for this test and returns its path.
fn scan_file(name: &str, content: &str) -> PathBuf {
    let path = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    fs::write(&path, content).unwrap();
    path
}

/// One TCP row, reachable from `networks` (in JSON).
fn row(port: u16, networks: &str) -> String {
    format!(
        r#"{{"port": {port}, "protocol": "tcp", "address": "0.0.0.0",
            "reach": {{"kind": "from", "networks": [{networks}]}},
            "reason": {{"kind": "all_addresses"}}}}"#
    )
}

fn scan_of(rows: &[String]) -> String {
    format!(
        r#"{{"schema_version": 1, "ports": [{}], "collector_errors": []}}"#,
        rows.join(",")
    )
}

#[path = "cli/host_input_snapshot.rs"]
mod host_input_snapshot;
#[path = "cli/inbound_path.rs"]
mod inbound_path;

// All test listeners take this lock when binding. A closed-port test keeps it
// through the probe because macOS allows a listener to bind a connected port.
// The lock protects no data, so a test panic cannot leave inconsistent state.
static PORT_ALLOCATION: Mutex<()> = Mutex::new(());

fn allocate_listener() -> (TcpListener, MutexGuard<'static, ()>) {
    let allocation = PORT_ALLOCATION
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    (listener, allocation)
}

/// An open port, and the listener that keeps it open.
fn open_port() -> (u16, TcpListener) {
    let (listener, _allocation) = allocate_listener();
    (listener.local_addr().unwrap().port(), listener)
}

struct ClosedPortReservation {
    _socket: Socket,
    _peer: TcpListener,
    _allocation: MutexGuard<'static, ()>,
}

/// Uses a port as the source of an outgoing TCP connection, without listening on it.
/// Allocate any other fixture ports first. The reservation holds the allocation
/// lock until it is dropped, so another call to either helper would block.
fn closed_port() -> (u16, ClosedPortReservation) {
    let (peer, allocation) = allocate_listener();
    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).unwrap();
    socket
        .bind(&SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0).into())
        .unwrap();
    socket.connect(&peer.local_addr().unwrap().into()).unwrap();
    let port = socket
        .local_addr()
        .unwrap()
        .as_socket_ipv4()
        .unwrap()
        .port();
    (
        port,
        ClosedPortReservation {
            _socket: socket,
            _peer: peer,
            _allocation: allocation,
        },
    )
}

#[test]
fn closed_port_refuses_connections_while_listener_allocation_is_locked() {
    let (port, _reservation) = closed_port();
    assert!(matches!(
        PORT_ALLOCATION.try_lock(),
        Err(TryLockError::WouldBlock)
    ));

    let port = port.to_string();
    let out = run(&["probe", "127.0.0.1", "--ports", &port]);

    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr(&out));
    assert!(
        stdout(&out).contains(" closed\n"),
        "stdout: {}",
        stdout(&out)
    );
}

#[test]
fn probe_scan_that_matches_exits_with_0_and_says_so() {
    let (open, _listener) = open_port();
    let (closed, _reservation) = closed_port();
    let scan = scan_of(&[row(open, r#""this_host""#), row(closed, r#""lan""#)]);
    let path = scan_file("probe_scan_matches.json", &scan);

    let out = run(&["probe", "127.0.0.1", "--scan", path.to_str().unwrap()]);

    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr(&out));
    let text = stdout(&out);
    assert!(text.contains(" open\n"), "stdout: {text}");
    assert!(
        text.contains("compared with the scan from this host"),
        "stdout: {text}"
    );
    assert!(text.ends_with(": no differences\n"), "stdout: {text}");
}

#[test]
fn probe_scan_reports_both_kinds_of_difference_and_exits_with_1() {
    let (open, _listener) = open_port();
    let (closed, _reservation) = closed_port();
    let scan = scan_of(&[row(open, r#""lan""#), row(closed, r#""this_host""#)]);
    let path = scan_file("probe_scan_differs.json", &scan);

    let out = run(&["probe", "127.0.0.1", "--scan", path.to_str().unwrap()]);

    assert_eq!(out.status.code(), Some(1), "stderr: {}", stderr(&out));
    let text = stdout(&out);
    assert!(
        text.contains(&format!("{open}")) && text.contains("connected, but the scan says"),
        "stdout: {text}"
    );
    assert!(
        text.contains("did not connect, but the scan says"),
        "stdout: {text}"
    );
}

#[test]
fn probe_scan_from_overrides_the_network_of_the_address() {
    let (open, _listener) = open_port();
    let scan = scan_of(&[row(open, r#""this_host""#)]);
    let path = scan_file("probe_scan_from.json", &scan);
    let path = path.to_str().unwrap();

    let guessed = run(&["probe", "127.0.0.1", "--scan", path]);
    let chosen = run(&["probe", "127.0.0.1", "--scan", path, "--from", "lan"]);

    assert_eq!(guessed.status.code(), Some(0), "{}", stdout(&guessed));
    assert_eq!(chosen.status.code(), Some(1), "{}", stdout(&chosen));
    assert!(
        stdout(&chosen).contains("compared with the scan from LAN\n"),
        "stdout: {}",
        stdout(&chosen)
    );
}

#[test]
fn probe_scan_json_has_the_differences_and_exits_with_1() {
    let (open, _listener) = open_port();
    let scan = scan_of(&[row(open, r#""lan""#)]);
    let path = scan_file("probe_scan_json.json", &scan);

    let out = run(&[
        "probe",
        "127.0.0.1",
        "--scan",
        path.to_str().unwrap(),
        "--json",
    ]);

    assert_eq!(out.status.code(), Some(1), "stderr: {}", stderr(&out));
    let document: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let difference = &document["comparison"]["differences"][0];
    assert_eq!(document["results"][0]["result"]["kind"], "open");
    assert_eq!(document["comparison"]["from"][0], "this_host");
    assert_eq!(difference["kind"], "unexpected_connection");
    assert_eq!(difference["port"], open);
    assert_eq!(difference["from"], "this_host");
}

#[test]
fn probe_json_without_a_scan_has_no_comparison() {
    let (open, _listener) = open_port();
    let port = open.to_string();
    let out = run(&["probe", "127.0.0.1", "--ports", &port, "--json"]);
    let document: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(document.get("comparison").is_none(), "{document}");
}

#[test]
fn probe_scan_prints_no_text_from_the_file() {
    let (open, _listener) = open_port();
    let row = format!(
        r#"{{"port": {open}, "protocol": "tcp", "address": "0.0.0.0",
            "service": {{"kind": "process", "pid": 1, "name": "evil\u001b[2J"}},
            "reach": {{"kind": "from", "networks": ["this_host"]}},
            "reason": {{"kind": "on_interfaces", "interfaces": ["evil\u001b[2J"]}}}}"#
    );
    let path = scan_file("probe_scan_text.json", &scan_of(&[row]));

    let out = run(&["probe", "127.0.0.1", "--scan", path.to_str().unwrap()]);

    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr(&out));
    assert!(!stdout(&out).contains("evil"), "stdout: {}", stdout(&out));
    assert!(!stderr(&out).contains("evil"), "stderr: {}", stderr(&out));
}

#[test]
fn probe_scan_refuses_another_schema_version_before_any_traffic() {
    let path = scan_file(
        "probe_scan_version.json",
        r#"{"schema_version": 2, "rows": []}"#,
    );

    let out = run(&[
        "probe",
        "no-such-host.invalid",
        "--scan",
        path.to_str().unwrap(),
    ]);

    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty(), "stdout: {}", stdout(&out));
    assert!(
        stderr(&out).contains("schema_version 2 is not supported"),
        "stderr: {}",
        stderr(&out)
    );
}

#[test]
fn probe_scan_of_a_missing_file_says_so_and_exits_with_1() {
    let out = run(&["probe", "127.0.0.1", "--scan", "/no/such/scan.json"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty(), "stdout: {}", stdout(&out));
    assert!(
        stderr(&out).contains("error: could not read /no/such/scan.json"),
        "stderr: {}",
        stderr(&out)
    );
}

#[test]
fn probe_scan_without_tcp_ports_says_so_and_exits_with_1() {
    let path = scan_file("probe_scan_empty.json", &scan_of(&[]));
    let out = run(&["probe", "127.0.0.1", "--scan", path.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty(), "stdout: {}", stdout(&out));
    assert!(
        stderr(&out).contains("no TCP ports"),
        "stderr: {}",
        stderr(&out)
    );
}

#[test]
fn probe_refuses_an_invalid_port_list_with_exit_2() {
    let out = run(&["probe", "192.0.2.1", "--ports", "22,ssh"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        stderr(&out).contains("is not a port"),
        "stderr: {}",
        stderr(&out)
    );
}

#[test]
fn probe_refuses_a_concurrency_of_zero_with_exit_2() {
    let out = run(&["probe", "192.0.2.1", "--ports", "22", "--concurrency", "0"]);
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn probe_refuses_a_timeout_of_zero_with_exit_2() {
    let out = run(&["probe", "192.0.2.1", "--ports", "22", "--timeout", "0"]);
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn probe_reports_open_and_closed_ports_and_exits_with_0() {
    let (open, _listener) = open_port();
    let (closed, _reservation) = closed_port();

    let ports = format!("{open},{closed}");
    let out = run(&["probe", "127.0.0.1", "--ports", &ports]);

    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr(&out));
    let text = stdout(&out);
    assert!(text.starts_with("PORT"), "stdout: {text}");
    assert!(text.contains(" open\n"), "stdout: {text}");
    assert!(text.contains(" closed\n"), "stdout: {text}");
}

#[test]
fn probe_json_is_one_document_on_standard_output() {
    let (port, _listener) = open_port();
    let port = port.to_string();

    let out = run(&["probe", "127.0.0.1", "--ports", &port, "--json"]);

    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr(&out));
    let document: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(document["host"], "127.0.0.1");
    assert_eq!(document["results"][0]["result"]["kind"], "open");
}

#[test]
fn probe_of_an_unknown_host_says_so_and_exits_with_1() {
    let out = run(&["probe", "no-such-host.invalid", "--ports", "80"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty(), "stdout: {}", stdout(&out));
    assert!(
        stderr(&out).contains("error: could not resolve no-such-host.invalid"),
        "stderr: {}",
        stderr(&out)
    );
}
