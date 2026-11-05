//! Runs the binary against real sockets, because only a Linux kernel can
//! answer. A small Python program opens them: it can set `SO_BINDTODEVICE`,
//! which needs no privileges on a socket that is not bound to a device yet.

#![cfg(target_os = "linux")]
// Test helpers may panic: a failed test should stop loudly.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::io::{BufRead, BufReader};
use std::process::{Child, ChildStdin, Command, Stdio};

use serde_json::{Value, json};

/// Opens the listeners on free ports, prints the ports, and stays until its
/// standard input closes.
const LISTENERS: &str = r#"
import socket, sys
SO_BINDTODEVICE = 25

def listen(family, address, device=None, ipv6_only=None):
    s = socket.socket(family, socket.SOCK_STREAM)
    if ipv6_only is not None:
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, int(ipv6_only))
    if device:
        s.setsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE, device.encode())
    s.bind((address, 0))
    s.listen()
    return s

sockets = [
    listen(socket.AF_INET, "0.0.0.0"),
    listen(socket.AF_INET, "0.0.0.0", device="lo"),
    listen(socket.AF_INET6, "::", ipv6_only=False),
    listen(socket.AF_INET6, "::", ipv6_only=True),
]
print(*[s.getsockname()[1] for s in sockets], flush=True)
sys.stdin.read()
"#;

/// The listeners. Closing their standard input ends them.
struct Listeners {
    child: Child,
    stdin: Option<ChildStdin>,
    ports: Vec<u64>,
}

impl Listeners {
    fn start() -> Self {
        let mut child = Command::new("python3")
            .args(["-c", LISTENERS])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("python3 runs");
        let stdin = child.stdin.take();
        let mut line = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        let ports = line
            .split_whitespace()
            .map(|port| port.parse().expect("the program printed ports"))
            .collect();
        Listeners {
            child,
            stdin,
            ports,
        }
    }
}

impl Drop for Listeners {
    fn drop(&mut self) {
        drop(self.stdin.take());
        let _ = self.child.wait();
    }
}

fn scan() -> Value {
    let out = Command::new(env!("CARGO_BIN_EXE_reachmap"))
        .args(["scan", "--json"])
        .output()
        .expect("the reachmap binary runs");
    serde_json::from_slice(&out.stdout).expect("the scan printed JSON")
}

/// The reason given for the only socket on `port`.
fn reason(report: &Value, port: u64) -> &Value {
    let rows = report["ports"].as_array().unwrap();
    let mut on_port = rows.iter().filter(|row| row["port"] == port);
    let row = on_port.next().expect("the scan lists the port");
    assert!(on_port.next().is_none(), "port {port} has one socket");
    &row["reason"]
}

#[test]
fn verdicts_use_what_the_kernel_reports_about_real_sockets() {
    let listeners = Listeners::start();
    let [plain, on_lo, dual_stack, ipv6_only] = listeners.ports[..] else {
        panic!("expected four ports, got {:?}", listeners.ports);
    };

    let report = scan();

    let errors = report["collector_errors"].as_array().unwrap();
    let failed = |name: &str| errors.iter().any(|error| error["collector"] == name);
    assert!(!failed("socket_options"), "{errors:?}");
    assert!(!failed("interfaces"), "{errors:?}");
    assert_eq!(
        reason(&report, plain),
        &json!({"kind": "all_addresses", "covers": "ipv4", "checked": true})
    );
    assert_eq!(
        reason(&report, on_lo),
        &json!({"kind": "on_interfaces", "interfaces": ["lo"]})
    );
    assert_eq!(
        reason(&report, dual_stack),
        &json!({"kind": "all_addresses", "covers": "ipv4_and_ipv6", "checked": true})
    );
    // `all_addresses`, or `no_addresses` on a host without IPv6 addresses.
    assert_eq!(
        reason(&report, ipv6_only)["covers"],
        "ipv6",
        "{}",
        reason(&report, ipv6_only)
    );
}
