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

def bind(kind, family, address, device=None, ipv6_only=None):
    s = socket.socket(family, kind)
    if ipv6_only is not None:
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, int(ipv6_only))
    if device:
        s.setsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE, device.encode())
    s.bind((address, 0))
    return s

def listen(*args, **options):
    s = bind(socket.SOCK_STREAM, *args, **options)
    s.listen()
    return s

def datagram(*args, **options):
    return bind(socket.SOCK_DGRAM, *args, **options)

connected = datagram(socket.AF_INET, "127.0.0.1")
connected.connect(("127.0.0.1", 9))

sockets = [
    listen(socket.AF_INET, "0.0.0.0"),
    listen(socket.AF_INET, "0.0.0.0", device="lo"),
    listen(socket.AF_INET6, "::", ipv6_only=False),
    listen(socket.AF_INET6, "::", ipv6_only=True),
    datagram(socket.AF_INET, "0.0.0.0"),
    datagram(socket.AF_INET, "0.0.0.0", device="lo"),
    datagram(socket.AF_INET6, "::", ipv6_only=False),
    datagram(socket.AF_INET6, "::", ipv6_only=True),
    datagram(socket.AF_INET, "239.255.0.1"),
    connected,
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

/// The rows of `protocol` on `port`.
fn rows<'a>(report: &'a Value, protocol: &str, port: u64) -> Vec<&'a Value> {
    report["ports"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| row["port"] == port && row["protocol"] == protocol)
        .collect()
}

/// The reason given for the only socket of `protocol` on `port`.
fn reason<'a>(report: &'a Value, protocol: &str, port: u64) -> &'a Value {
    match rows(report, protocol, port)[..] {
        [row] => &row["reason"],
        ref other => panic!("expected one {protocol} row on port {port}, got {other:?}"),
    }
}

/// Asserts what the kernel reported on four sockets of one protocol.
fn assert_kernel_facts(report: &Value, protocol: &str, ports: &[u64]) {
    let [plain, on_lo, dual_stack, ipv6_only] = ports[..] else {
        panic!("expected four ports, got {ports:?}");
    };
    assert_eq!(
        reason(report, protocol, plain),
        &json!({"kind": "all_addresses", "covers": "ipv4", "checked": true})
    );
    assert_eq!(
        reason(report, protocol, on_lo),
        &json!({"kind": "on_interfaces", "interfaces": ["lo"]})
    );
    assert_eq!(
        reason(report, protocol, dual_stack),
        &json!({"kind": "all_addresses", "covers": "ipv4_and_ipv6", "checked": true})
    );
    // `all_addresses`, or `no_addresses` on a host without IPv6 addresses.
    assert_eq!(
        reason(report, protocol, ipv6_only)["covers"],
        "ipv6",
        "{}",
        reason(report, protocol, ipv6_only)
    );
}

#[test]
fn verdicts_use_what_the_kernel_reports_about_real_sockets() {
    let listeners = Listeners::start();
    let [tcp @ .., multicast, connected] = &listeners.ports[..] else {
        panic!("expected more ports, got {:?}", listeners.ports);
    };
    let (tcp, udp) = tcp.split_at(4);

    let report = scan();

    let errors = report["collector_errors"].as_array().unwrap();
    let failed = |name: &str| errors.iter().any(|error| error["collector"] == name);
    assert!(!failed("socket_options"), "{errors:?}");
    assert!(!failed("interfaces"), "{errors:?}");
    assert_kernel_facts(&report, "tcp", tcp);
    assert_kernel_facts(&report, "udp", udp);
    assert_eq!(
        reason(&report, "udp", *multicast),
        &json!({"kind": "multicast"})
    );
    assert_eq!(rows(&report, "udp", *connected), Vec::<&Value>::new());
}
