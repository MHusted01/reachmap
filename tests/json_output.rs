//! Snapshot tests of `reachmap scan --json`: fixture input goes through the
//! same join as a real scan, and the JSON must match the expected file byte
//! for byte. A failure here means the documented shape in `docs/json.md`
//! changed: update both on purpose, and raise `schema_version` if scripts
//! would break.

// Test helpers may panic: a failed test should stop loudly.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::HashMap;
use std::io;

use reachmap::collect::{CollectError, ProcessFds, RawProcess, RawTable};
use reachmap::docker::DockerError;
use reachmap::firewall::{DockerUserChain, Firewall};
use reachmap::json::render;
use reachmap::parse::docker::parse_docker_inspect;
use reachmap::parse::ip_addr::parse_ip_addr;
use reachmap::parse::iptables::parse_docker_user;
use reachmap::parse::ufw::parse_ufw_conf;
use reachmap::scan::{InterfacesError, join, parse_tables};
use reachmap::socket::{AddressFamily, ListeningSocket, SocketOptions};
use reachmap::socket_options::SocketOptionsError;

const TCP: &str = include_str!("fixtures/proc_net_tcp.txt");
const DOCKER: &str = include_str!("fixtures/docker_inspect.json");
const IP_ADDR: &str = include_str!("fixtures/ip_addr.json");
const UFW_ENABLED: &str = include_str!("fixtures/ufw_enabled.conf");
const UFW_DISABLED: &str = include_str!("fixtures/ufw_disabled.conf");
const DOCKER_USER: &str = include_str!("fixtures/iptables_docker_user.txt");

fn sockets() -> Vec<ListeningSocket> {
    parse_tables(&[RawTable {
        family: AddressFamily::Ipv4,
        path: "/proc/net/tcp".into(),
        text: TCP.to_string(),
    }])
    .unwrap()
}

/// One visible process, `sshd`, and at least one that could not be inspected.
fn open_files() -> ProcessFds {
    ProcessFds {
        processes: vec![RawProcess {
            pid: 812,
            comm: "sshd\n".to_string(),
            fd_targets: vec!["socket:[21345]".to_string()],
        }],
        permission_denied: true,
        processes_may_be_hidden: false,
    }
}

#[test]
fn a_full_scan_matches_the_snapshot() {
    let firewall = Firewall {
        ufw: parse_ufw_conf(UFW_ENABLED),
        docker_user: Some(parse_docker_user(DOCKER_USER)),
    };
    // The kernel reported on sshd's socket only.
    let options = HashMap::from([(
        21345,
        SocketOptions {
            bound_device: None,
            ipv6_only: false,
        },
    )]);
    let report = join(
        sockets(),
        &open_files(),
        Ok(parse_ip_addr(IP_ADDR).unwrap()),
        Ok(parse_docker_inspect(DOCKER).unwrap()),
        Ok(options),
        &firewall,
    );

    assert_eq!(
        render(&report).unwrap(),
        include_str!("fixtures/scan_report.json")
    );
}

#[test]
fn a_scan_with_missing_collectors_matches_the_snapshot() {
    let firewall = Firewall {
        ufw: parse_ufw_conf(UFW_DISABLED),
        docker_user: Some(DockerUserChain::NoRules),
    };
    let interfaces = InterfacesError::Collect(CollectError::Run {
        command: "ip -j addr".to_string(),
        source: io::Error::new(io::ErrorKind::NotFound, "not found"),
    });
    let options = SocketOptionsError::Collect(CollectError::SockDiag {
        action: "open",
        source: io::Error::other("not supported"),
    });
    let sockets = sockets().into_iter().take(1).collect();

    let report = join(
        sockets,
        &ProcessFds::default(),
        Err(interfaces),
        Err(DockerError::NotInstalled),
        Err(options),
        &firewall,
    );

    assert_eq!(
        render(&report).unwrap(),
        include_str!("fixtures/scan_report_degraded.json")
    );
}
