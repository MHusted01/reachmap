//! Snapshot tests of `reachmap scan --json`: fixture input goes through the
//! same join as a real scan, and the JSON must match the expected file byte
//! for byte. A failure here means the documented shape in `docs/json.md`
//! changed: update both on purpose, and raise `schema_version` if scripts
//! would break.

// Test helpers may panic: a failed test should stop loudly.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::HashMap;
use std::io;
use std::process::ExitStatus;

use reachmap::baseline::parse;
use reachmap::collect::{CollectError, ProcessFds, RawProcess, RawTable};
use reachmap::docker::DockerError;
use reachmap::firewall::{DockerUserChain, Firewall};
use reachmap::json::render;
use reachmap::network::{HostAddress, HostInterfaces};
use reachmap::parse::docker::parse_docker_inspect;
use reachmap::parse::ip_addr::parse_ip_addr;
use reachmap::parse::iptables::parse_docker_user;
use reachmap::parse::tailscale::parse_serve_status;
use reachmap::parse::ufw::parse_ufw_conf;
use reachmap::scan::{InterfacesError, join, parse_tables};
use reachmap::socket::{AddressFamily, ListeningSocket, Protocol, SocketOptions};
use reachmap::socket_options::{OptionsReport, SocketOptionsError};
use reachmap::tailscale::TailscaleError;

const TCP: &str = include_str!("fixtures/proc_net_tcp.txt");
const UDP: &str = include_str!("fixtures/proc_net_udp.txt");
const DOCKER: &str = include_str!("fixtures/docker_inspect.json");
const IP_ADDR: &str = include_str!("fixtures/ip_addr.json");
const UFW_ENABLED: &str = include_str!("fixtures/ufw_enabled.conf");
const UFW_DISABLED: &str = include_str!("fixtures/ufw_disabled.conf");
const DOCKER_USER: &str = include_str!("fixtures/iptables_docker_user.txt");

fn sockets() -> Vec<ListeningSocket> {
    parse_tables(&[
        RawTable {
            family: AddressFamily::Ipv4,
            protocol: Protocol::Tcp,
            path: "/proc/net/tcp".into(),
            text: TCP.to_string(),
        },
        RawTable {
            family: AddressFamily::Ipv4,
            protocol: Protocol::Udp,
            path: "/proc/net/udp".into(),
            text: UDP.to_string(),
        },
    ])
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
    let options = OptionsReport {
        by_inode: HashMap::from([(
            21345,
            SocketOptions {
                bound_device: None,
                ipv6_only: false,
            },
        )]),
        error: None,
    };
    let report = join(
        sockets(),
        &open_files(),
        Ok(parse_ip_addr(IP_ADDR).unwrap()),
        Ok(parse_docker_inspect(DOCKER).unwrap()),
        Ok(Vec::new()),
        options,
        &firewall,
    );

    assert_eq!(
        render(&report).unwrap(),
        include_str!("fixtures/scan_report.json")
    );
}

#[test]
fn a_scan_with_a_funnel_matches_the_snapshot() {
    let firewall = Firewall {
        ufw: parse_ufw_conf(UFW_DISABLED),
        docker_user: None,
    };
    let shared = parse_serve_status(
        r#"{
            "TCP": {"443": {"HTTPS": true}},
            "Web": {"host.example.ts.net:443": {"Handlers": {"/": {"Proxy": "http://127.0.0.1:22"}}}},
            "AllowFunnel": {"host.example.ts.net:443": true}
        }"#,
    )
    .unwrap();
    let sockets = sockets().into_iter().take(1).collect();

    let report = join(
        sockets,
        &open_files(),
        Ok(parse_ip_addr(IP_ADDR).unwrap()),
        Ok(Vec::new()),
        Ok(shared),
        OptionsReport::default(),
        &firewall,
    );

    let json = render(&report).unwrap();
    assert_eq!(json, include_str!("fixtures/scan_report_tailscale.json"));
    // `diff` must be able to read a saved scan with the nested reason.
    assert!(parse(&json).is_ok());
}

#[test]
fn a_scan_with_a_share_without_a_row_matches_the_snapshot() {
    let firewall = Firewall {
        ufw: parse_ufw_conf(UFW_DISABLED),
        docker_user: None,
    };
    let shared = parse_serve_status(
        r#"{
            "TCP": {"443": {"HTTPS": true}},
            "Web": {"host.example.ts.net:443": {"Handlers": {"/": {"Path": "/srv/site"}}}},
            "AllowFunnel": {"host.example.ts.net:443": true}
        }"#,
    )
    .unwrap();
    let host = HostInterfaces {
        addresses: vec![HostAddress {
            interface: "tailscale0".to_string(),
            ip: "100.64.0.1".parse().unwrap(),
            broadcast: None,
        }],
        ..HostInterfaces::default()
    };

    let report = join(
        Vec::new(),
        &open_files(),
        Ok(host),
        Ok(Vec::new()),
        Ok(shared),
        OptionsReport::default(),
        &firewall,
    );

    let json = render(&report).unwrap();
    assert_eq!(
        json,
        include_str!("fixtures/scan_report_tailscale_share.json")
    );
    // `diff` must be able to read a saved scan with the new values.
    assert!(parse(&json).is_ok());
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
    let options = OptionsReport {
        error: Some(SocketOptionsError::Open(CollectError::SockDiag {
            action: "open",
            source: io::Error::other("not supported"),
        })),
        ..OptionsReport::default()
    };
    let sockets = sockets().into_iter().take(1).collect();

    let report = join(
        sockets,
        &ProcessFds::default(),
        Err(interfaces),
        Err(DockerError::NotInstalled),
        Err(TailscaleError::Collect(CollectError::CommandFailed {
            command: "tailscale serve status --json".to_string(),
            status: ExitStatus::default(),
            stderr: "Failed to connect to local Tailscale daemon".to_string(),
        })),
        options,
        &firewall,
    );

    assert_eq!(
        render(&report).unwrap(),
        include_str!("fixtures/scan_report_degraded.json")
    );
}
