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
use std::time::Duration;

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
use reachmap::pf::{PfCommand, PfReport, PfRunner, SocketTarget, collect_with, parse_ifconfig};
use reachmap::probe::claims;
use reachmap::scan::{ApplicationFirewall, InterfacesError, MacosReport, join, parse_tables};
use reachmap::service::Process;
use reachmap::socket::{AddressFamily, Endpoint, ListeningSocket, Protocol, SocketOptions};
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
            subnet_broadcast: None,
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

enum MacosFixtureMode {
    Disabled,
    Enabled,
    Denied,
}

struct MacosPfFixtureRunner {
    mode: MacosFixtureMode,
}

fn exit_status_one() -> ExitStatus {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        ExitStatus::from_raw(1 << 8)
    }
    #[cfg(not(unix))]
    {
        ExitStatus::default()
    }
}

impl PfRunner for MacosPfFixtureRunner {
    fn run(&mut self, command: PfCommand<'_>, _timeout: Duration) -> Result<String, CollectError> {
        match (&self.mode, command) {
            (MacosFixtureMode::Denied, PfCommand::Info) => Err(CollectError::CommandFailed {
                command: "/sbin/pfctl -s info".to_owned(),
                status: exit_status_one(),
                stderr: "pfctl: /dev/pf: Operation not permitted".to_owned(),
            }),
            (MacosFixtureMode::Disabled, PfCommand::Info) => {
                Ok(include_str!("fixtures/pf/pfctl_info_disabled.txt").to_owned())
            }
            (_, PfCommand::Info) => {
                Ok(include_str!("fixtures/pf/pfctl_info_enabled.txt").to_owned())
            }
            (_, PfCommand::MainRules) => {
                Ok(include_str!("fixtures/pf/default_block.txt").to_owned())
            }
            (_, PfCommand::Interfaces) => {
                Ok(include_str!("fixtures/pf/pfctl_interfaces_skip_lo0.txt").to_owned())
            }
            (_, PfCommand::RootAnchors) => {
                Ok(include_str!("fixtures/pf/pfctl_anchors_default.txt").to_owned())
            }
            (_, PfCommand::AnchorRules(_)) => Ok(String::new()),
            (_, PfCommand::AnchorChildren("com.apple")) => {
                Ok(include_str!("fixtures/pf/pfctl_anchors_com_apple.txt").to_owned())
            }
            (_, PfCommand::AnchorChildren(_)) => Ok(String::new()),
        }
    }
}

fn macos_fixture_sockets() -> Vec<(Endpoint, Process)> {
    let worker = Process {
        pid: 42,
        name: "worker".to_owned(),
    };
    vec![
        (
            Endpoint {
                port: 8080,
                protocol: Protocol::Tcp,
                address: "127.0.0.1".parse().unwrap(),
            },
            worker.clone(),
        ),
        (
            Endpoint {
                port: 8443,
                protocol: Protocol::Tcp,
                address: "192.0.2.10".parse().unwrap(),
            },
            worker,
        ),
    ]
}

fn macos_pf_report(mode: MacosFixtureMode, sockets: &[(Endpoint, Process)]) -> PfReport {
    let targets: Vec<SocketTarget> = sockets
        .iter()
        .map(|(endpoint, _)| SocketTarget {
            endpoint: *endpoint,
            zone: None,
        })
        .collect();
    let ifaces = parse_ifconfig(include_str!("fixtures/pf/ifconfig_macos.txt"));
    let collected = collect_with(&mut MacosPfFixtureRunner { mode });
    PfReport::evaluate(collected, &targets, Ok(&ifaces))
}

#[test]
fn macos_pf_reports_match_snapshots_and_stay_compatible_with_diff_and_probe() {
    let sockets = macos_fixture_sockets();
    let cases = [
        (
            MacosFixtureMode::Disabled,
            ApplicationFirewall::Enabled,
            include_str!("fixtures/pf/scan_report_macos_disabled.json"),
        ),
        (
            MacosFixtureMode::Enabled,
            ApplicationFirewall::Disabled,
            include_str!("fixtures/pf/scan_report_macos_enabled.json"),
        ),
        (
            MacosFixtureMode::Denied,
            ApplicationFirewall::Enabled,
            include_str!("fixtures/pf/scan_report_macos_unknown.json"),
        ),
    ];
    for (mode, firewall, expected) in cases {
        let pf = macos_pf_report(mode, &sockets);
        let report = MacosReport::scan_report(sockets.clone(), firewall, Some(pf), None);
        let json = render(&report).unwrap();
        assert_eq!(json, expected);
        assert!(parse(&json).is_ok());
        assert!(claims::parse(&json).is_ok());
    }

    let legacy = include_str!("fixtures/pf/scan_report_macos_legacy.json");
    assert!(parse(legacy).is_ok());
    assert!(claims::parse(legacy).is_ok());
    let legacy_doc: serde_json::Value = serde_json::from_str(legacy).unwrap();
    let macos: MacosReport = serde_json::from_value(legacy_doc["macos"].clone()).unwrap();
    assert_eq!(macos.pf, None);
}
