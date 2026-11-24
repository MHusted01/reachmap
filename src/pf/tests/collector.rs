use std::collections::BTreeMap;
use std::io;
use std::process::ExitStatus;
use std::time::Duration;

use crate::collect::CollectError;
use crate::pf::{
    CollectedPf, PfCollectError, PfCommand, PfInterfaceVerdict, PfPort, PfReport, PfRunner,
    SocketTarget, Verdict, collect_with, parse_ifconfig,
};
use crate::socket::{AddressFamily, Endpoint, Protocol};

const INFO_DISABLED: &str = include_str!("../../../tests/fixtures/pf/pfctl_info_disabled.txt");
const INFO_ENABLED: &str = include_str!("../../../tests/fixtures/pf/pfctl_info_enabled.txt");
const IFACES_SKIP_LO0: &str =
    include_str!("../../../tests/fixtures/pf/pfctl_interfaces_skip_lo0.txt");
const ANCHORS_DEFAULT: &str = include_str!("../../../tests/fixtures/pf/pfctl_anchors_default.txt");
const ANCHORS_COM_APPLE: &str =
    include_str!("../../../tests/fixtures/pf/pfctl_anchors_com_apple.txt");
const DEFAULT_MACOS: &str = include_str!("../../../tests/fixtures/pf/default_macos.txt");
const DEFAULT_BLOCK: &str = include_str!("../../../tests/fixtures/pf/default_block.txt");
const IFCONFIG_MACOS: &str = include_str!("../../../tests/fixtures/pf/ifconfig_macos.txt");

#[derive(Default)]
struct StubRunner {
    info: Option<Result<String, CollectError>>,
    main_rules: Option<Result<String, CollectError>>,
    interfaces: Option<Result<String, CollectError>>,
    root_anchors: Option<Result<String, CollectError>>,
    anchor_rules: BTreeMap<String, Result<String, CollectError>>,
    anchor_children: BTreeMap<String, Result<String, CollectError>>,
    calls: Vec<String>,
}

impl StubRunner {
    fn enabled_default() -> Self {
        let mut runner = Self {
            info: Some(Ok(INFO_ENABLED.to_owned())),
            main_rules: Some(Ok(DEFAULT_MACOS.to_owned())),
            interfaces: Some(Ok(IFACES_SKIP_LO0.to_owned())),
            root_anchors: Some(Ok(ANCHORS_DEFAULT.to_owned())),
            ..Self::default()
        };
        runner
            .anchor_rules
            .insert("com.apple".to_owned(), Ok(String::new()));
        runner
            .anchor_children
            .insert("com.apple".to_owned(), Ok(ANCHORS_COM_APPLE.to_owned()));
        runner.anchor_rules.insert(
            "com.apple/250.ApplicationFirewall".to_owned(),
            Ok(String::new()),
        );
        runner.anchor_children.insert(
            "com.apple/250.ApplicationFirewall".to_owned(),
            Ok(String::new()),
        );
        runner
    }
}

impl PfRunner for StubRunner {
    fn run(&mut self, command: PfCommand<'_>, _timeout: Duration) -> Result<String, CollectError> {
        let label = match command {
            PfCommand::Info => "-s info".to_owned(),
            PfCommand::MainRules => "-sr".to_owned(),
            PfCommand::Interfaces => "-v -s Interfaces".to_owned(),
            PfCommand::RootAnchors => "-sA".to_owned(),
            PfCommand::AnchorRules(a) => format!("-a {a} -sr"),
            PfCommand::AnchorChildren(a) => format!("-a {a} -sA"),
        };
        self.calls.push(label);
        match command {
            PfCommand::Info => self.info.take().unwrap(),
            PfCommand::MainRules => self.main_rules.take().unwrap(),
            PfCommand::Interfaces => self.interfaces.take().unwrap(),
            PfCommand::RootAnchors => self.root_anchors.take().unwrap(),
            PfCommand::AnchorRules(a) => self
                .anchor_rules
                .remove(a)
                .unwrap_or_else(|| Ok(String::new())),
            PfCommand::AnchorChildren(a) => self
                .anchor_children
                .remove(a)
                .unwrap_or_else(|| Ok(String::new())),
        }
    }
}

fn target(port: u16, protocol: Protocol, address: &str, zone: Option<&str>) -> SocketTarget {
    SocketTarget {
        endpoint: Endpoint {
            port,
            protocol,
            address: address.parse().unwrap(),
        },
        zone: zone.map(ToOwned::to_owned),
    }
}

#[test]
fn disabled_pf_stops_after_info_and_reports_disabled() {
    let mut runner = StubRunner {
        info: Some(Ok(INFO_DISABLED.to_owned())),
        ..StubRunner::default()
    };
    let collected = collect_with(&mut runner).unwrap();
    assert!(matches!(collected, CollectedPf::Disabled));
    assert_eq!(runner.calls, ["-s info"]);

    let sockets = [target(8080, Protocol::Tcp, "0.0.0.0", None)];
    let ifaces = parse_ifconfig(IFCONFIG_MACOS);
    assert_eq!(
        PfReport::evaluate(Ok(collected), &sockets, Ok(&ifaces)),
        PfReport::Disabled
    );
}

#[test]
fn default_macos_anchors_and_skip_lo0_pass_sockets() {
    let mut runner = StubRunner::enabled_default();
    let collected = collect_with(&mut runner).unwrap();
    let ifaces = parse_ifconfig(IFCONFIG_MACOS);
    let sockets = [
        target(8080, Protocol::Tcp, "127.0.0.1", None),
        target(443, Protocol::Tcp, "192.0.2.10", None),
    ];
    let report = PfReport::evaluate(Ok(collected), &sockets, Ok(&ifaces));
    assert_eq!(
        report,
        PfReport::Enabled {
            ports: vec![
                PfPort {
                    port: 443,
                    protocol: Protocol::Tcp,
                    address: "192.0.2.10".parse().unwrap(),
                    family: AddressFamily::Ipv4,
                    interfaces: vec![PfInterfaceVerdict {
                        interface: Some("en0".to_owned()),
                        outcome: Verdict::Pass {
                            reason: "no rule matched, and pf passes by default".to_owned(),
                        },
                    }],
                },
                PfPort {
                    port: 8080,
                    protocol: Protocol::Tcp,
                    address: "127.0.0.1".parse().unwrap(),
                    family: AddressFamily::Ipv4,
                    interfaces: vec![PfInterfaceVerdict {
                        interface: Some("lo0".to_owned()),
                        outcome: Verdict::Pass {
                            reason: "the interface is excluded by set skip".to_owned(),
                        },
                    }],
                },
            ],
        }
    );
}

#[test]
fn custom_rules_evaluate_block_pass_skip_wildcard_and_dual_stack() {
    let mut runner = StubRunner::enabled_default();
    runner.main_rules = Some(Ok(DEFAULT_BLOCK.to_owned()));
    let collected = collect_with(&mut runner).unwrap();
    let ifaces = parse_ifconfig(IFCONFIG_MACOS);
    let sockets = [
        target(22, Protocol::Tcp, "::", None),
        target(5353, Protocol::Udp, "192.0.2.10", None),
        target(9000, Protocol::Tcp, "192.0.2.10", None),
        target(9001, Protocol::Tcp, "127.0.0.1", None),
    ];
    let PfReport::Enabled { ports } = PfReport::evaluate(Ok(collected), &sockets, Ok(&ifaces))
    else {
        panic!("expected enabled pf report");
    };
    // `::` expands into IPv4 and IPv6 entries for port 22.
    let v4_22 = ports
        .iter()
        .find(|p| p.port == 22 && p.family == AddressFamily::Ipv4)
        .unwrap();
    assert_eq!(v4_22.interfaces[0].interface.as_deref(), Some("en0"));
    assert!(matches!(v4_22.interfaces[0].outcome, Verdict::Pass { .. }));
    assert_eq!(v4_22.interfaces[1].interface.as_deref(), Some("lo0"));
    assert!(matches!(v4_22.interfaces[1].outcome, Verdict::Pass { .. }));

    let v6_22 = ports
        .iter()
        .find(|p| p.port == 22 && p.family == AddressFamily::Ipv6)
        .unwrap();
    assert_eq!(v6_22.interfaces[0].interface.as_deref(), Some("en0"));
    assert!(matches!(v6_22.interfaces[0].outcome, Verdict::Block { .. }));
    assert_eq!(v6_22.interfaces[1].interface.as_deref(), Some("lo0"));
    assert!(matches!(v6_22.interfaces[1].outcome, Verdict::Pass { .. }));

    let udp_5353 = ports.iter().find(|p| p.port == 5353).unwrap();
    assert!(matches!(
        udp_5353.interfaces[0].outcome,
        Verdict::Pass { .. }
    ));

    let tcp_9000 = ports.iter().find(|p| p.port == 9000).unwrap();
    assert!(matches!(
        tcp_9000.interfaces[0].outcome,
        Verdict::Block { .. }
    ));

    let tcp_9001 = ports.iter().find(|p| p.port == 9001).unwrap();
    assert_eq!(
        tcp_9001.interfaces[0].outcome,
        Verdict::Pass {
            reason: "the interface is excluded by set skip".to_owned(),
        }
    );
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

#[test]
fn permission_denied_timeout_and_size_bounds_become_unknown() {
    let mut denied = StubRunner {
        info: Some(Err(CollectError::CommandFailed {
            command: "/sbin/pfctl -s info".to_owned(),
            status: exit_status_one(),
            stderr: "pfctl: /dev/pf: Operation not permitted".to_owned(),
        })),
        ..StubRunner::default()
    };
    let err = collect_with(&mut denied).unwrap_err();
    assert!(matches!(err, PfCollectError::PermissionDenied { .. }));
    let report = PfReport::evaluate(Err(err), &[], Err("not read"));
    assert!(matches!(
        report,
        PfReport::Unknown { reason } if reason.contains("sudo")
    ));

    let mut timed_out = StubRunner {
        info: Some(Err(CollectError::TimedOut {
            command: "/sbin/pfctl -s info".to_owned(),
            timeout: Duration::from_secs(3),
        })),
        ..StubRunner::default()
    };
    assert!(matches!(
        collect_with(&mut timed_out).unwrap_err(),
        PfCollectError::TimedOut { .. }
    ));

    let mut oversized = StubRunner {
        info: Some(Err(CollectError::OutputTooLarge {
            command: "/sbin/pfctl -s info".to_owned(),
            stream: "stdout",
            limit_bytes: 65536,
        })),
        ..StubRunner::default()
    };
    assert!(matches!(
        collect_with(&mut oversized).unwrap_err(),
        PfCollectError::OutputTooLarge { .. }
    ));

    let mut total_oversized = StubRunner::enabled_default();
    total_oversized.main_rules = Some(Ok("a".repeat(2 * 1024 * 1024 + 1)));
    assert!(matches!(
        collect_with(&mut total_oversized).unwrap_err(),
        PfCollectError::OutputTooLarge { .. }
    ));

    let mut unrecognised = StubRunner {
        info: Some(Ok("unexpected pfctl output\n".to_owned())),
        ..StubRunner::default()
    };
    assert_eq!(
        collect_with(&mut unrecognised).unwrap_err(),
        PfCollectError::UnrecognisedInfo
    );

    let mut missing_bin = StubRunner {
        info: Some(Err(CollectError::Run {
            command: "/sbin/pfctl -s info".to_owned(),
            source: io::Error::new(io::ErrorKind::NotFound, "not found"),
        })),
        ..StubRunner::default()
    };
    assert!(matches!(
        collect_with(&mut missing_bin).unwrap_err(),
        PfCollectError::Command { .. }
    ));
}

#[test]
fn anchor_bounds_and_validation_reject_excess_or_unsafe_names() {
    let mut too_many = StubRunner::enabled_default();
    let list = (0..65)
        .map(|i| format!("a{i}"))
        .collect::<Vec<_>>()
        .join("\n");
    too_many.root_anchors = Some(Ok(list));
    assert_eq!(
        collect_with(&mut too_many).unwrap_err(),
        PfCollectError::AnchorCountLimit { limit: 64 }
    );

    let mut too_deep = StubRunner::enabled_default();
    too_deep.root_anchors = Some(Ok("d1\n".to_owned()));
    for depth in 1..=8 {
        let path = (1..=depth)
            .map(|i| format!("d{i}"))
            .collect::<Vec<_>>()
            .join("/");
        let next = format!("d{}", depth + 1);
        too_deep
            .anchor_rules
            .insert(path.clone(), Ok(String::new()));
        too_deep.anchor_children.insert(path, Ok(next));
    }
    assert!(matches!(
        collect_with(&mut too_deep).unwrap_err(),
        PfCollectError::AnchorDepthLimit { limit: 8, .. }
    ));

    let mut pre_nested_too_deep = StubRunner::enabled_default();
    pre_nested_too_deep.root_anchors = Some(Ok("d1/d2/d3/d4/d5/d6/d7/d8/d9\n".to_owned()));
    assert!(matches!(
        collect_with(&mut pre_nested_too_deep).unwrap_err(),
        PfCollectError::AnchorDepthLimit { limit: 8, .. }
    ));

    for bad in ["-evil", "../escape", "a*b", "bad\u{1b}name"] {
        let mut runner = StubRunner::enabled_default();
        runner.root_anchors = Some(Ok(format!("{bad}\n")));
        assert!(
            matches!(
                collect_with(&mut runner).unwrap_err(),
                PfCollectError::InvalidAnchorName { .. }
            ),
            "expected InvalidAnchorName for {bad:?}"
        );
    }
}

#[test]
fn skipped_interface_group_turns_block_unknown_but_keeps_pass() {
    let mut runner = StubRunner::enabled_default();
    runner.main_rules = Some(Ok(
        "block drop in on en0 all\npass in on lo0 all\n".to_owned()
    ));
    runner.interfaces = Some(Ok("egress (skip)\nen0\nlo0 (skip)\n".to_owned()));
    let collected = collect_with(&mut runner).unwrap();
    let ifaces = parse_ifconfig(IFCONFIG_MACOS);
    let sockets = [
        target(8080, Protocol::Tcp, "192.0.2.10", None),
        target(8081, Protocol::Tcp, "127.0.0.1", None),
    ];
    let PfReport::Enabled { ports } = PfReport::evaluate(Ok(collected), &sockets, Ok(&ifaces))
    else {
        panic!("expected enabled pf report");
    };
    assert!(matches!(
        &ports[0].interfaces[0].outcome,
        Verdict::Unknown { reason } if reason.contains("egress")
    ));
    assert!(matches!(
        &ports[1].interfaces[0].outcome,
        Verdict::Pass { .. }
    ));
}

#[test]
fn ifconfig_failure_still_evaluates_loopback_and_reports_other_binds_unknown() {
    let mut runner = StubRunner::enabled_default();
    let collected = collect_with(&mut runner).unwrap();
    let sockets = [
        target(8080, Protocol::Tcp, "127.0.0.1", None),
        target(8081, Protocol::Tcp, "192.0.2.10", None),
        target(8082, Protocol::Udp, "fe80::200:ff:fe00:1", Some("en0")),
        target(5353, Protocol::Udp, "224.0.0.251", None),
    ];
    let PfReport::Enabled { ports } =
        PfReport::evaluate(Ok(collected), &sockets, Err("ifconfig failed"))
    else {
        panic!("expected enabled pf report");
    };
    assert!(matches!(
        &ports[0].interfaces[0].outcome,
        Verdict::Unknown { .. }
    ));
    assert_eq!(ports[1].interfaces[0].interface.as_deref(), Some("lo0"));
    assert!(matches!(
        &ports[1].interfaces[0].outcome,
        Verdict::Pass { .. }
    ));
    assert!(matches!(
        &ports[2].interfaces[0].outcome,
        Verdict::Unknown { reason } if reason.contains("ifconfig failed")
    ));
    assert_eq!(ports[3].interfaces[0].interface.as_deref(), Some("en0"));
    assert!(matches!(
        &ports[3].interfaces[0].outcome,
        Verdict::Pass { .. }
    ));
}
