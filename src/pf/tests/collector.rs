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

fn target(port: u16, protocol: Protocol, address: &str) -> SocketTarget {
    target_with_zone(port, protocol, address, None)
}

fn target_with_zone(
    port: u16,
    protocol: Protocol,
    address: &str,
    zone: Option<&str>,
) -> SocketTarget {
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

    let sockets = [target(8080, Protocol::Tcp, "0.0.0.0")];
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
        target(8080, Protocol::Tcp, "127.0.0.1"),
        target(443, Protocol::Tcp, "192.0.2.10"),
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
                    interfaces: vec![
                        PfInterfaceVerdict {
                            interface: Some("en0".to_owned()),
                            outcome: Verdict::Pass {
                                reason: "no rule matched, and pf passes by default".to_owned(),
                            },
                        },
                        PfInterfaceVerdict {
                            interface: Some("lo0".to_owned()),
                            outcome: Verdict::Pass {
                                reason: "the interface is excluded by set skip".to_owned(),
                            },
                        },
                    ],
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
        target(22, Protocol::Tcp, "::"),
        target(22, Protocol::Tcp, "0.0.0.0"),
        target(5353, Protocol::Udp, "192.0.2.10"),
        target(9000, Protocol::Tcp, "192.0.2.10"),
        target(9001, Protocol::Tcp, "127.0.0.1"),
    ];
    let PfReport::Enabled { ports } = PfReport::evaluate(Ok(collected), &sockets, Ok(&ifaces))
    else {
        panic!("expected enabled pf report");
    };
    // `::` emits IPv4 as Unknown (`IPV6_V6ONLY` not known) and evaluates IPv6.
    let v6_wild_v4 = ports
        .iter()
        .find(|p| {
            p.port == 22
                && p.address == "::".parse::<std::net::IpAddr>().unwrap()
                && p.family == AddressFamily::Ipv4
        })
        .unwrap();
    assert_eq!(v6_wild_v4.interfaces[0].interface, None);
    assert!(matches!(
        &v6_wild_v4.interfaces[0].outcome,
        Verdict::Unknown { reason } if reason.contains("IPV6_V6ONLY")
    ));

    let v6_wild_v6 = ports
        .iter()
        .find(|p| {
            p.port == 22
                && p.address == "::".parse::<std::net::IpAddr>().unwrap()
                && p.family == AddressFamily::Ipv6
        })
        .unwrap();
    assert_eq!(v6_wild_v6.interfaces[0].interface.as_deref(), Some("en0"));
    assert!(matches!(
        v6_wild_v6.interfaces[0].outcome,
        Verdict::Block { .. }
    ));
    assert_eq!(v6_wild_v6.interfaces[1].interface.as_deref(), Some("lo0"));
    assert!(matches!(
        v6_wild_v6.interfaces[1].outcome,
        Verdict::Pass { .. }
    ));

    // Explicit `0.0.0.0` evaluates IPv4 wildcard across active interfaces.
    let v4_wild = ports
        .iter()
        .find(|p| {
            p.port == 22
                && p.address == "0.0.0.0".parse::<std::net::IpAddr>().unwrap()
                && p.family == AddressFamily::Ipv4
        })
        .unwrap();
    assert_eq!(v4_wild.interfaces[0].interface.as_deref(), Some("en0"));
    assert!(matches!(
        v4_wild.interfaces[0].outcome,
        Verdict::Pass { .. }
    ));
    assert_eq!(v4_wild.interfaces[1].interface.as_deref(), Some("lo0"));
    assert!(matches!(
        v4_wild.interfaces[1].outcome,
        Verdict::Pass { .. }
    ));

    let udp_5353 = ports.iter().find(|p| p.port == 5353).unwrap();
    assert_eq!(udp_5353.interfaces[0].interface.as_deref(), Some("en0"));
    assert!(matches!(
        udp_5353.interfaces[0].outcome,
        Verdict::Pass { .. }
    ));
    assert_eq!(udp_5353.interfaces[1].interface.as_deref(), Some("lo0"));
    assert!(matches!(
        udp_5353.interfaces[1].outcome,
        Verdict::Pass { .. }
    ));

    let tcp_9000 = ports.iter().find(|p| p.port == 9000).unwrap();
    assert_eq!(tcp_9000.interfaces[0].interface.as_deref(), Some("en0"));
    assert!(matches!(
        tcp_9000.interfaces[0].outcome,
        Verdict::Block { .. }
    ));
    assert_eq!(tcp_9000.interfaces[1].interface.as_deref(), Some("lo0"));
    assert!(matches!(
        tcp_9000.interfaces[1].outcome,
        Verdict::Pass { .. }
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
        target(8080, Protocol::Tcp, "192.0.2.10"),
        target(8081, Protocol::Tcp, "127.0.0.1"),
    ];
    let PfReport::Enabled { ports } = PfReport::evaluate(Ok(collected), &sockets, Ok(&ifaces))
    else {
        panic!("expected enabled pf report");
    };
    let port_8080 = ports.iter().find(|p| p.port == 8080).unwrap();
    assert_eq!(port_8080.interfaces[0].interface.as_deref(), Some("en0"));
    assert!(matches!(
        &port_8080.interfaces[0].outcome,
        Verdict::Unknown { reason } if reason.contains("egress")
    ));
    assert_eq!(port_8080.interfaces[1].interface.as_deref(), Some("lo0"));
    assert!(matches!(
        &port_8080.interfaces[1].outcome,
        Verdict::Pass { .. }
    ));

    let port_8081 = ports.iter().find(|p| p.port == 8081).unwrap();
    assert!(matches!(
        &port_8081.interfaces[0].outcome,
        Verdict::Pass { .. }
    ));
}

#[test]
fn ifconfig_failure_still_evaluates_loopback_and_reports_other_binds_unknown() {
    let mut runner = StubRunner::enabled_default();
    let collected = collect_with(&mut runner).unwrap();
    let sockets = [
        target(8080, Protocol::Tcp, "127.0.0.1"),
        target(8081, Protocol::Tcp, "192.0.2.10"),
        target(8082, Protocol::Udp, "fe80::200:ff:fe00:1"),
        target(5353, Protocol::Udp, "224.0.0.251"),
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
    assert!(matches!(
        &ports[3].interfaces[0].outcome,
        Verdict::Unknown { reason } if reason.contains("ifconfig failed")
    ));
}

#[test]
fn inline_brace_anchors_do_not_leak_inner_rules_to_top_level() {
    let rules_cases = [
        concat!(
            "scrub in all fragment reassemble\n",
            "pass in quick on en0 inet proto tcp from any to any port = 8443 flags S/SA keep state\n",
            "anchor in on en1 all {\n",
            "  block drop in quick all\n",
            "}\n",
        ),
        concat!(
            "scrub in all fragment reassemble\n",
            "pass in quick on en0 inet proto tcp from any to any port = 8443 flags S/SA keep state\n",
            "anchor \"scoped\" in on en1 all {\n",
            "  anchor \"nested\" {\n",
            "    block drop in quick all\n",
            "  }\n",
            "}\n",
        ),
        concat!(
            "scrub in all fragment reassemble\n",
            "pass in quick on en0 inet proto tcp from any to any port = 8443 flags S/SA keep state\n",
            "scrub-anchor \"sc\" in on en1 {\n",
            "  scrub in all fragment reassemble\n",
            "}\n",
        ),
    ];
    let ifaces = parse_ifconfig(IFCONFIG_MACOS);
    let sockets = [
        target(8443, Protocol::Tcp, "192.0.2.10"),
        target(9000, Protocol::Tcp, "192.0.2.10"),
    ];
    for rules in rules_cases {
        let mut runner = StubRunner::enabled_default();
        runner.main_rules = Some(Ok(rules.to_owned()));
        let collected = collect_with(&mut runner).unwrap();
        let PfReport::Enabled { ports } = PfReport::evaluate(Ok(collected), &sockets, Ok(&ifaces))
        else {
            panic!("expected enabled pf report");
        };
        let port_8443 = ports.iter().find(|p| p.port == 8443).unwrap();
        assert_eq!(port_8443.interfaces[0].interface.as_deref(), Some("en0"));
        assert!(
            matches!(&port_8443.interfaces[0].outcome, Verdict::Pass { .. }),
            "quick pass on en0 before inline block should pass, got {:?}",
            port_8443.interfaces[0].outcome
        );

        let port_9000 = ports.iter().find(|p| p.port == 9000).unwrap();
        assert_eq!(port_9000.interfaces[0].interface.as_deref(), Some("en0"));
        assert!(
            matches!(&port_9000.interfaces[0].outcome, Verdict::Unknown { .. }),
            "inline anchor block must not report block/pass on en0, got {:?}",
            port_9000.interfaces[0].outcome
        );
    }

    let mut runner = StubRunner::enabled_default();
    runner.main_rules = Some(Ok(concat!(
        "scrub in all fragment reassemble\n",
        "pass in quick on en0 inet proto tcp from any to any port = 8443 flags S/SA keep state\n",
        "rdr-anchor \"ra\" in on en1 {\n",
        "  rdr pass on en1 proto tcp from any to any port 80 -> 127.0.0.1 port 8080\n",
        "}\n",
    )
    .to_owned()));
    let collected = collect_with(&mut runner).unwrap();
    let PfReport::Enabled { ports } = PfReport::evaluate(Ok(collected), &sockets, Ok(&ifaces))
    else {
        panic!("expected enabled pf report");
    };
    for port in &ports {
        assert!(
            matches!(&port.interfaces[0].outcome, Verdict::Unknown { .. }),
            "inline translation anchor must make target unknown, got {:?}",
            port.interfaces[0].outcome
        );
    }
}

#[test]
fn weak_host_evaluates_all_active_interfaces_for_non_loopback_and_wildcard_sockets() {
    let ifconfig_multi = concat!(
        "lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384\n",
        "\tinet 127.0.0.1 netmask 0xff000000\n",
        "\tinet6 ::1 prefixlen 128\n",
        "en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n",
        "\tinet 192.0.2.10 netmask 0xffffff00 broadcast 192.0.2.255\n",
        "\tinet6 fe80::200:ff:fe00:1%en0 prefixlen 64 scopeid 0x4\n",
        "\tstatus: active\n",
        "en1: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n",
        "\tinet 198.51.100.20 netmask 0xffffff00 broadcast 198.51.100.255\n",
        "\tstatus: active\n",
        "en2: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n",
        "\tinet 203.0.113.30 netmask 0xffffff00 broadcast 203.0.113.255\n",
        "\tstatus: inactive\n",
        "gif0: flags=8010<POINTOPOINT,MULTICAST> mtu 1280\n",
        "\tinet 198.18.0.1 netmask 0xffffffff\n",
    );
    let mut runner = StubRunner::enabled_default();
    runner.main_rules = Some(Ok(concat!(
        "scrub in all fragment reassemble\n",
        "block drop in all\n",
        "pass in on en1 inet proto udp from any to 192.0.2.10 port = 5353 keep state\n",
    )
    .to_owned()));
    let collected = collect_with(&mut runner).unwrap();
    let ifaces = parse_ifconfig(ifconfig_multi);
    let sockets = [
        target(5353, Protocol::Udp, "192.0.2.10"),
        target(5353, Protocol::Udp, "0.0.0.0"),
        target(5353, Protocol::Udp, "fe80::200:ff:fe00:1"),
    ];
    let PfReport::Enabled { ports } = PfReport::evaluate(Ok(collected), &sockets, Ok(&ifaces))
    else {
        panic!("expected enabled pf report");
    };

    let specific = ports
        .iter()
        .find(|p| p.address == "192.0.2.10".parse::<std::net::IpAddr>().unwrap())
        .unwrap();
    let names: Vec<_> = specific
        .interfaces
        .iter()
        .filter_map(|v| v.interface.as_deref())
        .collect();
    assert_eq!(names, ["en0", "en1", "lo0"]);
    assert!(matches!(
        specific.interfaces[0].outcome,
        Verdict::Block { .. }
    ));
    assert!(matches!(
        specific.interfaces[1].outcome,
        Verdict::Pass { .. }
    ));
    assert!(matches!(
        specific.interfaces[2].outcome,
        Verdict::Pass { .. }
    ));

    let wildcard = ports
        .iter()
        .find(|p| p.address == "0.0.0.0".parse::<std::net::IpAddr>().unwrap())
        .unwrap();
    let wild_names: Vec<_> = wildcard
        .interfaces
        .iter()
        .filter_map(|v| v.interface.as_deref())
        .collect();
    assert_eq!(wild_names, ["en0", "en1", "lo0"]);
    assert!(matches!(
        wildcard.interfaces[0].outcome,
        Verdict::Block { .. }
    ));
    assert!(matches!(
        &wildcard.interfaces[1].outcome,
        Verdict::Unknown { reason } if reason.contains("differ across addresses")
    ));
    assert!(matches!(
        wildcard.interfaces[2].outcome,
        Verdict::Pass { .. }
    ));

    // Link-local remains scoped to its holding active interface.
    let link_local = ports
        .iter()
        .find(|p| p.address == "fe80::200:ff:fe00:1".parse::<std::net::IpAddr>().unwrap())
        .unwrap();
    assert_eq!(link_local.interfaces.len(), 1);
    assert_eq!(link_local.interfaces[0].interface.as_deref(), Some("en0"));
}

#[test]
fn link_local_zone_scopes_to_one_interface_and_unzoned_duplicate_is_unknown() {
    let ifconfig_dup = concat!(
        "en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n",
        "\tinet6 fe80::1234%en0 prefixlen 64 scopeid 0x4\n",
        "\tstatus: active\n",
        "en1: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n",
        "\tinet6 fe80::1234%en1 prefixlen 64 scopeid 0x5\n",
        "\tstatus: active\n",
    );
    let mut runner = StubRunner::enabled_default();
    runner.main_rules = Some(Ok(concat!(
        "scrub in all fragment reassemble\n",
        "block drop in on en0 all\n",
        "pass in on en1 all\n",
    )
    .to_owned()));
    let collected = collect_with(&mut runner).unwrap();
    let ifaces = parse_ifconfig(ifconfig_dup);
    let sockets = [
        target_with_zone(5353, Protocol::Udp, "fe80::1234", Some("en0")),
        target_with_zone(5354, Protocol::Udp, "fe80::1234", None),
        target_with_zone(5355, Protocol::Udp, "fe80::1234", Some("4")),
    ];
    let PfReport::Enabled { ports } = PfReport::evaluate(Ok(collected), &sockets, Ok(&ifaces))
    else {
        panic!("expected enabled pf report");
    };

    let zoned = ports.iter().find(|p| p.port == 5353).unwrap();
    assert_eq!(zoned.interfaces.len(), 1);
    assert_eq!(zoned.interfaces[0].interface.as_deref(), Some("en0"));
    assert!(matches!(zoned.interfaces[0].outcome, Verdict::Block { .. }));

    let unzoned = ports.iter().find(|p| p.port == 5354).unwrap();
    assert_eq!(unzoned.interfaces[0].interface, None);
    assert!(matches!(
        &unzoned.interfaces[0].outcome,
        Verdict::Unknown { reason } if reason.contains("multiple interfaces without a socket zone")
    ));

    let numeric = ports.iter().find(|p| p.port == 5355).unwrap();
    assert_eq!(numeric.interfaces[0].interface, None);
    assert!(matches!(
        &numeric.interfaces[0].outcome,
        Verdict::Unknown { reason } if reason.contains("numeric IPv6 zone")
    ));
}

#[test]
fn ipv4_wildcard_udp_checks_limited_and_interface_broadcast_destinations() {
    let ifaces = parse_ifconfig(IFCONFIG_MACOS);
    let sockets = [
        target(5353, Protocol::Udp, "0.0.0.0"),
        target(5353, Protocol::Tcp, "0.0.0.0"),
    ];
    for allow_dst in ["255.255.255.255", "192.0.2.255"] {
        let mut runner = StubRunner::enabled_default();
        runner.main_rules = Some(Ok(format!(
            "scrub in all fragment reassemble\n\
             block drop in all\n\
             pass in on en0 inet proto udp from any to {allow_dst} port = 5353 keep state\n"
        )));
        let collected = collect_with(&mut runner).unwrap();
        let PfReport::Enabled { ports } = PfReport::evaluate(Ok(collected), &sockets, Ok(&ifaces))
        else {
            panic!("expected enabled pf report");
        };
        let udp = ports.iter().find(|p| p.protocol == Protocol::Udp).unwrap();
        assert_eq!(udp.interfaces[0].interface.as_deref(), Some("en0"));
        assert!(
            matches!(
                &udp.interfaces[0].outcome,
                Verdict::Unknown { reason } if reason.contains("differ across addresses")
            ),
            "expected Unknown when broadcast {allow_dst} passes on en0, got {:?}",
            udp.interfaces[0].outcome
        );

        let tcp = ports.iter().find(|p| p.protocol == Protocol::Tcp).unwrap();
        assert_eq!(tcp.interfaces[0].interface.as_deref(), Some("en0"));
        assert!(matches!(tcp.interfaces[0].outcome, Verdict::Block { .. }));
    }
}

#[test]
fn populated_child_anchor_changes_verdict_and_names_anchor_in_reason() {
    let mut runner = StubRunner::enabled_default();
    runner.anchor_rules.insert(
        "com.apple".to_owned(),
        Ok("scrub in all fragment reassemble\n".to_owned()),
    );
    runner.anchor_rules.insert(
        "com.apple/250.ApplicationFirewall".to_owned(),
        Ok("block drop in quick on en0 inet proto tcp from any to any port = 8080 flags S/SA keep state\n".to_owned()),
    );
    let collected = collect_with(&mut runner).unwrap();
    let ifaces = parse_ifconfig(IFCONFIG_MACOS);
    let sockets = [target(8080, Protocol::Tcp, "192.0.2.10")];
    let PfReport::Enabled { ports } = PfReport::evaluate(Ok(collected), &sockets, Ok(&ifaces))
    else {
        panic!("expected enabled pf report");
    };
    assert_eq!(ports[0].interfaces[0].interface.as_deref(), Some("en0"));
    assert!(
        matches!(
            &ports[0].interfaces[0].outcome,
            Verdict::Block { reason } if reason.contains("anchor \"com.apple/250.ApplicationFirewall\"")
        ),
        "expected child anchor block reason, got {:?}",
        ports[0].interfaces[0].outcome
    );
}
