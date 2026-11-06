use super::*;
use crate::collect::RawProcess;
use crate::errors::render_chain;
use crate::network::{HostAddress, Network};
use crate::parse::sock_diag::SockDiagError;
use crate::reach::{Coverage, Reach, Reason};
use crate::service::{Container, Process};
use crate::socket::{Protocol, SocketOptions};
use std::collections::{BTreeSet, HashMap};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

mod tailscale;

fn socket(port: u16, inode: u64) -> ListeningSocket {
    ListeningSocket {
        protocol: Protocol::Tcp,
        address: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        port,
        inode,
        options: None,
    }
}

fn open_files(permission_denied: bool) -> ProcessFds {
    ProcessFds {
        processes: vec![RawProcess {
            pid: 812,
            comm: "sshd\n".to_string(),
            fd_targets: vec!["/dev/null".to_string(), "socket:[100]".to_string()],
        }],
        permission_denied,
        processes_may_be_hidden: false,
    }
}

fn lan_host() -> HostInterfaces {
    HostInterfaces {
        addresses: vec![
            HostAddress {
                interface: "lo".to_string(),
                ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            },
            HostAddress {
                interface: "enp1s0".to_string(),
                ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20)),
            },
        ],
        names: HashMap::from([(1, "lo".to_string()), (2, "enp1s0".to_string())]),
    }
}

fn firewall(ufw: UfwState) -> Firewall {
    Firewall {
        ufw,
        docker_user: None,
    }
}

/// [`join`] on a host where UFW is off, for tests about everything else.
fn join_without_ufw(
    sockets: Vec<ListeningSocket>,
    open_files: &ProcessFds,
    host: Result<HostInterfaces, InterfacesError>,
    published: Result<Vec<PublishedPort>, DockerError>,
) -> ScanReport {
    join(
        sockets,
        open_files,
        host,
        published,
        Ok(Vec::new()),
        OptionsReport::default(),
        &firewall(UfwState::Inactive),
    )
}

/// [`join`] on a LAN host with these facts from the kernel.
fn join_with_options(
    sockets: Vec<ListeningSocket>,
    published: Vec<PublishedPort>,
    options: OptionsReport,
) -> ScanReport {
    join(
        sockets,
        &open_files(false),
        Ok(lan_host()),
        Ok(published),
        Ok(Vec::new()),
        options,
        &firewall(UfwState::Inactive),
    )
}

/// What the kernel reported when nothing failed.
fn reported(by_inode: OptionsByInode) -> OptionsReport {
    OptionsReport {
        by_inode,
        error: None,
    }
}

fn options(bound_device: Option<u32>, ipv6_only: bool) -> SocketOptions {
    SocketOptions {
        bound_device,
        ipv6_only,
    }
}

fn all_ipv4(checked: bool) -> Reason {
    Reason::AllAddresses {
        covers: Coverage::Ipv4,
        checked,
    }
}

fn services(report: &ScanReport) -> Vec<(u16, Service)> {
    report
        .ports
        .iter()
        .map(|s| (s.endpoint.port, s.service.clone()))
        .collect()
}

fn not_found() -> InterfacesError {
    InterfacesError::Collect(CollectError::Run {
        command: "ip -j addr".to_string(),
        source: io::Error::new(ErrorKind::NotFound, "No such file or directory"),
    })
}

#[test]
fn a_socket_without_owner_needs_root_when_processes_may_be_hidden() {
    // With hidepid nothing is denied: other users' processes are simply absent.
    let hidden = ProcessFds {
        processes_may_be_hidden: true,
        ..open_files(false)
    };

    let report = join_without_ufw(
        vec![socket(53, 999)],
        &hidden,
        Ok(lan_host()),
        Ok(Vec::new()),
    );

    assert_eq!(
        services(&report),
        vec![(
            53,
            Service::Unknown {
                reason: UnknownReason::NeedsRoot
            }
        )]
    );
}

#[test]
fn names_the_owner_and_explains_the_rest_when_nothing_was_hidden() {
    let report = join_without_ufw(
        vec![socket(22, 100), socket(53, 999)],
        &open_files(false),
        Ok(lan_host()),
        Ok(Vec::new()),
    );

    assert_eq!(
        services(&report),
        vec![
            (
                22,
                Service::Process(Process {
                    pid: 812,
                    name: "sshd".to_string()
                })
            ),
            (
                53,
                Service::Unknown {
                    reason: UnknownReason::NoProcess
                }
            ),
        ]
    );
}

#[test]
fn suggests_root_for_unowned_sockets_when_processes_were_hidden() {
    let report = join_without_ufw(
        vec![socket(22, 100), socket(53, 999)],
        &open_files(true),
        Ok(lan_host()),
        Ok(Vec::new()),
    );

    assert!(matches!(report.ports[0].service, Service::Process(_)));
    assert_eq!(
        report.ports[1].service,
        Service::Unknown {
            reason: UnknownReason::NeedsRoot
        }
    );
}

#[test]
fn classifies_each_socket_against_the_host_interfaces() {
    let report = join_without_ufw(
        vec![socket(22, 100)],
        &open_files(false),
        Ok(lan_host()),
        Ok(Vec::new()),
    );

    assert_eq!(
        report.ports[0].verdict,
        Verdict {
            reach: Reach::From {
                networks: BTreeSet::from([Network::ThisHost, Network::Lan]),
            },
            reason: all_ipv4(false),
        }
    );
    assert!(report.interfaces_error.is_none());
}

#[test]
fn unknown_interfaces_give_unknown_verdicts_and_keep_the_error() {
    let report = join_without_ufw(
        vec![socket(22, 100)],
        &open_files(false),
        Err(not_found()),
        Ok(Vec::new()),
    );

    assert_eq!(report.ports[0].verdict.reach, Reach::Unknown);
    assert_eq!(report.ports[0].verdict.reason, Reason::InterfacesUnknown);
    let error = report.interfaces_error.unwrap();
    assert_eq!(
        render_chain(&error),
        "could not list interfaces: could not run `ip -j addr`: No such file or directory"
    );
}

fn published(port: u16, name: &str) -> PublishedPort {
    PublishedPort {
        protocol: Protocol::Tcp,
        address: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        port,
        container: Container {
            name: name.to_string(),
            compose_service: None,
        },
    }
}

#[test]
fn a_published_port_shows_the_container_instead_of_the_process() {
    let report = join_without_ufw(
        vec![socket(8080, 100)],
        &open_files(false),
        Ok(lan_host()),
        Ok(vec![published(8080, "web")]),
    );

    assert_eq!(report.ports.len(), 1);
    assert_eq!(report.ports[0].listener, Listener::HostSocket);
    assert_eq!(report.ports[0].service.to_string(), "container web");
}

#[test]
fn a_published_port_without_a_socket_gets_its_own_row_in_port_order() {
    let report = join_without_ufw(
        vec![socket(22, 100), socket(9000, 200)],
        &open_files(false),
        Ok(lan_host()),
        Ok(vec![published(8080, "web")]),
    );

    let row = &report.ports[1];
    assert_eq!(row.endpoint.port, 8080);
    assert_eq!(row.listener, Listener::DockerForward);
    assert_eq!(row.service.to_string(), "container web");
    assert_eq!(row.verdict.reason, all_ipv4(false));
    assert_eq!(report.ports.len(), 3);
}

#[test]
fn without_docker_the_sockets_keep_their_processes_and_the_error_is_kept() {
    let report = join_without_ufw(
        vec![socket(22, 100)],
        &open_files(false),
        Ok(lan_host()),
        Err(DockerError::NotInstalled),
    );

    assert!(matches!(report.ports[0].service, Service::Process(_)));
    assert!(matches!(
        report.docker_error,
        Some(DockerError::NotInstalled)
    ));
}

#[test]
fn a_missing_ip_command_suggests_installing_iproute2() {
    assert_eq!(
        not_found().hint().as_deref(),
        Some("install iproute2, the package that provides `ip`")
    );
}

#[test]
fn other_command_errors_have_no_hint() {
    let error = InterfacesError::Collect(CollectError::Run {
        command: "ip -j addr".to_string(),
        source: io::Error::new(ErrorKind::PermissionDenied, "Permission denied"),
    });
    assert_eq!(error.hint(), None);
}

#[test]
fn unreadable_ip_output_asks_for_a_bug_report() {
    let source = serde_json::from_str::<Vec<u8>>("nope").unwrap_err();
    let error = InterfacesError::Parse(source);

    assert!(render_chain(&error).starts_with("could not understand the output of `ip -j addr`: "));
    assert!(error.hint().unwrap().contains(ISSUES_URL));
}

fn published_on(address: &str, port: u16) -> PublishedPort {
    PublishedPort {
        protocol: Protocol::Tcp,
        address: address.parse().unwrap(),
        port,
        container: Container {
            name: "web".to_string(),
            compose_service: None,
        },
    }
}

fn warnings_by_port(report: &ScanReport) -> Vec<(u16, Option<Warning>)> {
    report
        .ports
        .iter()
        .map(|s| (s.endpoint.port, s.warning))
        .collect()
}

#[test]
fn active_ufw_flags_published_rows_and_only_those() {
    let report = join(
        vec![socket(22, 100), socket(8080, 200)],
        &open_files(false),
        Ok(lan_host()),
        Ok(vec![
            published_on("0.0.0.0", 8080),
            published_on("0.0.0.0", 9000),
            published_on("127.0.0.1", 9100),
        ]),
        Ok(Vec::new()),
        OptionsReport::default(),
        &firewall(UfwState::Active),
    );

    assert_eq!(
        warnings_by_port(&report),
        vec![
            (22, None),
            (8080, Some(Warning::UfwBypassed)),
            (9000, Some(Warning::UfwBypassed)),
            (9100, None),
        ]
    );
    assert_eq!(
        report.warnings,
        vec![ScanWarning::UfwBypassed {
            ports: BTreeSet::from([8080, 9000])
        }]
    );
}

#[test]
fn inactive_ufw_flags_nothing() {
    let report = join_without_ufw(
        vec![socket(8080, 200)],
        &open_files(false),
        Ok(lan_host()),
        Ok(vec![published_on("0.0.0.0", 8080)]),
    );

    assert_eq!(warnings_by_port(&report), vec![(8080, None)]);
    assert_eq!(report.warnings, Vec::new());
}

#[test]
fn unknown_docker_under_active_ufw_ends_up_in_the_warnings() {
    let report = join(
        vec![socket(22, 100)],
        &open_files(false),
        Ok(lan_host()),
        Err(docker_not_reachable()),
        Ok(Vec::new()),
        OptionsReport::default(),
        &firewall(UfwState::Active),
    );

    assert_eq!(
        report.warnings,
        vec![ScanWarning::DockerUnknown { ufw_reason: None }]
    );
}

fn docker_not_reachable() -> DockerError {
    DockerError::Collect(CollectError::Run {
        command: "docker ps -q".to_string(),
        source: io::Error::new(ErrorKind::PermissionDenied, "no"),
    })
}

fn chain_must_not_be_read() -> DockerUserChain {
    panic!("the chain does not matter here")
}

#[test]
fn the_chain_is_read_when_a_port_bypasses_ufw() {
    let published = Ok(vec![published_on("0.0.0.0", 8080)]);
    let facts = firewall_facts(&published, UfwState::Active, || DockerUserChain::HasRules);
    assert_eq!(facts.docker_user, Some(DockerUserChain::HasRules));
}

#[test]
fn the_chain_is_read_when_ufw_is_unknown_too() {
    let published = Ok(vec![published_on("0.0.0.0", 8080)]);
    let ufw = UfwState::Unknown("ufw.conf has no ENABLED setting".to_string());
    let facts = firewall_facts(&published, ufw, || DockerUserChain::NoRules);
    assert_eq!(facts.docker_user, Some(DockerUserChain::NoRules));
}

#[test]
fn the_chain_is_left_alone_when_no_port_makes_it_matter() {
    let on_loopback = Ok(vec![published_on("127.0.0.1", 8080)]);
    let on_all = Ok(vec![published_on("0.0.0.0", 8080)]);
    let no_docker = Err(docker_not_reachable());
    for (published, ufw) in [
        (&on_loopback, UfwState::Active),
        (&on_all, UfwState::Inactive),
        (&no_docker, UfwState::Active),
    ] {
        let facts = firewall_facts(published, ufw, chain_must_not_be_read);
        assert_eq!(facts.docker_user, None);
    }
}

#[test]
fn a_socket_the_kernel_reports_on_is_checked() {
    let report = join_with_options(
        vec![socket(22, 100)],
        Vec::new(),
        reported(HashMap::from([(100, options(None, false))])),
    );

    assert_eq!(report.ports[0].verdict.reason, all_ipv4(true));
}

#[test]
fn a_bound_device_narrows_the_verdict_to_its_interface() {
    let report = join_with_options(
        vec![socket(22, 100)],
        Vec::new(),
        reported(HashMap::from([(100, options(Some(1), false))])),
    );

    assert_eq!(
        report.ports[0].verdict,
        Verdict {
            reach: Reach::From {
                networks: BTreeSet::from([Network::ThisHost]),
            },
            reason: Reason::OnInterfaces {
                interfaces: BTreeSet::from(["lo".to_string()]),
            },
        }
    );
}

#[test]
fn a_socket_the_kernel_did_not_report_stays_unchecked() {
    let report = join_with_options(
        vec![socket(22, 100), socket(23, 200)],
        Vec::new(),
        reported(HashMap::from([(100, options(None, false))])),
    );

    assert_eq!(report.ports[1].verdict.reason, all_ipv4(false));
}

#[test]
fn a_device_no_interface_has_leaves_the_socket_unchecked() {
    let report = join_with_options(
        vec![socket(22, 100)],
        Vec::new(),
        reported(HashMap::from([(100, options(Some(9), false))])),
    );

    assert_eq!(report.ports[0].verdict.reason, all_ipv4(false));
}

#[test]
fn without_options_verdicts_stay_unchecked_and_the_error_is_kept_without_a_warning() {
    let refused = SockDiagError::Refused(io::Error::from_raw_os_error(13));

    let report = join_with_options(
        vec![socket(22, 100)],
        Vec::new(),
        OptionsReport {
            by_inode: OptionsByInode::new(),
            error: Some(SocketOptionsError::Reply {
                protocol: Protocol::Tcp,
                source: refused,
            }),
        },
    );

    assert_eq!(report.ports[0].verdict.reason, all_ipv4(false));
    assert!(report.socket_options_error.is_some());
    assert!(report.warnings.is_empty());
}

#[test]
fn a_udp_failure_leaves_tcp_checked_and_udp_unchecked() {
    let udp = ListeningSocket {
        protocol: Protocol::Udp,
        ..socket(53, 200)
    };
    let refused = SockDiagError::Refused(io::Error::from_raw_os_error(2));

    let report = join_with_options(
        vec![socket(22, 100), udp],
        Vec::new(),
        OptionsReport {
            by_inode: HashMap::from([(100, options(None, false))]),
            error: Some(SocketOptionsError::Reply {
                protocol: Protocol::Udp,
                source: refused,
            }),
        },
    );

    assert_eq!(report.ports[0].verdict.reason, all_ipv4(true));
    assert_eq!(report.ports[1].verdict.reason, all_ipv4(false));
    assert!(report.socket_options_error.is_some());
    assert!(report.warnings.is_empty());
}

#[test]
fn an_ipv6_only_socket_does_not_take_the_name_of_a_port_published_on_ipv4() {
    let unrelated = ListeningSocket {
        address: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        ..socket(8080, 100)
    };

    let report = join_with_options(
        vec![unrelated],
        vec![published(8080, "web")],
        reported(HashMap::from([(100, options(None, true))])),
    );

    let kinds: Vec<Listener> = report.ports.iter().map(|row| row.listener).collect();
    assert_eq!(kinds, [Listener::DockerForward, Listener::HostSocket]);
    assert_eq!(report.ports[0].service.to_string(), "container web");
    assert_eq!(report.ports[1].service.to_string(), "sshd (812)");
}

fn udp_socket(port: u16, inode: u64) -> ListeningSocket {
    ListeningSocket {
        protocol: Protocol::Udp,
        ..socket(port, inode)
    }
}

#[test]
fn a_host_udp_socket_is_not_credited_to_a_container_publishing_tcp() {
    let report = join_without_ufw(
        vec![udp_socket(8080, 100)],
        &open_files(false),
        Ok(lan_host()),
        Ok(vec![published(8080, "web")]),
    );

    let rows: Vec<(Protocol, String)> = report
        .ports
        .iter()
        .map(|row| (row.endpoint.protocol, row.service.to_string()))
        .collect();
    assert_eq!(
        rows,
        [
            (Protocol::Tcp, "container web".to_string()),
            (Protocol::Udp, "sshd (812)".to_string()),
        ]
    );
}

#[test]
fn a_published_udp_port_past_active_ufw_gets_the_warning() {
    let port = PublishedPort {
        protocol: Protocol::Udp,
        ..published(5353, "dns")
    };

    let report = join(
        vec![udp_socket(5353, 100)],
        &open_files(false),
        Ok(lan_host()),
        Ok(vec![port]),
        Ok(Vec::new()),
        OptionsReport::default(),
        &firewall(UfwState::Active),
    );

    assert_eq!(report.ports[0].service.to_string(), "container dns");
    assert_eq!(report.ports[0].warning, Some(Warning::UfwBypassed));
    assert_eq!(
        report.warnings,
        [ScanWarning::UfwBypassed {
            ports: BTreeSet::from([5353]),
        }]
    );
}

#[test]
fn udp_sockets_alone_raise_no_warning_so_the_exit_status_stays_zero() {
    let report = join(
        vec![udp_socket(53, 100)],
        &open_files(false),
        Ok(lan_host()),
        Ok(Vec::new()),
        Ok(Vec::new()),
        OptionsReport::default(),
        &firewall(UfwState::Active),
    );

    assert!(report.warnings.is_empty());
}

#[test]
fn a_docker_forward_has_no_socket_to_check() {
    let report = join_with_options(
        Vec::new(),
        vec![published(8080, "web")],
        OptionsReport::default(),
    );

    assert_eq!(report.ports[0].verdict.reason, all_ipv4(false));
}
