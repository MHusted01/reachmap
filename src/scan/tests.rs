use super::*;
use crate::collect::RawProcess;
use crate::errors::render_chain;
use crate::network::Network;
use crate::reach::{Reach, Reason};
use crate::service::{Container, Process};
use crate::socket::{AddressFamily, Protocol};
use std::collections::BTreeSet;
use std::io;
use std::net::{IpAddr, Ipv4Addr};

fn socket(port: u16, inode: u64) -> ListeningSocket {
    ListeningSocket {
        protocol: Protocol::Tcp,
        address: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        port,
        inode,
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
    }
}

fn lan_host() -> Vec<HostAddress> {
    vec![
        HostAddress {
            interface: "lo".to_string(),
            ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        },
        HostAddress {
            interface: "enp1s0".to_string(),
            ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20)),
        },
    ]
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
    host: Result<Vec<HostAddress>, InterfacesError>,
    published: Result<Vec<PublishedPort>, DockerError>,
) -> ScanReport {
    join(
        sockets,
        open_files,
        host,
        published,
        &firewall(UfwState::Inactive),
    )
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
            (53, Service::Unknown(UnknownReason::NoProcess)),
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
        Service::Unknown(UnknownReason::NeedsRoot)
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
            reach: Reach::From(BTreeSet::from([Network::ThisHost, Network::Lan])),
            reason: Reason::AllAddresses(AddressFamily::Ipv4),
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
    assert_eq!(
        row.verdict.reason,
        Reason::AllAddresses(AddressFamily::Ipv4)
    );
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
