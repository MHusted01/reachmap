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
    let report = join(
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
    let report = join(
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
    let report = join(
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
    let report = join(
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
    let report = join(
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
    let report = join(
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
    let report = join(
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
