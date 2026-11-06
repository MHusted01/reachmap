//! How [`join`] uses what Tailscale shares, and what `diff` makes of it.

use std::time::Duration;

use super::*;
use crate::baseline::{Snapshot, Tolerant};
use crate::diff::{Change, Difference, compare};
use crate::json::Collector;
use crate::tailscale::{SharedPort, Sharing};

fn tcp_socket(address: Ipv4Addr, port: u16, inode: u64) -> ListeningSocket {
    ListeningSocket {
        address: IpAddr::V4(address),
        ..socket(port, inode)
    }
}

fn shared(port: u16, sharing: Sharing, target: &str) -> SharedPort {
    SharedPort {
        port,
        sharing,
        targets: BTreeSet::from([target.parse().unwrap()]),
    }
}

/// [`join`] on a LAN host with these facts from Tailscale.
fn join_with_tailscale(
    sockets: Vec<ListeningSocket>,
    published: Vec<PublishedPort>,
    tailscale: Result<Vec<SharedPort>, TailscaleError>,
) -> ScanReport {
    join(
        sockets,
        &open_files(false),
        Ok(lan_host()),
        Ok(published),
        tailscale,
        OptionsReport::default(),
        &firewall(UfwState::Inactive),
    )
}

fn tailscale_timed_out() -> TailscaleError {
    TailscaleError::Collect(CollectError::TimedOut {
        command: "tailscale serve status --json".to_string(),
        timeout: Duration::from_secs(5),
    })
}

#[test]
fn a_loopback_socket_behind_funnel_can_be_reached_from_the_internet() {
    let report = join_with_tailscale(
        vec![tcp_socket(Ipv4Addr::LOCALHOST, 3000, 100)],
        Vec::new(),
        Ok(vec![shared(443, Sharing::Funnel, "127.0.0.1:3000")]),
    );

    assert_eq!(
        report.ports[0].verdict.reach,
        Reach::From {
            networks: BTreeSet::from([Network::ThisHost, Network::Tailnet, Network::Internet]),
        }
    );
    assert_eq!(
        report.warnings,
        [ScanWarning::TailscaleFunnel {
            ports: BTreeSet::from([443]),
        }]
    );
}

#[test]
fn serve_alone_widens_the_row_but_is_no_warning() {
    let report = join_with_tailscale(
        vec![tcp_socket(Ipv4Addr::LOCALHOST, 3000, 100)],
        Vec::new(),
        Ok(vec![shared(8443, Sharing::Tailnet, "127.0.0.1:3000")]),
    );

    assert_eq!(
        report.ports[0].verdict.reach,
        Reach::From {
            networks: BTreeSet::from([Network::ThisHost, Network::Tailnet]),
        }
    );
    assert!(report.warnings.is_empty());
}

#[test]
fn funnel_warns_even_when_no_row_is_behind_it() {
    let report = join_with_tailscale(
        Vec::new(),
        Vec::new(),
        Ok(vec![SharedPort {
            port: 443,
            sharing: Sharing::Funnel,
            targets: BTreeSet::new(),
        }]),
    );

    assert!(report.ports.is_empty());
    assert_eq!(
        report.warnings,
        [ScanWarning::TailscaleFunnel {
            ports: BTreeSet::from([443]),
        }]
    );
}

#[test]
fn a_docker_forward_behind_funnel_is_widened_too() {
    let report = join_with_tailscale(
        Vec::new(),
        vec![published(8080, "web")],
        Ok(vec![shared(443, Sharing::Funnel, "127.0.0.1:8080")]),
    );

    assert!(matches!(
        report.ports[0].verdict.reason,
        Reason::TailscaleShared { .. }
    ));
}

#[test]
fn a_tailscale_that_cannot_be_asked_is_a_warning_and_the_scan_finishes() {
    let report = join_with_tailscale(
        vec![tcp_socket(Ipv4Addr::LOCALHOST, 3000, 100)],
        Vec::new(),
        Err(tailscale_timed_out()),
    );

    assert_eq!(report.ports[0].verdict.reason, Reason::Loopback);
    assert_eq!(report.warnings, [ScanWarning::TailscaleUnknown]);
    assert!(report.tailscale_error.is_some());
}

#[test]
fn diff_reports_a_port_that_became_shared_as_a_change() {
    let sockets = || vec![tcp_socket(Ipv4Addr::LOCALHOST, 3000, 100)];
    let before = join_with_tailscale(sockets(), Vec::new(), Ok(Vec::new()));
    let after = join_with_tailscale(
        sockets(),
        Vec::new(),
        Ok(vec![shared(443, Sharing::Funnel, "127.0.0.1:3000")]),
    );

    let diff = compare(&Snapshot::from(&before), &Snapshot::from(&after));

    assert!(matches!(
        diff.differences.as_slice(),
        [Difference {
            change: Change::Changed { .. },
            ..
        }]
    ));
}

#[test]
fn diff_knows_when_tailscale_could_not_be_asked() {
    let report = join_with_tailscale(Vec::new(), Vec::new(), Err(tailscale_timed_out()));

    assert_eq!(
        Snapshot::from(&report).missing,
        BTreeSet::from([Tolerant::Known(Collector::Tailscale)])
    );
}

/// A LAN host that is on a tailnet. `tailscale0` carries a link-local address
/// as well, which no client connects to.
fn tailnet_host() -> HostInterfaces {
    let on_tailscale = |ip: &str| HostAddress {
        interface: "tailscale0".to_string(),
        ip: ip.parse().unwrap(),
        broadcast: None,
    };
    let lan = lan_host();
    HostInterfaces {
        addresses: lan
            .addresses
            .into_iter()
            .chain(["100.64.0.1", "fd7a:115c:a1e0::1", "fe80::1"].map(on_tailscale))
            .collect(),
        ..lan
    }
}

/// [`join`] on a host on a tailnet, where Tailscale shares `shared`.
fn join_on_tailnet(sockets: Vec<ListeningSocket>, shared: Vec<SharedPort>) -> ScanReport {
    join(
        sockets,
        &open_files(false),
        Ok(tailnet_host()),
        Ok(Vec::new()),
        Ok(shared),
        OptionsReport::default(),
        &firewall(UfwState::Inactive),
    )
}

fn answered_by_tailscale(port: u16, sharing: Sharing) -> SharedPort {
    SharedPort {
        port,
        sharing,
        targets: BTreeSet::new(),
    }
}

fn addresses(report: &ScanReport) -> Vec<String> {
    report
        .ports
        .iter()
        .map(|port| port.endpoint.address.to_string())
        .collect()
}

#[test]
fn a_share_with_no_row_gets_one_on_each_tailscale_address() {
    let report = join_on_tailnet(
        Vec::new(),
        vec![answered_by_tailscale(8443, Sharing::Tailnet)],
    );

    assert_eq!(addresses(&report), ["100.64.0.1", "fd7a:115c:a1e0::1"]);
    let row = &report.ports[0];
    assert_eq!(row.endpoint.port, 8443);
    assert_eq!(row.endpoint.protocol, Protocol::Tcp);
    assert_eq!(row.listener, Listener::TailscaleShare);
    assert_eq!(row.service, Service::Tailscale);
    assert_eq!(
        row.verdict,
        Verdict {
            reach: Reach::From {
                networks: BTreeSet::from([Network::Tailnet]),
            },
            reason: Reason::TailscaleAccepts {
                sharing: Sharing::Tailnet,
            },
        }
    );
    assert!(report.warnings.is_empty());
}

#[test]
fn a_funnel_with_no_row_reaches_the_internet_and_still_warns() {
    let report = join_on_tailnet(
        Vec::new(),
        vec![answered_by_tailscale(443, Sharing::Funnel)],
    );

    assert_eq!(
        report.ports[0].verdict.reach,
        Reach::From {
            networks: BTreeSet::from([Network::Tailnet, Network::Internet]),
        }
    );
    assert_eq!(
        report.warnings,
        [ScanWarning::TailscaleFunnel {
            ports: BTreeSet::from([443]),
        }]
    );
}

#[test]
fn a_share_that_forwards_to_a_row_gets_no_row_of_its_own() {
    let report = join_on_tailnet(
        vec![tcp_socket(Ipv4Addr::LOCALHOST, 3000, 100)],
        vec![shared(443, Sharing::Tailnet, "127.0.0.1:3000")],
    );

    assert_eq!(addresses(&report), ["127.0.0.1"]);
}

#[test]
fn a_share_of_a_stopped_program_gets_a_row() {
    let report = join_on_tailnet(
        Vec::new(),
        vec![shared(443, Sharing::Tailnet, "127.0.0.1:3000")],
    );

    assert_eq!(addresses(&report), ["100.64.0.1", "fd7a:115c:a1e0::1"]);
}

#[test]
fn a_socket_on_a_shared_address_keeps_its_row_and_the_share_adds_one() {
    // The share can reach further than the socket, so one must not hide the other.
    let report = join_on_tailnet(
        vec![tcp_socket(Ipv4Addr::new(100, 64, 0, 1), 443, 100)],
        vec![answered_by_tailscale(443, Sharing::Funnel)],
    );

    let on_address: Vec<Listener> = report
        .ports
        .iter()
        .filter(|port| port.endpoint.address == IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1)))
        .map(|port| port.listener)
        .collect();
    assert_eq!(on_address, [Listener::HostSocket, Listener::TailscaleShare]);
}

#[test]
fn a_tailnet_share_with_no_tailscale_address_is_a_warning() {
    let report = join_with_tailscale(
        Vec::new(),
        Vec::new(),
        Ok(vec![answered_by_tailscale(8443, Sharing::Tailnet)]),
    );

    assert!(report.ports.is_empty());
    assert_eq!(
        report.warnings,
        [ScanWarning::TailscaleNoRow {
            ports: BTreeSet::from([8443]),
        }]
    );
}

#[test]
fn a_share_that_forwards_to_a_row_needs_no_tailscale_address() {
    let report = join_with_tailscale(
        vec![tcp_socket(Ipv4Addr::LOCALHOST, 3000, 100)],
        Vec::new(),
        Ok(vec![shared(8443, Sharing::Tailnet, "127.0.0.1:3000")]),
    );

    assert!(report.warnings.is_empty());
}

#[test]
fn diff_reports_a_new_share_with_no_row() {
    let before = join_on_tailnet(Vec::new(), Vec::new());
    let after = join_on_tailnet(
        Vec::new(),
        vec![answered_by_tailscale(443, Sharing::Funnel)],
    );

    let diff = compare(&Snapshot::from(&before), &Snapshot::from(&after));

    assert!(matches!(
        diff.differences.as_slice(),
        [
            Difference {
                change: Change::New { .. },
                ..
            },
            Difference {
                change: Change::New { .. },
                ..
            }
        ]
    ));
}

#[test]
fn a_tailnet_share_is_a_warning_when_the_interfaces_could_not_be_listed() {
    let report = join(
        Vec::new(),
        &open_files(false),
        Err(not_found()),
        Ok(Vec::new()),
        Ok(vec![answered_by_tailscale(8443, Sharing::Tailnet)]),
        OptionsReport::default(),
        &firewall(UfwState::Inactive),
    );

    assert!(report.ports.is_empty());
    assert_eq!(
        report.warnings,
        [ScanWarning::TailscaleNoRow {
            ports: BTreeSet::from([8443]),
        }]
    );
}

#[test]
fn a_wildcard_socket_on_a_shared_port_keeps_its_reach_beside_the_share() {
    // The socket does not get what Tailscale accepts, so its row stays as it is.
    let sockets = || vec![tcp_socket(Ipv4Addr::UNSPECIFIED, 443, 100)];
    let alone = join_on_tailnet(sockets(), Vec::new());

    let report = join_on_tailnet(sockets(), vec![answered_by_tailscale(443, Sharing::Funnel)]);

    assert_eq!(
        addresses(&report),
        ["0.0.0.0", "100.64.0.1", "fd7a:115c:a1e0::1"]
    );
    assert_eq!(report.ports[0], alone.ports[0]);
    assert_eq!(report.ports[1].listener, Listener::TailscaleShare);
}

#[test]
fn diff_tells_a_share_from_a_socket_on_the_same_address() {
    let sockets = || vec![tcp_socket(Ipv4Addr::new(100, 64, 0, 1), 443, 100)];
    let before = join_on_tailnet(sockets(), vec![answered_by_tailscale(443, Sharing::Funnel)]);
    let after = join_on_tailnet(sockets(), Vec::new());

    let diff = compare(&Snapshot::from(&before), &Snapshot::from(&after));

    // The share goes from both Tailscale addresses, and the socket's row stays.
    assert_eq!(diff.differences.len(), 2);
    assert!(diff.differences.iter().all(|difference| matches!(
        &difference.change,
        Change::Removed { was } if was.listener == Tolerant::Known(Listener::TailscaleShare)
    )));
}
