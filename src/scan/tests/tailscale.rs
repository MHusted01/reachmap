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
