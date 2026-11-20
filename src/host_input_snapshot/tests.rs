use super::*;
use crate::docker::DockerCollectError;
use crate::socket::SocketOptions;
use crate::socket_options::SocketOptionsError;

const EMPTY_RULES: &str = r#"{"nftables":[]}"#;

fn command_error(command: &str, kind: ErrorKind) -> CollectError {
    CollectError::Run {
        command: command.into(),
        source: kind.into(),
    }
}

fn report() -> ScanReport {
    ScanReport {
        ports: Vec::new(),
        interfaces_error: None,
        docker_error: None,
        socket_options_error: None,
        tailscale_error: None,
        nftables: None,
        docker_publishes: Vec::new(),
        macos: None,
        warnings: Vec::new(),
    }
}

fn capture(report: &ScanReport) -> HostInputSnapshot {
    HostInputSnapshot::from_scan(
        "fixture-host".parse().unwrap(),
        1_700_000_000,
        None,
        report,
        Status::Collected,
        Ok(EMPTY_RULES.to_owned()),
    )
}

#[test]
fn socket_options_capture_reports_partial_reads_separately() {
    let mut report = OptionsReport::default();
    assert!(matches!(Status::socket_options(&report), Status::Collected));
    report.error = Some(SocketOptionsError::Open(CollectError::SockDiag {
        action: "open",
        source: ErrorKind::PermissionDenied.into(),
    }));
    assert!(matches!(Status::socket_options(&report), Status::Failed));
    report.by_inode.insert(
        42,
        SocketOptions {
            bound_device: None,
            ipv6_only: true,
        },
    );
    assert!(matches!(Status::socket_options(&report), Status::Partial));
}

#[test]
fn snapshot_marks_docker_unavailable_when_it_is_not_installed() {
    let mut report = report();
    assert!(matches!(
        capture(&report).collectors.docker,
        Status::Collected
    ));
    report.docker_error = Some(DockerError::NotInstalled);
    assert!(matches!(
        capture(&report).collectors.docker,
        Status::Unavailable
    ));
    report.docker_error = Some(DockerCollectError::HttpStatus(500).into());
    assert!(matches!(capture(&report).collectors.docker, Status::Failed));
}

#[test]
fn live_and_replayed_checks_report_the_same_interface_failure_reason() {
    for kind in [ErrorKind::NotFound, ErrorKind::PermissionDenied] {
        let mut report = report();
        report.interfaces_error = Some(InterfacesError::Collect(command_error("ip -j addr", kind)));
        nftables::check_scan(Ok(EMPTY_RULES.to_owned()), None, &mut report);
        let snapshot = capture(&report);
        let expected_status = if kind == ErrorKind::NotFound {
            "unavailable"
        } else {
            "failed"
        };
        let evidence = serde_json::to_value(&snapshot.collectors.interfaces).unwrap();
        assert_eq!(evidence["status"], expected_status);
        let replayed =
            serde_json::to_value(replay_document(&snapshot.render().unwrap()).unwrap()).unwrap();
        assert_eq!(
            replayed,
            serde_json::to_value(report.nftables.unwrap()).unwrap()
        );
        assert_eq!(replayed["status"], "unknown");
        assert_eq!(replayed["reason"], evidence["reason"]);
    }
}

#[test]
fn nftables_capture_distinguishes_absent_command_failed_read_and_empty_rules() {
    let nft_error = |kind| Err(command_error("nft -j list ruleset", kind));
    assert!(matches!(
        nftables_evidence(nft_error(ErrorKind::NotFound)),
        Evidence::Unavailable { .. }
    ));
    assert!(matches!(
        nftables_evidence(nft_error(ErrorKind::PermissionDenied)),
        Evidence::Failed { .. }
    ));
    assert!(matches!(
        nftables_evidence(Ok("malformed".into())),
        Evidence::Failed { .. }
    ));
    assert!(matches!(
        nftables_evidence(Ok(EMPTY_RULES.into())),
        Evidence::Collected { .. }
    ));
}

#[test]
fn host_reference_requires_a_short_printable_label() {
    for label in ["", "  ", "bad\nlabel", "bad\u{202e}label", &"x".repeat(129)] {
        assert!(matches!(
            label.parse::<HostRef>(),
            Err(SnapshotError::HostRef)
        ));
    }
    assert!("x".repeat(128).parse::<HostRef>().is_ok());
}
