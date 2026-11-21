use reachmap::inbound_path::audit::{
    Capture, Comparison, Gap, Ingress, Observation, Scope, correlate,
};
use reachmap::inbound_path::{Snapshot, read};
use reachmap::probe::Outcome;
use serde_json::{Value, json, to_value};

use super::{collected, docker_snapshot, scan_file, snapshot};

const SCOPE: Scope<'static> = Scope {
    collector_identity: "example-authenticated-host",
    network_context: "example-network",
};
const CAPTURED_AT: u64 = 1_700_000_000;
const MAX_AGE: u64 = 30;

fn load(name: &str, fixture: &Value) -> Snapshot {
    read(&scan_file(name, &fixture.to_string())).unwrap()
}

fn capture(snapshot: &Snapshot) -> Capture<'_> {
    Capture {
        snapshot,
        scope: Some(SCOPE),
    }
}

fn observed(outcome: &Outcome) -> Observation<'_> {
    Observation {
        scope: Some(SCOPE),
        source: Some("192.0.2.2".parse().unwrap()),
        destination: "192.0.2.1:8443".parse().unwrap(),
        ingress: Some(Ingress::Declared("eth0")),
        started_at_unix_seconds: NonZeroU64::new(CAPTURED_AT + MAX_AGE - 1),
        finished_at_unix_seconds: NonZeroU64::new(CAPTURED_AT + MAX_AGE),
        outcome,
    }
}

#[test]
fn successful_handshakes_match_supported_predictions_for_both_ip_families() {
    let v4 = load("audit_ipv4.json", &snapshot());
    let observation = observed(&Outcome::Open);
    let report = correlate(Some(capture(&v4)), Some(observation), MAX_AGE);
    assert_eq!(report.comparison, Comparison::Consistent);
    let json = to_value(report).unwrap();
    assert_eq!(json["prediction"]["verdict"], "listener_reachable");
    assert_eq!(json["observation"]["outcome"]["kind"], "open");
    assert_eq!(json["observation"]["ingress"], json!({"declared": "eth0"}));

    let mut v6 = snapshot();
    v6["flow"]["source"] = json!("2001:db8::2");
    v6["flow"]["destination"] = json!("2001:db8::1");
    v6["evidence"]["ipv6_disabled"] = collected(false);
    v6["evidence"]["routing_rules"] = collected(
        r#"[{"priority":0,"src":"all","table":"local"},
            {"priority":32766,"src":"all","table":"main"}]"#,
    );
    v6["evidence"]["route"] = collected(
        r#"[{"type":"local","dst":"2001:db8::1","from":"2001:db8::2","iif":"eth0","dev":"lo"}]"#,
    );
    let v6 = load("audit_ipv6.json", &v6);
    let observation = Observation {
        source: Some("2001:db8::2".parse().unwrap()),
        destination: "[2001:db8::1]:8443".parse().unwrap(),
        ingress: Some(Ingress::Observed("eth0")),
        ..observation
    };
    let report = correlate(Some(capture(&v6)), Some(observation), MAX_AGE);
    assert_eq!(report.comparison, Comparison::Consistent, "{report:?}");
    assert_eq!(
        to_value(report).unwrap()["observation"]["ingress"],
        json!({"observed": "eth0"})
    );
}

#[test]
fn divergence_keeps_the_prediction_and_handshake_outcome_visible() {
    let mut fixture = snapshot();
    fixture["evidence"]["nftables"] = collected(
        r#"{"nftables":[{"table":{"family":"inet","name":"site"}},
        {"chain":{"family":"inet","table":"site","name":"input","type":"filter",
        "hook":"input","prio":0,"policy":"drop"}}]}"#,
    );
    let blocked = load("audit_blocked.json", &fixture);
    let blocked = Some(capture(&blocked));
    let report = correlate(blocked, Some(observed(&Outcome::Open)), MAX_AGE);
    assert_eq!(report.comparison, Comparison::Disagrees);
    let json = to_value(report).unwrap();
    assert_eq!(json["prediction"]["verdict"], "blocked");
    assert_eq!(json["observation"]["outcome"]["kind"], "open");

    let report = correlate(blocked, Some(observed(&Outcome::NoAnswer)), MAX_AGE);
    assert_eq!(report.comparison, Comparison::Consistent);

    let reachable = load("audit_refused.json", &snapshot());
    let report = correlate(
        Some(capture(&reachable)),
        Some(observed(&Outcome::Closed)),
        MAX_AGE,
    );
    assert_eq!(report.comparison, Comparison::Disagrees);
    let json = to_value(report).unwrap();
    assert_eq!(json["prediction"]["verdict"], "listener_reachable");
    assert_eq!(json["observation"]["outcome"]["kind"], "closed");
}

#[test]
fn docker_predictions_correlate_only_with_the_published_endpoint() {
    let fixture = load("audit_docker_publish.json", &docker_snapshot());
    let capture = Some(capture(&fixture));
    let observation = observed(&Outcome::Open);
    let report = correlate(capture, Some(observation), MAX_AGE);
    assert_eq!(report.comparison, Comparison::Consistent);
    let json = to_value(report).unwrap();
    assert_eq!(
        json["prediction"]["steps"][1]["translation"]["translated"],
        "198.51.100.2:8080"
    );

    let backend = Observation {
        destination: "198.51.100.2:8080".parse().unwrap(),
        ..observation
    };
    let report = correlate(capture, Some(backend), MAX_AGE);
    assert_eq!(
        report.comparison,
        Comparison::Unavailable(Gap::DestinationMismatch)
    );
}

#[test]
fn comparison_requires_the_same_host_network_addresses_source_and_ingress() {
    let fixture = load("audit_flow_scope.json", &snapshot());
    let capture = capture(&fixture);
    let observation = observed(&Outcome::Open);
    let other_host = Scope {
        collector_identity: "example-host",
        ..SCOPE
    };
    let other_network = Scope {
        network_context: "other-network",
        ..SCOPE
    };
    let cases = [
        (
            Observation {
                scope: None,
                ..observation
            },
            Gap::ObservationScopeMissing,
        ),
        (
            Observation {
                scope: Some(other_host),
                ..observation
            },
            Gap::CollectorMismatch,
        ),
        (
            Observation {
                scope: Some(other_network),
                ..observation
            },
            Gap::NetworkMismatch,
        ),
        (
            Observation {
                destination: "192.0.2.9:8443".parse().unwrap(),
                ..observation
            },
            Gap::DestinationMismatch,
        ),
        (
            Observation {
                destination: "192.0.2.1:8444".parse().unwrap(),
                ..observation
            },
            Gap::DestinationMismatch,
        ),
        (
            Observation {
                source: None,
                ..observation
            },
            Gap::SourceMissing,
        ),
        (
            Observation {
                source: Some("192.0.2.9".parse().unwrap()),
                ..observation
            },
            Gap::SourceMismatch,
        ),
        (
            Observation {
                ingress: None,
                ..observation
            },
            Gap::IngressMissing,
        ),
        (
            Observation {
                ingress: Some(Ingress::Observed("eth1")),
                ..observation
            },
            Gap::IngressMismatch,
        ),
    ];
    for (observation, gap) in cases {
        let report = correlate(Some(capture), Some(observation), MAX_AGE);
        assert_eq!(report.comparison, Comparison::Unavailable(gap));
        assert!(report.prediction.is_some());
        assert!(report.observation.is_some());
    }

    let untrusted = Capture {
        scope: None,
        ..capture
    };
    let report = correlate(Some(untrusted), Some(observation), MAX_AGE);
    assert_eq!(
        report.comparison,
        Comparison::Unavailable(Gap::CaptureScopeMissing)
    );
}

#[test]
fn comparison_requires_ordered_times_within_the_age_limit_at_probe_finish() {
    let fixture = load("audit_capture_age.json", &snapshot());
    let timed_capture = Some(capture(&fixture));
    let observation = observed(&Outcome::Open);
    for (start, finish, gap) in [
        (None, Some(CAPTURED_AT), Gap::CaptureOrProbeTimeMissing),
        (Some(CAPTURED_AT), None, Gap::CaptureOrProbeTimeMissing),
        (
            Some(CAPTURED_AT - 1),
            Some(CAPTURED_AT),
            Gap::CaptureAfterProbe,
        ),
        (
            Some(CAPTURED_AT + 1),
            Some(CAPTURED_AT),
            Gap::ProbeTimeReversed,
        ),
        (
            Some(CAPTURED_AT),
            Some(CAPTURED_AT + MAX_AGE + 1),
            Gap::CaptureStale,
        ),
    ] {
        let observation = Observation {
            started_at_unix_seconds: start.and_then(NonZeroU64::new),
            finished_at_unix_seconds: finish.and_then(NonZeroU64::new),
            ..observation
        };
        let report = correlate(timed_capture, Some(observation), MAX_AGE);
        assert_eq!(report.comparison, Comparison::Unavailable(gap));
    }

    let mut no_time = snapshot();
    no_time["captured_at_unix_seconds"] = json!(0);
    let no_time = load("audit_capture_without_timestamp.json", &no_time);
    let report = correlate(Some(capture(&no_time)), Some(observation), MAX_AGE);
    assert_eq!(
        report.comparison,
        Comparison::Unavailable(Gap::CaptureOrProbeTimeMissing)
    );
}

#[test]
fn absent_evidence_and_an_unsupported_stage_leave_each_available_result_intact() {
    let mut fixture = snapshot();
    fixture["evidence"]["routing_rules"] = collected(
        r#"[{"priority":0,"src":"all","table":"local"},
            {"priority":100,"src":"192.0.2.2/32","table":"site"},
            {"priority":32766,"src":"all","table":"main"},
            {"priority":32767,"src":"all","table":"default"}]"#,
    );
    let snapshot = load("audit_unsupported_stage.json", &fixture);
    let capture = Some(capture(&snapshot));
    let observation = Some(observed(&Outcome::Open));
    let report = correlate(capture, observation, MAX_AGE);
    assert_eq!(
        report.comparison,
        Comparison::Unavailable(Gap::PredictionInconclusive)
    );
    let json = to_value(report).unwrap();
    assert_eq!(json["prediction"]["verdict"], "unknown");
    assert_eq!(json["prediction"]["steps"][1]["stage"], "routing");
    assert_eq!(
        json["prediction"]["steps"][1]["reason"],
        "routing policy differs from the default rules"
    );
    assert_eq!(json["observation"]["outcome"]["kind"], "open");

    let report = correlate(None, observation, MAX_AGE);
    assert_eq!(
        report.comparison,
        Comparison::Unavailable(Gap::CaptureMissing)
    );
    assert!(report.observation.is_some());
    let report = correlate(capture, None, MAX_AGE);
    assert_eq!(
        report.comparison,
        Comparison::Unavailable(Gap::ObservationMissing)
    );
    assert!(report.prediction.is_some());
}

#[test]
fn probe_execution_errors_leave_no_handshake_evidence_to_compare() {
    let fixture = load("audit_failed_probe.json", &snapshot());
    let outcome = Outcome::Failed {
        message: "local socket unavailable".to_owned(),
    };
    let report = correlate(Some(capture(&fixture)), Some(observed(&outcome)), MAX_AGE);
    assert_eq!(report.comparison, Comparison::Unavailable(Gap::ProbeFailed));
    assert_eq!(
        to_value(report).unwrap()["observation"]["outcome"]["message"],
        "local socket unavailable"
    );
}

#[test]
fn comparison_declines_an_ipv6_flow_that_requires_a_zone() {
    let mut fixture = snapshot();
    fixture["flow"]["source"] = json!("fe80::2");
    fixture["flow"]["destination"] = json!("fe80::1");
    let fixture = load("audit_zoned_ipv6.json", &fixture);
    let observation = Observation {
        source: Some("fe80::2".parse().unwrap()),
        destination: "[fe80::1%2]:8443".parse().unwrap(),
        ..observed(&Outcome::Open)
    };
    let report = correlate(Some(capture(&fixture)), Some(observation), MAX_AGE);
    assert_eq!(
        report.comparison,
        Comparison::Unavailable(Gap::Ipv6ZoneUnsupported)
    );
}

#[test]
fn a_directly_decoded_snapshot_still_requires_a_supported_format() {
    let mut fixture = snapshot();
    fixture["snapshot_version"] = json!(2);
    let fixture = serde_json::from_value(fixture).unwrap();
    let report = correlate(
        Some(capture(&fixture)),
        Some(observed(&Outcome::Open)),
        MAX_AGE,
    );
    assert_eq!(
        report.comparison,
        Comparison::Unavailable(Gap::InvalidCapture)
    );
    assert!(report.prediction.is_none());
    assert!(report.observation.is_some());
}
use std::num::NonZeroU64;
