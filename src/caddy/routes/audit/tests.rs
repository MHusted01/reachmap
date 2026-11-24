//! Correlation outcomes for the lab-shaped Caddy configuration.

use std::net::SocketAddr;
use std::num::NonZeroU64;

use super::*;
use crate::caddy::routes::collect_with;
use crate::caddy::routes::snapshot::Snapshot;
use crate::caddy::routes::tests::{Socket, addr, inventory, json_source};
use crate::probe::Outcome;
use crate::scan::ScanError;

mod routes;

/// `caddy adapt` output (Caddy 2.11.9) for a Caddyfile with `/app/*`,
/// `/missing/*`, `/admin/*` (`basic_auth`), `/pool/*`, `/remote/*` and
/// `/healthz` on `http://app.example.test:8080` with `auto_https off`.
pub(super) const LAB: &str = include_str!("../../../../tests/fixtures/caddy/audit/lab.json");

pub(super) const BASE_TIME: u64 = 1_700_000_000;

pub(super) fn lab_sockets() -> Vec<Socket> {
    vec![
        (addr("[::]:8080"), Some(false)),
        (addr("127.0.0.1:18080"), Some(false)),
    ]
}

pub(super) fn snapshot(json: &str, sockets: &[Socket]) -> Snapshot {
    let report = collect_with(json_source(json), || Ok(inventory(sockets))).expect("report");
    Snapshot::new(
        "example-caddy".parse().expect("host ref"),
        BASE_TIME,
        report,
    )
}

pub(super) fn scope() -> Scope<'static> {
    Scope {
        collector_identity: "host-a",
        network_context: "test-net",
    }
}

pub(super) fn capture(snapshot: &Snapshot) -> Capture<'_> {
    Capture {
        snapshot,
        scope: Some(scope()),
    }
}

pub(super) fn obs(path: &'static str, status: u16) -> HttpObservation<'static> {
    HttpObservation {
        scope: Some(scope()),
        destination: addr("192.0.2.1:8080"),
        host: "app.example.test",
        path,
        tls: false,
        tls_status: TlsStatus::NotUsed,
        credentials_presented: None,
        started_at_unix_seconds: NonZeroU64::new(BASE_TIME + 1),
        finished_at_unix_seconds: NonZeroU64::new(BASE_TIME + 2),
        outcome: HttpOutcome::from_status_code(status).unwrap_or(HttpOutcome::NoResponse {}),
        tcp: None,
    }
}

pub(super) fn run<'a>(snapshot: &'a Snapshot, observation: HttpObservation<'a>) -> Report<'a> {
    correlate(Some(capture(snapshot)), Some(observation), 30)
}

pub(super) fn unavailable(reason: Gap) -> Comparison {
    Comparison::Unavailable { reason }
}

#[test]
fn live_backend_success_is_consistent_and_keeps_application_auth_unverified() {
    let snap = snapshot(LAB, &lab_sockets());
    let report = run(&snap, obs("/app/items", 200));

    assert_eq!(report.comparison, Comparison::Consistent {});
    let route = report.route.as_ref().expect("route");
    assert!(route.on_disk_config_only);
    assert!(route.running_config_unverified);
    assert!(route.collection_complete);
    assert_eq!(route.uncertainty_count, 0);
    assert_eq!(route.server_name, "srv0");
    assert_eq!(route.listen_port, 8080);
    assert!(!route.tls);
    assert_eq!(
        route.frontend_listener,
        ListenerEvidence::Matched {
            address: addr("[::]:8080")
        }
    );
    assert!(matches!(
        route.end,
        Some(RouteEnd::ReverseProxy { upstreams }) if upstreams.len() == 1
    ));
    assert_eq!(
        report.backend,
        Some(BackendEvidence::LocalTcpPresent {
            addresses: vec![addr("127.0.0.1:18080")]
        })
    );
    let auth = report.auth.expect("auth");
    assert_eq!(auth.indicator, ProxyAuthIndicator::NoneConfigured);
    assert_eq!(auth.application_auth, ApplicationAuthStatus::Unverified {});
    assert_eq!(report.tcp.state, TcpLayerState::NotSeparatelyObserved);
}

#[test]
fn gateway_errors_are_explained_by_backend_listeners_not_firewalls() {
    let snap = snapshot(LAB, &lab_sockets());
    for status in [502, 503, 504] {
        let missing = run(&snap, obs("/missing/x", status));
        assert_eq!(missing.comparison, Comparison::Consistent {});
        assert_eq!(missing.backend, Some(BackendEvidence::LocalTcpAbsent {}));
        assert_eq!(missing.tcp.state, TcpLayerState::NotSeparatelyObserved);

        let present = run(&snap, obs("/app/x", status));
        assert_eq!(
            present.comparison,
            unavailable(Gap::BackendApplicationErrorUnverified)
        );
    }
    let healthz = run(&snap, obs("/healthz", 502));
    assert_eq!(healthz.backend, Some(BackendEvidence::NoProxyTarget {}));
    assert_eq!(healthz.comparison, Comparison::Disagrees {});
}

#[test]
fn success_or_not_found_without_a_backend_listener_disagrees() {
    let snap = snapshot(LAB, &lab_sockets());
    assert_eq!(
        run(&snap, obs("/missing/x", 200)).comparison,
        Comparison::Disagrees {}
    );
    assert_eq!(
        run(&snap, obs("/missing/x", 404)).comparison,
        Comparison::Disagrees {}
    );
    assert_eq!(
        run(&snap, obs("/app/x", 404)).comparison,
        Comparison::Consistent {}
    );
    assert_eq!(
        run(&snap, obs("/missing/x", 302)).comparison,
        unavailable(Gap::HttpStatusInconclusive)
    );
    assert_eq!(
        run(&snap, obs("/app/x", 500)).comparison,
        unavailable(Gap::HttpStatusInconclusive)
    );
}

#[test]
fn basic_auth_is_proxy_auth_and_never_application_auth() {
    let snap = snapshot(LAB, &lab_sockets());
    for status in [401, 403] {
        let report = run(&snap, obs("/admin/", status));
        assert_eq!(report.comparison, Comparison::Consistent {});
        let auth = report.auth.expect("auth");
        assert!(auth.http_basic);
        assert_eq!(auth.indicator, ProxyAuthIndicator::Configured);
        assert_eq!(auth.application_auth, ApplicationAuthStatus::Unverified {});

        assert_eq!(
            run(&snap, obs("/app/x", status)).comparison,
            unavailable(Gap::UnverifiedApplicationPolicy)
        );
        assert_eq!(
            run(&snap, obs("/missing/x", status)).comparison,
            Comparison::Disagrees {}
        );
    }
    assert_eq!(
        run(&snap, obs("/admin/", 200)).comparison,
        unavailable(Gap::ProxyAuthStateUnverified)
    );
    let without = HttpObservation {
        credentials_presented: Some(false),
        ..obs("/admin/", 200)
    };
    assert_eq!(run(&snap, without).comparison, Comparison::Disagrees {});
    let with = HttpObservation {
        credentials_presented: Some(true),
        ..obs("/admin/", 200)
    };
    assert_eq!(run(&snap, with).comparison, Comparison::Consistent {});
}

#[test]
fn remote_mixed_and_responder_backends() {
    let snap = snapshot(LAB, &lab_sockets());
    let remote = run(&snap, obs("/remote/x", 200));
    assert_eq!(remote.backend, Some(BackendEvidence::NonLocalOrRemote {}));
    assert_eq!(remote.comparison, unavailable(Gap::BackendUnverified));

    let pool = run(&snap, obs("/pool/x", 502));
    assert_eq!(
        pool.backend,
        Some(BackendEvidence::LocalTcpUncertain {
            reason: BackendUncertainty::MixedUpstreamAvailability
        })
    );
    assert_eq!(pool.comparison, unavailable(Gap::BackendUnverified));

    let healthz = run(&snap, obs("/healthz", 200));
    assert!(matches!(
        healthz.route.as_ref().and_then(|route| route.end),
        Some(RouteEnd::Respond { .. })
    ));
    assert_eq!(healthz.comparison, Comparison::Consistent {});
}

#[test]
fn no_response_and_failed_probes_never_become_firewall_verdicts() {
    let snap = snapshot(LAB, &lab_sockets());
    let silent = run(&snap, obs("/app/x", 0));
    assert_eq!(silent.comparison, unavailable(Gap::NoResponseInconclusive));
    assert_eq!(silent.tcp.state, TcpLayerState::NotSeparatelyObserved);

    let failed = Outcome::Failed {
        message: "test".to_owned(),
    };
    let probe_failed = HttpObservation {
        tcp: Some(TcpObservation {
            handshake: Some(&failed),
            inbound_path_verdict: None,
        }),
        ..obs("/app/x", 0)
    };
    let report = run(&snap, probe_failed);
    assert_eq!(report.comparison, unavailable(Gap::TcpProbeFailed));
    assert_eq!(report.tcp.state, TcpLayerState::ProbeFailed);

    let blocked = HttpObservation {
        tcp: Some(TcpObservation {
            handshake: Some(&Outcome::NoAnswer),
            inbound_path_verdict: Some(InboundTcpVerdict::Blocked),
        }),
        ..obs("/app/x", 200)
    };
    let report = run(&snap, blocked);
    assert_eq!(report.comparison, Comparison::Disagrees {});
    assert_eq!(report.tcp.state, TcpLayerState::BlockedOrClosed);

    let handshake_failed = HttpObservation {
        tls: true,
        tls_status: TlsStatus::HandshakeFailed,
        ..obs("/app/x", 0)
    };
    assert_eq!(
        run(&snap, handshake_failed).comparison,
        unavailable(Gap::TlsSchemeMismatch)
    );
}

#[test]
fn missing_frontend_listener_disagrees_only_with_a_response() {
    let sockets = [(addr("127.0.0.1:18080"), Some(false))];
    let snap = snapshot(LAB, &sockets);
    let report = run(&snap, obs("/app/x", 200));
    let route = report.route.as_ref().expect("route");
    assert_eq!(route.frontend_listener, ListenerEvidence::Missing {});
    assert_eq!(report.comparison, Comparison::Disagrees {});
    assert_eq!(
        run(&snap, obs("/app/x", 0)).comparison,
        unavailable(Gap::NoResponseInconclusive)
    );

    let unknown_options = [
        (addr("[::]:8080"), None),
        (addr("127.0.0.1:18080"), Some(false)),
    ];
    let snap = snapshot(LAB, &unknown_options);
    assert_eq!(
        run(&snap, obs("/app/x", 200)).comparison,
        unavailable(Gap::FrontendListenerUncertain)
    );
}

#[test]
fn stale_mismatched_or_missing_scope_is_inconclusive() {
    let snap = snapshot(LAB, &lab_sockets());
    let report = |capture: Option<Capture<'_>>, observation| {
        correlate(capture, Some(observation), 30).comparison
    };
    let ok = obs("/app/x", 200);

    assert_eq!(
        correlate(None, Some(ok), 30).comparison,
        unavailable(Gap::CaptureMissing)
    );
    assert_eq!(
        correlate(Some(capture(&snap)), None, 30).comparison,
        unavailable(Gap::ObservationMissing)
    );
    let unscoped = Capture {
        snapshot: &snap,
        scope: None,
    };
    assert_eq!(
        report(Some(unscoped), ok),
        unavailable(Gap::CaptureScopeMissing)
    );
    let other_host = HttpObservation {
        scope: Some(Scope {
            collector_identity: "host-b",
            ..scope()
        }),
        ..ok
    };
    assert_eq!(
        report(Some(capture(&snap)), other_host),
        unavailable(Gap::CollectorMismatch)
    );
    let other_net = HttpObservation {
        scope: Some(Scope {
            network_context: "other-net",
            ..scope()
        }),
        ..ok
    };
    assert_eq!(
        report(Some(capture(&snap)), other_net),
        unavailable(Gap::NetworkMismatch)
    );
    let stale = HttpObservation {
        started_at_unix_seconds: NonZeroU64::new(BASE_TIME + 100),
        finished_at_unix_seconds: NonZeroU64::new(BASE_TIME + 101),
        ..ok
    };
    assert_eq!(
        report(Some(capture(&snap)), stale),
        unavailable(Gap::CaptureStale)
    );
    let before_capture = HttpObservation {
        started_at_unix_seconds: NonZeroU64::new(BASE_TIME - 5),
        ..ok
    };
    assert_eq!(
        report(Some(capture(&snap)), before_capture),
        unavailable(Gap::CaptureAfterProbe)
    );
    let untimed = HttpObservation {
        finished_at_unix_seconds: None,
        ..ok
    };
    assert_eq!(
        report(Some(capture(&snap)), untimed),
        unavailable(Gap::CaptureOrProbeTimeMissing)
    );
    let invalid = HttpObservation {
        path: "app?x=1",
        ..ok
    };
    let invalid_report = correlate(Some(capture(&snap)), Some(invalid), 30);
    assert_eq!(
        invalid_report.comparison,
        unavailable(Gap::InvalidObservation)
    );
    assert!(invalid_report.route.is_none());
}

#[test]
fn partial_collection_and_uncertain_configuration_are_inconclusive() {
    let partial_report = collect_with(json_source(LAB), || {
        Err(ScanError::UnsupportedOs { os: "plan9" })
    })
    .expect("report");
    let partial = Snapshot::new(
        "example-caddy".parse().expect("host ref"),
        BASE_TIME,
        partial_report,
    );
    let report = run(&partial, obs("/app/x", 200));
    assert_eq!(report.comparison, unavailable(Gap::CollectionPartial));
    assert_eq!(
        report.route.map(|route| route.frontend_listener),
        Some(ListenerEvidence::InventoryUnavailable {})
    );

    let dynamic = LAB.replace("127.0.0.1:18081", "{http.request.header.X-Backend}");
    let snap = snapshot(&dynamic, &lab_sockets());
    let report = run(&snap, obs("/app/x", 200));
    assert_eq!(report.comparison, unavailable(Gap::ConfigUncertain));
    assert!(report.route.expect("route").uncertainty_count > 0);
}

#[test]
fn report_serializes_layers_without_configured_secrets() {
    let snap = snapshot(LAB, &lab_sockets());
    let report = run(&snap, obs("/admin/", 401));
    let json = serde_json::to_string(&report).expect("json");
    assert!(
        json.contains(r#""comparison":{"status":"consistent"}"#),
        "{json}"
    );
    assert!(
        json.contains(r#""application_auth":{"status":"unverified"}"#),
        "{json}"
    );
    assert!(!json.contains("SYNTHETIC"), "{json}");
    assert!(!json.contains("labuser"), "{json}");

    let gap = run(&snap, obs("/app/x", 0));
    let json = serde_json::to_string(&gap.comparison).expect("json");
    assert_eq!(
        json,
        r#"{"status":"unavailable","reason":"no_response_inconclusive"}"#
    );
    assert!(Gap::NoResponseInconclusive.to_string().contains("firewall"));
}

#[test]
fn listener_addresses_are_matched_by_family() {
    let ipv4_only = [
        (addr("0.0.0.0:8080"), Some(false)),
        (addr("127.0.0.1:18080"), Some(false)),
    ];
    let snap = snapshot(LAB, &ipv4_only);
    let report = run(&snap, obs("/app/x", 200));
    assert_eq!(
        report.route.map(|route| route.frontend_listener),
        Some(ListenerEvidence::Matched {
            address: SocketAddr::from(([0, 0, 0, 0], 8080))
        })
    );
}
