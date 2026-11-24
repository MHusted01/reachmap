//! Tests for the proxy-neutral correlation steps.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::num::NonZeroU64;

use super::*;
use crate::probe::Outcome;

type Result = std::result::Result<Comparison<()>, CommonGap>;

const T0: u64 = 1_700_000_000;

fn scope() -> Scope<'static> {
    Scope {
        collector_identity: "host-a",
        network_context: "test-net",
    }
}

fn obs(status: u16) -> HttpObservation<'static> {
    HttpObservation {
        scope: Some(scope()),
        destination: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 80),
        host: "app.example.test",
        path: "/",
        tls: false,
        tls_status: TlsStatus::NotUsed,
        credentials_presented: None,
        started_at_unix_seconds: NonZeroU64::new(T0 + 1),
        finished_at_unix_seconds: NonZeroU64::new(T0 + 2),
        outcome: HttpOutcome::from_status_code(status).unwrap_or(HttpOutcome::NoResponse {}),
        tcp: None,
    }
}

fn probe_failed() -> Outcome {
    Outcome::Failed {
        message: "test".to_owned(),
    }
}

const MATCHED: ListenerEvidence = ListenerEvidence::Matched {
    address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 80),
};

const NO_AUTH: ProxyAuth = ProxyAuth {
    indicator: ProxyAuthIndicator::NoneConfigured,
    basic_credentials_required: false,
};

const BASIC_AUTH: ProxyAuth = ProxyAuth {
    indicator: ProxyAuthIndicator::Configured,
    basic_credentials_required: true,
};

fn layers(observation: &HttpObservation<'_>, backend: BackendState, auth: ProxyAuth) -> Result {
    correlate_layers(observation, MATCHED, backend, auth)
}

#[test]
fn gateway_errors_follow_backend_listener_evidence_not_firewall_state() {
    use BackendState::{Absent, NoTarget, Present, Unverified};
    for status in [502, 503, 504] {
        let observation = obs(status);
        assert_eq!(
            layers(&observation, Absent, NO_AUTH),
            Ok(Comparison::Consistent {})
        );
        assert_eq!(
            layers(&observation, Present, NO_AUTH),
            Err(CommonGap::BackendApplicationErrorUnverified)
        );
        assert_eq!(
            layers(&observation, NoTarget, NO_AUTH),
            Ok(Comparison::Disagrees {})
        );
        assert_eq!(
            layers(&observation, Unverified, NO_AUTH),
            Err(CommonGap::BackendUnverified)
        );
    }
}

#[test]
fn auth_rejections_never_claim_application_auth() {
    use BackendState::{Absent, Present};
    for status in [401, 403] {
        let observation = obs(status);
        assert_eq!(
            layers(&observation, Present, BASIC_AUTH),
            Ok(Comparison::Consistent {})
        );
        assert_eq!(
            layers(&observation, Present, NO_AUTH),
            Err(CommonGap::UnverifiedApplicationPolicy)
        );
        assert_eq!(
            layers(&observation, Absent, NO_AUTH),
            Ok(Comparison::Disagrees {})
        );
    }
}

#[test]
fn success_checks_credentials_then_backend() {
    use BackendState::{Absent, NoTarget, Present, Unverified};
    let ok = obs(200);
    assert_eq!(
        layers(&ok, Present, BASIC_AUTH),
        Err(CommonGap::ProxyAuthStateUnverified)
    );
    let without = HttpObservation {
        credentials_presented: Some(false),
        ..ok
    };
    assert_eq!(
        layers(&without, Present, BASIC_AUTH),
        Ok(Comparison::Disagrees {})
    );
    let with = HttpObservation {
        credentials_presented: Some(true),
        ..ok
    };
    assert_eq!(
        layers(&with, Present, BASIC_AUTH),
        Ok(Comparison::Consistent {})
    );
    assert_eq!(
        layers(&ok, NoTarget, NO_AUTH),
        Ok(Comparison::Consistent {})
    );
    assert_eq!(layers(&ok, Absent, NO_AUTH), Ok(Comparison::Disagrees {}));
    assert_eq!(
        layers(&ok, Unverified, NO_AUTH),
        Err(CommonGap::BackendUnverified)
    );
    assert_eq!(
        layers(&obs(302), Absent, NO_AUTH),
        Err(CommonGap::HttpStatusInconclusive)
    );
}

#[test]
fn not_found_other_status_and_no_response() {
    use BackendState::{Absent, Present, Unverified};
    let missing = obs(404);
    assert_eq!(
        layers(&missing, Absent, NO_AUTH),
        Ok(Comparison::Disagrees {})
    );
    assert_eq!(
        layers(&missing, Present, NO_AUTH),
        Ok(Comparison::Consistent {})
    );
    assert_eq!(
        layers(&missing, Unverified, NO_AUTH),
        Err(CommonGap::BackendUnverified)
    );
    assert_eq!(
        layers(&obs(500), Present, NO_AUTH),
        Err(CommonGap::HttpStatusInconclusive)
    );
    assert_eq!(
        layers(&obs(0), Absent, NO_AUTH),
        Err(CommonGap::NoResponseInconclusive)
    );
}

#[test]
fn transport_evidence_comes_before_http_status() {
    let observation = obs(200);
    let backend = BackendState::Present;
    let handshake_failed = HttpObservation {
        tls: true,
        tls_status: TlsStatus::HandshakeFailed,
        ..observation
    };
    assert_eq!(
        layers(&handshake_failed, backend, NO_AUTH),
        Err(CommonGap::TlsHandshakeFailed)
    );
    let failed = probe_failed();
    let probe_failed = HttpObservation {
        tcp: Some(TcpObservation {
            handshake: Some(&failed),
            inbound_path_verdict: None,
        }),
        ..observation
    };
    assert_eq!(
        layers(&probe_failed, backend, NO_AUTH),
        Err(CommonGap::TcpProbeFailed)
    );
    let blocked = HttpObservation {
        tcp: Some(TcpObservation {
            handshake: None,
            inbound_path_verdict: Some(InboundTcpVerdict::Blocked),
        }),
        ..observation
    };
    assert_eq!(
        layers(&blocked, backend, NO_AUTH),
        Ok(Comparison::Disagrees {})
    );
    let run = |frontend| correlate_layers::<()>(&observation, frontend, backend, NO_AUTH);
    assert_eq!(
        run(ListenerEvidence::Missing {}),
        Ok(Comparison::Disagrees {})
    );
    assert_eq!(
        correlate_layers::<()>(&obs(0), ListenerEvidence::Missing {}, backend, NO_AUTH),
        Err(CommonGap::NoResponseInconclusive)
    );
    for uncertain in [
        ListenerEvidence::Ambiguous {},
        ListenerEvidence::UncertainOptions {},
        ListenerEvidence::InventoryUnavailable {},
    ] {
        assert_eq!(run(uncertain), Err(CommonGap::FrontendListenerUncertain));
    }
}

#[test]
fn tcp_layer_is_derived_only_from_tcp_evidence() {
    let failed = probe_failed();
    let state = |handshake, verdict| {
        tcp_layer(Some(TcpObservation {
            handshake,
            inbound_path_verdict: verdict,
        }))
        .state
    };
    assert_eq!(state(Some(&failed), None), TcpLayerState::ProbeFailed);
    assert_eq!(
        state(Some(&Outcome::Closed), None),
        TcpLayerState::BlockedOrClosed
    );
    assert_eq!(
        state(None, Some(InboundTcpVerdict::NoListener)),
        TcpLayerState::BlockedOrClosed
    );
    assert_eq!(
        state(Some(&Outcome::Open), None),
        TcpLayerState::ReachableObservedOrPredicted
    );
    assert_eq!(
        state(None, Some(InboundTcpVerdict::Unknown)),
        TcpLayerState::NotSeparatelyObserved
    );
    assert_eq!(tcp_layer(None).state, TcpLayerState::NotSeparatelyObserved);
}

#[test]
fn provenance_requires_matching_scope_and_fresh_ordered_times() {
    let observation = obs(200);
    let check = |capture_scope, observation: &HttpObservation<'_>, captured_at| {
        check_provenance(capture_scope, observation, captured_at, 30)
    };
    assert_eq!(check(Some(scope()), &observation, T0), Ok(()));
    assert_eq!(
        check(None, &observation, T0),
        Err(CommonGap::CaptureScopeMissing)
    );
    let blank = Scope {
        collector_identity: " ",
        network_context: "test-net",
    };
    assert_eq!(
        check(Some(blank), &observation, T0),
        Err(CommonGap::CaptureScopeMissing)
    );
    let unscoped = HttpObservation {
        scope: None,
        ..observation
    };
    assert_eq!(
        check(Some(scope()), &unscoped, T0),
        Err(CommonGap::ObservationScopeMissing)
    );
    let other_host = Scope {
        collector_identity: "host-b",
        ..scope()
    };
    assert_eq!(
        check(Some(other_host), &observation, T0),
        Err(CommonGap::CollectorMismatch)
    );
    let other_net = Scope {
        network_context: "other-net",
        ..scope()
    };
    assert_eq!(
        check(Some(other_net), &observation, T0),
        Err(CommonGap::NetworkMismatch)
    );
    assert_eq!(
        check(Some(scope()), &observation, 0),
        Err(CommonGap::CaptureOrProbeTimeMissing)
    );
    assert_eq!(
        check(Some(scope()), &observation, T0 + 5),
        Err(CommonGap::CaptureAfterProbe)
    );
    let reversed = HttpObservation {
        finished_at_unix_seconds: NonZeroU64::new(T0),
        ..observation
    };
    assert_eq!(
        check(Some(scope()), &reversed, T0),
        Err(CommonGap::ProbeTimeReversed)
    );
    assert_eq!(
        check(Some(scope()), &observation, T0 - 100),
        Err(CommonGap::CaptureStale)
    );
}
