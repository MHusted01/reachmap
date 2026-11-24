//! Proxy-neutral correlation steps: provenance and age checks, the TCP layer
//! summary, and the decision table that compares one HTTP observation with
//! frontend listener, backend listener and proxy-auth evidence.

use std::num::NonZeroU64;

use crate::probe::Outcome;

use super::types::{
    Comparison, HttpObservation, HttpOutcome, InboundTcpVerdict, ListenerEvidence,
    ProxyAuthIndicator, Scope, TcpLayerEvidence, TcpLayerState, TcpObservation, TlsStatus,
};

/// An evidence gap every proxy audit shares. Each proxy converts it into its
/// own gap type with `From`, so explanations can name the proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CommonGap {
    CaptureScopeMissing,
    ObservationScopeMissing,
    CollectorMismatch,
    NetworkMismatch,
    CaptureOrProbeTimeMissing,
    CaptureAfterProbe,
    ProbeTimeReversed,
    CaptureStale,
    TlsHandshakeFailed,
    TcpProbeFailed,
    FrontendListenerUncertain,
    NoResponseInconclusive,
    ProxyAuthStateUnverified,
    UnverifiedApplicationPolicy,
    BackendApplicationErrorUnverified,
    BackendUnverified,
    HttpStatusInconclusive,
}

/// What the backend layer says, reduced to what the decision table needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BackendState {
    /// The route ends without proxying (a responder or no handler).
    NoTarget,
    /// A local TCP listener accepts every configured backend.
    Present,
    /// No local TCP listener accepts the loopback backend(s).
    Absent,
    /// Backend presence cannot be established from local evidence.
    Unverified,
}

/// What the auth layer says, reduced to what the decision table needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ProxyAuth {
    /// Whether any proxy-layer authentication or ACL is configured.
    pub(crate) indicator: ProxyAuthIndicator,
    /// Whether the route requires Basic credentials, so a success without
    /// them contradicts the configuration.
    pub(crate) basic_credentials_required: bool,
}

/// Checks that capture and observation share a known scope and that the
/// capture was taken shortly before the observation.
pub(crate) fn check_provenance(
    capture_scope: Option<Scope<'_>>,
    observation: &HttpObservation<'_>,
    captured_at: u64,
    max_age: u64,
) -> Result<(), CommonGap> {
    match_scope(capture_scope, observation.scope)?;
    check_age(captured_at, observation, max_age)
}

fn match_scope(
    capture: Option<Scope<'_>>,
    observation: Option<Scope<'_>>,
) -> Result<(), CommonGap> {
    let capture = capture
        .filter(Scope::is_known)
        .ok_or(CommonGap::CaptureScopeMissing)?;
    let observation = observation
        .filter(Scope::is_known)
        .ok_or(CommonGap::ObservationScopeMissing)?;
    if capture.collector_identity != observation.collector_identity {
        return Err(CommonGap::CollectorMismatch);
    }
    if capture.network_context != observation.network_context {
        return Err(CommonGap::NetworkMismatch);
    }
    Ok(())
}

fn check_age(
    captured_at: u64,
    observation: &HttpObservation<'_>,
    max_age: u64,
) -> Result<(), CommonGap> {
    let missing = CommonGap::CaptureOrProbeTimeMissing;
    let captured_at = NonZeroU64::new(captured_at).ok_or(missing)?.get();
    let started_at = observation.started_at_unix_seconds.ok_or(missing)?.get();
    let finished_at = observation.finished_at_unix_seconds.ok_or(missing)?.get();
    if captured_at > started_at {
        return Err(CommonGap::CaptureAfterProbe);
    }
    if started_at > finished_at {
        return Err(CommonGap::ProbeTimeReversed);
    }
    if finished_at - captured_at > max_age {
        return Err(CommonGap::CaptureStale);
    }
    Ok(())
}

/// Summarizes the separate TCP evidence without looking at HTTP results.
pub(crate) fn tcp_layer(tcp: Option<TcpObservation<'_>>) -> TcpLayerEvidence<'_> {
    let state = match tcp {
        Some(obs) if matches!(obs.handshake, Some(Outcome::Failed { .. })) => {
            TcpLayerState::ProbeFailed
        }
        Some(obs) if tcp_blocked_or_closed(obs) => TcpLayerState::BlockedOrClosed,
        Some(obs)
            if matches!(obs.handshake, Some(Outcome::Open))
                || matches!(
                    obs.inbound_path_verdict,
                    Some(InboundTcpVerdict::ListenerReachable)
                ) =>
        {
            TcpLayerState::ReachableObservedOrPredicted
        }
        _ => TcpLayerState::NotSeparatelyObserved,
    };
    TcpLayerEvidence {
        observation: tcp,
        state,
    }
}

fn tcp_blocked_or_closed(obs: TcpObservation<'_>) -> bool {
    matches!(
        obs.handshake,
        Some(Outcome::Closed | Outcome::NoAnswer | Outcome::Unreachable)
    ) || matches!(
        obs.inbound_path_verdict,
        Some(InboundTcpVerdict::Blocked | InboundTcpVerdict::NoListener)
    )
}

/// Compares the observation with the frontend listener, backend and auth
/// layers once the route is resolved. Only returns `Consistent` or
/// `Disagrees`; a failed probe or HTTP error never becomes a firewall
/// verdict or an application-auth claim.
pub(crate) fn correlate_layers<G>(
    observation: &HttpObservation<'_>,
    frontend: ListenerEvidence,
    backend: BackendState,
    auth: ProxyAuth,
) -> Result<Comparison<G>, CommonGap> {
    if observation.tls_status == TlsStatus::HandshakeFailed {
        return Err(CommonGap::TlsHandshakeFailed);
    }
    if let Some(tcp) = observation.tcp
        && matches!(tcp.handshake, Some(Outcome::Failed { .. }))
    {
        return Err(CommonGap::TcpProbeFailed);
    }
    match frontend {
        ListenerEvidence::Matched { .. } => {}
        ListenerEvidence::Missing {} => {
            if observation.outcome.received_response() {
                return Ok(Comparison::Disagrees {});
            }
            return Err(CommonGap::NoResponseInconclusive);
        }
        ListenerEvidence::Ambiguous {}
        | ListenerEvidence::UncertainOptions {}
        | ListenerEvidence::InventoryUnavailable {} => {
            return Err(CommonGap::FrontendListenerUncertain);
        }
    }
    if !observation.outcome.received_response() {
        return Err(CommonGap::NoResponseInconclusive);
    }
    if observation.tcp.is_some_and(tcp_blocked_or_closed) {
        return Ok(Comparison::Disagrees {});
    }
    correlate_http(observation, backend, auth)
}

fn correlate_http<G>(
    observation: &HttpObservation<'_>,
    backend: BackendState,
    auth: ProxyAuth,
) -> Result<Comparison<G>, CommonGap> {
    use BackendState::{Absent, NoTarget, Present, Unverified};
    use HttpOutcome::{
        AuthRejected, GatewayError, NoResponse, NotFound404, OtherStatus, Redirect3xx, Success2xx,
    };
    use ProxyAuthIndicator::{Configured, NoneConfigured};

    match (observation.outcome, backend, auth.indicator) {
        (NoResponse {}, _, _) => Err(CommonGap::NoResponseInconclusive),
        (AuthRejected { .. }, _, Configured) => Ok(Comparison::Consistent {}),
        (AuthRejected { .. }, Absent, NoneConfigured) => Ok(Comparison::Disagrees {}),
        (AuthRejected { .. }, _, NoneConfigured) => Err(CommonGap::UnverifiedApplicationPolicy),
        (GatewayError { .. }, Absent, _) => Ok(Comparison::Consistent {}),
        (GatewayError { .. }, Present, _) => Err(CommonGap::BackendApplicationErrorUnverified),
        (GatewayError { .. }, NoTarget, _) => Ok(Comparison::Disagrees {}),
        (GatewayError { .. }, Unverified, _) => Err(CommonGap::BackendUnverified),
        (outcome @ (Success2xx { .. } | Redirect3xx { .. }), _, _) => {
            if auth.basic_credentials_required {
                match observation.credentials_presented {
                    Some(false) => return Ok(Comparison::Disagrees {}),
                    None => return Err(CommonGap::ProxyAuthStateUnverified),
                    Some(true) => {}
                }
            }
            match backend {
                Absent if matches!(outcome, Success2xx { .. }) => Ok(Comparison::Disagrees {}),
                Absent => Err(CommonGap::HttpStatusInconclusive),
                Present | NoTarget => Ok(Comparison::Consistent {}),
                Unverified => Err(CommonGap::BackendUnverified),
            }
        }
        (NotFound404 {}, Absent, _) => Ok(Comparison::Disagrees {}),
        (NotFound404 {}, Present | NoTarget, _) => Ok(Comparison::Consistent {}),
        (NotFound404 {}, Unverified, _) => Err(CommonGap::BackendUnverified),
        (OtherStatus { .. }, _, _) => Err(CommonGap::HttpStatusInconclusive),
    }
}
