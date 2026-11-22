//! Scoped offline correlation across configured Nginx routes, TCP connectivity,
//! HTTP observations, local backend listeners, and proxy-layer authentication.

use std::num::NonZeroU64;

use crate::nginx::AuthSignals;
use crate::probe::Outcome;

use self::backend::{evaluate_backend, evaluate_frontend_listener};
use self::match_route::{RouteMatchError, resolve_location, resolve_server};

mod backend;
mod match_route;
mod outcome;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_matching;
mod types;

pub use self::backend::{BackendEvidence, BackendUncertainty, ListenerEvidence};
pub use self::outcome::{Comparison, Gap};
pub use self::types::{
    ApplicationAuthStatus, AuthEvidence, Capture, ConfiguredRouteEvidence, HttpObservation,
    HttpOutcome, InboundTcpVerdict, ProxyAuthIndicator, Report, Scope, TcpLayerEvidence,
    TcpLayerState, TcpObservation, TlsStatus,
};

/// Correlates one captured Nginx route snapshot with one scoped client HTTP observation.
///
/// Performs no network or filesystem I/O, trusts scope only as supplied by the caller,
/// keeps all five layers independent, and never infers a firewall verdict or application-auth
/// safety claim from failed probes or HTTP responses.
#[must_use]
pub fn correlate<'a>(
    capture: Option<Capture<'a>>,
    observation: Option<HttpObservation<'a>>,
    max_capture_age_seconds: u64,
) -> Report<'a> {
    let valid_capture = capture.filter(|cap| cap.snapshot.validate().is_ok());
    let valid_observation = observation.filter(HttpObservation::is_valid);

    let mut route = None;
    let mut backend = None;
    let mut auth = None;
    let mut route_error = None;

    if let (Some(cap), Some(obs)) = (valid_capture, valid_observation) {
        let report = cap.snapshot.evidence();
        let config = report.config();
        match resolve_server(config, obs.destination, obs.host, obs.tls) {
            Ok(resolved_server) => {
                let frontend_listener =
                    evaluate_frontend_listener(resolved_server.listen, report.inventory());
                match resolve_location(resolved_server.server, obs.path) {
                    Ok(matched_loc) => {
                        let effective_auth =
                            matched_loc.map_or(resolved_server.server.auth, |loc| loc.auth);
                        let target = matched_loc.and_then(|loc| loc.target.as_ref());
                        let backend_evidence = evaluate_backend(target, config, report.inventory());
                        route = Some(ConfiguredRouteEvidence {
                            on_disk_config_only: true,
                            running_master_reload_unverified: true,
                            collection_complete: report.is_collection_complete(),
                            uncertainty_count: config.uncertainties.len(),
                            server_source_file: resolved_server.server.source_file.as_deref(),
                            listen_port: resolved_server.listen.port,
                            listen_ssl: resolved_server.listen.ssl,
                            location_modifier: matched_loc.map(|loc| loc.modifier),
                            location_path: matched_loc.map(|loc| loc.path.as_str()),
                            frontend_listener,
                        });
                        backend = Some(backend_evidence);
                        auth = Some(build_auth_evidence(effective_auth));
                    }
                    Err(err) => {
                        route = Some(ConfiguredRouteEvidence {
                            on_disk_config_only: true,
                            running_master_reload_unverified: true,
                            collection_complete: report.is_collection_complete(),
                            uncertainty_count: config.uncertainties.len(),
                            server_source_file: resolved_server.server.source_file.as_deref(),
                            listen_port: resolved_server.listen.port,
                            listen_ssl: resolved_server.listen.ssl,
                            location_modifier: None,
                            location_path: None,
                            frontend_listener,
                        });
                        route_error = Some(err);
                    }
                }
            }
            Err(err) => route_error = Some(err),
        }
    }

    let tcp = build_tcp_layer(observation.and_then(|obs| obs.tcp));
    let comparison = compare(
        capture,
        valid_capture.is_some(),
        observation,
        valid_observation.is_some(),
        max_capture_age_seconds,
        route.as_ref(),
        backend.as_ref(),
        auth.as_ref(),
        route_error,
    )
    .unwrap_or_else(|reason| Comparison::Unavailable { reason });

    Report {
        capture_scope: capture.and_then(|cap| cap.scope),
        route,
        tcp,
        http: observation,
        backend,
        auth,
        max_capture_age_seconds,
        comparison,
    }
}

fn build_auth_evidence(proxy_auth: AuthSignals) -> AuthEvidence {
    let configured = proxy_auth_configured(proxy_auth);
    AuthEvidence {
        proxy_auth,
        indicator: if configured {
            ProxyAuthIndicator::Configured
        } else {
            ProxyAuthIndicator::NoneConfigured
        },
        application_auth: ApplicationAuthStatus::Unverified {},
    }
}

fn proxy_auth_configured(auth: AuthSignals) -> bool {
    auth.auth_basic == Some(true)
        || auth.auth_request
        || matches!(
            auth.ssl_verify_client,
            Some(crate::nginx::SslVerifyClient::On)
        )
        || auth.access_control
}

fn build_tcp_layer(tcp: Option<TcpObservation<'_>>) -> TcpLayerEvidence<'_> {
    let state = match tcp {
        Some(obs) if matches!(obs.handshake, Some(Outcome::Failed { .. })) => {
            TcpLayerState::ProbeFailed
        }
        Some(obs)
            if matches!(
                obs.handshake,
                Some(Outcome::Closed | Outcome::NoAnswer | Outcome::Unreachable)
            ) || matches!(
                obs.inbound_path_verdict,
                Some(InboundTcpVerdict::Blocked | InboundTcpVerdict::NoListener)
            ) =>
        {
            TcpLayerState::BlockedOrClosed
        }
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

#[allow(clippy::too_many_arguments)]
fn compare(
    capture: Option<Capture<'_>>,
    capture_valid: bool,
    observation: Option<HttpObservation<'_>>,
    observation_valid: bool,
    max_age: u64,
    route: Option<&ConfiguredRouteEvidence<'_>>,
    backend: Option<&BackendEvidence>,
    auth: Option<&AuthEvidence>,
    route_error: Option<RouteMatchError>,
) -> Result<Comparison, Gap> {
    let capture = capture.ok_or(Gap::CaptureMissing)?;
    if !capture_valid {
        return Err(Gap::InvalidCapture);
    }
    let observation = observation.ok_or(Gap::ObservationMissing)?;
    if !observation_valid {
        return Err(Gap::InvalidObservation);
    }
    match_scope(capture.scope, observation.scope)?;
    check_age(
        capture.snapshot.captured_at_unix_seconds(),
        &observation,
        max_age,
    )?;

    let report = capture.snapshot.evidence();
    if !report.is_collection_complete() {
        return Err(Gap::CollectionPartial);
    }
    if !report.config().uncertainties.is_empty() {
        return Err(Gap::ConfigUncertain);
    }

    if let Some(err) = route_error {
        return Err(match err {
            RouteMatchError::TlsSchemeMismatch => Gap::TlsSchemeMismatch,
            RouteMatchError::NoMatchingServer => Gap::NoMatchingServer,
            RouteMatchError::Ambiguous => Gap::RouteAmbiguous,
        });
    }

    let route = route.ok_or(Gap::NoMatchingServer)?;
    let backend = backend.ok_or(Gap::BackendUnverified)?;
    let auth = auth.ok_or(Gap::UnverifiedApplicationPolicy)?;

    if observation.tls_status == TlsStatus::HandshakeFailed {
        return Err(Gap::TlsHandshakeFailed);
    }
    if let Some(tcp) = observation.tcp
        && matches!(tcp.handshake, Some(Outcome::Failed { .. }))
    {
        return Err(Gap::TcpProbeFailed);
    }
    match route.frontend_listener {
        ListenerEvidence::Matched { .. } => {}
        ListenerEvidence::Missing {} => {
            if observation.outcome.received_response() {
                return Ok(Comparison::Disagrees {});
            }
            return Err(Gap::NoResponseInconclusive);
        }
        ListenerEvidence::Ambiguous {}
        | ListenerEvidence::UncertainOptions {}
        | ListenerEvidence::InventoryUnavailable {} => {
            return Err(Gap::FrontendListenerUncertain);
        }
    }

    if !observation.outcome.received_response() {
        return Err(Gap::NoResponseInconclusive);
    }

    if let Some(tcp) = observation.tcp
        && (matches!(
            tcp.handshake,
            Some(Outcome::Closed | Outcome::NoAnswer | Outcome::Unreachable)
        ) || matches!(
            tcp.inbound_path_verdict,
            Some(InboundTcpVerdict::Blocked | InboundTcpVerdict::NoListener)
        ))
    {
        return Ok(Comparison::Disagrees {});
    }

    correlate_http_layer(&observation, backend, auth)
}

fn correlate_http_layer(
    observation: &HttpObservation<'_>,
    backend: &BackendEvidence,
    auth: &AuthEvidence,
) -> Result<Comparison, Gap> {
    let proxy_auth = auth.indicator;
    match (observation.outcome, backend, proxy_auth) {
        (HttpOutcome::NoResponse {}, _, _) => Err(Gap::NoResponseInconclusive),
        (HttpOutcome::AuthRejected { .. }, _, ProxyAuthIndicator::Configured) => {
            Ok(Comparison::Consistent {})
        }
        (
            HttpOutcome::AuthRejected { .. },
            BackendEvidence::LocalTcpAbsent {},
            ProxyAuthIndicator::NoneConfigured,
        ) => Ok(Comparison::Disagrees {}),
        (HttpOutcome::AuthRejected { .. }, _, ProxyAuthIndicator::NoneConfigured) => {
            Err(Gap::UnverifiedApplicationPolicy)
        }
        (HttpOutcome::GatewayError { .. }, BackendEvidence::LocalTcpAbsent {}, _) => {
            Ok(Comparison::Consistent {})
        }
        (HttpOutcome::GatewayError { .. }, BackendEvidence::LocalTcpPresent { .. }, _) => {
            Err(Gap::BackendApplicationErrorUnverified)
        }
        (HttpOutcome::GatewayError { .. }, BackendEvidence::NoProxyTarget {}, _) => {
            Ok(Comparison::Disagrees {})
        }
        (
            HttpOutcome::GatewayError { .. },
            BackendEvidence::NonLocalOrRemote {}
            | BackendEvidence::UnresolvedHostname {}
            | BackendEvidence::LocalTcpUncertain { .. }
            | BackendEvidence::UnsupportedTarget { .. },
            _,
        ) => Err(Gap::BackendUnverified),
        (HttpOutcome::Success2xx { .. } | HttpOutcome::Redirect3xx { .. }, _, _) => {
            if auth.proxy_auth.auth_basic == Some(true) {
                match observation.credentials_presented {
                    Some(false) => return Ok(Comparison::Disagrees {}),
                    None => return Err(Gap::ProxyAuthStateUnverified),
                    Some(true) => {}
                }
            }
            match backend {
                BackendEvidence::LocalTcpAbsent {} => Ok(Comparison::Disagrees {}),
                BackendEvidence::LocalTcpPresent { .. } | BackendEvidence::NoProxyTarget {} => {
                    Ok(Comparison::Consistent {})
                }
                BackendEvidence::NonLocalOrRemote {}
                | BackendEvidence::UnresolvedHostname {}
                | BackendEvidence::LocalTcpUncertain { .. }
                | BackendEvidence::UnsupportedTarget { .. } => Err(Gap::BackendUnverified),
            }
        }
        (HttpOutcome::NotFound404 {}, BackendEvidence::LocalTcpAbsent {}, _) => {
            Ok(Comparison::Disagrees {})
        }
        (
            HttpOutcome::NotFound404 {},
            BackendEvidence::LocalTcpPresent { .. } | BackendEvidence::NoProxyTarget {},
            _,
        ) => Ok(Comparison::Consistent {}),
        (
            HttpOutcome::NotFound404 {},
            BackendEvidence::NonLocalOrRemote {}
            | BackendEvidence::UnresolvedHostname {}
            | BackendEvidence::LocalTcpUncertain { .. }
            | BackendEvidence::UnsupportedTarget { .. },
            _,
        ) => Err(Gap::BackendUnverified),
        (HttpOutcome::OtherStatus { .. }, BackendEvidence::LocalTcpAbsent {}, _) => {
            Ok(Comparison::Disagrees {})
        }
        (HttpOutcome::OtherStatus { .. }, _, _) => Err(Gap::HttpStatusInconclusive),
    }
}

fn match_scope(capture: Option<Scope<'_>>, observation: Option<Scope<'_>>) -> Result<(), Gap> {
    let capture = capture
        .filter(Scope::is_known)
        .ok_or(Gap::CaptureScopeMissing)?;
    let observation = observation
        .filter(Scope::is_known)
        .ok_or(Gap::ObservationScopeMissing)?;
    if capture.collector_identity != observation.collector_identity {
        return Err(Gap::CollectorMismatch);
    }
    if capture.network_context != observation.network_context {
        return Err(Gap::NetworkMismatch);
    }
    Ok(())
}

fn check_age(captured_at: u64, observation: &HttpObservation<'_>, max_age: u64) -> Result<(), Gap> {
    let missing = Gap::CaptureOrProbeTimeMissing;
    let captured_at = NonZeroU64::new(captured_at).ok_or(missing)?.get();
    let started_at = observation.started_at_unix_seconds.ok_or(missing)?.get();
    let finished_at = observation.finished_at_unix_seconds.ok_or(missing)?.get();
    if captured_at > started_at {
        return Err(Gap::CaptureAfterProbe);
    }
    if started_at > finished_at {
        return Err(Gap::ProbeTimeReversed);
    }
    if finished_at - captured_at > max_age {
        return Err(Gap::CaptureStale);
    }
    Ok(())
}
