//! Scoped offline correlation across configured Caddy routes, TCP
//! connectivity, HTTP observations, local upstream listeners, and
//! proxy-layer authentication.

use crate::proxy_audit::{ProxyAuthIndicator, check_provenance, correlate_layers, tcp_layer};

use self::backend::{evaluate_backend, evaluate_frontend};
use self::walk::{AuthSeen, End, Request, ResolvedServer, RouteMatchError, resolve_server, walk};
use super::CaddyRouteReport;

mod backend;
mod outcome;
#[cfg(test)]
mod tests;
mod types;
mod walk;

pub use self::backend::{BackendEvidence, BackendUncertainty};
pub use self::outcome::{Comparison, Gap};
pub use self::types::{AuthEvidence, Capture, ConfiguredRouteEvidence, Report, RouteEnd};
pub use crate::proxy_audit::{
    ApplicationAuthStatus, HttpObservation, HttpOutcome, InboundTcpVerdict, ListenerEvidence,
    Scope, TcpLayerEvidence, TcpLayerState, TcpObservation, TlsStatus,
};

/// Correlates one captured Caddy route snapshot with one scoped client HTTP
/// observation.
///
/// Performs no network or filesystem I/O, trusts scope only as supplied by
/// the caller, keeps all five layers independent, and never infers a
/// firewall verdict or application-auth safety claim from failed probes or
/// HTTP responses.
#[must_use]
pub fn correlate<'a>(
    capture: Option<Capture<'a>>,
    observation: Option<HttpObservation<'a>>,
    max_capture_age_seconds: u64,
) -> Report<'a> {
    let checked_capture = checked(
        capture,
        |cap| cap.snapshot.evidence().validate().is_ok(),
        Gap::CaptureMissing,
        Gap::InvalidCapture,
    );
    let checked_observation = checked(
        observation,
        HttpObservation::is_valid,
        Gap::ObservationMissing,
        Gap::InvalidObservation,
    );
    let resolution = match (&checked_capture, &checked_observation) {
        (Ok(cap), Ok(obs)) => resolve(cap.snapshot.evidence(), obs),
        _ => Resolution::default(),
    };
    let comparison = compare(
        checked_capture,
        checked_observation,
        max_capture_age_seconds,
        &resolution,
    )
    .unwrap_or_else(|reason| Comparison::Unavailable { reason });

    Report {
        capture_scope: capture.and_then(|cap| cap.scope),
        route: resolution.route,
        tcp: tcp_layer(observation.and_then(|obs| obs.tcp)),
        http: observation,
        backend: resolution.backend,
        auth: resolution.auth,
        max_capture_age_seconds,
        comparison,
    }
}

fn checked<T>(
    value: Option<T>,
    valid: impl FnOnce(&T) -> bool,
    missing: Gap,
    invalid: Gap,
) -> Result<T, Gap> {
    let value = value.ok_or(missing)?;
    if valid(&value) {
        Ok(value)
    } else {
        Err(invalid)
    }
}

/// The configured layers for one request, or why its route is unresolved.
#[derive(Default)]
struct Resolution<'a> {
    route: Option<ConfiguredRouteEvidence<'a>>,
    backend: Option<BackendEvidence>,
    auth: Option<AuthEvidence>,
    error: Option<RouteMatchError>,
}

fn resolve<'a>(report: &'a CaddyRouteReport, obs: &HttpObservation<'_>) -> Resolution<'a> {
    let resolved = match resolve_server(&report.config, obs.destination, obs.tls) {
        Ok(resolved) => resolved,
        Err(error) => {
            return Resolution {
                error: Some(error),
                ..Resolution::default()
            };
        }
    };
    let walked = Request::new(obs.host, obs.path)
        .and_then(|request| walk(&resolved.server.routes, &request));
    let mut route = route_evidence(report, &resolved, obs.destination.port());
    match walked {
        Ok(walked) => {
            route.end = Some(route_end(walked.end));
            let proxy = match walked.end {
                End::Proxy(proxy) => Some(proxy),
                End::Respond(_) | End::Nothing => None,
            };
            Resolution {
                route: Some(route),
                backend: Some(evaluate_backend(proxy, &report.inventory)),
                auth: Some(auth_evidence(walked.auth, &resolved)),
                error: None,
            }
        }
        Err(error) => Resolution {
            route: Some(route),
            error: Some(error),
            ..Resolution::default()
        },
    }
}

fn route_evidence<'a>(
    report: &'a CaddyRouteReport,
    resolved: &ResolvedServer<'a>,
    port: u16,
) -> ConfiguredRouteEvidence<'a> {
    let config = &report.config;
    ConfiguredRouteEvidence {
        on_disk_config_only: true,
        running_config_unverified: true,
        collection_complete: report.is_collection_complete(),
        uncertainty_count: config.uncertainties.len() + config.uncertainties_omitted,
        server_name: &resolved.server.name,
        listen_port: port,
        tls: resolved.tls,
        end: None,
        frontend_listener: evaluate_frontend(resolved.listen, port, &report.inventory),
    }
}

fn route_end(end: End<'_>) -> RouteEnd<'_> {
    match end {
        End::Proxy(proxy) => RouteEnd::ReverseProxy {
            upstreams: &proxy.upstreams,
        },
        End::Respond(responder) => RouteEnd::Respond { responder },
        End::Nothing => RouteEnd::NoHandler {},
    }
}

fn auth_evidence(seen: AuthSeen, resolved: &ResolvedServer<'_>) -> AuthEvidence {
    let configured = seen.http_basic || seen.other_providers || seen.forward_auth;
    AuthEvidence {
        http_basic: seen.http_basic,
        other_providers: seen.other_providers,
        forward_auth: seen.forward_auth,
        tls_client_auth_configured: resolved.tls
            && resolved
                .server
                .tls_policies
                .iter()
                .any(|policy| policy.client_auth.is_some()),
        indicator: if configured {
            ProxyAuthIndicator::Configured
        } else {
            ProxyAuthIndicator::NoneConfigured
        },
        application_auth: ApplicationAuthStatus::Unverified {},
    }
}

fn compare(
    capture: Result<Capture<'_>, Gap>,
    observation: Result<HttpObservation<'_>, Gap>,
    max_age: u64,
    resolution: &Resolution<'_>,
) -> Result<Comparison, Gap> {
    let capture = capture?;
    let observation = observation?;
    check_provenance(
        capture.scope,
        &observation,
        capture.snapshot.captured_at_unix_seconds(),
        max_age,
    )?;
    let report = capture.snapshot.evidence();
    if !report.is_collection_complete() {
        return Err(Gap::CollectionPartial);
    }
    if !report.is_complete() {
        return Err(Gap::ConfigUncertain);
    }
    if let Some(error) = resolution.error {
        return Err(error.into());
    }
    let route = resolution.route.as_ref().ok_or(Gap::NoMatchingServer)?;
    let backend = resolution.backend.as_ref().ok_or(Gap::BackendUnverified)?;
    let auth = resolution.auth.ok_or(Gap::UnverifiedApplicationPolicy)?;
    correlate_layers(
        &observation,
        route.frontend_listener,
        backend.state(),
        auth.proxy_auth(),
    )
    .map_err(Gap::from)
}
