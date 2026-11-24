//! Correlation outcome and explicit evidence-gap diagnostics for Caddy audits.

use serde::Serialize;
use thiserror::Error;

use crate::proxy_audit::CommonGap;

use super::walk::RouteMatchError;

/// How the five evidence layers correlate within the audited Caddy scope.
pub type Comparison = crate::proxy_audit::Comparison<Gap>;

/// The first evidence gap preventing a conclusive Caddy route correlation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Error)]
#[serde(rename_all = "snake_case")]
pub enum Gap {
    /// No Caddy route snapshot capture was supplied.
    #[error("collect a Caddy route snapshot before correlating")]
    CaptureMissing,
    /// No client HTTP observation was supplied.
    #[error("record a scoped client HTTP observation for the audited route")]
    ObservationMissing,
    /// The supplied Caddy route snapshot failed validation.
    #[error("use a valid versioned Caddy route snapshot")]
    InvalidCapture,
    /// The supplied client HTTP observation failed validation.
    #[error("supply a valid HTTP destination, host, normalized path, TLS status, and status code")]
    InvalidObservation,
    /// Capture provenance or network context is missing.
    #[error("establish the authenticated collector identity and capture network context")]
    CaptureScopeMissing,
    /// Observation provenance or network context is missing.
    #[error("establish which audited collector and network context own the HTTP destination")]
    ObservationScopeMissing,
    /// Capture and observation refer to different authenticated collector identities.
    #[error("verify that the HTTP destination belongs to the authenticated capture host")]
    CollectorMismatch,
    /// Capture and observation refer to different network contexts.
    #[error("use capture and observation evidence from the same audited network context")]
    NetworkMismatch,
    /// A capture or observation timestamp is missing or zero.
    #[error("record capture and observation times on comparable clocks")]
    CaptureOrProbeTimeMissing,
    /// The snapshot capture timestamp follows the start of the HTTP observation.
    #[error("finish capturing Caddy route evidence before starting the client observation")]
    CaptureAfterProbe,
    /// The HTTP observation finished before it started.
    #[error("record ordered start and finish times for the HTTP observation")]
    ProbeTimeReversed,
    /// The HTTP observation finished outside the allowed snapshot age window.
    #[error("take a fresh Caddy route snapshot and repeat the observation within max capture age")]
    CaptureStale,
    /// Snapshot collection had partial socket inventory, option or configuration notes.
    #[error("collect complete Caddy configuration and local TCP socket evidence on the Caddy host")]
    CollectionPartial,
    /// The parsed Caddy configuration has unmodeled constructs.
    #[error(
        "resolve the Caddy configuration uncertainties before relying on static route correlation"
    )]
    ConfigUncertain,
    /// The observed HTTP/HTTPS scheme does not match the server's TLS mode.
    #[error("align the client HTTP/HTTPS scheme with the Caddy server's TLS configuration")]
    TlsSchemeMismatch,
    /// Automatic HTTPS decides at runtime whether the matched server speaks TLS.
    #[error(
        "disable automatic HTTPS or configure TLS connection policies explicitly; automatic HTTPS decides TLS and redirects at runtime"
    )]
    AutomaticHttpsUnverified,
    /// No Caddy server listens on the observed destination address and port.
    #[error("verify the observed destination address and port match a configured Caddy listener")]
    NoMatchingServer,
    /// Several servers accept the destination, or a matcher or handler on the
    /// request's path is not modeled.
    #[error("disambiguate overlapping Caddy listeners, unmodeled matchers or handlers")]
    RouteAmbiguous,
    /// The observed path is not normalized, so Caddy's path cleaning decides the route.
    #[error(
        "observe a normalized ASCII path without `//`, dot segments or percent escapes; Caddy path cleaning is not modeled"
    )]
    PathNotNormalized,
    /// The TLS handshake failed before an HTTP response was observed.
    #[error("inspect the frontend TLS certificate, SNI, and handshake error separately")]
    TlsHandshakeFailed,
    /// The optional TCP handshake probe failed locally without testing port reachability.
    #[error("resolve the reported TCP probe error and retry the handshake check")]
    TcpProbeFailed,
    /// Local frontend TCP listener status could not be established cleanly.
    #[error("resolve ambiguous or incomplete local frontend TCP socket evidence")]
    FrontendListenerUncertain,
    /// No HTTP response was received; cannot establish a firewall verdict.
    #[error(
        "check frontend TCP reachability and return path separately; no HTTP response does not prove a firewall block"
    )]
    NoResponseInconclusive,
    /// Basic authentication is configured on the route, but credential presentation was not recorded.
    #[error(
        "record whether proxy-layer credentials were presented when testing an auth-protected route"
    )]
    ProxyAuthStateUnverified,
    /// HTTP 401/403 occurred without configured Caddy proxy auth; application-level auth or upstream policy is unverified.
    #[error(
        "inspect backend application authentication or upstream policy separately from Caddy proxy auth"
    )]
    UnverifiedApplicationPolicy,
    /// HTTP 502/503/504 occurred while a local upstream TCP listener is present.
    #[error(
        "check backend application health and logs; a local TCP listener is present so HTTP 502/503/504 does not show a missing socket or firewall block"
    )]
    BackendApplicationErrorUnverified,
    /// Upstream reachability could not be correlated locally (remote, host name, incomplete or uncertain).
    #[error(
        "verify the upstream separately because local TCP listener evidence cannot prove remote or dynamic upstreams"
    )]
    BackendUnverified,
    /// The observed HTTP status leaves route behavior inconclusive.
    #[error(
        "inspect the backend response directly; the observed HTTP status does not establish route consistency"
    )]
    HttpStatusInconclusive,
}

impl From<RouteMatchError> for Gap {
    fn from(error: RouteMatchError) -> Self {
        match error {
            RouteMatchError::TlsSchemeMismatch => Self::TlsSchemeMismatch,
            RouteMatchError::AutomaticHttpsUnverified => Self::AutomaticHttpsUnverified,
            RouteMatchError::NoMatchingServer => Self::NoMatchingServer,
            RouteMatchError::Ambiguous => Self::RouteAmbiguous,
            RouteMatchError::PathNotNormalized => Self::PathNotNormalized,
        }
    }
}

impl From<CommonGap> for Gap {
    fn from(gap: CommonGap) -> Self {
        match gap {
            CommonGap::CaptureScopeMissing => Self::CaptureScopeMissing,
            CommonGap::ObservationScopeMissing => Self::ObservationScopeMissing,
            CommonGap::CollectorMismatch => Self::CollectorMismatch,
            CommonGap::NetworkMismatch => Self::NetworkMismatch,
            CommonGap::CaptureOrProbeTimeMissing => Self::CaptureOrProbeTimeMissing,
            CommonGap::CaptureAfterProbe => Self::CaptureAfterProbe,
            CommonGap::ProbeTimeReversed => Self::ProbeTimeReversed,
            CommonGap::CaptureStale => Self::CaptureStale,
            CommonGap::TlsHandshakeFailed => Self::TlsHandshakeFailed,
            CommonGap::TcpProbeFailed => Self::TcpProbeFailed,
            CommonGap::FrontendListenerUncertain => Self::FrontendListenerUncertain,
            CommonGap::NoResponseInconclusive => Self::NoResponseInconclusive,
            CommonGap::ProxyAuthStateUnverified => Self::ProxyAuthStateUnverified,
            CommonGap::UnverifiedApplicationPolicy => Self::UnverifiedApplicationPolicy,
            CommonGap::BackendApplicationErrorUnverified => Self::BackendApplicationErrorUnverified,
            CommonGap::BackendUnverified => Self::BackendUnverified,
            CommonGap::HttpStatusInconclusive => Self::HttpStatusInconclusive,
        }
    }
}
