//! Correlation outcome and explicit evidence-gap diagnostics for Nginx audits.

use serde::Serialize;
use thiserror::Error;

use crate::proxy_audit::CommonGap;

/// How the five evidence layers correlate within the audited Nginx scope.
pub type Comparison = crate::proxy_audit::Comparison<Gap>;

/// The first evidence gap preventing a conclusive Nginx route correlation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Error)]
#[serde(rename_all = "snake_case")]
pub enum Gap {
    /// No Nginx route snapshot capture was supplied.
    #[error("collect an Nginx route snapshot before correlating")]
    CaptureMissing,
    /// No client HTTP observation was supplied.
    #[error("record a scoped client HTTP observation for the audited route")]
    ObservationMissing,
    /// The supplied Nginx route snapshot failed validation.
    #[error("use a valid versioned Nginx route snapshot")]
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
    #[error("finish capturing Nginx route evidence before starting the client observation")]
    CaptureAfterProbe,
    /// The HTTP observation finished before it started.
    #[error("record ordered start and finish times for the HTTP observation")]
    ProbeTimeReversed,
    /// The HTTP observation finished outside the allowed snapshot age window.
    #[error("take a fresh Nginx route snapshot and repeat the observation within max capture age")]
    CaptureStale,
    /// Snapshot collection had partial socket inventory or option notes.
    #[error("collect complete local TCP socket and socket-option evidence on the Nginx host")]
    CollectionPartial,
    /// Parsed Nginx configuration contains dynamic or unmodeled directives (`if`, `rewrite`, etc.).
    #[error(
        "resolve dynamic or unmodeled Nginx configuration directives before relying on static correlation"
    )]
    ConfigUncertain,
    /// The observed HTTP/HTTPS scheme does not match any `listen` `ssl` flag for the destination.
    #[error("align the client HTTP/HTTPS scheme with the configured Nginx listen ssl setting")]
    TlsSchemeMismatch,
    /// No configured Nginx `server` block matched the observed destination IP and port.
    #[error(
        "verify the observed destination address and port match a configured Nginx server block"
    )]
    NoMatchingServer,
    /// Multiple server blocks, locations, or ambiguous IPv4/IPv6 wildcard listens matched the request.
    #[error("disambiguate overlapping Nginx server_name, location, or ipv6only configurations")]
    RouteAmbiguous,
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
    /// Proxy-layer authentication is configured on the route, but credential presentation was not recorded.
    #[error(
        "record whether proxy-layer credentials were presented when testing an auth-protected route"
    )]
    ProxyAuthStateUnverified,
    /// HTTP 401/403 occurred without configured Nginx proxy auth; application-level auth or upstream policy is unverified.
    #[error(
        "inspect backend application authentication or upstream policy separately from Nginx proxy auth"
    )]
    UnverifiedApplicationPolicy,
    /// HTTP 502/503/504 occurred while a local backend TCP listener is present; backend app error or protocol mismatch is unverified.
    #[error(
        "check backend application health and logs; a local TCP listener is present so HTTP 502/503/504 does not show a missing socket or firewall block"
    )]
    BackendApplicationErrorUnverified,
    /// Backend listener reachability could not be correlated locally (non-loopback, unresolved host, unsupported, or uncertain upstream).
    #[error(
        "verify the backend target separately because local TCP listener evidence cannot prove remote or dynamic backends"
    )]
    BackendUnverified,
    /// The observed HTTP status code outside 2xx/3xx/401/403/404/502-504 leaves route behavior inconclusive.
    #[error(
        "inspect the backend response directly; the observed HTTP status does not establish route consistency"
    )]
    HttpStatusInconclusive,
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
