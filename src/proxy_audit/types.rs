//! Public data types shared by the reverse proxy correlation audits.

use std::net::SocketAddr;
use std::num::NonZeroU64;

use serde::Serialize;

use crate::probe::Outcome;

/// Caller-established identity and network scope for one audited proxy host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Scope<'a> {
    /// Identity of the authenticated collector that produced the capture.
    pub collector_identity: &'a str,
    /// Context that identifies the audited address space and applicable client path.
    pub network_context: &'a str,
}

impl Scope<'_> {
    pub(crate) fn is_known(&self) -> bool {
        !self.collector_identity.trim().is_empty() && !self.network_context.trim().is_empty()
    }
}

/// Outcome of TLS negotiation for a client HTTP request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsStatus {
    /// Plain HTTP request (`tls == false`).
    NotUsed,
    /// HTTPS handshake succeeded and the server certificate was verified.
    Verified,
    /// HTTPS handshake succeeded without full certificate verification.
    Unverified,
    /// TLS handshake failed before an HTTP status was received.
    HandshakeFailed,
}

/// Scoped HTTP status class observed by the client.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum HttpOutcome {
    /// Successful HTTP `2xx` response.
    Success2xx {
        /// Observed HTTP status code (`200..=299`).
        status_code: u16,
    },
    /// HTTP `3xx` redirect response.
    Redirect3xx {
        /// Observed HTTP status code (`300..=399`).
        status_code: u16,
    },
    /// HTTP `401` or `403` authentication or authorization rejection.
    AuthRejected {
        /// Observed HTTP status code (`401` or `403`).
        status_code: u16,
    },
    /// HTTP `404` not-found response.
    NotFound404 {},
    /// HTTP `502`, `503`, or `504` proxy/upstream gateway error.
    GatewayError {
        /// Observed HTTP status code (`502`, `503`, or `504`).
        status_code: u16,
    },
    /// Another HTTP status code outside the primary proxy classes.
    OtherStatus {
        /// Observed HTTP status code (`100..=599`).
        status_code: u16,
    },
    /// No HTTP response was received (connection refused, timeout, reset, or TLS failure).
    NoResponse {},
}

impl HttpOutcome {
    /// Classifies a raw HTTP status code into an [`HttpOutcome`], returning `None` if outside `100..=599`.
    #[must_use]
    pub fn from_status_code(status_code: u16) -> Option<Self> {
        match status_code {
            200..=299 => Some(Self::Success2xx { status_code }),
            300..=399 => Some(Self::Redirect3xx { status_code }),
            401 | 403 => Some(Self::AuthRejected { status_code }),
            404 => Some(Self::NotFound404 {}),
            502..=504 => Some(Self::GatewayError { status_code }),
            100..=599 => Some(Self::OtherStatus { status_code }),
            _ => None,
        }
    }

    pub(crate) fn is_valid(&self) -> bool {
        match *self {
            Self::Success2xx { status_code } => (200..=299).contains(&status_code),
            Self::Redirect3xx { status_code } => (300..=399).contains(&status_code),
            Self::AuthRejected { status_code } => matches!(status_code, 401 | 403),
            Self::NotFound404 {} | Self::NoResponse {} => true,
            Self::GatewayError { status_code } => matches!(status_code, 502..=504),
            Self::OtherStatus { status_code } => {
                (100..=599).contains(&status_code)
                    && !(200..=399).contains(&status_code)
                    && !matches!(status_code, 401 | 403 | 404 | 502..=504)
            }
        }
    }

    pub(crate) fn received_response(&self) -> bool {
        !matches!(self, Self::NoResponse {})
    }
}

/// Optional verdict imported from a scoped Linux inbound TCP path prediction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InboundTcpVerdict {
    /// Inbound TCP SYN path predicts the packet reaches a local listener.
    ListenerReachable,
    /// Inbound TCP SYN path predicts a firewall drop.
    Blocked,
    /// Inbound TCP SYN path predicts no matching local listener.
    NoListener,
    /// Inbound TCP SYN destination is not local to the audited host.
    NotLocal,
    /// Inbound TCP SYN prediction is unknown.
    Unknown,
}

/// Optional TCP-layer connectivity evidence for the frontend endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct TcpObservation<'a> {
    /// Result of a direct TCP handshake attempt to the frontend endpoint, if performed.
    pub handshake: Option<&'a Outcome>,
    /// Verdict from an independently scoped Linux inbound TCP path check, if performed.
    pub inbound_path_verdict: Option<InboundTcpVerdict>,
}

/// One scoped HTTP or HTTPS request from the operator's client.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct HttpObservation<'a> {
    /// Independently established collector identity and network context for the destination.
    pub scope: Option<Scope<'a>>,
    /// Socket address (`IP:port`) the client connected to.
    pub destination: SocketAddr,
    /// HTTP `Host` header / SNI server name used for the request.
    pub host: &'a str,
    /// Normalized URI path requested (must begin with `/` without query or fragment).
    pub path: &'a str,
    /// Whether TLS (`https://`) was used on the frontend connection.
    pub tls: bool,
    /// Outcome of TLS negotiation.
    pub tls_status: TlsStatus,
    /// Whether proxy-layer credentials (Basic auth or client cert) were sent, if known.
    pub credentials_presented: Option<bool>,
    /// Request start time in Unix seconds on a clock comparable to the capture clock.
    pub started_at_unix_seconds: Option<NonZeroU64>,
    /// Request finish time in Unix seconds on a clock comparable to the capture clock.
    pub finished_at_unix_seconds: Option<NonZeroU64>,
    /// Observed HTTP status class or lack of HTTP response.
    pub outcome: HttpOutcome,
    /// Optional TCP handshake or inbound TCP path evidence for the frontend socket.
    pub tcp: Option<TcpObservation<'a>>,
}

impl HttpObservation<'_> {
    pub(crate) fn is_valid(&self) -> bool {
        let host_ok = !self.host.trim().is_empty()
            && !self.host.bytes().any(|b| b.is_ascii_control())
            && self.host.len() <= 253;
        let path_ok = self.path.starts_with('/')
            && !self.path.contains('?')
            && !self.path.contains('#')
            && !self.path.bytes().any(|b| b.is_ascii_control());
        let tls_ok = if self.tls {
            self.tls_status != TlsStatus::NotUsed
        } else {
            self.tls_status == TlsStatus::NotUsed
        };
        host_ok && path_ok && tls_ok && self.outcome.is_valid()
    }
}

/// Local TCP listener evidence for the matched frontend listen address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ListenerEvidence {
    /// A single local TCP listener can accept traffic for the configured listen address.
    Matched {
        /// Bound socket address of the matching local TCP listener.
        address: SocketAddr,
    },
    /// No local TCP listener matched the configured listen address.
    Missing {},
    /// Multiple local TCP listeners could accept traffic for the configured listen address.
    Ambiguous {},
    /// Socket options (`SO_BINDTODEVICE` or `IPV6_V6ONLY`) were unavailable to confirm the match.
    UncertainOptions {},
    /// Local TCP socket inventory was unavailable during capture.
    InventoryUnavailable {},
}

/// Summary of the separate Layer 2 TCP connectivity state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TcpLayerState {
    /// Independent TCP handshake succeeded or inbound TCP path predicts reachability.
    ReachableObservedOrPredicted,
    /// Independent TCP evidence indicates blocked, closed, or no answer.
    BlockedOrClosed,
    /// TCP handshake attempt failed locally without observing port reachability.
    ProbeFailed,
    /// Independent TCP connectivity was not probed or predicted; not inferred from HTTP errors.
    NotSeparatelyObserved,
}

/// Layer 2: Frontend TCP connectivity evidence, kept separate from HTTP errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct TcpLayerEvidence<'a> {
    /// Raw optional TCP handshake / inbound path observation supplied by the caller.
    pub observation: Option<TcpObservation<'a>>,
    /// Derived TCP connectivity state without inferring firewall verdicts from HTTP status codes.
    pub state: TcpLayerState,
}

/// Configured proxy-layer authentication and ACL posture for the matched route.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProxyAuthIndicator {
    /// Proxy-layer authentication or an access control list is configured.
    Configured,
    /// No proxy-layer authentication or access control list is configured on the matched route.
    NoneConfigured,
}

/// Application-level authentication and upstream authorization status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ApplicationAuthStatus {
    /// Application-level authentication and upstream policy cannot be verified from proxy configuration alone.
    Unverified {},
}

/// How the five evidence layers correlate within the audited scope. `G` is
/// the proxy's own evidence-gap type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Comparison<G> {
    /// The HTTP observation, configured route, TCP evidence, backend listener, and proxy auth agree within scope.
    Consistent {},
    /// One or more evidence layers directly disagree (for example, HTTP succeeded when no backend listener exists).
    Disagrees {},
    /// Insufficient, stale, mismatched, or uncertain evidence prevents a conclusive correlation.
    Unavailable {
        /// First evidence gap preventing correlation.
        reason: G,
    },
}
