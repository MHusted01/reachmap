//! Public data types for five-layer Caddy reverse proxy correlation.

use serde::Serialize;

use crate::caddy::routes::snapshot::Snapshot;
use crate::caddy::{DialTarget, Responder};
use crate::proxy_audit::{
    ApplicationAuthStatus, HttpObservation, ListenerEvidence, ProxyAuth, ProxyAuthIndicator, Scope,
    TcpLayerEvidence,
};

use super::backend::BackendEvidence;
use super::outcome::Comparison;

/// A Caddy route snapshot and the trusted scope attached to that capture.
#[derive(Debug, Clone, Copy)]
pub struct Capture<'a> {
    /// Evidence returned by `reachmap scan --caddy-routes --snapshot`.
    pub snapshot: &'a Snapshot,
    /// Supply only when authenticated provenance and capture context have been established.
    pub scope: Option<Scope<'a>>,
}

/// Where the matched handler chain ends for the observed request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RouteEnd<'a> {
    /// A `reverse_proxy` handler sends the request to these upstreams.
    ReverseProxy {
        /// Statically understood upstreams, in configuration order.
        upstreams: &'a [DialTarget],
    },
    /// A handler answers the request itself.
    Respond {
        /// Which responder answers.
        responder: Responder,
    },
    /// No handler answers; Caddy sends an empty `200` response.
    NoHandler {},
}

/// Layer 1: Configured on-disk Caddy route evidence and frontend listener status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConfiguredRouteEvidence<'a> {
    /// Always `true`: the collector reads the on-disk configuration file.
    pub on_disk_config_only: bool,
    /// Always `true`: whether a running Caddy loaded this configuration (it
    /// may not have been reloaded, or may have been changed through its admin
    /// API) is unverified.
    pub running_config_unverified: bool,
    /// Whether configuration and local TCP socket inventory collection completed without notes.
    pub collection_complete: bool,
    /// Number of unmodeled configuration constructs, including omitted ones.
    pub uncertainty_count: usize,
    /// Configuration key of the matched server, e.g. `srv0`.
    pub server_name: &'a str,
    /// Observed destination port served by the matched listen address.
    pub listen_port: u16,
    /// Whether the matched server speaks TLS.
    pub tls: bool,
    /// Where the handler chain ends, when the route could be resolved.
    pub end: Option<RouteEnd<'a>>,
    /// Local TCP listener match for the matched listen address.
    pub frontend_listener: ListenerEvidence,
}

/// Layer 5: Proxy-layer auth indicators kept separate from unverified application auth.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct AuthEvidence {
    /// Whether an `authentication` handler with `http_basic` runs before the end.
    pub http_basic: bool,
    /// Whether an `authentication` handler with another provider runs before the end.
    pub other_providers: bool,
    /// Whether a `forward_auth`-shaped `reverse_proxy` runs before the end.
    pub forward_auth: bool,
    /// Whether a TLS connection policy of the server configures client certificates.
    pub tls_client_auth_configured: bool,
    /// Whether Caddy proxy-layer authentication is configured on the route.
    pub indicator: ProxyAuthIndicator,
    /// Explicit marker that application-level authentication remains unverified.
    pub application_auth: ApplicationAuthStatus,
}

impl AuthEvidence {
    pub(super) fn proxy_auth(&self) -> ProxyAuth {
        ProxyAuth {
            indicator: self.indicator,
            basic_credentials_required: self.http_basic,
        }
    }
}

/// Five-layer Caddy reverse proxy correlation report.
#[derive(Debug, Serialize)]
pub struct Report<'a> {
    /// Trusted scope attached to the snapshot capture, when available.
    pub capture_scope: Option<Scope<'a>>,
    /// Layer 1: Configured on-disk Caddy route and frontend listener evidence.
    pub route: Option<ConfiguredRouteEvidence<'a>>,
    /// Layer 2: Frontend TCP connectivity evidence, never inferred from HTTP errors.
    pub tcp: TcpLayerEvidence<'a>,
    /// Layer 3: Scoped client HTTP observation, when supplied.
    pub http: Option<HttpObservation<'a>>,
    /// Layer 4: Local upstream TCP listener evidence, separate from HTTP gateway errors.
    pub backend: Option<BackendEvidence>,
    /// Layer 5: Proxy-layer auth indicators and explicit unverified application auth marker.
    pub auth: Option<AuthEvidence>,
    /// Maximum permitted age of the capture when the observation finishes.
    pub max_capture_age_seconds: u64,
    /// Outcome of correlating the five layers within scope.
    pub comparison: Comparison,
}
