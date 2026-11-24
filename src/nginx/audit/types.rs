//! Public data types for five-layer Nginx reverse proxy correlation.

use serde::Serialize;

use crate::nginx::routes::snapshot::Snapshot;
use crate::nginx::{AuthSignals, LocationModifier};
use crate::proxy_audit::{
    ApplicationAuthStatus, HttpObservation, ListenerEvidence, ProxyAuthIndicator, Scope,
    TcpLayerEvidence,
};

use super::backend::BackendEvidence;
use super::outcome::Comparison;

/// An Nginx route snapshot and the trusted scope attached to that capture.
#[derive(Debug, Clone, Copy)]
pub struct Capture<'a> {
    /// Evidence returned by `reachmap scan --nginx-routes --snapshot`.
    pub snapshot: &'a Snapshot,
    /// Supply only when authenticated provenance and capture context have been established.
    pub scope: Option<Scope<'a>>,
}

/// Layer 1: Configured on-disk Nginx route evidence and frontend listener status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConfiguredRouteEvidence<'a> {
    /// Always `true`: the collector reads on-disk configuration rather than master worker memory.
    pub on_disk_config_only: bool,
    /// Always `true`: whether the running Nginx master reloaded this config is unverified.
    pub running_master_reload_unverified: bool,
    /// Whether configuration and local TCP socket inventory collection completed without partial notes.
    pub collection_complete: bool,
    /// Number of dynamic or unmodeled configuration uncertainties recorded during parsing.
    pub uncertainty_count: usize,
    /// Matched server source file, when known.
    pub server_source_file: Option<&'a str>,
    /// Matched `listen` port from the Nginx configuration.
    pub listen_port: u16,
    /// Whether the matched `listen` directive sets `ssl`.
    pub listen_ssl: bool,
    /// Matched `location` modifier, if a `location` block matched the requested path.
    pub location_modifier: Option<LocationModifier>,
    /// Matched `location` path pattern, if a `location` block matched the requested path.
    pub location_path: Option<&'a str>,
    /// Local TCP listener match for the frontend `listen` directive.
    pub frontend_listener: ListenerEvidence,
}

/// Layer 5: Proxy-layer auth indicators kept separate from unverified application auth.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct AuthEvidence {
    /// Sanitized proxy-layer auth/ACL flags from the matched route.
    pub proxy_auth: AuthSignals,
    /// Whether Nginx proxy-layer authentication or ACLs are configured.
    pub indicator: ProxyAuthIndicator,
    /// Explicit marker that application-level authentication remains unverified.
    pub application_auth: ApplicationAuthStatus,
}

/// Five-layer Nginx reverse proxy correlation report.
#[derive(Debug, Serialize)]
pub struct Report<'a> {
    /// Trusted scope attached to the snapshot capture, when available.
    pub capture_scope: Option<Scope<'a>>,
    /// Layer 1: Configured on-disk Nginx route and frontend listener evidence.
    pub route: Option<ConfiguredRouteEvidence<'a>>,
    /// Layer 2: Frontend TCP connectivity evidence, never inferred from HTTP errors.
    pub tcp: TcpLayerEvidence<'a>,
    /// Layer 3: Scoped client HTTP observation, when supplied.
    pub http: Option<HttpObservation<'a>>,
    /// Layer 4: Local backend TCP listener evidence, separate from HTTP gateway errors.
    pub backend: Option<BackendEvidence>,
    /// Layer 5: Proxy-layer auth indicators and explicit unverified application auth marker.
    pub auth: Option<AuthEvidence>,
    /// Maximum permitted age of the capture when the observation finishes.
    pub max_capture_age_seconds: u64,
    /// Outcome of correlating the five layers within scope.
    pub comparison: Comparison,
}
