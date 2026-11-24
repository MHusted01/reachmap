//! Secret-minimized domain model for a bounded subset of Caddy's native JSON
//! configuration (what `caddy adapt` prints).
//!
//! [`parse_caddy_config`] projects the JSON straight into these types. Only
//! listeners, route matchers, proxy upstreams, proxy-layer authentication
//! presence and explicit uncertainties are kept: never password hashes,
//! header values, TLS material, storage or admin settings, or any field the
//! model does not name.
//!
//! Two limits matter to consumers:
//! - Listeners are TCP only. HTTP/3 is recorded as [`CaddyServer::http3`];
//!   the UDP sockets it opens are not listed as [`ListenAddress`]es.
//! - The Caddyfile adapter expands `{$VAR}` before this JSON exists, so an
//!   expanded secret looks like any literal path, host or upstream. A
//!   collector that knows the substituted values passes them as
//!   [`Substitutions`] to [`parse_caddy_config_with`], which then leaves out
//!   every modeled value containing one.

use std::fmt;

use serde::{Deserialize, Serialize};

mod address;
mod dial;
mod error;
mod handler;
mod listen;
mod location;
mod matcher;
mod project;
mod raw;
pub mod routes;
mod substitution;

#[cfg(test)]
mod tests;

pub use dial::{DialTarget, HostName};
pub use error::{CaddyParseError, MAX_INPUT_BYTES};
pub use handler::{Handler, Middleware, Responder, ReverseProxy};
pub use listen::{ListenAddress, ListenHost, ListenNetwork, PortRange};
pub use matcher::{HostMatcher, PathMatcher};
pub use project::{
    MAX_ROUTE_DEPTH, MAX_UNCERTAINTIES, REDACTED, parse_caddy_config, parse_caddy_config_with,
};
pub use substitution::{MIN_SUBSTITUTION_CHARS, Substitutions};

/// Port Caddy uses for HTTP when the `http` app names none.
pub const DEFAULT_HTTP_PORT: u16 = 80;

/// Port Caddy uses for HTTPS when the `http` app names none.
pub const DEFAULT_HTTPS_PORT: u16 = 443;

/// Routes, listeners and uncertainties extracted from one Caddy JSON config.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaddyConfig {
    /// Port of the HTTP-to-HTTPS redirects that automatic HTTPS adds; `None`
    /// when the configured value was left out as a known substitution.
    pub http_port: Option<u16>,
    /// Port automatic HTTPS treats as the HTTPS port; `None` when the
    /// configured value was left out as a known substitution.
    pub https_port: Option<u16>,
    /// Servers of the `http` app, ordered by their configuration key.
    pub servers: Vec<CaddyServer>,
    /// Constructs that could change routing or exposure but are not modeled,
    /// at most [`MAX_UNCERTAINTIES`].
    pub uncertainties: Vec<Uncertainty>,
    /// How many more uncertainties were found beyond the bound.
    pub uncertainties_omitted: usize,
}

impl Default for CaddyConfig {
    fn default() -> Self {
        Self {
            http_port: Some(DEFAULT_HTTP_PORT),
            https_port: Some(DEFAULT_HTTPS_PORT),
            servers: Vec::new(),
            uncertainties: Vec::new(),
            uncertainties_omitted: 0,
        }
    }
}

/// One entry of `apps.http.servers`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaddyServer {
    /// Sanitized, length-bounded configuration key, e.g. `srv0`.
    pub name: String,
    /// Statically understood `listen` addresses.
    pub listen: Vec<ListenAddress>,
    /// Automatic HTTPS switches set on this server.
    pub automatic_https: AutomaticHttps,
    /// Whether HTTP/3 is enabled (`protocols` unset or holding `h3`). Caddy
    /// then also listens on UDP on the ports where it serves TLS.
    pub http3: bool,
    /// Whether Caddy certainly opens a TCP listener on every `listen`
    /// address. `false` when `protocols` holds only `h3` (whether a TCP
    /// socket is still opened depends on the Caddy version) or when
    /// `listen_protocols` overrides the protocols of some addresses; an
    /// uncertainty then names the field.
    pub tcp_known: bool,
    /// One entry per `tls_connection_policies` item.
    pub tls_policies: Vec<TlsPolicy>,
    /// Top-level routes in configuration order.
    pub routes: Vec<Route>,
}

/// The `automatic_https` switches of a server. All `false` when unset.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AutomaticHttps {
    /// `disable`: no certificates and no redirects for this server.
    pub disabled: bool,
    /// `disable_redirects`: certificates, but no HTTP-to-HTTPS redirect listener.
    pub redirects_disabled: bool,
    /// `skip` or `skip_certificates`: some hosts are left out of automatic HTTPS.
    pub hosts_skipped: bool,
}

/// One TLS connection policy of a server, reduced to access signals.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsPolicy {
    /// Whether the policy applies only to connections it matches (e.g. by SNI).
    pub scoped: bool,
    /// Client certificate requirement, when the policy configures one.
    pub client_auth: Option<ClientAuthMode>,
}

/// How a TLS policy treats client certificates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientAuthMode {
    /// `request`: asks for a certificate, accepts connections without one.
    Request,
    /// `require`: needs a certificate, does not verify it.
    Require,
    /// `verify_if_given`: verifies a certificate only when one is sent.
    VerifyIfGiven,
    /// `require_and_verify`: needs a certificate that verifies.
    RequireAndVerify,
    /// No `mode`, but trusted certificates or verifiers are configured;
    /// Caddy picks the mode.
    Implicit,
}

/// One route: matcher sets, then a chain of handlers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Route {
    /// The route's `group`. Only the first matching route of a group runs.
    pub group: Option<RouteGroup>,
    /// Matcher sets, of which any one must match. Empty matches every request.
    pub matchers: Vec<MatcherSet>,
    /// Handlers in chain order.
    pub handlers: Vec<Handler>,
    /// Whether no later route runs after this one matched.
    pub terminal: bool,
}

/// A route `group`. Caddy keeps one set of applied groups per request,
/// shared by a server's routes and all their subroutes, so two routes of
/// one server are in the same group exactly when their `id`s are equal. The
/// label is for display and may be cut short or redacted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteGroup {
    /// Number assigned to the full group name, unique within one server.
    pub id: usize,
    /// Sanitized, length-bounded group name.
    pub label: String,
}

/// One matcher set: every matcher in it must match.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatcherSet {
    /// `host` patterns, any of which may match; `None` when unconstrained.
    pub hosts: Option<Vec<HostMatcher>>,
    /// `path` patterns, any of which may match; `None` when unconstrained.
    pub paths: Option<Vec<PathMatcher>>,
    /// `false` when a matcher or pattern of this set was not modeled, so the
    /// set may match other requests than `hosts` and `paths` say.
    pub complete: bool,
}

/// A construct that could change routing or exposure but is not modeled.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Uncertainty {
    /// Category of the construct.
    pub kind: UncertaintyKind,
    /// Sanitized name of the construct (a field, matcher or handler name),
    /// never a configured value.
    pub construct: String,
    /// JSON location, e.g. `apps.http.servers["srv0"].routes[1].handle[0]`.
    pub location: String,
}

/// Category of an [`Uncertainty`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UncertaintyKind {
    /// A runtime placeholder (`{...}`) in a listener, matcher or upstream.
    Placeholder,
    /// A matcher other than `host` and `path`, e.g. `expression` or `remote_ip`.
    UnmodeledMatcher,
    /// A `host` or `path` pattern beyond exact, prefix or leading wildcard.
    UnsupportedPattern,
    /// A handler that rewrites or remaps the request: `rewrite`, `uri`, `map`.
    RoutingHandler,
    /// A handler type the model does not know.
    UnknownHandler,
    /// `dynamic_upstreams`: proxy targets chosen at runtime.
    DynamicUpstreams,
    /// A Unix socket, UDP, file descriptor or non-HTTP proxy transport.
    UnsupportedTransport,
    /// A host name that needs DNS to become an address.
    UnresolvedHost,
    /// A server without `listen`, or a listen address without a port.
    ImplicitListen,
    /// An app other than `http` that may accept connections, e.g. `layer4`.
    UnmodeledApp,
    /// A server or subroute feature that can route requests or change how
    /// connections are accepted, e.g. `errors`, `named_routes`,
    /// `listener_wrappers` or `listen_protocols`.
    UnmodeledServerFeature,
    /// An authentication provider other than `http_basic`.
    UnmodeledAuthProvider,
    /// A client authentication `mode` the model does not know.
    UnknownClientAuthMode,
    /// Client certificate `verifiers`, whose checks are not modeled.
    ClientCertificateVerifier,
    /// A responder that passes the request on when it cannot answer, e.g.
    /// `file_server` with `pass_thru`.
    ConditionalFallthrough,
    /// `handle_response` routes other than the `forward_auth` shape.
    ResponseHandling,
    /// A value containing a known [`Substitutions`] value; it is left out.
    SubstitutedValue,
    /// Subroutes nested deeper than [`MAX_ROUTE_DEPTH`].
    NestingTooDeep,
    /// A value of the wrong shape or an invalid address.
    Malformed,
}

impl fmt::Display for UncertaintyKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Placeholder => "runtime placeholder",
            Self::UnmodeledMatcher => "unmodeled matcher",
            Self::UnsupportedPattern => "unsupported match pattern",
            Self::RoutingHandler => "request-rewriting handler",
            Self::UnknownHandler => "unknown handler",
            Self::DynamicUpstreams => "dynamic upstreams",
            Self::UnsupportedTransport => "unsupported transport",
            Self::UnresolvedHost => "host name requiring DNS resolution",
            Self::ImplicitListen => "implicit listen port",
            Self::UnmodeledApp => "unmodeled app",
            Self::UnmodeledServerFeature => "unmodeled server feature",
            Self::UnmodeledAuthProvider => "unmodeled authentication provider",
            Self::UnknownClientAuthMode => "unknown client authentication mode",
            Self::ClientCertificateVerifier => "client certificate verifier",
            Self::ConditionalFallthrough => "conditional fall-through",
            Self::ResponseHandling => "proxy response handling",
            Self::SubstitutedValue => "substituted value left out",
            Self::NestingTooDeep => "subroutes nested too deep",
            Self::Malformed => "malformed value",
        })
    }
}

impl fmt::Display for Uncertainty {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} (`{}`) at {}",
            self.kind, self.construct, self.location
        )
    }
}
