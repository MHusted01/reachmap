//! The parts of Caddy's JSON that the model reads.
//!
//! Fields that can hold secrets (`admin`, `storage`, account lists, headers,
//! TLS material) are not declared in these structs, so they never reach the
//! model. Where only presence matters, [`IgnoredAny`] checks that a field is
//! there and discards it. One exception: each route's `handle` list is read
//! as JSON first (see [`RawRoute::handle`]), so a handler's fields sit in
//! memory until that handler is projected; nothing is kept from them but
//! what [`RawHandler`] declares.

use std::collections::BTreeMap;

use serde::Deserialize;
use serde::de::IgnoredAny;
use serde_json::Value;

/// The whole config.
#[derive(Deserialize)]
pub(super) struct RawConfig {
    pub(super) apps: Option<RawApps>,
}

/// `apps`: the `http` app, and the names of all others.
#[derive(Default, Deserialize)]
pub(super) struct RawApps {
    pub(super) http: Option<RawHttpApp>,
    #[serde(flatten)]
    pub(super) other: BTreeMap<String, IgnoredAny>,
}

/// `apps.http`.
#[derive(Default, Deserialize)]
pub(super) struct RawHttpApp {
    pub(super) http_port: Option<u16>,
    pub(super) https_port: Option<u16>,
    #[serde(default)]
    pub(super) servers: BTreeMap<String, RawServer>,
}

/// One entry of `apps.http.servers`.
#[derive(Deserialize)]
pub(super) struct RawServer {
    pub(super) listen: Option<Vec<String>>,
    #[serde(default)]
    pub(super) listener_wrappers: Vec<RawListenerWrapper>,
    pub(super) protocols: Option<Vec<String>>,
    #[serde(default)]
    pub(super) routes: Vec<RawRoute>,
    pub(super) automatic_https: Option<RawAutomaticHttps>,
    #[serde(default)]
    pub(super) tls_connection_policies: Vec<RawTlsPolicy>,
    pub(super) errors: Option<IgnoredAny>,
    pub(super) named_routes: Option<IgnoredAny>,
}

/// One `listener_wrappers` item.
#[derive(Deserialize)]
pub(super) struct RawListenerWrapper {
    pub(super) wrapper: Option<String>,
}

/// `automatic_https`.
#[derive(Deserialize)]
pub(super) struct RawAutomaticHttps {
    #[serde(default)]
    pub(super) disable: bool,
    #[serde(default)]
    pub(super) disable_redirects: bool,
    pub(super) skip: Option<IgnoredAny>,
    pub(super) skip_certificates: Option<IgnoredAny>,
}

/// One `tls_connection_policies` item.
#[derive(Deserialize)]
pub(super) struct RawTlsPolicy {
    #[serde(rename = "match")]
    pub(super) matcher: Option<IgnoredAny>,
    pub(super) client_authentication: Option<RawClientAuth>,
}

/// `client_authentication`: the mode, and whether any trust is configured.
#[derive(Deserialize)]
pub(super) struct RawClientAuth {
    pub(super) mode: Option<String>,
    pub(super) ca: Option<IgnoredAny>,
    pub(super) trusted_ca_certs: Option<IgnoredAny>,
    pub(super) trusted_ca_certs_pem_files: Option<IgnoredAny>,
    pub(super) trusted_leaf_certs: Option<IgnoredAny>,
    #[serde(default)]
    pub(super) verifiers: Vec<IgnoredAny>,
}

impl RawClientAuth {
    /// Whether certificates to trust or verifiers are configured.
    pub(super) fn has_trust(&self) -> bool {
        self.ca.is_some()
            || self.trusted_ca_certs.is_some()
            || self.trusted_ca_certs_pem_files.is_some()
            || self.trusted_leaf_certs.is_some()
            || !self.verifiers.is_empty()
    }
}

/// One route.
#[derive(Deserialize)]
pub(super) struct RawRoute {
    pub(super) group: Option<String>,
    #[serde(rename = "match", default)]
    pub(super) matchers: Vec<RawMatcherSet>,
    /// Kept as JSON so an unknown handler can still be named; each one is
    /// turned into a [`RawHandler`] on its own.
    #[serde(default)]
    pub(super) handle: Vec<Value>,
    #[serde(default)]
    pub(super) terminal: bool,
}

/// One matcher set: `host` and `path`, and the names of all other matchers.
#[derive(Deserialize)]
pub(super) struct RawMatcherSet {
    pub(super) host: Option<Vec<String>>,
    pub(super) path: Option<Vec<String>>,
    #[serde(flatten)]
    pub(super) other: BTreeMap<String, IgnoredAny>,
}

/// One handler, chosen by its `handler` field.
#[derive(Deserialize)]
#[serde(tag = "handler", rename_all = "snake_case")]
pub(super) enum RawHandler {
    ReverseProxy(RawReverseProxy),
    Subroute(RawSubroute),
    Authentication(RawAuthentication),
    Rewrite {},
    Uri {},
    Map {},
    StaticResponse {},
    FileServer {
        #[serde(default)]
        pass_thru: bool,
    },
    Error {},
    Headers {},
    Encode {},
    RequestBody {},
    Vars {},
    Templates {},
    Tracing {},
    LogAppend {},
    #[serde(other)]
    Unknown,
}

/// `reverse_proxy`.
#[derive(Deserialize)]
pub(super) struct RawReverseProxy {
    #[serde(default)]
    pub(super) upstreams: Vec<RawUpstream>,
    pub(super) dynamic_upstreams: Option<IgnoredAny>,
    pub(super) transport: Option<RawTransport>,
    #[serde(default)]
    pub(super) handle_response: Vec<RawResponseHandler>,
}

impl RawReverseProxy {
    /// Whether `handle_response` has the shape Caddy's `forward_auth`
    /// directive adapts to: one handler matching only 2xx status codes.
    pub(super) fn is_forward_auth(&self) -> bool {
        match self.handle_response.as_slice() {
            [only] => only.matcher.as_ref().is_some_and(|matcher| {
                matcher.headers.is_none() && matcher.status_code.as_deref() == Some(&[2])
            }),
            _ => false,
        }
    }
}

/// One static upstream.
#[derive(Deserialize)]
pub(super) struct RawUpstream {
    pub(super) dial: Option<String>,
    pub(super) lookup_srv: Option<IgnoredAny>,
}

/// One `handle_response` item.
#[derive(Deserialize)]
pub(super) struct RawResponseHandler {
    #[serde(rename = "match")]
    pub(super) matcher: Option<RawResponseMatch>,
}

/// The response matcher of a `handle_response` item.
#[derive(Deserialize)]
pub(super) struct RawResponseMatch {
    pub(super) status_code: Option<Vec<u16>>,
    pub(super) headers: Option<IgnoredAny>,
}

/// `reverse_proxy.transport`.
#[derive(Deserialize)]
pub(super) struct RawTransport {
    pub(super) protocol: Option<String>,
    pub(super) tls: Option<IgnoredAny>,
}

/// `subroute`.
#[derive(Deserialize)]
pub(super) struct RawSubroute {
    #[serde(default)]
    pub(super) routes: Vec<RawRoute>,
}

/// `authentication`: only the provider names.
#[derive(Deserialize)]
pub(super) struct RawAuthentication {
    #[serde(default)]
    pub(super) providers: BTreeMap<String, IgnoredAny>,
}
