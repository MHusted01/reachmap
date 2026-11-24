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
    pub(super) listen_protocols: Vec<IgnoredAny>,
    pub(super) strict_sni_host: Option<bool>,
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
    #[serde(default)]
    pub(super) trusted_ca_certs: Vec<IgnoredAny>,
    #[serde(default)]
    pub(super) trusted_ca_certs_pem_files: Vec<IgnoredAny>,
    #[serde(default)]
    pub(super) trusted_leaf_certs: Vec<IgnoredAny>,
    #[serde(default)]
    pub(super) verifiers: Vec<IgnoredAny>,
}

impl RawClientAuth {
    /// Whether certificates to trust or verifiers are configured. Empty
    /// lists configure nothing, so Caddy leaves client authentication off.
    pub(super) fn has_trust(&self) -> bool {
        self.ca.is_some()
            || !self.trusted_ca_certs.is_empty()
            || !self.trusted_ca_certs_pem_files.is_empty()
            || !self.trusted_leaf_certs.is_empty()
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
    StaticResponse {
        status_code: Option<RawStatusCode>,
        #[serde(default)]
        abort: bool,
    },
    FileServer {
        #[serde(default)]
        pass_thru: bool,
    },
    Error {},
    Headers(RawHeaders),
    Encode {},
    RequestBody {},
    Vars {},
    Templates {},
    Tracing {},
    LogAppend {},
    #[serde(other)]
    Unknown,
}

/// `headers`: only which request headers it changes.
#[derive(Deserialize)]
pub(super) struct RawHeaders {
    pub(super) request: Option<RawHeaderOps>,
}

/// Request header operations, reduced to the header names they touch.
#[derive(Deserialize)]
pub(super) struct RawHeaderOps {
    #[serde(default)]
    pub(super) set: BTreeMap<String, IgnoredAny>,
    #[serde(default)]
    pub(super) add: BTreeMap<String, IgnoredAny>,
    #[serde(default)]
    pub(super) delete: Vec<String>,
    #[serde(default)]
    pub(super) replace: BTreeMap<String, IgnoredAny>,
}

impl RawHeaderOps {
    /// Whether the operations change `Host`, which later host matchers see.
    pub(super) fn touches_host(&self) -> bool {
        let is_host = |name: &str| name.eq_ignore_ascii_case("host");
        self.set.keys().any(|name| is_host(name))
            || self.add.keys().any(|name| is_host(name))
            || self.replace.keys().any(|name| is_host(name))
            || self.delete.iter().any(|name| is_host(name))
    }
}

/// A `static_response` status: Caddy accepts a number or a string, which
/// may hold a placeholder.
#[derive(Deserialize)]
#[serde(untagged)]
pub(super) enum RawStatusCode {
    Number(u16),
    Text(String),
}

/// `reverse_proxy`.
#[derive(Deserialize)]
pub(super) struct RawReverseProxy {
    #[serde(default)]
    pub(super) upstreams: Vec<RawUpstream>,
    pub(super) dynamic_upstreams: Option<IgnoredAny>,
    pub(super) transport: Option<RawTransport>,
    pub(super) rewrite: Option<RawProxyRewrite>,
    #[serde(default)]
    pub(super) handle_response: Vec<RawResponseHandler>,
}

impl RawReverseProxy {
    /// Whether the proxy has the shape Caddy's `forward_auth` directive
    /// adapts to: the request is rewritten to a `GET` of the auth service's
    /// URI, and one response handler matches only 2xx answers. Its routes
    /// start with a lone `vars` handler, which lets the original request
    /// continue down the chain, and the rest only copy headers.
    pub(super) fn is_forward_auth(&self) -> bool {
        let rewrites_to_get = self.rewrite.as_ref().is_some_and(|rewrite| {
            rewrite.method.as_deref() == Some("GET") && rewrite.uri.is_some()
        });
        let [only] = self.handle_response.as_slice() else {
            return false;
        };
        let only_2xx = only.matcher.as_ref().is_some_and(|matcher| {
            matcher.headers.is_none() && matcher.status_code.as_deref() == Some(&[2])
        });
        let Some((first, rest)) = only.routes.split_first() else {
            return false;
        };
        let falls_through = first.handles_only("vars") && first.handle.len() == 1;
        let copies_headers = rest.iter().all(|route| route.handles_only("headers"));
        rewrites_to_get && only_2xx && falls_through && copies_headers
    }
}

/// `reverse_proxy.rewrite`: how the proxied request is changed.
#[derive(Deserialize)]
pub(super) struct RawProxyRewrite {
    pub(super) method: Option<String>,
    pub(super) uri: Option<IgnoredAny>,
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
    #[serde(default)]
    pub(super) routes: Vec<RawResponseRoute>,
}

/// One route of a `handle_response` item, reduced to its handler types.
#[derive(Deserialize)]
pub(super) struct RawResponseRoute {
    #[serde(default)]
    pub(super) handle: Vec<RawHandlerTag>,
}

impl RawResponseRoute {
    /// Whether the route has handlers, all of type `handler`.
    fn handles_only(&self, handler: &str) -> bool {
        !self.handle.is_empty()
            && self
                .handle
                .iter()
                .all(|tag| tag.handler.as_deref() == Some(handler))
    }
}

/// Only the `handler` field of a handler.
#[derive(Deserialize)]
pub(super) struct RawHandlerTag {
    pub(super) handler: Option<String>,
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
    pub(super) network_proxy: Option<IgnoredAny>,
    pub(super) forward_proxy_url: Option<IgnoredAny>,
}

/// `subroute`.
#[derive(Deserialize)]
pub(super) struct RawSubroute {
    #[serde(default)]
    pub(super) routes: Vec<RawRoute>,
    pub(super) errors: Option<IgnoredAny>,
}

/// `authentication`: only the provider names.
#[derive(Deserialize)]
pub(super) struct RawAuthentication {
    #[serde(default)]
    pub(super) providers: BTreeMap<String, IgnoredAny>,
}
