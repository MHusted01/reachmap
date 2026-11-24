//! Turning raw handlers into [`Handler`]s.

use serde_json::Value;

use super::{MAX_ROUTE_DEPTH, Projector};
use crate::caddy::dial::DialTarget;
use crate::caddy::location::JsonPath;
use crate::caddy::raw::{
    RawAuthentication, RawHandler, RawReverseProxy, RawStatusCode, RawSubroute, RawUpstream,
};
use crate::caddy::{Handler, Middleware, Responder, ReverseProxy, UncertaintyKind};

/// The construct named when a handler has no readable `handler` field.
const UNNAMED_HANDLER: &str = "handler";

/// The only `reverse_proxy` transport the model follows.
const HTTP_TRANSPORT: &str = "http";

/// Informational status codes, which Caddy sends before passing the request
/// on to the next handler.
const INFORMATIONAL: std::ops::RangeInclusive<u16> = 100..=199;

impl Projector<'_> {
    /// Projects one element of a route's `handle` list. The handler name is
    /// read first so an unknown or malformed handler can still be named.
    pub(super) fn handler(&mut self, value: Value, at: &JsonPath, depth: usize) -> Handler {
        let name = value
            .get("handler")
            .and_then(Value::as_str)
            .unwrap_or(UNNAMED_HANDLER)
            .to_owned();
        let Ok(raw) = serde_json::from_value::<RawHandler>(value) else {
            self.note(UncertaintyKind::Malformed, &name, at);
            return Handler::Unmodeled {};
        };
        let respond = |responder| Handler::Respond { responder };
        let middleware = |middleware| Handler::Middleware { middleware };
        match raw {
            RawHandler::ReverseProxy(proxy) => Handler::ReverseProxy(self.reverse_proxy(proxy, at)),
            RawHandler::Subroute(subroute) => self.subroute(subroute, at, depth),
            RawHandler::Authentication(auth) => self.authentication(&auth, at),
            RawHandler::Rewrite {} | RawHandler::Uri {} | RawHandler::Map {} => {
                self.note(UncertaintyKind::RoutingHandler, &name, at);
                Handler::Unmodeled {}
            }
            RawHandler::StaticResponse { status_code } => self.static_response(status_code, at),
            RawHandler::FileServer { pass_thru: false } => respond(Responder::FileServer),
            RawHandler::FileServer { pass_thru: true } => {
                let kind = UncertaintyKind::ConditionalFallthrough;
                self.note(kind, "pass_thru", &at.field("pass_thru"));
                Handler::Unmodeled {}
            }
            RawHandler::Error {} => respond(Responder::Error),
            RawHandler::Headers {} => middleware(Middleware::Headers),
            RawHandler::Encode {} => middleware(Middleware::Encode),
            RawHandler::RequestBody {} => middleware(Middleware::RequestBody),
            RawHandler::Vars {} => middleware(Middleware::Vars),
            RawHandler::Templates {} => middleware(Middleware::Templates),
            RawHandler::Tracing {} => middleware(Middleware::Tracing),
            RawHandler::LogAppend {} => middleware(Middleware::LogAppend),
            RawHandler::Unknown => {
                self.note(UncertaintyKind::UnknownHandler, &name, at);
                Handler::Unmodeled {}
            }
        }
    }

    /// Follows a subroute unless it is nested deeper than [`MAX_ROUTE_DEPTH`].
    /// Its `errors` routes can proxy a failed request and are not modeled.
    fn subroute(&mut self, raw: RawSubroute, at: &JsonPath, depth: usize) -> Handler {
        if depth >= MAX_ROUTE_DEPTH {
            self.note(UncertaintyKind::NestingTooDeep, "subroute", at);
            return Handler::Unmodeled {};
        }
        if raw.errors.is_some() {
            let kind = UncertaintyKind::UnmodeledServerFeature;
            self.note(kind, "errors", &at.field("errors"));
        }
        Handler::Subroute {
            routes: self.routes(raw.routes, &at.field("routes"), depth + 1),
        }
    }

    /// A `static_response` ends the chain, except with a 1xx status, which
    /// Caddy sends before passing the request on.
    fn static_response(&mut self, status: Option<RawStatusCode>, at: &JsonPath) -> Handler {
        let status_at = at.field("status_code");
        let code = match status {
            None => None,
            Some(RawStatusCode::Number(code)) => Some(code),
            Some(RawStatusCode::Text(text)) if text.contains('{') => {
                self.note(UncertaintyKind::Placeholder, "status_code", &status_at);
                return Handler::Unmodeled {};
            }
            Some(RawStatusCode::Text(text)) => {
                let Ok(code) = text.trim().parse() else {
                    self.note(UncertaintyKind::Malformed, "status_code", &status_at);
                    return Handler::Unmodeled {};
                };
                Some(code)
            }
        };
        match code {
            Some(code) if INFORMATIONAL.contains(&code) => Handler::Middleware {
                middleware: Middleware::InformationalResponse,
            },
            _ => Handler::Respond {
                responder: Responder::StaticResponse,
            },
        }
    }

    fn authentication(&mut self, raw: &RawAuthentication, at: &JsonPath) -> Handler {
        let providers_at = at.field("providers");
        let mut other_providers = false;
        for name in raw.providers.keys().filter(|name| *name != "http_basic") {
            other_providers = true;
            let at = self.key(&providers_at, name);
            self.note(UncertaintyKind::UnmodeledAuthProvider, name, &at);
        }
        Handler::Authentication {
            http_basic: raw.providers.contains_key("http_basic"),
            other_providers,
        }
    }

    /// A proxy is complete when this added no uncertainty.
    fn reverse_proxy(&mut self, raw: RawReverseProxy, at: &JsonPath) -> ReverseProxy {
        let before = self.found();
        if raw.dynamic_upstreams.is_some() {
            let field = "dynamic_upstreams";
            self.note(UncertaintyKind::DynamicUpstreams, field, &at.field(field));
        } else if raw.upstreams.is_empty() {
            self.note(
                UncertaintyKind::Malformed,
                "upstreams",
                &at.field("upstreams"),
            );
        }
        let forward_auth = raw.is_forward_auth();
        if !forward_auth && !raw.handle_response.is_empty() {
            let field = "handle_response";
            self.note(UncertaintyKind::ResponseHandling, field, &at.field(field));
        }
        let tls = raw
            .transport
            .as_ref()
            .is_some_and(|transport| transport.tls.is_some());
        let other_protocol = raw
            .transport
            .as_ref()
            .and_then(|transport| transport.protocol.as_deref())
            .is_some_and(|protocol| protocol != HTTP_TRANSPORT);
        if other_protocol {
            let protocol_at = at.field("transport").field("protocol");
            self.note(
                UncertaintyKind::UnsupportedTransport,
                "protocol",
                &protocol_at,
            );
        }
        let upstreams_at = at.field("upstreams");
        let upstreams = raw
            .upstreams
            .iter()
            .enumerate()
            .filter_map(|(index, upstream)| self.upstream(upstream, &upstreams_at.index(index)))
            .collect();
        ReverseProxy {
            upstreams,
            complete: self.found() == before,
            tls,
            forward_auth,
        }
    }

    /// A static upstream; a host name is kept but noted, as it needs DNS.
    /// With `lookup_srv`, Caddy ignores `dial` and asks DNS for targets.
    fn upstream(&mut self, raw: &RawUpstream, at: &JsonPath) -> Option<DialTarget> {
        if raw.lookup_srv.is_some() {
            let field = "lookup_srv";
            self.note(UncertaintyKind::DynamicUpstreams, field, &at.field(field));
            return None;
        }
        let dial_at = at.field("dial");
        let Some(text) = raw.dial.as_deref() else {
            self.note(UncertaintyKind::Malformed, "dial", &dial_at);
            return None;
        };
        if self.substituted(text, "dial", &dial_at) {
            return None;
        }
        match DialTarget::parse(text) {
            Ok(target) => {
                if matches!(target, DialTarget::Hostname { .. }) {
                    self.note(UncertaintyKind::UnresolvedHost, "dial", &dial_at);
                }
                Some(target)
            }
            Err(problem) => {
                self.note(problem.kind(), "dial", &dial_at);
                None
            }
        }
    }
}
