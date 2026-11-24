//! Turning raw handlers into [`Handler`]s.

use serde_json::Value;

use super::{MAX_ROUTE_DEPTH, Projector};
use crate::caddy::dial::DialTarget;
use crate::caddy::location::JsonPath;
use crate::caddy::raw::{
    RawAuthentication, RawHandler, RawReverseProxy, RawStatusCode, RawSubroute, RawTransport,
    RawUpstream,
};
use crate::caddy::{Handler, Middleware, Responder, ReverseProxy, UncertaintyKind};

/// The construct named when a handler has no readable `handler` field.
const UNNAMED_HANDLER: &str = "handler";

/// The only `reverse_proxy` transport the model follows.
const HTTP_TRANSPORT: &str = "http";

/// `103 Early Hints`, the only status Caddy sends before passing the
/// request on to the next handler.
const EARLY_HINTS: u16 = 103;

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
            RawHandler::StaticResponse { status_code, abort } => {
                self.static_response(status_code, abort, at)
            }
            RawHandler::FileServer { pass_thru: false } => respond(Responder::FileServer),
            RawHandler::FileServer { pass_thru: true } => {
                let kind = UncertaintyKind::ConditionalFallthrough;
                self.note(kind, "pass_thru", &at.field("pass_thru"));
                Handler::Unmodeled {}
            }
            RawHandler::Error {} => respond(Responder::Error),
            RawHandler::Headers(headers) => {
                if headers.request.is_some_and(|ops| ops.touches_host()) {
                    let kind = UncertaintyKind::RoutingHandler;
                    self.note(kind, "request", &at.field("request"));
                }
                middleware(Middleware::Headers)
            }
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

    /// A `static_response` ends the chain, except `103 Early Hints` without
    /// `abort`, which Caddy sends before passing the request on.
    fn static_response(
        &mut self,
        status: Option<RawStatusCode>,
        abort: bool,
        at: &JsonPath,
    ) -> Handler {
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
            Some(EARLY_HINTS) if !abort => Handler::Middleware {
                middleware: Middleware::EarlyHints,
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
            .is_some_and(|transport| self.transport(transport, &at.field("transport")));
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

    /// Notes what makes the transport differ from a direct HTTP connection to
    /// the upstream, and says whether it speaks TLS.
    fn transport(&mut self, raw: &RawTransport, at: &JsonPath) -> bool {
        if raw
            .protocol
            .as_deref()
            .is_some_and(|protocol| protocol != HTTP_TRANSPORT)
        {
            self.note(
                UncertaintyKind::UnsupportedTransport,
                "protocol",
                &at.field("protocol"),
            );
        }
        let proxies = [
            ("network_proxy", raw.network_proxy.is_some()),
            ("forward_proxy_url", raw.forward_proxy_url.is_some()),
        ];
        for (field, _) in proxies.into_iter().filter(|(_, present)| *present) {
            self.note(
                UncertaintyKind::UnsupportedTransport,
                field,
                &at.field(field),
            );
        }
        raw.tls.is_some()
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
