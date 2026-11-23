//! Turning raw handlers into [`Handler`]s.

use serde_json::Value;

use super::{MAX_ROUTE_DEPTH, Projector};
use crate::caddy::dial::DialTarget;
use crate::caddy::location::JsonPath;
use crate::caddy::raw::{RawAuthentication, RawHandler, RawReverseProxy, RawRoute, RawUpstream};
use crate::caddy::{Handler, Middleware, Responder, ReverseProxy, UncertaintyKind};

/// The construct named when a handler has no readable `handler` field.
const UNNAMED_HANDLER: &str = "handler";

/// The only `reverse_proxy` transport the model follows.
const HTTP_TRANSPORT: &str = "http";

impl Projector {
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
            RawHandler::Subroute(subroute) => self.subroute(subroute.routes, at, depth),
            RawHandler::Authentication(auth) => self.authentication(&auth, at),
            RawHandler::Rewrite {} | RawHandler::Uri {} | RawHandler::Map {} => {
                self.note(UncertaintyKind::RoutingHandler, &name, at);
                Handler::Unmodeled {}
            }
            RawHandler::StaticResponse {} => respond(Responder::StaticResponse),
            RawHandler::FileServer {} => respond(Responder::FileServer),
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
    fn subroute(&mut self, routes: Vec<RawRoute>, at: &JsonPath, depth: usize) -> Handler {
        if depth >= MAX_ROUTE_DEPTH {
            self.note(UncertaintyKind::NestingTooDeep, "subroute", at);
            return Handler::Unmodeled {};
        }
        Handler::Subroute {
            routes: self.routes(routes, &at.field("routes"), depth + 1),
        }
    }

    fn authentication(&mut self, raw: &RawAuthentication, at: &JsonPath) -> Handler {
        let providers_at = at.field("providers");
        let mut other_providers = false;
        for name in raw.providers.keys().filter(|name| *name != "http_basic") {
            other_providers = true;
            self.note(
                UncertaintyKind::UnmodeledAuthProvider,
                name,
                &providers_at.key(name),
            );
        }
        Handler::Authentication {
            http_basic: raw.providers.contains_key("http_basic"),
            other_providers,
        }
    }

    /// A proxy is complete when this added no uncertainty.
    fn reverse_proxy(&mut self, raw: RawReverseProxy, at: &JsonPath) -> ReverseProxy {
        let before = self.uncertainties.len();
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
        let tls = raw
            .transport
            .as_ref()
            .is_some_and(|transport| transport.tls.is_some());
        if let Some(protocol) = raw
            .transport
            .and_then(|transport| transport.protocol)
            .filter(|protocol| protocol != HTTP_TRANSPORT)
        {
            let protocol_at = at.field("transport").field("protocol");
            self.note(
                UncertaintyKind::UnsupportedTransport,
                &protocol,
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
            complete: self.uncertainties.len() == before,
            tls,
            forward_auth: !raw.handle_response.is_empty(),
        }
    }

    /// A static upstream; a host name is kept but noted, as it needs DNS.
    fn upstream(&mut self, raw: &RawUpstream, at: &JsonPath) -> Option<DialTarget> {
        let dial_at = at.field("dial");
        let Some(text) = raw.dial.as_deref() else {
            self.note(UncertaintyKind::Malformed, "dial", &dial_at);
            return None;
        };
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
