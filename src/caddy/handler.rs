//! Modeled route handlers.

use serde::{Deserialize, Serialize};

use super::{DialTarget, Route};

/// One handler in a route's chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Handler {
    /// `reverse_proxy`.
    ReverseProxy(ReverseProxy),
    /// `subroute`: nested routes, evaluated in order.
    Subroute {
        /// Nested routes.
        routes: Vec<Route>,
    },
    /// `authentication`, reduced to which providers are present.
    Authentication {
        /// Whether `http_basic` is configured.
        http_basic: bool,
        /// Whether any other provider is configured.
        other_providers: bool,
    },
    /// A handler that answers the request itself and ends the chain.
    Respond {
        /// Which responder.
        responder: Responder,
    },
    /// A handler that adjusts the request or response and passes it on.
    Middleware {
        /// Which middleware.
        middleware: Middleware,
    },
    /// A handler the model does not follow; an uncertainty names it.
    Unmodeled {},
}

/// A `reverse_proxy` handler, reduced to where it sends requests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReverseProxy {
    /// Statically understood upstreams, in configuration order.
    pub upstreams: Vec<DialTarget>,
    /// `false` when an upstream, the transport or `dynamic_upstreams` was not
    /// understood, so requests may go elsewhere than `upstreams` says.
    pub complete: bool,
    /// Whether the transport speaks TLS to the upstreams.
    pub tls: bool,
    /// Whether the proxy has `handle_response` routes, the shape Caddy's
    /// `forward_auth` directive adapts to: the request only continues once
    /// the proxied auth service answers.
    pub forward_auth: bool,
}

/// A handler that writes the response itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Responder {
    /// `static_response`.
    StaticResponse,
    /// `file_server`.
    FileServer,
    /// `error`.
    Error,
}

/// A handler that passes the request on without changing where it goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Middleware {
    /// `headers`.
    Headers,
    /// `encode`.
    Encode,
    /// `request_body`.
    RequestBody,
    /// `vars`.
    Vars,
    /// `templates`.
    Templates,
    /// `tracing`.
    Tracing,
    /// `log_append`.
    LogAppend,
}
