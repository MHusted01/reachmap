//! Proxy-layer authentication configured in front of a handler.
//!
//! Caddy compiles a route list into one middleware chain: an
//! `authentication` handler, or a `forward_auth` proxy, wraps every handler
//! after it, including those of later routes. A signal from an earlier route
//! with matchers or a group applies only to the requests that route matched;
//! a terminal route passes nothing on.

use std::collections::BTreeMap;
use std::fmt;

use crate::caddy::{CaddyServer, ClientAuthMode, Handler, Route};

/// Auth signals in front of a handler, by label: `true` when the signal
/// applies to every request reaching the handler, `false` when only to some.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct AuthContext(BTreeMap<&'static str, bool>);

impl AuthContext {
    /// The client certificate policies of `server`, in Caddy's first-match
    /// order: policies after an unscoped one are never used. A policy only
    /// covers TLS connections, and a server can also take cleartext HTTP on
    /// some listeners, so a client certificate never counts as covering
    /// every request.
    pub(super) fn for_server(server: &CaddyServer) -> Self {
        let mut context = Self::default();
        for policy in &server.tls_policies {
            if let Some(mode) = policy.client_auth {
                context.add(client_auth_label(mode), false);
            }
            if !policy.scoped {
                break;
            }
        }
        context
    }

    /// Adds what `handler` puts in front of the handlers after it.
    pub(super) fn pass_handler(&mut self, handler: &Handler) {
        self.merge(&handler_signals(handler), true);
    }

    /// Adds what `route` puts in front of the routes after it. A terminal
    /// route adds nothing: a request it matched ends with it, and one it
    /// did not match never ran its handlers.
    pub(super) fn pass_route(&mut self, route: &Route) {
        if !route.terminal {
            self.merge(&route_signals(route), always_runs(route));
        }
    }

    fn add(&mut self, label: &'static str, always: bool) {
        let applies = self.0.entry(label).or_insert(always);
        *applies |= always;
    }

    fn merge(&mut self, other: &Self, always: bool) {
        for (&label, &applies) in &other.0 {
            self.add(label, applies && always);
        }
    }
}

impl fmt::Display for AuthContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.is_empty() {
            return f.write_str("none configured");
        }
        for (index, (label, always)) in self.0.iter().enumerate() {
            if index > 0 {
                f.write_str(", ")?;
            }
            f.write_str(label)?;
            if !always {
                f.write_str(" (some requests only)")?;
            }
        }
        Ok(())
    }
}

fn handler_signals(handler: &Handler) -> AuthContext {
    let mut signals = AuthContext::default();
    match handler {
        Handler::Authentication {
            http_basic,
            other_providers,
        } => {
            if *http_basic {
                signals.add("http_basic", true);
            }
            if *other_providers {
                signals.add("other authentication provider", true);
            }
        }
        Handler::ReverseProxy(proxy) if proxy.forward_auth => signals.add("forward_auth", true),
        Handler::Subroute { routes } => {
            for route in routes {
                signals.pass_route(route);
            }
        }
        Handler::ReverseProxy(_)
        | Handler::Respond { .. }
        | Handler::Middleware { .. }
        | Handler::Unmodeled {} => {}
    }
    signals
}

fn route_signals(route: &Route) -> AuthContext {
    let mut signals = AuthContext::default();
    for handler in &route.handlers {
        signals.pass_handler(handler);
    }
    signals
}

/// A route without matchers or group runs for every request that reaches it.
fn always_runs(route: &Route) -> bool {
    route.group.is_none() && route.matchers.is_empty()
}

fn client_auth_label(mode: ClientAuthMode) -> &'static str {
    match mode {
        ClientAuthMode::Request => "TLS client certificate requested",
        ClientAuthMode::Require => "TLS client certificate required (not verified)",
        ClientAuthMode::VerifyIfGiven => "TLS client certificate verified if given",
        ClientAuthMode::RequireAndVerify => "TLS client certificate required and verified",
        ClientAuthMode::Implicit => "TLS client certificate (mode chosen by Caddy)",
    }
}
