//! Turning the raw JSON into the model, noting every construct that is not
//! modeled as an [`Uncertainty`].

use std::collections::HashMap;

use super::error::{CaddyParseError, MAX_INPUT_BYTES};
use super::listen::ListenAddress;
use super::location::{JsonPath, bounded_name};
use super::matcher::{HostMatcher, PathMatcher, PatternProblem};
use super::raw::{
    RawApps, RawAutomaticHttps, RawClientAuth, RawConfig, RawMatcherSet, RawRoute, RawServer,
    RawTlsPolicy,
};
use super::{
    AutomaticHttps, CaddyConfig, CaddyServer, ClientAuthMode, DEFAULT_HTTP_PORT,
    DEFAULT_HTTPS_PORT, MatcherSet, Route, RouteGroup, TlsPolicy, Uncertainty, UncertaintyKind,
};

mod handler;

/// Deepest subroute nesting followed; deeper subroutes become uncertain.
pub const MAX_ROUTE_DEPTH: usize = 16;

/// Most uncertainties kept; more are only counted, so a hostile config
/// cannot make the result grow without bound.
pub const MAX_UNCERTAINTIES: usize = 512;

/// The `listener_wrappers` entry that only marks where TLS is handled.
const TLS_WRAPPER: &str = "tls";

/// The `protocols` entry that turns on HTTP/3.
const HTTP3: &str = "h3";

/// Apps that never accept connections of their own.
const PASSIVE_APPS: [&str; 3] = ["tls", "pki", "events"];

/// Parses Caddy's native JSON config (what `caddy adapt` prints) into the
/// secret-minimized model.
///
/// # Errors
///
/// Returns [`CaddyParseError`] when the input is too large, is not complete
/// JSON, or has a modeled field of the wrong type. Problems inside a single
/// handler or address become uncertainties instead.
pub fn parse_caddy_config(json: &str) -> Result<CaddyConfig, CaddyParseError> {
    if json.len() > MAX_INPUT_BYTES {
        return Err(CaddyParseError::InputTooLarge {
            limit_bytes: MAX_INPUT_BYTES,
        });
    }
    let raw: RawConfig = serde_json::from_str(json)?;
    Ok(Projector::default().config(raw))
}

/// Collects uncertainties and route group numbers while walking the config.
#[derive(Default)]
struct Projector {
    uncertainties: Vec<Uncertainty>,
    omitted: usize,
    groups: HashMap<String, usize>,
}

impl Projector {
    /// Records that `construct` at `at` is not modeled.
    fn note(&mut self, kind: UncertaintyKind, construct: &str, at: &JsonPath) {
        if self.uncertainties.len() >= MAX_UNCERTAINTIES {
            self.omitted += 1;
            return;
        }
        self.uncertainties.push(Uncertainty {
            kind,
            construct: bounded_name(construct),
            location: at.into(),
        });
    }

    /// How many uncertainties were found so far, kept or omitted.
    fn found(&self) -> usize {
        self.uncertainties.len() + self.omitted
    }

    /// The group of a route, numbered by its full name within the current
    /// route list, so that names which differ only after the display bound
    /// stay apart.
    fn group(&mut self, name: &str) -> RouteGroup {
        let next = self.groups.len();
        let id = *self.groups.entry(name.to_owned()).or_insert(next);
        RouteGroup {
            id,
            label: bounded_name(name),
        }
    }

    fn config(mut self, raw: RawConfig) -> CaddyConfig {
        let apps_at = JsonPath::root("apps");
        let RawApps { http, other } = raw.apps.unwrap_or_default();
        for name in other
            .keys()
            .filter(|name| !PASSIVE_APPS.contains(&name.as_str()))
        {
            self.note(UncertaintyKind::UnmodeledApp, name, &apps_at.key(name));
        }
        let http = http.unwrap_or_default();
        let servers_at = apps_at.field("http").field("servers");
        let servers = http
            .servers
            .into_iter()
            .map(|(name, server)| self.server(&name, server, &servers_at.key(&name)))
            .collect();
        CaddyConfig {
            http_port: http.http_port.unwrap_or(DEFAULT_HTTP_PORT),
            https_port: http.https_port.unwrap_or(DEFAULT_HTTPS_PORT),
            servers,
            uncertainties: self.uncertainties,
            uncertainties_omitted: self.omitted,
        }
    }

    fn server(&mut self, name: &str, raw: RawServer, at: &JsonPath) -> CaddyServer {
        let listen = self.listen(raw.listen.as_deref(), &at.field("listen"));
        self.server_features(&raw, at);
        let policies_at = at.field("tls_connection_policies");
        let tls_policies = raw
            .tls_connection_policies
            .into_iter()
            .enumerate()
            .map(|(index, policy)| self.tls_policy(policy, &policies_at.index(index)))
            .collect();
        CaddyServer {
            name: bounded_name(name),
            listen,
            automatic_https: raw
                .automatic_https
                .as_ref()
                .map(automatic_https)
                .unwrap_or_default(),
            http3: raw
                .protocols
                .as_ref()
                .is_none_or(|protocols| protocols.iter().any(|protocol| protocol == HTTP3)),
            tls_policies,
            routes: self.routes(raw.routes, &at.field("routes"), 0),
        }
    }

    /// Notes server fields that can route requests or change how the
    /// listener accepts connections.
    fn server_features(&mut self, raw: &RawServer, at: &JsonPath) {
        let fields = [
            ("errors", raw.errors.is_some()),
            ("named_routes", raw.named_routes.is_some()),
        ];
        for (field, _) in fields.into_iter().filter(|(_, present)| *present) {
            self.note(
                UncertaintyKind::UnmodeledServerFeature,
                field,
                &at.field(field),
            );
        }
        let wrappers_at = at.field("listener_wrappers");
        for (index, _) in raw
            .listener_wrappers
            .iter()
            .enumerate()
            .filter(|(_, wrapper)| wrapper.wrapper.as_deref() != Some(TLS_WRAPPER))
        {
            let kind = UncertaintyKind::UnmodeledServerFeature;
            self.note(kind, "listener_wrappers", &wrappers_at.index(index));
        }
    }

    /// The statically understood addresses; a missing or empty `listen` is
    /// uncertain because Caddy then picks the ports itself.
    fn listen(&mut self, raw: Option<&[String]>, at: &JsonPath) -> Vec<ListenAddress> {
        let Some(addresses) = raw.filter(|addresses| !addresses.is_empty()) else {
            self.note(UncertaintyKind::ImplicitListen, "listen", at);
            return Vec::new();
        };
        addresses
            .iter()
            .enumerate()
            .filter_map(|(index, text)| {
                ListenAddress::parse(text)
                    .map_err(|problem| self.note(problem.kind(), "listen", &at.index(index)))
                    .ok()
            })
            .collect()
    }

    fn tls_policy(&mut self, raw: RawTlsPolicy, at: &JsonPath) -> TlsPolicy {
        let client_auth = raw
            .client_authentication
            .and_then(|auth| self.client_auth(&auth, &at.field("client_authentication")));
        TlsPolicy {
            scoped: raw.matcher.is_some(),
            client_auth,
        }
    }

    fn client_auth(&mut self, raw: &RawClientAuth, at: &JsonPath) -> Option<ClientAuthMode> {
        if !raw.verifiers.is_empty() {
            let field = "verifiers";
            self.note(
                UncertaintyKind::ClientCertificateVerifier,
                field,
                &at.field(field),
            );
        }
        match raw.mode.as_deref() {
            Some("request") => Some(ClientAuthMode::Request),
            Some("require") => Some(ClientAuthMode::Require),
            Some("verify_if_given") => Some(ClientAuthMode::VerifyIfGiven),
            Some("require_and_verify") => Some(ClientAuthMode::RequireAndVerify),
            None | Some("") => raw.has_trust().then_some(ClientAuthMode::Implicit),
            Some(_) => {
                self.note(
                    UncertaintyKind::UnknownClientAuthMode,
                    "mode",
                    &at.field("mode"),
                );
                None
            }
        }
    }

    /// One route list. Group numbers restart for each list, as Caddy only
    /// applies a group among the routes of one list.
    fn routes(&mut self, raw: Vec<RawRoute>, at: &JsonPath, depth: usize) -> Vec<Route> {
        let outer_groups = std::mem::take(&mut self.groups);
        let routes = raw
            .into_iter()
            .enumerate()
            .map(|(index, route)| self.route(route, &at.index(index), depth))
            .collect();
        self.groups = outer_groups;
        routes
    }

    fn route(&mut self, raw: RawRoute, at: &JsonPath, depth: usize) -> Route {
        let match_at = at.field("match");
        let matchers = raw
            .matchers
            .into_iter()
            .enumerate()
            .map(|(index, set)| self.matcher_set(set, &match_at.index(index)))
            .collect();
        let handle_at = at.field("handle");
        let handlers = raw
            .handle
            .into_iter()
            .enumerate()
            .map(|(index, handler)| self.handler(handler, &handle_at.index(index), depth))
            .collect();
        Route {
            group: raw.group.as_deref().map(|name| self.group(name)),
            matchers,
            handlers,
            terminal: raw.terminal,
        }
    }

    /// A matcher set is complete when this added no uncertainty.
    fn matcher_set(&mut self, raw: RawMatcherSet, at: &JsonPath) -> MatcherSet {
        let before = self.found();
        for name in raw.other.keys() {
            self.note(UncertaintyKind::UnmodeledMatcher, name, &at.key(name));
        }
        let hosts = raw
            .host
            .map(|hosts| self.patterns("host", &hosts, &at.field("host"), HostMatcher::parse));
        let paths = raw
            .path
            .map(|paths| self.patterns("path", &paths, &at.field("path"), PathMatcher::parse));
        MatcherSet {
            hosts,
            paths,
            complete: self.found() == before,
        }
    }

    fn patterns<T>(
        &mut self,
        construct: &str,
        patterns: &[String],
        at: &JsonPath,
        parse: impl Fn(&str) -> Result<T, PatternProblem>,
    ) -> Vec<T> {
        patterns
            .iter()
            .enumerate()
            .filter_map(|(index, pattern)| {
                parse(pattern)
                    .map_err(|problem| self.note(problem.kind(), construct, &at.index(index)))
                    .ok()
            })
            .collect()
    }
}

/// The `automatic_https` switches.
fn automatic_https(raw: &RawAutomaticHttps) -> AutomaticHttps {
    AutomaticHttps {
        disabled: raw.disable,
        redirects_disabled: raw.disable_redirects,
        hosts_skipped: raw.skip.is_some() || raw.skip_certificates.is_some(),
    }
}
