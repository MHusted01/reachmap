//! Turning the raw JSON into the model, noting every construct that is not
//! modeled as an [`Uncertainty`].

use std::collections::HashMap;

use super::error::{CaddyParseError, MAX_INPUT_BYTES};
use super::location::{JsonPath, bounded_name};
use super::matcher::{HostMatcher, PathMatcher, PatternProblem};
use super::raw::{RawApps, RawConfig, RawMatcherSet, RawRoute};
use super::substitution::Substitutions;
use super::{
    CaddyConfig, DEFAULT_HTTP_PORT, DEFAULT_HTTPS_PORT, MatcherSet, Route, RouteGroup, Uncertainty,
    UncertaintyKind,
};

mod handler;
mod server;

/// Deepest subroute nesting followed; deeper subroutes become uncertain.
pub const MAX_ROUTE_DEPTH: usize = 16;

/// Most uncertainties kept; more are only counted, so a hostile config
/// cannot make the result grow without bound.
pub const MAX_UNCERTAINTIES: usize = 512;

/// Shown in place of a name that contains a substituted value.
pub const REDACTED: &str = "[substituted]";

/// Apps that never accept connections of their own.
const PASSIVE_APPS: [&str; 3] = ["tls", "pki", "events"];

/// Parses Caddy's native JSON config (what `caddy adapt` prints) into the
/// secret-minimized model, with no known substitutions.
///
/// # Errors
///
/// See [`parse_caddy_config_with`].
pub fn parse_caddy_config(json: &str) -> Result<CaddyConfig, CaddyParseError> {
    parse_caddy_config_with(json, &Substitutions::none())
}

/// Parses Caddy's native JSON config into the secret-minimized model,
/// leaving out every modeled value that contains one of `substitutions`.
///
/// # Errors
///
/// Returns [`CaddyParseError`] when the input is too large, is not complete
/// JSON, or has a modeled field of the wrong type. Problems inside a single
/// handler or address become uncertainties instead.
pub fn parse_caddy_config_with(
    json: &str,
    substitutions: &Substitutions,
) -> Result<CaddyConfig, CaddyParseError> {
    if json.len() > MAX_INPUT_BYTES {
        return Err(CaddyParseError::InputTooLarge {
            limit_bytes: MAX_INPUT_BYTES,
        });
    }
    let raw: RawConfig = serde_json::from_str(json)?;
    Ok(Projector::new(substitutions).config(raw))
}

/// Collects uncertainties and route group numbers while walking the config.
struct Projector<'a> {
    substitutions: &'a Substitutions,
    uncertainties: Vec<Uncertainty>,
    omitted: usize,
    /// Group numbers of the current server, by full group name.
    groups: HashMap<String, usize>,
}

impl<'a> Projector<'a> {
    fn new(substitutions: &'a Substitutions) -> Self {
        Self {
            substitutions,
            uncertainties: Vec::new(),
            omitted: 0,
            groups: HashMap::new(),
        }
    }
}

impl Projector<'_> {
    /// Records that `construct` at `at` is not modeled.
    fn note(&mut self, kind: UncertaintyKind, construct: &str, at: &JsonPath) {
        if self.uncertainties.len() >= MAX_UNCERTAINTIES {
            self.omitted += 1;
            return;
        }
        self.uncertainties.push(Uncertainty {
            kind,
            construct: self.name(construct),
            location: at.into(),
        });
    }

    /// How many uncertainties were found so far, kept or omitted.
    fn found(&self) -> usize {
        self.uncertainties.len() + self.omitted
    }

    /// A name from the config made safe to show, or [`REDACTED`] when it
    /// contains a substituted value.
    fn name(&self, text: &str) -> String {
        if self.substitutions.taints(text) {
            REDACTED.to_owned()
        } else {
            bounded_name(text)
        }
    }

    /// `at["key"]`, with a key that contains a substituted value redacted.
    fn key(&self, at: &JsonPath, key: &str) -> JsonPath {
        if self.substitutions.taints(key) {
            at.key(REDACTED)
        } else {
            at.key(key)
        }
    }

    /// Whether `value` contains a substituted value; if so, notes that the
    /// `construct` at `at` was left out.
    fn substituted(&mut self, value: &str, construct: &str, at: &JsonPath) -> bool {
        let substituted = self.substitutions.taints(value);
        if substituted {
            self.note(UncertaintyKind::SubstitutedValue, construct, at);
        }
        substituted
    }

    /// The group of a route, numbered by its full name within the current
    /// server, so that names which differ only after the display bound stay
    /// apart.
    fn group(&mut self, name: &str) -> RouteGroup {
        let next = self.groups.len();
        let id = *self.groups.entry(name.to_owned()).or_insert(next);
        RouteGroup {
            id,
            label: self.name(name),
        }
    }

    fn config(mut self, raw: RawConfig) -> CaddyConfig {
        let apps_at = JsonPath::root("apps");
        let RawApps { http, other } = raw.apps.unwrap_or_default();
        for name in other
            .keys()
            .filter(|name| !PASSIVE_APPS.contains(&name.as_str()))
        {
            let at = self.key(&apps_at, name);
            self.note(UncertaintyKind::UnmodeledApp, name, &at);
        }
        let http = http.unwrap_or_default();
        let servers_at = apps_at.field("http").field("servers");
        let servers = http
            .servers
            .into_iter()
            .map(|(name, server)| {
                let at = self.key(&servers_at, &name);
                self.server(&name, server, &at)
            })
            .collect();
        CaddyConfig {
            http_port: http.http_port.unwrap_or(DEFAULT_HTTP_PORT),
            https_port: http.https_port.unwrap_or(DEFAULT_HTTPS_PORT),
            servers,
            uncertainties: self.uncertainties,
            uncertainties_omitted: self.omitted,
        }
    }

    fn routes(&mut self, raw: Vec<RawRoute>, at: &JsonPath, depth: usize) -> Vec<Route> {
        raw.into_iter()
            .enumerate()
            .map(|(index, route)| self.route(route, &at.index(index), depth))
            .collect()
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
            let matcher_at = self.key(at, name);
            self.note(UncertaintyKind::UnmodeledMatcher, name, &matcher_at);
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
                let at = at.index(index);
                if self.substituted(pattern, construct, &at) {
                    return None;
                }
                parse(pattern)
                    .map_err(|problem| self.note(problem.kind(), construct, &at))
                    .ok()
            })
            .collect()
    }
}
