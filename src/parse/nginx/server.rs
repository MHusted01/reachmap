//! Projection for Nginx `server {}` and `location {}` blocks.

use std::collections::BTreeSet;

use crate::nginx::{AuthSignals, LocationRoute, ServerBlock, UncertaintyKind};
use crate::sanitize::sanitize;

use super::directives::{LocationHeader, ScopeKind, apply_shared_directive, parse_location_header};
use super::listen::{parse_listen, parse_server_names, push_uncertainty};
use super::parser::Directive;
use super::project::Projector;
use super::target::parse_proxy_pass;

impl<'a> Projector<'a> {
    pub(super) fn project_server(
        &mut self,
        directive: &'a Directive<'a>,
        source_file: Option<&'a str>,
        inherited_auth: AuthSignals,
    ) {
        let Some(block) = &directive.block else {
            push_uncertainty(
                &mut self.config.uncertainties,
                UncertaintyKind::InvalidDirective,
                "server",
                source_file,
                directive.line,
            );
            return;
        };

        let mut server = ServerBlock {
            source_file: source_file.map(sanitize),
            auth: inherited_auth,
            ..ServerBlock::default()
        };
        let mut pending_locations = Vec::new();
        let mut visited = BTreeSet::new();
        self.collect_server_items(
            block,
            source_file,
            &mut server,
            &mut pending_locations,
            &mut visited,
        );

        if server.listens.is_empty() {
            push_uncertainty(
                &mut self.config.uncertainties,
                UncertaintyKind::ImplicitListen,
                "server",
                source_file,
                directive.line,
            );
        }
        for (loc_dir, loc_file) in pending_locations {
            self.project_location(loc_dir, loc_file, &mut server);
        }
        self.config.servers.push(server);
    }

    fn collect_server_items(
        &mut self,
        block: &'a [Directive<'a>],
        source_file: Option<&'a str>,
        server: &mut ServerBlock,
        pending_locations: &mut Vec<(&'a Directive<'a>, Option<&'a str>)>,
        visited: &mut BTreeSet<usize>,
    ) {
        for directive in block {
            match directive.name.as_ref() {
                "listen" => {
                    if let Some(listen) = parse_listen(
                        &directive.args,
                        source_file,
                        directive.line,
                        &mut self.config.uncertainties,
                    ) {
                        server.listens.push(listen);
                    }
                }
                "server_name" => server.server_names.extend(parse_server_names(
                    &directive.args,
                    source_file,
                    directive.line,
                    &mut self.config.uncertainties,
                )),
                "location" => pending_locations.push((directive, source_file)),
                "include" => {
                    for included in self.resolve_include(
                        &directive.args,
                        source_file,
                        directive.line,
                        visited,
                        true,
                    ) {
                        self.consumed[included] = true;
                        let inc_file = &self.files[included];
                        self.collect_server_items(
                            &inc_file.directives,
                            inc_file.source_file,
                            server,
                            pending_locations,
                            visited,
                        );
                    }
                }
                _ => apply_shared_directive(
                    directive,
                    source_file,
                    &mut server.auth,
                    ScopeKind::Server,
                    &mut self.config.uncertainties,
                ),
            }
        }
    }

    fn project_location(
        &mut self,
        directive: &'a Directive<'a>,
        source_file: Option<&'a str>,
        server: &mut ServerBlock,
    ) {
        let Some(block) = &directive.block else {
            push_uncertainty(
                &mut self.config.uncertainties,
                UncertaintyKind::InvalidDirective,
                "location",
                source_file,
                directive.line,
            );
            return;
        };

        let (modifier, path) = match parse_location_header(&directive.args) {
            LocationHeader::Parsed(modifier, path) => (modifier, path),
            LocationHeader::Regex => {
                push_uncertainty(
                    &mut self.config.uncertainties,
                    UncertaintyKind::RegexMatch,
                    "location",
                    source_file,
                    directive.line,
                );
                return;
            }
            LocationHeader::Named => {
                push_uncertainty(
                    &mut self.config.uncertainties,
                    UncertaintyKind::UnsupportedLocation,
                    "location",
                    source_file,
                    directive.line,
                );
                return;
            }
            LocationHeader::Invalid => {
                push_uncertainty(
                    &mut self.config.uncertainties,
                    UncertaintyKind::InvalidDirective,
                    "location",
                    source_file,
                    directive.line,
                );
                return;
            }
        };

        let mut route = LocationRoute {
            source_file: source_file.map(sanitize),
            modifier,
            path,
            target: None,
            auth: server.auth,
        };
        let mut visited = BTreeSet::new();
        self.collect_location_items(block, source_file, &mut route, &mut visited);
        server.locations.push(route);
    }

    fn collect_location_items(
        &mut self,
        block: &'a [Directive<'a>],
        source_file: Option<&'a str>,
        route: &mut LocationRoute,
        visited: &mut BTreeSet<usize>,
    ) {
        for directive in block {
            match directive.name.as_ref() {
                "proxy_pass" => {
                    if route.target.is_some() {
                        push_uncertainty(
                            &mut self.config.uncertainties,
                            UncertaintyKind::AmbiguousDirective,
                            "proxy_pass",
                            source_file,
                            directive.line,
                        );
                    } else {
                        route.target = Some(parse_proxy_pass(
                            &directive.args,
                            &self.upstreams,
                            source_file,
                            directive.line,
                            &mut self.config.uncertainties,
                        ));
                    }
                }
                "location" => push_uncertainty(
                    &mut self.config.uncertainties,
                    UncertaintyKind::NestedLocation,
                    "location",
                    source_file,
                    directive.line,
                ),
                "include" => {
                    for included in self.resolve_include(
                        &directive.args,
                        source_file,
                        directive.line,
                        visited,
                        true,
                    ) {
                        self.consumed[included] = true;
                        let inc_file = &self.files[included];
                        self.collect_location_items(
                            &inc_file.directives,
                            inc_file.source_file,
                            route,
                            visited,
                        );
                    }
                }
                _ => apply_shared_directive(
                    directive,
                    source_file,
                    &mut route.auth,
                    ScopeKind::Location,
                    &mut self.config.uncertainties,
                ),
            }
        }
    }
}
