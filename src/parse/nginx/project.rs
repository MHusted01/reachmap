//! Secret-minimizing projection from temporary Nginx AST into [`NginxConfig`].

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};

use crate::nginx::{AuthSignals, NginxConfig, UncertaintyKind, UpstreamGroup};
use crate::sanitize::sanitize;

use super::directives::{
    ScopeAclState, ScopeKind, apply_shared_directive, glob_match, is_benign_top_level,
    is_benign_upstream_directive, is_secret_bearing, record_common_uncertainty,
    resolve_relative_pattern,
};
use super::listen::push_uncertainty;
use super::parser::{Directive, FileAst};
use super::target::parse_upstream_server;

pub(super) fn project(files: &[FileAst<'_>]) -> NginxConfig {
    let mut projector = Projector::new(files);
    projector.run();
    projector.config
}

pub(super) struct Projector<'a> {
    pub(super) files: &'a [FileAst<'a>],
    pub(super) consumed: Vec<bool>,
    pub(super) upstreams: BTreeMap<String, UpstreamGroup>,
    pub(super) config: NginxConfig,
}

impl<'a> Projector<'a> {
    fn new(files: &'a [FileAst<'a>]) -> Self {
        Self {
            files,
            consumed: vec![false; files.len()],
            upstreams: BTreeMap::new(),
            config: NginxConfig::default(),
        }
    }

    fn run(&mut self) {
        let mut saw_stream = false;
        let mut http_roots = Vec::new();

        for (index, file) in self.files.iter().enumerate() {
            for directive in &file.directives {
                if directive.name == "stream" {
                    saw_stream = true;
                } else if directive.name == "http" {
                    http_roots.push((index, directive));
                }
            }
        }

        for (index, http_dir) in http_roots {
            self.consumed[index] = true;
            if let Some(block) = &http_dir.block {
                let mut visited = BTreeSet::from([index]);
                self.collect_http_upstreams(block, self.files[index].source_file, &mut visited);

                let mut visited = BTreeSet::from([index]);
                let mut http_auth = AuthSignals::default();
                let mut http_acl = ScopeAclState::default();
                self.project_http_directives(
                    block,
                    self.files[index].source_file,
                    &mut http_auth,
                    &mut http_acl,
                    &mut visited,
                );
            } else {
                push_uncertainty(
                    &mut self.config.uncertainties,
                    UncertaintyKind::InvalidDirective,
                    "http",
                    self.files[index].source_file,
                    http_dir.line,
                );
            }
            for directive in &self.files[index].directives {
                if directive.name != "http" {
                    self.project_top_level_directive(
                        directive,
                        self.files[index].source_file,
                        index,
                        saw_stream,
                    );
                }
            }
        }

        for index in 0..self.files.len() {
            if !self.consumed[index] {
                self.consumed[index] = true;
                self.project_top_level_file(&self.files[index], index, saw_stream);
            }
        }

        self.config.upstreams = self.upstreams.values().cloned().collect();
    }

    fn project_top_level_file(
        &mut self,
        file: &'a FileAst<'a>,
        file_index: usize,
        saw_stream: bool,
    ) {
        let has_http_children = file
            .directives
            .iter()
            .any(|d| matches!(d.name.as_ref(), "server" | "upstream"));
        if has_http_children && !saw_stream {
            let mut visited = BTreeSet::from([file_index]);
            self.collect_http_upstreams(&file.directives, file.source_file, &mut visited);
            let mut visited = BTreeSet::from([file_index]);
            let mut auth = AuthSignals::default();
            let mut acl = ScopeAclState::default();
            self.project_http_directives(
                &file.directives,
                file.source_file,
                &mut auth,
                &mut acl,
                &mut visited,
            );
            return;
        }

        for directive in &file.directives {
            self.project_top_level_directive(directive, file.source_file, file_index, saw_stream);
        }
    }

    fn project_top_level_directive(
        &mut self,
        directive: &'a Directive<'a>,
        source_file: Option<&'a str>,
        file_index: usize,
        saw_stream: bool,
    ) {
        let name = directive.name.as_ref();
        match name {
            "stream" | "mail" => push_uncertainty(
                &mut self.config.uncertainties,
                UncertaintyKind::UnsupportedContext,
                name,
                source_file,
                directive.line,
            ),
            "server" | "upstream" if saw_stream => push_uncertainty(
                &mut self.config.uncertainties,
                UncertaintyKind::UnsupportedContext,
                "stream",
                source_file,
                directive.line,
            ),
            "include" => {
                let mut visited = BTreeSet::from([file_index]);
                for included in self.resolve_include(
                    &directive.args,
                    source_file,
                    directive.line,
                    &mut visited,
                    true,
                ) {
                    self.consumed[included] = true;
                    self.project_top_level_file(&self.files[included], included, saw_stream);
                }
            }
            _ if is_benign_top_level(name) || is_secret_bearing(name) => {}
            _ => record_common_uncertainty(
                name,
                source_file,
                directive.line,
                &mut self.config.uncertainties,
            ),
        }
    }

    fn collect_http_upstreams(
        &mut self,
        directives: &'a [Directive<'a>],
        source_file: Option<&'a str>,
        visited: &mut BTreeSet<usize>,
    ) {
        for directive in directives {
            match directive.name.as_ref() {
                "upstream" => self.collect_upstream(directive, source_file),
                "include" => {
                    for included in self.resolve_include(
                        &directive.args,
                        source_file,
                        directive.line,
                        visited,
                        false,
                    ) {
                        self.consumed[included] = true;
                        let inc_file = &self.files[included];
                        self.collect_http_upstreams(
                            &inc_file.directives,
                            inc_file.source_file,
                            visited,
                        );
                    }
                }
                _ => {}
            }
        }
    }

    fn collect_upstream(&mut self, directive: &'a Directive<'a>, source_file: Option<&'a str>) {
        let (Some(name_word), Some(block)) = (directive.args.first(), &directive.block) else {
            push_uncertainty(
                &mut self.config.uncertainties,
                UncertaintyKind::InvalidDirective,
                "upstream",
                source_file,
                directive.line,
            );
            return;
        };
        if directive.args.len() != 1 {
            push_uncertainty(
                &mut self.config.uncertainties,
                UncertaintyKind::InvalidDirective,
                "upstream",
                source_file,
                directive.line,
            );
            return;
        }
        let name = sanitize(name_word.as_ref());
        let mut servers = Vec::new();
        let mut complete = true;

        for inner in block {
            let inner_name = inner.name.as_ref();
            match inner_name {
                "server" => {
                    if let Some(server) = parse_upstream_server(
                        &inner.args,
                        source_file,
                        inner.line,
                        &mut self.config.uncertainties,
                    ) {
                        servers.push(server);
                    } else {
                        complete = false;
                    }
                }
                opt if is_benign_upstream_directive(opt) => {}
                _ => {
                    complete = false;
                    record_common_uncertainty(
                        inner_name,
                        source_file,
                        inner.line,
                        &mut self.config.uncertainties,
                    );
                }
            }
        }

        if let Some(existing) = self.upstreams.get_mut(&name) {
            existing.complete = false;
            push_uncertainty(
                &mut self.config.uncertainties,
                UncertaintyKind::AmbiguousDirective,
                "upstream",
                source_file,
                directive.line,
            );
            return;
        }

        self.upstreams.insert(
            name.clone(),
            UpstreamGroup {
                source_file: source_file.map(sanitize),
                name,
                servers,
                complete,
            },
        );
    }

    fn project_http_directives(
        &mut self,
        directives: &'a [Directive<'a>],
        source_file: Option<&'a str>,
        http_auth: &mut AuthSignals,
        http_acl: &mut ScopeAclState,
        visited: &mut BTreeSet<usize>,
    ) {
        let mut server_directives = Vec::new();
        for directive in directives {
            match directive.name.as_ref() {
                "upstream" => {}
                "server" => server_directives.push(directive),
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
                        self.project_http_directives(
                            &inc_file.directives,
                            inc_file.source_file,
                            http_auth,
                            http_acl,
                            visited,
                        );
                    }
                }
                _ => apply_shared_directive(
                    directive,
                    source_file,
                    http_auth,
                    http_acl,
                    ScopeKind::Http,
                    &mut self.config.uncertainties,
                ),
            }
        }

        for directive in server_directives {
            self.project_server(directive, source_file, *http_auth);
        }
    }

    pub(super) fn resolve_include(
        &mut self,
        args: &[Cow<'_, str>],
        source_file: Option<&'a str>,
        line: usize,
        visited: &mut BTreeSet<usize>,
        report_missing_literal: bool,
    ) -> Vec<usize> {
        let Some(pattern) = args.first().filter(|_| args.len() == 1) else {
            push_uncertainty(
                &mut self.config.uncertainties,
                UncertaintyKind::InvalidDirective,
                "include",
                source_file,
                line,
            );
            return Vec::new();
        };
        let pattern = pattern.as_ref();
        if pattern.contains('$') {
            push_uncertainty(
                &mut self.config.uncertainties,
                UncertaintyKind::DynamicInclude,
                "include",
                source_file,
                line,
            );
            return Vec::new();
        }

        // Nginx resolves relative includes against the configuration prefix,
        // the directory of the main file, which comes first in the dump.
        let main_file = self.files.first().and_then(|file| file.source_file);
        let resolved_pattern = resolve_relative_pattern(main_file, pattern);
        let is_glob = pattern.contains('*') || pattern.contains('?');
        let mut matched = Vec::new();

        for (index, file) in self.files.iter().enumerate() {
            let Some(candidate) = file.source_file else {
                continue;
            };
            let matches_pattern = glob_match(pattern, candidate)
                || resolved_pattern
                    .as_deref()
                    .is_some_and(|rel| glob_match(rel, candidate));
            if matches_pattern && visited.insert(index) {
                matched.push(index);
            }
        }

        if matched.is_empty() && !is_glob && report_missing_literal {
            push_uncertainty(
                &mut self.config.uncertainties,
                UncertaintyKind::UnresolvedInclude,
                "include",
                source_file,
                line,
            );
        }
        matched
    }
}
