//! Secret-minimizing projection from temporary Nginx AST into [`NginxConfig`].

use std::collections::{BTreeMap, BTreeSet};

use crate::nginx::{AuthSignals, NginxConfig, UncertaintyKind, UpstreamGroup};
use crate::sanitize::sanitize;

use super::NginxParseError;
use super::directives::{
    ScopeAclState, ScopeKind, apply_shared_directive, is_benign_top_level,
    is_benign_upstream_directive, is_secret_bearing, record_common_uncertainty,
};
use super::listen::push_uncertainty;
use super::parser::{Directive, FileAst};
use super::target::parse_upstream_server;

/// Most included files projected in one parse. Each `include` is projected
/// where it appears, so a file that includes the next one twice, thirty files
/// deep, would otherwise mean over a billion projections.
pub(super) const MAX_INCLUDE_PROJECTIONS: usize = 100_000;

pub(super) fn project(files: &[FileAst<'_>]) -> Result<NginxConfig, NginxParseError> {
    let mut projector = Projector::new(files);
    projector.run();
    if projector.include_projections > MAX_INCLUDE_PROJECTIONS {
        return Err(NginxParseError::TooManyIncludeProjections {
            limit: MAX_INCLUDE_PROJECTIONS,
        });
    }
    Ok(projector.config)
}

pub(super) struct Projector<'a> {
    pub(super) files: &'a [FileAst<'a>],
    pub(super) consumed: Vec<bool>,
    pub(super) upstreams: BTreeMap<String, UpstreamGroup>,
    pub(super) config: NginxConfig,
    /// Included files projected so far; past [`MAX_INCLUDE_PROJECTIONS`] no
    /// further include is followed and the parse fails.
    pub(super) include_projections: usize,
}

impl<'a> Projector<'a> {
    fn new(files: &'a [FileAst<'a>]) -> Self {
        Self {
            files,
            consumed: vec![false; files.len()],
            upstreams: BTreeMap::new(),
            config: NginxConfig::default(),
            include_projections: 0,
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
            let mut visited = BTreeSet::from([index]);
            for directive in &self.files[index].directives {
                if directive.name != "http" {
                    self.project_top_level_directive(
                        directive,
                        self.files[index].source_file,
                        saw_stream,
                        &mut visited,
                    );
                }
            }
        }

        for index in 0..self.files.len() {
            if !self.consumed[index] {
                self.consumed[index] = true;
                let mut visited = BTreeSet::from([index]);
                self.project_top_level_file(&self.files[index], saw_stream, &mut visited);
            }
        }

        self.config.upstreams = self.upstreams.values().cloned().collect();
    }

    /// Projects a file outside `http`. `visited` holds the files already on
    /// this include chain, so an include cycle ends instead of recursing.
    fn project_top_level_file(
        &mut self,
        file: &'a FileAst<'a>,
        saw_stream: bool,
        visited: &mut BTreeSet<usize>,
    ) {
        let has_http_children = file
            .directives
            .iter()
            .any(|d| matches!(d.name.as_ref(), "server" | "upstream"));
        if has_http_children && !saw_stream {
            let mut upstream_visited = visited.clone();
            self.collect_http_upstreams(&file.directives, file.source_file, &mut upstream_visited);
            let mut visited = visited.clone();
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
            self.project_top_level_directive(directive, file.source_file, saw_stream, visited);
        }
    }

    fn project_top_level_directive(
        &mut self,
        directive: &'a Directive<'a>,
        source_file: Option<&'a str>,
        saw_stream: bool,
        visited: &mut BTreeSet<usize>,
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
                for included in self.resolve_include(
                    &directive.args,
                    source_file,
                    directive.line,
                    visited,
                    true,
                ) {
                    self.consumed[included] = true;
                    visited.insert(included);
                    self.project_top_level_file(&self.files[included], saw_stream, visited);
                    visited.remove(&included);
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
                        visited.insert(included);
                        self.collect_http_upstreams(
                            &inc_file.directives,
                            inc_file.source_file,
                            visited,
                        );
                        visited.remove(&included);
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
                        visited.insert(included);
                        self.project_http_directives(
                            &inc_file.directives,
                            inc_file.source_file,
                            http_auth,
                            http_acl,
                            visited,
                        );
                        visited.remove(&included);
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
}
