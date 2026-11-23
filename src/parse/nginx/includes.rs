//! Pure helpers for reading Nginx configuration files from disk without
//! running Nginx: the `include` patterns of one file, and the main
//! configuration path from `nginx -V` build information.

use std::borrow::Cow;
use std::collections::BTreeSet;

use super::directives::resolve_relative_pattern;
use super::glob::glob_match;
use super::listen::push_uncertainty;
use super::parser::Directive;
use super::project::{MAX_INCLUDE_PROJECTIONS, Projector};
use super::{NginxParseError, lexer, parser};
use crate::nginx::UncertaintyKind;

/// Nginx's compiled-in prefix when `configure` was run without `--prefix`.
const DEFAULT_PREFIX: &str = "/usr/local/nginx";

/// The main configuration file relative to the prefix when `configure` was
/// run without `--conf-path`.
const DEFAULT_CONF_PATH: &str = "conf/nginx.conf";

/// Returns the static `include` patterns of one configuration file, in the
/// order they appear and at any block depth.
///
/// Includes with a variable or the wrong number of arguments are skipped: the
/// route parser reports them as uncertainties.
///
/// # Errors
///
/// Returns [`NginxParseError`] when the file cannot be lexed or parsed within
/// the parser's bounds.
pub fn include_patterns(file: &str) -> Result<Vec<String>, NginxParseError> {
    let tokens = lexer::tokenize(file)?;
    let files = parser::parse(&tokens)?;
    let mut patterns = Vec::new();
    for file in &files {
        collect_includes(&file.directives, &mut patterns);
    }
    Ok(patterns)
}

fn collect_includes(directives: &[Directive<'_>], patterns: &mut Vec<String>) {
    for directive in directives {
        if directive.name == "include"
            && let [pattern] = directive.args.as_slice()
            && !pattern.contains('$')
        {
            patterns.push(pattern.to_string());
        }
        if let Some(block) = &directive.block {
            collect_includes(block, patterns);
        }
    }
}

/// Returns the absolute path of the main configuration file that `nginx`
/// loads without `-c`, from the `configure arguments:` line of `nginx -V`.
///
/// A relative `--conf-path` is relative to `--prefix`, as in Nginx. Returns
/// `None` when the result is not an absolute path, or when a value is quoted
/// (it may contain spaces that the printed arguments no longer delimit).
pub fn conf_path_from_build_info(build_info: &str) -> Option<String> {
    let arguments = build_info
        .lines()
        .find_map(|line| line.trim().strip_prefix("configure arguments:"))
        .unwrap_or_default();
    let value = |flag: &str| {
        arguments
            .split_whitespace()
            .filter_map(|argument| argument.strip_prefix(flag))
            .next_back()
    };
    let prefix = value("--prefix=").unwrap_or(DEFAULT_PREFIX);
    let conf = value("--conf-path=").unwrap_or(DEFAULT_CONF_PATH);
    // An explicit empty `--prefix=` makes Nginx resolve a relative path from
    // its startup directory, which reachmap cannot know.
    let quoted = [prefix, conf]
        .iter()
        .any(|value| value.starts_with(['\'', '"']));
    if quoted || (prefix.is_empty() && !conf.starts_with('/')) {
        return None;
    }
    let path = if conf.starts_with('/') {
        conf.to_owned()
    } else {
        format!("{}/{conf}", prefix.trim_end_matches('/'))
    };
    path.starts_with('/').then_some(path)
}

/// Whether an `include` pattern, or one component of it, is expanded by
/// Nginx's `glob()`: it contains `*`, `?` or `[`, as Nginx checks.
pub fn is_glob_component(component: &str) -> bool {
    component.contains(['*', '?', '['])
}

/// Whether `path` is named by the `include` pattern `pattern`, both absolute.
/// Matching is per path component, as in `glob()`, so `*` never crosses `/`.
pub fn include_path_matches(pattern: &str, path: &str) -> bool {
    let mut pattern = pattern.split('/');
    let mut path = path.split('/');
    loop {
        match (pattern.next(), path.next()) {
            (None, None) => return true,
            (Some(want), Some(have)) if is_glob_component(want) => {
                if !matches_glob_component(want, have) {
                    return false;
                }
            }
            (Some(want), Some(have)) if want == have => {}
            _ => return false,
        }
    }
}

/// Whether a directory entry matches one glob component. Like `glob()`, a
/// leading `.` must be matched explicitly.
pub fn matches_glob_component(component: &str, name: &str) -> bool {
    (!name.starts_with('.') || component.starts_with('.')) && glob_match(component, name)
}

impl<'a> Projector<'a> {
    /// Returns the files an `include` directive names that are not already on
    /// the current include chain (`visited`). A missing literal include, or a
    /// match that would close a cycle, is reported as unresolved when
    /// `report_missing_literal` is set.
    pub(super) fn resolve_include(
        &mut self,
        args: &[Cow<'_, str>],
        source_file: Option<&'a str>,
        line: usize,
        visited: &mut BTreeSet<usize>,
        report_missing_literal: bool,
    ) -> Vec<usize> {
        if self.include_projections > MAX_INCLUDE_PROJECTIONS {
            return Vec::new();
        }
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
        let full_pattern = resolve_relative_pattern(main_file, pattern);
        let full_pattern = full_pattern.as_deref().unwrap_or(pattern);
        let is_glob = is_glob_component(pattern);
        let mut matched = Vec::new();
        let mut cycle = false;

        for (index, file) in self.files.iter().enumerate() {
            let Some(candidate) = file.source_file else {
                continue;
            };
            if !include_path_matches(full_pattern, candidate) {
                continue;
            }
            // `visited` holds the files on the current include chain: matching
            // one of them again is a cycle, which Nginx rejects.
            if visited.contains(&index) {
                cycle = true;
            } else {
                matched.push(index);
            }
        }

        // `glob()` returns matches sorted; the dump lists files in the order
        // they were first included, which can differ.
        if is_glob {
            matched.sort_unstable_by_key(|&index| self.files[index].source_file);
        }
        self.include_projections += matched.len();
        if self.include_projections > MAX_INCLUDE_PROJECTIONS {
            return Vec::new();
        }

        if report_missing_literal && (cycle || (matched.is_empty() && !is_glob)) {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_static_includes_at_every_depth_in_order() {
        let file = "
            include modules-enabled/*.conf;
            http {
                include mime.types;
                server {
                    location / { include \"snippets/proxy params.conf\"; }
                }
                include $dynamic.conf;
                include a.conf b.conf;
            }
        ";
        assert_eq!(
            include_patterns(file).unwrap(),
            [
                "modules-enabled/*.conf",
                "mime.types",
                "snippets/proxy params.conf"
            ]
        );
    }

    #[test]
    fn include_discovery_reports_parse_errors() {
        assert!(matches!(
            include_patterns("http { include a.conf;"),
            Err(NginxParseError::UnclosedBlock { .. })
        ));
        assert_eq!(include_patterns("").unwrap(), Vec::<String>::new());
    }

    #[test]
    fn reads_conf_path_from_build_info() {
        let debian = "nginx version: nginx/1.26.3\nbuilt with OpenSSL 3.0.15\n\
            configure arguments: --with-cc-opt='-g -O2' --prefix=/usr/share/nginx \
            --conf-path=/etc/nginx/nginx.conf --http-log-path=/var/log/nginx/access.log\n";
        assert_eq!(
            conf_path_from_build_info(debian).as_deref(),
            Some("/etc/nginx/nginx.conf")
        );
    }

    #[test]
    fn relative_and_missing_conf_paths_use_the_prefix() {
        let relative = "configure arguments: --prefix=/opt/nginx/ --conf-path=etc/main.conf";
        assert_eq!(
            conf_path_from_build_info(relative).as_deref(),
            Some("/opt/nginx/etc/main.conf")
        );
        let prefix_only = "configure arguments: --prefix=/opt/nginx";
        assert_eq!(
            conf_path_from_build_info(prefix_only).as_deref(),
            Some("/opt/nginx/conf/nginx.conf")
        );
        assert_eq!(
            conf_path_from_build_info("nginx version: nginx/1.27.0\n").as_deref(),
            Some("/usr/local/nginx/conf/nginx.conf")
        );
    }

    #[test]
    fn non_absolute_conf_paths_are_rejected() {
        let relative_prefix = "configure arguments: --prefix=nginx --conf-path=nginx.conf";
        assert_eq!(conf_path_from_build_info(relative_prefix), None);
        let quoted = "configure arguments: --conf-path='/etc/my nginx/nginx.conf'";
        assert_eq!(conf_path_from_build_info(quoted), None);
        let empty_prefix = "configure arguments: --prefix= --conf-path=conf/nginx.conf";
        assert_eq!(conf_path_from_build_info(empty_prefix), None);
        let empty_prefix_absolute =
            "configure arguments: --prefix= --conf-path=/etc/nginx/nginx.conf";
        assert_eq!(
            conf_path_from_build_info(empty_prefix_absolute).as_deref(),
            Some("/etc/nginx/nginx.conf")
        );
    }

    #[test]
    fn include_paths_match_per_component() {
        let matches = include_path_matches;
        assert!(matches(
            "/etc/nginx/snippets/*.conf",
            "/etc/nginx/snippets/a.conf"
        ));
        assert!(!matches(
            "/etc/nginx/snippets/[a-z]*.conf",
            "/etc/nginx/snippets/nested/backend.conf"
        ));
        assert!(matches("/srv/*/site.conf", "/srv/alpha/site.conf"));
        assert!(!matches("/srv/*/site.conf", "/srv/site.conf"));
        assert!(!matches("/etc/nginx/*", "/etc/nginx/.hidden"));
        assert!(matches("/etc/nginx/a.conf", "/etc/nginx/a.conf"));
    }

    #[test]
    fn glob_components_follow_nginx_glob_rules() {
        assert!(is_glob_component("*.conf"));
        assert!(is_glob_component("site?"));
        assert!(is_glob_component("site[12].conf"));
        assert!(!is_glob_component("default"));

        assert!(matches_glob_component("*.conf", "app.conf"));
        assert!(!matches_glob_component("*.conf", "app.conf.bak"));
        assert!(!matches_glob_component("*", ".app.conf.swp"));
        assert!(matches_glob_component(".*", ".hidden"));
        assert!(matches_glob_component("site?", "site1"));
        assert!(matches_glob_component("site[12]*.conf", "site1-prod.conf"));
        assert!(!matches_glob_component("site[12]*.conf", "site3.conf"));
        assert!(matches_glob_component("[!.]*", "app"));
        assert!(matches_glob_component("[a-c]x", "bx"));
        assert!(!matches_glob_component("[a-c]x", "dx"));
        assert!(matches_glob_component("[^a-c]x", "dx"));
        assert!(matches_glob_component("[]]x", "]x"));
        assert!(
            matches_glob_component("[x", "[x"),
            "an unclosed `[` is literal"
        );
        assert!(matches_glob_component("site[[:digit:]].conf", "site1.conf"));
        assert!(!matches_glob_component(
            "site[[:digit:]].conf",
            "siteA.conf"
        ));
        assert!(matches_glob_component("[[:alpha:]_]*", "_x"));
        assert!(matches_glob_component("[![:space:]]", "a"));
        assert!(!matches_glob_component("[[:bogus:]]", "b"));
        assert!(matches_glob_component("[[.a.]]", "a"));
    }
}
