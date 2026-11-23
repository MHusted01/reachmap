//! Pure helpers for reading Nginx configuration files from disk without
//! running Nginx: the `include` patterns of one file, and the main
//! configuration path from `nginx -V` build information.

use super::directives::glob_match;
use super::parser::Directive;
use super::{NginxParseError, lexer, parser};

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
    if [prefix, conf]
        .iter()
        .any(|value| value.starts_with(['\'', '"']))
    {
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

/// Whether a directory entry matches one glob component. Like `glob()`, a
/// leading `.` must be matched explicitly.
pub fn matches_glob_component(component: &str, name: &str) -> bool {
    (!name.starts_with('.') || component.starts_with('.')) && glob_match(component, name)
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
    }
}
