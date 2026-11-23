//! Modeled `host` and `path` matcher patterns.

use serde::{Deserialize, Serialize};

use super::UncertaintyKind;
use crate::sanitize::sanitize;

/// Longest `host` pattern kept, in characters.
const MAX_HOST_CHARS: usize = 255;

/// Longest `path` pattern kept, in characters.
const MAX_PATH_CHARS: usize = 2048;

/// One `host` matcher pattern. Caddy compares hosts case-insensitively, so
/// patterns are stored in lowercase.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum HostMatcher {
    /// An exact host, e.g. `app.example.test`.
    Exact {
        /// Lowercase host.
        host: String,
    },
    /// `*.suffix`: any single label in front of `suffix`.
    LeadingWildcard {
        /// Lowercase suffix after `*.`.
        suffix: String,
    },
}

impl HostMatcher {
    /// Parses one `host` pattern, or says why it is not modeled.
    pub(crate) fn parse(pattern: &str) -> Result<Self, PatternProblem> {
        if pattern.contains('{') {
            return Err(PatternProblem::Placeholder);
        }
        let valid = |text: &str| {
            !text.is_empty()
                && text.len() <= MAX_HOST_CHARS
                && text.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric()
                        || matches!(byte, b'-' | b'_' | b'.' | b':' | b'[' | b']')
                })
        };
        let pattern = pattern.to_ascii_lowercase();
        match pattern.strip_prefix("*.") {
            Some(suffix) if valid(suffix) => Ok(Self::LeadingWildcard {
                suffix: suffix.to_owned(),
            }),
            None if valid(&pattern) => Ok(Self::Exact { host: pattern }),
            _ => Err(PatternProblem::Unsupported),
        }
    }
}

/// One `path` matcher pattern. Caddy compares paths case-insensitively, so
/// patterns are stored in lowercase.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PathMatcher {
    /// A pattern without `*`, matching that path only.
    Exact {
        /// Lowercase path.
        path: String,
    },
    /// A pattern ending in its only `*`, e.g. `/api/*`.
    Prefix {
        /// Lowercase text before the `*`.
        prefix: String,
    },
}

impl PathMatcher {
    /// Parses one `path` pattern, or says why it is not modeled. Suffix and
    /// inner wildcards and `%` escape matching are not modeled.
    pub(crate) fn parse(pattern: &str) -> Result<Self, PatternProblem> {
        if pattern.contains('{') {
            return Err(PatternProblem::Placeholder);
        }
        if pattern.contains('%') || pattern.len() > MAX_PATH_CHARS || sanitize(pattern) != pattern {
            return Err(PatternProblem::Unsupported);
        }
        let pattern = pattern.to_lowercase();
        match pattern.split_once('*') {
            None => Ok(Self::Exact { path: pattern }),
            Some((prefix, "")) => Ok(Self::Prefix {
                prefix: prefix.to_owned(),
            }),
            Some(_) => Err(PatternProblem::Unsupported),
        }
    }
}

/// Why a `host` or `path` pattern is not modeled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PatternProblem {
    /// Contains a `{...}` placeholder.
    Placeholder,
    /// Uses a form beyond exact, prefix or leading wildcard.
    Unsupported,
}

impl PatternProblem {
    /// Uncertainty category of the problem.
    pub(crate) fn kind(self) -> UncertaintyKind {
        match self {
            Self::Placeholder => UncertaintyKind::Placeholder,
            Self::Unsupported => UncertaintyKind::UnsupportedPattern,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_exact_and_leading_wildcard_hosts() {
        assert_eq!(
            HostMatcher::parse("App.Example.Test"),
            Ok(HostMatcher::Exact {
                host: "app.example.test".into()
            })
        );
        assert_eq!(
            HostMatcher::parse("*.example.test"),
            Ok(HostMatcher::LeadingWildcard {
                suffix: "example.test".into()
            })
        );
        assert_eq!(
            HostMatcher::parse("[::1]"),
            Ok(HostMatcher::Exact {
                host: "[::1]".into()
            })
        );
    }

    #[test]
    fn rejects_other_host_forms() {
        let problem = |text| HostMatcher::parse(text).expect_err(text);
        assert_eq!(problem("{http.request.host}"), PatternProblem::Placeholder);
        assert_eq!(problem("app.*"), PatternProblem::Unsupported);
        assert_eq!(problem("*.*.example.test"), PatternProblem::Unsupported);
        assert_eq!(problem("*"), PatternProblem::Unsupported);
        assert_eq!(problem(""), PatternProblem::Unsupported);
        assert_eq!(problem("\u{1b}[31mevil.test"), PatternProblem::Unsupported);
    }

    #[test]
    fn parses_exact_and_prefix_paths() {
        assert_eq!(
            PathMatcher::parse("/Health"),
            Ok(PathMatcher::Exact {
                path: "/health".into()
            })
        );
        assert_eq!(
            PathMatcher::parse("/api/*"),
            Ok(PathMatcher::Prefix {
                prefix: "/api/".into()
            })
        );
        assert_eq!(
            PathMatcher::parse("*"),
            Ok(PathMatcher::Prefix { prefix: "".into() })
        );
    }

    #[test]
    fn rejects_other_path_forms() {
        let problem = |text| PathMatcher::parse(text).expect_err(text);
        assert_eq!(problem("{http.vars.root}/*"), PatternProblem::Placeholder);
        assert_eq!(problem("*.php"), PatternProblem::Unsupported);
        assert_eq!(problem("/a/*/b"), PatternProblem::Unsupported);
        assert_eq!(problem("/a%2Fb"), PatternProblem::Unsupported);
        assert_eq!(problem("/a\u{1b}[2Jb"), PatternProblem::Unsupported);
        assert_eq!(
            problem(&"/".repeat(MAX_PATH_CHARS + 1)),
            PatternProblem::Unsupported
        );
    }
}
