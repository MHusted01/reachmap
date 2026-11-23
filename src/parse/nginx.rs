//! Pure, bounded parser for expanded Nginx configuration in the `nginx -T`
//! format: each file after a `# configuration file <path>:` line.
//!
//! Lexes and parses Nginx directives over borrowed `&str` slices and
//! immediately projects them into a secret-minimized [`NginxConfig`], never
//! retaining raw config text, comments, credentials, headers, key paths, or
//! response bodies.

use std::fmt;

use thiserror::Error;

use crate::nginx::NginxConfig;

pub use includes::{
    conf_path_from_build_info, include_patterns, is_glob_component, matches_glob_component,
};

mod directives;
mod includes;
mod lexer;
mod listen;
mod parser;
mod project;
mod server;
mod target;

/// Maximum accepted size of an expanded configuration input (8 MiB).
pub const MAX_INPUT_BYTES: usize = 8 * 1024 * 1024;

/// Maximum number of lexical tokens accepted from a single input.
const MAX_TOKENS: usize = 250_000;

/// Maximum block nesting depth accepted by the parser.
const MAX_NESTING_DEPTH: usize = 32;

/// Why an Nginx configuration dump could not be parsed within safety bounds.
///
/// Variants never embed raw directive arguments, quoted strings, or config
/// lines; only sanitized `# configuration file` provenance and line numbers are
/// reported.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum NginxParseError {
    /// Input exceeded [`MAX_INPUT_BYTES`].
    #[error("nginx configuration exceeds the {limit_bytes}-byte input limit")]
    InputTooLarge {
        /// Maximum allowed byte length.
        limit_bytes: usize,
    },
    /// Token stream exceeded the parser token bound.
    #[error("nginx configuration exceeds the {limit}-token limit")]
    TooManyTokens {
        /// Maximum allowed token count.
        limit: usize,
    },
    /// Block nesting exceeded the parser depth bound.
    #[error("nginx configuration exceeds {limit} levels of block nesting at {}", format_location(.file.as_deref(), *.line))]
    NestingTooDeep {
        /// Sanitized file provenance, if known.
        file: Option<String>,
        /// 1-based line number in `file`.
        line: usize,
        /// Maximum allowed nesting depth.
        limit: usize,
    },
    /// A single- or double-quoted string was not closed before EOF.
    #[error("unterminated quoted string in nginx configuration at {}", format_location(.file.as_deref(), *.line))]
    UnterminatedString {
        /// Sanitized file provenance, if known.
        file: Option<String>,
        /// 1-based line number where the string started.
        line: usize,
    },
    /// A backslash escape at the end of an unquoted token reached EOF.
    #[error("truncated escape sequence in nginx configuration at {}", format_location(.file.as_deref(), *.line))]
    TruncatedEscape {
        /// Sanitized file provenance, if known.
        file: Option<String>,
        /// 1-based line number of the truncated escape.
        line: usize,
    },
    /// A `{` block was not closed with `}` before the end of its file or input.
    #[error("unclosed block in nginx configuration at {}", format_location(.file.as_deref(), *.line))]
    UnclosedBlock {
        /// Sanitized file provenance, if known.
        file: Option<String>,
        /// 1-based line number where the block opened.
        line: usize,
    },
    /// Encountered `}` with no matching opening `{`.
    #[error("unexpected closing brace in nginx configuration at {}", format_location(.file.as_deref(), *.line))]
    UnexpectedClosingBrace {
        /// Sanitized file provenance, if known.
        file: Option<String>,
        /// 1-based line number of the stray `}`.
        line: usize,
    },
    /// Encountered an unexpected token where a directive name or block was required.
    #[error("unexpected token in nginx configuration at {} (expected {expected})", format_location(.file.as_deref(), *.line))]
    UnexpectedToken {
        /// Sanitized file provenance, if known.
        file: Option<String>,
        /// 1-based line number of the unexpected token.
        line: usize,
        /// Static description of what the grammar expected.
        expected: &'static str,
    },
    /// A directive reached EOF, `}`, or a new file marker without `;` or `{`.
    #[error("truncated directive in nginx configuration at {}", format_location(.file.as_deref(), *.line))]
    TruncatedDirective {
        /// Sanitized file provenance, if known.
        file: Option<String>,
        /// 1-based line number where the directive started.
        line: usize,
    },
}

fn format_location(file: Option<&str>, line: usize) -> String {
    struct Location<'a>(Option<&'a str>, usize);
    impl fmt::Display for Location<'_> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self.0 {
                Some(file) => write!(f, "{file}:{}", self.1),
                None => write!(f, "line {}", self.1),
            }
        }
    }
    Location(file, line).to_string()
}

/// Parses expanded Nginx configuration in the `nginx -T` format into a secret-minimized
/// [`NginxConfig`] model without touching the filesystem or network.
pub fn parse_nginx_config(input: &str) -> Result<NginxConfig, NginxParseError> {
    let tokens = lexer::tokenize(input)?;
    let files = parser::parse(&tokens)?;
    Ok(project::project(&files))
}

#[cfg(test)]
mod tests;
