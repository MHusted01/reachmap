//! Why a Caddy config could not be read at all.

use serde_json::error::Category;
use thiserror::Error;

/// Largest config accepted, in bytes (8 MiB).
pub const MAX_INPUT_BYTES: usize = 8 * 1024 * 1024;

/// Why Caddy JSON could not be parsed.
///
/// serde_json's own messages can quote the offending value (`invalid type:
/// string "..."`), so they are dropped: only the category and position remain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum CaddyParseError {
    /// The input is larger than [`MAX_INPUT_BYTES`].
    #[error("Caddy configuration exceeds the {limit_bytes}-byte input limit")]
    InputTooLarge {
        /// Maximum accepted length.
        limit_bytes: usize,
    },
    /// The input ends before the JSON document does.
    #[error("Caddy configuration ends early at line {line}, column {column}")]
    Truncated {
        /// 1-based line.
        line: usize,
        /// 1-based column.
        column: usize,
    },
    /// The input is not valid JSON.
    #[error("Caddy configuration is not valid JSON at line {line}, column {column}")]
    Syntax {
        /// 1-based line.
        line: usize,
        /// 1-based column.
        column: usize,
    },
    /// The JSON is valid, but a modeled field has the wrong type.
    #[error("Caddy configuration has a value of the wrong type at line {line}, column {column}")]
    Shape {
        /// 1-based line.
        line: usize,
        /// 1-based column.
        column: usize,
    },
}

impl From<serde_json::Error> for CaddyParseError {
    fn from(error: serde_json::Error) -> Self {
        let (line, column) = (error.line(), error.column());
        match error.classify() {
            Category::Eof => Self::Truncated { line, column },
            Category::Syntax | Category::Io => Self::Syntax { line, column },
            Category::Data => Self::Shape { line, column },
        }
    }
}
