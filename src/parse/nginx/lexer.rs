//! Bounded, zero-copy-by-default lexer for Nginx configuration in the
//! `nginx -T` format.

use std::borrow::Cow;

use crate::sanitize::sanitize;

use super::{MAX_INPUT_BYTES, MAX_TOKENS, NginxParseError};

#[derive(Debug, Clone)]
pub(super) enum TokenKind<'a> {
    FileMarker(&'a str),
    Word(Cow<'a, str>),
    Semicolon,
    OpenBrace,
    CloseBrace,
}

#[derive(Debug, Clone)]
pub(super) struct Token<'a> {
    pub kind: TokenKind<'a>,
    pub line: usize,
}

pub(super) fn tokenize(input: &str) -> Result<Vec<Token<'_>>, NginxParseError> {
    if input.len() > MAX_INPUT_BYTES {
        return Err(NginxParseError::InputTooLarge {
            limit_bytes: MAX_INPUT_BYTES,
        });
    }

    let bytes = input.as_bytes();
    let mut pos = 0usize;
    let mut line = 1usize;
    let mut current_file: Option<&str> = None;
    let mut tokens = Vec::new();

    while pos < bytes.len() {
        let byte = bytes[pos];
        if byte == b'\n' {
            line += 1;
            pos += 1;
            continue;
        }
        if byte.is_ascii_whitespace() {
            pos += 1;
            continue;
        }

        match byte {
            b';' => {
                push_token(
                    &mut tokens,
                    Token {
                        kind: TokenKind::Semicolon,
                        line,
                    },
                )?;
                pos += 1;
            }
            b'{' => {
                push_token(
                    &mut tokens,
                    Token {
                        kind: TokenKind::OpenBrace,
                        line,
                    },
                )?;
                pos += 1;
            }
            b'}' => {
                push_token(
                    &mut tokens,
                    Token {
                        kind: TokenKind::CloseBrace,
                        line,
                    },
                )?;
                pos += 1;
            }
            b'#' => {
                let end = find_line_end(bytes, pos);
                let comment = &input[pos..end];
                if let Some(path) = parse_file_marker(comment) {
                    current_file = Some(path);
                    line = 0;
                    push_token(
                        &mut tokens,
                        Token {
                            kind: TokenKind::FileMarker(path),
                            line: 1,
                        },
                    )?;
                }
                pos = end;
            }
            b'\'' | b'"' => {
                let start_line = line;
                let (word, next_pos) = lex_quoted(input, pos, &mut line, current_file, start_line)?;
                push_token(
                    &mut tokens,
                    Token {
                        kind: TokenKind::Word(word),
                        line: start_line,
                    },
                )?;
                pos = next_pos;
            }
            _ => {
                let start_line = line;
                let (word, next_pos) = lex_unquoted(input, pos, &mut line, current_file)?;
                push_token(
                    &mut tokens,
                    Token {
                        kind: TokenKind::Word(word),
                        line: start_line,
                    },
                )?;
                pos = next_pos;
            }
        }
    }

    Ok(tokens)
}

fn push_token<'a>(tokens: &mut Vec<Token<'a>>, token: Token<'a>) -> Result<(), NginxParseError> {
    if tokens.len() >= MAX_TOKENS {
        return Err(NginxParseError::TooManyTokens { limit: MAX_TOKENS });
    }
    tokens.push(token);
    Ok(())
}

/// Decodes one backslash escape as Nginx copies a token: `\"`, `\'` and `\\`
/// drop the backslash, `\t`, `\r` and `\n` become control characters, and
/// any other escape keeps its backslash (so `include` globs see `\?`).
fn push_escape(buf: &mut String, next: char) {
    match next {
        '"' | '\'' | '\\' => buf.push(next),
        't' => buf.push('\t'),
        'r' => buf.push('\r'),
        'n' => buf.push('\n'),
        other => {
            buf.push('\\');
            buf.push(other);
        }
    }
}

fn find_line_end(bytes: &[u8], mut pos: usize) -> usize {
    while pos < bytes.len() && bytes[pos] != b'\n' {
        pos += 1;
    }
    pos
}

fn parse_file_marker(comment: &str) -> Option<&str> {
    let rest = comment.trim_end_matches('\r').trim_end();
    let path = rest
        .strip_prefix("# configuration file ")?
        .strip_suffix(':')?;
    (!path.is_empty()).then_some(path)
}

fn lex_quoted<'a>(
    input: &'a str,
    start: usize,
    line: &mut usize,
    current_file: Option<&'a str>,
    start_line: usize,
) -> Result<(Cow<'a, str>, usize), NginxParseError> {
    let bytes = input.as_bytes();
    let quote = bytes[start];
    let mut pos = start + 1;
    let mut escaped: Option<String> = None;
    let mut chunk_start = pos;

    while pos < bytes.len() {
        let byte = bytes[pos];
        if byte == b'\n' {
            *line += 1;
        }
        if byte == quote {
            let text = match escaped {
                Some(mut buf) => {
                    buf.push_str(&input[chunk_start..pos]);
                    Cow::Owned(buf)
                }
                None => Cow::Borrowed(&input[chunk_start..pos]),
            };
            return Ok((text, pos + 1));
        }
        if byte == b'\\' {
            if pos + 1 >= bytes.len() {
                return Err(NginxParseError::UnterminatedString {
                    file: current_file.map(sanitize),
                    line: start_line,
                });
            }
            let next_char = input[pos + 1..].chars().next().ok_or_else(|| {
                NginxParseError::UnterminatedString {
                    file: current_file.map(sanitize),
                    line: start_line,
                }
            })?;
            let buf = escaped.get_or_insert_with(String::new);
            buf.push_str(&input[chunk_start..pos]);
            if next_char == '\n' {
                *line += 1;
            }
            push_escape(buf, next_char);
            pos += 1 + next_char.len_utf8();
            chunk_start = pos;
            continue;
        }
        pos += 1;
    }

    Err(NginxParseError::UnterminatedString {
        file: current_file.map(sanitize),
        line: start_line,
    })
}

fn lex_unquoted<'a>(
    input: &'a str,
    start: usize,
    line: &mut usize,
    current_file: Option<&'a str>,
) -> Result<(Cow<'a, str>, usize), NginxParseError> {
    let bytes = input.as_bytes();
    let mut pos = start;
    let mut escaped: Option<String> = None;
    let mut chunk_start = pos;
    let mut prev_unescaped_dollar = false;

    while pos < bytes.len() {
        let byte = bytes[pos];
        if byte == b'{' && prev_unescaped_dollar {
            // Keep `${var}` braced variable references inside the same word.
            pos += 1;
            while pos < bytes.len()
                && !bytes[pos].is_ascii_whitespace()
                && !matches!(bytes[pos], b';' | b'}')
            {
                pos += 1;
            }
            if pos < bytes.len() && bytes[pos] == b'}' {
                pos += 1;
            }
            prev_unescaped_dollar = false;
            continue;
        }
        if byte.is_ascii_whitespace() || matches!(byte, b';' | b'{' | b'}') {
            break;
        }
        if byte == b'\\' {
            if pos + 1 >= bytes.len() {
                return Err(NginxParseError::TruncatedEscape {
                    file: current_file.map(sanitize),
                    line: *line,
                });
            }
            let next_char = input[pos + 1..].chars().next().ok_or_else(|| {
                NginxParseError::TruncatedEscape {
                    file: current_file.map(sanitize),
                    line: *line,
                }
            })?;
            let buf = escaped.get_or_insert_with(String::new);
            buf.push_str(&input[chunk_start..pos]);
            if next_char == '\n' {
                *line += 1;
            }
            push_escape(buf, next_char);
            pos += 1 + next_char.len_utf8();
            chunk_start = pos;
            prev_unescaped_dollar = false;
            continue;
        }
        prev_unescaped_dollar = byte == b'$';
        pos += 1;
    }

    let text = match escaped {
        Some(mut buf) => {
            buf.push_str(&input[chunk_start..pos]);
            Cow::Owned(buf)
        }
        None => Cow::Borrowed(&input[chunk_start..pos]),
    };

    Ok((text, pos))
}
