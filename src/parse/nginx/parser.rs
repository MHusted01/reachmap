//! Recursive-descent parser turning Nginx tokens into a temporary borrowed AST.

use std::borrow::Cow;

use crate::sanitize::sanitize;

use super::lexer::{Token, TokenKind};
use super::{MAX_NESTING_DEPTH, NginxParseError};

#[derive(Debug)]
pub(super) struct FileAst<'a> {
    pub source_file: Option<&'a str>,
    pub directives: Vec<Directive<'a>>,
}

#[derive(Debug)]
pub(super) struct Directive<'a> {
    pub name: Cow<'a, str>,
    pub args: Vec<Cow<'a, str>>,
    pub block: Option<Vec<Directive<'a>>>,
    pub line: usize,
}

pub(super) fn parse<'a>(tokens: &'a [Token<'a>]) -> Result<Vec<FileAst<'a>>, NginxParseError> {
    let mut files = Vec::new();
    let mut cursor = 0usize;

    let mut current_file: Option<&'a str> = None;
    let mut current_directives = Vec::new();

    while cursor < tokens.len() {
        match &tokens[cursor].kind {
            TokenKind::FileMarker(path) => {
                if current_file.is_some() || !current_directives.is_empty() {
                    files.push(FileAst {
                        source_file: current_file,
                        directives: current_directives,
                    });
                    current_directives = Vec::new();
                }
                current_file = Some(path);
                cursor += 1;
            }
            TokenKind::CloseBrace => {
                return Err(NginxParseError::UnexpectedClosingBrace {
                    file: current_file.map(sanitize),
                    line: tokens[cursor].line,
                });
            }
            _ => {
                let directive = parse_directive(tokens, &mut cursor, current_file, 0)?;
                current_directives.push(directive);
            }
        }
    }

    if current_file.is_some() || !current_directives.is_empty() {
        files.push(FileAst {
            source_file: current_file,
            directives: current_directives,
        });
    }

    Ok(files)
}

fn parse_directive<'a>(
    tokens: &'a [Token<'a>],
    cursor: &mut usize,
    current_file: Option<&'a str>,
    depth: usize,
) -> Result<Directive<'a>, NginxParseError> {
    let token = &tokens[*cursor];
    let TokenKind::Word(name_word) = &token.kind else {
        return Err(NginxParseError::UnexpectedToken {
            file: current_file.map(sanitize),
            line: token.line,
            expected: "directive name",
        });
    };
    let line = token.line;
    let name = name_word.clone();
    *cursor += 1;

    let mut args = Vec::new();
    while *cursor < tokens.len() {
        match &tokens[*cursor].kind {
            TokenKind::Word(word) => {
                args.push(word.clone());
                *cursor += 1;
            }
            TokenKind::Semicolon => {
                *cursor += 1;
                return Ok(Directive {
                    name,
                    args,
                    block: None,
                    line,
                });
            }
            TokenKind::OpenBrace => {
                let open_line = tokens[*cursor].line;
                let next_depth = depth + 1;
                if next_depth > MAX_NESTING_DEPTH {
                    return Err(NginxParseError::NestingTooDeep {
                        file: current_file.map(sanitize),
                        line: open_line,
                        limit: MAX_NESTING_DEPTH,
                    });
                }
                *cursor += 1;
                let block = parse_block(tokens, cursor, current_file, open_line, next_depth)?;
                return Ok(Directive {
                    name,
                    args,
                    block: Some(block),
                    line,
                });
            }
            TokenKind::CloseBrace | TokenKind::FileMarker(_) => {
                return Err(NginxParseError::TruncatedDirective {
                    file: current_file.map(sanitize),
                    line,
                });
            }
        }
    }

    Err(NginxParseError::TruncatedDirective {
        file: current_file.map(sanitize),
        line,
    })
}

fn parse_block<'a>(
    tokens: &'a [Token<'a>],
    cursor: &mut usize,
    current_file: Option<&'a str>,
    open_line: usize,
    depth: usize,
) -> Result<Vec<Directive<'a>>, NginxParseError> {
    let mut directives = Vec::new();
    while *cursor < tokens.len() {
        match &tokens[*cursor].kind {
            TokenKind::CloseBrace => {
                *cursor += 1;
                return Ok(directives);
            }
            TokenKind::FileMarker(_) => {
                return Err(NginxParseError::UnclosedBlock {
                    file: current_file.map(sanitize),
                    line: open_line,
                });
            }
            _ => {
                directives.push(parse_directive(tokens, cursor, current_file, depth)?);
            }
        }
    }
    Err(NginxParseError::UnclosedBlock {
        file: current_file.map(sanitize),
        line: open_line,
    })
}
