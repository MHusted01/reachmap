//! Reading `pfctl -sr` text into a [`Ruleset`].
//!
//! Reading never fails: a line that cannot be read becomes an entry that makes
//! every verdict that reaches it unknown, so nothing is silently dropped.

use std::iter::Peekable;
use std::vec::IntoIter;

use crate::sanitize::sanitize;

use super::fields::{Operator, PortMatch};
use super::lex::{Token, tokenize};
use super::model::{
    Action, AnchorName, BinatTarget, Criteria, Entry, Kind, RuleProtocol, Ruleset, Skip,
    TargetEndpoint, TargetPort, TranslationTarget,
};

mod criteria;
mod endpoints;

use criteria::{CriteriaMode, parse_criteria};
use endpoints::{address, port};

type Cursor<'a> = Peekable<IntoIter<Token<'a>>>;

enum Parsed {
    Ignored,
    Skip(Vec<String>),
    Entry(Kind),
}

pub(super) fn parse(text: &str) -> Ruleset {
    let mut ruleset = Ruleset::default();
    let mut brace_depth: usize = 0;
    for (index, raw) in text.lines().enumerate() {
        let line = index + 1;
        let trimmed = raw.trim();
        if brace_depth > 0 {
            let (opens, closes) = brace_counts(raw);
            brace_depth = brace_depth.saturating_add(opens).saturating_sub(closes);
            continue;
        }
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let (opens, closes) = brace_counts(trimmed);
        if opens > closes {
            brace_depth = opens - closes;
            let entry = match trimmed.split_whitespace().next() {
                Some("table") => None,
                Some("rdr-anchor" | "nat-anchor" | "binat-anchor") => Some(Kind::Translation {
                    criteria: Criteria::default(),
                    target: TranslationTarget::Any,
                }),
                _ => Some(Kind::Unparseable),
            };
            if let Some(kind) = entry {
                ruleset.entries.push(Entry { line, kind });
            }
            continue;
        }
        if closes > opens {
            ruleset.entries.push(Entry {
                line,
                kind: Kind::Unparseable,
            });
            continue;
        }
        match parse_line(trimmed) {
            Parsed::Ignored => {}
            Parsed::Skip(names) => record_skip(&mut ruleset, line, names),
            Parsed::Entry(kind) => ruleset.entries.push(Entry { line, kind }),
        }
    }
    ruleset
}

fn brace_counts(line: &str) -> (usize, usize) {
    let mut opens = 0usize;
    let mut closes = 0usize;
    let mut in_quotes = false;
    for ch in line.chars() {
        match ch {
            '"' => in_quotes = !in_quotes,
            '#' if !in_quotes => break,
            '{' if !in_quotes => opens += 1,
            '}' if !in_quotes => closes += 1,
            _ => {}
        }
    }
    (opens, closes)
}

fn record_skip(ruleset: &mut Ruleset, line: usize, names: Vec<String>) {
    if names == ["none"] {
        ruleset.skip.clear();
    } else {
        ruleset
            .skip
            .extend(names.into_iter().map(|name| Skip { line, name }));
    }
}

fn parse_line(line: &str) -> Parsed {
    let unparseable = || Parsed::Entry(Kind::Unparseable);
    let Some(tokens) = tokenize(line) else {
        return unparseable();
    };
    let mut cursor = tokens.into_iter().peekable();
    let Some(Token::Word(first)) = cursor.next() else {
        return unparseable();
    };
    match first {
        "pass" => filter(Action::Pass, &mut cursor),
        "block" => filter(Action::Block, &mut cursor),
        "anchor" => anchor(&mut cursor),
        "set" => set_option(&mut cursor),
        "scrub" => scrub(&mut cursor),
        "scrub-anchor" => scrub_anchor(&mut cursor),
        "no" if cursor.peek() == Some(&Token::Word("scrub")) => {
            cursor.next();
            Parsed::Entry(Kind::NoScrub {
                criteria: parse_criteria(&mut cursor, CriteriaMode::Scrub).criteria,
            })
        }
        "rdr" | "nat" | "binat" | "no" | "rdr-anchor" | "nat-anchor" | "binat-anchor" => {
            translation(first, &mut cursor)
        }
        // Table definitions never pass or block traffic.
        "table" => Parsed::Ignored,
        _ => unparseable(),
    }
}

fn filter(action: Action, cursor: &mut Cursor<'_>) -> Parsed {
    Parsed::Entry(Kind::Filter {
        action,
        criteria: parse_criteria(cursor, CriteriaMode::Filter).criteria,
    })
}

fn anchor(cursor: &mut Cursor<'_>) -> Parsed {
    let Some(Token::Quoted(name)) = cursor.next() else {
        return Parsed::Entry(Kind::Unparseable);
    };
    Parsed::Entry(Kind::Anchor {
        name: AnchorName::new(name),
        criteria: parse_criteria(cursor, CriteriaMode::Filter).criteria,
    })
}

fn scrub(cursor: &mut Cursor<'_>) -> Parsed {
    let parsed = parse_criteria(cursor, CriteriaMode::Scrub);
    if parsed.scrub_changes_verdict || parsed.criteria.unsupported.is_some() {
        Parsed::Entry(Kind::ScrubOther {
            criteria: parsed.criteria,
        })
    } else {
        Parsed::Entry(Kind::ScrubReassemble {
            criteria: parsed.criteria,
        })
    }
}

fn scrub_anchor(cursor: &mut Cursor<'_>) -> Parsed {
    let Some(Token::Quoted(name)) = cursor.next() else {
        return Parsed::Entry(Kind::Unparseable);
    };
    let parsed = parse_criteria(cursor, CriteriaMode::Scrub);
    if parsed.scrub_changes_verdict || parsed.criteria.unsupported.is_some() {
        Parsed::Entry(Kind::ScrubOther {
            criteria: parsed.criteria,
        })
    } else {
        Parsed::Entry(Kind::ScrubAnchor {
            name: AnchorName::new(name),
            criteria: parsed.criteria,
        })
    }
}

fn translation(first: &str, cursor: &mut Cursor<'_>) -> Parsed {
    let (is_no, kind) = match first {
        "no" => match cursor.next() {
            Some(Token::Word(kind @ ("rdr" | "nat" | "binat"))) => (true, kind),
            _ => return Parsed::Entry(Kind::Unparseable),
        },
        "rdr-anchor" | "nat-anchor" | "binat-anchor" => {
            if !matches!(cursor.next(), Some(Token::Quoted(_) | Token::Word(_))) {
                return Parsed::Entry(Kind::Unparseable);
            }
            (false, first)
        }
        _ => (false, first),
    };
    cursor.next_if(|token| *token == Token::Word("pass"));
    let parsed = parse_criteria(cursor, CriteriaMode::Translation);
    let target = if parsed.criteria.protocol == Some(RuleProtocol::Other) {
        TranslationTarget::None
    } else {
        match (is_no, kind) {
            (true, "binat") => TranslationTarget::Binat(BinatTarget::None),
            (true, _) | (false, "nat") => TranslationTarget::None,
            (false, "binat-anchor") => TranslationTarget::Binat(BinatTarget::Any),
            (false, "rdr-anchor" | "nat-anchor") => TranslationTarget::Any,
            (false, "binat") => {
                if parsed.criteria.unsupported.is_some() {
                    TranslationTarget::Binat(BinatTarget::Any)
                } else if !parsed.saw_arrow {
                    return Parsed::Entry(Kind::Unparseable);
                } else {
                    TranslationTarget::Binat(parse_binat_target(cursor))
                }
            }
            (false, "rdr") => {
                if parsed.criteria.unsupported.is_some() {
                    TranslationTarget::Any
                } else if !parsed.saw_arrow {
                    return Parsed::Entry(Kind::Unparseable);
                } else {
                    parse_translation_target(cursor, &parsed.criteria)
                }
            }
            _ => TranslationTarget::Any,
        }
    };
    Parsed::Entry(Kind::Translation {
        criteria: parsed.criteria,
        target,
    })
}

fn parse_binat_target(cursor: &mut Cursor<'_>) -> BinatTarget {
    if matches!(cursor.peek(), None | Some(Token::Open)) {
        return BinatTarget::Any;
    }
    address(cursor).map_or(BinatTarget::Any, BinatTarget::Address)
}

fn parse_translation_target(cursor: &mut Cursor<'_>, criteria: &Criteria) -> TranslationTarget {
    if matches!(cursor.peek(), None | Some(Token::Open)) {
        return TranslationTarget::Any;
    }
    let address = address(cursor).ok();
    let port = if cursor
        .next_if(|token| *token == Token::Word("port"))
        .is_some()
    {
        let exact_src = matches!(
            criteria.destination.as_ref().and_then(|ep| ep.port),
            None | Some(PortMatch::Compare(Operator::Eq, _))
        );
        match port(cursor) {
            Ok(parsed) if exact_src => TargetPort::Match(parsed),
            _ => TargetPort::Any,
        }
    } else {
        TargetPort::Inherit
    };
    TranslationTarget::Endpoint(TargetEndpoint { address, port })
}

/// `set skip on ...` is the only `set` statement that changes which packets
/// are filtered. The others (`block-policy`, `timeout`, ...) are ignored.
fn set_option(cursor: &mut Cursor<'_>) -> Parsed {
    if cursor.next() != Some(Token::Word("skip")) {
        return Parsed::Ignored;
    }
    if cursor.next() == Some(Token::Word("on"))
        && let Some(names) = skip_names(cursor)
        && !names.is_empty()
        && cursor.peek().is_none()
    {
        return Parsed::Skip(names);
    }
    Parsed::Entry(Kind::Unparseable)
}

fn skip_names(cursor: &mut Cursor<'_>) -> Option<Vec<String>> {
    match cursor.next()? {
        Token::Word(name) if sanitize(name) == name => Some(vec![name.to_string()]),
        Token::Open => {
            let mut names = Vec::new();
            loop {
                match cursor.next()? {
                    Token::Word(name) if sanitize(name) == name => names.push(name.to_string()),
                    Token::Comma => {}
                    Token::Close => return Some(names),
                    _ => return None,
                }
            }
        }
        _ => None,
    }
}
