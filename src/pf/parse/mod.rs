//! Reading `pfctl -sr` text into a [`Ruleset`].
//!
//! Reading never fails: a line that cannot be read becomes an entry that makes
//! every verdict that reaches it unknown, so nothing is silently dropped.

use std::iter::Peekable;
use std::vec::IntoIter;

use crate::sanitize::sanitize;
use crate::socket::AddressFamily;

use super::fields::{Operator, PortMatch, TcpFlags};
use super::lex::{Token, tokenize};
use super::model::{
    Action, AnchorName, BinatTarget, Construct, Criteria, Direction, Entry, Kind, RuleProtocol,
    Ruleset, Skip, TargetEndpoint, TargetPort, TranslationTarget,
};

mod endpoints;

use endpoints::{address, endpoint, interface, next_word, port, protocol};

type Cursor<'a> = Peekable<IntoIter<Token<'a>>>;

enum Parsed {
    Ignored,
    Skip(Vec<String>),
    Entry(Kind),
}

pub(super) fn parse(text: &str) -> Ruleset {
    let mut ruleset = Ruleset::default();
    for (index, raw) in text.lines().enumerate() {
        let line = index + 1;
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
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
        "rdr" | "nat" | "binat" | "no" | "rdr-anchor" | "nat-anchor" | "binat-anchor" => {
            translation(first, &mut cursor)
        }
        // Normalization and table definitions never pass or block traffic.
        "scrub" | "scrub-anchor" | "table" => Parsed::Ignored,
        _ => unparseable(),
    }
}

fn filter(action: Action, cursor: &mut Cursor<'_>) -> Parsed {
    Parsed::Entry(Kind::Filter {
        action,
        criteria: criteria(cursor, false).0,
    })
}

fn anchor(cursor: &mut Cursor<'_>) -> Parsed {
    let Some(Token::Quoted(name)) = cursor.next() else {
        return Parsed::Entry(Kind::Unparseable);
    };
    Parsed::Entry(Kind::Anchor {
        name: AnchorName::new(name),
        criteria: criteria(cursor, false).0,
    })
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
    let (criteria, saw_arrow) = criteria(cursor, true);
    let target = if criteria.protocol == Some(RuleProtocol::Other) {
        TranslationTarget::None
    } else {
        match (is_no, kind) {
            (true, "binat") => TranslationTarget::Binat(BinatTarget::None),
            (true, _) | (false, "nat") => TranslationTarget::None,
            (false, "binat-anchor") => TranslationTarget::Binat(BinatTarget::Any),
            (false, "rdr-anchor" | "nat-anchor") => TranslationTarget::Any,
            (false, "binat") => {
                if criteria.unsupported.is_some() {
                    TranslationTarget::Binat(BinatTarget::Any)
                } else if !saw_arrow {
                    return Parsed::Entry(Kind::Unparseable);
                } else {
                    TranslationTarget::Binat(parse_binat_target(cursor))
                }
            }
            (false, "rdr") => {
                if criteria.unsupported.is_some() {
                    TranslationTarget::Any
                } else if !saw_arrow {
                    return Parsed::Entry(Kind::Unparseable);
                } else {
                    parse_translation_target(cursor, &criteria)
                }
            }
            _ => TranslationTarget::Any,
        }
    };
    Parsed::Entry(Kind::Translation { criteria, target })
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

/// Reads conditions until the line ends, a translation target (`->`) starts
/// when `allow_arrow` is set, or something the evaluator does not model appears.
fn criteria(cursor: &mut Cursor<'_>, allow_arrow: bool) -> (Criteria, bool) {
    let mut criteria = Criteria::default();
    let mut saw_arrow = false;
    while let Some(token) = cursor.next() {
        let outcome = match token {
            Token::Word("->") if allow_arrow => {
                saw_arrow = true;
                break;
            }
            Token::Word(word) => apply(&mut criteria, cursor, word),
            Token::Open | Token::Close | Token::Comma => Err(Construct::List),
            Token::Quoted(_) => Err(Construct::UnrecognizedSyntax),
        };
        if let Err(construct) = outcome {
            criteria.unsupported = Some(construct);
            saw_arrow = scan_remaining_effects(cursor, &mut criteria, allow_arrow);
            break;
        }
        if criteria.protocol == Some(RuleProtocol::Other) {
            // Never matches TCP or UDP, so the rest cannot matter.
            break;
        }
    }
    (criteria, saw_arrow)
}

fn scan_remaining_effects(
    cursor: &mut Cursor<'_>,
    criteria: &mut Criteria,
    allow_arrow: bool,
) -> bool {
    while let Some(token) = cursor.next() {
        match token {
            Token::Word("->") if allow_arrow => return true,
            Token::Word("->") => {
                criteria
                    .effect_unsupported
                    .get_or_insert(Construct::UnrecognizedSyntax);
            }
            Token::Word("quick") => criteria.quick = true,
            Token::Word("keep" | "modulate" | "synproxy")
                if cursor.next_if(|t| *t == Token::Word("state")).is_some() =>
            {
                check_state_options(cursor, criteria);
            }
            Token::Word("fastroute" | "route-to" | "dup-to") => {
                criteria
                    .effect_unsupported
                    .get_or_insert(Construct::RouteTo);
            }
            Token::Word("reply-to") => {
                criteria
                    .effect_unsupported
                    .get_or_insert(Construct::ReplyTo);
            }
            Token::Word("label" | "tag") => {
                cursor.next();
            }
            _ => {}
        }
    }
    false
}

fn apply(criteria: &mut Criteria, cursor: &mut Cursor<'_>, word: &str) -> Result<(), Construct> {
    match word {
        "in" => criteria.direction = Some(Direction::In),
        "out" => criteria.direction = Some(Direction::Out),
        "quick" => criteria.quick = true,
        "inet" => criteria.family = Some(AddressFamily::Ipv4),
        "inet6" => criteria.family = Some(AddressFamily::Ipv6),
        "on" => criteria.interface = Some(interface(cursor)?),
        "proto" => criteria.protocol = Some(protocol(next_word(cursor)?)?),
        "from" => {
            if criteria.source.is_some() {
                criteria.source = None;
                return Err(Construct::UnrecognizedSyntax);
            }
            criteria.source = Some(endpoint(cursor)?);
        }
        "to" => {
            if criteria.destination.is_some() {
                criteria.destination = None;
                return Err(Construct::UnrecognizedSyntax);
            }
            criteria.destination = Some(endpoint(cursor)?);
        }
        "flags" => {
            criteria.flags =
                Some(TcpFlags::parse(next_word(cursor)?).ok_or(Construct::UnrecognizedSyntax)?);
        }
        "all" | "drop" | "return" | "allow-opts" => {}
        "log" | "return-rst" | "return-icmp" | "return-icmp6" => {
            skip_group(cursor);
        }
        "keep" | "modulate" | "synproxy" => {
            if next_word(cursor)? != "state" {
                return Err(Construct::UnrecognizedSyntax);
            }
            check_state_options(cursor, criteria);
        }
        "no" => {
            if next_word(cursor)? != "state" {
                return Err(Construct::UnrecognizedSyntax);
            }
        }
        "label" | "tag" => match cursor.next() {
            Some(Token::Quoted(_) | Token::Word(_)) => {}
            _ => return Err(Construct::UnrecognizedSyntax),
        },
        "fastroute" => {
            criteria
                .effect_unsupported
                .get_or_insert(Construct::RouteTo);
        }
        "route-to" | "dup-to" => mark_effect(criteria, cursor, Construct::RouteTo)?,
        "reply-to" => mark_effect(criteria, cursor, Construct::ReplyTo)?,
        "!" => {
            if next_word(cursor)? == "tagged" {
                return Err(Construct::Tagged);
            }
            return Err(Construct::UnrecognizedSyntax);
        }
        "tagged" | "!tagged" => return Err(Construct::Tagged),
        "user" => return Err(Construct::User),
        "group" => return Err(Construct::Group),
        "os" => return Err(Construct::OsFingerprint),
        "received-on" => return Err(Construct::ReceivedOn),
        "probability" => return Err(Construct::Probability),
        _ => return Err(Construct::UnrecognizedSyntax),
    }
    Ok(())
}

fn mark_effect(
    criteria: &mut Criteria,
    cursor: &mut Cursor<'_>,
    construct: Construct,
) -> Result<(), Construct> {
    criteria.effect_unsupported.get_or_insert(construct);
    if cursor
        .next_if(|token| matches!(token, Token::Word(_)))
        .is_none()
    {
        return Err(construct);
    }
    Ok(())
}

fn check_state_options(cursor: &mut Cursor<'_>, criteria: &mut Criteria) {
    let Some(group) = skip_group(cursor) else {
        return;
    };
    let inner = group
        .strip_prefix('(')
        .and_then(|rest| rest.strip_suffix(')'))
        .unwrap_or("");
    let mut items = inner.split(',').map(str::trim).peekable();
    let known = items.peek().is_some()
        && items.all(|item| {
            matches!(
                item,
                "if-bound" | "floating" | "sloppy" | "no-sync" | "pflow"
            )
        });
    if !known {
        criteria
            .effect_unsupported
            .get_or_insert(Construct::StateLimit);
    }
}

/// Consumes an optional `(...)` option group.
fn skip_group<'a>(cursor: &mut Cursor<'a>) -> Option<&'a str> {
    match cursor.next_if(|token| matches!(token, Token::Word(word) if word.starts_with('('))) {
        Some(Token::Word(group)) => Some(group),
        _ => None,
    }
}
