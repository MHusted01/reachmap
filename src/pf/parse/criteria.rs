//! Rule match conditions and trailing verdict-changing options.

use crate::socket::AddressFamily;

use super::super::fields::TcpFlags;
use super::super::lex::Token;
use super::super::model::{Construct, Criteria, Direction};
use super::Cursor;
use super::endpoints::{endpoint, interface, next_word, protocol};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CriteriaMode {
    Filter,
    Translation,
    Scrub,
}

pub(super) struct ParsedCriteria {
    pub(super) criteria: Criteria,
    pub(super) saw_arrow: bool,
    pub(super) scrub_changes_verdict: bool,
}

/// Reads conditions until the line ends, a translation target (`->`) starts
/// in translation mode, a scrub option that alters packet handling appears, or
/// an unmodeled construct is reached.
pub(super) fn parse_criteria(cursor: &mut Cursor<'_>, mode: CriteriaMode) -> ParsedCriteria {
    let mut criteria = Criteria::default();
    let mut saw_arrow = false;
    let mut scrub_changes_verdict = false;
    while let Some(token) = cursor.next() {
        if mode == CriteriaMode::Translation && token == Token::Word("->") {
            saw_arrow = true;
            break;
        }
        if mode == CriteriaMode::Scrub && is_scrub_option(token, cursor, &mut scrub_changes_verdict)
        {
            if scrub_changes_verdict {
                break;
            }
            continue;
        }
        let outcome = match token {
            Token::Word(word) => apply(&mut criteria, cursor, word),
            Token::Open | Token::Close | Token::Comma => Err(Construct::List),
            Token::Quoted(_) => Err(Construct::UnrecognizedSyntax),
        };
        if let Err(construct) = outcome {
            criteria.unsupported = Some(construct);
            saw_arrow =
                scan_remaining_effects(cursor, &mut criteria, mode == CriteriaMode::Translation);
            break;
        }
    }
    ParsedCriteria {
        criteria,
        saw_arrow,
        scrub_changes_verdict,
    }
}

fn is_scrub_option(token: Token<'_>, cursor: &mut Cursor<'_>, changes_verdict: &mut bool) -> bool {
    match token {
        Token::Word("fragment") => {
            if cursor
                .next_if(|next| *next == Token::Word("reassemble"))
                .is_none()
            {
                *changes_verdict = true;
            }
            true
        }
        Token::Word("reassemble" | "no-df" | "min-ttl" | "max-mss" | "random-id" | "set-tos") => {
            *changes_verdict = true;
            true
        }
        _ => false,
    }
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

fn set_once<T>(slot: &mut Option<T>, value: T) -> Result<(), Construct> {
    if slot.is_some() {
        *slot = None;
        return Err(Construct::UnrecognizedSyntax);
    }
    *slot = Some(value);
    Ok(())
}

fn set_once_with<T>(
    slot: &mut Option<T>,
    parse: impl FnOnce() -> Result<T, Construct>,
) -> Result<(), Construct> {
    if slot.is_some() {
        *slot = None;
        return Err(Construct::UnrecognizedSyntax);
    }
    *slot = Some(parse()?);
    Ok(())
}

fn apply(criteria: &mut Criteria, cursor: &mut Cursor<'_>, word: &str) -> Result<(), Construct> {
    match word {
        "in" => set_once(&mut criteria.direction, Direction::In)?,
        "out" => set_once(&mut criteria.direction, Direction::Out)?,
        "quick" => criteria.quick = true,
        "inet" => set_once(&mut criteria.family, AddressFamily::Ipv4)?,
        "inet6" => set_once(&mut criteria.family, AddressFamily::Ipv6)?,
        "on" => set_once_with(&mut criteria.interface, || interface(cursor))?,
        "proto" => set_once_with(&mut criteria.protocol, || protocol(next_word(cursor)?))?,
        "from" => {
            if criteria.saw_all {
                return Err(Construct::UnrecognizedSyntax);
            }
            set_once_with(&mut criteria.source, || endpoint(cursor))?;
        }
        "to" => {
            if criteria.saw_all {
                return Err(Construct::UnrecognizedSyntax);
            }
            set_once_with(&mut criteria.destination, || endpoint(cursor))?;
        }
        "flags" => {
            criteria.flags =
                Some(TcpFlags::parse(next_word(cursor)?).ok_or(Construct::UnrecognizedSyntax)?);
        }
        "all" => {
            if criteria.saw_all || criteria.source.is_some() || criteria.destination.is_some() {
                criteria.source = None;
                criteria.destination = None;
                return Err(Construct::UnrecognizedSyntax);
            }
            criteria.saw_all = true;
        }
        "drop" | "return" | "allow-opts" => {}
        "icmp-type" | "icmp6-type" => {
            next_word(cursor)?;
            if cursor
                .next_if(|token| *token == Token::Word("code"))
                .is_some()
            {
                next_word(cursor)?;
            }
        }
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
        "tos" => return Err(Construct::Tos),
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
