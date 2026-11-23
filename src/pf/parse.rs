//! Reading `pfctl -sr` text into a [`Ruleset`].
//!
//! Reading never fails: a line that cannot be read becomes an entry that makes
//! every verdict that reaches it unknown, so nothing is silently dropped.

use std::iter::Peekable;
use std::vec::IntoIter;

use crate::socket::AddressFamily;

use super::fields::{Cidr, Operator, PortMatch, RangeKind, TcpFlags, port_number};
use super::lex::{Token, tokenize};
use super::model::{
    Action, Address, Construct, Criteria, Direction, Endpoint, Entry, InterfaceMatch, Kind,
    RuleProtocol, Ruleset, Skip, is_group_name,
};

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
        criteria: criteria(cursor),
    })
}

fn anchor(cursor: &mut Cursor<'_>) -> Parsed {
    let Some(Token::Quoted(name)) = cursor.next() else {
        return Parsed::Entry(Kind::Unparseable);
    };
    Parsed::Entry(Kind::Anchor {
        name: name.to_string(),
        criteria: criteria(cursor),
    })
}

fn translation(first: &str, cursor: &mut Cursor<'_>) -> Parsed {
    let well_formed = match first {
        "no" => matches!(cursor.next(), Some(Token::Word("rdr" | "nat" | "binat"))),
        "rdr-anchor" | "nat-anchor" | "binat-anchor" => {
            matches!(cursor.next(), Some(Token::Quoted(_) | Token::Word(_)))
        }
        _ => true,
    };
    if !well_formed {
        return Parsed::Entry(Kind::Unparseable);
    }
    cursor.next_if(|token| *token == Token::Word("pass"));
    Parsed::Entry(Kind::Translation {
        criteria: criteria(cursor),
    })
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
    {
        return Parsed::Skip(names);
    }
    Parsed::Entry(Kind::Unparseable)
}

fn skip_names(cursor: &mut Cursor<'_>) -> Option<Vec<String>> {
    match cursor.next()? {
        Token::Word(name) => Some(vec![name.to_string()]),
        Token::Open => {
            let mut names = Vec::new();
            loop {
                match cursor.next()? {
                    Token::Word(name) => names.push(name.to_string()),
                    Token::Comma => {}
                    Token::Close => return Some(names),
                    Token::Quoted(_) | Token::Open => return None,
                }
            }
        }
        _ => None,
    }
}

/// Reads conditions until the line ends, a translation target (`->`) starts,
/// or something the evaluator does not model appears.
fn criteria(cursor: &mut Cursor<'_>) -> Criteria {
    let mut criteria = Criteria::default();
    while let Some(token) = cursor.next() {
        let outcome = match token {
            Token::Word("->") => break,
            Token::Word(word) => apply(&mut criteria, cursor, word),
            Token::Open | Token::Close | Token::Comma => Err(Construct::List),
            Token::Quoted(_) => Err(Construct::UnrecognizedSyntax),
        };
        if let Err(construct) = outcome {
            criteria.unsupported = Some(construct);
            break;
        }
        if criteria.protocol == Some(RuleProtocol::Other) {
            // Never matches TCP or UDP, so the rest cannot matter.
            break;
        }
    }
    criteria
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
        "from" => criteria.source = endpoint(cursor)?,
        "to" => criteria.destination = endpoint(cursor)?,
        "flags" => {
            criteria.flags =
                Some(TcpFlags::parse(next_word(cursor)?).ok_or(Construct::UnrecognizedSyntax)?);
        }
        // Options that do not change which packets the rule matches.
        "all" | "drop" | "return" | "return-rst" | "return-icmp" | "return-icmp6"
        | "allow-opts" => {}
        "log" => skip_group(cursor),
        "keep" | "modulate" | "synproxy" | "no" => {
            if next_word(cursor)? != "state" {
                return Err(Construct::UnrecognizedSyntax);
            }
            skip_group(cursor);
        }
        "label" | "tag" => match cursor.next() {
            Some(Token::Quoted(_) | Token::Word(_)) => {}
            _ => return Err(Construct::UnrecognizedSyntax),
        },
        "user" => return Err(Construct::User),
        "group" => return Err(Construct::Group),
        "os" => return Err(Construct::OsFingerprint),
        "route-to" | "dup-to" | "fastroute" => return Err(Construct::RouteTo),
        "reply-to" => return Err(Construct::ReplyTo),
        "tagged" => return Err(Construct::Tagged),
        "received-on" => return Err(Construct::ReceivedOn),
        "probability" => return Err(Construct::Probability),
        _ => return Err(Construct::UnrecognizedSyntax),
    }
    Ok(())
}

/// Consumes an optional `(...)` option group.
fn skip_group(cursor: &mut Cursor<'_>) {
    cursor.next_if(|token| matches!(token, Token::Word(word) if word.starts_with('(')));
}

fn next_word<'a>(cursor: &mut Cursor<'a>) -> Result<&'a str, Construct> {
    match cursor.next() {
        Some(Token::Word(word)) => Ok(word),
        Some(Token::Open | Token::Close | Token::Comma) => Err(Construct::List),
        Some(Token::Quoted(_)) | None => Err(Construct::UnrecognizedSyntax),
    }
}

fn interface(cursor: &mut Cursor<'_>) -> Result<InterfaceMatch, Construct> {
    let (negated, name) = negated_word(cursor)?;
    if name.starts_with('(') {
        return Err(Construct::DynamicAddress);
    }
    if is_group_name(name) {
        return Err(Construct::InterfaceGroup);
    }
    Ok(InterfaceMatch {
        name: name.to_string(),
        negated,
    })
}

/// Reads a word with an optional leading `!`, written either attached
/// (`!en0`) or apart (`! en0`).
fn negated_word<'a>(cursor: &mut Cursor<'a>) -> Result<(bool, &'a str), Construct> {
    let word = next_word(cursor)?;
    match word.strip_prefix('!') {
        Some("") => Ok((true, next_word(cursor)?)),
        Some(rest) => Ok((true, rest)),
        None => Ok((false, word)),
    }
}

fn protocol(word: &str) -> Result<RuleProtocol, Construct> {
    match word {
        "tcp" | "6" => Ok(RuleProtocol::Tcp),
        "udp" | "17" => Ok(RuleProtocol::Udp),
        "icmp" | "icmp6" | "esp" | "ah" | "gre" | "igmp" => Ok(RuleProtocol::Other),
        _ if word.parse::<u8>().is_ok() => Ok(RuleProtocol::Other),
        _ => Err(Construct::UnrecognizedSyntax),
    }
}

fn endpoint(cursor: &mut Cursor<'_>) -> Result<Endpoint, Construct> {
    let address = address(cursor)?;
    let port = if cursor
        .next_if(|token| *token == Token::Word("port"))
        .is_some()
    {
        Some(port(cursor)?)
    } else {
        None
    };
    Ok(Endpoint { address, port })
}

fn address(cursor: &mut Cursor<'_>) -> Result<Address, Construct> {
    let (negated, word) = negated_word(cursor)?;
    match word {
        "any" | "self" if negated => Err(Construct::UnrecognizedSyntax),
        "any" => Ok(Address::Any),
        "self" => Ok(Address::SelfHost),
        _ if word.starts_with('<') => Err(Construct::Table),
        _ if word.starts_with('(') => Err(Construct::DynamicAddress),
        _ => Cidr::parse(word)
            .map(|net| Address::Net { net, negated })
            .ok_or(Construct::UnrecognizedSyntax),
    }
}

fn port(cursor: &mut Cursor<'_>) -> Result<PortMatch, Construct> {
    let first = next_word(cursor)?;
    if let Some(operator) = Operator::parse(first) {
        return Ok(PortMatch::Compare(operator, number(next_word(cursor)?)?));
    }
    if let Some((low, high)) = first.split_once(':') {
        return Ok(PortMatch::Range {
            kind: RangeKind::Inclusive,
            low: number(low)?,
            high: number(high)?,
        });
    }
    let low = number(first)?;
    let kind = match cursor.peek() {
        Some(Token::Word(word)) => RangeKind::parse(word),
        _ => None,
    };
    let Some(kind) = kind else {
        return Ok(PortMatch::Compare(Operator::Eq, low));
    };
    cursor.next();
    Ok(PortMatch::Range {
        kind,
        low,
        high: number(next_word(cursor)?)?,
    })
}

fn number(word: &str) -> Result<u16, Construct> {
    port_number(word).ok_or(Construct::UnrecognizedSyntax)
}
