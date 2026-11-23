//! Endpoint, port, protocol and interface parsing from a token cursor.

use crate::sanitize::sanitize;

use super::super::fields::{Cidr, Operator, PortMatch, RangeKind, port_number};
use super::super::lex::Token;
use super::super::model::{
    Address, Construct, Endpoint, InterfaceMatch, RuleProtocol, is_group_name,
};
use super::Cursor;

pub(super) fn next_word<'a>(cursor: &mut Cursor<'a>) -> Result<&'a str, Construct> {
    match cursor.next() {
        Some(Token::Word(word)) => Ok(word),
        Some(Token::Open | Token::Close | Token::Comma) => Err(Construct::List),
        Some(Token::Quoted(_)) | None => Err(Construct::UnrecognizedSyntax),
    }
}

pub(super) fn interface(cursor: &mut Cursor<'_>) -> Result<InterfaceMatch, Construct> {
    let (negated, name) = negated_word(cursor)?;
    if name.starts_with('(') {
        return Err(Construct::DynamicAddress);
    }
    if sanitize(name) != name {
        return Err(Construct::UnrecognizedSyntax);
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

pub(super) fn protocol(word: &str) -> Result<RuleProtocol, Construct> {
    match word {
        "tcp" | "6" => Ok(RuleProtocol::Tcp),
        "udp" | "17" => Ok(RuleProtocol::Udp),
        "icmp" | "icmp6" | "esp" | "ah" | "gre" | "igmp" => Ok(RuleProtocol::Other),
        _ if word.parse::<u8>().is_ok() => Ok(RuleProtocol::Other),
        _ => Err(Construct::UnrecognizedSyntax),
    }
}

pub(super) fn endpoint(cursor: &mut Cursor<'_>) -> Result<Endpoint, Construct> {
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

pub(super) fn address(cursor: &mut Cursor<'_>) -> Result<Address, Construct> {
    let (negated, word) = negated_word(cursor)?;
    match word {
        "any" | "self" if negated => Err(Construct::UnrecognizedSyntax),
        "any" => Ok(Address::Any),
        "self" => Ok(Address::SelfHost),
        "urpf-failed" => Err(Construct::UrpfFailed),
        "no-route" => Err(Construct::NoRoute),
        _ if word.starts_with('<') => Err(Construct::Table),
        _ if word.starts_with('(') => Err(Construct::DynamicAddress),
        _ => Cidr::parse(word)
            .map(|net| Address::Net { net, negated })
            .ok_or(Construct::UnrecognizedSyntax),
    }
}

pub(super) fn port(cursor: &mut Cursor<'_>) -> Result<PortMatch, Construct> {
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
