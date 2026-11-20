//! Port, interface and transport matches from the nftables JSON snapshot.

use std::collections::HashMap;

use serde::Deserialize;
use serde::de::IgnoredAny;

use crate::socket::Protocol;

pub(super) type SetIndex<'a> = HashMap<(&'a str, &'a str, &'a str), &'a NamedSet>;

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub(super) enum NamedSetEntry {
    Supported(NamedSet),
    Other(IgnoredAny),
}

#[derive(Debug, Deserialize)]
pub(super) struct NamedSet {
    family: String,
    table: String,
    name: String,
    #[serde(rename = "type")]
    kind: SetKind,
    #[serde(default, rename = "flags")]
    _flags: Vec<SetFlag>,
    #[serde(default)]
    elem: Vec<Literal>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SetKind {
    InetService,
    Ifname,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SetFlag {
    Constant,
    Interval,
}

impl NamedSet {
    pub(super) fn key(&self) -> (&str, &str, &str) {
        (&self.family, &self.table, &self.name)
    }

    fn contains(&self, value: MatchValue<'_>) -> Option<bool> {
        match (&self.kind, value) {
            (SetKind::InetService, MatchValue::Port(_))
            | (SetKind::Ifname, MatchValue::Interface(_)) => value.in_set(&self.elem),
            _ => None,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Comparison {
    op: Operator,
    left: Field,
    right: Right,
}

#[derive(Debug, Deserialize)]
enum Operator {
    #[serde(rename = "==")]
    Equal,
    #[serde(rename = "!=")]
    NotEqual,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
enum Field {
    Meta { key: String },
    Payload { protocol: Header, field: String },
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Header {
    Tcp,
    Udp,
    Th,
}

#[derive(Debug, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
enum Right {
    Set { set: Vec<Literal> },
    One(Literal),
}

#[derive(Debug, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
enum Literal {
    Number(u16),
    Name(String),
    Range { range: [u16; 2] },
    Other(IgnoredAny),
}

#[derive(Clone, Copy)]
enum MatchValue<'a> {
    Port(u16),
    Interface(&'a str),
    Transport(Protocol),
}

impl Comparison {
    pub(super) fn matches<'a>(
        &self,
        protocol: Protocol,
        port: u16,
        interface: &str,
        named_set: impl FnOnce(&str) -> Option<&'a NamedSet>,
    ) -> Option<bool> {
        let value = match &self.left {
            Field::Meta { key } if key == "iifname" => MatchValue::Interface(interface),
            Field::Meta { key } if key == "l4proto" => MatchValue::Transport(protocol),
            Field::Payload {
                protocol: header,
                field,
            } if field == "dport" => {
                // Negation applies to the port comparison, after the header check.
                if matches!(
                    (header, protocol),
                    (Header::Tcp, Protocol::Udp) | (Header::Udp, Protocol::Tcp)
                ) {
                    return Some(false);
                }
                MatchValue::Port(port)
            }
            _ => return None,
        };
        let matched = match &self.right {
            Right::Set { set } => value.in_set(set),
            Right::One(literal) => {
                if let Literal::Name(reference) = literal
                    && let Some(name) = reference.strip_prefix('@')
                {
                    let member = named_set(name)?.contains(value)?;
                    // nft also prints a quoted, literal iifname of this form as "@name".
                    if let MatchValue::Interface(interface) = value
                        && member != (reference == interface)
                    {
                        return None;
                    }
                    Some(member)
                } else {
                    value.matches(literal)
                }
            }
        }?;
        Some(matched != matches!(self.op, Operator::NotEqual))
    }
}

impl MatchValue<'_> {
    fn in_set(self, elements: &[Literal]) -> Option<bool> {
        // An unsupported element makes the comparison unknown, even if another one matches.
        elements.iter().try_fold(false, |found, literal| {
            self.matches(literal).map(|matched| found || matched)
        })
    }

    fn matches(self, literal: &Literal) -> Option<bool> {
        match (self, literal) {
            (Self::Port(port), Literal::Number(number)) => Some(port == *number),
            (
                Self::Port(port),
                Literal::Range {
                    range: [start, end],
                },
            ) if start <= end => Some((*start..=*end).contains(&port)),
            (Self::Interface(interface), Literal::Name(name))
                if !name.is_empty() && !name.contains(['*', '\\', '\0']) =>
            {
                Some(interface == name)
            }
            (Self::Transport(protocol), Literal::Number(6)) => Some(protocol == Protocol::Tcp),
            (Self::Transport(protocol), Literal::Number(17)) => Some(protocol == Protocol::Udp),
            (Self::Transport(protocol), Literal::Name(name)) => match name.as_str() {
                "tcp" => Some(protocol == Protocol::Tcp),
                "udp" => Some(protocol == Protocol::Udp),
                _ => None,
            },
            _ => None,
        }
    }
}
