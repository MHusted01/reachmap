//! Port, interface and transport matches from the nftables JSON snapshot.

use std::collections::HashMap;
use std::net::Ipv4Addr;

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
    #[serde(rename = "in")]
    In,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
enum Field {
    Meta { key: String },
    Payload { protocol: Header, field: String },
    Ct { key: String },
    Fib { result: String, flags: Vec<String> },
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Header {
    Tcp,
    Udp,
    Th,
    Ip,
}

#[derive(Debug, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
enum Right {
    Set { set: Vec<Literal> },
    Flags(Vec<String>),
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
    Address(Ipv4Addr),
    Local(bool),
}

#[derive(Clone, Copy)]
pub(super) struct Packet<'a> {
    pub(super) protocol: Protocol,
    pub(super) port: u16,
    pub(super) ingress: &'a str,
    pub(super) path: Option<PathPacket<'a>>,
}

#[derive(Clone, Copy)]
pub(super) struct PathPacket<'a> {
    pub(super) source: Ipv4Addr,
    pub(super) destination: Ipv4Addr,
    pub(super) egress: Option<&'a str>,
    pub(super) local_destination: bool,
    pub(super) local_source: Option<bool>,
    pub(super) new_connection: bool,
    pub(super) allow_dnat: bool,
}

impl Comparison {
    pub(super) fn matches<'a>(
        &self,
        packet: Packet<'_>,
        named_set: impl FnOnce(&str) -> Option<&'a NamedSet>,
    ) -> Option<bool> {
        if let Field::Ct { key } = &self.left {
            if key == "state"
                && packet.path.is_some_and(|path| path.new_connection)
                && let (Operator::In, Right::Flags(flags)) = (&self.op, &self.right)
                && flags.iter().all(|flag| {
                    matches!(
                        flag.as_str(),
                        "new" | "established" | "related" | "invalid" | "untracked"
                    )
                })
            {
                return Some(flags.iter().any(|flag| flag == "new"));
            }
            return None;
        }
        if matches!(self.op, Operator::In) {
            return None;
        }
        let value = match &self.left {
            Field::Meta { key } if key == "iifname" => MatchValue::Interface(packet.ingress),
            Field::Meta { key } if key == "oifname" => MatchValue::Interface(packet.path?.egress?),
            Field::Meta { key } if key == "l4proto" => MatchValue::Transport(packet.protocol),
            Field::Payload {
                protocol: Header::Ip,
                field,
            } => {
                let path = packet.path?;
                MatchValue::Address(match field.as_str() {
                    "saddr" => path.source,
                    "daddr" => path.destination,
                    _ => return None,
                })
            }
            Field::Fib { result, flags } if result == "type" => {
                let path = packet.path?;
                MatchValue::Local(match flags.as_slice() {
                    [flag] if flag == "daddr" => path.local_destination,
                    [flag] if flag == "saddr" => path.local_source?,
                    _ => return None,
                })
            }
            Field::Payload {
                protocol: header,
                field,
            } if field == "dport" => {
                // Negation applies to the port comparison, after the header check.
                if matches!(
                    (header, packet.protocol),
                    (Header::Tcp, Protocol::Udp) | (Header::Udp, Protocol::Tcp)
                ) {
                    return Some(false);
                }
                MatchValue::Port(packet.port)
            }
            _ => return None,
        };
        let matched = match &self.right {
            Right::Flags(_) => None,
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
            (Self::Address(address), Literal::Name(other)) => {
                Some(address == other.parse::<Ipv4Addr>().ok()?)
            }
            (Self::Local(local), Literal::Name(kind)) if kind == "local" => Some(local),
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
