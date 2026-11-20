//! The subset of `nft -j list ruleset` that can be evaluated for local IP input.

use serde::Deserialize;
use serde::de::IgnoredAny;
use thiserror::Error;

use crate::socket::{AddressFamily, Protocol};

mod input;
pub(crate) use input::InputHook;

#[derive(Debug, Error)]
pub(crate) enum RulesetError {
    #[error("could not understand the JSON from `nft -j list ruleset`")]
    Json(#[from] serde_json::Error),
    #[error("unsupported nftables JSON schema version {0}")]
    Schema(u32),
}

#[derive(Debug, Deserialize)]
pub(crate) struct Ruleset {
    nftables: Vec<Entry>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Entry {
    Metainfo {
        json_schema_version: u32,
    },
    Table(Table),
    Chain(Chain),
    Rule(Rule),
    #[serde(
        rename = "set",
        alias = "map",
        alias = "element",
        alias = "flowtable",
        alias = "counter",
        alias = "quota",
        alias = "limit",
        alias = "ct helper",
        alias = "ct timeout",
        alias = "ct expectation",
        alias = "synproxy",
        alias = "secmark"
    )]
    Other(IgnoredAny),
}

#[derive(Debug, Deserialize)]
struct Table {
    family: String,
    name: String,
    flags: Option<TableFlags>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum TableFlags {
    One(TableFlag),
    Many(Vec<TableFlag>),
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum TableFlag {
    Dormant,
    Owner,
    Persist,
}

impl TableFlags {
    fn dormant(&self) -> bool {
        match self {
            Self::One(flag) => *flag == TableFlag::Dormant,
            Self::Many(flags) => flags.contains(&TableFlag::Dormant),
        }
    }
}

#[derive(Debug, Deserialize)]
struct Chain {
    family: String,
    table: String,
    name: String,
    hook: Option<String>,
    #[serde(rename = "type")]
    kind: Option<String>,
    prio: Option<i32>,
    policy: Option<Policy>,
}

type ChainKey<'a> = (&'a str, &'a str, &'a str);

impl Chain {
    fn key(&self) -> ChainKey<'_> {
        (&self.family, &self.table, &self.name)
    }
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Action {
    Accept,
    Drop,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum Policy {
    Known(Action),
    Unsupported(IgnoredAny),
}

#[derive(Debug, Deserialize)]
struct Rule {
    family: String,
    table: String,
    chain: String,
    expr: Vec<Statement>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum Statement {
    Known(Expression),
    Other(IgnoredAny),
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Expression {
    Match(Comparison),
    Accept(()),
    Drop(()),
    Reject(Option<RejectReply>),
    #[serde(rename = "counter", alias = "log")]
    Passive(IgnoredAny),
    Jump(ChainTarget),
    Goto(ChainTarget),
    Return(()),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChainTarget {
    target: String,
}

enum RuleAction<'a> {
    Verdict(Action, &'static str),
    Jump(&'a str),
    Goto(&'a str),
    Return,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RejectReply {
    #[serde(rename = "type")]
    kind: Option<RejectKind>,
    #[serde(rename = "expr")]
    _code: Option<IgnoredAny>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RejectKind {
    Icmp,
    Icmpv6,
    Icmpx,
    #[serde(rename = "tcp reset")]
    TcpReset,
}

impl RejectReply {
    fn applies_to(&self, family: AddressFamily, protocol: Protocol) -> bool {
        match self.kind {
            None | Some(RejectKind::Icmpx) => true,
            Some(RejectKind::Icmp) => family == AddressFamily::Ipv4,
            Some(RejectKind::Icmpv6) => family == AddressFamily::Ipv6,
            Some(RejectKind::TcpReset) => protocol == Protocol::Tcp,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Comparison {
    op: String,
    left: Field,
    right: Literal,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
enum Field {
    Meta { key: String },
    Payload { protocol: Protocol, field: String },
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum Literal {
    Port(u16),
    Name(String),
}

pub(crate) fn parse_ruleset(json: &str) -> Result<Ruleset, RulesetError> {
    let rules: Ruleset = serde_json::from_str(json)?;
    for entry in &rules.nftables {
        if let Entry::Metainfo {
            json_schema_version,
        } = entry
            && *json_schema_version != 1
        {
            return Err(RulesetError::Schema(*json_schema_version));
        }
    }
    Ok(rules)
}

impl Rule {
    fn chain_key(&self) -> ChainKey<'_> {
        (&self.family, &self.table, &self.chain)
    }

    /// `Ok(None)` means evaluation can proceed to the next rule. An
    /// unsupported statement reached during evaluation can contain a verdict.
    fn evaluate(
        &self,
        family: AddressFamily,
        protocol: Protocol,
        port: u16,
        interface: &str,
    ) -> Result<Option<RuleAction<'_>>, &'static str> {
        let mut has_passive_statement = false;
        for (index, statement) in self.expr.iter().enumerate() {
            let last = index + 1 == self.expr.len();
            match statement {
                Statement::Known(Expression::Match(comparison)) => {
                    match comparison.matches(protocol, port, interface) {
                        Some(true) => continue,
                        Some(false) => return Ok(None),
                        None => return Err("unsupported input rule"),
                    }
                }
                Statement::Known(Expression::Passive(_)) => {
                    has_passive_statement = true;
                }
                Statement::Known(Expression::Accept(())) if last => {
                    return Ok(Some(RuleAction::Verdict(Action::Accept, "matching rule")));
                }
                Statement::Known(Expression::Drop(())) if last => {
                    return Ok(Some(RuleAction::Verdict(Action::Drop, "matching rule")));
                }
                Statement::Known(Expression::Reject(reply))
                    if last
                        && reply
                            .as_ref()
                            .is_none_or(|reply| reply.applies_to(family, protocol)) =>
                {
                    return Ok(Some(RuleAction::Verdict(
                        Action::Drop,
                        "matching reject rule",
                    )));
                }
                Statement::Known(Expression::Jump(target)) if last => {
                    return Ok(Some(RuleAction::Jump(&target.target)));
                }
                Statement::Known(Expression::Goto(target)) if last => {
                    return Ok(Some(RuleAction::Goto(&target.target)));
                }
                Statement::Known(Expression::Return(())) if last => {
                    return Ok(Some(RuleAction::Return));
                }
                _ => return Err("unsupported input rule"),
            }
        }
        if has_passive_statement {
            Ok(None)
        } else {
            Err("unsupported input rule")
        }
    }
}

impl Comparison {
    fn matches(&self, protocol: Protocol, port: u16, interface: &str) -> Option<bool> {
        if self.op != "==" {
            return None;
        }
        match (&self.left, &self.right) {
            (Field::Meta { key }, Literal::Name(name))
                if key == "iifname" && !name.is_empty() && !name.contains(['*', '\\', '\0']) =>
            {
                Some(name == interface)
            }
            (
                Field::Payload {
                    protocol: expected,
                    field,
                },
                Literal::Port(destination),
            ) if field == "dport" => Some(*expected == protocol && *destination == port),
            _ => None,
        }
    }
}
