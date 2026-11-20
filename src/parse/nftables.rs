//! The subset of `nft -j list ruleset` that can be evaluated for local IP input.

use serde::Deserialize;
use serde::de::IgnoredAny;
use thiserror::Error;

use crate::nftables::InputVerdict;
use crate::socket::{AddressFamily, Protocol};

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
    policy: Option<Action>,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Action {
    Accept,
    Drop,
}

impl Action {
    fn verdict(self, reason: &'static str) -> InputVerdict {
        match self {
            Self::Accept => InputVerdict::Accept { reason },
            Self::Drop => InputVerdict::Drop { reason },
        }
    }
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

impl Ruleset {
    pub(crate) fn input(&self, family: AddressFamily) -> Result<InputChain<'_>, &'static str> {
        let family = match family {
            AddressFamily::Ipv4 => "ip",
            AddressFamily::Ipv6 => "ip6",
        };
        let mut selected = None;
        for chain in self.nftables.iter().filter_map(|entry| match entry {
            Entry::Chain(chain)
                if chain.hook.as_deref() == Some("input")
                    && (chain.family == family || chain.family == "inet") =>
            {
                Some(chain)
            }
            _ => None,
        }) {
            let table = self
                .nftables
                .iter()
                .find_map(|entry| match entry {
                    Entry::Table(table)
                        if table.family == chain.family && table.name == chain.table =>
                    {
                        Some(table)
                    }
                    _ => None,
                })
                .ok_or("input chain's table is missing")?;
            if table.flags.as_ref().is_some_and(TableFlags::dormant) {
                continue;
            }
            // An accept in one base chain still permits a later chain to drop.
            if selected.replace(chain).is_some() {
                return Err("multiple applicable input chains");
            }
        }
        let chain = selected.ok_or("no applicable input chain")?;
        if chain.kind.as_deref() != Some("filter") {
            return Err("unsupported input chain type");
        }
        let policy = chain.policy.ok_or("input chain policy is missing")?;
        let rules = self
            .nftables
            .iter()
            .filter_map(|entry| match entry {
                Entry::Rule(rule)
                    if rule.family == chain.family
                        && rule.table == chain.table
                        && rule.chain == chain.name =>
                {
                    Some(rule)
                }
                _ => None,
            })
            .collect();
        Ok(InputChain { policy, rules })
    }
}

#[derive(Debug)]
pub(crate) struct InputChain<'a> {
    policy: Action,
    rules: Vec<&'a Rule>,
}

impl InputChain<'_> {
    pub(crate) fn evaluate(&self, protocol: Protocol, port: u16, interface: &str) -> InputVerdict {
        self.rules
            .iter()
            .find_map(|rule| rule.evaluate(protocol, port, interface))
            .unwrap_or_else(|| self.policy.verdict("chain policy"))
    }
}

impl Rule {
    /// `None` means a known condition rules this rule out. An unsupported
    /// statement reached during evaluation can also contain a verdict.
    fn evaluate(&self, protocol: Protocol, port: u16, interface: &str) -> Option<InputVerdict> {
        for (index, statement) in self.expr.iter().enumerate() {
            let last = index + 1 == self.expr.len();
            match statement {
                Statement::Known(Expression::Match(comparison)) => {
                    match comparison.matches(protocol, port, interface) {
                        Some(true) => continue,
                        Some(false) => return None,
                        None => break,
                    }
                }
                Statement::Known(Expression::Accept(())) if last => {
                    return Some(Action::Accept.verdict("matching rule"));
                }
                Statement::Known(Expression::Drop(())) if last => {
                    return Some(Action::Drop.verdict("matching rule"));
                }
                _ => break,
            }
        }
        Some(InputVerdict::Unknown {
            reason: "unsupported input rule",
        })
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
