//! What a parsed `pfctl -sr` line says, before it meets any traffic.

use std::fmt;

use crate::sanitize::sanitize;
use crate::socket::AddressFamily;

use super::fields::{Cidr, PortMatch, TcpFlags};

/// Something pf supports that this evaluator does not model. A rule that uses
/// one can only be answered with "unknown" when the rest of it could match.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Construct {
    Table,
    User,
    Group,
    OsFingerprint,
    Translation,
    Normalization,
    RouteTo,
    ReplyTo,
    Tagged,
    ReceivedOn,
    InterfaceGroup,
    DynamicAddress,
    UrpfFailed,
    NoRoute,
    List,
    Probability,
    StateLimit,
    TcpEcnFlags,
    Tos,
    UnreassembledFragment,
    UnrecognizedSyntax,
    UnparseableRule,
    MissingAnchor,
    AnchorTooDeep,
    SourceAddress,
    SourcePort,
}

impl fmt::Display for Construct {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Table => "table",
            Self::User => "user condition",
            Self::Group => "group condition",
            Self::OsFingerprint => "os fingerprint",
            Self::Translation => "translation rule",
            Self::Normalization => "normalization rule",
            Self::RouteTo => "route-to option",
            Self::ReplyTo => "reply-to option",
            Self::Tagged => "tagged condition",
            Self::ReceivedOn => "received-on condition",
            Self::InterfaceGroup => "interface group",
            Self::DynamicAddress => "dynamic address",
            Self::UrpfFailed => "urpf-failed condition",
            Self::NoRoute => "no-route condition",
            Self::List => "list",
            Self::Probability => "probability",
            Self::StateLimit => "state limit",
            Self::TcpEcnFlags => "tcp flags (ECN)",
            Self::Tos => "tos condition",
            Self::UnreassembledFragment => "unreassembled UDP fragment",
            Self::UnrecognizedSyntax => "unrecognized syntax",
            Self::UnparseableRule => "unparseable text",
            Self::MissingAnchor => "missing anchor ruleset",
            Self::AnchorTooDeep => "anchor nesting too deep",
            Self::SourceAddress => "source address restriction",
            Self::SourcePort => "source port restriction",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Action {
    Pass,
    Block,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Direction {
    In,
    Out,
}

/// The protocol a rule names. `Other` covers every protocol that is not TCP or
/// UDP, so such a rule never matches a listening socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RuleProtocol {
    Tcp,
    Udp,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct InterfaceMatch {
    pub name: String,
    pub negated: bool,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(super) enum Address {
    #[default]
    Any,
    SelfHost,
    Net {
        net: Cidr,
        negated: bool,
    },
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(super) struct Endpoint {
    pub address: Address,
    pub port: Option<PortMatch>,
}

/// An anchor reference: keeps the raw key for [`super::AnchorRulesets`] lookup
/// and a sanitized display string so diagnostics and `Debug` never emit raw
/// control characters.
#[derive(Clone, PartialEq, Eq)]
pub(super) struct AnchorName {
    lookup: String,
    display: String,
}

impl AnchorName {
    pub(super) fn new(raw: &str) -> Self {
        Self {
            lookup: raw.to_string(),
            display: sanitize(raw),
        }
    }

    pub(super) fn lookup(&self) -> &str {
        &self.lookup
    }

    pub(super) fn display(&self) -> &str {
        &self.display
    }

    /// Resolves `self` relative to `parent`, matching Apple PF's
    /// `pf_anchor_setup`: only leading `../` segments step up the parent path,
    /// while embedded `..`, `.`, `./`, and `//` stay literal.
    pub(super) fn resolve(&self, parent: Option<&Self>) -> Option<Self> {
        if let Some(absolute) = self.lookup.strip_prefix('/') {
            let trimmed = absolute.trim_start_matches('/');
            return (!trimmed.is_empty()).then(|| Self::new(trimmed));
        }
        if self.lookup.is_empty() {
            return None;
        }
        let mut base: Vec<&str> = match parent {
            Some(parent) => {
                let prefix = parent.lookup.strip_suffix("/*").unwrap_or(&parent.lookup);
                if prefix == "*" {
                    Vec::new()
                } else {
                    prefix.split('/').filter(|part| !part.is_empty()).collect()
                }
            }
            None => Vec::new(),
        };
        let mut rest = self.lookup.as_str();
        while let Some(next) = rest.strip_prefix("../") {
            base.pop()?;
            rest = next;
        }
        if rest.is_empty() || rest == ".." {
            return None;
        }
        if base.is_empty() {
            Some(Self::new(rest))
        } else {
            Some(Self::new(&format!("{}/{rest}", base.join("/"))))
        }
    }

    pub(super) fn is_wildcard(&self) -> bool {
        self.lookup == "*" || self.lookup.ends_with("/*")
    }
}

impl fmt::Debug for AnchorName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.display, f)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TargetPort {
    Inherit,
    Match(PortMatch),
    Any,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct TargetEndpoint {
    pub address: Option<Address>,
    pub port: TargetPort,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum BinatTarget {
    None,
    Any,
    Address(Address),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum TranslationTarget {
    None,
    Any,
    Endpoint(TargetEndpoint),
    Binat(BinatTarget),
}

/// Every condition of a rule that the evaluator understands, plus the first
/// construct it does not. Parsing stops at that construct, so the conditions
/// after it are not recorded: the rule then matches at least as often as in pf.
#[derive(Debug, Default)]
pub(super) struct Criteria {
    pub direction: Option<Direction>,
    pub quick: bool,
    pub interface: Option<InterfaceMatch>,
    pub family: Option<AddressFamily>,
    pub protocol: Option<RuleProtocol>,
    pub source: Option<Endpoint>,
    pub destination: Option<Endpoint>,
    pub saw_all: bool,
    pub flags: Option<TcpFlags>,
    pub unsupported: Option<Construct>,
    pub effect_unsupported: Option<Construct>,
}

#[derive(Debug)]
pub(super) enum Kind {
    Filter {
        action: Action,
        criteria: Criteria,
    },
    Anchor {
        name: AnchorName,
        criteria: Criteria,
    },
    Translation {
        criteria: Criteria,
        target: TranslationTarget,
    },
    ScrubReassemble {
        criteria: Criteria,
    },
    NoScrub {
        criteria: Criteria,
    },
    ScrubOther {
        criteria: Criteria,
    },
    ScrubAnchor {
        name: AnchorName,
        criteria: Criteria,
    },
    Unparseable,
}

#[derive(Debug)]
pub(super) struct Entry {
    pub line: usize,
    pub kind: Kind,
}

/// One interface of a `set skip on` statement and the line that named it.
#[derive(Debug)]
pub(super) struct Skip {
    pub line: usize,
    pub name: String,
}

/// A parsed pf ruleset, in the normalized form `pfctl -sr` prints, possibly
/// with `set skip on` lines. Anchor rulesets are separate values.
#[derive(Debug, Default)]
pub struct Ruleset {
    pub(super) skip: Vec<Skip>,
    pub(super) entries: Vec<Entry>,
}

/// macOS interface names end in a unit number (`en0`, `lo0`, `utun3`). A name
/// without one, such as `egress` or `lo`, is an interface group.
pub(super) fn is_group_name(name: &str) -> bool {
    !name.ends_with(|character: char| character.is_ascii_digit())
}
