//! Value types for single rule fields: networks, ports and TCP flags.

use std::cmp::Ordering;
use std::net::IpAddr;

/// An address with a prefix length. A bare address has the full length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Cidr {
    address: IpAddr,
    prefix: u8,
}

impl Cidr {
    pub(super) fn parse(text: &str) -> Option<Self> {
        let (address, prefix) = match text.split_once('/') {
            Some((address, prefix)) => (address, Some(prefix.parse::<u8>().ok()?)),
            None => (text, None),
        };
        let address: IpAddr = address.parse().ok()?;
        let longest = if address.is_ipv4() { 32 } else { 128 };
        let prefix = prefix.unwrap_or(longest);
        (prefix <= longest).then_some(Self { address, prefix })
    }

    pub(super) fn is_ipv4(self) -> bool {
        self.address.is_ipv4()
    }

    /// Whether `ip` is inside the network. Addresses of the other family are not.
    pub(super) fn contains(self, ip: IpAddr) -> bool {
        match (self.address, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let shift = 32 - u32::from(self.prefix);
                u32::from(net).checked_shr(shift).unwrap_or(0)
                    == u32::from(ip).checked_shr(shift).unwrap_or(0)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let shift = 128 - u32::from(self.prefix);
                u128::from(net).checked_shr(shift).unwrap_or(0)
                    == u128::from(ip).checked_shr(shift).unwrap_or(0)
            }
            _ => false,
        }
    }
}

/// The comparison operators pf prints before a port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Operator {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

impl Operator {
    pub(super) fn parse(word: &str) -> Option<Self> {
        Some(match word {
            "=" => Self::Eq,
            "!=" => Self::Ne,
            "<" => Self::Lt,
            "<=" => Self::Le,
            ">" => Self::Gt,
            ">=" => Self::Ge,
            _ => return None,
        })
    }

    fn accepts(self, ordering: Ordering) -> bool {
        match self {
            Self::Eq => ordering.is_eq(),
            Self::Ne => ordering.is_ne(),
            Self::Lt => ordering.is_lt(),
            Self::Le => ordering.is_le(),
            Self::Gt => ordering.is_gt(),
            Self::Ge => ordering.is_ge(),
        }
    }
}

/// How the two ends of a port range are read: `a:b` includes both, `a >< b`
/// excludes both, `a <> b` is everything outside `a..=b`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RangeKind {
    Inclusive,
    Exclusive,
    Outside,
}

impl RangeKind {
    pub(super) fn parse(word: &str) -> Option<Self> {
        match word {
            "><" => Some(Self::Exclusive),
            "<>" => Some(Self::Outside),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PortMatch {
    Compare(Operator, u16),
    Range {
        kind: RangeKind,
        low: u16,
        high: u16,
    },
}

impl PortMatch {
    pub(super) fn contains(self, port: u16) -> bool {
        match self {
            Self::Compare(operator, value) => operator.accepts(port.cmp(&value)),
            Self::Range { kind, low, high } => match kind {
                RangeKind::Inclusive => (low..=high).contains(&port),
                RangeKind::Exclusive => port > low && port < high,
                RangeKind::Outside => port < low || port > high,
            },
        }
    }
}

/// Service names `pfctl` prints in place of a port number. A name that is not
/// listed makes the rule unmodeled instead of guessing its number.
const SERVICES: &[(&str, u16)] = &[
    ("ftp", 21),
    ("ssh", 22),
    ("telnet", 23),
    ("smtp", 25),
    ("domain", 53),
    ("bootps", 67),
    ("bootpc", 68),
    ("http", 80),
    ("pop3", 110),
    ("ntp", 123),
    ("netbios-ssn", 139),
    ("imap", 143),
    ("snmp", 161),
    ("ldap", 389),
    ("https", 443),
    ("microsoft-ds", 445),
    ("submission", 587),
    ("imaps", 993),
    ("pop3s", 995),
    ("mdns", 5353),
];

pub(super) fn port_number(word: &str) -> Option<u16> {
    word.parse().ok().or_else(|| {
        SERVICES
            .iter()
            .find(|(name, _)| *name == word)
            .map(|&(_, port)| port)
    })
}

/// A `flags set/mask` condition: a packet matches when its flags, cut down to
/// the mask, equal the set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct TcpFlags {
    set: u8,
    mask: u8,
}

/// The flags of the first packet of a connection: SYN alone.
const SYN: u8 = 0x02;

impl TcpFlags {
    pub(super) fn parse(text: &str) -> Option<Self> {
        if text == "any" {
            return Some(Self { set: 0, mask: 0 });
        }
        let (set, mask) = match text.split_once('/') {
            Some((set, mask)) => (bits(set)?, bits(mask)?),
            None => (bits(text)?, u8::MAX),
        };
        (set & !mask == 0).then_some(Self { set, mask })
    }

    /// Whether the opening SYN of a new connection matches.
    pub(super) fn matches_new_connection(self) -> bool {
        SYN & self.mask == self.set
    }
}

fn bits(letters: &str) -> Option<u8> {
    letters.chars().try_fold(0u8, |bits, letter| {
        let bit = match letter {
            'F' => 0x01,
            'S' => SYN,
            'R' => 0x04,
            'P' => 0x08,
            'A' => 0x10,
            'U' => 0x20,
            'E' => 0x40,
            'W' => 0x80,
            _ => return None,
        };
        Some(bits | bit)
    })
}
