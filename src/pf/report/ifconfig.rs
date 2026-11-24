//! Parsing `/sbin/ifconfig -a` output into interface-to-IP address mappings.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::sanitize::sanitize;

/// Parsed metadata and assigned IP addresses for one macOS interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct InterfaceInfo {
    pub(super) is_up: bool,
    pub(super) is_loopback: bool,
    pub(super) is_inactive: bool,
    pub(super) addresses: BTreeSet<IpAddr>,
}

impl Default for InterfaceInfo {
    fn default() -> Self {
        Self {
            is_up: true,
            is_loopback: false,
            is_inactive: false,
            addresses: BTreeSet::new(),
        }
    }
}

/// Interface-to-IP address map parsed from `/sbin/ifconfig -a`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct MacosInterfaces {
    pub(super) interfaces: BTreeMap<String, InterfaceInfo>,
}

impl MacosInterfaces {
    pub(super) fn active_interfaces(&self) -> Vec<(&String, &InterfaceInfo)> {
        self.interfaces
            .iter()
            .filter(|(_, info)| info.is_up && !info.is_inactive)
            .collect()
    }
}

/// Parses `ifconfig -a` output into interface addresses and link states.
#[must_use]
pub fn parse_ifconfig(text: &str) -> MacosInterfaces {
    let mut interfaces: BTreeMap<String, InterfaceInfo> = BTreeMap::new();
    let mut current: Option<String> = None;
    for line in text.lines() {
        if line.is_empty() {
            continue;
        }
        if !line.starts_with(|ch: char| ch.is_ascii_whitespace()) {
            let parsed = line
                .split_once(':')
                .map(|(name, rest)| (sanitize(name.trim()), rest))
                .filter(|(name, _)| !name.is_empty());
            current = parsed.as_ref().map(|(name, _)| name.clone());
            if let Some((name, rest)) = parsed {
                let (is_up, is_loopback) = parse_flags(rest);
                let info = interfaces.entry(name).or_default();
                info.is_up = is_up;
                info.is_loopback |= is_loopback;
            }
            continue;
        }
        let Some(iface) = current.as_ref() else {
            continue;
        };
        let Some(info) = interfaces.get_mut(iface) else {
            continue;
        };
        let trimmed = line.trim_start();
        if let Some(rest) = trimmed.strip_prefix("inet ") {
            if let Some(token) = rest.split_whitespace().next()
                && let Ok(ip) = token.parse::<Ipv4Addr>()
            {
                let addr = IpAddr::V4(ip);
                if addr.is_loopback() {
                    info.is_loopback = true;
                }
                info.addresses.insert(addr);
            }
        } else if let Some(rest) = trimmed.strip_prefix("inet6 ") {
            if let Some(token) = rest.split_whitespace().next() {
                let ip_part = token.split('%').next().unwrap_or(token);
                if let Ok(ip) = ip_part.parse::<Ipv6Addr>() {
                    let addr = IpAddr::V6(ip);
                    if addr.is_loopback() {
                        info.is_loopback = true;
                    }
                    info.addresses.insert(addr);
                }
            }
        } else if let Some(rest) = trimmed.strip_prefix("status:") {
            let status = rest.trim();
            if status.eq_ignore_ascii_case("inactive") {
                info.is_inactive = true;
            } else if status.eq_ignore_ascii_case("active") {
                info.is_inactive = false;
            }
        }
    }
    MacosInterfaces { interfaces }
}

fn parse_flags(rest: &str) -> (bool, bool) {
    let Some(flags_pos) = rest.find("flags=") else {
        return (true, false);
    };
    let after = &rest[flags_pos..];
    let Some(open) = after.find('<') else {
        return (true, false);
    };
    let Some(close) = after[open + 1..].find('>') else {
        return (true, false);
    };
    let inner = &after[open + 1..open + 1 + close];
    let is_up = inner.split(',').any(|flag| flag.trim() == "UP");
    let is_loopback = inner.split(',').any(|flag| flag.trim() == "LOOPBACK");
    (is_up, is_loopback)
}
