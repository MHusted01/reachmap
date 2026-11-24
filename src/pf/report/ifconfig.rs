//! Parsing `/sbin/ifconfig -a` output into interface-to-IP address mappings.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::sanitize::sanitize;

/// Parsed metadata and assigned IP addresses for one macOS interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct InterfaceInfo {
    pub(super) is_up: bool,
    pub(super) is_loopback: bool,
    pub(super) is_broadcast: bool,
    pub(super) is_inactive: bool,
    pub(super) scope_id: Option<u16>,
    pub(super) addresses: BTreeSet<IpAddr>,
    pub(super) broadcasts: BTreeSet<IpAddr>,
}

impl Default for InterfaceInfo {
    fn default() -> Self {
        Self {
            is_up: true,
            is_loopback: false,
            is_broadcast: false,
            is_inactive: false,
            scope_id: None,
            addresses: BTreeSet::new(),
            broadcasts: BTreeSet::new(),
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

    pub(super) fn interface_for_scope_id(&self, scope_id: u16) -> Option<&str> {
        let mut matches = self
            .interfaces
            .iter()
            .filter(|(_, info)| info.scope_id == Some(scope_id))
            .map(|(name, _)| name.as_str());
        let first = matches.next()?;
        matches.next().is_none().then_some(first)
    }
}

/// Decodes XNU's KAME-style embedded link-local interface index (`fe80:4::...`),
/// returning the canonical IPv6 address and extracted scope ID if present.
pub(super) fn decode_embedded_scope(ip: IpAddr) -> (IpAddr, Option<u16>) {
    if let IpAddr::V6(v6) = ip {
        let mut segs = v6.segments();
        if (segs[0] & 0xffc0) == 0xfe80 && segs[1] != 0 {
            let scope_id = segs[1];
            segs[1] = 0;
            return (IpAddr::V6(Ipv6Addr::from(segs)), Some(scope_id));
        }
    }
    (ip, None)
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
                let (is_up, is_loopback, is_broadcast) = parse_flags(rest);
                let info = interfaces.entry(name).or_default();
                info.is_up = is_up;
                info.is_loopback |= is_loopback;
                info.is_broadcast |= is_broadcast;
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
            parse_inet(rest, info);
        } else if let Some(rest) = trimmed.strip_prefix("inet6 ") {
            parse_inet6(rest, info);
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

fn parse_inet(rest: &str, info: &mut InterfaceInfo) {
    let mut tokens = rest.split_whitespace();
    let Some(ip_token) = tokens.next() else {
        return;
    };
    let Ok(ip) = ip_token.parse::<Ipv4Addr>() else {
        return;
    };
    let addr = IpAddr::V4(ip);
    if addr.is_loopback() {
        info.is_loopback = true;
    }
    info.addresses.insert(addr);

    let mut netmask: Option<u32> = None;
    let mut saw_broadcast = false;
    while let Some(key) = tokens.next() {
        match key {
            "netmask" => {
                if let Some(val) = tokens.next()
                    && let Some(hex) = val.strip_prefix("0x").or_else(|| val.strip_prefix("0X"))
                    && let Ok(parsed) = u32::from_str_radix(hex, 16)
                {
                    netmask = Some(parsed);
                }
            }
            "broadcast" => {
                if let Some(val) = tokens.next()
                    && let Ok(bcast) = val.parse::<Ipv4Addr>()
                {
                    info.is_broadcast = true;
                    info.broadcasts.insert(IpAddr::V4(bcast));
                    saw_broadcast = true;
                }
            }
            _ => {}
        }
    }
    if !saw_broadcast
        && info.is_broadcast
        && let Some(mask) = netmask
        && mask != 0xffff_ffff
        && mask != 0xffff_fffe
    {
        info.broadcasts
            .insert(IpAddr::V4(Ipv4Addr::from(u32::from(ip) | !mask)));
    }
}

fn parse_inet6(rest: &str, info: &mut InterfaceInfo) {
    let mut tokens = rest.split_whitespace();
    let Some(token) = tokens.next() else {
        return;
    };
    let ip_part = token.split('%').next().unwrap_or(token);
    if let Ok(ip) = ip_part.parse::<Ipv6Addr>() {
        let addr = IpAddr::V6(ip);
        if addr.is_loopback() {
            info.is_loopback = true;
        }
        info.addresses.insert(addr);
    }
    while let Some(key) = tokens.next() {
        if key == "scopeid"
            && let Some(val) = tokens.next()
            && let Some(parsed) = parse_scope_id(val)
        {
            info.scope_id = Some(parsed);
        }
    }
}

fn parse_scope_id(val: &str) -> Option<u16> {
    let parsed = if let Some(hex) = val.strip_prefix("0x").or_else(|| val.strip_prefix("0X")) {
        u16::from_str_radix(hex, 16).ok()
    } else {
        val.parse::<u16>().ok()
    };
    parsed.filter(|id| *id != 0)
}

fn parse_flags(rest: &str) -> (bool, bool, bool) {
    let Some(flags_pos) = rest.find("flags=") else {
        return (true, false, false);
    };
    let after = &rest[flags_pos..];
    let Some(open) = after.find('<') else {
        return (true, false, false);
    };
    let Some(close) = after[open + 1..].find('>') else {
        return (true, false, false);
    };
    let inner = &after[open + 1..open + 1 + close];
    let has = |flag_name: &str| inner.split(',').any(|flag| flag.trim() == flag_name);
    (has("UP"), has("LOOPBACK"), has("BROADCAST"))
}
