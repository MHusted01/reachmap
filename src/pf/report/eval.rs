//! Socket-to-interface expansion and pf evaluation helpers for [`super::PfReport`].

use std::collections::BTreeSet;
use std::net::IpAddr;

use crate::sanitize::sanitize;
use crate::socket::{AddressFamily, Protocol};

use super::super::{AnchorRulesets, Ruleset, Traffic, Verdict};
use super::ifconfig::decode_embedded_scope;
use super::{MacosInterfaces, PfInterfaceVerdict, SocketTarget};

const UNVERIFIED_V6ONLY_REASON: &str = "dual-stack acceptance of IPv4 on this IPv6 wildcard socket is not verified \
     (lsof does not report IPV6_V6ONLY)";

pub(super) struct EvalContext<'a> {
    pub(super) rules: &'a Ruleset,
    pub(super) anchors: &'a AnchorRulesets,
    pub(super) listed_interfaces: &'a BTreeSet<String>,
    pub(super) skipped_groups: &'a BTreeSet<String>,
    pub(super) interfaces: Result<&'a MacosInterfaces, &'a str>,
}

impl EvalContext<'_> {
    pub(super) fn evaluate_socket(
        &self,
        socket: &SocketTarget,
    ) -> Vec<(AddressFamily, Vec<PfInterfaceVerdict>)> {
        let endpoint = socket.endpoint;
        let (canonical, embedded_scope) = decode_embedded_scope(endpoint.address.to_canonical());
        if canonical.is_multicast() {
            return vec![(
                family_of(canonical),
                vec![PfInterfaceVerdict {
                    interface: None,
                    outcome: Verdict::Unknown {
                        reason: "multicast destination is not evaluated by pf".to_owned(),
                    },
                }],
            )];
        }
        if canonical.is_unspecified() {
            return match canonical {
                IpAddr::V4(_) => vec![(
                    AddressFamily::Ipv4,
                    self.evaluate_wildcard(AddressFamily::Ipv4, endpoint.protocol, endpoint.port),
                )],
                IpAddr::V6(_) => vec![
                    (
                        AddressFamily::Ipv4,
                        vec![PfInterfaceVerdict {
                            interface: None,
                            outcome: Verdict::Unknown {
                                reason: UNVERIFIED_V6ONLY_REASON.to_owned(),
                            },
                        }],
                    ),
                    (
                        AddressFamily::Ipv6,
                        self.evaluate_wildcard(
                            AddressFamily::Ipv6,
                            endpoint.protocol,
                            endpoint.port,
                        ),
                    ),
                ],
            };
        }
        let family = family_of(canonical);
        let verdicts = if canonical.is_loopback() {
            self.evaluate_loopback(endpoint.protocol, canonical, endpoint.port)
        } else if let Some(zone) = socket.zone.as_deref().filter(|zone| !zone.is_empty()) {
            if zone.chars().all(|ch| ch.is_ascii_digit()) {
                match zone.parse::<u16>().ok().filter(|id| *id != 0) {
                    Some(id) => {
                        self.resolve_scope_id(id, endpoint.protocol, canonical, endpoint.port)
                    }
                    None => vec![PfInterfaceVerdict {
                        interface: None,
                        outcome: Verdict::Unknown {
                            reason: "numeric IPv6 zone identifier could not be mapped to an interface name".to_owned(),
                        },
                    }],
                }
            } else {
                let iface = sanitize(zone);
                vec![PfInterfaceVerdict {
                    interface: Some(iface.clone()),
                    outcome: self.eval_one(&iface, endpoint.protocol, canonical, endpoint.port),
                }]
            }
        } else if let Some(scope_id) = embedded_scope {
            self.resolve_scope_id(scope_id, endpoint.protocol, canonical, endpoint.port)
        } else {
            self.evaluate_specific(endpoint.protocol, canonical, endpoint.port)
        };
        vec![(family, verdicts)]
    }

    fn resolve_scope_id(
        &self,
        scope_id: u16,
        protocol: Protocol,
        destination: IpAddr,
        port: u16,
    ) -> Vec<PfInterfaceVerdict> {
        let map = match self.interfaces {
            Ok(map) => map,
            Err(reason) => {
                return vec![PfInterfaceVerdict {
                    interface: None,
                    outcome: Verdict::Unknown {
                        reason: format!(
                            "could not map IPv6 scope id {scope_id} without interfaces: {}",
                            sanitize(reason)
                        ),
                    },
                }];
            }
        };
        let Some(iface) = map.interface_for_scope_id(scope_id) else {
            return vec![PfInterfaceVerdict {
                interface: None,
                outcome: Verdict::Unknown {
                    reason: format!("no unique interface matches IPv6 scope id {scope_id}"),
                },
            }];
        };
        vec![PfInterfaceVerdict {
            interface: Some(iface.to_owned()),
            outcome: self.eval_one(iface, protocol, destination, port),
        }]
    }

    fn evaluate_loopback(
        &self,
        protocol: Protocol,
        destination: IpAddr,
        port: u16,
    ) -> Vec<PfInterfaceVerdict> {
        let ifaces = match self.interfaces {
            Ok(map) => {
                let mut exact: Vec<String> = map
                    .interfaces
                    .iter()
                    .filter(|(_, info)| info.addresses.contains(&destination))
                    .map(|(name, _)| name.clone())
                    .collect();
                if exact.is_empty() {
                    exact = map
                        .interfaces
                        .iter()
                        .filter(|(_, info)| info.is_loopback)
                        .map(|(name, _)| name.clone())
                        .collect();
                }
                if exact.is_empty() {
                    vec!["lo0".to_owned()]
                } else {
                    exact
                }
            }
            Err(_) => vec!["lo0".to_owned()],
        };
        ifaces
            .into_iter()
            .map(|iface| PfInterfaceVerdict {
                outcome: self.eval_one(&iface, protocol, destination, port),
                interface: Some(iface),
            })
            .collect()
    }

    fn evaluate_specific(
        &self,
        protocol: Protocol,
        destination: IpAddr,
        port: u16,
    ) -> Vec<PfInterfaceVerdict> {
        let map = match self.interfaces {
            Ok(map) => map,
            Err(reason) => {
                return vec![PfInterfaceVerdict {
                    interface: None,
                    outcome: Verdict::Unknown {
                        reason: format!("could not list interfaces: {}", sanitize(reason)),
                    },
                }];
            }
        };
        let holders: Vec<&String> = map
            .interfaces
            .iter()
            .filter(|(_, info)| info.addresses.contains(&destination))
            .map(|(name, _)| name)
            .collect();
        if holders.is_empty() {
            return vec![PfInterfaceVerdict {
                interface: None,
                outcome: Verdict::Unknown {
                    reason: "no interface has this address".to_owned(),
                },
            }];
        }
        // Link-local destinations are scoped to their interface; routable
        // destinations can arrive on any active interface under macOS's
        // weak-host input model.
        let ingress: Vec<&String> = if is_link_local(destination) {
            let active_holders: Vec<&String> = map
                .active_interfaces()
                .into_iter()
                .filter(|(_, info)| info.addresses.contains(&destination))
                .map(|(name, _)| name)
                .collect();
            let candidates = if active_holders.is_empty() {
                holders
            } else {
                active_holders
            };
            if candidates.len() > 1 {
                return vec![PfInterfaceVerdict {
                    interface: None,
                    outcome: Verdict::Unknown {
                        reason:
                            "link-local address matches multiple interfaces without a socket zone"
                                .to_owned(),
                    },
                }];
            }
            candidates
        } else {
            let active: Vec<&String> = map
                .active_interfaces()
                .into_iter()
                .map(|(name, _)| name)
                .collect();
            if active.is_empty() {
                return vec![PfInterfaceVerdict {
                    interface: None,
                    outcome: Verdict::Unknown {
                        reason: "no active interface can receive traffic for this address"
                            .to_owned(),
                    },
                }];
            }
            active
        };
        ingress
            .into_iter()
            .map(|iface| PfInterfaceVerdict {
                interface: Some(iface.clone()),
                outcome: self.eval_one(iface, protocol, destination, port),
            })
            .collect()
    }

    pub(super) fn eval_one(
        &self,
        interface: &str,
        protocol: Protocol,
        destination: IpAddr,
        port: u16,
    ) -> Verdict {
        let traffic = Traffic {
            interface,
            protocol,
            destination,
            port,
            source: None,
        };
        let verdict = self.rules.evaluate(self.anchors, &traffic);
        match verdict {
            Verdict::Block { .. } if !self.skipped_groups.is_empty() => {
                let groups = self
                    .skipped_groups
                    .iter()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ");
                let scope_note = if self.listed_interfaces.contains(interface) {
                    format!("interface group in set skip ({groups}) may exclude {interface}")
                } else {
                    format!(
                        "interface group in set skip ({groups}) may exclude unlisted interface {interface}"
                    )
                };
                Verdict::Unknown { reason: scope_note }
            }
            other => other,
        }
    }
}

pub(super) fn is_link_local(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(v4) => v4.is_link_local(),
        IpAddr::V6(v6) => (v6.segments()[0] & 0xffc0) == 0xfe80,
    }
}

pub(super) fn family_of(ip: IpAddr) -> AddressFamily {
    if ip.to_canonical().is_ipv6() {
        AddressFamily::Ipv6
    } else {
        AddressFamily::Ipv4
    }
}
