//! Socket-to-interface expansion and pf evaluation helpers for [`super::PfReport`].

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr};

use crate::sanitize::sanitize;
use crate::socket::{AddressFamily, Protocol};

use super::super::{AnchorRulesets, Ruleset, Traffic, Verdict};
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
        let canonical = endpoint.address.to_canonical();
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
                vec![PfInterfaceVerdict {
                    interface: None,
                    outcome: Verdict::Unknown {
                        reason:
                            "numeric IPv6 zone identifier could not be mapped to an interface name"
                                .to_owned(),
                    },
                }]
            } else {
                let iface = sanitize(zone);
                vec![PfInterfaceVerdict {
                    interface: Some(iface.clone()),
                    outcome: self.eval_one(&iface, endpoint.protocol, canonical, endpoint.port),
                }]
            }
        } else {
            self.evaluate_specific(endpoint.protocol, canonical, endpoint.port)
        };
        vec![(family, verdicts)]
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

    fn evaluate_wildcard(
        &self,
        family: AddressFamily,
        protocol: Protocol,
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
        let label = match family {
            AddressFamily::Ipv4 => "IPv4",
            AddressFamily::Ipv6 => "IPv6",
        };
        let all_family_ips: BTreeSet<IpAddr> = map
            .interfaces
            .values()
            .flat_map(|info| info.addresses.iter().copied())
            .filter(|ip| family_of(*ip) == family)
            .collect();
        if all_family_ips.is_empty() {
            return vec![PfInterfaceVerdict {
                interface: None,
                outcome: Verdict::Unknown {
                    reason: format!("no interface has an {label} address"),
                },
            }];
        }
        let routable_family_ips: BTreeSet<IpAddr> = all_family_ips
            .iter()
            .copied()
            .filter(|ip| !ip.is_loopback() && !is_link_local(*ip))
            .collect();
        let mut results = Vec::new();
        for (iface, info) in map.active_interfaces() {
            let mut candidates: BTreeSet<IpAddr> = if info.is_loopback {
                all_family_ips
                    .iter()
                    .copied()
                    .filter(|ip| !is_link_local(*ip))
                    .collect()
            } else {
                routable_family_ips.clone()
            };
            candidates.extend(
                info.addresses
                    .iter()
                    .copied()
                    .filter(|ip| family_of(*ip) == family && is_link_local(*ip)),
            );
            if family == AddressFamily::Ipv4
                && protocol == Protocol::Udp
                && !info.is_loopback
                && (info.is_broadcast || !info.broadcasts.is_empty())
            {
                candidates.insert(IpAddr::V4(Ipv4Addr::BROADCAST));
                candidates.extend(info.broadcasts.iter().copied());
            }
            if candidates.is_empty() {
                continue;
            }
            let verdicts: Vec<Verdict> = candidates
                .into_iter()
                .map(|ip| self.eval_one(iface, protocol, ip, port))
                .collect();
            results.push(PfInterfaceVerdict {
                interface: Some(iface.clone()),
                outcome: combine_address_verdicts(iface, verdicts),
            });
        }
        if results.is_empty() {
            return vec![PfInterfaceVerdict {
                interface: None,
                outcome: Verdict::Unknown {
                    reason: format!("no active interface has an {label} address"),
                },
            }];
        }
        results
    }

    fn eval_one(
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
                // Only concrete interface skips were added to `rules.skip`; an
                // active interface group in `set skip` may include `interface`.
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

fn combine_address_verdicts(interface: &str, verdicts: Vec<Verdict>) -> Verdict {
    let mut iter = verdicts.into_iter();
    let Some(first) = iter.next() else {
        return Verdict::Unknown {
            reason: format!("no address available on {interface}"),
        };
    };
    let mut current = first;
    for next in iter {
        current = match (&current, &next) {
            (Verdict::Unknown { .. }, _) => current,
            (_, Verdict::Unknown { .. }) => next,
            (Verdict::Pass { .. }, Verdict::Pass { .. })
            | (Verdict::Block { .. }, Verdict::Block { .. }) => current,
            (Verdict::Pass { .. }, Verdict::Block { .. })
            | (Verdict::Block { .. }, Verdict::Pass { .. }) => Verdict::Unknown {
                reason: format!("pf rules differ across addresses on {interface}"),
            },
        };
    }
    current
}

fn is_link_local(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(v4) => v4.is_link_local(),
        IpAddr::V6(v6) => (v6.segments()[0] & 0xffc0) == 0xfe80,
    }
}

fn family_of(ip: IpAddr) -> AddressFamily {
    if ip.to_canonical().is_ipv6() {
        AddressFamily::Ipv6
    } else {
        AddressFamily::Ipv4
    }
}
