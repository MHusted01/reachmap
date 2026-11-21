//! Evaluation of the active base chains at the local IP input hook.

use std::collections::HashMap;
use std::ops::ControlFlow;

use crate::nftables::InputVerdict;
use crate::sanitize::sanitize;
use crate::socket::{AddressFamily, Protocol};

use super::matches::{NamedSetEntry, Packet, SetIndex};
use super::path::{PathHookResult, VerdictMapEntry};
use super::{Action, Chain, ChainKey, Entry, Policy, Rule, RuleAction, Ruleset, TableFlags};

#[cfg(test)]
mod tests;

const MAX_CHAIN_TRANSFERS: usize = 32;
const MAX_RULE_VISITS: usize = 4096;

type ChainIndex<'a> = HashMap<ChainKey<'a>, IndexedChain<'a>>;
type ChainDecision<'a> = Result<(Action, Reason<'a>), Reason<'a>>;

impl Ruleset {
    pub(crate) fn input(&self, family: AddressFamily) -> Option<InputHook<'_>> {
        self.hook(family, "input")
    }

    pub(super) fn hook(&self, family: AddressFamily, hook: &str) -> Option<InputHook<'_>> {
        let family_name = match family {
            AddressFamily::Ipv4 => "ip",
            AddressFamily::Ipv6 => "ip6",
        };
        let mut chains = Vec::new();
        for chain in self.nftables.iter().filter_map(|entry| match entry {
            Entry::Chain(chain)
                if chain.hook.as_deref() == Some(hook)
                    && (chain.family == family_name || chain.family == "inet") =>
            {
                Some(chain)
            }
            _ => None,
        }) {
            let table = self.nftables.iter().find_map(|entry| match entry {
                Entry::Table(table)
                    if table.family == chain.family && table.name == chain.table =>
                {
                    Some(table)
                }
                _ => None,
            });
            if table
                .and_then(|table| table.flags.as_ref())
                .is_some_and(TableFlags::dormant)
            {
                continue;
            }
            let policy = table
                .ok_or("input chain's table is missing")
                .and_then(|_| chain_policy(chain, hook));
            chains.push(InputChain { chain, policy });
        }
        // A missing priority could precede every known priority.
        chains.sort_by_key(|input| input.chain.prio);
        (!chains.is_empty()).then(|| InputHook {
            family,
            chains,
            index: self.index_chains(),
            maps: self
                .nftables
                .iter()
                .filter_map(|entry| match entry {
                    Entry::Map(VerdictMapEntry::Supported(map)) => Some((map.key(), map)),
                    _ => None,
                })
                .collect(),
            sets: self
                .nftables
                .iter()
                .filter_map(|entry| match entry {
                    Entry::Set(NamedSetEntry::Supported(set)) => Some((set.key(), set)),
                    _ => None,
                })
                .collect(),
        })
    }

    fn index_chains(&self) -> ChainIndex<'_> {
        let mut index: ChainIndex<'_> = self
            .nftables
            .iter()
            .filter_map(|entry| match entry {
                Entry::Chain(chain) => Some((
                    chain.key(),
                    IndexedChain {
                        chain,
                        rules: Vec::new(),
                    },
                )),
                _ => None,
            })
            .collect();
        for entry in &self.nftables {
            if let Entry::Rule(rule) = entry
                && let Some(chain) = index.get_mut(&rule.chain_key())
            {
                chain.rules.push(rule);
            }
        }
        index
    }
}

fn chain_policy(chain: &Chain, hook: &str) -> Result<Action, &'static str> {
    let nat = matches!(hook, "prerouting" | "postrouting") && chain.kind.as_deref() == Some("nat");
    if !nat && chain.kind.as_deref() != Some("filter") {
        return Err("unsupported input chain type");
    }
    if chain.prio.is_none() {
        return Err("input chain priority is missing");
    }
    match chain.policy {
        Some(Policy::Known(action)) => Ok(action),
        Some(Policy::Unsupported(_)) => Err("unsupported input chain policy"),
        None => Err("input chain policy is missing"),
    }
}

#[derive(Debug)]
pub(crate) struct InputHook<'a> {
    family: AddressFamily,
    chains: Vec<InputChain<'a>>,
    index: ChainIndex<'a>,
    sets: SetIndex<'a>,
    maps: super::path::MapIndex<'a>,
}

impl InputHook<'_> {
    pub(crate) fn evaluate(&self, protocol: Protocol, port: u16, interface: &str) -> InputVerdict {
        let packet = Packet {
            protocol,
            port,
            ingress: interface,
            path: None,
        };
        match self.evaluate_packet(packet) {
            PathHookResult::Accept { reason } => InputVerdict::Accept { reason },
            PathHookResult::Drop { reason } => InputVerdict::Drop { reason },
            PathHookResult::Unknown { reason } => InputVerdict::Unknown { reason },
            PathHookResult::Dnat { .. } => InputVerdict::Unknown {
                reason: "unexpected translation at the input hook".to_owned(),
            },
        }
    }

    pub(super) fn evaluate_packet(&self, packet: Packet<'_>) -> PathHookResult {
        let mut accept_reason = if packet.path.is_some() {
            "all applicable base chains accept".to_owned()
        } else {
            "all applicable input chains accept".to_owned()
        };
        let mut walk = Walk {
            index: &self.index,
            sets: &self.sets,
            maps: &self.maps,
            family: self.family,
            packet,
            active: Vec::new(),
            remaining: MAX_RULE_VISITS,
        };
        for group in self
            .chains
            .chunk_by(|left, right| left.chain.prio == right.chain.prio)
        {
            let mut drop = None;
            for input in group {
                match walk.evaluate(input) {
                    Ok((Action::Accept, reason)) if self.chains.len() == 1 => {
                        accept_reason = if packet.path.is_some() {
                            reason.with_chain()
                        } else {
                            reason.message.to_owned()
                        };
                    }
                    Ok((Action::Accept, _)) => {}
                    Ok((Action::Drop, reason)) => {
                        drop.get_or_insert(reason);
                    }
                    Ok((Action::Dnat(endpoint), reason)) => {
                        // Path validation admits exactly one NAT chain, last in prerouting.
                        return PathHookResult::Dnat {
                            endpoint,
                            reason: reason.with_chain(),
                        };
                    }
                    // Netfilter does not guarantee an order within a priority.
                    Err(reason) => {
                        return PathHookResult::Unknown {
                            reason: reason.with_chain(),
                        };
                    }
                }
            }
            if let Some(reason) = drop {
                return PathHookResult::Drop {
                    reason: reason.with_chain(),
                };
            }
        }
        PathHookResult::Accept {
            reason: accept_reason,
        }
    }
}

#[derive(Debug)]
struct InputChain<'a> {
    chain: &'a Chain,
    policy: Result<Action, &'static str>,
}

#[derive(Debug)]
struct IndexedChain<'a> {
    chain: &'a Chain,
    rules: Vec<&'a Rule>,
}

struct Reason<'a> {
    chain: &'a Chain,
    message: &'static str,
}

impl Reason<'_> {
    fn with_chain(&self) -> String {
        sanitize(&format!(
            "{} in {} {} {}",
            self.message, self.chain.family, self.chain.table, self.chain.name
        ))
    }
}

struct Walk<'index, 'rules, 'packet> {
    index: &'index ChainIndex<'rules>,
    sets: &'index SetIndex<'rules>,
    family: AddressFamily,
    maps: &'index super::path::MapIndex<'rules>,
    packet: Packet<'packet>,
    active: Vec<&'rules str>,
    remaining: usize,
}

impl<'index, 'rules> Walk<'index, 'rules, '_> {
    fn evaluate(&mut self, input: &InputChain<'rules>) -> ChainDecision<'rules> {
        let reason = |message| Reason {
            chain: input.chain,
            message,
        };
        let policy = input.policy.map_err(reason)?;
        let chain = self
            .index
            .get(&input.chain.key())
            .ok_or_else(|| reason("input chain is missing"))?;
        match self.walk(chain) {
            ControlFlow::Break(decision) => decision,
            ControlFlow::Continue(()) => Ok((policy, reason("chain policy"))),
        }
    }

    fn walk(&mut self, indexed: &IndexedChain<'rules>) -> ControlFlow<ChainDecision<'rules>> {
        self.active.push(&indexed.chain.name);
        let decision = self.walk_rules(indexed);
        self.active.pop();
        decision
    }

    fn walk_rules(&mut self, indexed: &IndexedChain<'rules>) -> ControlFlow<ChainDecision<'rules>> {
        let chain = indexed.chain;
        let reason = |message| Reason { chain, message };
        for rule in &indexed.rules {
            if self.remaining == 0 {
                return ControlFlow::Break(Err(reason("input rule visit limit exceeded")));
            }
            self.remaining -= 1;
            let mut packet = self.packet;
            if let Some(path) = &mut packet.path {
                path.allow_dnat &= self
                    .active
                    .first()
                    .is_some_and(|&name| name == "nat-PREROUTING");
            }
            match rule.evaluate(self.sets, self.family, packet, |map, interface| {
                let map = self
                    .maps
                    .get(&(chain.family.as_str(), chain.table.as_str(), map))
                    .ok_or("missing or unsupported interface verdict map")?;
                map.target(interface)
            }) {
                Ok(None) => {}
                Ok(Some(RuleAction::Verdict(action, message))) => {
                    return ControlFlow::Break(Ok((action, reason(message))));
                }
                Ok(Some(RuleAction::Return)) => return ControlFlow::Continue(()),
                Ok(Some(RuleAction::Jump(target))) => self.follow(chain, target)?,
                // A goto's return goes directly to the caller of this chain.
                Ok(Some(RuleAction::Goto(target))) => return self.follow(chain, target),
                Err(message) => return ControlFlow::Break(Err(reason(message))),
            }
        }
        ControlFlow::Continue(())
    }

    fn follow(
        &mut self,
        from: &'rules Chain,
        target: &'rules str,
    ) -> ControlFlow<ChainDecision<'rules>> {
        match self.target(from, target) {
            Ok(chain) => self.walk(chain),
            Err(message) => ControlFlow::Break(Err(Reason {
                chain: from,
                message,
            })),
        }
    }

    fn target(
        &self,
        from: &'rules Chain,
        target: &'rules str,
    ) -> Result<&'index IndexedChain<'rules>, &'static str> {
        let chain = self
            .index
            .get(&(from.family.as_str(), from.table.as_str(), target))
            .ok_or("missing input rule chain target")?;
        if chain.chain.hook.is_some() {
            return Err("input rule target is a base chain");
        }
        if self.active.contains(&target) {
            return Err("recursive input rule chain target");
        }
        if self.active.len() > MAX_CHAIN_TRANSFERS {
            return Err("input rule chain depth limit exceeded");
        }
        Ok(chain)
    }
}
