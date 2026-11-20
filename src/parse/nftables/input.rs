//! Evaluation of the active base chains at the local IP input hook.

use std::collections::HashMap;
use std::ops::ControlFlow;

use crate::nftables::InputVerdict;
use crate::sanitize::sanitize;
use crate::socket::{AddressFamily, Protocol};

use super::matches::{NamedSetEntry, SetIndex};
use super::{Action, Chain, ChainKey, Entry, Policy, Rule, RuleAction, Ruleset, TableFlags};

#[cfg(test)]
mod tests;

const MAX_CHAIN_TRANSFERS: usize = 32;
const MAX_RULE_VISITS: usize = 4096;

type ChainIndex<'a> = HashMap<ChainKey<'a>, IndexedChain<'a>>;
type ChainDecision<'a> = Result<(Action, Reason<'a>), Reason<'a>>;

impl Ruleset {
    pub(crate) fn input(&self, family: AddressFamily) -> Option<InputHook<'_>> {
        let family_name = match family {
            AddressFamily::Ipv4 => "ip",
            AddressFamily::Ipv6 => "ip6",
        };
        let mut chains = Vec::new();
        for chain in self.nftables.iter().filter_map(|entry| match entry {
            Entry::Chain(chain)
                if chain.hook.as_deref() == Some("input")
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
                .and_then(|_| input_policy(chain));
            chains.push(InputChain { chain, policy });
        }
        // A missing priority could precede every known priority.
        chains.sort_by_key(|input| input.chain.prio);
        (!chains.is_empty()).then(|| InputHook {
            family,
            chains,
            index: self.index_chains(),
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

fn input_policy(chain: &Chain) -> Result<Action, &'static str> {
    if chain.kind.as_deref() != Some("filter") {
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
}

impl InputHook<'_> {
    pub(crate) fn evaluate(&self, protocol: Protocol, port: u16, interface: &str) -> InputVerdict {
        let mut accept_reason = "all applicable input chains accept";
        let mut walk = Walk {
            index: &self.index,
            sets: &self.sets,
            family: self.family,
            protocol,
            port,
            interface,
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
                        accept_reason = reason.message;
                    }
                    Ok((Action::Accept, _)) => {}
                    Ok((Action::Drop, reason)) => {
                        drop.get_or_insert(reason);
                    }
                    // Netfilter does not guarantee an order within a priority.
                    Err(reason) => {
                        return InputVerdict::Unknown {
                            reason: reason.with_chain(),
                        };
                    }
                }
            }
            if let Some(reason) = drop {
                return InputVerdict::Drop {
                    reason: reason.with_chain(),
                };
            }
        }
        InputVerdict::Accept {
            reason: accept_reason.to_string(),
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
    protocol: Protocol,
    port: u16,
    interface: &'packet str,
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
            match rule.evaluate(
                self.sets,
                self.family,
                self.protocol,
                self.port,
                self.interface,
            ) {
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
