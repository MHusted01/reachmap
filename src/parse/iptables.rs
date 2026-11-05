//! The output of `iptables -S`.

use crate::firewall::DockerUserChain;

/// How `iptables -S` declares the `DOCKER-USER` chain.
const CHAIN_LINE: &str = "-N DOCKER-USER";

/// How `iptables -S` starts a rule of the `DOCKER-USER` chain.
const RULE_PREFIX: &str = "-A DOCKER-USER ";

/// The rule older Docker versions add by themselves. It filters nothing.
const DEFAULT_RULE: &str = "-A DOCKER-USER -j RETURN";

/// Reads what `DOCKER-USER` holds from the output of `iptables -S DOCKER-USER`.
/// The rules are only counted; what they do is not evaluated. Output that does
/// not declare the chain says nothing about it.
pub fn parse_docker_user(rules: &str) -> DockerUserChain {
    let lines = || rules.lines().map(str::trim);
    if !lines().any(|line| line == CHAIN_LINE) {
        return DockerUserChain::Unchecked("iptables did not print the chain".to_string());
    }
    if lines().any(|line| line.starts_with(RULE_PREFIX) && line != DEFAULT_RULE) {
        DockerUserChain::HasRules
    } else {
        DockerUserChain::NoRules
    }
}
