//! The output of `iptables -S`.

use crate::firewall::DockerUserChain;

/// How `iptables -S` starts a rule of the `DOCKER-USER` chain.
const RULE_PREFIX: &str = "-A DOCKER-USER ";

/// The rule older Docker versions add by themselves. It filters nothing.
const DEFAULT_RULE: &str = "-A DOCKER-USER -j RETURN";

/// Reads what `DOCKER-USER` holds from the output of `iptables -S DOCKER-USER`.
/// The rules are only counted; what they do is not evaluated.
pub fn parse_docker_user(rules: &str) -> DockerUserChain {
    let filters = rules
        .lines()
        .map(str::trim)
        .any(|line| line.starts_with(RULE_PREFIX) && line != DEFAULT_RULE);
    if filters {
        DockerUserChain::HasRules
    } else {
        DockerUserChain::NoRules
    }
}
