//! The firewall parsers against text in the format of real hosts.

use reachmap::firewall::{DockerUserChain, UfwState};
use reachmap::parse::iptables::parse_docker_user;
use reachmap::parse::ufw::parse_ufw_conf;

#[test]
fn an_enabled_config_means_active() {
    let text = include_str!("fixtures/ufw_enabled.conf");
    assert_eq!(parse_ufw_conf(text), UfwState::Active);
}

#[test]
fn a_disabled_config_means_inactive_even_with_a_commented_out_yes() {
    let text = include_str!("fixtures/ufw_disabled.conf");
    assert_eq!(parse_ufw_conf(text), UfwState::Inactive);
}

#[test]
fn quotes_case_and_spaces_do_not_change_the_answer() {
    assert_eq!(parse_ufw_conf("ENABLED=\"yes\"\n"), UfwState::Active);
    assert_eq!(parse_ufw_conf("  enabled = 'YES'  \n"), UfwState::Active);
    assert_eq!(parse_ufw_conf("ENABLED=No\n"), UfwState::Inactive);
}

#[test]
fn the_last_setting_wins() {
    assert_eq!(
        parse_ufw_conf("ENABLED=no\nENABLED=yes\n"),
        UfwState::Active
    );
}

#[test]
fn a_config_without_the_setting_leaves_the_state_unknown() {
    assert_eq!(
        parse_ufw_conf("LOGLEVEL=low\n"),
        UfwState::Unknown("ufw.conf has no ENABLED setting".to_string())
    );
}

#[test]
fn a_strange_value_leaves_the_state_unknown_and_is_sanitised() {
    assert_eq!(
        parse_ufw_conf("ENABLED=maybe\u{1b}[2J\n"),
        UfwState::Unknown("ufw.conf has ENABLED=maybe\\u{1b}[2J, not yes or no".to_string())
    );
}

#[test]
fn a_chain_with_a_rule_of_its_own_has_rules() {
    let rules = include_str!("fixtures/iptables_docker_user.txt");
    assert_eq!(parse_docker_user(rules), DockerUserChain::HasRules);
}

#[test]
fn an_empty_chain_has_no_rules() {
    assert_eq!(
        parse_docker_user("-N DOCKER-USER\n"),
        DockerUserChain::NoRules
    );
}

#[test]
fn dockers_default_return_rule_does_not_count() {
    let rules = "-N DOCKER-USER\n-A DOCKER-USER -j RETURN\n";
    assert_eq!(parse_docker_user(rules), DockerUserChain::NoRules);
}
