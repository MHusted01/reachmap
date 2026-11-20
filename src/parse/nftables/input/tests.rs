use serde_json::{Value, json};

use crate::parse::nftables::parse_ruleset;
use crate::socket::{AddressFamily, Protocol};

fn evaluate(ruleset: &str, port: u16) -> String {
    parse_ruleset(ruleset)
        .unwrap()
        .input(AddressFamily::Ipv4)
        .unwrap()
        .evaluate(Protocol::Tcp, port, "eth0")
        .to_string()
}

#[test]
fn ufw_style_input_follows_jumps_until_a_verdict_or_unsupported_rule() {
    let rules = include_str!("../../../../tests/fixtures/nftables_input_ufw.json");
    assert_eq!(evaluate(rules, 8443), "accept (matching rule)");
    assert_eq!(
        evaluate(rules, 9090),
        "unknown (unsupported input rule in ip filter ufw-user-input)"
    );
    assert_eq!(
        evaluate(rules, 8000),
        "drop (chain policy in ip filter INPUT)"
    );
}

fn chain(name: &str) -> Value {
    json!({"chain": {"family": "ip", "table": "filter", "name": name}})
}

fn rule(chain: &str, statement: Value) -> Value {
    json!({"rule": {"family": "ip", "table": "filter", "chain": chain, "expr": [statement]}})
}

fn outcome(entries: impl IntoIterator<Item = Value>) -> String {
    let mut rules = vec![
        json!({"table": {"family": "ip", "name": "filter"}}),
        json!({"chain": {"family": "ip", "table": "filter", "name": "INPUT",
            "hook": "input", "type": "filter", "prio": 0, "policy": "drop"}}),
    ];
    rules.extend(entries);
    evaluate(&json!({"nftables": rules}).to_string(), 8443)
}

#[test]
fn jump_resumes_after_an_explicit_or_implicit_return() {
    for body in [
        rule("user", json!({"return": null})),
        rule("user", json!({"counter": "hits"})),
    ] {
        assert_eq!(
            outcome([
                chain("user"),
                rule("INPUT", json!({"jump": {"target": "user"}})),
                body,
                rule("INPUT", json!({"accept": null})),
            ]),
            "accept (matching rule)"
        );
    }
}

#[test]
fn goto_skips_the_rest_of_its_chain_and_returns_to_the_last_jump() {
    assert_eq!(
        outcome([
            chain("first"),
            chain("second"),
            rule("INPUT", json!({"jump": {"target": "first"}})),
            rule("first", json!({"goto": {"target": "second"}})),
            rule("first", json!({"drop": null})),
            rule("second", json!({"return": null})),
            rule("INPUT", json!({"accept": null})),
        ]),
        "accept (matching rule)"
    );
}

#[test]
fn base_chain_return_or_goto_falls_back_to_policy() {
    for statement in [json!({"return": null}), json!({"goto": {"target": "user"}})] {
        assert_eq!(
            outcome([
                chain("user"),
                rule("INPUT", statement),
                rule("INPUT", json!({"accept": null})),
            ]),
            "drop (chain policy in ip filter INPUT)"
        );
    }
}

#[test]
fn a_verdict_in_a_regular_chain_ends_the_base_chain() {
    assert_eq!(
        outcome([
            chain("user"),
            rule("INPUT", json!({"goto": {"target": "user"}})),
            rule("user", json!({"drop": null})),
            rule("INPUT", json!({"accept": null})),
        ]),
        "drop (matching rule in ip filter user)"
    );
}

#[test]
fn chain_targets_must_be_regular_chains_in_the_same_family_and_table() {
    let jump = rule("INPUT", json!({"jump": {"target": "user"}}));
    assert_eq!(
        outcome([
            json!({"chain": {"family": "ip6", "table": "filter", "name": "user"}}),
            json!({"chain": {"family": "ip", "table": "other", "name": "user"}}),
            rule("user", json!({"accept": null})),
            jump.clone(),
        ]),
        "unknown (missing input rule chain target in ip filter INPUT)"
    );
    assert_eq!(
        outcome([
            json!({"chain": {"family": "ip", "table": "filter", "name": "user",
                "hook": "output", "type": "filter", "prio": 0, "policy": "accept"}}),
            jump,
        ]),
        "unknown (input rule target is a base chain in ip filter INPUT)"
    );
}

#[test]
fn recursive_transfers_are_unknown() {
    assert_eq!(
        outcome([
            chain("one"),
            chain("two"),
            rule("INPUT", json!({"jump": {"target": "one"}})),
            rule("one", json!({"goto": {"target": "two"}})),
            rule("two", json!({"jump": {"target": "one"}})),
        ]),
        "unknown (recursive input rule chain target in ip filter two)"
    );
}

#[test]
fn long_goto_paths_hit_the_depth_limit() {
    let mut entries = vec![rule("INPUT", json!({"jump": {"target": "chain0"}}))];
    for index in 0..64 {
        let name = format!("chain{index}");
        entries.push(chain(&name));
        if index < 63 {
            entries.push(rule(
                &name,
                json!({"goto": {"target": format!("chain{}", index + 1)}}),
            ));
        }
    }
    assert!(
        outcome(entries)
            .starts_with("unknown (input rule chain depth limit exceeded in ip filter ")
    );
}

#[test]
fn repeat_visits_to_a_returning_chain_count_towards_the_rule_limit() {
    let jump = rule("INPUT", json!({"jump": {"target": "user"}}));
    let entries = |jumps| {
        [chain("user"), rule("user", json!({"return": null}))]
            .into_iter()
            .chain(std::iter::repeat_n(jump.clone(), jumps))
            .chain([rule("INPUT", json!({"accept": null}))])
    };
    assert_eq!(outcome(entries(2)), "accept (matching rule)");
    assert!(
        outcome(entries(2500))
            .starts_with("unknown (input rule visit limit exceeded in ip filter ")
    );
}
