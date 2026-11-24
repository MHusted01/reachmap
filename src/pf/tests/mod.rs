use std::net::IpAddr;

use serde_json::json;

use crate::socket::Protocol;

use super::{AnchorRulesets, Ruleset, Traffic, Verdict};

mod collector;
mod edge_cases;
mod regressions;

const DEFAULT_MACOS: &str = include_str!("../../../tests/fixtures/pf/default_macos.txt");
const DEFAULT_BLOCK: &str = include_str!("../../../tests/fixtures/pf/default_block.txt");
const QUICK_ORDER: &str = include_str!("../../../tests/fixtures/pf/quick_order.txt");
const CONDITIONS: &str = include_str!("../../../tests/fixtures/pf/conditions.txt");

const HOST: &str = "192.0.2.10";

fn ip(text: &str) -> IpAddr {
    text.parse().unwrap()
}

fn traffic<'a>(
    interface: &'a str,
    protocol: Protocol,
    destination: &str,
    port: u16,
) -> Traffic<'a> {
    Traffic {
        interface,
        protocol,
        destination: ip(destination),
        port,
        source: None,
    }
}

fn anchors(entries: &[(&str, &str)]) -> AnchorRulesets {
    entries
        .iter()
        .map(|(name, text)| ((*name).to_string(), Ruleset::parse(text)))
        .collect()
}

fn check(rules: &str, anchors: &AnchorRulesets, traffic: &Traffic<'_>) -> Verdict {
    Ruleset::parse(rules).evaluate(anchors, traffic)
}

fn tcp_to(rules: &str, interface: &str, destination: &str, port: u16) -> Verdict {
    let traffic = traffic(interface, Protocol::Tcp, destination, port);
    check(rules, &AnchorRulesets::new(), &traffic)
}

fn tcp(rules: &str, interface: &str, port: u16) -> Verdict {
    tcp_to(rules, interface, HOST, port)
}

fn udp(rules: &str, interface: &str, port: u16) -> Verdict {
    let traffic = traffic(interface, Protocol::Udp, HOST, port);
    check(rules, &AnchorRulesets::new(), &traffic)
}

fn pass_at(line: usize) -> Verdict {
    Verdict::Pass {
        reason: format!("matched pass rule at line {line}"),
    }
}

fn block_at(line: usize) -> Verdict {
    Verdict::Block {
        reason: format!("matched block rule at line {line}"),
    }
}

fn default_pass() -> Verdict {
    Verdict::Pass {
        reason: "no rule matched, and pf passes by default".to_string(),
    }
}

fn unknown(reason: &str) -> Verdict {
    Verdict::Unknown {
        reason: reason.to_string(),
    }
}

#[test]
fn the_default_macos_ruleset_passes_when_its_anchor_is_empty() {
    let anchors = anchors(&[("com.apple/*", "")]);
    let traffic = traffic("en0", Protocol::Tcp, HOST, 22);
    assert_eq!(check(DEFAULT_MACOS, &anchors, &traffic), default_pass());
}

#[test]
fn a_missing_anchor_ruleset_is_unknown_not_pass() {
    let traffic = traffic("en0", Protocol::Tcp, HOST, 22);
    assert_eq!(
        check(DEFAULT_MACOS, &AnchorRulesets::new(), &traffic),
        unknown("missing anchor ruleset in rule at line 1")
    );
    assert_eq!(
        check(
            "pass in all\nanchor \"com.apple/*\" all",
            &AnchorRulesets::new(),
            &traffic
        ),
        unknown("missing anchor ruleset in rule at line 2")
    );
}

#[test]
fn an_anchor_that_cannot_match_is_not_needed() {
    let rules = "anchor \"x\" on en1 all";
    assert_eq!(tcp(rules, "en0", 22), default_pass());
}

#[test]
fn inbound_default_block_with_exceptions() {
    let anchors = anchors(&[("com.apple/*", "")]);
    let run = |interface: &str, protocol: Protocol, destination: &str, port: u16| {
        check(
            DEFAULT_BLOCK,
            &anchors,
            &traffic(interface, protocol, destination, port),
        )
    };
    assert_eq!(run("en0", Protocol::Tcp, HOST, 22), pass_at(5));
    assert_eq!(run("en1", Protocol::Tcp, HOST, 22), block_at(3));
    assert_eq!(run("en0", Protocol::Tcp, HOST, 8000), pass_at(6));
    assert_eq!(run("en0", Protocol::Tcp, HOST, 8100), pass_at(6));
    assert_eq!(run("en0", Protocol::Tcp, HOST, 8101), block_at(3));
    assert_eq!(run("en0", Protocol::Udp, HOST, 5353), pass_at(7));
    assert_eq!(run("en0", Protocol::Tcp, HOST, 5353), block_at(3));
    assert_eq!(run("lo0", Protocol::Tcp, "127.0.0.1", 9999), pass_at(4));
    assert_eq!(run("en0", Protocol::Tcp, "2001:db8::5", 22), block_at(3));
}

#[test]
fn the_last_match_wins_unless_a_quick_rule_ends_the_walk() {
    assert_eq!(tcp("block drop in all\npass in all", "en0", 22), pass_at(2));
    assert_eq!(
        tcp("pass in all\nblock drop in all", "en0", 22),
        block_at(2)
    );
    assert_eq!(
        tcp("pass in quick all\nblock drop in all", "en0", 22),
        pass_at(1)
    );
}

#[test]
fn quick_rules_decide_in_file_order() {
    assert_eq!(tcp(QUICK_ORDER, "en0", 22), pass_at(2));
    assert_eq!(tcp(QUICK_ORDER, "en0", 8080), block_at(3));
    assert_eq!(tcp(QUICK_ORDER, "en0", 9000), block_at(3));
    assert_eq!(tcp(QUICK_ORDER, "en0", 80), default_pass());
    assert_eq!(tcp(QUICK_ORDER, "en1", 8080), default_pass());
}

#[test]
fn interface_address_family_and_source_conditions() {
    assert_eq!(tcp(CONDITIONS, "en0", 22), pass_at(3));
    assert_eq!(tcp_to(CONDITIONS, "en0", "192.0.2.11", 22), block_at(2));
    assert_eq!(tcp(CONDITIONS, "en1", 80), block_at(4));
    assert_eq!(tcp(CONDITIONS, "en0", 80), block_at(2));
    assert_eq!(tcp_to(CONDITIONS, "en1", "2001:db8::7", 443), pass_at(5));
    assert_eq!(tcp_to(CONDITIONS, "en1", "2001:db9::7", 443), block_at(2));
    assert_eq!(tcp(CONDITIONS, "en1", 443), block_at(2));
    // Rule 6 only matches peers in 198.51.100.0/24 and blocks like rule 2.
    assert_eq!(tcp(CONDITIONS, "en0", 8443), block_at(2));
}

fn port_rule(spec: &str, port: u16) -> Verdict {
    tcp(
        &format!(
            "scrub in all fragment reassemble\nblock drop in proto tcp from any to any port {spec}"
        ),
        "en0",
        port,
    )
}

#[test]
fn port_operators() {
    let cases: &[(&str, &[(u16, bool)])] = &[
        ("= 22", &[(22, true), (23, false)]),
        ("!= 22", &[(22, false), (23, true)]),
        ("< 1024", &[(1023, true), (1024, false)]),
        ("<= 1024", &[(1024, true), (1025, false)]),
        ("> 1024", &[(1025, true), (1024, false)]),
        (">= 1024", &[(1024, true), (1023, false)]),
        (
            "1000:2000",
            &[(1000, true), (2000, true), (999, false), (2001, false)],
        ),
        (
            "1000 >< 2000",
            &[(1000, false), (1500, true), (2000, false)],
        ),
        (
            "1000 <> 2000",
            &[(1000, false), (999, true), (2001, true), (1500, false)],
        ),
        ("= ssh", &[(22, true), (80, false)]),
    ];
    for (spec, ports) in cases {
        for &(port, blocked) in *ports {
            let expected = if blocked { block_at(2) } else { default_pass() };
            assert_eq!(port_rule(spec, port), expected, "port {spec} for {port}");
        }
    }
}

#[test]
fn an_unknown_service_name_is_not_guessed() {
    assert_eq!(
        port_rule("= nonsense", 22),
        unknown("unrecognized syntax in rule at line 2")
    );
}

#[test]
fn network_prefixes_and_negation() {
    let rules =
        "scrub in all fragment reassemble\nblock drop in all\npass in proto tcp from any to";
    assert_eq!(
        tcp_to(&format!("{rules} 192.0.2.0/24 port = 22"), "en0", HOST, 22),
        pass_at(3)
    );
    assert_eq!(
        tcp_to(
            &format!("{rules} 192.0.2.10/32 port = 22"),
            "en0",
            "192.0.2.11",
            22
        ),
        block_at(2)
    );
    assert_eq!(
        tcp_to(&format!("{rules} 0.0.0.0/0 port = 22"), "en0", HOST, 22),
        pass_at(3)
    );
    assert_eq!(
        tcp_to(
            &format!("{rules} 2001:db8::/32 port = 22"),
            "en0",
            "2001:db8:1::5",
            22
        ),
        pass_at(3)
    );
    assert_eq!(
        tcp_to(
            &format!("{rules} 2001:db8::/32 port = 22"),
            "en0",
            "2001:db9::5",
            22
        ),
        block_at(2)
    );
    let negated = format!("{rules} ! 192.0.2.0/24 port = 22");
    assert_eq!(tcp_to(&negated, "en0", "198.51.100.1", 22), pass_at(3));
    assert_eq!(tcp_to(&negated, "en0", HOST, 22), block_at(2));
    assert_eq!(tcp_to(&negated, "en0", "2001:db8::1", 22), block_at(2));
    assert_eq!(
        tcp_to(&format!("{rules} 192.0.2.0/33 port = 22"), "en0", HOST, 22),
        unknown("unrecognized syntax in rule at line 3")
    );
}

#[test]
fn to_self_matches_a_local_destination() {
    assert_eq!(
        tcp(
            "scrub in all fragment reassemble\nblock drop in all\npass in on en0 from any to self port = 22",
            "en0",
            22
        ),
        pass_at(3)
    );
}

#[test]
fn protocol_direction_and_other_protocols() {
    assert_eq!(
        tcp("block drop in proto udp all", "en0", 22),
        default_pass()
    );
    assert_eq!(udp("block drop in proto udp all", "en0", 22), block_at(1));
    assert_eq!(tcp("block drop out all", "en0", 22), default_pass());
    assert_eq!(
        tcp(
            "block drop in quick proto icmp all icmp-type echoreq",
            "en0",
            22
        ),
        default_pass()
    );
    assert_eq!(tcp("block drop in proto 6 all", "en0", 22), block_at(1));
}

#[test]
fn tcp_flags_only_match_the_opening_syn() {
    let rule = |flags: &str| {
        format!(
            "scrub in all fragment reassemble\nblock drop in proto tcp from any to any flags {flags}"
        )
    };
    assert_eq!(tcp(&rule("A/A"), "en0", 22), default_pass());
    assert_eq!(tcp(&rule("S/SA"), "en0", 22), block_at(2));
    assert_eq!(tcp(&rule("any"), "en0", 22), block_at(2));
    assert_eq!(
        tcp(&rule("Q/SA"), "en0", 22),
        unknown("unrecognized syntax in rule at line 2")
    );
}

#[test]
fn set_skip_passes_traffic_on_the_named_interfaces() {
    let skip = |text: &str, interface: &str| tcp(text, interface, 22);
    let skipped = Verdict::Pass {
        reason: "the interface is excluded by set skip".to_string(),
    };
    assert_eq!(skip("set skip on lo0\nblock drop in all", "lo0"), skipped);
    assert_eq!(
        skip("set skip on lo0\nblock drop in all", "en0"),
        block_at(2)
    );
    assert_eq!(
        skip("set skip on { lo0 utun1 }\nblock drop in all", "utun1"),
        skipped
    );
    assert_eq!(
        skip(
            "set skip on lo0\nset skip on none\nblock drop in all",
            "lo0"
        ),
        block_at(3)
    );
    assert_eq!(
        skip("set block-policy drop\nblock drop in all", "en0"),
        block_at(2)
    );
}

#[test]
fn a_skipped_interface_group_is_unknown() {
    assert_eq!(
        tcp("set skip on lo\nblock drop in all", "lo0", 22),
        unknown("interface group in rule at line 1")
    );
}

#[test]
fn unmodeled_constructs_are_unknown_and_named() {
    let cases = [
        ("proto tcp from <scanners> to any", "table"),
        (
            "proto tcp from any to any port = 22 user 501",
            "user condition",
        ),
        (
            "proto tcp from any to any port = 22 group staff",
            "group condition",
        ),
        (
            "proto tcp from any to any port = 22 os \"Linux\"",
            "os fingerprint",
        ),
        (
            "proto tcp from any to any port = 22 route-to (en1 192.0.2.1)",
            "route-to option",
        ),
        (
            "proto tcp from any to any port = 22 reply-to en1",
            "reply-to option",
        ),
        (
            "proto tcp from any to any port = 22 tagged office",
            "tagged condition",
        ),
        (
            "proto tcp from any to any port = 22 received-on en1",
            "received-on condition",
        ),
        (
            "on egress proto tcp from any to any port = 22",
            "interface group",
        ),
        ("proto tcp from any to (en0) port = 22", "dynamic address"),
        (
            "proto tcp from any to any port = 22 probability 50%",
            "probability",
        ),
        ("proto { tcp udp } from any to any", "list"),
    ];
    for (rule, construct) in cases {
        let verdict = tcp(
            &format!("pass in all\nblock drop in quick {rule}"),
            "en0",
            22,
        );
        assert_eq!(
            verdict,
            unknown(&format!("{construct} in rule at line 2")),
            "{rule}"
        );
    }
}

#[test]
fn an_unmodeled_rule_only_matters_if_it_could_match() {
    assert_eq!(
        tcp(
            "pass in all\nblock drop in quick proto udp from <x> to any",
            "en0",
            22
        ),
        pass_at(1)
    );
    assert_eq!(
        tcp(
            "block drop in all\nblock drop in from <x> to any",
            "en0",
            22
        ),
        block_at(1)
    );
    assert_eq!(
        tcp(
            "block drop in quick all\nblock drop in from <x> to any",
            "en0",
            22
        ),
        block_at(1)
    );
}

#[test]
fn translation_rules_make_matching_traffic_unknown() {
    let rdr = "rdr on en0 inet proto tcp from any to any port = 80 -> 192.0.2.50 port 8080\nblock drop in all";
    assert_eq!(
        tcp(rdr, "en0", 80),
        unknown("translation rule in rule at line 1")
    );
    assert_eq!(tcp(rdr, "en0", 22), block_at(2));
    assert_eq!(tcp(rdr, "en1", 80), block_at(2));
    assert_eq!(
        tcp("no rdr proto tcp from any to any -> 192.0.2.50", "en0", 80),
        unknown("translation rule in rule at line 1")
    );
    assert_eq!(
        tcp("nat on en0 inet from any to any -> (en0)", "en0", 80),
        unknown("translation rule in rule at line 1")
    );
    assert_eq!(
        tcp("rdr-anchor \"x\" all", "en0", 80),
        unknown("translation rule in rule at line 1")
    );
}

#[test]
fn translation_rules_inside_supplied_anchors_count() {
    let anchors = anchors(&[("x", "rdr proto tcp from any to any port = 80 -> 192.0.2.50")]);
    let traffic = traffic("en0", Protocol::Tcp, HOST, 80);
    assert_eq!(
        check("anchor \"x\" all", &anchors, &traffic),
        unknown("translation rule in rule at line 1 of anchor \"x\"")
    );
}

#[test]
fn restrictions_on_the_peer_are_unknown_unless_a_source_is_named() {
    let rules = "scrub in all fragment reassemble\nblock drop in all\npass in on en0 inet proto tcp from 192.0.2.0/24 to any port = 22";
    assert_eq!(
        tcp(rules, "en0", 22),
        unknown("source address restriction in rule at line 3")
    );
    let with_source = |source: &str| {
        let mut traffic = traffic("en0", Protocol::Tcp, HOST, 22);
        traffic.source = Some(ip(source));
        check(rules, &AnchorRulesets::new(), &traffic)
    };
    assert_eq!(with_source("192.0.2.77"), pass_at(3));
    assert_eq!(with_source("198.51.100.9"), block_at(2));
    assert_eq!(
        tcp(
            "scrub in all fragment reassemble\nblock drop in all\npass in proto tcp from any port = 53 to any port = 22",
            "en0",
            22
        ),
        unknown("source port restriction in rule at line 3")
    );
    assert_eq!(
        tcp("block drop in all\npass in from self to any", "en0", 22),
        unknown("source address restriction in rule at line 2")
    );
}

#[test]
fn supplied_anchor_rules_are_evaluated_in_place_of_the_anchor_line() {
    let anchors = anchors(&[
        ("quick", "pass in quick proto tcp from any to any port = 22"),
        ("plain", "pass in proto tcp from any to any port = 22"),
    ]);
    let traffic = traffic("en0", Protocol::Tcp, HOST, 22);
    let anchor_pass = |name: &str| Verdict::Pass {
        reason: format!("matched pass rule at line 1 of anchor \"{name}\""),
    };
    assert_eq!(
        check(
            "scrub in all fragment reassemble\nblock drop in all\nanchor \"quick\" all\nblock drop in all",
            &anchors,
            &traffic
        ),
        anchor_pass("quick")
    );
    assert_eq!(
        check(
            "scrub in all fragment reassemble\nblock drop in all\nanchor \"plain\" all",
            &anchors,
            &traffic
        ),
        anchor_pass("plain")
    );
    assert_eq!(
        check(
            "scrub in all fragment reassemble\nanchor \"plain\" all\nblock drop in all",
            &anchors,
            &traffic
        ),
        block_at(3)
    );
}

#[test]
fn anchors_nest_and_nesting_is_bounded() {
    let nested = anchors(&[
        ("a", "anchor \"b\" all"),
        ("a/b", "pass in proto tcp from any to any port = 22"),
    ]);
    let traffic = traffic("en0", Protocol::Tcp, HOST, 22);
    assert_eq!(
        check(
            "scrub in all fragment reassemble\nblock drop in all\nanchor \"a\" all",
            &nested,
            &traffic
        ),
        Verdict::Pass {
            reason: "matched pass rule at line 1 of anchor \"a/b\"".to_string()
        }
    );
    let looping = anchors(&[("loop", "anchor \"/loop\" all")]);
    assert_eq!(
        check("anchor \"loop\" all", &looping, &traffic),
        unknown("anchor nesting too deep in rule at line 1 of anchor \"loop\"")
    );
}

#[test]
fn a_rule_that_might_enter_an_anchor_keeps_both_outcomes() {
    let anchors = anchors(&[("x", "block drop in all")]);
    let traffic = traffic("en0", Protocol::Tcp, HOST, 22);
    let rules = "pass in all\nanchor \"x\" in proto tcp from 192.0.2.0/24 to any";
    assert_eq!(
        check(rules, &anchors, &traffic),
        unknown("source address restriction in rule at line 2")
    );
}

#[test]
fn unreadable_lines_make_the_verdict_unknown() {
    assert_eq!(
        tcp("block drop in banana", "en0", 22),
        unknown("unrecognized syntax in rule at line 1")
    );
    assert_eq!(
        tcp("this is not pf", "en0", 22),
        unknown("unparseable text in rule at line 1")
    );
    assert_eq!(
        tcp("anchor \"x all", "en0", 22),
        unknown("unparseable text in rule at line 1")
    );
    assert_eq!(
        tcp("block drop in on { en0 en1 } all", "en0", 22),
        unknown("list in rule at line 1")
    );
    assert_eq!(
        tcp("block drop in proto tcp from any to any port =", "en0", 22),
        unknown("unrecognized syntax in rule at line 1")
    );
    assert_eq!(
        tcp("pass in label \"unterminated all", "en0", 22),
        unknown("unparseable text in rule at line 1")
    );
}

#[test]
fn an_earlier_quick_rule_decides_before_an_unreadable_line() {
    assert_eq!(
        tcp("block drop in quick all\nthis is garbage", "en0", 22),
        block_at(1)
    );
}

#[test]
fn comments_blank_lines_and_empty_input() {
    assert_eq!(tcp("", "en0", 22), default_pass());
    assert_eq!(
        tcp("# comment\n\nblock drop in all", "en0", 22),
        block_at(3)
    );
}

#[test]
fn options_after_the_conditions_do_not_change_the_match() {
    let rule = "pass in log (all) quick on en0 inet proto tcp from any to any port = 22 flags S/SA keep state (if-bound) label \"ssh rule\" tag \"t\"";
    assert_eq!(
        tcp(
            &format!("scrub in all fragment reassemble\nblock drop in all\n{rule}"),
            "en0",
            22
        ),
        pass_at(3)
    );
    assert_eq!(
        tcp("block return-rst in proto tcp all no state", "en0", 22),
        block_at(1)
    );
}

#[test]
fn anchor_names_are_sanitized_in_reasons() {
    let anchors = anchors(&[("a\u{1b}b", "garbage")]);
    let traffic = traffic("en0", Protocol::Tcp, HOST, 22);
    assert_eq!(
        check("anchor \"a\u{1b}b\" all", &anchors, &traffic),
        unknown("unparseable text in rule at line 1 of anchor \"a\\u{1b}b\"")
    );
}

#[test]
fn verdicts_serialize_with_a_verdict_tag() {
    assert_eq!(
        serde_json::to_value(pass_at(3)).unwrap(),
        json!({"verdict": "pass", "reason": "matched pass rule at line 3"})
    );
    assert_eq!(
        serde_json::to_value(block_at(1)).unwrap(),
        json!({"verdict": "block", "reason": "matched block rule at line 1"})
    );
    assert_eq!(
        serde_json::to_value(unknown("table in rule at line 2")).unwrap(),
        json!({"verdict": "unknown", "reason": "table in rule at line 2"})
    );
}
