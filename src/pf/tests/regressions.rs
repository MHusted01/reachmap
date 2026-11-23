use crate::socket::Protocol;

use super::{
    HOST, Ruleset, Verdict, anchors, block_at, check, default_pass, pass_at, tcp, tcp_to, traffic,
    unknown,
};

const SCOPED_ANCHORS: &str = include_str!("../../../tests/fixtures/pf/scoped_anchors.txt");
const RDR_TARGET: &str = include_str!("../../../tests/fixtures/pf/rdr_target.txt");

#[test]
fn quick_anchor_stops_after_a_matching_child_rule() {
    let child_anchors = anchors(&[
        ("local", "pass in proto tcp from any to any port = 22"),
        ("empty", "pass in proto tcp from any to any port = 80"),
        ("outer", "anchor \"inner\" all"),
        ("outer/inner", "pass in proto tcp from any to any port = 22"),
    ]);
    let packet = traffic("en0", Protocol::Tcp, HOST, 22);
    assert_eq!(
        check(
            "block drop in all\nanchor \"local\" quick all\nblock drop in all",
            &child_anchors,
            &packet
        ),
        Verdict::Pass {
            reason: "matched pass rule at line 1 of anchor \"local\"".to_string()
        }
    );
    assert_eq!(
        check(
            "block drop in all\nanchor \"empty\" quick all\nblock drop in all",
            &child_anchors,
            &packet
        ),
        block_at(3)
    );
    assert_eq!(
        check(
            "block drop in all\nanchor \"outer\" quick all\nblock drop in all",
            &child_anchors,
            &packet
        ),
        Verdict::Pass {
            reason: "matched pass rule at line 1 of anchor \"outer/inner\"".to_string()
        }
    );
}

#[test]
fn anchor_lookup_resolves_relative_and_root_paths() {
    let packet = traffic("en0", Protocol::Tcp, HOST, 22);
    let scoped = anchors(&[
        ("site", "anchor \"rules\" all"),
        ("rules", "block drop in all"),
        ("site/rules", "pass in proto tcp from any to any port = 22"),
    ]);
    assert_eq!(
        check(SCOPED_ANCHORS, &scoped, &packet),
        Verdict::Pass {
            reason: "matched pass rule at line 1 of anchor \"site/rules\"".to_string()
        }
    );

    let root_only = anchors(&[
        ("site", "anchor \"rules\" all"),
        ("rules", "block drop in all"),
    ]);
    assert_eq!(
        check(SCOPED_ANCHORS, &root_only, &packet),
        unknown("missing anchor ruleset in rule at line 1 of anchor \"site\"")
    );

    let explicit_root = anchors(&[
        ("site", "anchor \"/rules\" all"),
        ("rules", "block drop in all"),
    ]);
    assert_eq!(
        check(SCOPED_ANCHORS, &explicit_root, &packet),
        Verdict::Block {
            reason: "matched block rule at line 1 of anchor \"rules\"".to_string()
        }
    );

    let scoped_rdr = anchors(&[
        ("site", "anchor \"rules\" all"),
        (
            "site/rules",
            "rdr on en0 inet proto tcp from any to any port = 80 -> 192.0.2.10 port 8080",
        ),
    ]);
    assert_eq!(
        check(
            SCOPED_ANCHORS,
            &scoped_rdr,
            &traffic("en0", Protocol::Tcp, HOST, 8080)
        ),
        unknown("translation rule in rule at line 1 of anchor \"site/rules\"")
    );
}

#[test]
fn redirect_target_port_and_address_trigger_unknown() {
    assert_eq!(
        tcp(RDR_TARGET, "en0", 8080),
        unknown("translation rule in rule at line 1")
    );
    assert_eq!(
        tcp(RDR_TARGET, "en0", 80),
        unknown("translation rule in rule at line 1")
    );
    assert_eq!(tcp(RDR_TARGET, "en0", 22), block_at(2));
    assert_eq!(tcp_to(RDR_TARGET, "en0", "192.0.2.50", 8080), block_at(2));

    let inherit_port =
        "rdr on en0 inet proto tcp from any to any port = 80 -> 192.0.2.10\nblock drop in all";
    assert_eq!(
        tcp(inherit_port, "en0", 80),
        unknown("translation rule in rule at line 1")
    );
    assert_eq!(tcp(inherit_port, "en0", 8080), block_at(2));

    let dynamic =
        "rdr on en0 inet proto tcp from any to any port = 80 -> (en0) port 8080\nblock drop in all";
    assert_eq!(
        tcp(dynamic, "en0", 8080),
        unknown("translation rule in rule at line 1")
    );
    assert_eq!(tcp(dynamic, "en0", 22), block_at(2));

    let range_remap = "rdr on en0 inet proto tcp from any to any port 8000:8100 -> 192.0.2.10 port 9000\nblock drop in all";
    assert_eq!(
        tcp(range_remap, "en0", 9050),
        unknown("translation rule in rule at line 1")
    );
}

#[test]
fn set_skip_bypasses_translation_rules() {
    let skipped = Verdict::Pass {
        reason: "the interface is excluded by set skip".to_string(),
    };
    let rules = "set skip on lo0\nrdr on lo0 inet proto tcp from any to any port = 80 -> 127.0.0.1 port 8080";
    assert_eq!(tcp_to(rules, "lo0", "127.0.0.1", 8080), skipped);

    let other_if = "set skip on lo0\nrdr on en0 inet proto tcp from any to any port = 80 -> 192.0.2.10 port 8080";
    assert_eq!(
        tcp(other_if, "en0", 8080),
        unknown("translation rule in rule at line 2")
    );

    let group_skip = "set skip on lo\nrdr on lo0 inet proto tcp from any to any port = 80 -> 127.0.0.1 port 8080";
    assert_eq!(
        tcp_to(group_skip, "lo0", "127.0.0.1", 8080),
        unknown("translation rule in rule at line 2")
    );
}

#[test]
fn routing_options_stay_unknown_even_against_default_pass() {
    assert_eq!(
        tcp(
            "pass in quick on en0 route-to (en1 192.0.2.1) all",
            "en0",
            22
        ),
        unknown("route-to option in rule at line 1")
    );
    assert_eq!(
        tcp("pass in on en0 reply-to en1 all", "en0", 22),
        unknown("reply-to option in rule at line 1")
    );
    assert_eq!(
        tcp(
            "pass in on en0 route-to (en1 192.0.2.1) all\nblock drop in all",
            "en0",
            22
        ),
        block_at(2)
    );
    assert_eq!(
        tcp(
            "pass in quick on en0 route-to (en1 192.0.2.1) proto udp all",
            "en0",
            22
        ),
        default_pass()
    );
}

#[test]
fn state_limits_make_deciding_rules_unknown() {
    let limited =
        "pass in quick on en0 proto tcp from any to any port = 22 flags S/SA keep state (max 1)";
    assert_eq!(
        tcp(limited, "en0", 22),
        unknown("state limit in rule at line 1")
    );
    assert_eq!(
        tcp(
            "pass in quick on en0 proto tcp from any to any port = 22 flags S/SA keep state (if-bound, max-src-conn 5)",
            "en0",
            22
        ),
        unknown("state limit in rule at line 1")
    );
    assert_eq!(
        tcp(
            "pass in quick on en0 proto tcp from any to any port = 22 flags S/SA keep state (if-bound)",
            "en0",
            22
        ),
        pass_at(1)
    );
    assert_eq!(
        tcp(
            "pass in on en0 proto tcp from any to any port = 22 flags S/SA keep state (max 1)\nblock drop in all",
            "en0",
            22
        ),
        block_at(2)
    );
}

#[test]
fn filter_rules_reject_translation_arrows() {
    assert_eq!(
        tcp("block drop in all ->", "en0", 22),
        unknown("unrecognized syntax in rule at line 1")
    );
    assert_eq!(
        tcp("pass in all ->", "en0", 22),
        unknown("unrecognized syntax in rule at line 1")
    );
    assert_eq!(
        tcp("block drop in all\nblock drop in all ->", "en0", 22),
        unknown("unrecognized syntax in rule at line 2")
    );
}

#[test]
fn negated_tagged_names_construct_without_echoing_tag() {
    let rules = "pass in all\nblock drop in quick on en0 proto tcp from any to any port = 22 ! tagged secret-tag";
    let result = tcp(rules, "en0", 22);
    assert_eq!(result, unknown("tagged condition in rule at line 2"));
    if let Verdict::Unknown { reason } = result {
        assert!(!reason.contains("secret-tag"));
    }
    assert_eq!(
        tcp(
            "pass in all\nblock drop in quick on en0 proto tcp from any to any port = 22 !tagged secret-tag",
            "en0",
            22
        ),
        unknown("tagged condition in rule at line 2")
    );
}

#[test]
fn parse_time_sanitization_strips_bidi_from_debug_and_rejects_bad_names() {
    let debug = format!("{:?}", Ruleset::parse("anchor \"a\u{202e}b\" all"));
    assert!(!debug.contains('\u{202e}'));
    assert!(debug.contains("\\u{202e}"));

    assert_eq!(
        tcp("block drop in on en0\u{202e} all", "en0", 22),
        unknown("unrecognized syntax in rule at line 1")
    );
    assert_eq!(
        tcp("set skip on lo0\u{202e}\nblock drop in all", "lo0", 22),
        unknown("unparseable text in rule at line 1")
    );
}
