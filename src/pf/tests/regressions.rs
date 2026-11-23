use crate::socket::Protocol;

use super::{
    DEFAULT_MACOS, HOST, Ruleset, Verdict, anchors, block_at, check, default_pass, ip, pass_at,
    tcp, tcp_to, traffic, unknown,
};

const SCOPED_ANCHORS: &str = include_str!("../../../tests/fixtures/pf/scoped_anchors.txt");
const RDR_TARGET: &str = include_str!("../../../tests/fixtures/pf/rdr_target.txt");
const BLOCK_RETURN_OPTIONS: &str =
    include_str!("../../../tests/fixtures/pf/block_return_options.txt");
const SCRUB_FRAGMENTS: &str = include_str!("../../../tests/fixtures/pf/scrub_fragments.txt");

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
            "scrub in all fragment reassemble\nblock drop in all\nanchor \"local\" quick all\nblock drop in all",
            &child_anchors,
            &packet
        ),
        Verdict::Pass {
            reason: "matched pass rule at line 1 of anchor \"local\"".to_string()
        }
    );
    assert_eq!(
        check(
            "scrub in all fragment reassemble\nblock drop in all\nanchor \"empty\" quick all\nblock drop in all",
            &child_anchors,
            &packet
        ),
        block_at(4)
    );
    assert_eq!(
        check(
            "scrub in all fragment reassemble\nblock drop in all\nanchor \"outer\" quick all\nblock drop in all",
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

#[test]
fn inbound_binat_reverse_mapping_triggers_unknown_for_internal_listener() {
    let rules = "binat pass on en0 inet from 192.0.2.10 to 198.51.100.0/24 -> 203.0.113.10\nblock drop in all";
    assert_eq!(
        tcp_to(rules, "en0", HOST, 22),
        unknown("translation rule in rule at line 1")
    );
    assert_eq!(
        tcp_to(rules, "en0", "203.0.113.10", 22),
        unknown("translation rule in rule at line 1")
    );
    assert_eq!(tcp_to(rules, "en0", "192.0.2.99", 22), block_at(2));
    assert_eq!(tcp_to(rules, "en1", HOST, 22), block_at(2));

    let mut allowed_peer = traffic("en0", Protocol::Tcp, HOST, 22);
    allowed_peer.source = Some(ip("198.51.100.5"));
    assert_eq!(
        check(rules, &Default::default(), &allowed_peer),
        unknown("translation rule in rule at line 1")
    );

    let mut other_peer = traffic("en0", Protocol::Tcp, HOST, 22);
    other_peer.source = Some(ip("192.0.2.50"));
    assert_eq!(check(rules, &Default::default(), &other_peer), block_at(2));
}

#[test]
fn tcp_ecn_opening_syn_flags_are_evaluated_alongside_bare_syn() {
    assert_eq!(
        tcp(
            "scrub in all fragment reassemble\nblock drop in all\npass in on en0 proto tcp from any to any port = 22 flags SEW/SAEW",
            "en0",
            22
        ),
        unknown("tcp flags (ECN) in rule at line 3")
    );
    assert_eq!(
        tcp(
            "scrub in all fragment reassemble\nblock drop in all\npass in on en0 proto tcp from any to any port = 22 flags S/SAEW",
            "en0",
            22
        ),
        unknown("tcp flags (ECN) in rule at line 3")
    );
    assert_eq!(
        tcp(
            "scrub in all fragment reassemble\nblock drop in all\npass in on en0 proto tcp from any to any port = 22 flags S/SAEW\npass in on en0 proto tcp from any to any port = 22 flags SEW/SAEW",
            "en0",
            22
        ),
        pass_at(3)
    );
    assert_eq!(
        tcp(
            "scrub in all fragment reassemble\nblock drop in all\npass in on en0 proto tcp from any to any port = 22 flags S/SA",
            "en0",
            22
        ),
        pass_at(3)
    );
}

#[test]
fn wildcard_anchors_evaluate_direct_children_and_require_complete_marker() {
    let packet = traffic("en0", Protocol::Tcp, HOST, 22);
    let ordered = anchors(&[
        ("com.apple/*", ""),
        ("com.apple/100.scrub", "scrub in all fragment reassemble"),
        (
            "com.apple/200.allow",
            "pass in on en0 proto tcp from any to any port = 22",
        ),
        (
            "com.apple/250.deny",
            "block drop in on en0 proto tcp from any to any port = 22",
        ),
    ]);
    assert_eq!(
        check(DEFAULT_MACOS, &ordered, &packet),
        Verdict::Block {
            reason: "matched block rule at line 1 of anchor \"com.apple/250.deny\"".to_string()
        }
    );

    let quick_child = anchors(&[
        ("com.apple/*", ""),
        ("com.apple/100.scrub", "scrub in all fragment reassemble"),
        (
            "com.apple/200.allow",
            "pass in quick on en0 proto tcp from any to any port = 22",
        ),
        (
            "com.apple/250.deny",
            "block drop in on en0 proto tcp from any to any port = 22",
        ),
    ]);
    assert_eq!(
        check(DEFAULT_MACOS, &quick_child, &packet),
        Verdict::Pass {
            reason: "matched pass rule at line 1 of anchor \"com.apple/200.allow\"".to_string()
        }
    );

    let incomplete = anchors(&[(
        "com.apple/200.allow",
        "pass in on en0 proto tcp from any to any port = 22",
    )]);
    assert_eq!(
        check(DEFAULT_MACOS, &incomplete, &packet),
        unknown("missing anchor ruleset in rule at line 1")
    );
    assert_eq!(
        check(
            "pass in all\nanchor \"com.apple/*\" all",
            &incomplete,
            &packet
        ),
        unknown("missing anchor ruleset in rule at line 2")
    );

    let quick_wildcard = anchors(&[
        ("site/*", ""),
        ("site/web", "pass in proto tcp from any to any port = 22"),
        (
            "site/web/sub",
            "block drop in proto tcp from any to any port = 22",
        ),
    ]);
    assert_eq!(
        check(
            "scrub in all fragment reassemble\nanchor \"site/*\" quick all\nblock drop in all",
            &quick_wildcard,
            &packet
        ),
        Verdict::Pass {
            reason: "matched pass rule at line 1 of anchor \"site/web\"".to_string()
        }
    );

    let child_rdr = anchors(&[
        ("site/*", ""),
        (
            "site/web",
            "rdr on en0 inet proto tcp from any to any port = 80 -> 192.0.2.10 port 8080",
        ),
    ]);
    assert_eq!(
        check(
            "anchor \"site/*\" all",
            &child_rdr,
            &traffic("en0", Protocol::Tcp, HOST, 8080)
        ),
        unknown("translation rule in rule at line 1 of anchor \"site/web\"")
    );
}

#[test]
fn parent_relative_anchor_paths_resolve_against_parent() {
    let packet = traffic("en0", Protocol::Tcp, HOST, 22);
    let sibling = anchors(&[
        ("site", "anchor \"app\" all"),
        ("site/app", "anchor \"../rules\" all"),
        ("site/rules", "pass in proto tcp from any to any port = 22"),
    ]);
    assert_eq!(
        check(SCOPED_ANCHORS, &sibling, &packet),
        Verdict::Pass {
            reason: "matched pass rule at line 1 of anchor \"site/rules\"".to_string()
        }
    );

    let to_root = anchors(&[
        ("site", "anchor \"app\" all"),
        ("site/app", "anchor \"../../root_rules\" all"),
        ("root_rules", "pass in proto tcp from any to any port = 22"),
    ]);
    assert_eq!(
        check(SCOPED_ANCHORS, &to_root, &packet),
        Verdict::Pass {
            reason: "matched pass rule at line 1 of anchor \"root_rules\"".to_string()
        }
    );

    let above_root = anchors(&[("site", "anchor \"../../escape\" all")]);
    assert_eq!(
        check(SCOPED_ANCHORS, &above_root, &packet),
        unknown("missing anchor ruleset in rule at line 1 of anchor \"site\"")
    );

    let sibling_rdr = anchors(&[
        ("site", "anchor \"app\" all"),
        ("site/app", "anchor \"../rules\" all"),
        (
            "site/rules",
            "rdr on en0 inet proto tcp from any to any port = 80 -> 192.0.2.10 port 8080",
        ),
    ]);
    assert_eq!(
        check(
            SCOPED_ANCHORS,
            &sibling_rdr,
            &traffic("en0", Protocol::Tcp, HOST, 8080)
        ),
        unknown("translation rule in rule at line 1 of anchor \"site/rules\"")
    );
}

#[test]
fn set_skip_rejects_trailing_tokens() {
    assert_eq!(
        tcp(
            "set skip on lo0 garbage\nblock drop in quick all",
            "lo0",
            22
        ),
        unknown("unparseable text in rule at line 1")
    );
    assert_eq!(
        tcp(
            "set skip on { lo0 } extra\nblock drop in quick all",
            "lo0",
            22
        ),
        unknown("unparseable text in rule at line 1")
    );
}

#[test]
fn verdict_changing_options_after_unsupported_conditions_are_preserved() {
    assert_eq!(
        tcp(
            "pass in quick proto tcp from any to <services> flags S/SA keep state (max 1)",
            "en0",
            22
        ),
        unknown("state limit in rule at line 1")
    );
    assert_eq!(
        tcp(
            "pass in proto tcp from any to <services> route-to (en1 192.0.2.1)",
            "en0",
            22
        ),
        unknown("route-to option in rule at line 1")
    );
}

#[test]
fn wildcard_marker_contents_are_ignored_in_both_walks() {
    let packet = traffic("en0", Protocol::Tcp, HOST, 22);
    let marker_block = anchors(&[
        ("site/*", "block drop in quick all"),
        ("site/web", "pass in proto tcp from any to any port = 22"),
    ]);
    assert_eq!(
        check("anchor \"site/*\" all", &marker_block, &packet),
        Verdict::Pass {
            reason: "matched pass rule at line 1 of anchor \"site/web\"".to_string()
        }
    );

    let marker_rdr = anchors(&[
        (
            "site/*",
            "rdr on en0 inet proto tcp from any to any port = 22 -> 192.0.2.10 port 8080",
        ),
        ("site/web", "pass in proto tcp from any to any port = 22"),
    ]);
    assert_eq!(
        check("anchor \"site/*\" all", &marker_rdr, &packet),
        Verdict::Pass {
            reason: "matched pass rule at line 1 of anchor \"site/web\"".to_string()
        }
    );
}

#[test]
fn duplicate_endpoint_clauses_are_rejected_as_unknown() {
    let dup_to = "block drop in quick proto tcp from any to any port = 22 to any";
    assert_eq!(
        tcp(dup_to, "en0", 80),
        unknown("unrecognized syntax in rule at line 1")
    );
    assert_eq!(
        tcp(dup_to, "en0", 22),
        unknown("unrecognized syntax in rule at line 1")
    );
    assert_eq!(
        tcp(
            "block drop in quick proto tcp from 192.0.2.1 from 198.51.100.1 to any",
            "en0",
            22
        ),
        unknown("unrecognized syntax in rule at line 1")
    );
}

#[test]
fn block_return_options_with_parentheses_are_accepted() {
    assert_eq!(tcp(BLOCK_RETURN_OPTIONS, "en0", 23), block_at(2));
    assert_eq!(
        check(
            BLOCK_RETURN_OPTIONS,
            &Default::default(),
            &traffic("en0", Protocol::Udp, HOST, 161)
        ),
        block_at(3)
    );
    assert_eq!(
        check(
            BLOCK_RETURN_OPTIONS,
            &Default::default(),
            &traffic("en0", Protocol::Udp, "2001:db8::1", 161)
        ),
        block_at(4)
    );
    assert_eq!(tcp(BLOCK_RETURN_OPTIONS, "en0", 22), default_pass());
}

#[test]
fn earliest_ecn_sensitive_rule_is_named_in_reason() {
    assert_eq!(
        tcp(
            "block drop in all\npass in on en0 proto tcp from any to any port = 22 flags SEW/SAEW\npass in on en0 proto tcp from any to any port = 22 flags SEW/SAEW",
            "en0",
            22
        ),
        unknown("tcp flags (ECN) in rule at line 2")
    );
}

#[test]
fn nested_quick_anchor_unwinds_through_non_quick_outer_anchor() {
    let packet = traffic("en0", Protocol::Tcp, HOST, 22);
    let non_quick_outer = anchors(&[
        ("outer", "anchor \"inner\" quick all"),
        ("outer/inner", "block drop in all"),
    ]);
    assert_eq!(
        check(
            "anchor \"outer\" all\npass in all",
            &non_quick_outer,
            &packet
        ),
        pass_at(2)
    );

    let outer_with_more = anchors(&[
        ("outer", "anchor \"inner\" quick all\npass in proto udp all"),
        ("outer/inner", "block drop in all"),
    ]);
    assert_eq!(
        check(
            "anchor \"outer\" all\npass in all",
            &outer_with_more,
            &packet
        ),
        Verdict::Block {
            reason: "matched block rule at line 1 of anchor \"outer/inner\"".to_string()
        }
    );

    assert_eq!(
        check(
            "anchor \"outer\" quick all\npass in all",
            &non_quick_outer,
            &packet
        ),
        Verdict::Block {
            reason: "matched block rule at line 1 of anchor \"outer/inner\"".to_string()
        }
    );

    let inner_quick_rule = anchors(&[
        ("outer", "anchor \"inner\" all"),
        ("outer/inner", "block drop in quick all"),
    ]);
    assert_eq!(
        check(
            "anchor \"outer\" all\npass in all",
            &inner_quick_rule,
            &packet
        ),
        Verdict::Block {
            reason: "matched block rule at line 1 of anchor \"outer/inner\"".to_string()
        }
    );
}

#[test]
fn embedded_dot_dot_segments_in_anchor_paths_are_preserved() {
    let packet = traffic("en0", Protocol::Tcp, HOST, 22);
    let both = anchors(&[
        ("rules", "block drop in all"),
        (
            "site/../rules",
            "pass in proto tcp from any to any port = 22",
        ),
    ]);
    assert_eq!(
        check("anchor \"site/../rules\" all", &both, &packet),
        Verdict::Pass {
            reason: "matched pass rule at line 1 of anchor \"site/../rules\"".to_string()
        }
    );

    let only_root = anchors(&[("rules", "block drop in all")]);
    assert_eq!(
        check("anchor \"site/../rules\" all", &only_root, &packet),
        unknown("missing anchor ruleset in rule at line 1")
    );
}

#[test]
fn scrub_rules_that_can_change_filtering_yield_unknown() {
    let udp_en0 = traffic("en0", Protocol::Udp, HOST, 5353);
    assert_eq!(
        check(SCRUB_FRAGMENTS, &Default::default(), &udp_en0),
        unknown("normalization rule in rule at line 1")
    );
    assert_eq!(tcp(SCRUB_FRAGMENTS, "en0", 5353), block_at(2));
    assert_eq!(
        check(
            SCRUB_FRAGMENTS,
            &Default::default(),
            &traffic("en1", Protocol::Udp, HOST, 5353)
        ),
        block_at(2)
    );

    let benign = "scrub in all fragment reassemble\nblock drop in all\npass in on en0 proto udp from any to any port = 5353";
    assert_eq!(check(benign, &Default::default(), &udp_en0), pass_at(3));

    let skipped = "set skip on lo0\nscrub in on lo0 all fragment crop\nblock drop in all";
    assert_eq!(
        tcp_to(skipped, "lo0", "127.0.0.1", 5353),
        Verdict::Pass {
            reason: "the interface is excluded by set skip".to_string()
        }
    );

    let anchored = anchors(&[
        ("com.apple/*", ""),
        (
            "com.apple/frag",
            "scrub in on en0 proto udp all fragment drop-ovl",
        ),
    ]);
    assert_eq!(
        check(
            "scrub-anchor \"com.apple/*\" all fragment reassemble\nanchor \"com.apple/*\" all",
            &anchored,
            &udp_en0
        ),
        unknown("normalization rule in rule at line 1 of anchor \"com.apple/frag\"")
    );
}

#[test]
fn duplicate_family_direction_and_protocol_clauses_are_rejected() {
    let families = "block drop in quick inet inet6 all";
    assert_eq!(
        tcp(families, "en0", 22),
        unknown("unrecognized syntax in rule at line 1")
    );
    assert_eq!(
        tcp_to(families, "en0", "2001:db8::1", 22),
        unknown("unrecognized syntax in rule at line 1")
    );
    assert_eq!(
        tcp("block drop in out all", "en0", 22),
        unknown("unrecognized syntax in rule at line 1")
    );
    assert_eq!(
        tcp("block drop in proto tcp proto udp all", "en0", 22),
        unknown("unrecognized syntax in rule at line 1")
    );
}

#[test]
fn tos_condition_yields_named_unknown_with_line_number() {
    assert_eq!(
        check(
            "block drop in quick inet proto udp all tos 0x10",
            &Default::default(),
            &traffic("en0", Protocol::Udp, HOST, 5353)
        ),
        unknown("tos condition in rule at line 1")
    );
}
