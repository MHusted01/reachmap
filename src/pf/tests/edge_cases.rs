use crate::socket::Protocol;

use super::{
    HOST, Verdict, anchors, block_at, check, default_pass, pass_at, tcp, tcp_to, traffic, unknown,
};

#[test]
fn nested_anchor_entry_clears_previous_match_flag() {
    let packet = traffic("en0", Protocol::Tcp, HOST, 22);
    let empty_child = anchors(&[
        ("outer", "block drop in all\nanchor \"empty\" all"),
        ("outer/empty", ""),
    ]);
    assert_eq!(
        check(
            "anchor \"outer\" quick all\npass in all",
            &empty_child,
            &packet
        ),
        pass_at(2)
    );

    let skipped_child = anchors(&[
        ("outer", "block drop in all\nanchor \"other\" on en1 all"),
        ("outer/other", ""),
    ]);
    assert_eq!(
        check(
            "anchor \"outer\" quick all\npass in all",
            &skipped_child,
            &packet
        ),
        Verdict::Block {
            reason: "matched block rule at line 1 of anchor \"outer\"".to_string()
        }
    );
}

#[test]
fn udp_port_rules_require_reassembly_and_follow_first_match_scrub() {
    let udp_v4 = traffic("en0", Protocol::Udp, HOST, 5353);
    let lone_block = "block drop in on en0 inet proto udp from any to any port = 5353";
    assert_eq!(
        check(lone_block, &Default::default(), &udp_v4),
        unknown("unreassembled fragment in rule at line 1")
    );

    let reassembled = "scrub in all fragment reassemble\nblock drop in on en0 inet proto udp from any to any port = 5353";
    assert_eq!(
        check(reassembled, &Default::default(), &udp_v4),
        block_at(2)
    );

    let scrub_before_no_scrub = "scrub in all fragment reassemble\nno scrub in on en0 proto udp all\nblock drop in on en0 inet proto udp from any to any port = 5353";
    assert_eq!(
        check(scrub_before_no_scrub, &Default::default(), &udp_v4),
        block_at(3)
    );

    let no_scrub_before_scrub = "no scrub in on en0 proto udp all\nscrub in all fragment reassemble\nblock drop in on en0 inet proto udp from any to any port = 5353";
    assert_eq!(
        check(no_scrub_before_scrub, &Default::default(), &udp_v4),
        unknown("unreassembled fragment in rule at line 3")
    );

    let no_port_with_no_scrub = "no scrub in on en0 all\nblock drop in all";
    assert_eq!(
        check(no_port_with_no_scrub, &Default::default(), &udp_v4),
        block_at(2)
    );

    let udp_v6 = traffic("en0", Protocol::Udp, "2001:db8::1", 5353);
    let lone_v6_block = "block drop in on en0 inet6 proto udp from any to any port = 5353";
    assert_eq!(
        check(lone_v6_block, &Default::default(), &udp_v6),
        unknown("unreassembled fragment in rule at line 1")
    );

    let v6_reassembled = "scrub in all fragment reassemble\nblock drop in on en0 inet6 proto udp from any to any port = 5353";
    assert_eq!(
        check(v6_reassembled, &Default::default(), &udp_v6),
        block_at(2)
    );
}

#[test]
fn unresolved_scrub_anchor_yields_unknown_without_filter_anchor() {
    let udp_v4 = traffic("en0", Protocol::Udp, HOST, 5353);
    let missing = "scrub-anchor \"missing\" all\nblock drop in all\npass in on en0 proto udp from any to any port = 5353";
    assert_eq!(
        check(missing, &Default::default(), &udp_v4),
        unknown("missing anchor ruleset in rule at line 1")
    );

    let incomplete_wild = "scrub-anchor \"site/*\" all\nblock drop in all";
    let partial = anchors(&[("site/web", "scrub in all fragment reassemble")]);
    assert_eq!(
        check(incomplete_wild, &partial, &udp_v4),
        unknown("missing anchor ruleset in rule at line 1")
    );

    let loop_scrub = anchors(&[("loop", "scrub-anchor \"/loop\" all")]);
    assert_eq!(
        check("scrub-anchor \"loop\" all", &loop_scrub, &udp_v4),
        unknown("anchor nesting too deep in rule at line 1 of anchor \"loop\"")
    );

    let supplied = anchors(&[("norm", "scrub in all fragment reassemble")]);
    let with_norm = "scrub-anchor \"norm\" all\nblock drop in on en0 inet proto udp from any to any port = 5353";
    assert_eq!(check(with_norm, &supplied, &udp_v4), block_at(2));
}

#[test]
fn duplicate_protocol_after_icmp_is_rejected_and_valid_icmp_still_parses() {
    assert_eq!(
        tcp("block drop in quick proto icmp proto tcp all", "en0", 22),
        unknown("unrecognized syntax in rule at line 1")
    );
    assert_eq!(
        tcp(
            "block drop in quick proto icmp all icmp-type echoreq code 0",
            "en0",
            22
        ),
        default_pass()
    );
}

#[test]
fn anchor_path_edge_cases_for_dot_dot_dot_slash_and_double_slash() {
    let packet = traffic("en0", Protocol::Tcp, HOST, 22);
    let bare_dot_dot = anchors(&[("site", "anchor \"..\" all")]);
    assert_eq!(
        check("anchor \"site\" all", &bare_dot_dot, &packet),
        unknown("missing anchor ruleset in rule at line 1 of anchor \"site\"")
    );

    let dot_slash = anchors(&[
        ("site", "anchor \"./rules\" all"),
        ("site/rules", "block drop in all"),
        (
            "site/./rules",
            "pass in proto tcp from any to any port = 22",
        ),
    ]);
    assert_eq!(
        check("anchor \"site\" all", &dot_slash, &packet),
        Verdict::Pass {
            reason: "matched pass rule at line 1 of anchor \"site/./rules\"".to_string()
        }
    );

    let double_slash = anchors(&[
        ("a/b", "block drop in all"),
        ("a//b", "pass in proto tcp from any to any port = 22"),
    ]);
    assert_eq!(
        check("anchor \"a//b\" all", &double_slash, &packet),
        Verdict::Pass {
            reason: "matched pass rule at line 1 of anchor \"a//b\"".to_string()
        }
    );
}

#[test]
fn wildcard_multi_child_promotes_trailing_quick_anchor_stop() {
    let packet = traffic("en0", Protocol::Tcp, HOST, 22);
    let tree = anchors(&[
        ("outer/*", ""),
        ("outer/100", "anchor \"inner\" quick all"),
        ("outer/100/inner", "block drop in all"),
        ("outer/200", "pass in proto udp all"),
    ]);
    assert_eq!(
        check("anchor \"outer/*\" all\npass in all", &tree, &packet),
        Verdict::Block {
            reason: "matched block rule at line 1 of anchor \"outer/100/inner\"".to_string()
        }
    );
}

#[test]
fn wildcard_preserves_earlier_child_match_across_later_empty_anchor() {
    let packet = traffic("en0", Protocol::Tcp, HOST, 22);
    let tree = anchors(&[
        ("site/*", ""),
        ("site/100", "pass in proto tcp from any to any port = 22"),
        ("site/200", "anchor \"empty\" all"),
        ("site/200/empty", ""),
    ]);
    assert_eq!(
        check(
            "scrub in all fragment reassemble\nanchor \"site/*\" quick all\nblock drop in all",
            &tree,
            &packet
        ),
        Verdict::Pass {
            reason: "matched pass rule at line 1 of anchor \"site/100\"".to_string()
        }
    );
}

#[test]
fn urpf_failed_and_no_route_yield_named_unknowns() {
    assert_eq!(
        tcp("block drop in quick from urpf-failed to any", "en0", 22),
        unknown("urpf-failed condition in rule at line 1")
    );
    assert_eq!(
        tcp(
            "pass in all\nblock drop in quick from no-route to any",
            "en0",
            22
        ),
        unknown("no-route condition in rule at line 2")
    );
}

#[test]
fn all_is_mutually_exclusive_with_explicit_host_clauses() {
    assert_eq!(
        tcp("block drop in quick all from any to any", "en0", 22),
        unknown("unrecognized syntax in rule at line 1")
    );
    let trailing_all = "block drop in quick from any to any port = 22 all";
    assert_eq!(
        tcp(trailing_all, "en0", 22),
        unknown("unrecognized syntax in rule at line 1")
    );
    assert_eq!(
        tcp(trailing_all, "en0", 80),
        unknown("unrecognized syntax in rule at line 1")
    );
    assert_eq!(
        tcp("block drop in quick all all", "en0", 22),
        unknown("unrecognized syntax in rule at line 1")
    );
}

#[test]
fn nested_non_quick_wildcard_consumes_match_on_quick_outer_unwind() {
    let packet = traffic("en0", Protocol::Tcp, HOST, 22);
    let tree = anchors(&[
        ("outer", "anchor \"sub/*\" all"),
        ("outer/sub/*", ""),
        ("outer/sub/10", "block drop in all"),
    ]);
    assert_eq!(
        check("anchor \"outer\" quick all\npass in all", &tree, &packet),
        pass_at(2)
    );

    let quick_wildcard = anchors(&[
        ("outer", "anchor \"sub/*\" quick all"),
        ("outer/sub/*", ""),
        ("outer/sub/10", "block drop in all"),
    ]);
    assert_eq!(
        check(
            "anchor \"outer\" quick all\npass in all",
            &quick_wildcard,
            &packet
        ),
        Verdict::Block {
            reason: "matched block rule at line 1 of anchor \"outer/sub/10\"".to_string()
        }
    );
}

#[test]
fn ipv6_scrub_ignores_protocol_predicate_while_ipv4_checks_it() {
    let rules = "scrub in proto udp from any to any fragment reassemble\nblock drop in all\npass in on en0 proto tcp from any to any port = 22";
    assert_eq!(tcp_to(rules, "en0", "2001:db8::1", 22), pass_at(3));
    assert_eq!(
        tcp(rules, "en0", 22),
        unknown("unreassembled fragment in rule at line 3")
    );
}

#[test]
fn tcp_port_and_flag_rules_require_reassembly_unless_flags_any() {
    let port_rule = "block drop in all\npass in on en0 proto tcp from any to any port = 22";
    assert_eq!(
        tcp(port_rule, "en0", 22),
        unknown("unreassembled fragment in rule at line 2")
    );
    assert_eq!(
        tcp(
            &format!("scrub in all fragment reassemble\n{port_rule}"),
            "en0",
            22
        ),
        pass_at(3)
    );

    let flag_rule = "block drop in all\npass in on en0 proto tcp all flags S/SA";
    assert_eq!(
        tcp(flag_rule, "en0", 22),
        unknown("unreassembled fragment in rule at line 2")
    );
    assert_eq!(
        tcp(
            "block drop in all\npass in on en0 proto tcp all flags any",
            "en0",
            22
        ),
        pass_at(2)
    );
}

#[test]
fn scrub_rule_with_table_preserves_table_reason_without_table_name() {
    let reassemble_table = "scrub in on en0 proto tcp from <secret_tbl> to any fragment reassemble\nblock drop in all\npass in on en0 proto tcp from any to any port = 22";
    let reassemble_result = tcp(reassemble_table, "en0", 22);
    assert_eq!(reassemble_result, unknown("table in rule at line 1"));
    if let Verdict::Unknown { reason } = reassemble_result {
        assert!(!reason.contains("secret_tbl"));
    }

    let other_table = "scrub in on en0 from <secret_tbl> to any fragment crop\nblock drop in all";
    let other_result = tcp(other_table, "en0", 22);
    assert_eq!(other_result, unknown("table in rule at line 1"));
    if let Verdict::Unknown { reason } = other_result {
        assert!(!reason.contains("secret_tbl"));
    }
}

#[test]
fn non_quick_outer_preserves_stop_from_trailing_quick_wildcard() {
    let packet = traffic("en0", Protocol::Tcp, HOST, 22);
    let tree = anchors(&[
        ("outer", "anchor \"sub/*\" quick all"),
        ("outer/sub/*", ""),
        ("outer/sub/10", "pass in all"),
    ]);
    assert_eq!(
        check("anchor \"outer\" all\nblock drop in all", &tree, &packet),
        Verdict::Pass {
            reason: "matched pass rule at line 1 of anchor \"outer/sub/10\"".to_string()
        }
    );
}

#[test]
fn ipv6_portless_protocol_rule_requires_reassembly_while_ipv4_does_not() {
    let udp_v6 = traffic("en0", Protocol::Udp, "2001:db8::1", 5353);
    let udp_v4 = traffic("en0", Protocol::Udp, HOST, 5353);

    let lone_v6 = "block drop in quick inet6 proto udp all";
    assert_eq!(
        check(lone_v6, &Default::default(), &udp_v6),
        unknown("unreassembled fragment in rule at line 1")
    );
    assert_eq!(
        check(
            &format!("scrub in all fragment reassemble\n{lone_v6}"),
            &Default::default(),
            &udp_v6
        ),
        block_at(2)
    );
    assert_eq!(
        check(
            "block drop in quick inet proto udp all",
            &Default::default(),
            &udp_v4
        ),
        block_at(1)
    );

    let table_scrub = "scrub in on en0 from <secret_tbl> to any fragment reassemble\nblock drop in quick inet6 proto udp all";
    let table_result = check(table_scrub, &Default::default(), &udp_v6);
    assert_eq!(table_result, unknown("table in rule at line 1"));
    if let Verdict::Unknown { reason } = table_result {
        assert!(!reason.contains("secret_tbl"));
    }

    let port_then_portless = "block drop in quick inet6 proto udp from any to any port = 5353\npass in quick inet6 proto udp all\nblock drop in all";
    assert_eq!(
        check(port_then_portless, &Default::default(), &udp_v6),
        unknown("unreassembled fragment in rule at line 2")
    );

    let post_frag_header = "block drop in all\npass in quick inet6 proto 60 all";
    assert_eq!(
        check(post_frag_header, &Default::default(), &udp_v6),
        unknown("unreassembled fragment in rule at line 2")
    );
    assert_eq!(
        check(
            &format!("scrub in all fragment reassemble\n{post_frag_header}"),
            &Default::default(),
            &udp_v6
        ),
        block_at(2)
    );
}

#[test]
fn fragment_filter_predicate_yields_named_unknown_with_line() {
    assert_eq!(
        tcp("block drop in quick all fragment", "en0", 22),
        unknown("fragment condition in rule at line 1")
    );
    assert_eq!(
        tcp(
            "pass in all\nblock drop in quick inet proto tcp all fragment",
            "en0",
            22
        ),
        unknown("fragment condition in rule at line 2")
    );
    assert_eq!(
        tcp("block drop in quick proto udp all fragment", "en0", 22),
        default_pass()
    );
}

#[test]
fn flags_without_proto_tcp_do_not_trigger_fragment_skip_for_udp() {
    let udp_v4 = traffic("en0", Protocol::Udp, HOST, 5353);
    assert_eq!(
        check("block drop in all flags S/SA", &Default::default(), &udp_v4),
        block_at(1)
    );
    assert_eq!(
        tcp("block drop in all flags S/SA", "en0", 22),
        unknown("unreassembled fragment in rule at line 1")
    );
}

#[test]
fn uncertain_no_scrub_without_reassembly_blames_fragment_rule_not_table() {
    let rules = "no scrub in on en0 from <secret_tbl> to any\nblock drop in all\npass in on en0 proto tcp from any to any port = 22";
    assert_eq!(
        tcp(rules, "en0", 22),
        unknown("unreassembled fragment in rule at line 3")
    );
}
