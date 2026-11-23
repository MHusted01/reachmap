use crate::socket::Protocol;

use super::{
    HOST, Verdict, anchors, block_at, check, default_pass, pass_at, tcp, traffic, unknown,
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
fn ipv4_udp_port_rules_require_reassembly_or_yield_unknown() {
    let udp_v4 = traffic("en0", Protocol::Udp, HOST, 5353);
    let lone_block = "block drop in on en0 inet proto udp from any to any port = 5353";
    assert_eq!(
        check(lone_block, &Default::default(), &udp_v4),
        unknown("unreassembled IPv4 fragment in rule at line 1")
    );

    let reassembled = "scrub in all fragment reassemble\nblock drop in on en0 inet proto udp from any to any port = 5353";
    assert_eq!(
        check(reassembled, &Default::default(), &udp_v4),
        block_at(2)
    );

    let exempted = "scrub in all fragment reassemble\nno scrub in on en0 proto udp all\nblock drop in on en0 inet proto udp from any to any port = 5353";
    assert_eq!(
        check(exempted, &Default::default(), &udp_v4),
        unknown("unreassembled IPv4 fragment in rule at line 3")
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
        block_at(1)
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
