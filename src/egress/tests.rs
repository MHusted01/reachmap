use super::*;

fn address(ip: &str) -> IpAddr {
    ip.parse().unwrap()
}

fn sample(configured: &str, observed: &str) -> DnsSample {
    DnsSample {
        configured: address(configured),
        observed: Ok(address(observed)),
    }
}

fn report() -> Report {
    Report {
        target: "app".parse().unwrap(),
        host: Observations {
            ipv4: Ok(address("192.0.2.1")),
            ipv6: Ok(address("2001:db8::1")),
            dns: Ok(vec![sample("127.0.0.53", "192.0.2.2")]),
        },
        container: Observations {
            ipv4: Ok(address("198.51.100.1")),
            ipv6: Err("could not connect".into()),
            dns: Ok(vec![sample("127.0.0.11", "198.51.100.2")]),
        },
        unreachable_ipv6_observer: Some(address("2001:db8::53")),
    }
}

#[test]
fn different_ipv4_and_dns_with_no_ipv6_route_complete_the_check() {
    let report = report();
    assert!(report.is_clean());
    let output = report.to_string();
    assert!(output.contains("IPv6: no route to the IPv6 observer"));
    assert!(output.contains("kernel reports no route to 2001:db8::53"));
    assert!(output.contains("container nameserver 127.0.0.11: observed 198.51.100.2"));
}

#[test]
fn a_failed_ipv6_connection_alone_is_unknown() {
    let mut report = report();
    report.unreachable_ipv6_observer = None;
    assert_eq!(report.ipv6(), Verdict::Unknown);
    assert!(!report.is_clean());
}

#[test]
fn ipv6_egress_needs_attention_even_when_the_ip_differs() {
    let mut report = report();
    report.unreachable_ipv6_observer = None;
    report.container.ipv6 = Ok(address("2001:db8::2"));
    assert_eq!(report.ipv6(), Verdict::Different);
    assert!(!report.is_clean());

    report.container.ipv6 = report.host.ipv6.clone();
    assert_eq!(report.ipv6(), Verdict::Same);
    assert!(!report.is_clean());
}

#[test]
fn observed_resolver_overlap_matters_even_when_stubs_differ() {
    let mut report = report();
    report.container.dns = Ok(vec![
        sample("127.0.0.11", "192.0.2.2"),
        sample("198.51.100.3", "198.51.100.3"),
    ]);
    assert_eq!(report.dns(), Verdict::Same);
    assert!(!report.is_clean());
}

#[test]
fn a_missing_resolver_answer_cannot_confirm_a_difference() {
    let mut report = report();
    report.container.dns.as_mut().unwrap().push(DnsSample {
        configured: address("198.51.100.3"),
        observed: Err("DNS timeout".into()),
    });
    assert_eq!(report.dns(), Verdict::Unknown);
    assert!(!report.is_clean());
}

#[test]
fn matching_public_ipv4_needs_attention() {
    let mut report = report();
    report.container.ipv4 = report.host.ipv4.clone();
    assert_eq!(report.ipv4(), Verdict::Same);
    assert!(!report.is_clean());
}
