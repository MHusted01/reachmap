//! Server, TLS and route resolution against Caddy's matching rules.

use super::*;
use crate::caddy::DialTarget;
use crate::caddy::routes::tests::server;

fn end_of<'a>(snap: &'a Snapshot, observation: HttpObservation<'static>) -> Option<RouteEnd<'a>> {
    run(snap, observation).route.and_then(|route| route.end)
}

fn proxy_port(end: Option<RouteEnd<'_>>) -> Option<u16> {
    match end {
        Some(RouteEnd::ReverseProxy { upstreams }) => upstreams.first().map(DialTarget::port),
        _ => None,
    }
}

const PLAIN: &str = r#""automatic_https":{"disable":true}"#;

fn sockets() -> Vec<Socket> {
    vec![
        (addr("[::]:8080"), Some(false)),
        (addr("127.0.0.1:18080"), Some(false)),
        (addr("127.0.0.1:18082"), Some(false)),
    ]
}

#[test]
fn tls_mode_must_be_known_and_match_the_scheme() {
    let snap = snapshot(LAB, &lab_sockets());
    let https = HttpObservation {
        tls: true,
        tls_status: TlsStatus::Verified,
        ..obs("/app/x", 200)
    };
    assert_eq!(
        run(&snap, https).comparison,
        unavailable(Gap::TlsSchemeMismatch)
    );

    let tls_json = server(
        r#"{"listen":[":8080"],"tls_connection_policies":[{}],
            "routes":[{"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"127.0.0.1:18080"}]}]}]}"#,
    );
    let tls_snap = snapshot(&tls_json, &sockets());
    assert_eq!(
        run(&tls_snap, obs("/", 200)).comparison,
        unavailable(Gap::TlsSchemeMismatch)
    );
    let https_root = HttpObservation {
        tls: true,
        tls_status: TlsStatus::Verified,
        ..obs("/", 200)
    };
    let report = run(&tls_snap, https_root);
    assert_eq!(report.comparison, Comparison::Consistent {});
    assert!(report.route.expect("route").tls);

    let automatic = server(
        r#"{"listen":[":8080"],
            "routes":[{"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"127.0.0.1:18080"}]}]}]}"#,
    );
    let auto_snap = snapshot(&automatic, &sockets());
    assert_eq!(
        run(&auto_snap, obs("/", 200)).comparison,
        unavailable(Gap::AutomaticHttpsUnverified)
    );
}

#[test]
fn servers_are_matched_by_port_address_and_family() {
    let snap = snapshot(LAB, &lab_sockets());
    let other_port = HttpObservation {
        destination: addr("192.0.2.1:9090"),
        ..obs("/app/x", 200)
    };
    assert_eq!(
        run(&snap, other_port).comparison,
        unavailable(Gap::NoMatchingServer)
    );

    let specific = server(&format!(
        r#"{{"listen":["192.0.2.1:8080","tcp6/[::]:8443"],{PLAIN},
            "routes":[{{"handle":[{{"handler":"reverse_proxy","upstreams":[{{"dial":"127.0.0.1:18080"}}]}}]}}]}}"#
    ));
    let sockets = [
        (addr("192.0.2.1:8080"), Some(false)),
        (addr("[::]:8443"), Some(true)),
        (addr("127.0.0.1:18080"), Some(false)),
    ];
    let snap = snapshot(&specific, &sockets);
    assert_eq!(
        run(&snap, obs("/", 200)).comparison,
        Comparison::Consistent {}
    );
    let other_address = HttpObservation {
        destination: addr("192.0.2.9:8080"),
        ..obs("/", 200)
    };
    assert_eq!(
        run(&snap, other_address).comparison,
        unavailable(Gap::NoMatchingServer)
    );
    let ipv4_to_tcp6 = HttpObservation {
        destination: addr("192.0.2.1:8443"),
        ..obs("/", 200)
    };
    assert_eq!(
        run(&snap, ipv4_to_tcp6).comparison,
        unavailable(Gap::NoMatchingServer)
    );
    let ipv6 = HttpObservation {
        destination: addr("[2001:db8::1]:8443"),
        ..obs("/", 200)
    };
    assert_eq!(run(&snap, ipv6).comparison, Comparison::Consistent {});
}

#[test]
fn overlapping_servers_are_ambiguous() {
    let json = format!(
        r#"{{"apps":{{"http":{{"servers":{{
            "a":{{"listen":[":8080"],{PLAIN},"routes":[]}},
            "b":{{"listen":["192.0.2.1:8080"],{PLAIN},"routes":[]}}}}}}}}}}"#
    );
    let snap = snapshot(&json, &sockets());
    assert_eq!(
        run(&snap, obs("/", 200)).comparison,
        unavailable(Gap::RouteAmbiguous)
    );
}

#[test]
fn hosts_match_case_insensitively_without_port_and_unmatched_requests_fall_through() {
    let snap = snapshot(LAB, &lab_sockets());
    let upper = HttpObservation {
        host: "APP.Example.Test:8080",
        ..obs("/APP/x", 200)
    };
    assert_eq!(proxy_port(end_of(&snap, upper)), Some(18080));

    let other = HttpObservation {
        host: "other.example.test",
        ..obs("/app/x", 200)
    };
    let report = run(&snap, other);
    assert_eq!(
        report.route.as_ref().and_then(|route| route.end),
        Some(RouteEnd::NoHandler {})
    );
    assert_eq!(report.backend, Some(BackendEvidence::NoProxyTarget {}));
    assert_eq!(
        end_of(&snap, obs("/unrouted", 200)),
        Some(RouteEnd::NoHandler {})
    );
}

#[test]
fn wildcard_hosts_match_exactly_one_label() {
    let json = server(&format!(
        r#"{{"listen":[":8080"],{PLAIN},"routes":[{{"match":[{{"host":["*.example.test"]}}],
            "handle":[{{"handler":"reverse_proxy","upstreams":[{{"dial":"127.0.0.1:18080"}}]}}]}}]}}"#
    ));
    let snap = snapshot(&json, &sockets());
    assert_eq!(proxy_port(end_of(&snap, obs("/", 200))), Some(18080));
    let deeper = HttpObservation {
        host: "a.app.example.test",
        ..obs("/", 200)
    };
    assert_eq!(end_of(&snap, deeper), Some(RouteEnd::NoHandler {}));
}

#[test]
fn only_the_first_matching_route_of_a_group_runs_and_terminal_stops() {
    let json = server(&format!(
        r#"{{"listen":[":8080"],{PLAIN},"routes":[
            {{"match":[{{"path":["/stop"]}}],"handle":[{{"handler":"headers"}}],"terminal":true}},
            {{"group":"g","match":[{{"path":["/a/*"]}}],
              "handle":[{{"handler":"reverse_proxy","upstreams":[{{"dial":"127.0.0.1:18080"}}]}}]}},
            {{"group":"g","handle":[{{"handler":"reverse_proxy","upstreams":[{{"dial":"127.0.0.1:18082"}}]}}]}}]}}"#
    ));
    let snap = snapshot(&json, &sockets());
    assert_eq!(proxy_port(end_of(&snap, obs("/a/x", 200))), Some(18080));
    assert_eq!(proxy_port(end_of(&snap, obs("/b", 200))), Some(18082));
    assert_eq!(
        end_of(&snap, obs("/stop", 200)),
        Some(RouteEnd::NoHandler {})
    );
}

#[test]
fn subroute_terminal_returns_to_the_parent_chain() {
    let json = server(&format!(
        r#"{{"listen":[":8080"],{PLAIN},"routes":[
            {{"handle":[
                {{"handler":"subroute","routes":[{{"handle":[{{"handler":"headers"}}],"terminal":true}},
                    {{"handle":[{{"handler":"static_response"}}]}}]}},
                {{"handler":"reverse_proxy","upstreams":[{{"dial":"127.0.0.1:18080"}}]}}]}}]}}"#
    ));
    let snap = snapshot(&json, &sockets());
    assert_eq!(proxy_port(end_of(&snap, obs("/", 200))), Some(18080));
}

#[test]
fn forward_auth_counts_as_proxy_auth_and_continues_the_chain() {
    let json = format!(
        r#"{{"apps":{{"http":{{"servers":{{"srv0":{{"listen":[":8080"],{PLAIN},"routes":[{{"handle":[
            {{"handle_response":[{{"match":{{"status_code":[2]}},"routes":[{{"handle":[{{"handler":"vars"}}]}}]}}],
              "handler":"reverse_proxy","rewrite":{{"method":"GET","uri":"/verify"}},
              "upstreams":[{{"dial":"127.0.0.1:18082"}}]}},
            {{"handler":"reverse_proxy","upstreams":[{{"dial":"127.0.0.1:18080"}}]}}]}}]}}}}}}}}}}"#
    );
    let snap = snapshot(&json, &sockets());
    let report = run(&snap, obs("/", 401));
    assert_eq!(report.comparison, Comparison::Consistent {});
    let auth = report.auth.expect("auth");
    assert!(auth.forward_auth);
    assert_eq!(auth.indicator, ProxyAuthIndicator::Configured);
    assert_eq!(
        proxy_port(report.route.and_then(|route| route.end)),
        Some(18080)
    );
}

#[test]
fn unnormalized_paths_are_not_matched() {
    let snap = snapshot(LAB, &lab_sockets());
    for path in [
        "/app//x",
        "/app/./x",
        "/app/../admin/",
        "/app/%2e",
        "/app/.",
    ] {
        let report = run(&snap, obs(path, 200));
        assert_eq!(
            report.comparison,
            unavailable(Gap::PathNotNormalized),
            "{path}"
        );
        assert!(report.backend.is_none(), "{path}");
    }
}

#[test]
fn incomplete_proxies_and_unresolved_hosts_stay_unverified() {
    let named = LAB.replace("198.51.100.25:8080", "backend.example.test:8080");
    let snap = snapshot(&named, &lab_sockets());
    let report = run(&snap, obs("/remote/x", 200));
    assert_eq!(report.backend, Some(BackendEvidence::UnresolvedHostname {}));
    assert_eq!(report.comparison, unavailable(Gap::ConfigUncertain));

    let without_inventory = collect_with(json_source(LAB), || {
        Err(ScanError::UnsupportedOs { os: "plan9" })
    })
    .expect("report");
    let snap = Snapshot::new(
        "example-caddy".parse().expect("host ref"),
        BASE_TIME,
        without_inventory,
    );
    assert_eq!(
        run(&snap, obs("/app/x", 200)).backend,
        Some(BackendEvidence::LocalTcpUncertain {
            reason: BackendUncertainty::InventoryUnavailable
        })
    );
}
