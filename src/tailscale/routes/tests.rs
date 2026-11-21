use super::*;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::socket_options::SocketOptionsError;

const CONFIG: &str = include_str!("../../../tests/fixtures/tailscale_routes.json");

fn socket(address: IpAddr, port: u16, inode: u64) -> ListeningSocket {
    ListeningSocket {
        address,
        port,
        inode,
        protocol: Protocol::Tcp,
        options: None,
    }
}

fn report(config: &str, sockets: Vec<ListeningSocket>) -> RouteReport {
    collect_with(Ok(config.to_owned()), || {
        let by_inode = sockets
            .iter()
            .map(|socket| {
                (
                    socket.inode,
                    SocketOptions {
                        bound_device: None,
                        ipv6_only: false,
                    },
                )
            })
            .collect();
        Ok(Inventory {
            sockets,
            options: OptionsReport {
                by_inode,
                error: None,
            },
        })
    })
    .unwrap()
}

#[test]
fn routes_retain_exact_entry_points_and_backend_evidence() {
    let report = report(
        CONFIG,
        vec![
            socket(Ipv4Addr::LOCALHOST.into(), 3000, 1),
            socket(Ipv6Addr::LOCALHOST.into(), 9443, 2),
        ],
    );
    let text = report.to_string();
    for expected in [
        "node.example.ts.net:443 / [Funnel] -> http://127.0.0.1:3000 (TCP listener 127.0.0.1:3000)",
        "node.example.ts.net:443 /api [Funnel] -> https+insecure://[::1]:9443/internal (TCP listener [::1]:9443)",
        "node.example.ts.net:443 /docs [Funnel] -> /srv/example (unsupported handler: file or directory)",
        "node.example.ts.net:443 /missing [Funnel] -> localhost:4000 (no matching TCP listener)",
        "node.example.ts.net:443 /remote [Funnel] -> https://backend.example.test/api (target is outside the supported loopback TCP scope)",
        "other.example.ts.net:443 / [Serve] -> 3000 (TCP listener 127.0.0.1:3000)",
        "other.example.ts.net:443 /status [Serve] (unsupported handler: static text)",
        "node.example.ts.net:8443 / [Serve] -> unix:/run/example.sock (unsupported handler: Unix socket proxy)",
    ] {
        assert!(text.contains(expected), "missing {expected:?} in {text}");
    }
    assert!(!text.contains("secret") && !text.contains("private contents"));
    assert!(report.is_complete());
}

#[test]
fn incomplete_status_preserves_valid_routes_and_explains_unknown_scope() {
    let report = report(
        r#"{"Web":{"bad":{},"node.example.ts.net:443":{"Handlers":{"/":{"Proxy":"3000"},"/bad":false}}},"AllowFunnel":[]}"#,
        vec![],
    );
    let text = report.to_string();
    assert!(
        text.contains("Partial Tailscale route collection"),
        "{text}"
    );
    assert!(
        text.contains("node.example.ts.net:443 / [unknown scope] -> 3000"),
        "{text}"
    );
    assert!(text.contains("invalid Web entry point"), "{text}");
    assert!(!report.is_complete());
}

#[test]
fn empty_status_is_distinct_from_a_failed_command_or_invalid_json() {
    for config in ["{}", "null"] {
        let report = collect_with(Ok(config.to_owned()), || {
            panic!("empty status needs no sockets")
        })
        .unwrap();
        assert!(
            report
                .to_string()
                .contains("No configured host-level Tailscale routes")
        );
        assert!(report.is_complete());
    }
    let error = collect_with(Err(CollectError::UnsupportedOs { os: "test" }), || {
        panic!("failed status needs no sockets")
    });
    assert!(matches!(error, Err(RouteScanError::Collect(_))));
    let error = collect_with(Ok("{".into()), || panic!("invalid status needs no sockets"));
    assert!(matches!(error, Err(RouteScanError::Json(_))));
}

#[test]
fn ambiguous_localhost_does_not_pick_one_of_two_listeners() {
    let route = report(
        r#"{"Web":{"node.example.ts.net:443":{"Handlers":{"/":{"Proxy":"http://localhost:3000"}}}}}"#,
        vec![
            socket(Ipv4Addr::LOCALHOST.into(), 3000, 1),
            socket(Ipv6Addr::LOCALHOST.into(), 3000, 2),
        ],
    );
    assert!(
        route
            .to_string()
            .contains("multiple possible TCP listeners")
    );
}

#[test]
fn inventory_failure_keeps_routes_and_a_udp_socket_cannot_match() {
    let json = r#"{"Web":{"node.example.ts.net:443":{"Handlers":{"/":{"Proxy":"3000"}}}}}"#;
    let unavailable = collect_with(Ok(json.into()), || {
        Err(ScanError::Collect(CollectError::UnsupportedOs {
            os: "test",
        }))
    })
    .unwrap();
    let text = unavailable.to_string();
    assert!(text.contains("[Serve] -> 3000 (TCP socket inventory unavailable)"));
    assert!(!unavailable.is_complete());

    let udp = ListeningSocket {
        protocol: Protocol::Udp,
        ..socket(Ipv4Addr::LOCALHOST.into(), 3000, 1)
    };
    assert!(
        report(json, vec![udp])
            .to_string()
            .contains("no matching TCP listener")
    );
}

#[test]
fn a_wildcard_listener_needs_known_dual_stack_to_match_an_ipv4_target() {
    let listener = socket(Ipv6Addr::UNSPECIFIED.into(), 3000, 1);
    let target = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 3000);
    let options = SocketOptions {
        ipv6_only: false,
        bound_device: None,
    };
    assert_eq!(candidate(&listener, target, None), Some(false));
    assert_eq!(candidate(&listener, target, Some(&options)), Some(true));
    assert_eq!(
        candidate(
            &listener,
            target,
            Some(&SocketOptions {
                ipv6_only: true,
                ..options
            })
        ),
        None
    );
    assert_eq!(
        candidate(
            &listener,
            target,
            Some(&SocketOptions {
                bound_device: Some(2),
                ..options
            })
        ),
        Some(false)
    );
}

#[test]
fn tcp_forwarding_and_named_services_stay_visible_outside_the_web_scope() {
    let report = report(
        include_str!("../../../tests/fixtures/tailscale_serve.json"),
        vec![],
    );
    let text = report.to_string();
    assert!(text.contains(
        "host.example.ts.net:6379 [Serve] -> localhost:6379 (unsupported handler: TCP forwarding)"
    ));
    assert!(text.contains("Tailscale Services are outside the supported host-level route scope"));
    assert!(text.contains("host.example.ts.net:10000 / [Funnel]"));
    assert!(report.is_complete());
}

#[test]
fn an_exact_match_with_missing_socket_options_is_uncertain() {
    let listener = socket(Ipv4Addr::LOCALHOST.into(), 3000, 1);
    let target = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 3000);
    assert_eq!(candidate(&listener, target, None), Some(false));
}

#[test]
fn a_socket_options_error_keeps_the_route_and_reports_partial_collection() {
    let json = r#"{"Web":{"node.example.ts.net:443":{"Handlers":{"/":{"Proxy":"3000"}}}}}"#;
    let report = collect_with(Ok(json.into()), || {
        Ok(Inventory {
            sockets: vec![socket(Ipv4Addr::LOCALHOST.into(), 3000, 1)],
            options: OptionsReport {
                error: Some(SocketOptionsError::Open(CollectError::UnsupportedOs {
                    os: "test",
                })),
                ..OptionsReport::default()
            },
        })
    })
    .unwrap();
    let text = report.to_string();
    assert!(text.contains("listener's socket options leave the match uncertain"));
    assert!(text.contains("TCP socket options incomplete"));
    assert!(!report.is_complete());
}

#[test]
fn a_tcp_entry_without_a_forwarding_target_is_unrecognised() {
    let report = report(
        r#"{"TCP":{"443":{"HTTPS":false,"TerminateTLS":"node.example.ts.net"}}}"#,
        vec![],
    );
    let text = report.to_string();
    assert!(
        text.contains(
            "node.example.ts.net:443 [Serve] (unsupported handler: unrecognised TCP handler)"
        ),
        "{text}"
    );
}
