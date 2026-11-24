//! Tests for Caddy route collection, listener linking and auth signals.

use std::net::SocketAddr;

use super::source::{Adapted, SourceKind};
use super::*;
use crate::caddy::ListenAddress;
use crate::collect::CollectError;
use crate::local_tcp::{Listener, ListenerOptions};
use crate::socket::{ListeningSocket, Protocol, SocketOptions};
use crate::socket_options::{OptionsReport, SocketOptionsError};

mod collect;
mod replay;

pub(super) const LINKED: &str = include_str!("../../../tests/fixtures/caddy/routes/linked.json");

/// One TCP socket for the inventory: address and `IPV6_V6ONLY`, or `None`
/// when its socket options are unknown.
pub(super) type Socket = (SocketAddr, Option<bool>);

pub(super) fn addr(text: &str) -> SocketAddr {
    text.parse().expect("socket address")
}

pub(super) fn inventory(sockets: &[Socket]) -> Inventory {
    let listening = sockets
        .iter()
        .zip(1..)
        .map(|(&(address, _), inode)| ListeningSocket {
            address: address.ip(),
            port: address.port(),
            inode,
            protocol: Protocol::Tcp,
            options: None,
        })
        .collect();
    let by_inode = sockets
        .iter()
        .zip(1..)
        .filter_map(|(&(_, ipv6_only), inode)| {
            ipv6_only.map(|ipv6_only| {
                (
                    inode,
                    SocketOptions {
                        bound_device: None,
                        ipv6_only,
                    },
                )
            })
        })
        .collect();
    Inventory {
        sockets: listening,
        options: OptionsReport {
            by_inode,
            error: None,
        },
    }
}

pub(super) fn json_source(json: &str) -> Result<Adapted, CaddyScanError> {
    Ok(Adapted {
        kind: SourceKind::Json,
        json: json.to_owned(),
        env_placeholders: false,
        file_imports: false,
    })
}

pub(super) fn report(json: &str, sockets: &[Socket]) -> CaddyRouteReport {
    collect_with(json_source(json), || Ok(inventory(sockets))).expect("report")
}

pub(super) fn server(body: &str) -> String {
    format!(r#"{{"apps":{{"http":{{"servers":{{"srv0":{body}}}}}}}}}"#)
}

/// The sockets the linked fixture expects, plus unrelated listeners.
pub(super) fn linked_sockets() -> Vec<Socket> {
    vec![
        (addr("[::]:443"), Some(false)),
        (addr("0.0.0.0:80"), Some(false)),
        (addr("[::]:8443"), Some(true)),
        (addr("127.0.0.1:9000"), Some(false)),
        (addr("127.0.0.1:3000"), Some(false)),
        (addr("[::1]:3001"), Some(true)),
        (addr("0.0.0.0:8080"), Some(false)),
        (addr("0.0.0.0:22"), Some(false)),
    ]
}

#[test]
fn links_frontends_and_upstreams_and_keeps_auth_layers_apart() {
    let report = report(LINKED, &linked_sockets());
    let text = report.to_string();

    for line in [
        "Caddy routes (native JSON config file on disk and local TCP sockets only; whether a running Caddy loaded this configuration (it may not have been reloaded, or may have been changed through its admin API)",
        "Server public",
        "  listen: :443 (TCP listener [::]:443)",
        "  listen: tcp4/:80 (TCP listener 0.0.0.0:80)",
        "  listen: tcp6/[::]:8443 (TCP listener [::]:8443)",
        "  listen: 127.0.0.1:9000-9001",
        "    port 9000 (TCP listener 127.0.0.1:9000)",
        "    port 9001 (no matching TCP listener)",
        "  HTTP/3: enabled (its UDP sockets are not linked)",
        "  route match all requests",
        "    authentication: http_basic",
        "  route match (host app.example.test path /api/*) [terminal]",
        "      upstream 127.0.0.1:3000 (TCP listener 127.0.0.1:3000)",
        "      upstream localhost:3001 (TCP listener [::1]:3001)",
        "      upstream 192.0.2.10:8080 (non-loopback upstream (no exact local TCP listener; may be remote))",
        "      upstream backend.example.test:9000 (host name requires DNS resolution; not linked)",
        "      proxy auth: client certificate required and verified, http_basic; application auth: unverified",
        "Configuration uncertainties:",
    ] {
        assert!(text.contains(line), "missing {line:?} in:\n{text}");
    }
    assert!(!text.contains("hash-value"), "{text}");
    assert!(report.is_collection_complete());
    assert!(!report.is_complete(), "the host name upstream is uncertain");
    assert_eq!(report.source(), SourceKind::Json);
}

#[test]
fn keeps_only_listeners_relevant_to_the_configuration() {
    let report = report(LINKED, &linked_sockets());
    let TcpEvidence::Collected { listeners } = &report.inventory else {
        panic!("expected collected listeners");
    };
    let kept: Vec<_> = listeners.iter().map(|listener| listener.address).collect();
    assert!(!kept.contains(&addr("0.0.0.0:22")), "{kept:?}");
    assert!(!kept.contains(&addr("0.0.0.0:8080")), "{kept:?}");
    assert!(kept.contains(&addr("127.0.0.1:3000")), "{kept:?}");
    assert_eq!(kept.len(), 6);
    assert_eq!(report.validate(), Ok(()));
}

fn listener(text: &str, ipv6_only: Option<bool>) -> Listener {
    Listener {
        address: addr(text),
        options: ipv6_only.map(|ipv6_only| ListenerOptions {
            bound_to_device: false,
            ipv6_only,
        }),
    }
}

fn frontend(listen: &str, socket: &str, ipv6_only: Option<bool>) -> Option<bool> {
    let listen = ListenAddress::parse(listen).expect("listen address");
    let port = listen.ports().first();
    link::frontend_candidate(&listener(socket, ipv6_only), &listen, port)
}

#[test]
fn wildcard_listens_follow_go_socket_semantics() {
    for wildcard in [":443", "0.0.0.0:443", "[::]:443", "tcp/:443"] {
        assert_eq!(frontend(wildcard, "[::]:443", Some(false)), Some(true));
        assert_eq!(frontend(wildcard, "[::]:443", Some(true)), None);
        assert_eq!(frontend(wildcard, "[::]:443", None), Some(false));
        assert_eq!(frontend(wildcard, "0.0.0.0:443", Some(false)), Some(true));
        assert_eq!(frontend(wildcard, "127.0.0.1:443", Some(false)), None);
    }
    assert_eq!(frontend("tcp4/:80", "0.0.0.0:80", Some(false)), Some(true));
    assert_eq!(frontend("tcp4/:80", "[::]:80", Some(false)), None);
    assert_eq!(frontend("tcp6/[::]:80", "[::]:80", Some(true)), Some(true));
    assert_eq!(frontend("tcp6/:80", "[::]:80", Some(false)), None);
    assert_eq!(frontend("tcp6/:80", "0.0.0.0:80", Some(false)), None);
    assert_eq!(
        frontend("127.0.0.1:8080", "127.0.0.1:8080", Some(false)),
        Some(true)
    );
    assert_eq!(
        frontend("127.0.0.1:8080", "0.0.0.0:8080", Some(false)),
        None
    );
    assert_eq!(frontend("[::1]:8080", "[::1]:8080", None), Some(false));
}

#[test]
fn reports_ambiguous_uncertain_and_missing_upstreams() {
    let json = server(
        r#"{"listen":["127.0.0.1:8000"],"routes":[{"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"localhost:3001"},{"dial":"127.0.0.1:3002"},{"dial":"[::1]:3003"}]}]}]}"#,
    );
    let sockets = [
        (addr("127.0.0.1:3001"), Some(false)),
        (addr("[::1]:3001"), Some(true)),
        (addr("127.0.0.1:3002"), None),
    ];
    let text = report(&json, &sockets).to_string();
    for line in [
        "  listen: 127.0.0.1:8000 (no matching TCP listener)",
        "upstream localhost:3001 (multiple possible TCP listeners)",
        "upstream 127.0.0.1:3002 (listener's socket options leave the match uncertain)",
        "upstream [::1]:3003 (no matching TCP listener)",
    ] {
        assert!(text.contains(line), "missing {line:?} in:\n{text}");
    }
}

#[test]
fn loopback_upstreams_also_match_wildcard_listeners() {
    let json = server(
        r#"{"listen":[":80"],"routes":[{"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"127.0.0.1:3000"},{"dial":"0.0.0.0:3000"}]}]}]}"#,
    );
    let text = report(&json, &[(addr("[::]:3000"), Some(false))]).to_string();
    assert!(
        text.contains("upstream 127.0.0.1:3000 (TCP listener [::]:3000)"),
        "{text}"
    );
    assert!(
        text.contains("upstream 0.0.0.0:3000 (unspecified address; not linked)"),
        "{text}"
    );
}

#[test]
fn auth_from_earlier_routes_and_scoped_policies_is_conditional() {
    let json = server(
        r#"{"listen":[":443"],
            "tls_connection_policies":[{"match":{"sni":["a.example.test"]},"client_authentication":{"mode":"request"}}],
            "routes":[
              {"match":[{"path":["/admin/*"]}],"handle":[{"handler":"authentication","providers":{"http_basic":{}}}]},
              {"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"127.0.0.1:9091"}],
                "rewrite":{"method":"GET","uri":"/verify"},
                "handle_response":[{"match":{"status_code":[2]},"routes":[{"handle":[{"handler":"vars"}]}]}]},
                {"handler":"reverse_proxy","upstreams":[{"dial":"127.0.0.1:3000"}]}]}
            ]}"#,
    );
    let text = report(&json, &[]).to_string();
    let conditional = "client certificate requested (some requests only)";
    assert!(
        text.contains(&format!(
            "    reverse_proxy [forward_auth]\n      upstream 127.0.0.1:9091 (no matching TCP listener)\n      proxy auth: {conditional}, http_basic (some requests only); application auth: unverified"
        )),
        "{text}"
    );
    assert!(
        text.contains(&format!(
            "      proxy auth: {conditional}, forward_auth, http_basic (some requests only); application auth: unverified"
        )),
        "{text}"
    );
}

#[test]
fn auth_inside_a_matcherless_subroute_applies_to_later_routes() {
    let json = server(
        r#"{"listen":[":80"],"routes":[
              {"handle":[{"handler":"subroute","routes":[{"handle":[{"handler":"authentication","providers":{"http_basic":{},"jwt":{}}}]}]}]},
              {"group":"g","handle":[{"handler":"authentication","providers":{"http_basic":{}}}]},
              {"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"127.0.0.1:3000"}]}]}
            ]}"#,
    );
    let text = report(&json, &[]).to_string();
    assert!(
        text.contains("proxy auth: http_basic, other authentication provider; application auth"),
        "{text}"
    );
}

#[test]
fn without_endpoints_no_socket_inventory_is_read() {
    let report =
        collect_with(json_source("{}"), || panic!("inventory must not be read")).expect("report");
    assert!(report.is_complete());
    assert!(matches!(report.inventory, TcpEvidence::NotNeeded));
    assert!(
        report
            .to_string()
            .contains("No configured Caddy HTTP servers found.")
    );
    assert_eq!(report.validate(), Ok(()));
}

#[test]
fn an_unreadable_inventory_is_partial_and_never_reports_missing_listeners() {
    let report = collect_with(json_source(LINKED), || {
        Err(ScanError::UnsupportedOs { os: "plan9" })
    })
    .expect("report");
    let text = report.to_string();
    assert!(!report.is_collection_complete());
    assert!(
        text.contains("  listen: :443 (TCP socket inventory unavailable)"),
        "{text}"
    );
    assert!(text.contains("upstream 127.0.0.1:3000 (TCP socket inventory unavailable)"));
    assert!(!text.contains("no matching TCP listener"), "{text}");
    assert!(text.contains("Partial Caddy route collection:\n  TCP socket inventory unavailable"));
    assert_eq!(report.validate(), Ok(()));
}

#[test]
fn incomplete_socket_options_are_noted() {
    let report = collect_with(json_source(LINKED), || {
        let mut inventory = inventory(&linked_sockets());
        inventory.options.error = Some(SocketOptionsError::Open(CollectError::UnsupportedOs {
            os: "plan9",
        }));
        Ok(inventory)
    })
    .expect("report");
    assert!(!report.is_collection_complete());
    assert!(report.to_string().contains("TCP socket options incomplete"));
    assert_eq!(report.validate(), Ok(()));
}

#[test]
fn wide_port_ranges_are_noted_instead_of_linked() {
    let json = server(r#"{"listen":[":1000-2000"]}"#);
    let report = collect_with(json_source(&json), || panic!("nothing to link")).expect("report");
    let text = report.to_string();
    assert!(
        text.contains("  listen: :1000-2000 (not linked: port range too wide)"),
        "{text}"
    );
    assert!(
        text.contains(
            "listen port range 1000-2000 not linked to TCP listeners (more than 64 ports)"
        )
    );
    assert!(!report.is_complete());
    assert_eq!(report.validate(), Ok(()));
}

#[test]
fn caddyfile_environment_placeholders_make_the_report_partial() {
    let adapted = Adapted {
        kind: SourceKind::Caddyfile,
        json: "{}".to_owned(),
        env_placeholders: true,
        file_imports: true,
    };
    let report = collect_with(Ok(adapted), || panic!("nothing to link")).expect("report");
    let text = report.to_string();
    assert!(text.starts_with("Caddy routes (Caddyfile on disk, adapted to JSON by `caddy adapt`"));
    assert!(text.contains("{$VAR} environment placeholders"), "{text}");
    assert!(
        text.contains("imports other files, which were not checked"),
        "{text}"
    );
    assert_eq!(report.validate(), Ok(()));
    assert!(!report.is_complete());
    assert!(!text.contains("No configured Caddy HTTP servers found."));
}

#[test]
fn collection_and_parse_errors_are_returned_not_an_empty_report() {
    let missing = collect_with(Err(CaddyScanError::MissingCommand), || panic!("not read"));
    assert!(matches!(missing, Err(CaddyScanError::MissingCommand)));
    let invalid = collect_with(json_source("{\"apps\":"), || panic!("not read"));
    assert!(matches!(invalid, Err(CaddyScanError::Parse(_))));
}

#[test]
fn route_depth_counts_nested_route_lists() {
    let nested = server(
        r#"{"routes":[{"handle":[{"handler":"subroute","routes":[{"handle":[{"handler":"vars"}]}]}]}]}"#,
    );
    let config = parse_caddy_config_with(&nested, &Substitutions::none()).expect("config");
    assert_eq!(link::route_depth(&config.servers[0].routes), 2);
    assert_eq!(link::route_depth(&[]), 0);
}

#[test]
fn auth_of_a_terminal_site_never_reaches_a_later_site() {
    let json = server(
        r#"{"listen":[":443"],"routes":[
              {"match":[{"host":["admin.example.test"]}],"terminal":true,
               "handle":[{"handler":"subroute","routes":[{"handle":[
                 {"handler":"authentication","providers":{"http_basic":{}}},
                 {"handler":"reverse_proxy","upstreams":[{"dial":"127.0.0.1:3001"}]}]}]}]},
              {"match":[{"host":["app.example.test"]}],"terminal":true,
               "handle":[{"handler":"subroute","routes":[{"handle":[
                 {"handler":"reverse_proxy","upstreams":[{"dial":"127.0.0.1:3002"}]}]}]}]}
            ]}"#,
    );
    let text = report(&json, &[]).to_string();
    let (admin, app) = text.split_once("host app.example.test").expect("two sites");
    assert!(
        admin.contains("proxy auth: http_basic; application auth"),
        "{text}"
    );
    assert!(
        app.contains("proxy auth: none configured; application auth"),
        "{text}"
    );
}

#[test]
fn only_an_unscoped_first_tls_policy_applies_to_every_connection() {
    let auth = |policies: &str| {
        let json = server(&format!(
            r#"{{"listen":[":443"],"tls_connection_policies":{policies},
                "routes":[{{"handle":[{{"handler":"reverse_proxy","upstreams":[{{"dial":"127.0.0.1:3000"}}]}}]}}]}}"#
        ));
        let text = report(&json, &[]).to_string();
        text.lines()
            .find(|line| line.contains("proxy auth:"))
            .expect("auth line")
            .trim()
            .to_owned()
    };
    let require = r#"{"client_authentication":{"mode":"require_and_verify"}}"#;
    let open_sni = r#"{"match":{"sni":["open.example.test"]}}"#;
    assert_eq!(
        auth(&format!("[{require}]")),
        "proxy auth: client certificate required and verified; application auth: unverified"
    );
    assert_eq!(
        auth(&format!("[{open_sni},{require}]")),
        "proxy auth: client certificate required and verified (some requests only); application auth: unverified"
    );
    assert_eq!(
        auth(&format!("[{{}},{require}]")),
        "proxy auth: none configured; application auth: unverified"
    );
}

#[test]
fn an_http3_only_server_links_no_tcp_listener() {
    let json = server(r#"{"listen":[":443"],"protocols":["h3"]}"#);
    let report = collect_with(json_source(&json), || panic!("nothing to link")).expect("report");
    let text = report.to_string();
    assert!(
        text.contains("  listen: :443 (HTTP/3 only: UDP, not linked)"),
        "{text}"
    );
    assert!(matches!(report.inventory, TcpEvidence::NotNeeded));
    assert_eq!(report.validate(), Ok(()));
}
