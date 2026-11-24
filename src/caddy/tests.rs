use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use super::*;

mod edge_cases;
mod redaction;

const SERVERS: &str = include_str!("../../tests/fixtures/caddy/servers.json");
const UNCERTAINTIES: &str = include_str!("../../tests/fixtures/caddy/uncertainties.json");
const SERVERS_MODEL: &str = include_str!("../../tests/fixtures/caddy/servers.model.json");
const SECRETS: &str = include_str!("../../tests/fixtures/caddy/secrets.json");

fn parse(json: &str) -> CaddyConfig {
    parse_caddy_config(json).expect("valid Caddy config")
}

fn socket(ip: impl Into<std::net::IpAddr>, port: u16) -> DialTarget {
    DialTarget::Socket {
        address: SocketAddr::new(ip.into(), port),
    }
}

fn proxy(handler: &Handler) -> &ReverseProxy {
    match handler {
        Handler::ReverseProxy(proxy) => proxy,
        other => panic!("expected reverse_proxy, got {other:?}"),
    }
}

fn subroutes(handler: &Handler) -> &[Route] {
    match handler {
        Handler::Subroute { routes } => routes,
        other => panic!("expected subroute, got {other:?}"),
    }
}

fn group_label(route: &Route) -> Option<&str> {
    route.group.as_ref().map(|group| group.label.as_str())
}

/// A config with one server whose body is `server`.
fn with_server(server: &str) -> String {
    format!(r#"{{"apps": {{"http": {{"servers": {{"s": {server}}}}}}}}}"#)
}

fn listed(config: &CaddyConfig) -> Vec<(UncertaintyKind, &str, &str)> {
    config
        .uncertainties
        .iter()
        .map(|u| (u.kind, u.construct.as_str(), u.location.as_str()))
        .collect()
}

#[test]
fn parses_servers_listeners_and_tls_policies() {
    let config = parse(SERVERS);
    assert_eq!(
        (config.http_port, config.https_port),
        (Some(8080), Some(8443))
    );
    let names: Vec<_> = config.servers.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(names, ["edge", "internal"]);

    let edge = &config.servers[0];
    assert_eq!(edge.listen.len(), 2);
    assert_eq!(edge.listen[0].network(), ListenNetwork::Tcp);
    assert_eq!(edge.listen[0].host(), ListenHost::Any {});
    assert_eq!(
        edge.listen[0].ports(),
        PortRange::new(443, 443).expect("range")
    );
    assert_eq!(edge.listen[1].network(), ListenNetwork::Tcp6);
    assert_eq!(
        edge.listen[1].ports(),
        PortRange::new(8443, 8445).expect("range")
    );
    assert_eq!(edge.automatic_https, AutomaticHttps::default());
    assert!(edge.http3, "HTTP/3 is on when protocols is unset");
    assert_eq!(
        edge.tls_policies,
        [
            TlsPolicy {
                scoped: true,
                client_auth: Some(ClientAuthMode::RequireAndVerify)
            },
            TlsPolicy::default()
        ]
    );

    let internal = &config.servers[1];
    assert_eq!(
        internal.listen[0].host(),
        ListenHost::Ipv4 {
            ip: Ipv4Addr::LOCALHOST
        }
    );
    assert!(internal.automatic_https.disabled);
    assert!(!internal.automatic_https.redirects_disabled);
    assert!(!internal.http3);
}

#[test]
fn parses_host_and_path_matchers_through_nested_subroutes() {
    let config = parse(SERVERS);
    let route = &config.servers[0].routes[0];
    assert!(route.terminal);
    assert_eq!(
        route.matchers,
        [MatcherSet {
            hosts: Some(vec![
                HostMatcher::Exact {
                    host: "app.example.test".into()
                },
                HostMatcher::LeadingWildcard {
                    suffix: "apps.example.test".into()
                },
            ]),
            paths: None,
            complete: true,
        }]
    );

    let inner = subroutes(&route.handlers[0]);
    assert_eq!(inner.len(), 2);
    assert_eq!(group_label(&inner[0]), Some("group0"));
    assert_eq!(inner[0].group, inner[1].group);
    assert_eq!(
        inner[0].matchers[0].paths,
        Some(vec![PathMatcher::Prefix {
            prefix: "/api/".into()
        }])
    );
    let api = proxy(&inner[0].handlers[0]);
    assert_eq!(
        api.upstreams,
        [
            socket(Ipv4Addr::LOCALHOST, 3000),
            socket(Ipv6Addr::LOCALHOST, 3001)
        ]
    );
    assert!(api.complete && !api.tls && !api.forward_auth);
    assert!(api.upstreams.iter().all(DialTarget::is_loopback));

    let deepest = subroutes(&inner[1].handlers[0]);
    assert!(inner[1].matchers.is_empty());
    assert_eq!(
        deepest[0].matchers[0].paths,
        Some(vec![PathMatcher::Exact {
            path: "/health".into()
        }])
    );
    assert_eq!(
        deepest[0].handlers,
        [Handler::Respond {
            responder: Responder::StaticResponse
        }]
    );
    let remote = proxy(&deepest[1].handlers[0]);
    assert_eq!(
        remote.upstreams,
        [socket(Ipv4Addr::new(192, 0, 2, 10), 8443)]
    );
    assert!(remote.tls && remote.complete);
    assert!(!remote.upstreams[0].is_loopback());
}

#[test]
fn parses_authentication_presence_and_forward_auth() {
    let config = parse(SERVERS);
    let routes = &config.servers[1].routes;

    assert_eq!(routes[0].matchers.len(), 2);
    assert_eq!(
        routes[0].handlers[0],
        Handler::Authentication {
            http_basic: true,
            other_providers: false
        }
    );
    assert_eq!(
        proxy(&routes[0].handlers[1]).upstreams,
        [DialTarget::Localhost { port: 4000 }]
    );

    let gate = proxy(&routes[1].handlers[0]);
    assert!(gate.forward_auth);
    assert!(!gate.complete, "a host name upstream needs DNS");
    assert_eq!(gate.upstreams[0].port(), 9091);
    let app = proxy(&routes[1].handlers[1]);
    assert_eq!(
        app.upstreams,
        [socket(Ipv4Addr::new(198, 51, 100, 7), 8000)]
    );

    assert_eq!(
        listed(&config),
        [(
            UncertaintyKind::UnresolvedHost,
            "dial",
            r#"apps.http.servers["internal"].routes[1].handle[0].upstreams[0].dial"#
        )]
    );
}

#[test]
fn model_round_trips_through_json() {
    for fixture in [SERVERS, UNCERTAINTIES, SECRETS] {
        let config = parse(fixture);
        let json = serde_json::to_string(&config).expect("serialize");
        let back: CaddyConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, config);
    }
}

#[test]
fn names_every_unmodeled_construct_and_its_location() {
    use UncertaintyKind::*;
    let config = parse(UNCERTAINTIES);
    let server = r#"apps.http.servers["dynamic"]"#;
    let route = format!("{server}.routes[0]");
    let set = format!("{route}.match[0]");
    let handle = format!("{route}.handle");
    let expected: Vec<(UncertaintyKind, &str, String)> = vec![
        (UnmodeledApp, "layer4", r#"apps["layer4"]"#.into()),
        (Placeholder, "listen", format!("{server}.listen[0]")),
        (
            UnsupportedTransport,
            "listen",
            format!("{server}.listen[1]"),
        ),
        (ImplicitListen, "listen", format!("{server}.listen[2]")),
        (UnresolvedHost, "listen", format!("{server}.listen[3]")),
        (
            UnsupportedTransport,
            "listen",
            format!("{server}.listen[4]"),
        ),
        (UnmodeledServerFeature, "errors", format!("{server}.errors")),
        (
            UnmodeledMatcher,
            "expression",
            format!(r#"{set}["expression"]"#),
        ),
        (UnmodeledMatcher, "header", format!(r#"{set}["header"]"#)),
        (UnmodeledMatcher, "not", format!(r#"{set}["not"]"#)),
        (UnmodeledMatcher, "query", format!(r#"{set}["query"]"#)),
        (
            UnmodeledMatcher,
            "remote_ip",
            format!(r#"{set}["remote_ip"]"#),
        ),
        (Placeholder, "host", format!("{set}.host[0]")),
        (UnsupportedPattern, "host", format!("{set}.host[1]")),
        (Placeholder, "path", format!("{set}.path[0]")),
        (UnsupportedPattern, "path", format!("{set}.path[1]")),
        (RoutingHandler, "rewrite", format!("{handle}[0]")),
        (RoutingHandler, "uri", format!("{handle}[1]")),
        (RoutingHandler, "map", format!("{handle}[2]")),
        (UnknownHandler, "custom_plugin", format!("{handle}[3]")),
        (
            DynamicUpstreams,
            "dynamic_upstreams",
            format!("{handle}[4].dynamic_upstreams"),
        ),
        (
            UnsupportedTransport,
            "protocol",
            format!("{handle}[5].transport.protocol"),
        ),
        (
            Placeholder,
            "dial",
            format!("{handle}[5].upstreams[0].dial"),
        ),
        (
            UnsupportedTransport,
            "dial",
            format!("{handle}[5].upstreams[1].dial"),
        ),
        (Malformed, "dial", format!("{handle}[5].upstreams[2].dial")),
        (Malformed, "dial", format!("{handle}[5].upstreams[3].dial")),
        (Malformed, "reverse_proxy", format!("{handle}[6]")),
        (
            ImplicitListen,
            "listen",
            r#"apps.http.servers["silent"].listen"#.into(),
        ),
    ];
    let actual = listed(&config);
    let expected: Vec<_> = expected
        .iter()
        .map(|(kind, construct, location)| (*kind, *construct, location.as_str()))
        .collect();
    assert_eq!(actual, expected);

    let dynamic = &config.servers[0];
    assert!(dynamic.listen.is_empty());
    let route = &dynamic.routes[0];
    assert!(!route.matchers[0].complete);
    assert_eq!(route.matchers[0].hosts, Some(Vec::new()));
    assert_eq!(&route.handlers[..4], [const { Handler::Unmodeled {} }; 4]);
    assert!(!proxy(&route.handlers[4]).complete);
    let fastcgi = proxy(&route.handlers[5]);
    assert!(fastcgi.upstreams.is_empty() && !fastcgi.complete);
    assert_eq!(route.handlers[6], Handler::Unmodeled {});
}

#[test]
fn uncertainties_print_kind_construct_and_location() {
    let config = parse(UNCERTAINTIES);
    assert_eq!(
        config.uncertainties[1].to_string(),
        r#"runtime placeholder (`listen`) at apps.http.servers["dynamic"].listen[0]"#
    );
}

#[test]
fn empty_config_has_no_servers_and_default_ports() {
    assert_eq!(parse("{}"), CaddyConfig::default());
    assert_eq!(parse(r#"{"apps": {}}"#), CaddyConfig::default());
}

#[test]
fn malformed_and_truncated_input_fails_with_position_only() {
    let truncated = &SERVERS[..SERVERS.len() / 2];
    assert!(matches!(
        parse_caddy_config(truncated),
        Err(CaddyParseError::Truncated { .. })
    ));
    assert!(matches!(
        parse_caddy_config(""),
        Err(CaddyParseError::Truncated { line: 1, column: 0 })
    ));
    assert_eq!(
        parse_caddy_config("{\n  \"apps\": nope }"),
        Err(CaddyParseError::Syntax {
            line: 2,
            column: 12
        })
    );
    assert!(matches!(
        parse_caddy_config(r#"{"apps": {"http": {"servers": {"s": {"listen": ":80"}}}}}"#),
        Err(CaddyParseError::Shape { .. })
    ));
    assert!(matches!(
        parse_caddy_config("null"),
        Err(CaddyParseError::Shape { .. })
    ));
    let too_large = " ".repeat(MAX_INPUT_BYTES + 1);
    assert_eq!(
        parse_caddy_config(&too_large),
        Err(CaddyParseError::InputTooLarge {
            limit_bytes: MAX_INPUT_BYTES
        })
    );
}

#[test]
fn serialized_model_matches_the_pinned_contract() {
    let pinned: serde_json::Value = serde_json::from_str(SERVERS_MODEL).expect("pinned JSON");
    let actual = serde_json::to_value(parse(SERVERS)).expect("serialize");
    assert_eq!(actual, pinned);
}

#[test]
fn enum_tags_are_pinned() {
    use serde_json::json;
    let pinned = [
        (
            serde_json::to_value(Handler::Middleware {
                middleware: Middleware::EarlyHints,
            }),
            json!({"kind": "middleware", "middleware": "early_hints"}),
        ),
        (
            serde_json::to_value(Uncertainty {
                kind: UncertaintyKind::SubstitutedValue,
                construct: "dial".into(),
                location: "apps".into(),
            }),
            json!({"kind": "substituted_value", "construct": "dial", "location": "apps"}),
        ),
    ];
    for (actual, expected) in pinned {
        assert_eq!(actual.expect("serialize"), expected);
    }
    use UncertaintyKind::*;
    let kinds = [
        (Placeholder, "placeholder"),
        (UnmodeledMatcher, "unmodeled_matcher"),
        (UnsupportedPattern, "unsupported_pattern"),
        (RoutingHandler, "routing_handler"),
        (UnknownHandler, "unknown_handler"),
        (DynamicUpstreams, "dynamic_upstreams"),
        (UnsupportedTransport, "unsupported_transport"),
        (UnresolvedHost, "unresolved_host"),
        (ImplicitListen, "implicit_listen"),
        (UnmodeledApp, "unmodeled_app"),
        (UnmodeledServerFeature, "unmodeled_server_feature"),
        (UnmodeledAuthProvider, "unmodeled_auth_provider"),
        (UnknownClientAuthMode, "unknown_client_auth_mode"),
        (ClientCertificateVerifier, "client_certificate_verifier"),
        (ConditionalFallthrough, "conditional_fallthrough"),
        (ResponseHandling, "response_handling"),
        (SubstitutedValue, "substituted_value"),
        (NestingTooDeep, "nesting_too_deep"),
        (Malformed, "malformed"),
    ];
    for (kind, tag) in kinds {
        assert_eq!(serde_json::to_value(kind).expect("serialize"), json!(tag));
        assert!(!kind.to_string().is_empty());
    }
}
