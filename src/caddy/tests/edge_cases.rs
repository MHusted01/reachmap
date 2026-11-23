//! Inline configs for single constructs and bounds.

use std::net::Ipv4Addr;

use super::*;

#[test]
fn notes_other_server_and_tls_constructs() {
    use UncertaintyKind::*;
    let config = parse(
        r#"{"apps": {"tls": {}, "pki": {}, "http": {"servers": {"s": {
            "listen": [":443"],
            "named_routes": {"shared": {}},
            "tls_connection_policies": [
                {"client_authentication": {"mode": "sometimes"}},
                {"client_authentication": {"trusted_ca_certs": ["AAAA"]}},
                {"client_authentication": {}}
            ],
            "routes": [{"handle": [
                {"handler": "authentication", "providers": {"jwt": {}}},
                {"handler": "reverse_proxy"},
                {"no_handler": true},
                {"handler": "file_server"},
                {"handler": "encode"}
            ]}]
        }}}}}"#,
    );
    let server = r#"apps.http.servers["s"]"#;
    let handle = format!("{server}.routes[0].handle");
    let named = format!("{server}.named_routes");
    let mode = format!("{server}.tls_connection_policies[0].client_authentication.mode");
    let jwt = format!(r#"{handle}[0].providers["jwt"]"#);
    let upstreams = format!("{handle}[1].upstreams");
    let unnamed = format!("{handle}[2]");
    assert_eq!(
        listed(&config),
        [
            (UnmodeledServerFeature, "named_routes", named.as_str()),
            (UnknownClientAuthMode, "mode", mode.as_str()),
            (UnmodeledAuthProvider, "jwt", jwt.as_str()),
            (Malformed, "upstreams", upstreams.as_str()),
            (Malformed, "handler", unnamed.as_str()),
        ]
    );
    let policies = &config.servers[0].tls_policies;
    assert_eq!(policies[0].client_auth, None);
    assert_eq!(policies[1].client_auth, Some(ClientAuthMode::Implicit));
    assert_eq!(policies[2].client_auth, None);
    let handlers = &config.servers[0].routes[0].handlers;
    assert_eq!(
        handlers[0],
        Handler::Authentication {
            http_basic: false,
            other_providers: true
        }
    );
    assert_eq!(
        handlers[3..],
        [
            Handler::Respond {
                responder: Responder::FileServer
            },
            Handler::Middleware {
                middleware: Middleware::Encode
            }
        ]
    );
}

#[test]
fn deep_subroutes_stop_at_the_depth_bound() {
    let levels = MAX_ROUTE_DEPTH + 4;
    let mut handler = r#"{"handler": "static_response"}"#.to_owned();
    for _ in 0..levels {
        handler = format!(r#"{{"handler": "subroute", "routes": [{{"handle": [{handler}]}}]}}"#);
    }
    let json = format!(
        r#"{{"apps": {{"http": {{"servers": {{"s": {{"listen": [":80"], "routes": [{{"handle": [{handler}]}}]}}}}}}}}}}"#
    );
    let config = parse(&json);
    assert_eq!(config.uncertainties.len(), 1);
    assert_eq!(
        config.uncertainties[0].kind,
        UncertaintyKind::NestingTooDeep
    );
    assert_eq!(
        config.uncertainties[0]
            .location
            .matches(".routes[0]")
            .count(),
        MAX_ROUTE_DEPTH + 1
    );

    let mut depth = 0;
    let mut handlers = &config.servers[0].routes[0].handlers;
    while let Handler::Subroute { routes } = &handlers[0] {
        depth += 1;
        handlers = &routes[0].handlers;
    }
    assert_eq!(depth, MAX_ROUTE_DEPTH);
    assert_eq!(handlers[0], Handler::Unmodeled {});
}

#[test]
fn maps_every_known_responder_and_middleware() {
    let names = [
        "static_response",
        "file_server",
        "error",
        "headers",
        "encode",
        "request_body",
        "vars",
        "templates",
        "tracing",
        "log_append",
    ];
    let handle: Vec<String> = names
        .iter()
        .map(|name| format!(r#"{{"handler": "{name}"}}"#))
        .collect();
    let json = format!(
        r#"{{"apps": {{"http": {{"servers": {{"s": {{"listen": [":80"], "routes": [{{"handle": [{}]}}]}}}}}}}}}}"#,
        handle.join(",")
    );
    let config = parse(&json);
    assert!(config.uncertainties.is_empty());
    let respond = |responder| Handler::Respond { responder };
    let middleware = |middleware| Handler::Middleware { middleware };
    assert_eq!(
        config.servers[0].routes[0].handlers,
        [
            respond(Responder::StaticResponse),
            respond(Responder::FileServer),
            respond(Responder::Error),
            middleware(Middleware::Headers),
            middleware(Middleware::Encode),
            middleware(Middleware::RequestBody),
            middleware(Middleware::Vars),
            middleware(Middleware::Templates),
            middleware(Middleware::Tracing),
            middleware(Middleware::LogAppend),
        ]
    );
}

const SERVER_AT: &str = r#"apps.http.servers["s"]"#;

#[test]
fn client_certificate_verifiers_count_as_client_auth_but_stay_uncertain() {
    let config = parse(&with_server(
        r#"{"listen": [":443"], "tls_connection_policies": [
            {"client_authentication": {"verifiers": [{"verifier": "leaf"}]}}
        ]}"#,
    ));
    let policy = &config.servers[0].tls_policies[0];
    assert_eq!(policy.client_auth, Some(ClientAuthMode::Implicit));
    let at = format!("{SERVER_AT}.tls_connection_policies[0].client_authentication.verifiers");
    assert_eq!(
        listed(&config),
        [(
            UncertaintyKind::ClientCertificateVerifier,
            "verifiers",
            at.as_str()
        )]
    );
}

#[test]
fn file_server_pass_thru_does_not_hide_the_next_handler() {
    let config = parse(&with_server(
        r#"{"listen": [":80"], "routes": [{"handle": [
            {"handler": "file_server", "pass_thru": true},
            {"handler": "reverse_proxy", "upstreams": [{"dial": "127.0.0.1:3000"}]}
        ]}]}"#,
    ));
    let handlers = &config.servers[0].routes[0].handlers;
    assert_eq!(handlers[0], Handler::Unmodeled {});
    assert!(proxy(&handlers[1]).complete);
    let at = format!("{SERVER_AT}.routes[0].handle[0].pass_thru");
    assert_eq!(
        listed(&config),
        [(
            UncertaintyKind::ConditionalFallthrough,
            "pass_thru",
            at.as_str()
        )]
    );
}

#[test]
fn only_the_forward_auth_shape_counts_as_an_auth_gate() {
    let config = parse(&with_server(
        r#"{"listen": [":80"], "routes": [{"handle": [
            {"handler": "reverse_proxy", "upstreams": [{"dial": "127.0.0.1:1"}],
             "handle_response": [{"match": {"status_code": [404]}, "routes": []}]},
            {"handler": "reverse_proxy", "upstreams": [{"dial": "127.0.0.1:2"}],
             "handle_response": [{"match": {"status_code": [2]}}, {"routes": []}]},
            {"handler": "reverse_proxy", "upstreams": [{"dial": "127.0.0.1:3"}],
             "handle_response": [{"match": {"status_code": [2], "headers": {"X": ["1"]}}}]},
            {"handler": "reverse_proxy", "upstreams": [{"dial": "127.0.0.1:4"}],
             "handle_response": [{"match": {"status_code": [2]}, "routes": []}]}
        ]}]}"#,
    ));
    let handlers = &config.servers[0].routes[0].handlers;
    let gates: Vec<bool> = handlers.iter().map(|h| proxy(h).forward_auth).collect();
    assert_eq!(gates, [false, false, false, true]);
    let handle = format!("{SERVER_AT}.routes[0].handle");
    let expected: Vec<String> = (0..3)
        .map(|index| format!("{handle}[{index}].handle_response"))
        .collect();
    let actual: Vec<_> = listed(&config);
    assert_eq!(actual.len(), 3);
    for ((kind, construct, location), at) in actual.iter().zip(&expected) {
        assert_eq!(
            (*kind, *construct, *location),
            (
                UncertaintyKind::ResponseHandling,
                "handle_response",
                at.as_str()
            )
        );
    }
}

#[test]
fn srv_lookups_are_dynamic_upstreams() {
    let config = parse(&with_server(
        r#"{"listen": [":80"], "routes": [{"handle": [
            {"handler": "reverse_proxy", "upstreams": [
                {"lookup_srv": "_api._tcp.example.test", "dial": "127.0.0.1:9"},
                {"dial": "127.0.0.1:3000"}
            ]}
        ]}]}"#,
    ));
    let proxied = proxy(&config.servers[0].routes[0].handlers[0]);
    assert_eq!(proxied.upstreams, [socket(Ipv4Addr::LOCALHOST, 3000)]);
    assert!(!proxied.complete);
    let at = format!("{SERVER_AT}.routes[0].handle[0].upstreams[0].lookup_srv");
    assert_eq!(
        listed(&config),
        [(UncertaintyKind::DynamicUpstreams, "lookup_srv", at.as_str())]
    );
}

#[test]
fn notes_listener_wrappers_and_models_http3_and_skipped_hosts() {
    let config = parse(&with_server(
        r#"{"listen": [":443"],
            "listener_wrappers": [{"wrapper": "proxy_protocol"}, {"wrapper": "tls"}],
            "protocols": ["h1", "h2", "h3"],
            "automatic_https": {"skip": ["static.example.test"]}}"#,
    ));
    let server = &config.servers[0];
    assert!(server.http3);
    assert!(server.automatic_https.hosts_skipped);
    assert!(!server.automatic_https.disabled);
    let at = format!("{SERVER_AT}.listener_wrappers[0]");
    assert_eq!(
        listed(&config),
        [(
            UncertaintyKind::UnmodeledServerFeature,
            "listener_wrappers",
            at.as_str()
        )]
    );
}

#[test]
fn groups_are_told_apart_by_their_full_names() {
    let shared = "g".repeat(80);
    let json = with_server(&format!(
        r#"{{"listen": [":80"], "routes": [
            {{"group": "{shared}a"}}, {{"group": "{shared}b"}}, {{"group": "{shared}a"}}
        ]}}"#
    ));
    let config = parse(&json);
    let groups: Vec<&RouteGroup> = config.servers[0]
        .routes
        .iter()
        .map(|route| route.group.as_ref().expect("grouped"))
        .collect();
    assert_eq!(groups[0].label, groups[1].label, "labels are cut short");
    assert_ne!(groups[0].id, groups[1].id);
    assert_eq!(groups[0].id, groups[2].id);
}

#[test]
fn uncertainties_are_bounded_but_still_counted() {
    let extra = 40;
    let handlers = vec![r#"{"handler": "plugin"}"#; MAX_UNCERTAINTIES + extra].join(",");
    let config = parse(&with_server(&format!(
        r#"{{"listen": [":80"], "routes": [
            {{"handle": [{handlers}]}},
            {{"match": [{{"method": ["GET"]}}], "handle": [{{"handler": "plugin"}}]}}
        ]}}"#
    )));
    assert_eq!(config.uncertainties.len(), MAX_UNCERTAINTIES);
    assert_eq!(config.uncertainties_omitted, extra + 2);
    let late = &config.servers[0].routes[1];
    assert!(
        !late.matchers[0].complete,
        "an omitted uncertainty still counts"
    );
}

#[test]
fn group_numbers_are_scoped_to_their_route_list() {
    let subroute = r#"{"handler": "subroute", "routes": [{"group": "b"}, {"group": "b"}]}"#;
    let routes = format!(
        r#"[{{"group": "a"}}, {{"group": "b", "handle": [{subroute}]}}, {{"group": "b"}}]"#
    );
    let json = format!(
        r#"{{"apps": {{"http": {{"servers": {{
            "one": {{"listen": [":80"], "routes": {routes}}},
            "two": {{"listen": [":81"], "routes": [{{"group": "b"}}]}}
        }}}}}}}}"#
    );
    let config = parse(&json);
    let ids = |routes: &[Route]| -> Vec<usize> {
        routes
            .iter()
            .map(|route| route.group.as_ref().expect("grouped").id)
            .collect()
    };
    let one = &config.servers[0].routes;
    assert_eq!(ids(one), [0, 1, 1], "the outer list keeps its numbering");
    assert_eq!(
        ids(subroutes(&one[1].handlers[0])),
        [0, 0],
        "a subroute restarts"
    );
    assert_eq!(
        ids(&config.servers[1].routes),
        [0],
        "another server restarts"
    );
}
