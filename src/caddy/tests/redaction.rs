//! Synthetic secrets must never leave the parser.

use std::net::Ipv4Addr;

use super::*;

/// Synthetic secrets planted in `secrets.json` in fields the model ignores.
const PLANTED: [&str; 8] = [
    "$2a$14$SYNTHETIC",
    "synthetic-user",
    "Basic c3ludGhldGljOnNlY3JldA==",
    "synthetic-dns-token-7f3a",
    "synthetic-private.key",
    "synthetic.crt",
    "synthetic-env-value-91c2",
    "SYNTHETIC_SECRET",
];

fn assert_clean(label: &str, text: &str) {
    for secret in PLANTED {
        assert!(!text.contains(secret), "{label} leaks {secret:?}: {text}");
    }
    for control in ['\u{1b}', '\u{7}'] {
        assert!(!text.contains(control), "{label} holds {control:?}: {text}");
    }
}

#[test]
fn secrets_never_reach_structs_json_or_formatted_output() {
    let config = parse(SECRETS);
    assert_clean("Debug", &format!("{config:?}"));
    assert_clean("JSON", &serde_json::to_string(&config).expect("serialize"));
    let printed: Vec<String> = config
        .uncertainties
        .iter()
        .map(ToString::to_string)
        .collect();
    assert_clean("Display", &printed.join("\n"));

    let server = &config.servers[0];
    assert_eq!(server.name, r"srv\u{1b}[31mred");
    assert_eq!(
        server.tls_policies[0].client_auth,
        Some(ClientAuthMode::Implicit)
    );
    let route = &server.routes[0];
    assert_eq!(group_label(route), Some(r"g\u{1b}[2J"));
    assert_eq!(
        route.handlers[0],
        Handler::Authentication {
            http_basic: true,
            other_providers: false
        }
    );
    let upstreams = &proxy(&route.handlers[3]).upstreams;
    assert_eq!(upstreams, &[socket(Ipv4Addr::LOCALHOST, 8080)]);
    assert!(
        printed
            .iter()
            .any(|line| line.contains(r"evil\u{1b}]0;title\u{7}"))
    );
}

#[test]
fn secrets_never_reach_error_chains() {
    let truncated = &SECRETS[..SECRETS.find("synthetic-dns-token").expect("planted") + 12];
    let shape = SECRETS.replace(
        r#""listen": [":443", "{env.SYNTHETIC_SECRET}:80"]"#,
        r#""listen": "synthetic-env-value-91c2""#,
    );
    assert_ne!(shape, SECRETS);
    for (input, label) in [
        (truncated, "truncated"),
        (shape.as_str(), "shape"),
        ("{\"apps\": synthetic-env-value-91c2}", "syntax"),
    ] {
        let error = parse_caddy_config(input).expect_err(label);
        let mut chain = vec![error.to_string(), format!("{error:?}")];
        let mut source = std::error::Error::source(&error);
        while let Some(cause) = source {
            chain.push(cause.to_string());
            source = cause.source();
        }
        assert_clean(label, &chain.join("\n"));
    }
}

/// A config as `caddy adapt` would print it after expanding `{$VAR}`
/// placeholders, with the expanded value in every modeled field.
const ADAPTED_WITH_TOKEN: &str = r#"{"apps": {"http": {"servers": {
    "srv-Synthetic-Token-5e1d": {
        "listen": [":443", "synthetic-token-5e1d.example.test:80"],
        "routes": [{
            "group": "g-synthetic-token-5e1d",
            "match": [{
                "path": ["/download/synthetic-token-5e1d", "/public/*"],
                "host": ["synthetic-token-5e1d.example.test"],
                "synthetic-token-5e1d": {}
            }],
            "handle": [
                {"handler": "synthetic-token-5e1d"},
                {"handler": "reverse_proxy", "upstreams": [
                    {"dial": "synthetic-token-5e1d.example.test:8080"},
                    {"dial": "127.0.0.1:8080"}
                ]}
            ]
        }]
    }
}}}}"#;

#[test]
fn known_substituted_values_never_reach_the_model() {
    let substitutions = Substitutions::new(["SYNTHETIC-TOKEN-5E1D"]);
    let config = parse_caddy_config_with(ADAPTED_WITH_TOKEN, &substitutions).expect("valid config");
    let json = serde_json::to_string(&config).expect("serialize");
    let printed: Vec<String> = config
        .uncertainties
        .iter()
        .map(ToString::to_string)
        .collect();
    for (label, text) in [
        ("Debug", format!("{config:?}")),
        ("JSON", json),
        ("Display", printed.join("\n")),
    ] {
        assert!(
            !text.to_lowercase().contains("synthetic-token-5e1d"),
            "{label} leaks the substituted value: {text}"
        );
    }

    let server = &config.servers[0];
    assert_eq!(server.name, REDACTED);
    assert_eq!(
        server.listen.len(),
        1,
        "the substituted listen address is left out"
    );
    let route = &server.routes[0];
    assert_eq!(group_label(route), Some(REDACTED));
    assert!(!route.matchers[0].complete);
    assert_eq!(
        route.matchers[0].paths,
        Some(vec![PathMatcher::Prefix {
            prefix: "/public/".into()
        }])
    );
    assert_eq!(route.matchers[0].hosts, Some(Vec::new()));
    let upstreams = &proxy(&route.handlers[1]).upstreams;
    assert_eq!(upstreams, &[socket(Ipv4Addr::LOCALHOST, 8080)]);

    let substituted: Vec<&str> = config
        .uncertainties
        .iter()
        .filter(|u| u.kind == UncertaintyKind::SubstitutedValue)
        .map(|u| u.construct.as_str())
        .collect();
    assert_eq!(substituted, ["listen", "host", "path", "dial"]);
}

#[test]
fn without_substitutions_the_same_config_is_kept_as_written() {
    let config = parse(ADAPTED_WITH_TOKEN);
    let route = &config.servers[0].routes[0];
    assert_eq!(
        route.matchers[0].paths.as_ref().map(Vec::len),
        Some(2),
        "nothing marks a literal path as substituted"
    );
}

#[test]
fn substituted_ports_and_short_values_are_left_out() {
    let json = r#"{"apps": {"http": {"http_port": 48217, "https_port": 8443, "servers": {
        "s": {"listen": [":443"], "routes": [{"match": [{"path": ["ABC", "/x/abc"]}]}]}
    }}}}"#;
    let config =
        parse_caddy_config_with(json, &Substitutions::new(["48217", "abc"])).expect("valid config");
    assert_eq!((config.http_port, config.https_port), (None, Some(8443)));
    let json = serde_json::to_string(&config).expect("serialize");
    assert!(!json.contains("48217"));
    assert_eq!(
        config.servers[0].routes[0].matchers[0].paths,
        Some(vec![PathMatcher::Exact {
            path: "/x/abc".into()
        }]),
        "a short value only taints a value it equals"
    );
    let substituted: Vec<(&str, &str)> = config
        .uncertainties
        .iter()
        .filter(|u| u.kind == UncertaintyKind::SubstitutedValue)
        .map(|u| (u.construct.as_str(), u.location.as_str()))
        .collect();
    let path_at = r#"apps.http.servers["s"].routes[0].match[0].path[0]"#;
    assert_eq!(
        substituted,
        [("path", path_at), ("http_port", "apps.http.http_port")]
    );
}
