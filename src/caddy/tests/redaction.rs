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
