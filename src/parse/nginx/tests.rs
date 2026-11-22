use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::nginx::{
    AuthSignals, ListenAddress, LocationModifier, NginxConfig, ProxyScheme, ProxyTarget,
    ServerName, SslVerifyClient, UncertaintyKind, UnsupportedProxyReason,
};
use crate::parse::nginx::{MAX_INPUT_BYTES, NginxParseError, parse_nginx_config};

const MULTI_FILE_FIXTURE: &str = include_str!("../../../tests/fixtures/nginx/multi_file.conf");
const UNCERTAINTIES_FIXTURE: &str =
    include_str!("../../../tests/fixtures/nginx/uncertainties.conf");
const SECRETS_FIXTURE: &str = include_str!("../../../tests/fixtures/nginx/secrets.conf");

#[test]
fn parses_multi_file_fixture_without_uncertainties_and_round_trips_json() {
    let config = parse_nginx_config(MULTI_FILE_FIXTURE).expect("valid multi-file fixture");
    assert!(
        config.uncertainties.is_empty(),
        "unexpected uncertainties: {:?}",
        config.uncertainties
    );

    assert_eq!(config.upstreams.len(), 1);
    let upstream = &config.upstreams[0];
    assert_eq!(upstream.name, "api_backend");
    assert_eq!(
        upstream.source_file.as_deref(),
        Some("/etc/nginx/conf.d/upstreams.conf")
    );
    assert!(upstream.complete);
    assert_eq!(upstream.servers.len(), 3);
    assert!(!upstream.servers[0].backup && !upstream.servers[0].down);
    assert!(upstream.servers[1].backup);
    assert!(upstream.servers[2].down);

    assert_eq!(config.servers.len(), 2);
    let first = &config.servers[0];
    assert_eq!(
        first.source_file.as_deref(),
        Some("/etc/nginx/sites-enabled/default.conf")
    );
    assert_eq!(first.listens.len(), 2);
    assert_eq!(first.listens[0].address, ListenAddress::AnyIpv4 {});
    assert_eq!(first.listens[0].port, 80);
    assert!(first.listens[0].default_server);
    assert!(!first.listens[0].ssl);
    assert_eq!(first.listens[1].address, ListenAddress::AnyIpv6 {});
    assert_eq!(first.listens[1].ipv6only, Some(true));

    assert_eq!(
        first.server_names,
        vec![
            ServerName::Exact {
                host: "app.example.test".into()
            },
            ServerName::LeadingWildcard {
                suffix: "example.test".into()
            },
            ServerName::TrailingWildcard {
                prefix: "demo".into()
            },
            ServerName::CatchAll {},
        ]
    );
    assert_eq!(
        first.auth,
        AuthSignals {
            auth_basic: None,
            auth_request: false,
            ssl_verify_client: Some(SslVerifyClient::Optional),
            access_control: false,
        }
    );

    assert_eq!(first.locations.len(), 3);
    assert_eq!(first.locations[0].modifier, LocationModifier::Exact);
    assert_eq!(first.locations[0].path, "/healthz");
    assert_eq!(
        first.locations[0].target,
        Some(ProxyTarget::StaticHttp {
            scheme: ProxyScheme::Http,
            endpoint: "http://127.0.0.1:9000/health".into(),
            targets: vec![SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                9000
            )],
        })
    );

    assert_eq!(
        first.locations[1].modifier,
        LocationModifier::PreferentialPrefix
    );
    assert_eq!(first.locations[1].auth.auth_basic, Some(true));
    assert_eq!(
        first.locations[1].auth.ssl_verify_client,
        Some(SslVerifyClient::Optional)
    );
    assert_eq!(
        first.locations[1].target,
        Some(ProxyTarget::Upstream {
            scheme: ProxyScheme::Https,
            name: "api_backend".into(),
            targets: vec![
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 3000),
                SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 3001),
            ],
            complete: true,
        })
    );

    assert_eq!(first.locations[2].modifier, LocationModifier::Prefix);
    assert_eq!(
        first.locations[2].target,
        Some(ProxyTarget::StaticHttp {
            scheme: ProxyScheme::Http,
            endpoint: "http://localhost:4000".into(),
            targets: vec![
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4000),
                SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 4000),
            ],
        })
    );

    let second = &config.servers[1];
    assert_eq!(second.listens[0].port, 443);
    assert!(second.listens[0].ssl);
    assert_eq!(
        second.listens[1].address,
        ListenAddress::Ipv4 {
            ip: Ipv4Addr::new(192, 0, 2, 10)
        }
    );
    assert_eq!(second.auth.auth_basic, Some(true));
    assert_eq!(second.locations[0].auth.auth_basic, Some(false));
    assert_eq!(
        second.locations[0].target,
        Some(ProxyTarget::StaticHttp {
            scheme: ProxyScheme::Http,
            endpoint: "http://198.51.100.25:8080/public/".into(),
            targets: vec![SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(198, 51, 100, 25)),
                8080
            )],
        })
    );

    let json = serde_json::to_string_pretty(&config).expect("serialize");
    let decoded: NginxConfig = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(decoded, config);
}

#[test]
fn records_explicit_uncertainties_without_echoing_raw_values() {
    let config = parse_nginx_config(UNCERTAINTIES_FIXTURE).expect("syntactically valid fixture");
    let expected = [
        (UncertaintyKind::DynamicVariable, "map"),
        (UncertaintyKind::DynamicVariable, "geo"),
        (UncertaintyKind::UnsupportedListenOption, "listen"),
        (UncertaintyKind::RegexMatch, "server_name"),
        (UncertaintyKind::DynamicRouting, "try_files"),
        (UncertaintyKind::DynamicRouting, "error_page"),
        (UncertaintyKind::UnsupportedLocation, "location"),
        (UncertaintyKind::RegexMatch, "location"),
        (UncertaintyKind::DynamicControlFlow, "if"),
        (UncertaintyKind::DynamicRouting, "rewrite"),
        (UncertaintyKind::DynamicTarget, "proxy_pass"),
        (UncertaintyKind::UnsupportedTransport, "proxy_pass"),
        (UncertaintyKind::UnsupportedBackend, "fastcgi_pass"),
        (UncertaintyKind::UnsupportedBackend, "grpc_pass"),
        (UncertaintyKind::AccessControl, "allow"),
        (UncertaintyKind::AccessControl, "deny"),
        (UncertaintyKind::SubrequestAuth, "auth_request"),
        (UncertaintyKind::NestedLocation, "location"),
        (
            UncertaintyKind::UnmodeledDirective,
            "custom_third_party_module",
        ),
        (UncertaintyKind::UnsupportedContext, "stream"),
    ];

    for (kind, directive) in expected {
        assert!(
            config.uncertainties.iter().any(|u| {
                u.kind == kind
                    && u.directive == directive
                    && u.source_file.as_deref() == Some("/etc/nginx/nginx.conf")
                    && u.line.is_some()
                    && !u.to_string().is_empty()
            }),
            "missing uncertainty ({kind:?}, {directive}) in {:?}",
            config.uncertainties
        );
    }

    let serialized = serde_json::to_string(&config).expect("serialize");
    let debug = format!("{config:?}");
    for raw_value in [
        "blocked-raw-body",
        "$http_upgrade",
        "$allowed_net",
        "$upstream_var",
        "/run/app.sock",
        "@fallback",
        "proxy_protocol",
        "50051",
        "/nested-inner",
        "/_auth",
        "5432",
    ] {
        assert!(
            !serialized.contains(raw_value) && !debug.contains(raw_value),
            "raw value `{raw_value}` leaked into model"
        );
    }
}

#[test]
fn redacts_secrets_and_sanitizes_control_sequences() {
    let config = parse_nginx_config(SECRETS_FIXTURE).expect("valid secrets fixture");
    let json = serde_json::to_string(&config).expect("serialize");
    let debug = format!("{config:?}");
    let display_uncertainties: String = config
        .uncertainties
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("\n");

    for secret in [
        "SENTINEL_COMMENT_SECRET_VALUE",
        "SENTINEL_CERT_PATH",
        "SENTINEL_PRIVATE_KEY_PATH",
        "SENTINEL_SSL_PASSWORD_FILE",
        "SENTINEL_AUTH_REALM_SECRET",
        "SENTINEL_HTPASSWD_FILE",
        "SENTINEL_BEARER_TOKEN",
        "SENTINEL_HEADER_SECRET",
        "SENTINEL_USER",
        "SENTINEL_PASS",
        "SENTINEL_QUERY_TOKEN",
        "SENTINEL_FRAGMENT",
        "SENTINEL_RETURN_BODY_SECRET",
    ] {
        assert!(!json.contains(secret), "{secret} leaked in JSON");
        assert!(!debug.contains(secret), "{secret} leaked in Debug");
        assert!(
            !display_uncertainties.contains(secret),
            "{secret} leaked in uncertainty Display"
        );
    }

    assert!(json.contains("https://127.0.0.1:8443/v1/items"));
    assert_eq!(config.servers[0].auth.auth_basic, Some(true));

    // Control characters and bidi overrides in file paths, paths, or directive names must be escaped.
    let escape_input = concat!(
        "# configuration file /etc/nginx/\u{1b}[2Jevil\u{202e}.conf:\n",
        "http {\n",
        "  server {\n",
        "    listen 80;\n",
        "    location /ok\u{1b}[31m {\n",
        "      evil\u{2066}_dir \"SENTINEL_ESCAPE_ARG\";\n",
        "      proxy_pass http://127.0.0.1:8080/path\u{1b}[0m;\n",
        "    }\n",
        "  }\n",
        "}\n",
    );
    let escaped = parse_nginx_config(escape_input).expect("parses with escapes");
    let escaped_json = serde_json::to_string(&escaped).expect("serialize");
    let escaped_debug = format!("{escaped:?}");
    for raw_ctrl in ["\u{1b}", "\u{202e}", "\u{2066}", "SENTINEL_ESCAPE_ARG"] {
        assert!(!escaped_json.contains(raw_ctrl));
        assert!(!escaped_debug.contains(raw_ctrl));
    }

    // Even syntax errors must never echo raw secrets or unescaped control sequences.
    let bad_with_secret = concat!(
        "# configuration file /etc/nginx/bad\u{1b}[2J.conf:\n",
        "http { server { proxy_set_header Authorization \"Bearer SENTINEL_ERR_SECRET\"; broken ",
    );
    let err = parse_nginx_config(bad_with_secret).expect_err("truncated directive");
    let err_msg = err.to_string();
    assert!(!err_msg.contains("SENTINEL_ERR_SECRET"));
    assert!(!err_msg.contains('\u{1b}'));
    assert!(err_msg.contains("\\u{1b}"));
}

#[test]
fn handles_quotes_escapes_relative_includes_and_edge_targets() {
    let config = parse_nginx_config(
        r#"
        # configuration file /etc/nginx/nginx.conf:
        http {
            include conf.d/common.conf;
            upstream dns_group {
                server backend.internal.test:8080;
                server 127.0.0.1:8081 resolve;
                server unix:/run/up.sock;
                server $dyn_up;
                server 127.0.0.1:8082 bad_flag;
            }
            server {
                listen [::1]:8443 ssl ipv6only=off;
                listen *:8000 default;
                server_name api.example.test ~^bad$ bad.*.mid;
                location "/quoted path" {
                    auth_basic_user_file '/etc/nginx/htpasswd\'secret';
                    proxy_pass http://dns_group;
                }
                location /unresolved-host {
                    proxy_pass https://service.internal.test/api?k=secret;
                }
                location /bad-scheme {
                    proxy_pass ftp://127.0.0.1:21;
                }
                location /missing-inc {
                    include snippets/missing.conf;
                    include $dyn_inc.conf;
                    proxy_pass http://127.0.0.1:7000;
                    proxy_pass http://127.0.0.1:7001;
                }
            }
        }
        # configuration file /etc/nginx/conf.d/common.conf:
        ssl_verify_client on;
        "#,
    )
    .expect("valid edge-target config");

    assert_eq!(
        config.servers[0].auth.ssl_verify_client,
        Some(SslVerifyClient::On)
    );
    assert_eq!(config.servers[0].listens[0].ipv6only, Some(false));
    assert!(config.servers[0].listens[1].default_server);
    assert_eq!(config.servers[0].locations[0].path, "/quoted path");
    assert_eq!(
        config.servers[0].locations[0].target,
        Some(ProxyTarget::Upstream {
            scheme: ProxyScheme::Http,
            name: "dns_group".into(),
            targets: vec![],
            complete: false,
        })
    );
    assert_eq!(
        config.servers[0].locations[1].target,
        Some(ProxyTarget::UnresolvedHost {
            scheme: ProxyScheme::Https,
            host: "service.internal.test".into(),
            port: 443,
        })
    );
    assert_eq!(
        config.servers[0].locations[2].target,
        Some(ProxyTarget::Unsupported {
            reason: UnsupportedProxyReason::UnsupportedScheme,
        })
    );

    assert!(
        config
            .uncertainties
            .iter()
            .any(|u| u.kind == UncertaintyKind::UnresolvedInclude && u.directive == "include")
    );
    assert!(
        config
            .uncertainties
            .iter()
            .any(|u| u.kind == UncertaintyKind::DynamicInclude && u.directive == "include")
    );
    assert!(
        config
            .uncertainties
            .iter()
            .any(|u| u.kind == UncertaintyKind::AmbiguousDirective && u.directive == "proxy_pass")
    );
}

#[test]
fn rejects_malformed_truncated_and_over_bounded_inputs() {
    assert!(matches!(
        parse_nginx_config("http { server { listen 80; }"),
        Err(NginxParseError::UnclosedBlock { line: 1, .. })
    ));
    assert!(matches!(
        parse_nginx_config("http { } }"),
        Err(NginxParseError::UnexpectedClosingBrace { line: 1, .. })
    ));
    assert!(matches!(
        parse_nginx_config("http { ; }"),
        Err(NginxParseError::UnexpectedToken { line: 1, .. })
    ));
    assert!(matches!(
        parse_nginx_config("http { server { listen 80"),
        Err(NginxParseError::TruncatedDirective { line: 1, .. })
    ));
    assert!(matches!(
        parse_nginx_config("http { return 200 \"unclosed; }"),
        Err(NginxParseError::UnterminatedString { line: 1, .. })
    ));
    assert!(matches!(
        parse_nginx_config("http { return 200 \\"),
        Err(NginxParseError::TruncatedEscape { line: 1, .. })
    ));
    assert!(matches!(
        parse_nginx_config(
            "# configuration file /etc/a.conf:\nhttp {\n# configuration file /etc/b.conf:\n}\n"
        ),
        Err(NginxParseError::UnclosedBlock { file: Some(f), line: 1 }) if f == "/etc/a.conf"
    ));

    let too_deep = format!("{}{}", "location /a { ".repeat(34), "}".repeat(34));
    assert!(matches!(
        parse_nginx_config(&too_deep),
        Err(NginxParseError::NestingTooDeep { limit: 32, .. })
    ));

    let too_large = " ".repeat(MAX_INPUT_BYTES + 1);
    assert_eq!(
        parse_nginx_config(&too_large),
        Err(NginxParseError::InputTooLarge {
            limit_bytes: MAX_INPUT_BYTES
        })
    );
}

#[test]
fn handles_braced_variables_acl_overrides_http_includes_and_duplicate_upstreams() {
    let config = parse_nginx_config(
        r#"
        # configuration file /etc/nginx/nginx.conf:
        http {
            include /etc/nginx/missing_http.conf;
            upstream dup_up {
                server 127.0.0.1:8080;
            }
            upstream dup_up {
                server 127.0.0.1:8081;
            }
            server {
                listen 80;
                deny all;
                location /open {
                    allow all;
                    proxy_pass http://${x};
                }
                location /protected {
                    satisfy any;
                    set $a ${b};
                    proxy_pass http://dup_up;
                }
                location /allow_only {
                    allow 10.0.0.0/8;
                    proxy_pass http://127.0.0.1:8082;
                }
                location /deny_single_ip {
                    deny 192.0.2.5;
                    proxy_pass http://127.0.0.1:8083;
                }
                location /deny_ip_then_allow_all {
                    deny 192.0.2.5;
                    allow all;
                    proxy_pass http://127.0.0.1:8084;
                }
            }
        }
        "#,
    )
    .expect("braced variables and overrides should parse cleanly");

    assert!(!config.servers[0].locations[0].auth.access_control);
    assert_eq!(
        config.servers[0].locations[0].target,
        Some(ProxyTarget::Unsupported {
            reason: UnsupportedProxyReason::Variable,
        })
    );
    assert!(config.servers[0].locations[1].auth.access_control);
    assert!(!config.servers[0].locations[2].auth.access_control);
    assert!(!config.servers[0].locations[3].auth.access_control);
    assert!(!config.servers[0].locations[4].auth.access_control);
    assert_eq!(
        config.servers[0].locations[1].target,
        Some(ProxyTarget::Upstream {
            scheme: ProxyScheme::Http,
            name: "dup_up".into(),
            targets: vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080)],
            complete: false,
        })
    );

    assert!(
        config
            .uncertainties
            .iter()
            .any(|u| u.kind == UncertaintyKind::UnresolvedInclude && u.directive == "include")
    );
    assert!(
        config
            .uncertainties
            .iter()
            .any(|u| u.kind == UncertaintyKind::AmbiguousDirective && u.directive == "upstream")
    );
    assert!(
        config
            .uncertainties
            .iter()
            .any(|u| u.kind == UncertaintyKind::DynamicTarget && u.directive == "proxy_pass")
    );
    assert!(
        config
            .uncertainties
            .iter()
            .any(|u| u.kind == UncertaintyKind::DynamicControlFlow && u.directive == "satisfy")
    );
    assert!(
        config
            .uncertainties
            .iter()
            .any(|u| u.kind == UncertaintyKind::UnmodeledDirective && u.directive == "set")
    );
}
