use super::*;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::process::ExitStatus;

use crate::collect::CollectError;
use crate::host_input_snapshot::render_document;
use crate::socket::{ListeningSocket, Protocol, SocketOptions};
use crate::socket_options::{OptionsReport, SocketOptionsError};

/// A collector failure as the scan reports it.
fn failed(error: CollectError) -> Result<String, NginxScanError> {
    Err(diagnostic::classify_nginx_error(error))
}

const MULTI_FILE: &str = include_str!("../../../tests/fixtures/nginx/multi_file.conf");
const SECRETS: &str = include_str!("../../../tests/fixtures/nginx/secrets.conf");
const UNCERTAINTIES: &str = include_str!("../../../tests/fixtures/nginx/uncertainties.conf");

fn socket(address: IpAddr, port: u16, inode: u64) -> ListeningSocket {
    ListeningSocket {
        address,
        port,
        inode,
        protocol: Protocol::Tcp,
        options: None,
    }
}

fn inventory_with(sockets: Vec<ListeningSocket>, ipv6_only: bool) -> Inventory {
    let by_inode = sockets
        .iter()
        .map(|sock| {
            (
                sock.inode,
                SocketOptions {
                    bound_device: None,
                    ipv6_only,
                },
            )
        })
        .collect();
    Inventory {
        sockets,
        options: OptionsReport {
            by_inode,
            error: None,
        },
    }
}

fn report(config: &str, sockets: Vec<ListeningSocket>, ipv6_only: bool) -> NginxRouteReport {
    collect_with(Ok(config.to_owned()), || {
        Ok(inventory_with(sockets, ipv6_only))
    })
    .unwrap()
}

fn round_trip(report: NginxRouteReport) -> String {
    let expected = report.to_string();
    let complete = report.is_complete();
    let snapshot = snapshot::Snapshot::new("example-host".parse().unwrap(), 1_700_000_000, report);
    let json = render_document(&snapshot).unwrap();
    let replay = snapshot::decode(&json).unwrap();
    assert_eq!(replay.is_complete(), complete);
    assert_eq!(replay.to_string().split_once('\n').unwrap().1, expected);
    json
}

#[test]
fn correlates_frontend_listens_and_backends_with_boundary_and_auth_separation() {
    let conf = r#"
http {
    upstream api_pool {
        server 127.0.0.1:3000;
        server [::1]:3001 backup;
        server 10.20.30.40:8080 down;
    }
    server {
        listen 80 default_server;
        listen [::]:80 ipv6only=on;
        server_name app.example.test;
        ssl_verify_client on;

        location = /healthz {
            proxy_pass http://127.0.0.1:9000/health;
        }
        location ^~ /api/ {
            auth_basic "API";
            proxy_pass https://api_pool;
        }
        location /remote/ {
            proxy_pass http://198.51.100.25:8080/remote/;
        }
    }
}
"#;
    let sockets = vec![
        socket(Ipv4Addr::UNSPECIFIED.into(), 80, 1),
        socket(Ipv6Addr::UNSPECIFIED.into(), 80, 2),
        socket(Ipv4Addr::LOCALHOST.into(), 9000, 3),
        socket(Ipv4Addr::LOCALHOST.into(), 3000, 4),
    ];
    let rep = report(conf, sockets, true);
    assert!(
        rep.is_complete(),
        "uncertainties: {:?}",
        rep.config.uncertainties
    );
    let text = rep.to_string();

    assert!(text.contains("on-disk config files and local TCP sockets only"));
    assert!(text.contains("running master reload state"));
    assert!(text.contains("application authentication are unverified"));
    assert!(text.contains("listen: 0.0.0.0:80 [default_server] (TCP listener 0.0.0.0:80)"));
    assert!(text.contains("listen: [::]:80 [ipv6only=on] (TCP listener [::]:80)"));
    assert!(text.contains("proxy auth: ssl_verify_client=on; application auth: unverified"));
    assert!(text.contains("location = /healthz"));
    assert!(text.contains("target: http://127.0.0.1:9000/health (TCP listener 127.0.0.1:9000)"));
    assert!(
        text.contains(
            "proxy auth: auth_basic=on, ssl_verify_client=on; application auth: unverified"
        )
    );
    assert!(text.contains("upstream server 127.0.0.1:3000 (TCP listener 127.0.0.1:3000)"));
    assert!(text.contains("upstream server [::1]:3001 [backup] (no matching TCP listener)"));
    assert!(!text.contains("10.20.30.40:8080"));
    assert!(text.contains("non-loopback target (no exact local TCP listener; may be remote)"));

    let dns_conf = r#"
http {
    server {
        listen 80;
        location /dns/ {
            proxy_pass http://upstream.example.test:8081/;
        }
    }
}
"#;
    let dns_rep = report(
        dns_conf,
        vec![socket(Ipv4Addr::UNSPECIFIED.into(), 80, 1)],
        false,
    );
    assert!(!dns_rep.is_complete());
    assert!(
        dns_rep
            .to_string()
            .contains("hostname requires DNS resolution; not correlated locally")
    );
}

#[test]
fn non_loopback_backend_does_not_match_wildcard_listener_but_matches_exact_listener() {
    let conf = r#"
http {
    server {
        listen 80;
        server_name app.example.test;
        location / {
            proxy_pass http://198.51.100.25:8080/;
        }
    }
}
"#;
    let wildcard_only = report(
        conf,
        vec![
            socket(Ipv4Addr::UNSPECIFIED.into(), 80, 1),
            socket(Ipv4Addr::UNSPECIFIED.into(), 8080, 2),
        ],
        false,
    );
    let wildcard_text = wildcard_only.to_string();
    assert!(
        wildcard_text.contains("non-loopback target (no exact local TCP listener; may be remote)")
    );

    let exact = report(
        conf,
        vec![
            socket(Ipv4Addr::UNSPECIFIED.into(), 80, 1),
            socket("198.51.100.25".parse().unwrap(), 8080, 2),
        ],
        false,
    );
    assert!(
        exact
            .to_string()
            .contains("target: http://198.51.100.25:8080/ (TCP listener 198.51.100.25:8080)")
    );
}

#[test]
fn ambiguous_localhost_and_missing_options_are_reported_as_uncertain() {
    let conf = r#"
http {
    server {
        listen 8080;
        location / {
            proxy_pass http://localhost:4000;
        }
    }
}
"#;
    let ambiguous = report(
        conf,
        vec![
            socket(Ipv4Addr::LOCALHOST.into(), 4000, 1),
            socket(Ipv6Addr::LOCALHOST.into(), 4000, 2),
        ],
        false,
    );
    let text = ambiguous.to_string();
    assert!(text.contains("listen: 0.0.0.0:8080 (no matching TCP listener)"));
    assert!(text.contains("target: http://localhost:4000 (multiple possible TCP listeners)"));

    let no_opts = collect_with(Ok(conf.to_owned()), || {
        Ok(Inventory {
            sockets: vec![socket(Ipv4Addr::UNSPECIFIED.into(), 8080, 1)],
            options: OptionsReport {
                error: Some(SocketOptionsError::Open(CollectError::UnsupportedOs {
                    os: "test",
                })),
                ..OptionsReport::default()
            },
        })
    })
    .unwrap();
    assert!(!no_opts.is_complete());
    let no_opts_text = no_opts.to_string();
    assert!(no_opts_text.contains("listener's socket options leave the match uncertain"));
    assert!(no_opts_text.contains("Partial Nginx route collection:"));
}

#[test]
fn ipv6only_on_listen_distinguishes_matching_and_mismatched_sockets() {
    let conf = "http { server { listen [::]:80 ipv6only=on; } }";
    let matched = report(
        conf,
        vec![socket(Ipv6Addr::UNSPECIFIED.into(), 80, 1)],
        true,
    );
    assert!(
        matched
            .to_string()
            .contains("listen: [::]:80 [ipv6only=on] (TCP listener [::]:80)")
    );

    let mismatched = report(
        conf,
        vec![socket(Ipv6Addr::UNSPECIFIED.into(), 80, 1)],
        false,
    );
    assert!(
        mismatched
            .to_string()
            .contains("listen: [::]:80 [ipv6only=on] (no matching TCP listener)")
    );
}

#[test]
fn collector_failures_degrade_cleanly_and_never_echo_secrets() {
    let missing = collect_with(
        failed(CollectError::Run {
            command: "nginx -V".into(),
            source: std::io::Error::from(ErrorKind::NotFound),
        }),
        || panic!("should not read sockets"),
    )
    .unwrap_err();
    assert!(matches!(missing, NginxScanError::MissingCommand));
    assert!(missing.to_string().contains("not found"));

    let denied_exec = collect_with(
        failed(CollectError::Run {
            command: "nginx -V".into(),
            source: std::io::Error::from(ErrorKind::PermissionDenied),
        }),
        || panic!("should not read sockets"),
    )
    .unwrap_err();
    assert!(matches!(denied_exec, NginxScanError::PermissionDenied));

    let denied_stderr = collect_with(
        failed(CollectError::CommandFailed {
            command: "nginx -V".into(),
            status: ExitStatus::default(),
            stderr: "nginx: [emerg] open() \"/etc/nginx/ssl.key\" failed (13: Permission denied)"
                .into(),
        }),
        || panic!("should not read sockets"),
    )
    .unwrap_err();
    assert!(matches!(denied_stderr, NginxScanError::PermissionDenied));
    assert!(!denied_stderr.to_string().contains("ssl.key"));

    let secret_stderr = collect_with(
        failed(CollectError::CommandFailed {
            command: "nginx -V".into(),
            status: ExitStatus::default(),
            stderr: "nginx: [emerg] unknown directive \"Bearer TOP_SECRET_TOKEN_VALUE\" in /etc/nginx/conf.d/app.conf:12".into(),
        }),
        || panic!("should not read sockets"),
    )
    .unwrap_err();
    assert!(matches!(
        secret_stderr,
        NginxScanError::CommandFailed { .. }
    ));
    assert!(!secret_stderr.to_string().contains("TOP_SECRET_TOKEN_VALUE"));
    assert!(!secret_stderr.to_string().contains("app.conf"));

    let timed_out = collect_with(
        failed(CollectError::TimedOut {
            command: "nginx -V".into(),
            timeout: Duration::from_secs(5),
        }),
        || panic!("should not read sockets"),
    )
    .unwrap_err();
    assert!(matches!(timed_out, NginxScanError::TimedOut { .. }));

    let oversized_stdout = collect_with(
        failed(CollectError::OutputTooLarge {
            command: "nginx -V".into(),
            stream: "stdout",
            limit_bytes: 8 * 1024 * 1024,
        }),
        || panic!("should not read sockets"),
    )
    .unwrap_err();
    assert!(matches!(
        oversized_stdout,
        NginxScanError::OutputTooLarge {
            stream: "stdout",
            limit_bytes: 8_388_608
        }
    ));
    assert!(
        oversized_stdout
            .to_string()
            .contains("stdout output exceeded the 8388608-byte")
    );

    let oversized_stderr = collect_with(
        failed(CollectError::OutputTooLarge {
            command: "nginx -V".into(),
            stream: "stderr",
            limit_bytes: 64 * 1024,
        }),
        || panic!("should not read sockets"),
    )
    .unwrap_err();
    assert!(matches!(
        oversized_stderr,
        NginxScanError::OutputTooLarge {
            stream: "stderr",
            limit_bytes: 65_536
        }
    ));
    assert!(
        oversized_stderr
            .to_string()
            .contains("stderr output exceeded the 65536-byte")
    );

    let not_utf8 = collect_with(
        failed(CollectError::NotUtf8 {
            command: "nginx -V".into(),
            source: String::from_utf8(vec![0xff]).unwrap_err(),
        }),
        || panic!("should not read sockets"),
    )
    .unwrap_err();
    assert!(matches!(not_utf8, NginxScanError::NotUtf8));

    let unsupported = collect_with(failed(CollectError::UnsupportedOs { os: "macos" }), || {
        panic!("should not read sockets")
    })
    .unwrap_err();
    assert!(matches!(
        unsupported,
        NginxScanError::UnsupportedOs { os: "macos" }
    ));
}

#[test]
fn empty_config_skips_inventory_and_uncertainties_mark_incomplete() {
    let empty = collect_with(Ok("events { worker_connections 1024; }".into()), || {
        panic!("empty http config needs no sockets")
    })
    .unwrap();
    assert!(empty.is_complete());
    assert!(
        empty
            .to_string()
            .contains("No configured Nginx HTTP servers found.")
    );
    let empty_json = round_trip(empty);
    assert!(empty_json.contains(r#""status": "not_needed""#));

    let uncertain = report(UNCERTAINTIES, vec![], false);
    assert!(!uncertain.is_complete());
    let text = uncertain.to_string();
    assert!(text.contains("Configuration uncertainties:"));
    let _ = round_trip(uncertain);
}

#[test]
fn snapshot_minimizes_secrets_and_unrelated_listeners() {
    let rep = report(
        SECRETS,
        vec![
            socket(Ipv4Addr::UNSPECIFIED.into(), 443, 1),
            socket(Ipv4Addr::LOCALHOST.into(), 8443, 2),
            socket("192.0.2.99".parse().unwrap(), 54321, 3),
        ],
        false,
    );
    let json = round_trip(rep);
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
        "192.0.2.99",
        "54321",
        "inode",
    ] {
        assert!(!json.contains(secret), "leaked {secret:?} in {json}");
    }
    assert!(json.contains("https://127.0.0.1:8443/v1/items"));
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["scope"], "nginx_routes");
    assert_eq!(parsed["snapshot_version"], 1);
    assert_eq!(
        parsed["evidence"]["inventory"]["listeners"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn multi_file_fixture_and_unavailable_inventory_round_trip() {
    let rep = collect_with(Ok(MULTI_FILE.to_owned()), || {
        Err(CollectError::Read {
            path: "/proc/net/tcp".into(),
            source: std::io::Error::new(ErrorKind::PermissionDenied, "private kernel detail"),
        }
        .into())
    })
    .unwrap();
    assert!(!rep.is_complete());
    let text = rep.to_string();
    assert!(text.contains("TCP socket inventory unavailable"));
    assert!(text.contains("permission denied"));
    let json = round_trip(rep);
    assert!(!json.contains("private kernel detail") && !json.contains("/proc/net/tcp"));
}
