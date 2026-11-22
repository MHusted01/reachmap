use super::tests::{BASE_TIME, default_obs, scope, snapshot_with, sock};
use super::*;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

#[test]
fn matches_wildcard_server_names_tls_schemes_and_upstream_groups() {
    let conf = r#"
http {
    upstream pool {
        server 127.0.0.1:8080;
        server [::1]:8081;
    }
    server {
        listen 443 ssl;
        server_name *.example.test;
        location = /exact {
            proxy_pass http://pool;
        }
        location /app/ {
            proxy_pass http://127.0.0.1:9000/;
        }
    }
    server {
        listen 80 default_server;
        server_name legacy.*;
        location / {
            proxy_pass http://127.0.0.1:9000/;
        }
    }
}
"#;
    let sockets = vec![
        sock(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 443, 1),
        sock(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 80, 2),
        sock(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080, 3),
        sock(IpAddr::V4(Ipv4Addr::LOCALHOST), 9000, 4),
    ];
    let snap = snapshot_with(conf, sockets, false, BASE_TIME);
    let cap = Capture {
        snapshot: &snap,
        scope: Some(scope("host-a", "test-net")),
    };

    let tls_obs = HttpObservation {
        destination: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 443),
        host: "API.EXAMPLE.TEST.",
        path: "/exact",
        tls: true,
        tls_status: TlsStatus::Verified,
        ..default_obs(HttpOutcome::Success2xx { status_code: 200 })
    };
    let tls_rep = correlate(Some(cap), Some(tls_obs), 30);
    assert_eq!(
        tls_rep.backend,
        Some(BackendEvidence::LocalTcpUncertain {
            reason: BackendUncertainty::MixedUpstreamAvailability,
        })
    );
    assert_eq!(
        tls_rep.comparison,
        Comparison::Unavailable {
            reason: Gap::BackendUnverified,
        }
    );

    let wrong_tls = HttpObservation {
        destination: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 443),
        tls: false,
        tls_status: TlsStatus::NotUsed,
        ..default_obs(HttpOutcome::Success2xx { status_code: 200 })
    };
    assert_eq!(
        correlate(Some(cap), Some(wrong_tls), 30).comparison,
        Comparison::Unavailable {
            reason: Gap::TlsSchemeMismatch,
        }
    );

    let trailing_obs = HttpObservation {
        host: "legacy.internal",
        path: "/index.html",
        ..default_obs(HttpOutcome::Success2xx { status_code: 200 })
    };
    assert_eq!(
        correlate(Some(cap), Some(trailing_obs), 30).comparison,
        Comparison::Consistent {}
    );

    let tls_fail = HttpObservation {
        destination: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 443),
        tls: true,
        tls_status: TlsStatus::HandshakeFailed,
        outcome: HttpOutcome::NoResponse {},
        ..default_obs(HttpOutcome::NoResponse {})
    };
    assert_eq!(
        correlate(Some(cap), Some(tls_fail), 30).comparison,
        Comparison::Unavailable {
            reason: Gap::TlsHandshakeFailed,
        }
    );

    let json = serde_json::to_value(&tls_rep).unwrap();
    assert_eq!(json["comparison"]["status"], "unavailable");
    assert_eq!(json["comparison"]["reason"], "backend_unverified");
    assert_eq!(json["auth"]["application_auth"]["status"], "unverified");
    assert_eq!(json["route"]["on_disk_config_only"], true);
    assert_eq!(json["tcp"]["state"], "not_separately_observed");
}

#[test]
fn detects_ambiguous_ipv6only_wildcard_and_serializes_ipv6_listener() {
    let conf = r#"
http {
    server {
        listen [::]:80;
        server_name _;
        location / {
            proxy_pass http://127.0.0.1:8080/;
        }
    }
}
"#;
    let snap = snapshot_with(
        conf,
        vec![
            sock(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 80, 1),
            sock(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080, 2),
        ],
        true,
        BASE_TIME,
    );
    let cap = Capture {
        snapshot: &snap,
        scope: Some(scope("host-a", "test-net")),
    };
    let ipv4_obs = default_obs(HttpOutcome::Success2xx { status_code: 200 });
    assert_eq!(
        correlate(Some(cap), Some(ipv4_obs), 30).comparison,
        Comparison::Unavailable {
            reason: Gap::RouteAmbiguous,
        }
    );
    let ipv6_obs = HttpObservation {
        destination: SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            80,
        ),
        ..default_obs(HttpOutcome::Success2xx { status_code: 200 })
    };
    assert_eq!(
        correlate(Some(cap), Some(ipv6_obs), 30).comparison,
        Comparison::Consistent {}
    );
}
