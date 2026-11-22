use super::*;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::num::NonZeroU64;

use crate::collect::CollectError;
use crate::local_tcp::Inventory;
use crate::nginx::LocationModifier;
use crate::nginx::routes::{collect_with, snapshot::Snapshot};
use crate::probe::Outcome;
use crate::scan::ScanError;
use crate::socket::{ListeningSocket, Protocol, SocketOptions};
use crate::socket_options::{OptionsReport, SocketOptionsError};

pub(super) const BASE_TIME: u64 = 1_700_000_000;

pub(super) fn sock(address: IpAddr, port: u16, inode: u64) -> ListeningSocket {
    ListeningSocket {
        address,
        port,
        inode,
        protocol: Protocol::Tcp,
        options: None,
    }
}

fn inventory(sockets: Vec<ListeningSocket>, ipv6_only: bool) -> Inventory {
    let by_inode = sockets
        .iter()
        .map(|s| {
            (
                s.inode,
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

pub(super) fn snapshot_with(
    conf: &str,
    sockets: Vec<ListeningSocket>,
    ipv6_only: bool,
    captured_at: u64,
) -> Snapshot {
    let report = collect_with(Ok(conf.to_owned()), || Ok(inventory(sockets, ipv6_only))).unwrap();
    Snapshot::new("example-nginx".parse().unwrap(), captured_at, report)
}

pub(super) fn scope(collector: &'static str, network: &'static str) -> Scope<'static> {
    Scope {
        collector_identity: collector,
        network_context: network,
    }
}

pub(super) fn default_obs(outcome: HttpOutcome) -> HttpObservation<'static> {
    HttpObservation {
        scope: Some(scope("host-a", "test-net")),
        destination: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 80),
        host: "app.example.test",
        path: "/api/items",
        tls: false,
        tls_status: TlsStatus::NotUsed,
        credentials_presented: None,
        started_at_unix_seconds: NonZeroU64::new(BASE_TIME + 1),
        finished_at_unix_seconds: NonZeroU64::new(BASE_TIME + 2),
        outcome,
        tcp: None,
    }
}

const STANDARD_CONF: &str = r#"
http {
    server {
        listen 192.0.2.10:80;
        server_name app.example.test;

        location = /healthz {
            proxy_pass http://127.0.0.1:9000/health;
        }
        location ^~ /api/ {
            proxy_pass http://127.0.0.1:8080/;
        }
        location /admin/ {
            auth_basic "Admin";
            proxy_pass http://127.0.0.1:8080/;
        }
        location /missing/ {
            proxy_pass http://127.0.0.1:18081/;
        }
        location /remote/ {
            proxy_pass http://198.51.100.25:8080/;
        }
    }
}
"#;

fn standard_sockets() -> Vec<ListeningSocket> {
    vec![
        sock(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 80, 1),
        sock(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080, 2),
        sock(IpAddr::V4(Ipv4Addr::LOCALHOST), 9000, 3),
    ]
}

#[test]
fn correlates_working_2xx_with_live_loopback_backend_and_keeps_app_auth_unverified() {
    let snap = snapshot_with(STANDARD_CONF, standard_sockets(), false, BASE_TIME);
    let cap = Capture {
        snapshot: &snap,
        scope: Some(scope("host-a", "test-net")),
    };
    let obs = HttpObservation {
        tcp: Some(TcpObservation {
            handshake: Some(&Outcome::Open),
            inbound_path_verdict: Some(InboundTcpVerdict::ListenerReachable),
        }),
        ..default_obs(HttpOutcome::from_status_code(200).unwrap())
    };
    let report = correlate(Some(cap), Some(obs), 30);

    assert_eq!(report.comparison, Comparison::Consistent {});
    let route = report.route.as_ref().unwrap();
    assert!(route.on_disk_config_only);
    assert!(route.running_master_reload_unverified);
    assert_eq!(
        route.location_modifier,
        Some(LocationModifier::PreferentialPrefix)
    );
    assert_eq!(route.location_path, Some("/api/"));
    assert_eq!(
        route.frontend_listener,
        ListenerEvidence::Matched {
            address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 80),
        }
    );
    assert_eq!(
        report.tcp.state,
        TcpLayerState::ReachableObservedOrPredicted
    );
    assert_eq!(
        report.backend,
        Some(BackendEvidence::LocalTcpPresent {
            addresses: vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080)],
        })
    );
    let auth = report.auth.unwrap();
    assert_eq!(auth.indicator, ProxyAuthIndicator::NoneConfigured);
    assert_eq!(auth.application_auth, ApplicationAuthStatus::Unverified {});
}

#[test]
fn separates_502_503_504_from_local_backend_listener_presence() {
    let snap = snapshot_with(STANDARD_CONF, standard_sockets(), false, BASE_TIME);
    let cap = Capture {
        snapshot: &snap,
        scope: Some(scope("host-a", "test-net")),
    };

    for code in [502, 503, 504] {
        let missing_obs = HttpObservation {
            path: "/missing/item",
            ..default_obs(HttpOutcome::from_status_code(code).unwrap())
        };
        let missing_report = correlate(Some(cap), Some(missing_obs), 30);
        assert_eq!(missing_report.comparison, Comparison::Consistent {});
        assert_eq!(
            missing_report.backend,
            Some(BackendEvidence::LocalTcpAbsent {})
        );
        assert_eq!(
            missing_report.tcp.state,
            TcpLayerState::NotSeparatelyObserved
        );

        let live_obs = default_obs(HttpOutcome::from_status_code(code).unwrap());
        let live_report = correlate(Some(cap), Some(live_obs), 30);
        assert_eq!(
            live_report.comparison,
            Comparison::Unavailable {
                reason: Gap::BackendApplicationErrorUnverified,
            }
        );
        assert!(matches!(
            live_report.backend,
            Some(BackendEvidence::LocalTcpPresent { .. })
        ));
    }
}

#[test]
fn disagrees_when_2xx_succeeds_for_absent_backend_or_absent_frontend_listener() {
    let snap = snapshot_with(STANDARD_CONF, standard_sockets(), false, BASE_TIME);
    let cap = Capture {
        snapshot: &snap,
        scope: Some(scope("host-a", "test-net")),
    };
    let obs_missing_backend = HttpObservation {
        path: "/missing/",
        ..default_obs(HttpOutcome::Success2xx { status_code: 200 })
    };
    let r1 = correlate(Some(cap), Some(obs_missing_backend), 30);
    assert_eq!(r1.comparison, Comparison::Disagrees {});
    assert_eq!(r1.backend, Some(BackendEvidence::LocalTcpAbsent {}));

    let no_frontend_snap = snapshot_with(
        STANDARD_CONF,
        vec![sock(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080, 2)],
        false,
        BASE_TIME,
    );
    let r2 = correlate(
        Some(Capture {
            snapshot: &no_frontend_snap,
            scope: Some(scope("host-a", "test-net")),
        }),
        Some(default_obs(HttpOutcome::Success2xx { status_code: 200 })),
        30,
    );
    assert_eq!(r2.comparison, Comparison::Disagrees {});
    assert_eq!(
        r2.route.unwrap().frontend_listener,
        ListenerEvidence::Missing {}
    );
}

#[test]
fn distinguishes_proxy_auth_from_unverified_application_auth() {
    let snap = snapshot_with(STANDARD_CONF, standard_sockets(), false, BASE_TIME);
    let cap = Capture {
        snapshot: &snap,
        scope: Some(scope("host-a", "test-net")),
    };

    // 401/403 on auth_basic=on route -> Consistent, app auth stays Unverified.
    for code in [401, 403] {
        let obs = HttpObservation {
            path: "/admin/panel",
            ..default_obs(HttpOutcome::from_status_code(code).unwrap())
        };
        let rep = correlate(Some(cap), Some(obs), 30);
        assert_eq!(rep.comparison, Comparison::Consistent {});
        let auth = rep.auth.unwrap();
        assert_eq!(auth.indicator, ProxyAuthIndicator::Configured);
        assert_eq!(auth.proxy_auth.auth_basic, Some(true));
        assert_eq!(auth.application_auth, ApplicationAuthStatus::Unverified {});
    }

    // 200 on auth_basic=on route without credentials -> Disagrees; unknown -> Gap.
    let unauth_200 = HttpObservation {
        path: "/admin/panel",
        credentials_presented: Some(false),
        ..default_obs(HttpOutcome::Success2xx { status_code: 200 })
    };
    assert_eq!(
        correlate(Some(cap), Some(unauth_200), 30).comparison,
        Comparison::Disagrees {}
    );
    let unknown_cred_200 = HttpObservation {
        path: "/admin/panel",
        credentials_presented: None,
        ..default_obs(HttpOutcome::Success2xx { status_code: 200 })
    };
    assert_eq!(
        correlate(Some(cap), Some(unknown_cred_200), 30).comparison,
        Comparison::Unavailable {
            reason: Gap::ProxyAuthStateUnverified,
        }
    );
    let authed_200 = HttpObservation {
        path: "/admin/panel",
        credentials_presented: Some(true),
        ..default_obs(HttpOutcome::Success2xx { status_code: 200 })
    };
    assert_eq!(
        correlate(Some(cap), Some(authed_200), 30).comparison,
        Comparison::Consistent {}
    );

    // 401/403 without proxy auth on live backend -> UnverifiedApplicationPolicy (not Disagrees, not Safe).
    let app_401 = default_obs(HttpOutcome::AuthRejected { status_code: 401 });
    assert_eq!(
        correlate(Some(cap), Some(app_401), 30).comparison,
        Comparison::Unavailable {
            reason: Gap::UnverifiedApplicationPolicy,
        }
    );

    // 401 without proxy auth when backend listener is absent -> Disagrees.
    let absent_401 = HttpObservation {
        path: "/missing/",
        ..default_obs(HttpOutcome::AuthRejected { status_code: 401 })
    };
    assert_eq!(
        correlate(Some(cap), Some(absent_401), 30).comparison,
        Comparison::Disagrees {}
    );
}

#[test]
fn never_turns_no_response_or_failed_probe_into_firewall_verdict() {
    let snap = snapshot_with(STANDARD_CONF, standard_sockets(), false, BASE_TIME);
    let cap = Capture {
        snapshot: &snap,
        scope: Some(scope("host-a", "test-net")),
    };

    let no_resp = HttpObservation {
        tcp: Some(TcpObservation {
            handshake: Some(&Outcome::NoAnswer),
            inbound_path_verdict: None,
        }),
        ..default_obs(HttpOutcome::NoResponse {})
    };
    let r1 = correlate(Some(cap), Some(no_resp), 30);
    assert_eq!(
        r1.comparison,
        Comparison::Unavailable {
            reason: Gap::NoResponseInconclusive,
        }
    );
    assert_eq!(r1.tcp.state, TcpLayerState::BlockedOrClosed);

    let failed_outcome = Outcome::Failed {
        message: "too many open files".to_owned(),
    };
    let failed_probe = HttpObservation {
        tcp: Some(TcpObservation {
            handshake: Some(&failed_outcome),
            inbound_path_verdict: None,
        }),
        ..default_obs(HttpOutcome::Success2xx { status_code: 200 })
    };
    let r2 = correlate(Some(cap), Some(failed_probe), 30);
    assert_eq!(
        r2.comparison,
        Comparison::Unavailable {
            reason: Gap::TcpProbeFailed,
        }
    );
    assert_eq!(r2.tcp.state, TcpLayerState::ProbeFailed);

    let blocked_contradiction = HttpObservation {
        tcp: Some(TcpObservation {
            handshake: Some(&Outcome::Open),
            inbound_path_verdict: Some(InboundTcpVerdict::Blocked),
        }),
        ..default_obs(HttpOutcome::Success2xx { status_code: 200 })
    };
    assert_eq!(
        correlate(Some(cap), Some(blocked_contradiction), 30).comparison,
        Comparison::Disagrees {}
    );
}

#[test]
fn handles_404_redirects_and_non_local_or_unresolved_backends() {
    let snap = snapshot_with(STANDARD_CONF, standard_sockets(), false, BASE_TIME);
    let cap = Capture {
        snapshot: &snap,
        scope: Some(scope("host-a", "test-net")),
    };

    // Unmatched location with 404 -> Consistent, NoProxyTarget.
    let unmatched_404 = HttpObservation {
        path: "/static/missing.txt",
        ..default_obs(HttpOutcome::NotFound404 {})
    };
    let r_unmatched = correlate(Some(cap), Some(unmatched_404), 30);
    assert_eq!(r_unmatched.comparison, Comparison::Consistent {});
    assert_eq!(r_unmatched.backend, Some(BackendEvidence::NoProxyTarget {}));

    // Matched live backend with 404 -> Consistent; absent backend with 404 -> Disagrees.
    let live_404 = default_obs(HttpOutcome::NotFound404 {});
    assert_eq!(
        correlate(Some(cap), Some(live_404), 30).comparison,
        Comparison::Consistent {}
    );
    let absent_404 = HttpObservation {
        path: "/missing/",
        ..default_obs(HttpOutcome::NotFound404 {})
    };
    assert_eq!(
        correlate(Some(cap), Some(absent_404), 30).comparison,
        Comparison::Disagrees {}
    );

    // 3xx on live backend -> Consistent; on absent backend -> HttpStatusInconclusive (nginx can emit redirects itself).
    let redir = default_obs(HttpOutcome::Redirect3xx { status_code: 302 });
    assert_eq!(
        correlate(Some(cap), Some(redir), 30).comparison,
        Comparison::Consistent {}
    );
    let redir_absent = HttpObservation {
        path: "/missing/",
        ..default_obs(HttpOutcome::Redirect3xx { status_code: 301 })
    };
    assert_eq!(
        correlate(Some(cap), Some(redir_absent), 30).comparison,
        Comparison::Unavailable {
            reason: Gap::HttpStatusInconclusive,
        }
    );

    // Non-loopback remote backend -> BackendUnverified.
    let remote = HttpObservation {
        path: "/remote/item",
        ..default_obs(HttpOutcome::Success2xx { status_code: 200 })
    };
    let r_remote = correlate(Some(cap), Some(remote), 30);
    assert_eq!(r_remote.backend, Some(BackendEvidence::NonLocalOrRemote {}));
    assert_eq!(
        r_remote.comparison,
        Comparison::Unavailable {
            reason: Gap::BackendUnverified,
        }
    );

    // Unresolved DNS hostname emits UnresolvedHost uncertainty -> BackendEvidence::UnresolvedHostname + Gap::ConfigUncertain.
    let host_conf = r#"
http {
    server {
        listen 192.0.2.10:80;
        server_name app.example.test;
        location /host/ {
            proxy_pass http://backend.internal:8080/;
        }
    }
}
"#;
    let host_snap = snapshot_with(host_conf, standard_sockets(), false, BASE_TIME);
    let host_obs = HttpObservation {
        path: "/host/item",
        ..default_obs(HttpOutcome::Success2xx { status_code: 200 })
    };
    let r_host = correlate(
        Some(Capture {
            snapshot: &host_snap,
            scope: Some(scope("host-a", "test-net")),
        }),
        Some(host_obs),
        30,
    );
    assert_eq!(r_host.backend, Some(BackendEvidence::UnresolvedHostname {}));
    assert_eq!(
        r_host.comparison,
        Comparison::Unavailable {
            reason: Gap::ConfigUncertain,
        }
    );

    // Other HTTP status (418/429/500) -> HttpStatusInconclusive regardless of backend presence.
    let other_live = default_obs(HttpOutcome::OtherStatus { status_code: 418 });
    assert_eq!(
        correlate(Some(cap), Some(other_live), 30).comparison,
        Comparison::Unavailable {
            reason: Gap::HttpStatusInconclusive,
        }
    );
    for code in [429, 500] {
        let other_absent = HttpObservation {
            path: "/missing/",
            ..default_obs(HttpOutcome::OtherStatus { status_code: code })
        };
        assert_eq!(
            correlate(Some(cap), Some(other_absent), 30).comparison,
            Comparison::Unavailable {
                reason: Gap::HttpStatusInconclusive,
            }
        );
    }
}

#[test]
fn rejects_scope_time_validation_partial_and_uncertainty_gaps() {
    let snap = snapshot_with(STANDARD_CONF, standard_sockets(), false, BASE_TIME);
    let cap = Capture {
        snapshot: &snap,
        scope: Some(scope("host-a", "test-net")),
    };
    let ok_obs = default_obs(HttpOutcome::Success2xx { status_code: 200 });

    assert_eq!(
        correlate(None, Some(ok_obs), 30).comparison,
        Comparison::Unavailable {
            reason: Gap::CaptureMissing,
        }
    );
    assert_eq!(
        correlate(Some(cap), None, 30).comparison,
        Comparison::Unavailable {
            reason: Gap::ObservationMissing,
        }
    );
    assert_eq!(
        correlate(
            Some(Capture {
                snapshot: &snap,
                scope: None,
            }),
            Some(ok_obs),
            30
        )
        .comparison,
        Comparison::Unavailable {
            reason: Gap::CaptureScopeMissing,
        }
    );
    assert_eq!(
        correlate(
            Some(cap),
            Some(HttpObservation {
                scope: Some(scope("host-b", "test-net")),
                ..ok_obs
            }),
            30
        )
        .comparison,
        Comparison::Unavailable {
            reason: Gap::CollectorMismatch,
        }
    );
    assert_eq!(
        correlate(
            Some(cap),
            Some(HttpObservation {
                scope: Some(scope("host-a", "other-net")),
                ..ok_obs
            }),
            30
        )
        .comparison,
        Comparison::Unavailable {
            reason: Gap::NetworkMismatch,
        }
    );
    assert_eq!(
        correlate(
            Some(cap),
            Some(HttpObservation {
                started_at_unix_seconds: NonZeroU64::new(BASE_TIME - 1),
                ..ok_obs
            }),
            30
        )
        .comparison,
        Comparison::Unavailable {
            reason: Gap::CaptureAfterProbe,
        }
    );
    assert_eq!(
        correlate(
            Some(cap),
            Some(HttpObservation {
                started_at_unix_seconds: NonZeroU64::new(BASE_TIME + 5),
                finished_at_unix_seconds: NonZeroU64::new(BASE_TIME + 4),
                ..ok_obs
            }),
            30
        )
        .comparison,
        Comparison::Unavailable {
            reason: Gap::ProbeTimeReversed,
        }
    );
    assert_eq!(
        correlate(
            Some(cap),
            Some(HttpObservation {
                finished_at_unix_seconds: NonZeroU64::new(BASE_TIME + 31),
                ..ok_obs
            }),
            30
        )
        .comparison,
        Comparison::Unavailable {
            reason: Gap::CaptureStale,
        }
    );
    assert_eq!(
        correlate(
            Some(cap),
            Some(HttpObservation {
                path: "no-leading-slash",
                ..ok_obs
            }),
            30
        )
        .comparison,
        Comparison::Unavailable {
            reason: Gap::InvalidObservation,
        }
    );
    assert_eq!(
        correlate(
            Some(cap),
            Some(HttpObservation {
                tls: false,
                tls_status: TlsStatus::Verified,
                ..ok_obs
            }),
            30
        )
        .comparison,
        Comparison::Unavailable {
            reason: Gap::InvalidObservation,
        }
    );

    // Partial collection (socket options error) -> CollectionPartial.
    let partial_report = collect_with(Ok(STANDARD_CONF.to_owned()), || {
        Ok(Inventory {
            sockets: standard_sockets(),
            options: OptionsReport {
                by_inode: Default::default(),
                error: Some(SocketOptionsError::Open(CollectError::UnsupportedOs {
                    os: "test",
                })),
            },
        })
    })
    .unwrap();
    let partial_snap = Snapshot::new("example-nginx".parse().unwrap(), BASE_TIME, partial_report);
    assert_eq!(
        correlate(
            Some(Capture {
                snapshot: &partial_snap,
                scope: Some(scope("host-a", "test-net")),
            }),
            Some(ok_obs),
            30
        )
        .comparison,
        Comparison::Unavailable {
            reason: Gap::CollectionPartial,
        }
    );

    // Unavailable inventory also triggers CollectionPartial.
    let no_inv_report = collect_with(Ok(STANDARD_CONF.to_owned()), || {
        Err(ScanError::UnsupportedOs { os: "test" })
    })
    .unwrap();
    let no_inv_snap = Snapshot::new("example-nginx".parse().unwrap(), BASE_TIME, no_inv_report);
    assert_eq!(
        correlate(
            Some(Capture {
                snapshot: &no_inv_snap,
                scope: Some(scope("host-a", "test-net")),
            }),
            Some(ok_obs),
            30
        )
        .comparison,
        Comparison::Unavailable {
            reason: Gap::CollectionPartial,
        }
    );

    // Dynamic directive (`if`/`rewrite`) -> ConfigUncertain.
    let dynamic_conf = r#"
http {
    server {
        listen 192.0.2.10:80;
        server_name app.example.test;
        location /dynamic/ {
            if ($arg_mode = bypass) { return 200; }
            proxy_pass http://127.0.0.1:8080/;
        }
    }
}
"#;
    let dyn_snap = snapshot_with(dynamic_conf, standard_sockets(), false, BASE_TIME);
    let dyn_rep = correlate(
        Some(Capture {
            snapshot: &dyn_snap,
            scope: Some(scope("host-a", "test-net")),
        }),
        Some(HttpObservation {
            path: "/dynamic/",
            ..ok_obs
        }),
        30,
    );
    assert_eq!(
        dyn_rep.comparison,
        Comparison::Unavailable {
            reason: Gap::ConfigUncertain,
        }
    );
    assert!(dyn_rep.route.unwrap().uncertainty_count > 0);
}
