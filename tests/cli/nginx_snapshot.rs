use std::process::Output;

use serde_json::{Value, json};

use super::{run, scan_file, stderr, stdout};

fn snapshot() -> Value {
    json!({
        "snapshot_version": 1,
        "host_ref": "example-host",
        "captured_at_unix_seconds": 1_700_000_000_u64,
        "scope": "nginx_routes",
        "evidence": {
            "config": {
                "servers": [{
                    "source_file": "/etc/nginx/sites-enabled/app.conf",
                    "listens": [{
                        "address": {"kind": "any_ipv4"},
                        "port": 443,
                        "ssl": true,
                        "default_server": false,
                        "ipv6only": null
                    }],
                    "server_names": [{"kind": "exact", "host": "app.example.test"}],
                    "locations": [{
                        "source_file": "/etc/nginx/sites-enabled/app.conf",
                        "modifier": "prefix",
                        "path": "/api",
                        "target": {
                            "kind": "static_http",
                            "scheme": "http",
                            "endpoint": "http://127.0.0.1:8080/v1",
                            "targets": ["127.0.0.1:8080"]
                        },
                        "auth": {
                            "auth_basic": true,
                            "auth_request": false,
                            "ssl_verify_client": "on",
                            "access_control": false
                        }
                    }],
                    "auth": {
                        "auth_basic": null,
                        "auth_request": false,
                        "ssl_verify_client": "on",
                        "access_control": false
                    }
                }],
                "upstreams": [],
                "uncertainties": []
            },
            "collection": {"status": "complete"},
            "inventory": {
                "status": "collected",
                "listeners": [
                    {
                        "address": "0.0.0.0:443",
                        "options": {"bound_to_device": false, "ipv6_only": false}
                    },
                    {
                        "address": "127.0.0.1:8080",
                        "options": {"bound_to_device": false, "ipv6_only": false}
                    }
                ]
            }
        }
    })
}

fn replay(name: &str, snapshot: &Value, flags: &[&str]) -> Output {
    let path = scan_file(name, &snapshot.to_string());
    let args = [&["replay", path.to_str().unwrap()][..], flags].concat();
    run(&args)
}

#[test]
fn replays_captured_nginx_routes_and_separates_frontend_backend_and_auth() {
    let out = replay("nginx_matched.json", &snapshot(), &[]);
    assert!(out.status.success(), "{}", stderr(&out));
    let text = stdout(&out);
    assert!(
        text.contains("example-host") && text.contains("1700000000"),
        "{text}"
    );
    assert!(
        text.contains("on-disk config files and local TCP sockets only"),
        "{text}"
    );
    assert!(
        text.contains("listen: 0.0.0.0:443 [ssl] (TCP listener 0.0.0.0:443)"),
        "{text}"
    );
    assert!(
        text.contains("target: http://127.0.0.1:8080/v1 (TCP listener 127.0.0.1:8080)"),
        "{text}"
    );
    assert!(
        text.contains(
            "proxy auth: auth_basic=on, ssl_verify_client=on; application auth: unverified"
        ),
        "{text}"
    );
}

#[test]
fn replay_preserves_missing_inventory_and_uncertainties_with_exit_1() {
    let mut partial = snapshot();
    partial["evidence"]["inventory"] = json!({"status": "unavailable"});
    partial["evidence"]["collection"] = json!({
        "status": "partial",
        "notes": [{"kind": "socket_inventory_unavailable", "reason": "permission_denied"}]
    });
    let out = replay("nginx_partial.json", &partial, &[]);
    assert_eq!(out.status.code(), Some(1));
    let text = stdout(&out);
    assert!(
        text.contains("(TCP socket inventory unavailable)"),
        "{text}"
    );
    assert!(text.contains("Partial Nginx route collection:"), "{text}");
    assert!(text.contains("permission denied"), "{text}");

    let mut uncertain = snapshot();
    uncertain["evidence"]["config"]["uncertainties"] = json!([{
        "kind": "dynamic_control_flow",
        "directive": "if",
        "source_file": "/etc/nginx/sites-enabled/app.conf",
        "line": 12
    }]);
    let out = replay("nginx_uncertain.json", &uncertain, &[]);
    assert_eq!(out.status.code(), Some(1));
    let text = stdout(&out);
    assert!(text.contains("Configuration uncertainties:"), "{text}");
    assert!(
        text.contains("dynamic control flow (`if`) at /etc/nginx/sites-enabled/app.conf:12"),
        "{text}"
    );
}

#[test]
fn replay_rejects_invalid_version_and_inconsistent_nginx_evidence() {
    let future = json!({"scope": "nginx_routes", "snapshot_version": 2});
    let out = replay("nginx_future.json", &future, &[]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("Nginx route snapshot version 2"));

    for (pointer, value, reason) in [
        (
            "/config/servers/0/listens/0/port",
            json!(0),
            "expected a nonzero listen port",
        ),
        (
            "/config/servers/0/locations/0/target/targets",
            json!(["127.0.0.1:0"]),
            "expected a nonzero backend target port",
        ),
        (
            "/inventory",
            json!({"status": "not_needed"}),
            "inconsistent Nginx route collection status",
        ),
        (
            "/inventory",
            json!({"status": "unavailable"}),
            "inconsistent Nginx route collection status",
        ),
        (
            "/collection",
            json!({"status": "partial", "notes": []}),
            "inconsistent Nginx route collection status",
        ),
        (
            "/inventory/listeners/0/address",
            json!("192.0.2.55:9999"),
            "unexpected TCP listener",
        ),
        (
            "/inventory/listeners/0/address",
            json!("not-a-socket"),
            "expected capture metadata and route evidence",
        ),
    ] {
        let mut invalid = snapshot();
        *invalid["evidence"].pointer_mut(pointer).unwrap() = value;
        let out = replay("nginx_invalid.json", &invalid, &[]);
        assert_eq!(out.status.code(), Some(1), "{pointer}");
        assert!(stderr(&out).contains(reason), "{pointer}: {}", stderr(&out));
        assert!(stdout(&out).is_empty(), "{pointer}");
    }
}

#[test]
fn replay_escapes_untrusted_text_and_rejects_json_flag() {
    let mut dirty = snapshot();
    dirty["evidence"]["config"]["servers"][0]["locations"][0]["path"] = json!("/api\n\u{1b}[2J");
    let out = replay("nginx_control_text.json", &dirty, &[]);
    assert!(out.status.success(), "{}", stderr(&out));
    let text = stdout(&out);
    assert!(text.contains(r"/api\n\u{1b}[2J"), "{text}");
    assert!(!text.contains('\u{1b}'));

    let out = replay("nginx_json_flag.json", &snapshot(), &["--json"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("--json"));
}
