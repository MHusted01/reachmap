use std::process::Output;

use serde_json::{Value, json};

use super::{run, scan_file, stderr, stdout};

fn snapshot() -> Value {
    json!({
        "snapshot_version": 1,
        "host_ref": "example-host",
        "captured_at_unix_seconds": 1_700_000_000_u64,
        "scope": "tailscale_routes",
        "evidence": {
            "routes": [{
                "entry": {"host": "node.example.ts.net", "port": 443, "sharing": "funnel"},
                "mount": "/",
                "backend": {"kind": "http_proxy", "endpoint": "3000", "targets": ["127.0.0.1:3000"]}
            }],
            "unsupported_services": false,
            "collection": {"status": "complete"},
            "inventory": {"status": "collected", "listeners": [{
                "address": "127.0.0.1:3000", "options": {"bound_to_device": false, "ipv6_only": false}
            }]}
        }
    })
}

fn replay(name: &str, snapshot: &Value, flags: &[&str]) -> Output {
    let path = scan_file(name, &snapshot.to_string());
    let args = [&["replay", path.to_str().unwrap()][..], flags].concat();
    run(&args)
}

#[test]
fn replays_captured_routes_and_identifies_the_capture() {
    let out = replay("tailscale_matched.json", &snapshot(), &[]);
    assert!(out.status.success(), "{}", stderr(&out));
    let text = stdout(&out);
    assert!(
        text.contains("example-host") && text.contains("1700000000"),
        "{text}"
    );
    assert!(
        text.contains("node.example.ts.net:443 / [Funnel] -> 3000 (TCP listener 127.0.0.1:3000)"),
        "{text}"
    );
}

#[test]
fn replay_preserves_missing_inventory_as_partial() {
    let mut snapshot = snapshot();
    snapshot["evidence"]["inventory"] = json!({"status": "unavailable"});
    snapshot["evidence"]["collection"] = json!({
        "status": "partial",
        "notes": [{"kind": "socket_inventory_unavailable", "reason": "permission_denied"}]
    });
    let out = replay("tailscale_partial.json", &snapshot, &[]);
    assert_eq!(out.status.code(), Some(1));
    let text = stdout(&out);
    assert!(
        text.contains("(TCP socket inventory unavailable)"),
        "{text}"
    );
    assert!(
        text.contains("Partial Tailscale route collection"),
        "{text}"
    );
    assert!(text.contains("permission denied"), "{text}");
}

#[test]
fn replay_rejects_a_future_version_and_invalid_evidence() {
    let future = json!({"scope": "tailscale_routes", "snapshot_version": 2});
    let out = replay("tailscale_future.json", &future, &[]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("Tailscale route snapshot version 2"));

    for (field, value, reason) in [
        (
            "/routes/0/backend/targets",
            json!(["192.0.2.1:3000"]),
            "expected a loopback TCP target",
        ),
        (
            "/routes/0/backend/targets",
            json!(["127.0.0.1:0"]),
            "expected a loopback TCP target",
        ),
        (
            "/routes/0/entry/port",
            json!(0),
            "expected a nonzero route port",
        ),
        (
            "/inventory",
            json!({"status": "not_needed"}),
            "inconsistent route collection status",
        ),
        (
            "/inventory",
            json!({"status": "unavailable"}),
            "inconsistent route collection status",
        ),
        ("/routes", json!([]), "inconsistent route collection status"),
        (
            "/collection",
            json!({"status": "partial", "notes": []}),
            "inconsistent route collection status",
        ),
        (
            "/inventory/listeners/0/address",
            json!("127.0.0.1:0"),
            "unexpected TCP listener",
        ),
        (
            "/inventory/listeners/0/address",
            json!("192.0.2.1:3000"),
            "unexpected TCP listener",
        ),
        (
            "/inventory/listeners/0/address",
            json!("not an address"),
            "expected capture metadata and route evidence",
        ),
    ] {
        let mut invalid = snapshot();
        *invalid["evidence"].pointer_mut(field).unwrap() = value;
        let out = replay("tailscale_invalid.json", &invalid, &[]);
        assert_eq!(out.status.code(), Some(1), "{field}");
        assert!(stderr(&out).contains(reason), "{field}: {}", stderr(&out));
        assert!(stdout(&out).is_empty(), "{field}");
    }
}

#[test]
fn replay_escapes_untrusted_report_text() {
    let mut snapshot = snapshot();
    snapshot["evidence"]["routes"][0]["mount"] = json!("/\n\u{1b}[2J");
    let out = replay("tailscale_control_text.json", &snapshot, &[]);
    assert!(out.status.success(), "{}", stderr(&out));
    let text = stdout(&out);
    assert!(text.contains(r"/\n\u{1b}[2J"), "{text}");
    assert!(!text.contains('\u{1b}'));
}

#[test]
fn tailscale_route_replay_uses_the_text_report() {
    let out = replay("tailscale_json_flag.json", &snapshot(), &["--json"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("--json"));
}
