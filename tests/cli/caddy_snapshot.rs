use std::process::Output;

use serde_json::{Value, json};

use super::{run, scan_file, stderr, stdout};

const SNAPSHOT: &str = include_str!("../fixtures/caddy/routes/snapshot.json");

fn snapshot() -> Value {
    serde_json::from_str(SNAPSHOT).unwrap()
}

/// The fixture without its host name upstream, so nothing is uncertain.
fn complete_snapshot() -> Value {
    let mut complete = snapshot();
    let route = &mut complete["evidence"]["config"]["servers"][0]["routes"][1];
    route["handlers"][0]["upstreams"]
        .as_array_mut()
        .unwrap()
        .pop();
    route["handlers"][0]["complete"] = json!(true);
    complete["evidence"]["config"]["uncertainties"] = json!([]);
    complete
}

fn replay(name: &str, snapshot: &Value, flags: &[&str]) -> Output {
    let path = scan_file(name, &snapshot.to_string());
    let args = [&["replay", path.to_str().unwrap()][..], flags].concat();
    run(&args)
}

#[test]
fn replays_captured_caddy_routes_with_frontend_upstream_and_auth_apart() {
    let out = replay("caddy_complete.json", &complete_snapshot(), &[]);
    assert!(out.status.success(), "{}", stderr(&out));
    let text = stdout(&out);
    for line in [
        "Captured Caddy route evidence for example-host at Unix time 1700000000",
        "native JSON config file on disk and local TCP sockets only",
        "  listen: :443 (TCP listener [::]:443)",
        "      upstream 127.0.0.1:3000 (TCP listener 127.0.0.1:3000)",
        "      proxy auth: TLS client certificate required and verified (some requests only), http_basic; application auth: unverified",
    ] {
        assert!(text.contains(line), "missing {line:?} in:\n{text}");
    }
}

#[test]
fn uncertain_or_partial_replays_exit_1() {
    let out = replay("caddy_uncertain.json", &snapshot(), &[]);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(stdout(&out).contains("Configuration uncertainties:"));

    let mut partial = complete_snapshot();
    partial["evidence"]["inventory"] = json!({"status": "unavailable"});
    partial["evidence"]["collection"] = json!({
        "status": "partial",
        "notes": [{"kind": "socket_inventory_unavailable", "reason": "permission_denied"}]
    });
    let out = replay("caddy_partial.json", &partial, &[]);
    assert_eq!(out.status.code(), Some(1));
    let text = stdout(&out);
    assert!(
        text.contains("(TCP socket inventory unavailable)"),
        "{text}"
    );
    assert!(text.contains("Partial Caddy route collection:"), "{text}");
}

#[test]
fn replay_rejects_other_versions_inconsistent_evidence_and_the_json_flag() {
    let future = json!({"scope": "caddy_routes", "snapshot_version": 2});
    let out = replay("caddy_future.json", &future, &[]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("Caddy route snapshot version 2"));

    let mut stray = snapshot();
    stray["evidence"]["inventory"]["listeners"]
        .as_array_mut()
        .unwrap()
        .push(json!({"address": "0.0.0.0:22", "options": null}));
    let out = replay("caddy_stray.json", &stray, &[]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains("unexpected TCP listener"),
        "{}",
        stderr(&out)
    );
    assert!(stdout(&out).is_empty());

    let out = replay("caddy_json_flag.json", &snapshot(), &["--json"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("--json is only supported"));
}
