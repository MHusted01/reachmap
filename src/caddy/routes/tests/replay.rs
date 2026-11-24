//! Versioned snapshots: pinned shape, identical offline replay, and
//! rejection of invalid or incompatible evidence.

use serde_json::{Value, json};

use super::*;
use crate::host_input_snapshot::render_document;
use crate::snapshot_replay::{self, Report};

const SNAPSHOT: &str = include_str!("../../../../tests/fixtures/caddy/routes/snapshot.json");
const SNAPSHOT_TEXT: &str = include_str!("../../../../tests/fixtures/caddy/routes/snapshot.txt");

fn capture(report: CaddyRouteReport) -> String {
    let snapshot = snapshot::Snapshot::new(
        "example-host".parse().expect("host label"),
        1_700_000_000,
        report,
    );
    render_document(&snapshot).expect("render")
}

fn decode_value(value: &Value) -> Result<snapshot::Snapshot, snapshot::ReplayError> {
    snapshot::decode(&value.to_string())
}

fn fixture() -> Value {
    serde_json::from_str(SNAPSHOT).expect("fixture")
}

/// The fixture without its host name upstream, so it replays as complete.
fn complete_fixture() -> Value {
    let mut value = fixture();
    let proxy = &mut value["evidence"]["config"]["servers"][0]["routes"][1]["handlers"][0];
    proxy["upstreams"].as_array_mut().expect("upstreams").pop();
    proxy["complete"] = json!(true);
    value["evidence"]["config"]["uncertainties"] = json!([]);
    assert!(decode_value(&value).expect("complete").is_complete());
    value
}

#[test]
fn snapshots_hold_only_the_minimized_evidence_and_match_the_pinned_shape() {
    let json = capture(report(LINKED, &linked_sockets()));
    assert_eq!(json, SNAPSHOT);
    for secret in [
        "hash-value",
        "admin",
        "0.0.0.0:22",
        "/etc/caddy",
        "accounts",
    ] {
        assert!(!json.contains(secret), "{secret} leaked into the snapshot");
    }
}

#[test]
fn replay_matches_the_live_report() {
    let live = report(LINKED, &linked_sockets());
    let expected = live.to_string();
    let replayed = snapshot::decode(&capture(live)).expect("decode");
    assert_eq!(replayed.to_string(), SNAPSHOT_TEXT);
    assert_eq!(SNAPSHOT_TEXT.split_once('\n').expect("header").1, expected);
    assert!(!replayed.is_complete());
    assert_eq!(replayed.host_ref(), "example-host");
    assert_eq!(replayed.captured_at_unix_seconds(), 1_700_000_000);
    assert_eq!(replayed.evidence().source(), SourceKind::Json);
}

#[test]
fn partial_and_empty_reports_round_trip() {
    let unavailable = collect_with(json_source(LINKED), || {
        Err(ScanError::UnsupportedOs { os: "plan9" })
    })
    .expect("report");
    let empty = collect_with(json_source("{}"), || panic!("not read")).expect("report");
    for report in [unavailable, empty] {
        let expected = report.to_string();
        let complete = report.is_complete();
        let replayed = snapshot::decode(&capture(report)).expect("decode");
        assert_eq!(replayed.evidence().to_string(), expected);
        assert_eq!(replayed.is_complete(), complete);
    }
}

#[test]
fn replay_dispatches_on_the_saved_scope() {
    let dir = crate::collect::test_support::TempDir::new("caddy-routes-replay");
    let path = dir.file("caddy.json", SNAPSHOT);
    let Report::CaddyRoutes(replayed) = snapshot_replay::replay(&path).expect("replay") else {
        panic!("expected Caddy route evidence");
    };
    assert_eq!(replayed.to_string(), SNAPSHOT_TEXT);
}

#[test]
fn rejects_other_versions_and_malformed_documents() {
    let mut newer = fixture();
    newer["snapshot_version"] = json!(2);
    let error = decode_value(&newer).expect_err("version");
    assert!(matches!(error, snapshot::ReplayError::Version(2)));
    assert!(error.to_string().contains("reads version 1"));

    assert!(snapshot::decode("{}").is_err());
    let mut broken = fixture();
    broken["evidence"]["config"]["servers"] = json!("none");
    assert!(decode_value(&broken).is_err());
    let mut label = fixture();
    label["host_ref"] = json!("bad\nlabel");
    assert!(decode_value(&label).is_err());
}

fn assert_invalid(edit: impl FnOnce(&mut Value)) {
    let mut value = fixture();
    edit(&mut value);
    let error = decode_value(&value).expect_err("invalid evidence");
    assert!(
        matches!(error, snapshot::ReplayError::Invalid(_)),
        "{error:?}"
    );
}

#[test]
fn rejects_evidence_that_breaks_the_report_rules() {
    assert_invalid(|value| {
        value["evidence"]["inventory"]["listeners"]
            .as_array_mut()
            .expect("listeners")
            .push(json!({"address": "0.0.0.0:22", "options": null}));
    });
    assert_invalid(|value| {
        value["evidence"]["collection"] = json!({"status": "partial", "notes": []});
    });
    assert_invalid(|value| {
        value["evidence"]["collection"] =
            json!({"status": "partial", "notes": [{"kind": "environment_placeholders"}]});
    });
    assert_invalid(|value| {
        value["evidence"]["collection"] = json!({"status": "partial", "notes": [
            {"kind": "port_range_not_linked", "first": 9000, "last": 9001}
        ]});
    });
    assert_invalid(|value| {
        value["evidence"]["collection"] = json!({"status": "partial", "notes": [
            {"kind": "socket_inventory_unavailable", "reason": "permission_denied"}
        ]});
    });
    assert_invalid(|value| value["evidence"]["inventory"] = json!({"status": "not_needed"}));
    assert_invalid(|value| value["evidence"]["inventory"] = json!({"status": "unavailable"}));
    assert_invalid(|value| value["evidence"]["config"]["http_port"] = json!(0));
    assert_invalid(|value| {
        value["evidence"]["inventory"] = json!({"status": "unavailable"});
        value["evidence"]["collection"] =
            json!({"status": "partial", "notes": [{"kind": "environment_placeholders"}]});
        value["evidence"]["source"] = json!("caddyfile");
    });
    assert_invalid(|value| {
        value["evidence"]["config"]["servers"][0]["listen"][3]["ports"] =
            json!({"first": 9000, "last": 9100});
    });
    assert_invalid(|value| {
        value["evidence"]["config"]["servers"][0]["routes"][1]["handlers"][0]["upstreams"][0] =
            json!({"kind": "localhost", "port": 0});
    });
}

#[test]
fn a_wide_range_replays_only_with_its_note() {
    let mut value = fixture();
    value["evidence"]["config"]["servers"][0]["listen"][3]["ports"] =
        json!({"first": 9000, "last": 9100});
    value["evidence"]["inventory"]["listeners"]
        .as_array_mut()
        .expect("listeners")
        .retain(|listener| listener["address"] != "127.0.0.1:9000");
    value["evidence"]["collection"] = json!({"status": "partial", "notes": [
        {"kind": "port_range_not_linked", "first": 9000, "last": 9100}
    ]});
    let replayed = decode_value(&value).expect("valid");
    assert!(!replayed.is_complete());
}

#[test]
fn caddyfile_note_tags_are_pinned_and_replay_as_partial() {
    for (kind, text) in [
        (
            "environment_placeholders",
            "{$VAR} environment placeholders",
        ),
        (
            "file_imports_not_checked",
            "imports other files, which were not checked",
        ),
    ] {
        let mut value = complete_fixture();
        value["evidence"]["source"] = json!("caddyfile");
        value["evidence"]["collection"] = json!({"status": "partial", "notes": [{"kind": kind}]});
        let replayed = decode_value(&value).expect(kind);
        assert!(!replayed.is_complete());
        assert!(replayed.to_string().contains(text), "{kind}");
    }
}

#[test]
fn unknown_tcp_state_replays_only_with_its_uncertainty() {
    let mut value = complete_fixture();
    value["evidence"]["config"]["servers"][0]["tcp_known"] = json!(false);
    value["evidence"]["inventory"] = json!({"status": "collected", "listeners": [
        {"address": "127.0.0.1:3000", "options": {"bound_to_device": false, "ipv6_only": false}},
        {"address": "[::1]:3001", "options": {"bound_to_device": false, "ipv6_only": true}}
    ]});
    let error = decode_value(&value).expect_err("missing uncertainty");
    assert!(
        matches!(error, snapshot::ReplayError::Invalid(_)),
        "{error:?}"
    );

    value["evidence"]["config"]["uncertainties"] = json!([{
        "kind": "unmodeled_server_feature",
        "construct": "protocols",
        "location": "apps.http.servers[\"public\"].protocols"
    }]);
    let replayed = decode_value(&value).expect("valid");
    assert!(!replayed.is_complete());
    assert!(
        replayed
            .to_string()
            .contains("not linked: the protocols leave its TCP listener unknown")
    );
}

#[test]
fn an_environment_note_is_valid_for_a_caddyfile_source() {
    let mut value = fixture();
    value["evidence"]["source"] = json!("caddyfile");
    value["evidence"]["collection"] =
        json!({"status": "partial", "notes": [{"kind": "environment_placeholders"}]});
    let replayed = decode_value(&value).expect("valid");
    assert!(
        replayed
            .to_string()
            .contains("{$VAR} environment placeholders")
    );
}

#[test]
fn replayed_strings_are_sanitized() {
    let mut value = fixture();
    value["evidence"]["config"]["servers"][0]["name"] = json!("evil\u{1b}[2J");
    let text = decode_value(&value).expect("valid").to_string();
    assert!(text.contains("Server evil\\u{1b}[2J"), "{text}");
}
