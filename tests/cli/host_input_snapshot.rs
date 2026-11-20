use serde_json::{Value, json};

use super::{run, scan_file, stderr, stdout};

const RULES: &str = include_str!("../fixtures/nftables_input.json");

fn snapshot() -> Value {
    json!({
        "snapshot_version": 1,
        "host_ref": "example-host",
        "captured_at_unix_seconds": 1_700_000_000_u64,
        "scope": "linux_host_input",
        "collectors": {
            "socket_tables": "collected",
            "interfaces": {"status": "collected", "data": [
                {"port": 8443, "protocol": "tcp", "address": "0.0.0.0", "family": "ipv4", "interfaces": ["eth0"]},
                {"port": 8443, "protocol": "tcp", "address": "::1", "family": "ipv6", "interfaces": ["lo"]}
            ]},
            "socket_options": "collected",
            "docker": "unavailable",
            "nftables": {"status": "collected", "data": RULES}
        }
    })
}

fn replay(name: &str, value: &Value) -> std::process::Output {
    let path = scan_file(name, &value.to_string());
    run(&["replay", path.to_str().unwrap(), "--json"])
}

#[test]
fn replay_reports_ipv4_and_ipv6_verdicts_and_reasons() {
    let out = replay("host_input_dual_stack.json", &snapshot());
    assert!(out.status.success(), "{}", stderr(&out));
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["status"], "checked");
    assert_eq!(report["ports"][0]["family"], "ipv4");
    assert_eq!(
        report["ports"][0]["interfaces"][0],
        json!({
            "interface": "eth0", "verdict": "accept", "reason": "matching rule"
        })
    );
    assert_eq!(report["ports"][1]["family"], "ipv6");
    assert_eq!(
        report["ports"][1]["interfaces"][0],
        json!({
            "interface": "lo", "verdict": "drop", "reason": "matching rule in inet sample inbound"
        })
    );
}

#[test]
fn replay_distinguishes_empty_rules_from_failed_and_unavailable_collection() {
    for (file, evidence, reason) in [
        (
            "empty",
            json!({"status": "collected", "data": "{\"nftables\":[]}"}),
            "no applicable input chain",
        ),
        (
            "failed",
            json!({"status": "failed", "reason": "permission denied"}),
            "permission denied",
        ),
        (
            "unavailable",
            json!({"status": "unavailable", "reason": "nft missing"}),
            "nft missing",
        ),
    ] {
        let mut value = snapshot();
        value["collectors"]["nftables"] = evidence;
        let out = replay(&format!("host_input_{file}.json"), &value);
        assert!(out.status.success(), "{}", stderr(&out));
        let report: Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(report, json!({"status": "unknown", "reason": reason}));
    }
}

#[test]
fn replay_checks_the_version_before_decoding_the_rest() {
    let out = replay("host_input_future.json", &json!({"snapshot_version": 2}));
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains("snapshot version 2"),
        "{}",
        stderr(&out)
    );
    assert!(stdout(&out).is_empty());
}

#[test]
fn replay_rejects_invalid_rules_in_a_successful_collection() {
    let mut value = snapshot();
    value["collectors"]["nftables"]["data"] = json!("not an nftables ruleset");
    let out = replay("host_input_invalid_rules.json", &value);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains("nftables ruleset"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn replay_escapes_artifact_text_in_unknown_reasons() {
    let mut value = snapshot();
    value["collectors"]["nftables"] = json!({"status": "failed", "reason": "bad\n\u{202e}text"});
    let path = scan_file("host_input_unsafe_text.json", &value.to_string());
    let out = run(&["replay", path.to_str().unwrap()]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(
        stdout(&out),
        "nftables input: unknown (bad\\n\\u{202e}text)\n"
    );
}

#[test]
fn replay_rejects_files_over_the_size_limit() {
    let path = scan_file("host_input_oversize.json", "{}");
    std::fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .unwrap()
        .set_len(64 * 1024 * 1024 + 1)
        .unwrap();
    let out = run(&["replay", path.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("64 MiB"), "{}", stderr(&out));
}

#[test]
fn replay_rejects_a_directory() {
    let out = run(&["replay", "tests/fixtures"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("regular file"), "{}", stderr(&out));
}

#[test]
fn collected_interface_evidence_requires_data_even_when_empty() {
    let mut value = snapshot();
    value["collectors"]["interfaces"] = json!({"status": "collected"});
    let out = replay("host_input_no_interface_data.json", &value);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains("missing field `data`"),
        "{}",
        stderr(&out)
    );

    value["collectors"]["interfaces"]["data"] = Value::Null;
    let out = replay("host_input_no_addresses.json", &value);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(
        serde_json::from_slice::<Value>(&out.stdout).unwrap(),
        json!({
            "status": "unknown", "reason": "no interface addresses available"
        })
    );

    value["collectors"]["interfaces"]["data"] = json!([]);
    let out = replay("host_input_no_targets.json", &value);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(
        serde_json::from_slice::<Value>(&out.stdout).unwrap(),
        json!({
            "status": "checked", "ports": []
        })
    );
}

#[cfg(target_os = "linux")]
#[test]
fn linux_scan_exports_a_replayable_snapshot_when_requested() {
    let out = run(&["scan", "--snapshot", "--host-ref", "example-host"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let value: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(value["snapshot_version"], 1);
    assert_eq!(value["host_ref"], "example-host");
    assert!(value["captured_at_unix_seconds"].as_u64().unwrap() > 0);
    assert_eq!(value["scope"], "linux_host_input");
    assert_eq!(value["collectors"]["socket_tables"], "collected");
    let out = replay("host_input_live_capture.json", &value);
    assert!(out.status.success(), "{}", stderr(&out));
}

#[test]
fn snapshot_output_requires_an_explicit_host_label() {
    let out = run(&["scan", "--snapshot"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("--host-ref"), "{}", stderr(&out));
}

#[cfg(not(target_os = "linux"))]
#[test]
fn snapshot_capture_names_its_platform_requirement() {
    let out = run(&["scan", "--snapshot", "--host-ref", "example-host"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains("snapshot on Linux"),
        "{}",
        stderr(&out)
    );
    assert!(out.stdout.is_empty());
}

#[test]
fn scan_v1_reports_still_work_at_both_cli_entry_points() {
    let report = "tests/fixtures/diff_baseline.json";
    let diff = run(&["diff", report, report]);
    assert!(diff.status.success(), "{}", stderr(&diff));
    assert_eq!(stdout(&diff), "No differences.\n");

    let (port, _listener) = super::open_port();
    let mut scan: Value =
        serde_json::from_str(include_str!("../fixtures/scan_report.json")).unwrap();
    let mut row = scan["ports"][1].clone();
    row["port"] = json!(port);
    row["address"] = json!("127.0.0.1");
    scan["ports"] = json!([row]);
    let path = scan_file("host_input_v1_compatibility.json", &scan.to_string());
    let probe = run(&["probe", "127.0.0.1", "--scan", path.to_str().unwrap()]);
    assert!(probe.status.success(), "{}", stderr(&probe));
    assert!(
        stdout(&probe).contains("no differences"),
        "{}",
        stdout(&probe)
    );
}
