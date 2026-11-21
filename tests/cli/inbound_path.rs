use serde_json::{Value, json};

use super::{run, scan_file, stderr};

fn collected(data: impl Into<Value>) -> Value {
    json!({"status": "collected", "data": data.into()})
}

fn snapshot() -> Value {
    json!({
        "snapshot_version": 1,
        "scope": "linux_inbound_tcp",
        "host_ref": "example-host",
        "captured_at_unix_seconds": 1_700_000_000_u64,
        "flow": {
            "source": "192.0.2.2",
            "ingress": "eth0",
            "destination": "192.0.2.1",
            "port": 8443
        },
        "evidence": {
            "link": collected(r#"[{"ifname":"eth0","ifindex":2,"link_type":"ether"}]"#),
            "legacy_tables": collected(""),
            "xfrm_policies": collected(""),
            "xfrm_defaults": collected("Default policies:\n in:  accept\n fwd: accept\n out: accept\n"),
            "nftables": collected(r#"{"nftables":[]}"#),
            "routing_rules": collected(r#"[{"priority":0,"src":"all","table":"local"},
                {"priority":32766,"src":"all","table":"main"},
                {"priority":32767,"src":"all","table":"default"}]"#),
            "route": collected(r#"[{"type":"local","dst":"192.0.2.1","from":"192.0.2.2","iif":"eth0","dev":"lo"}]"#),
            "listeners": collected(json!([
                {"address": "::", "inode": 42,
                 "options": {"bound_device": 2, "ipv6_only": false}}
            ]))
        }
    })
}

fn replay(name: &str, snapshot: &Value) -> Value {
    let path = scan_file(name, &snapshot.to_string());
    let out = run(&["path", "replay", path.to_str().unwrap(), "--json"]);
    assert!(out.status.success(), "{}", stderr(&out));
    serde_json::from_slice(&out.stdout).unwrap()
}

#[test]
fn replay_shows_ordered_evidence_for_a_dual_stack_listener() {
    let report = replay("inbound_path_local.json", &snapshot());
    assert_eq!(report["verdict"], "listener_reachable");
    assert_eq!(report["steps"][0]["stage"], "ingress");
    assert_eq!(report["steps"][1]["stage"], "routing");
    assert_eq!(report["steps"][2]["stage"], "input");
    assert_eq!(report["steps"][3]["stage"], "socket");
    assert_eq!(report["steps"][3]["listeners"][0]["inode"], 42);
}

#[test]
fn replay_stops_where_the_evidence_becomes_unknown() {
    let mut value = snapshot();
    value["evidence"]["routing_rules"] = json!({
        "status": "failed", "reason": "route policy unavailable\n"
    });
    let report = replay("inbound_path_unknown.json", &value);
    assert_eq!(report["verdict"], "unknown");
    assert_eq!(report["steps"].as_array().unwrap().len(), 2);
    assert_eq!(report["steps"][1]["stage"], "routing");
    assert_eq!(report["steps"][1]["reason"], r"route policy unavailable\n");
}

#[test]
fn older_scan_snapshots_require_a_flow_capture() {
    let file = scan_file(
        "inbound_path_wrong_scope.json",
        r#"{"snapshot_version":1,"scope":"linux_host_input"}"#,
    );
    let out = run(&["path", "replay", file.to_str().unwrap()]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("path capture"));
}

#[test]
fn replay_does_not_treat_a_nonlocal_route_as_a_firewall_block() {
    let mut value = snapshot();
    value["evidence"]["route"] =
        collected(r#"[{"dst":"192.0.2.1","from":"192.0.2.2","iif":"eth0","dev":"eth1"}]"#);
    let report = replay("inbound_path_not_local.json", &value);
    assert_eq!(report["verdict"], "not_local");
    assert_eq!(report["steps"].as_array().unwrap().len(), 2);
    assert_eq!(report["steps"][1]["decision"], "ends");
}

#[test]
fn replay_distinguishes_incompatible_listeners_from_missing_socket_options() {
    let mut value = snapshot();
    let listeners = &mut value["evidence"]["listeners"]["data"];
    listeners[0]["options"]["ipv6_only"] = json!(true);
    listeners.as_array_mut().unwrap().push(json!({
        "address": "0.0.0.0", "inode": 45,
        "options": {"bound_device": 3, "ipv6_only": false}
    }));
    let report = replay("inbound_path_no_match.json", &value);
    assert_eq!(report["verdict"], "no_listener");
    assert_eq!(report["steps"][3]["stage"], "socket");

    value["evidence"]["listeners"]["data"][0]["options"] = Value::Null;
    let report = replay("inbound_path_missing_options.json", &value);
    assert_eq!(report["verdict"], "unknown");
    assert_eq!(report["steps"][3]["listeners"][0]["inode"], 42);
}

#[test]
fn replay_checks_netfilter_early_hook_family_and_device() {
    let mut value = snapshot();
    value["evidence"]["nftables"] = collected(
        r#"{"nftables":[
        {"table":{"family":"ip6","name":"v6only"}},
        {"chain":{"family":"ip6","table":"v6only","name":"pre","hook":"prerouting"}},
        {"table":{"family":"inet","name":"sleeping","flags":["dormant"]}},
        {"chain":{"family":"inet","table":"sleeping","name":"pre","hook":"prerouting"}},
        {"table":{"family":"netdev","name":"l2"}},
        {"chain":{"family":"netdev","table":"l2","name":"arriving","hook":"ingress","dev":"eth1"}}
    ]}"#,
    );
    let report = replay("inbound_path_inactive_hooks.json", &value);
    assert_eq!(report["verdict"], "listener_reachable");

    let data = value["evidence"]["nftables"]["data"].as_str().unwrap();
    value["evidence"]["nftables"] = collected(data.replace("eth1", "eth0"));
    let report = replay("inbound_path_ingress_hook.json", &value);
    assert_eq!(report["verdict"], "unknown");
    assert_eq!(report["steps"][0]["stage"], "ingress");
    assert_eq!(
        report["steps"][0]["reason"],
        "unsupported nftables ingress hook in netdev l2 arriving"
    );
}

#[test]
fn replay_rejects_evidence_from_a_different_ingress_and_unknown_route_policy() {
    let mut value = snapshot();
    let route = value["evidence"]["route"]["data"]
        .as_str()
        .unwrap()
        .to_owned();
    value["evidence"]["route"] = collected(route.replace("eth0", "eth1"));
    let report = replay("inbound_path_wrong_ingress.json", &value);
    assert_eq!(report["verdict"], "unknown");
    assert_eq!(report["steps"][1]["stage"], "routing");
    assert_eq!(
        report["steps"][1]["reason"],
        "kernel route evidence does not match the stated flow"
    );

    value["evidence"]["route"] = collected(route);
    let rules = value["evidence"]["routing_rules"]["data"].as_str().unwrap();
    value["evidence"]["routing_rules"] =
        collected(rules.replace(r#""table":"main""#, r#""table":"main","sport":"100-200""#));
    let report = replay("inbound_path_policy.json", &value);
    assert_eq!(report["verdict"], "unknown");
    assert_eq!(report["steps"][1]["stage"], "routing");
    assert_eq!(
        report["steps"][1]["reason"],
        "unsupported routing policy rules"
    );
}

#[test]
fn a_nonaccepting_xfrm_default_is_unknown_even_without_listed_policies() {
    let mut value = snapshot();
    value["evidence"]["xfrm_defaults"] = collected("Default policies:\n in: block\n");
    let report = replay("inbound_path_xfrm_default.json", &value);
    assert_eq!(report["verdict"], "unknown");
    assert_eq!(report["steps"][0]["stage"], "ingress");
    assert_eq!(
        report["steps"][0]["reason"],
        "could not establish an accepting inbound XFRM default"
    );
}

#[test]
fn replay_needs_evidence_that_the_ipv6_ingress_is_enabled() {
    let mut value = snapshot();
    value["flow"]["source"] = json!("2001:db8::2");
    value["flow"]["destination"] = json!("2001:db8::1");
    let report = replay("inbound_path_ipv6_no_config.json", &value);
    assert_eq!(report["verdict"], "unknown");
    assert_eq!(
        report["steps"][0]["reason"],
        "IPv6 ingress configuration was not captured"
    );

    value["evidence"]["ipv6_disabled"] = collected(true);
    let report = replay("inbound_path_ipv6_disabled.json", &value);
    assert_eq!(report["verdict"], "unknown");
    assert_eq!(
        report["steps"][0]["reason"],
        "IPv6 is disabled on the ingress interface"
    );
}
