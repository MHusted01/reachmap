use serde_json::{Value, json};

use super::*;

#[test]
fn source_lookup_requires_a_matching_ipv4_route_type() {
    let source = "192.0.2.2".parse().unwrap();
    for (raw, expected) in [
        (r#"[{"dst":"192.0.2.2","type":"local"}]"#, Some(true)),
        (r#"[{"dst":"192.0.2.2"}]"#, Some(false)),
        (r#"[{"dst":"192.0.2.2","type":"unicast"}]"#, Some(false)),
        (r#"[{"dst":"192.0.2.3","type":"local"}]"#, None),
        (r#"[{"dst":"192.0.2.2","type":"blackhole"}]"#, None),
        ("[]", None),
    ] {
        assert_eq!(local_source_route(source, raw).ok(), expected);
    }
}

fn veth() -> Value {
    json!({
        "ifindex":2, "ifname":"eth0", "link_index":12, "flags":["UP","LOWER_UP"],
        "linkinfo":{"info_kind":"veth"},
        "addr_info":[{"local":"198.51.100.2"}]
    })
}

#[test]
fn container_endpoint_requires_one_active_veth_with_the_target_address() {
    let address = "198.51.100.2".parse().unwrap();
    let entry = veth();
    let link = container_link(&json!([entry]).to_string(), address).unwrap();
    assert_eq!(link.ifindex, 2);

    let mut down = veth();
    down["flags"] = json!(["UP"]);
    let mut dummy = veth();
    dummy["linkinfo"]["info_kind"] = json!("dummy");
    for links in [
        json!([]),
        json!([down]),
        json!([dummy]),
        json!([entry, entry]),
    ] {
        assert!(
            container_link(&links.to_string(), address).is_err(),
            "{links}"
        );
    }
    assert!(container_link(&json!([entry]).to_string(), "198.51.100.3".parse().unwrap()).is_err());
}

#[test]
fn bridge_peer_must_point_to_the_container_and_be_forwarding() {
    let link: Link = serde_json::from_value(veth()).unwrap();
    let peer = json!({
        "ifindex":12, "ifname":"veth-test", "link_index":2, "flags":["UP","LOWER_UP"],
        "linkinfo":{"info_kind":"veth","info_slave_data":{"state":"forwarding"}}
    });
    assert!(check_bridge_peer(&link, &json!([peer]).to_string()).is_ok());

    for (key, value) in [
        ("/ifindex", json!(3)),
        ("/link_index", json!(14)),
        ("/linkinfo/info_slave_data/state", json!("blocking")),
    ] {
        let mut invalid = peer.clone();
        *invalid.pointer_mut(key).unwrap() = value;
        assert!(check_bridge_peer(&link, &json!([invalid]).to_string()).is_err());
    }
}
