// Test helpers may panic: a failed test should stop loudly.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr};

use super::*;
use crate::baseline::Owner;
use crate::network::Network;
use crate::reach::Reach;
use crate::scan::Listener;
use crate::socket::Protocol;
use crate::warning::Warning;

const ADDRESS: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);

fn key(port: u16) -> RowKey {
    RowKey {
        port,
        protocol: Tolerant::Known(Protocol::Tcp),
        address: ADDRESS,
    }
}

fn exposure(name: &str) -> Exposure {
    Exposure {
        listener: Tolerant::Known(Listener::HostSocket),
        service: Owner::Process {
            name: name.to_string(),
        },
        reach: Reach::From {
            networks: BTreeSet::from([Network::Lan]),
        },
        warning: None,
    }
}

fn forwarded() -> Exposure {
    Exposure {
        listener: Tolerant::Known(Listener::DockerForward),
        ..exposure("web")
    }
}

fn snapshot(rows: impl IntoIterator<Item = (RowKey, Exposure)>) -> Snapshot {
    let mut grouped: BTreeMap<RowKey, BTreeSet<Exposure>> = BTreeMap::new();
    for (key, exposure) in rows {
        grouped.entry(key).or_default().insert(exposure);
    }
    Snapshot {
        rows: grouped,
        missing: BTreeSet::new(),
        needs_root: false,
    }
}

fn without_docker(snapshot: Snapshot) -> Snapshot {
    Snapshot {
        missing: BTreeSet::from([Tolerant::Known(Collector::Docker)]),
        ..snapshot
    }
}

fn shared_by_tailscale() -> Exposure {
    Exposure {
        listener: Tolerant::Known(Listener::TailscaleShare),
        service: Owner::Tailscale,
        ..exposure("unused")
    }
}

fn without(collector: Collector, snapshot: Snapshot) -> Snapshot {
    Snapshot {
        missing: BTreeSet::from([Tolerant::Known(collector)]),
        ..snapshot
    }
}

fn changes(diff: &Diff) -> Vec<(u16, Change)> {
    diff.differences
        .iter()
        .map(|difference| (difference.key.port, difference.change.clone()))
        .collect()
}

#[test]
fn identical_scans_have_no_differences() {
    let scan = snapshot([(key(22), exposure("sshd"))]);

    let diff = compare(&scan, &scan);

    assert_eq!(diff.differences, []);
    assert!(diff.is_clean());
}

#[test]
fn a_row_only_in_the_current_scan_is_new() {
    let diff = compare(&snapshot([]), &snapshot([(key(22), exposure("sshd"))]));

    assert_eq!(
        changes(&diff),
        [(
            22,
            Change::New {
                now: exposure("sshd")
            }
        )]
    );
    assert!(!diff.is_clean());
}

#[test]
fn a_row_only_in_the_baseline_is_removed() {
    let diff = compare(&snapshot([(key(22), exposure("sshd"))]), &snapshot([]));

    assert_eq!(
        changes(&diff),
        [(
            22,
            Change::Removed {
                was: exposure("sshd")
            }
        )]
    );
    assert!(!diff.is_clean());
}

#[test]
fn each_compared_fact_makes_a_row_changed() {
    let was = exposure("sshd");
    let variants = [
        Exposure {
            listener: Tolerant::Known(Listener::DockerForward),
            ..was.clone()
        },
        exposure("nc"),
        Exposure {
            reach: Reach::From {
                networks: BTreeSet::from([Network::Lan, Network::Internet]),
            },
            ..was.clone()
        },
        Exposure {
            reach: Reach::Unknown,
            ..was.clone()
        },
        Exposure {
            warning: Some(Tolerant::Known(Warning::UfwBypassed)),
            ..was.clone()
        },
    ];

    for now in variants {
        let diff = compare(
            &snapshot([(key(22), was.clone())]),
            &snapshot([(key(22), now.clone())]),
        );

        assert_eq!(
            changes(&diff),
            [(
                22,
                Change::Changed {
                    was: was.clone(),
                    now
                }
            )]
        );
    }
}

#[test]
fn another_address_is_another_row() {
    let loopback = RowKey {
        address: IpAddr::V4(Ipv4Addr::LOCALHOST),
        ..key(22)
    };

    let diff = compare(
        &snapshot([(loopback, exposure("sshd"))]),
        &snapshot([(key(22), exposure("sshd"))]),
    );

    assert_eq!(
        changes(&diff),
        [
            (
                22,
                Change::New {
                    now: exposure("sshd")
                }
            ),
            (
                22,
                Change::Removed {
                    was: exposure("sshd")
                }
            ),
        ]
    );
}

#[test]
fn differences_are_sorted_by_port() {
    let diff = compare(
        &snapshot([(key(443), exposure("a")), (key(22), exposure("b"))]),
        &snapshot([(key(80), exposure("c"))]),
    );

    let ports: Vec<u16> = changes(&diff).iter().map(|(port, _)| *port).collect();
    assert_eq!(ports, [22, 80, 443]);
}

#[test]
fn a_shared_endpoint_compares_what_is_left_after_the_common_rows() {
    let baseline = snapshot([(key(80), exposure("a")), (key(80), exposure("b"))]);
    let same_plus_one = snapshot([
        (key(80), exposure("a")),
        (key(80), exposure("b")),
        (key(80), exposure("c")),
    ]);
    let one_replaced = snapshot([(key(80), exposure("a")), (key(80), exposure("c"))]);
    let one_left = snapshot([(key(80), exposure("a"))]);
    let both_replaced_by_one = snapshot([(key(80), exposure("c"))]);

    assert_eq!(
        changes(&compare(&baseline, &same_plus_one)),
        [(80, Change::New { now: exposure("c") })]
    );
    assert_eq!(
        changes(&compare(&baseline, &one_replaced)),
        [(
            80,
            Change::Changed {
                was: exposure("b"),
                now: exposure("c")
            }
        )]
    );
    assert_eq!(
        changes(&compare(&baseline, &one_left)),
        [(80, Change::Removed { was: exposure("b") })]
    );
    assert_eq!(
        changes(&compare(&baseline, &both_replaced_by_one)),
        [
            (
                80,
                Change::Changed {
                    was: exposure("a"),
                    now: exposure("c")
                }
            ),
            (80, Change::Removed { was: exposure("b") }),
        ]
    );
}

#[test]
fn a_forwarded_port_is_unverified_when_docker_could_not_be_asked() {
    let diff = compare(
        &snapshot([(key(8080), forwarded())]),
        &without_docker(snapshot([])),
    );

    assert_eq!(
        changes(&diff),
        [(8080, Change::Unverified { was: forwarded() })]
    );
    assert!(!diff.is_clean());
}

#[test]
fn a_forwarded_port_is_removed_when_docker_answered() {
    let diff = compare(&snapshot([(key(8080), forwarded())]), &snapshot([]));

    assert_eq!(
        changes(&diff),
        [(8080, Change::Removed { was: forwarded() })]
    );
}

#[test]
fn a_host_socket_is_removed_even_when_docker_could_not_be_asked() {
    let diff = compare(
        &snapshot([(key(22), exposure("sshd"))]),
        &without_docker(snapshot([])),
    );

    assert_eq!(
        changes(&diff),
        [(
            22,
            Change::Removed {
                was: exposure("sshd")
            }
        )]
    );
}

#[test]
fn a_row_this_version_cannot_read_is_unverified_when_it_is_gone() {
    let unknown_protocol = RowKey {
        protocol: Tolerant::Unknown,
        ..key(22)
    };
    let unknown_listener = Exposure {
        listener: Tolerant::Unknown,
        ..exposure("sshd")
    };

    let diff = compare(
        &snapshot([
            (unknown_protocol, exposure("sshd")),
            (key(80), unknown_listener.clone()),
        ]),
        &snapshot([]),
    );

    assert_eq!(
        changes(&diff),
        [
            (
                22,
                Change::Unverified {
                    was: exposure("sshd")
                }
            ),
            (
                80,
                Change::Unverified {
                    was: unknown_listener
                }
            ),
        ]
    );
}

#[test]
fn facts_missing_from_both_scans_do_not_fail_the_diff() {
    let scan = without_docker(snapshot([(key(22), exposure("sshd"))]));

    let diff = compare(&scan, &scan);

    assert!(diff.is_clean());
    assert_eq!(
        diff.current_missing,
        BTreeSet::from([Tolerant::Known(Collector::Docker)])
    );
    assert_eq!(diff.baseline_missing, diff.current_missing);
}

#[test]
fn facts_lost_since_the_baseline_are_not_clean_even_with_identical_rows() {
    let baseline = snapshot([(key(22), exposure("sshd"))]);
    let current = without_docker(baseline.clone());

    let diff = compare(&baseline, &current);

    assert_eq!(diff.differences, []);
    assert!(!diff.is_clean());
}

#[test]
fn facts_gained_since_the_baseline_are_clean_when_the_rows_match() {
    let current = snapshot([(key(22), exposure("sshd"))]);
    let baseline = without_docker(current.clone());

    assert!(compare(&baseline, &current).is_clean());
}

#[test]
fn notices_when_only_one_scan_lacked_privileges() {
    let with_root = snapshot([]);
    let without_root = Snapshot {
        needs_root: true,
        ..snapshot([])
    };

    assert!(compare(&with_root, &without_root).privileges_differ);
    assert!(compare(&without_root, &with_root).privileges_differ);
    assert!(!compare(&without_root, &without_root).privileges_differ);
    assert!(!compare(&with_root, &with_root).privileges_differ);
}

fn ports(text: &str) -> PortList {
    text.parse().unwrap()
}

#[test]
fn a_comparison_has_no_filter_until_one_is_applied() {
    let diff = compare(&snapshot([]), &snapshot([(key(22), exposure("sshd"))]));

    assert_eq!(diff.ignored, None);
}

#[test]
fn ignoring_leaves_out_the_named_ports_and_counts_them() {
    let baseline = snapshot([(key(22), exposure("sshd"))]);
    let current = snapshot([(key(80), exposure("nginx")), (key(8000), exposure("api"))]);

    let diff = compare(&baseline, &current).ignoring(&ports("22,8000-8100"));

    assert_eq!(
        changes(&diff),
        [(
            80,
            Change::New {
                now: exposure("nginx")
            }
        )]
    );
    assert_eq!(diff.ignored, Some(2));
}

#[test]
fn ignoring_applies_to_every_protocol() {
    let udp = RowKey {
        protocol: Tolerant::Known(Protocol::Udp),
        ..key(5000)
    };
    let current = snapshot([(key(5000), exposure("tcp")), (udp, exposure("udp"))]);

    let diff = compare(&snapshot([]), &current).ignoring(&ports("5000"));

    assert!(diff.differences.is_empty());
    assert_eq!(diff.ignored, Some(2));
}

#[test]
fn ignoring_counts_each_difference_on_a_shared_row() {
    let current = snapshot([(key(22), exposure("one")), (key(22), exposure("two"))]);

    let diff = compare(&snapshot([]), &current).ignoring(&ports("22"));

    assert_eq!(diff.ignored, Some(2));
}

#[test]
fn a_filter_that_matches_nothing_still_shows_it_ran() {
    let row = snapshot([(key(22), exposure("sshd"))]);

    let diff = compare(&row, &row).ignoring(&ports("22"));

    assert_eq!(diff.ignored, Some(0));
}

#[test]
fn ignored_differences_need_no_attention() {
    let current = snapshot([(key(40000), exposure("client"))]);

    let diff = compare(&snapshot([]), &current);
    assert!(!diff.is_clean());

    assert!(diff.ignoring(&ports("40000")).is_clean());
}

#[test]
fn ignoring_ports_does_not_excuse_lost_facts() {
    let baseline = snapshot([(key(22), exposure("sshd"))]);
    let current = without_docker(snapshot([]));

    let diff = compare(&baseline, &current).ignoring(&ports("22"));

    assert!(diff.differences.is_empty());
    assert!(!diff.is_clean());
}

#[test]
fn a_share_is_unverified_when_tailscale_or_the_interfaces_are_missing() {
    let baseline = snapshot([(key(443), shared_by_tailscale())]);

    for collector in [Collector::Tailscale, Collector::Interfaces] {
        let diff = compare(&baseline, &without(collector, snapshot([])));
        assert_eq!(
            changes(&diff),
            [(
                443,
                Change::Unverified {
                    was: shared_by_tailscale()
                }
            )],
            "{collector:?}"
        );
    }
}

#[test]
fn a_share_is_removed_when_every_fact_it_needs_is_there() {
    let baseline = snapshot([(key(443), shared_by_tailscale())]);

    let diff = compare(&baseline, &without(Collector::Docker, snapshot([])));

    assert_eq!(
        changes(&diff),
        [(
            443,
            Change::Removed {
                was: shared_by_tailscale()
            }
        )]
    );
}

#[test]
fn a_host_socket_is_removed_even_when_tailscale_could_not_be_asked() {
    let baseline = snapshot([(key(22), exposure("sshd"))]);

    let diff = compare(&baseline, &without(Collector::Tailscale, snapshot([])));

    assert_eq!(
        changes(&diff),
        [(
            22,
            Change::Removed {
                was: exposure("sshd")
            }
        )]
    );
}
