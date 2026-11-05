use super::*;
use crate::collect::CollectError;
use crate::reach::classify;
use crate::scan::Listener;
use crate::service::{Container, Service};
use crate::socket::{Endpoint, Protocol};
use std::io::{self, ErrorKind};

const REASON: &str = "ufw.conf has no ENABLED setting";

fn unknown() -> UfwState {
    UfwState::Unknown(REASON.to_string())
}

fn published(address: &str) -> PublishedPort {
    PublishedPort {
        address: address.parse().unwrap(),
        port: 8080,
        container: Container {
            name: "web".to_string(),
            compose_service: None,
        },
    }
}

fn row(port: u16, warning: Option<Warning>) -> ScannedPort {
    let address = "0.0.0.0".parse().unwrap();
    ScannedPort {
        endpoint: Endpoint {
            port,
            protocol: Protocol::Tcp,
            address,
        },
        listener: Listener::HostSocket,
        service: Service::Container(Container {
            name: "web".to_string(),
            compose_service: None,
        }),
        verdict: classify(address, None, None),
        warning,
    }
}

fn firewall(ufw: UfwState, docker_user: Option<DockerUserChain>) -> Firewall {
    Firewall { ufw, docker_user }
}

fn unreachable_docker() -> DockerError {
    DockerError::Collect(CollectError::Run {
        command: "docker ps -q".to_string(),
        source: io::Error::new(ErrorKind::PermissionDenied, "no"),
    })
}

#[test]
fn ufw_off_warns_about_nothing() {
    for address in ["0.0.0.0", "::", "127.0.0.1"] {
        assert_eq!(
            docker_ufw_bypass(&published(address), &UfwState::Inactive),
            None
        );
    }
}

#[test]
fn ufw_on_warns_about_all_interfaces() {
    for address in ["0.0.0.0", "::"] {
        assert_eq!(
            docker_ufw_bypass(&published(address), &UfwState::Active),
            Some(Warning::UfwBypassed)
        );
    }
}

#[test]
fn ufw_on_warns_about_one_lan_address_too() {
    assert_eq!(
        docker_ufw_bypass(&published("192.168.1.20"), &UfwState::Active),
        Some(Warning::UfwBypassed)
    );
}

#[test]
fn ufw_on_leaves_loopback_alone() {
    for address in ["127.0.0.1", "::1", "::ffff:127.0.0.1"] {
        assert_eq!(
            docker_ufw_bypass(&published(address), &UfwState::Active),
            None
        );
    }
}

#[test]
fn unknown_ufw_warns_with_unknown_wording() {
    assert_eq!(
        docker_ufw_bypass(&published("0.0.0.0"), &unknown()),
        Some(Warning::UfwUnknown)
    );
    assert_eq!(docker_ufw_bypass(&published("127.0.0.1"), &unknown()), None);
}

#[test]
fn nothing_to_report_is_an_empty_summary() {
    let rows = [row(8080, None)];
    let facts = firewall(UfwState::Active, None);
    assert_eq!(summarise(&rows, None, &facts), Vec::new());
}

#[test]
fn bypassed_ports_are_listed_once_in_order() {
    let flagged = Some(Warning::UfwBypassed);
    let rows = [row(9000, flagged), row(8080, flagged), row(8080, flagged)];
    let facts = firewall(UfwState::Active, Some(DockerUserChain::NoRules));
    assert_eq!(
        summarise(&rows, None, &facts),
        vec![ScanWarning::UfwBypassed {
            ports: BTreeSet::from([8080, 9000])
        }]
    );
}

#[test]
fn unknown_ufw_carries_its_reason() {
    let rows = [row(8080, Some(Warning::UfwUnknown))];
    let facts = firewall(unknown(), Some(DockerUserChain::NoRules));
    assert_eq!(
        summarise(&rows, None, &facts),
        vec![ScanWarning::UfwUnknown {
            ports: BTreeSet::from([8080]),
            reason: REASON.to_string()
        }]
    );
}

#[test]
fn the_docker_user_chain_adds_a_line_of_its_own() {
    let rows = [row(8080, Some(Warning::UfwBypassed))];
    let bypassed = ScanWarning::UfwBypassed {
        ports: BTreeSet::from([8080]),
    };
    let has_rules = firewall(UfwState::Active, Some(DockerUserChain::HasRules));
    assert_eq!(
        summarise(&rows, None, &has_rules),
        vec![bypassed.clone(), ScanWarning::DockerUserRules]
    );
    let unchecked = DockerUserChain::Unchecked("run with sudo".to_string());
    assert_eq!(
        summarise(&rows, None, &firewall(UfwState::Active, Some(unchecked))),
        vec![
            bypassed,
            ScanWarning::DockerUserUnchecked {
                reason: "run with sudo".to_string(),
            }
        ]
    );
}

#[test]
fn unknown_docker_under_active_ufw_is_not_fine() {
    let error = unreachable_docker();
    let facts = firewall(UfwState::Active, None);
    assert_eq!(
        summarise(&[], Some(&error), &facts),
        vec![ScanWarning::DockerUnknown { ufw_reason: None }]
    );
}

#[test]
fn unknown_docker_and_unknown_ufw_say_both() {
    let error = unreachable_docker();
    assert_eq!(
        summarise(&[], Some(&error), &firewall(unknown(), None)),
        vec![ScanWarning::DockerUnknown {
            ufw_reason: Some(REASON.to_string())
        }]
    );
}

#[test]
fn unknown_docker_does_not_matter_when_ufw_is_off() {
    let error = unreachable_docker();
    let facts = firewall(UfwState::Inactive, None);
    assert_eq!(summarise(&[], Some(&error), &facts), Vec::new());
}

#[test]
fn without_docker_there_is_nothing_to_bypass() {
    let error = DockerError::NotInstalled;
    let facts = firewall(UfwState::Active, None);
    assert_eq!(summarise(&[], Some(&error), &facts), Vec::new());
}

#[test]
fn warnings_read_as_written_in_the_docs() {
    let ports = BTreeSet::from([8080, 9000]);
    let reason = REASON.to_string();
    let lines = [
        (
            ScanWarning::UfwBypassed {
                ports: ports.clone(),
            },
            "UFW is active, but it does not apply to these Docker ports: 8080, 9000",
        ),
        (
            ScanWarning::UfwUnknown {
                ports,
                reason: reason.clone(),
            },
            "could not tell whether UFW is active (ufw.conf has no ENABLED setting); \
             if it is, it does not apply to these Docker ports: 8080, 9000",
        ),
        (
            ScanWarning::DockerUnknown { ufw_reason: None },
            "UFW is active and Docker could not be asked, so it is unknown which \
             published ports bypass UFW",
        ),
        (
            ScanWarning::DockerUnknown {
                ufw_reason: Some(reason),
            },
            "could not tell whether UFW is active (ufw.conf has no ENABLED setting) and \
             Docker could not be asked, so it is unknown which published ports bypass UFW",
        ),
        (
            ScanWarning::DockerUserRules,
            "DOCKER-USER has rules, so filtering may apply, not verified",
        ),
        (
            ScanWarning::DockerUserUnchecked {
                reason: "run with sudo".to_string(),
            },
            "DOCKER-USER rules were not checked: run with sudo",
        ),
    ];
    for (warning, expected) in lines {
        assert_eq!(warning.to_string(), expected);
    }
}

#[test]
fn row_notes_name_ufw_without_promising_anything() {
    assert_eq!(
        Warning::UfwBypassed.to_string(),
        "Docker port: UFW does not apply"
    );
    assert_eq!(
        Warning::UfwUnknown.to_string(),
        "Docker port: UFW would not apply, its state is unknown"
    );
}

#[test]
fn no_text_ever_claims_protection() {
    let ports = BTreeSet::from([8080]);
    let reason = REASON.to_string();
    let texts = [
        Warning::UfwBypassed.to_string(),
        Warning::UfwUnknown.to_string(),
        ScanWarning::UfwBypassed {
            ports: ports.clone(),
        }
        .to_string(),
        ScanWarning::UfwUnknown {
            ports,
            reason: reason.clone(),
        }
        .to_string(),
        ScanWarning::DockerUnknown { ufw_reason: None }.to_string(),
        ScanWarning::DockerUnknown {
            ufw_reason: Some(reason),
        }
        .to_string(),
        ScanWarning::DockerUserRules.to_string(),
        ScanWarning::DockerUserUnchecked {
            reason: "run with sudo".to_string(),
        }
        .to_string(),
    ];
    for text in texts {
        let lowered = text.to_lowercase();
        for claim in ["protected", "blocked", "safe"] {
            assert!(!lowered.contains(claim), "{text:?} claims {claim}");
        }
    }
}
