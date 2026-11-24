//! Read-only commands from the macOS system volume.

use std::time::Duration;

use crate::pf::{
    CollectedPf, PFCTL_ANCHORS_LIMIT, PFCTL_IFACES_LIMIT, PFCTL_INFO_LIMIT, PFCTL_RULES_LIMIT,
    PfCollectError, PfCommand, PfRunner, collect_with,
};

use super::{CollectError, command};

const LSOF: &str = "/usr/sbin/lsof";
const FIREWALL: &str = "/usr/libexec/ApplicationFirewall/socketfilterfw";
const PFCTL: &str = "/sbin/pfctl";
const IFCONFIG: &str = "/sbin/ifconfig";
const LSOF_TIMEOUT: Duration = Duration::from_secs(5);
const FIREWALL_TIMEOUT: Duration = Duration::from_secs(2);
const IFCONFIG_TIMEOUT: Duration = Duration::from_secs(2);
const IFCONFIG_LIMIT: (u64, u64) = (512 * 1024, 64 * 1024);

pub(crate) fn read_sockets() -> Result<(String, Option<String>), CollectError> {
    // Numeric addresses and ports avoid name lookups. NUL-delimited fields
    // keep whitespace inside command names from changing the record structure.
    command::run_inventory(LSOF, &["-nP", "-i", "-F0pcfPtTn"], LSOF_TIMEOUT, 1)
}

pub(crate) fn read_firewall() -> Result<String, CollectError> {
    command::run(FIREWALL, &["--getglobalstate"], FIREWALL_TIMEOUT)
}

pub(crate) fn read_interfaces() -> Result<String, CollectError> {
    command::run_bounded(IFCONFIG, &["-a"], IFCONFIG_TIMEOUT, IFCONFIG_LIMIT, |_| {})
}

pub(crate) fn read_pf() -> Result<CollectedPf, PfCollectError> {
    collect_with(&mut SystemPfRunner)
}

struct SystemPfRunner;

impl PfRunner for SystemPfRunner {
    fn run(&mut self, cmd: PfCommand<'_>, timeout: Duration) -> Result<String, CollectError> {
        match cmd {
            PfCommand::Info => {
                command::run_bounded(PFCTL, &["-s", "info"], timeout, PFCTL_INFO_LIMIT, |_| {})
            }
            PfCommand::MainRules => {
                command::run_bounded(PFCTL, &["-sr"], timeout, PFCTL_RULES_LIMIT, |_| {})
            }
            PfCommand::Interfaces => command::run_bounded(
                PFCTL,
                &["-v", "-s", "Interfaces"],
                timeout,
                PFCTL_IFACES_LIMIT,
                |_| {},
            ),
            PfCommand::RootAnchors => {
                command::run_bounded(PFCTL, &["-sA"], timeout, PFCTL_ANCHORS_LIMIT, |_| {})
            }
            PfCommand::AnchorRules(anchor) => command::run_bounded(
                PFCTL,
                &["-a", anchor, "-sr"],
                timeout,
                PFCTL_RULES_LIMIT,
                |_| {},
            ),
            PfCommand::AnchorChildren(anchor) => command::run_bounded(
                PFCTL,
                &["-a", anchor, "-sA"],
                timeout,
                PFCTL_ANCHORS_LIMIT,
                |_| {},
            ),
        }
    }
}
