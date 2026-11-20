//! Read-only commands from the macOS system volume.

use std::time::Duration;

use super::{CollectError, command};

const LSOF: &str = "/usr/sbin/lsof";
const FIREWALL: &str = "/usr/libexec/ApplicationFirewall/socketfilterfw";
const LSOF_TIMEOUT: Duration = Duration::from_secs(5);
const FIREWALL_TIMEOUT: Duration = Duration::from_secs(2);

pub(crate) fn read_sockets() -> Result<(String, Option<String>), CollectError> {
    // Numeric addresses and ports avoid name lookups. NUL-delimited fields
    // keep whitespace inside command names from changing the record structure.
    command::run_inventory(LSOF, &["-nP", "-i", "-F0pcfPtTn"], LSOF_TIMEOUT, 1)
}

pub(crate) fn read_firewall() -> Result<String, CollectError> {
    command::run(FIREWALL, &["--getglobalstate"], FIREWALL_TIMEOUT)
}
