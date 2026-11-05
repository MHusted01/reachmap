//! UFW's configuration file, `/etc/ufw/ufw.conf`.

use crate::firewall::UfwState;
use crate::sanitize::sanitize;

/// The setting that says whether UFW is on.
const ENABLED: &str = "ENABLED";

/// Reads UFW's state from the text of its configuration file. The file holds
/// what UFW was last told, which is what it applies at boot; the rules in the
/// kernel are not checked. Anything but a clear yes or no leaves the state
/// unknown.
pub fn parse_ufw_conf(text: &str) -> UfwState {
    match enabled_value(text) {
        Some(value) if value.eq_ignore_ascii_case("yes") => UfwState::Active,
        Some(value) if value.eq_ignore_ascii_case("no") => UfwState::Inactive,
        Some(value) => UfwState::Unknown(format!(
            "ufw.conf has {ENABLED}={}, not yes or no",
            sanitize(value)
        )),
        None => UfwState::Unknown(format!("ufw.conf has no {ENABLED} setting")),
    }
}

/// The value of the last `ENABLED` line, without quotes. Comments need no
/// handling: `#ENABLED` is a different key.
fn enabled_value(text: &str) -> Option<&str> {
    text.lines().rev().find_map(|line| {
        let (key, value) = line.split_once('=')?;
        key.trim()
            .eq_ignore_ascii_case(ENABLED)
            .then(|| value.trim().trim_matches(['"', '\'']))
    })
}
