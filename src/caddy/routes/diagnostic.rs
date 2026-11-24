//! Why a Caddy route collection is partial.

use std::fmt;

use serde::{Deserialize, Serialize};

use super::link::MAX_LINKED_PORTS;
use crate::local_tcp::SocketFailure;

/// One reason the evidence is incomplete. Any note makes the report partial.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(super) enum Note {
    /// The TCP socket list could not be read.
    SocketInventoryUnavailable { reason: SocketFailure },
    /// Socket options (device binding, `IPV6_V6ONLY`) could not all be read.
    SocketOptionsIncomplete { reason: SocketFailure },
    /// The Caddyfile uses `{$VAR}` placeholders, expanded with an empty
    /// environment instead of the one the Caddy service runs with.
    EnvironmentPlaceholders {},
    /// A listen port range too wide to link port by port.
    PortRangeNotLinked { first: u16, last: u16 },
}

impl fmt::Display for Note {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SocketInventoryUnavailable { reason } => {
                write!(f, "TCP socket inventory unavailable ({reason})")
            }
            Self::SocketOptionsIncomplete { reason } => {
                write!(f, "TCP socket options incomplete ({reason})")
            }
            Self::EnvironmentPlaceholders {} => f.write_str(
                "the Caddyfile uses {$VAR} environment placeholders, which were adapted with an empty environment; the Caddy service may see other values",
            ),
            Self::PortRangeNotLinked { first, last } => write!(
                f,
                "listen port range {first}-{last} not linked to TCP listeners (more than {MAX_LINKED_PORTS} ports)"
            ),
        }
    }
}
