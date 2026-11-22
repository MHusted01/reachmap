//! Collection diagnostics that can be saved without raw kernel errors.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::local_tcp::SocketFailure;
use crate::sanitize::sanitize;

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(super) enum Note {
    RouteStatus { detail: String },
    SocketInventoryUnavailable { reason: SocketFailure },
    SocketOptionsIncomplete { reason: SocketFailure },
}

impl fmt::Display for Note {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RouteStatus { detail } => f.write_str(&sanitize(detail)),
            Self::SocketInventoryUnavailable { reason } => {
                write!(f, "TCP socket inventory unavailable ({reason})")
            }
            Self::SocketOptionsIncomplete { reason } => {
                write!(f, "TCP socket options incomplete ({reason})")
            }
        }
    }
}
