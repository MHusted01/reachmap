//! Reading a value that a newer reachmap may have replaced with one this
//! version does not know.

use std::fmt;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A value from a document, or a value this version of reachmap cannot read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Tolerant<T> {
    /// A value this version understands.
    Known(T),
    /// Anything else, for example a value added by a newer reachmap.
    Unknown,
}

impl<T> Tolerant<T> {
    /// The value, if this version understands it.
    pub(super) fn known(self) -> Option<T> {
        match self {
            Tolerant::Known(value) => Some(value),
            Tolerant::Unknown => None,
        }
    }
}

impl<'de, T: DeserializeOwned> Deserialize<'de> for Tolerant<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = serde_json::Value::deserialize(deserializer)?;
        Ok(serde_json::from_value(value).map_or(Tolerant::Unknown, Tolerant::Known))
    }
}

impl<T: Serialize> Serialize for Tolerant<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Tolerant::Known(value) => value.serialize(serializer),
            Tolerant::Unknown => serializer.serialize_str("unknown"),
        }
    }
}

impl<T: fmt::Display> fmt::Display for Tolerant<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Tolerant::Known(value) => value.fmt(f),
            Tolerant::Unknown => f.write_str("unknown"),
        }
    }
}
