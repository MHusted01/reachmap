//! Which on-disk Caddy configuration to read, and what reading it produced.

use std::convert::Infallible;
use std::fmt;
use std::path::Path;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// Where Caddy's packaged service reads its Caddyfile.
pub const DEFAULT_CADDYFILE: &str = "/etc/caddy/Caddyfile";

/// The configuration file to read: a Caddyfile, which `caddy adapt` turns
/// into JSON, or a native JSON config, which is read directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigSource {
    /// A Caddyfile at this path.
    Caddyfile(String),
    /// A native JSON config at this path.
    Json(String),
}

impl ConfigSource {
    /// The path of the configuration file.
    pub fn path(&self) -> &str {
        match self {
            Self::Caddyfile(path) | Self::Json(path) => path,
        }
    }

    /// Which kind of file this is.
    pub fn kind(&self) -> SourceKind {
        match self {
            Self::Caddyfile(_) => SourceKind::Caddyfile,
            Self::Json(_) => SourceKind::Json,
        }
    }
}

impl Default for ConfigSource {
    /// The packaged Caddyfile, [`DEFAULT_CADDYFILE`].
    fn default() -> Self {
        Self::Caddyfile(DEFAULT_CADDYFILE.to_owned())
    }
}

/// A path ending in `.json` (any case) is native JSON; any other is a Caddyfile.
impl FromStr for ConfigSource {
    type Err = Infallible;

    fn from_str(path: &str) -> Result<Self, Self::Err> {
        let is_json = Path::new(path)
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("json"));
        let path = path.to_owned();
        Ok(if is_json {
            Self::Json(path)
        } else {
            Self::Caddyfile(path)
        })
    }
}

/// The kind of configuration file a report was built from. The path itself
/// is not kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    /// A Caddyfile, adapted to JSON by `caddy adapt`.
    Caddyfile,
    /// A native JSON config.
    Json,
}

impl fmt::Display for SourceKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Caddyfile => "Caddyfile on disk, adapted to JSON by `caddy adapt`",
            Self::Json => "native JSON config file on disk",
        })
    }
}

/// The JSON config that was read, before it is parsed.
#[derive(Debug)]
pub(in crate::caddy) struct Adapted {
    pub(in crate::caddy) kind: SourceKind,
    pub(in crate::caddy) json: String,
    /// Whether the Caddyfile uses `{$VAR}` environment placeholders, which
    /// were expanded with an empty environment.
    pub(in crate::caddy) env_placeholders: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(path: &str) -> ConfigSource {
        path.parse()
            .unwrap_or_else(|never: Infallible| match never {})
    }

    #[test]
    fn json_extension_selects_native_json() {
        assert_eq!(
            parse("/srv/caddy/config.JSON"),
            ConfigSource::Json("/srv/caddy/config.JSON".to_owned())
        );
        assert_eq!(
            parse("/etc/caddy/Caddyfile"),
            ConfigSource::Caddyfile("/etc/caddy/Caddyfile".to_owned())
        );
        assert_eq!(parse("site.caddy").kind(), SourceKind::Caddyfile);
        assert_eq!(parse("json").kind(), SourceKind::Caddyfile);
    }

    #[test]
    fn defaults_to_the_packaged_caddyfile() {
        let source = ConfigSource::default();
        assert_eq!(source.path(), DEFAULT_CADDYFILE);
        assert_eq!(source.kind(), SourceKind::Caddyfile);
    }
}
