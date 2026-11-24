//! Reading the configuration from disk: a bounded file read, and for a
//! Caddyfile one bounded run of `caddy adapt`.

#[cfg(target_os = "linux")]
use std::time::Duration;

use super::caddyfile::imports_files;
use super::error::{CaddyScanError, classify_read_error};
use super::source::{Adapted, ConfigSource, SourceKind};
use crate::caddy::MAX_INPUT_BYTES;
use crate::collect::nginx_files::{ConfigFiles, FileRead};
use crate::sanitize::sanitize;

/// How long `caddy adapt` may run. It answers in well under a second.
#[cfg(target_os = "linux")]
const ADAPT_TIMEOUT: Duration = Duration::from_secs(10);

/// Most standard error accepted from `caddy adapt`; it is never printed.
#[cfg(target_os = "linux")]
const MAX_ADAPT_STDERR: u64 = 64 * 1024;

/// Reads `source`. A JSON file is returned as is; a Caddyfile is checked for
/// `{$VAR}` placeholders and file imports, then handed to `adapt`, which
/// returns its JSON.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(super) fn read_source(
    source: &ConfigSource,
    files: &impl ConfigFiles,
    adapt: impl FnOnce(&str) -> Result<String, CaddyScanError>,
) -> Result<Adapted, CaddyScanError> {
    let text = read_text(source.path(), files)?;
    match source {
        ConfigSource::Json(_) => Ok(Adapted {
            kind: SourceKind::Json,
            json: text,
            env_placeholders: false,
            file_imports: false,
        }),
        ConfigSource::Caddyfile(path) => {
            let env_placeholders = text.contains("{$");
            let file_imports = imports_files(&text);
            drop(text);
            Ok(Adapted {
                kind: SourceKind::Caddyfile,
                json: adapt(path)?,
                env_placeholders,
                file_imports,
            })
        }
    }
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn read_text(path: &str, files: &impl ConfigFiles) -> Result<String, CaddyScanError> {
    let unreadable = |reason| CaddyScanError::UnreadableFile {
        path: sanitize(path),
        reason,
    };
    let limit = u64::try_from(MAX_INPUT_BYTES).unwrap_or(u64::MAX);
    match files
        .read(path, limit)
        .map_err(|error| classify_read_error(path, &error))?
    {
        FileRead::Missing => Err(CaddyScanError::ConfigNotFound {
            path: sanitize(path),
        }),
        FileRead::NotRegular => Err(unreadable("not a regular file")),
        FileRead::KernelFile => Err(unreadable("a kernel pseudo-file")),
        FileRead::TooLarge => Err(CaddyScanError::ConfigTooLarge {
            limit_bytes: MAX_INPUT_BYTES,
        }),
        FileRead::Bytes(bytes) => {
            String::from_utf8(bytes).map_err(|_| CaddyScanError::ConfigNotUtf8 {
                path: sanitize(path),
            })
        }
    }
}

/// Reads `source` from disk. A Caddyfile is adapted by `caddy adapt`, run
/// with an empty environment (so no `{$VAR}` value from reachmap's own
/// environment can reach the JSON), a timeout and bounded output, and never
/// with `--validate`, which would start Caddy's modules.
#[cfg(target_os = "linux")]
pub(super) fn read(source: &ConfigSource) -> Result<Adapted, CaddyScanError> {
    use super::error::classify_adapt_error;
    use super::program::{CADDY_PATHS, inspect_program, locate};
    use crate::collect::command;
    use crate::collect::nginx_files::DiskFiles;

    read_source(source, &DiskFiles, |path| {
        let program = locate(&CADDY_PATHS, inspect_program)?;
        let program = program.as_str();
        let config = format!("--config={path}");
        let stdout_limit = u64::try_from(MAX_INPUT_BYTES).unwrap_or(u64::MAX);
        command::run_bounded(
            program,
            &["adapt", &config, "--adapter", "caddyfile"],
            ADAPT_TIMEOUT,
            (stdout_limit, MAX_ADAPT_STDERR),
            |_| {},
        )
        .map_err(classify_adapt_error)
    })
}

#[cfg(not(target_os = "linux"))]
pub(super) fn read(_source: &ConfigSource) -> Result<Adapted, CaddyScanError> {
    Err(CaddyScanError::UnsupportedOs {
        os: std::env::consts::OS,
    })
}
