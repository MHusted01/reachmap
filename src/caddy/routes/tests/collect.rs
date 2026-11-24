//! Reading the configuration and turning every failure into a clear error.

use std::cell::Cell;
use std::io::{self, ErrorKind};
use std::os::unix::process::ExitStatusExt;
use std::process::ExitStatus;
use std::time::Duration;

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use super::super::collect::read_source;
use super::super::error::classify_adapt_error;
use super::super::program::{
    CADDY_PATHS, Entry, Program, Refusal, inspect, locate, resolve_trusted,
};
use super::super::source::ConfigSource;
use super::*;
use crate::caddy::MAX_INPUT_BYTES;
use crate::collect::nginx_files::{ConfigFiles, DirList, FileRead};

/// One file the fake filesystem answers every read with.
struct OneFile(Result<FileRead, ErrorKind>);

impl ConfigFiles for OneFile {
    fn read(&self, _path: &str, limit: u64) -> io::Result<FileRead> {
        assert_eq!(limit, u64::try_from(MAX_INPUT_BYTES).expect("limit"));
        self.0.clone().map_err(io::Error::from)
    }

    fn list(&self, _dir: &str, _limit: usize) -> io::Result<DirList> {
        unreachable!("the Caddy collector lists no directories")
    }

    fn exists(&self, _path: &str) -> io::Result<bool> {
        unreachable!("the Caddy collector checks no paths")
    }
}

fn file(text: &str) -> OneFile {
    OneFile(Ok(FileRead::Bytes(text.as_bytes().to_vec())))
}

fn caddyfile() -> ConfigSource {
    ConfigSource::Caddyfile("/etc/caddy/Caddyfile".to_owned())
}

fn no_adapt(_: &str) -> Result<String, CaddyScanError> {
    panic!("caddy adapt must not run")
}

#[test]
fn a_json_file_is_read_without_running_caddy() {
    let source = ConfigSource::Json("/srv/caddy.json".to_owned());
    let adapted = read_source(&source, &file("{}"), no_adapt).expect("read");
    assert_eq!(adapted.kind, SourceKind::Json);
    assert_eq!(adapted.json, "{}");
    assert!(!adapted.env_placeholders);
}

#[test]
fn a_caddyfile_is_adapted_and_checked_for_environment_placeholders() {
    let adapted_path = Cell::new(None);
    let adapt = |path: &str| {
        adapted_path.set(Some(path.to_owned()));
        Ok(r#"{"apps":{}}"#.to_owned())
    };
    let text = "app.example.test {\n\treverse_proxy {$BACKEND}\n}\n";
    let adapted = read_source(&caddyfile(), &file(text), adapt).expect("read");
    assert_eq!(adapted.kind, SourceKind::Caddyfile);
    assert_eq!(adapted.json, r#"{"apps":{}}"#);
    assert!(adapted.env_placeholders);
    assert_eq!(adapted_path.take().as_deref(), Some("/etc/caddy/Caddyfile"));

    let plain = read_source(&caddyfile(), &file(":80 {\n\trespond ok\n}\n"), |_| {
        Ok("{}".to_owned())
    })
    .expect("read");
    assert!(!plain.env_placeholders);
    assert!(!plain.file_imports);

    let imported = read_source(&caddyfile(), &file("import sites/*\n"), |_| {
        Ok("{}".to_owned())
    })
    .expect("read");
    assert!(imported.file_imports);
}

/// A filesystem of `(path, uid, mode, symlink target)` entries.
fn tree(entries: &[(&str, u32, u32, Option<&str>)]) -> impl Fn(&Path) -> Result<Entry, Refusal> {
    let entries: HashMap<PathBuf, Entry> = entries
        .iter()
        .map(|&(path, uid, mode, link)| {
            let entry = Entry {
                uid,
                mode,
                link: link.map(PathBuf::from),
            };
            (PathBuf::from(path), entry)
        })
        .collect();
    move |path| entries.get(path).cloned().ok_or(Refusal::Missing)
}

const DIR: u32 = 0o755;
const LINK: u32 = 0o777;

fn system(
    extra: &[(&'static str, u32, u32, Option<&'static str>)],
) -> Vec<(&'static str, u32, u32, Option<&'static str>)> {
    let mut entries = vec![
        ("/", 0, DIR, None),
        ("/usr", 0, DIR, None),
        ("/usr/bin", 0, DIR, None),
        ("/usr/bin/caddy", 0, DIR, None),
        ("/bin", 0, LINK, Some("usr/bin")),
    ];
    entries.extend_from_slice(extra);
    entries
}

fn resolved(entries: &[(&str, u32, u32, Option<&str>)], path: &str) -> Result<PathBuf, Refusal> {
    resolve_trusted(Path::new(path), &tree(entries))
}

#[test]
fn a_missing_candidate_is_skipped_whatever_its_directory_allows() {
    let shared = system(&[
        ("/usr/local", 0, DIR, None),
        ("/usr/local/bin", 0, 0o775, None),
    ]);
    let lookup = tree(&shared);
    assert_eq!(
        inspect(Path::new("/usr/local/bin/caddy"), &lookup),
        Err(Refusal::Missing)
    );
    let present = system(&[
        ("/usr/local", 0, DIR, None),
        ("/usr/local/bin", 0, 0o775, None),
        ("/usr/local/bin/caddy", 0, DIR, None),
    ]);
    assert_eq!(
        inspect(Path::new("/usr/local/bin/caddy"), &tree(&present)),
        Err(Refusal::Untrusted)
    );
    assert_eq!(
        inspect(Path::new("/usr/bin/caddy"), &tree(&present)),
        Ok(PathBuf::from("/usr/bin/caddy"))
    );
}

#[test]
fn caddy_resolves_only_through_paths_only_root_can_change() {
    let usr_bin = Ok(PathBuf::from("/usr/bin/caddy"));
    assert_eq!(resolved(&system(&[]), "/usr/bin/caddy"), usr_bin);
    assert_eq!(resolved(&system(&[]), "/bin/caddy"), usr_bin, "merged /usr");

    let shared_dir = system(&[
        ("/usr/local", 0, DIR, None),
        ("/usr/local/bin", 0, 0o775, None),
        ("/usr/local/bin/caddy", 0, LINK, Some("/usr/bin/caddy")),
    ]);
    assert_eq!(
        resolved(&shared_dir, "/usr/local/bin/caddy"),
        Err(Refusal::Untrusted),
        "a group-writable directory picks the target"
    );

    let foreign_link = system(&[
        ("/usr/local", 0, DIR, None),
        ("/usr/local/bin", 0, DIR, None),
        ("/usr/local/bin/caddy", 1001, LINK, Some("/usr/bin/caddy")),
    ]);
    assert_eq!(
        resolved(&foreign_link, "/usr/local/bin/caddy"),
        Err(Refusal::Untrusted),
        "a symlink owned by another user"
    );

    let via_tmp = system(&[
        ("/usr/local", 0, DIR, None),
        ("/usr/local/bin", 0, DIR, None),
        ("/usr/local/bin/caddy", 0, LINK, Some("/tmp/caddy")),
        ("/tmp", 0, 0o1777, None),
        ("/tmp/caddy", 0, DIR, None),
    ]);
    assert_eq!(
        resolved(&via_tmp, "/usr/local/bin/caddy"),
        Err(Refusal::Untrusted),
        "a hop through a shared directory"
    );

    let foreign_file = vec![
        ("/", 0, DIR, None),
        ("/usr", 0, DIR, None),
        ("/usr/bin", 0, DIR, None),
        ("/usr/bin/caddy", 1001, DIR, None),
    ];
    assert_eq!(
        resolved(&foreign_file, "/usr/bin/caddy"),
        Err(Refusal::Untrusted)
    );

    let looping = system(&[
        ("/usr/bin/a", 0, LINK, Some("b")),
        ("/usr/bin/b", 0, LINK, Some("a")),
    ]);
    assert_eq!(
        resolved(&looping, "/usr/bin/a"),
        Err(Refusal::Untrusted),
        "symlink loops end"
    );
    assert_eq!(
        resolved(&system(&[]), "/usr/bin/missing"),
        Err(Refusal::Missing)
    );
    let dangling = system(&[("/usr/bin/stale", 0, LINK, Some("/opt/gone/caddy"))]);
    assert_eq!(
        resolved(&dangling, "/usr/bin/stale"),
        Err(Refusal::Missing),
        "a stale alternatives link lets the search go on"
    );
    assert_eq!(
        resolved(&system(&[]), "usr/bin/caddy"),
        Err(Refusal::Untrusted)
    );
}

#[test]
fn adapt_failures_propagate() {
    let failed = read_source(&caddyfile(), &file(":80"), |_| {
        Err(CaddyScanError::AdaptFailed { exit_code: Some(1) })
    });
    assert!(matches!(
        failed,
        Err(CaddyScanError::AdaptFailed { exit_code: Some(1) })
    ));
}

#[test]
fn unreadable_configuration_files_are_errors_with_a_reason() {
    let read = |files: OneFile| read_source(&caddyfile(), &files, no_adapt).expect_err("error");
    assert!(matches!(
        read(OneFile(Ok(FileRead::Missing))),
        CaddyScanError::ConfigNotFound { path } if path == "/etc/caddy/Caddyfile"
    ));
    assert!(matches!(
        read(OneFile(Ok(FileRead::NotRegular))),
        CaddyScanError::UnreadableFile {
            reason: "not a regular file",
            ..
        }
    ));
    assert!(matches!(
        read(OneFile(Ok(FileRead::KernelFile))),
        CaddyScanError::UnreadableFile {
            reason: "a kernel pseudo-file",
            ..
        }
    ));
    assert!(matches!(
        read(OneFile(Ok(FileRead::TooLarge))),
        CaddyScanError::ConfigTooLarge { limit_bytes } if limit_bytes == MAX_INPUT_BYTES
    ));
    assert!(matches!(
        read(OneFile(Err(ErrorKind::PermissionDenied))),
        CaddyScanError::PermissionDenied
    ));
    assert!(matches!(
        read(OneFile(Err(ErrorKind::NotFound))),
        CaddyScanError::ConfigNotFound { .. }
    ));
    assert!(matches!(
        read(OneFile(Err(ErrorKind::Interrupted))),
        CaddyScanError::ReadFailed { .. }
    ));
    assert!(matches!(
        read(OneFile(Ok(FileRead::Bytes(vec![0xff, 0xfe])))),
        CaddyScanError::ConfigNotUtf8 { .. }
    ));
}

#[test]
fn paths_in_errors_are_sanitized() {
    let source = ConfigSource::Caddyfile("/tmp/\u{1b}[2Jcaddy".to_owned());
    let error =
        read_source(&source, &OneFile(Ok(FileRead::Missing)), no_adapt).expect_err("missing");
    assert!(error.to_string().contains("\\u{1b}[2Jcaddy"), "{error}");
}

#[test]
fn caddy_runs_only_from_a_trusted_fixed_path() {
    let found = locate(&CADDY_PATHS, |path| {
        if path == "/usr/local/bin/caddy" {
            Program::Trusted("/opt/caddy/bin/caddy".to_owned())
        } else {
            Program::Missing
        }
    });
    assert_eq!(found.expect("found"), "/opt/caddy/bin/caddy");

    let untrusted = locate(&CADDY_PATHS, |_| Program::Untrusted).expect_err("untrusted");
    assert!(
        matches!(&untrusted, CaddyScanError::UntrustedCommand { path } if path == "/usr/bin/caddy")
    );
    assert!(untrusted.to_string().contains("owned by root"));

    let missing = locate(&CADDY_PATHS, |_| Program::Missing).expect_err("missing");
    assert!(matches!(missing, CaddyScanError::MissingCommand));
    assert!(missing.to_string().contains("--caddy-config"));
}

fn command_failed(stderr: &str) -> CaddyScanError {
    classify_adapt_error(CollectError::CommandFailed {
        command: "/usr/bin/caddy adapt".to_owned(),
        status: ExitStatus::from_raw(256),
        stderr: stderr.to_owned(),
    })
}

#[test]
fn adapt_errors_never_repeat_what_caddy_printed() {
    let failed = command_failed("Error: adapting config: basic_auth secret-token-value: unknown");
    assert!(matches!(
        failed,
        CaddyScanError::AdaptFailed { exit_code: Some(1) }
    ));
    let message = failed.to_string();
    assert!(!message.contains("secret-token-value"), "{message}");
    assert!(message.contains("exit code 1"), "{message}");

    let denied =
        command_failed("Error: reading imported file: open /etc/caddy/x: Permission denied");
    assert!(matches!(denied, CaddyScanError::PermissionDenied));
    assert!(denied.to_string().contains("sudo"));
}

#[test]
fn every_collector_failure_has_its_own_error() {
    let run = |kind: ErrorKind| {
        classify_adapt_error(CollectError::Run {
            command: "caddy adapt".to_owned(),
            source: io::Error::from(kind),
        })
    };
    assert!(matches!(
        run(ErrorKind::NotFound),
        CaddyScanError::MissingCommand
    ));
    assert!(matches!(
        run(ErrorKind::PermissionDenied),
        CaddyScanError::RunFailed { .. }
    ));
    let timed_out = classify_adapt_error(CollectError::TimedOut {
        command: "caddy adapt".to_owned(),
        timeout: Duration::from_secs(10),
    });
    assert!(matches!(timed_out, CaddyScanError::TimedOut { .. }));
    assert!(timed_out.to_string().contains("10s"));
    let too_large = classify_adapt_error(CollectError::OutputTooLarge {
        command: "caddy adapt".to_owned(),
        stream: "stdout",
        limit_bytes: 8,
    });
    assert!(matches!(
        too_large,
        CaddyScanError::OutputTooLarge {
            stream: "stdout",
            limit_bytes: 8
        }
    ));
    let not_utf8 = classify_adapt_error(CollectError::NotUtf8 {
        command: "caddy adapt".to_owned(),
        source: String::from_utf8(vec![0xff]).expect_err("invalid"),
    });
    assert!(matches!(not_utf8, CaddyScanError::NotUtf8));
    assert!(matches!(
        classify_adapt_error(CollectError::UnsupportedOs { os: "plan9" }),
        CaddyScanError::UnsupportedOs { os: "plan9" }
    ));
    assert!(matches!(
        classify_adapt_error(CollectError::SockDiag {
            action: "open",
            source: io::Error::from(ErrorKind::Other),
        }),
        CaddyScanError::RunFailed { .. }
    ));
}

#[cfg(not(target_os = "linux"))]
#[test]
fn collection_needs_linux() {
    let error = super::super::collect::read(&ConfigSource::default()).expect_err("unsupported");
    assert!(matches!(error, CaddyScanError::UnsupportedOs { .. }));
    assert!(error.to_string().contains("replay"));
}
