//! Running a read-only system command and capturing what it prints.

use std::path::Path;
use std::process::{Command, Stdio};

use super::CollectError;

/// The first of `candidates` that is an existing file, or `fallback` when none
/// is. Running a program by absolute path keeps a directory early in `PATH`
/// from supplying its own copy, which matters under `sudo`; the fallback is
/// looked up through `PATH` for systems that keep it elsewhere.
pub(super) fn locate<'a>(candidates: &[&'a str], fallback: &'a str) -> &'a str {
    candidates
        .iter()
        .copied()
        .find(|path| Path::new(path).is_file())
        .unwrap_or(fallback)
}

/// Runs `program` with `args` and returns its standard output. Standard input
/// is `/dev/null`, so the command cannot wait for input. A command that
/// cannot be started, exits with a failure status, or prints something other
/// than UTF-8 is an error.
///
/// There is no timeout: the only caller runs `ip -j addr`, which asks the
/// kernel over netlink and does no network or DNS lookups, so it returns at
/// once. A command that can block would need one.
pub(super) fn run(program: &str, args: &[&str]) -> Result<String, CollectError> {
    let command = || {
        std::iter::once(program)
            .chain(args.iter().copied())
            .collect::<Vec<_>>()
            .join(" ")
    };
    let output = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .map_err(|source| CollectError::Run {
            command: command(),
            source,
        })?;
    if !output.status.success() {
        return Err(CollectError::CommandFailed {
            command: command(),
            status: output.status,
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        });
    }
    String::from_utf8(output.stdout).map_err(|source| CollectError::NotUtf8 {
        command: command(),
        source,
    })
}

#[cfg(all(test, unix))]
mod tests {
    use super::super::test_support::TempDir;
    use super::*;
    use crate::errors::render_chain;
    use std::io::ErrorKind;

    #[test]
    fn returns_what_the_command_prints() {
        assert_eq!(run("sh", &["-c", "printf '[]'"]).unwrap(), "[]");
    }

    #[test]
    fn a_failing_command_is_an_error_with_its_status_and_message() {
        let error = run(
            "sh",
            &["-c", "echo 'Object \"addr\" is unknown' >&2; exit 3"],
        )
        .unwrap_err();

        assert!(matches!(
            &error,
            CollectError::CommandFailed { status, .. } if status.code() == Some(3)
        ));
        assert_eq!(
            render_chain(&error),
            "`sh -c echo 'Object \"addr\" is unknown' >&2; exit 3` failed with exit status: 3: \
             Object \"addr\" is unknown"
        );
    }

    #[test]
    fn a_missing_program_is_an_error_naming_the_command() {
        let error = run("reachmap-no-such-program", &["-j", "addr"]).unwrap_err();

        assert!(matches!(
            &error,
            CollectError::Run { source, .. } if source.kind() == ErrorKind::NotFound
        ));
        assert!(
            render_chain(&error).starts_with("could not run `reachmap-no-such-program -j addr`: "),
            "got: {}",
            render_chain(&error)
        );
    }

    #[test]
    fn output_that_is_not_utf8_is_an_error() {
        let error = run("sh", &["-c", "printf '\\377'"]).unwrap_err();
        assert!(matches!(error, CollectError::NotUtf8 { .. }));
    }

    #[test]
    fn locate_returns_the_first_existing_candidate() {
        let dir = TempDir::new("locate-first");
        let second = dir.file("bin/ip", "");
        let third = dir.file("usr/bin/ip", "");
        let missing = dir.path().join("sbin/ip");
        let candidates = [
            missing.to_str().unwrap(),
            second.to_str().unwrap(),
            third.to_str().unwrap(),
        ];

        assert_eq!(locate(&candidates, "ip"), second.to_str().unwrap());
    }

    #[test]
    fn locate_skips_directories_and_falls_back_when_nothing_exists() {
        let dir = TempDir::new("locate-fallback");
        let not_a_file = dir.path().to_str().unwrap();
        let missing = dir.path().join("ip");

        assert_eq!(locate(&[not_a_file, missing.to_str().unwrap()], "ip"), "ip");
        assert_eq!(locate(&[], "ip"), "ip");
    }
}
