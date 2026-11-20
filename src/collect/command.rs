//! Running a read-only system command and capturing what it prints.

use std::io::{self, Read};
#[cfg(any(target_os = "linux", test))]
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant};

use super::CollectError;
use crate::sanitize::sanitize;

/// How often a running command is checked. Short next to what commands take,
/// long enough to cost nothing.
const POLL_INTERVAL: Duration = Duration::from_millis(5);

/// How many arguments error messages show.
const MAX_SHOWN_ARGS: usize = 4;
const MAX_PROBE_OUTPUT: u64 = 64 * 1024;

/// The first of `candidates` that is an existing file, or `fallback` when none
/// is. Running a program by absolute path keeps a directory early in `PATH`
/// from supplying its own copy, which matters under `sudo`; the fallback is
/// looked up through `PATH` for systems that keep it elsewhere.
#[cfg(any(target_os = "linux", test))]
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
/// than UTF-8 is an error, and so is one that is not done within `timeout`.
///
/// On a timeout the command is killed but not waited for, and neither are the
/// threads reading its output: a process stuck in the kernel, or a child it
/// left behind with the pipe open, could block those waits forever. Both end
/// with reachmap at the latest.
pub(super) fn run(program: &str, args: &[&str], timeout: Duration) -> Result<String, CollectError> {
    checked_output(program, args, capture(program, args, timeout, false)?)
}

/// Run a fixed-path probe without environment variables or shell configuration.
#[cfg(target_os = "linux")]
pub(crate) fn run_isolated(
    program: &str,
    args: &[&str],
    timeout: Duration,
) -> Result<String, CollectError> {
    checked_output(program, args, capture(program, args, timeout, true)?)
}

fn checked_output(program: &str, args: &[&str], output: Output) -> Result<String, CollectError> {
    if !output.status.success() {
        return Err(failed_status(program, args, &output));
    }
    decode_stdout(program, args, output.stdout)
}

/// Accepts an inventory command's extra exit status for empty or partial output.
/// Partial output and diagnostics are returned for the caller to report.
#[cfg(any(target_os = "macos", test))]
pub(super) fn run_inventory(
    program: &str,
    args: &[&str],
    timeout: Duration,
    partial_status: i32,
) -> Result<(String, Option<String>), CollectError> {
    const MAX_DIAGNOSTIC_CHARS: usize = 200;

    let output = capture(program, args, timeout, false)?;
    if !output.status.success()
        && (output.status.code() != Some(partial_status)
            || (output.stdout.is_empty() && !output.stderr.is_empty()))
    {
        return Err(failed_status(program, args, &output));
    }
    let mut detail = sanitize(String::from_utf8_lossy(&output.stderr).trim());
    if let Some((end, _)) = detail.char_indices().nth(MAX_DIAGNOSTIC_CHARS) {
        detail.truncate(end);
        detail.push_str(" (truncated)");
    }
    let partial = !output.status.success() && !output.stdout.is_empty();
    let note = match (partial, detail.is_empty()) {
        (false, true) => None,
        (false, false) => Some(detail),
        (true, true) => Some(format!("Partial inventory (exit status {partial_status}).")),
        (true, false) => Some(format!(
            "Partial inventory (exit status {partial_status}): {detail}"
        )),
    };
    Ok((decode_stdout(program, args, output.stdout)?, note))
}

fn capture(
    program: &str,
    args: &[&str],
    timeout: Duration,
    isolated: bool,
) -> Result<Output, CollectError> {
    let deadline = Instant::now() + timeout;
    let command = || describe(program, args);
    let timed_out = || CollectError::TimedOut {
        command: command(),
        timeout,
    };
    let failed_to_run = |source| CollectError::Run {
        command: command(),
        source,
    };

    let mut process = Command::new(program);
    if isolated {
        process.env_clear().env("LC_ALL", "C");
    }
    let mut child = process
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(failed_to_run)?;
    let limit = isolated.then_some(MAX_PROBE_OUTPUT);
    let stdout = read_in_background(child.stdout.take(), limit);
    let stderr = read_in_background(child.stderr.take(), limit);

    let Some(status) = wait_until(&mut child, deadline).map_err(failed_to_run)? else {
        // Failing to kill means it already exited; the timeout is still the
        // truth to report, as its output never arrived in time.
        child.kill().ok();
        return Err(timed_out());
    };
    let stdout = receive(&stdout, deadline)
        .ok_or_else(timed_out)?
        .map_err(failed_to_run)?;
    let stderr = receive(&stderr, deadline)
        .ok_or_else(timed_out)?
        .map_err(failed_to_run)?;

    Ok(Output {
        status,
        stdout,
        stderr,
    })
}

fn failed_status(program: &str, args: &[&str], output: &Output) -> CollectError {
    CollectError::CommandFailed {
        command: describe(program, args),
        status: output.status,
        stderr: sanitize(String::from_utf8_lossy(&output.stderr).trim()),
    }
}

fn decode_stdout(program: &str, args: &[&str], stdout: Vec<u8>) -> Result<String, CollectError> {
    String::from_utf8(stdout).map_err(|source| CollectError::NotUtf8 {
        command: describe(program, args),
        source,
    })
}

/// The command line for messages. Long argument lists, such as one container
/// ID per argument, are cut after [`MAX_SHOWN_ARGS`].
fn describe(program: &str, args: &[&str]) -> String {
    let shown = std::iter::once(program)
        .chain(args.iter().copied().take(MAX_SHOWN_ARGS))
        .collect::<Vec<_>>()
        .join(" ");
    match args.len().saturating_sub(MAX_SHOWN_ARGS) {
        0 => shown,
        hidden => format!("{shown} and {hidden} more arguments"),
    }
}

/// Reads `pipe` to its end on a new thread, so that a full pipe never blocks
/// the command, and sends the bytes back once it is done.
fn read_in_background(
    pipe: Option<impl Read + Send + 'static>,
    limit: Option<u64>,
) -> Receiver<io::Result<Vec<u8>>> {
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let result = pipe.map_or_else(|| Ok(Vec::new()), |pipe| read_output(pipe, limit));
        // The receiver is gone after a timeout; nobody wants the bytes then.
        sender.send(result).ok();
    });
    receiver
}

fn read_output(pipe: impl Read, limit: Option<u64>) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    pipe.take(limit.map_or(u64::MAX, |limit| limit + 1))
        .read_to_end(&mut bytes)?;
    if limit.is_some_and(|limit| bytes.len() as u64 > limit) {
        return Err(io::Error::other("probe output exceeded its size limit"));
    }
    Ok(bytes)
}

/// Waits for `child` to exit. `None` means it was still running at `deadline`.
fn wait_until(child: &mut Child, deadline: Instant) -> io::Result<Option<ExitStatus>> {
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(Some(status));
        }
        if Instant::now() >= deadline {
            return Ok(None);
        }
        thread::sleep(POLL_INTERVAL);
    }
}

/// What a reader thread sent. `None` means nothing came before `deadline`: the
/// command exited, but a child it left behind still holds the pipe open.
fn receive(
    reader: &Receiver<io::Result<Vec<u8>>>,
    deadline: Instant,
) -> Option<io::Result<Vec<u8>>> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    match reader.recv_timeout(remaining) {
        Ok(result) => Some(result),
        Err(RecvTimeoutError::Timeout) => None,
        Err(RecvTimeoutError::Disconnected) => {
            Some(Err(io::Error::other("the output reader stopped")))
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::super::test_support::TempDir;
    use super::*;
    use crate::errors::render_chain;
    use std::io::ErrorKind;
    use std::time::Instant;

    /// More than any test command needs, even on a busy machine.
    const LONG: Duration = Duration::from_secs(30);
    /// Long enough for `sh` to start, far shorter than the commands it bounds.
    const SHORT: Duration = Duration::from_millis(300);
    /// A test that took this long waited for its command instead of giving up.
    const GAVE_UP_IN_TIME: Duration = Duration::from_secs(10);

    fn assert_times_out(script: &str) {
        let started = Instant::now();

        let result = run("sh", &["-c", script], SHORT);

        assert!(
            matches!(result, Err(CollectError::TimedOut { .. })),
            "got: {result:?}"
        );
        assert!(started.elapsed() < GAVE_UP_IN_TIME);
    }

    #[test]
    fn a_command_that_hangs_times_out() {
        assert_times_out("sleep 60");
    }

    #[test]
    fn a_hung_command_is_killed() {
        let dir = TempDir::new("killed");
        let marker = dir.path().join("still-running");
        let script = format!("sleep 1; touch {}", marker.display());

        let error = run("sh", &["-c", &script], SHORT).unwrap_err();

        assert!(matches!(error, CollectError::TimedOut { .. }));
        std::thread::sleep(Duration::from_millis(1500));
        assert!(
            !marker.exists(),
            "the command kept running after the timeout"
        );
    }

    #[test]
    fn a_background_child_holding_the_pipe_cannot_hang_the_read() {
        assert_times_out("sleep 60 & exit 0");
    }

    #[test]
    fn a_timeout_names_the_command_and_the_limit() {
        let error = run("sh", &["-c", "sleep 60"], SHORT).unwrap_err();
        assert_eq!(
            render_chain(&error),
            "`sh -c sleep 60` did not finish within 300ms"
        );
    }

    #[test]
    fn output_larger_than_a_pipe_buffer_is_read_in_full() {
        let output = run("sh", &["-c", "yes x | head -c 300000"], LONG).unwrap();
        assert_eq!(output.len(), 300_000);
    }

    #[test]
    fn stderr_is_sanitised_and_kept_on_one_line() {
        let error = run(
            "sh",
            &["-c", "printf 'bad\\033[2J\\nsecond\\n' >&2; exit 1"],
            LONG,
        )
        .unwrap_err();

        assert!(
            matches!(&error, CollectError::CommandFailed { stderr, .. }
                if stderr == "bad\\u{1b}[2J\\nsecond"),
            "got: {error:?}"
        );
    }

    #[test]
    fn long_argument_lists_are_cut_in_error_messages() {
        let args = ["inspect", "--type", "container", "a", "b", "c", "d"];
        assert_eq!(
            describe("docker", &args),
            "docker inspect --type container a and 3 more arguments"
        );
    }

    #[test]
    fn short_argument_lists_are_shown_whole() {
        assert_eq!(describe("ip", &["-j", "addr"]), "ip -j addr");
    }

    #[test]
    fn returns_what_the_command_prints() {
        assert_eq!(run("sh", &["-c", "printf '[]'"], LONG).unwrap(), "[]");
    }

    #[test]
    fn inventory_distinguishes_empty_partial_and_failed_output() {
        assert_eq!(
            run_inventory("sh", &["-c", "exit 1"], LONG, 1).unwrap(),
            (String::new(), None)
        );
        assert_eq!(
            run_inventory("sh", &["-c", "printf 'rows'; exit 1"], LONG, 1).unwrap(),
            (
                "rows".to_owned(),
                Some("Partial inventory (exit status 1).".to_owned())
            )
        );
        let script = "printf 'rows'; printf 'access denied\\033[2J' >&2; exit 1";
        assert_eq!(
            run_inventory("sh", &["-c", script], LONG, 1).unwrap(),
            (
                "rows".to_owned(),
                Some("Partial inventory (exit status 1): access denied\\u{1b}[2J".to_owned())
            )
        );
        for script in ["printf 'error' >&2; exit 1", "printf 'rows'; exit 2"] {
            assert!(run_inventory("sh", &["-c", script], LONG, 1).is_err());
        }
    }

    #[test]
    fn inventory_diagnostic_truncates_long_unicode_text() {
        let diagnostic = "ø".repeat(210);
        let (_, note) = run_inventory(
            "sh",
            &["-c", "printf '%s' \"$1\" >&2", "sh", &diagnostic],
            LONG,
            1,
        )
        .unwrap();
        assert_eq!(note, Some(format!("{} (truncated)", "ø".repeat(200))));
    }

    #[test]
    fn a_failing_command_is_an_error_with_its_status_and_message() {
        let error = run(
            "sh",
            &["-c", "echo 'Object \"addr\" is unknown' >&2; exit 3"],
            LONG,
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
        let error = run("reachmap-no-such-program", &["-j", "addr"], LONG).unwrap_err();

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
        let error = run("sh", &["-c", "printf '\\377'"], LONG).unwrap_err();
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
