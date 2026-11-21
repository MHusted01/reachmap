use std::env;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU16;
use std::path::Path;
use std::time::Duration;

use clap::Args;
use thiserror::Error;

use crate::collect::{CollectError, command};
use crate::host_input_snapshot::MAX_BYTES as MAX_SNAPSHOT_BYTES;

use super::super::Flow;

pub(super) const HOST_REF: &str = "ssh-collector";
const MAX_STDERR_BYTES: u64 = 16 * 1024;

#[derive(Args)]
pub(super) struct Config {
    /// SSH hostname or numeric address, separate from the audited endpoint
    #[arg(long, value_parser = parse_host)]
    ssh_host: String,
    /// SSH login name
    #[arg(long, value_parser = parse_user)]
    ssh_user: String,
    /// SSH server port
    #[arg(long, default_value = "22")]
    ssh_port: NonZeroU16,
    /// Absolute path to the operator-provisioned known_hosts file
    #[arg(long, value_parser = parse_file)]
    known_hosts: String,
    /// Absolute path to the existing SSH identity file
    #[arg(long, value_parser = parse_file)]
    identity_file: String,
}

impl Config {
    pub(super) fn identity(&self) -> String {
        let address = match self.ssh_host.parse::<IpAddr>() {
            Ok(ip) => SocketAddr::new(ip, self.ssh_port.get()).to_string(),
            Err(_) => format!("{}:{}", self.ssh_host, self.ssh_port),
        };
        format!("{}@{address}", self.ssh_user)
    }

    pub(super) fn collect(
        &self,
        flow: &Flow,
        program: &str,
        timeout: Duration,
    ) -> Result<String, Error> {
        check_file(&self.known_hosts, "--known-hosts")?;
        check_file(&self.identity_file, "--identity-file")?;

        // OpenSSH joins the remote argv with spaces before invoking the remote
        // shell. All values in that tail are fixed literals, numeric addresses
        // or ports, or an interface name validated by Flow::new.
        let args = [
            "-F",
            "/dev/null",
            "-T",
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "CheckHostIP=no",
            "-o",
            "GlobalKnownHostsFile=none",
            "-o",
            "UpdateHostKeys=no",
            "-o",
            "VerifyHostKeyDNS=no",
            "-o",
            "ControlPath=none",
            "-o",
            "ClearAllForwardings=yes",
            "-o",
            "ForwardAgent=no",
            "-o",
            "ForwardX11=no",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "PreferredAuthentications=publickey",
            "-o",
            "ConnectTimeout=5",
            "-o",
            &format!("UserKnownHostsFile=\"{}\"", self.known_hosts),
            "-o",
            &format!("IdentityFile=\"{}\"", self.identity_file),
            "-l",
            &self.ssh_user,
            "-p",
            &self.ssh_port.to_string(),
            "--",
            &self.ssh_host,
            "/usr/local/bin/reachmap",
            "path",
            "capture",
            "--host-ref",
            HOST_REF,
            "--source",
            &flow.source.to_string(),
            "--ingress",
            &flow.ingress,
            "--destination",
            &flow.destination.to_string(),
            "--port",
            &flow.port.to_string(),
        ];

        command::run_bounded(
            program,
            &args,
            timeout,
            (MAX_SNAPSHOT_BYTES, MAX_STDERR_BYTES),
            |process| {
                // IdentitiesOnly limits the agent to the selected key.
                if let Some(socket) = env::var_os("SSH_AUTH_SOCK") {
                    process.env("SSH_AUTH_SOCK", socket);
                }
            },
        )
        .map_err(|error| match &error {
            CollectError::CommandFailed { status, .. } if status.code() == Some(255) => {
                Error::Exit255(error)
            }
            CollectError::CommandFailed { .. } => Error::Collector(error),
            _ => Error::Process(error),
        })
    }
}

#[derive(Debug, Error)]
pub(super) enum Error {
    #[error("could not read the file named by {flag}")]
    File {
        flag: &'static str,
        source: io::Error,
    },
    #[error("{0} must name a regular file")]
    NotRegular(&'static str),
    #[error("SSH or the remote collector exited with status 255")]
    Exit255(#[source] CollectError),
    #[error("the remote collector exited unsuccessfully")]
    Collector(#[source] CollectError),
    #[error("could not capture bounded SSH output")]
    Process(#[source] CollectError),
}

fn check_file(path: &str, flag: &'static str) -> Result<(), Error> {
    let metadata = std::fs::metadata(path).map_err(|source| Error::File { flag, source })?;
    if metadata.is_file() {
        Ok(())
    } else {
        Err(Error::NotRegular(flag))
    }
}

fn parse_host(text: &str) -> Result<String, &'static str> {
    let valid_label = |label: &str| {
        (1..=63).contains(&label.len())
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    };
    let hostname = text.strip_suffix('.').unwrap_or(text);
    if text.parse::<IpAddr>().is_ok()
        || (hostname.len() <= 253 && hostname.split('.').all(valid_label))
    {
        Ok(text.to_owned())
    } else {
        Err("use an SSH hostname or numeric IP address")
    }
}

fn parse_user(text: &str) -> Result<String, &'static str> {
    if (1..=64).contains(&text.len())
        && !text.starts_with(['-', '.'])
        && text
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
    {
        Ok(text.to_owned())
    } else {
        Err("use an SSH login name of letters, digits, underscores, dots or hyphens")
    }
}

fn parse_file(text: &str) -> Result<String, &'static str> {
    // OpenSSH processes quotes, substitutions and percent tokens in -o paths.
    if Path::new(text).is_absolute()
        && !text
            .chars()
            .any(|character| character.is_control() || "\"\\%$".contains(character))
    {
        Ok(text.to_owned())
    } else {
        Err(
            "use an absolute path without control characters, quotes, backslashes, percent or dollar signs",
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_file, parse_host, parse_user};

    #[test]
    fn ssh_inputs_accept_literal_hosts_and_keep_paths_with_spaces() {
        for host in ["2001:db8::10", "192.0.2.10", "server.example."] {
            assert_eq!(parse_host(host).as_deref(), Ok(host));
        }
        assert_eq!(parse_user("audit_user-1").as_deref(), Ok("audit_user-1"));
        assert_eq!(
            parse_file("/example/ssh/known hosts").as_deref(),
            Ok("/example/ssh/known hosts")
        );
    }
}
