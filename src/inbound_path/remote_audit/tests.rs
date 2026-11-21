use std::fs;
use std::io::ErrorKind;
use std::net::{IpAddr, SocketAddr, TcpListener};
use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::Parser;
use serde_json::{Value, json};

use super::{Args, run_with};
use crate::collect::test_support::TempDir;
use crate::errors::render_chain;

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(clap::Subcommand)]
enum Command {
    Audit(Args),
}

struct Fixture {
    dir: TempDir,
    listener: TcpListener,
    args: Vec<String>,
}

impl Fixture {
    fn new(name: &str, local_ip: &str) -> Self {
        let dir = TempDir::new(name);
        let ip: IpAddr = local_ip.parse().unwrap();
        let listener = TcpListener::bind((ip, 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let trust = dir.file("known hosts", "fixture");
        let identity = dir.file("identity", "fixture");
        let args = [
            "reachmap",
            "audit",
            "--ssh-user",
            "auditor",
            "--ssh-host",
            "host.example",
            "--ssh-port",
            "2222",
            "--known-hosts",
            trust.to_str().unwrap(),
            "--identity-file",
            identity.to_str().unwrap(),
            "--source",
            local_ip,
            "--ingress",
            "lo",
            "--endpoint",
            &listener.local_addr().unwrap().to_string(),
            "--confirm-direct-path",
        ]
        .map(str::to_owned)
        .to_vec();
        Self {
            dir,
            listener,
            args,
        }
    }

    fn snapshot(&self) -> Value {
        let endpoint = self.listener.local_addr().unwrap();
        let address = endpoint.ip().to_string();
        let collected = |data: Value| json!({"status": "collected", "data": data});
        let mut rules = vec![
            json!({"priority":0, "src":"all", "table":"local"}),
            json!({"priority":32766, "src":"all", "table":"main"}),
        ];
        if endpoint.is_ipv4() {
            rules.push(json!({"priority":32767, "src":"all", "table":"default"}));
        }
        let mut snapshot = json!({
            "snapshot_version": 1,
            "scope": "linux_inbound_tcp",
            "host_ref": "ssh-collector",
            "captured_at_unix_seconds": SystemTime::now()
                .duration_since(UNIX_EPOCH).unwrap().as_secs(),
            "flow": {"source": address, "ingress": "lo", "destination": address,
                     "port": endpoint.port()},
            "evidence": {
                "link": collected(json!(r#"[{"ifname":"lo","ifindex":1,"link_type":"loopback"}]"#)),
                "legacy_tables": collected(json!("")),
                "xfrm_policies": collected(json!("")),
                "xfrm_defaults": collected(json!("Default policies:\n in:  accept\n fwd:  accept\n out:  accept\n")),
                "nftables": collected(json!(r#"{"nftables":[]}"#)),
                "routing_rules": collected(json!(json!(rules).to_string())),
                "route": collected(json!(json!([{"type":"local","dst":address,"from":address,
                    "iif":"lo","dev":"lo"}]).to_string())),
                "listeners": collected(json!([{"address":address,"inode":20,
                    "options":{"bound_device":null,"ipv6_only":endpoint.is_ipv6()}}]))
            }
        });
        if endpoint.is_ipv6() {
            snapshot["evidence"]["ipv6_disabled"] = collected(json!(false));
        }
        snapshot
    }

    fn with_stdout(&self, text: &str) -> Result<(Value, u8), super::Failure> {
        self.dir.file("snapshot.json", text);
        self.run(
            "exec /bin/cat \"$folder/snapshot.json\"",
            Duration::from_secs(5),
        )
    }

    fn run(&self, body: &str, timeout: Duration) -> Result<(Value, u8), super::Failure> {
        let script = self.dir.file(
            "ssh",
            &format!(
                "#!/bin/sh\nfolder=${{0%/*}}\nprintf '%s\\n' \"$@\" > \"$folder/args\"\n{body}\n"
            ),
        );
        fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
        let Command::Audit(args) = Cli::try_parse_from(&self.args).unwrap().command;
        run_with(args, script.to_str().unwrap(), timeout)
            .map(|(text, status)| (serde_json::from_str(&text).unwrap(), status))
    }

    fn assert_did_not_probe(&self) {
        assert_eq!(
            self.listener.accept().unwrap_err().kind(),
            ErrorKind::WouldBlock
        );
    }
}

#[test]
fn one_confirmed_endpoint_reuses_the_bound_source_after_ssh_capture() {
    for (name, ip) in [
        ("audit-loopback-v4", "127.0.0.1"),
        ("audit-loopback-v6", "::1"),
    ] {
        let fixture = Fixture::new(name, ip);
        let (report, status) = fixture
            .with_stdout(&fixture.snapshot().to_string())
            .unwrap();
        assert_eq!(status, 0, "{report}");
        assert_eq!(report["comparison"]["status"], "consistent");
        assert_eq!(report["prediction"]["verdict"], "listener_reachable");
        assert_eq!(report["observation"]["outcome"]["kind"], "open");
        let (_, peer) = fixture.listener.accept().unwrap();
        assert_eq!(
            peer,
            report["client_bind"]
                .as_str()
                .unwrap()
                .parse::<SocketAddr>()
                .unwrap()
        );
        fixture.assert_did_not_probe();
        let args = fs::read_to_string(fixture.dir.path().join("args")).unwrap();
        let remote_port = fixture.listener.local_addr().unwrap().port().to_string();
        assert_eq!(
            args.lines().collect::<Vec<_>>(),
            [
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
                &format!(
                    "UserKnownHostsFile=\"{}/known hosts\"",
                    fixture.dir.path().display()
                ),
                "-o",
                &format!("IdentityFile=\"{}/identity\"", fixture.dir.path().display()),
                "-l",
                "auditor",
                "-p",
                "2222",
                "--",
                "host.example",
                "/usr/local/bin/reachmap",
                "path",
                "capture",
                "--host-ref",
                "ssh-collector",
                "--source",
                ip,
                "--ingress",
                "lo",
                "--destination",
                ip,
                "--port",
                &remote_port,
            ]
        );
    }
}

#[test]
fn no_probe_follows_failed_authentication_or_nonzero_collector_exit() {
    let fixture = Fixture::new("audit-status", "127.0.0.1");
    for (exit, detail) in [
        (255, "Host key verification failed."),
        (255, "ssh: Connection refused"),
        (255, "collector: unexpected exit"),
        (1, "collector: Permission denied"),
    ] {
        let body = format!("printf '%s\\n' '{detail}' >&2; exit {exit}");
        let error = fixture.run(&body, Duration::from_secs(5)).unwrap_err();
        let message = render_chain(&error);
        assert!(message.contains(detail), "{message}");
        if exit == 255 {
            assert!(message.contains("SSH or the remote collector exited with status 255"));
        }
        fixture.assert_did_not_probe();
    }
}

#[test]
fn invalid_incompatible_or_wrong_flow_captures_prevent_the_probe() {
    let fixture = Fixture::new("audit-invalid", "127.0.0.1");
    let mut wrong_flow = fixture.snapshot();
    wrong_flow["flow"]["ingress"] = json!("eth1");
    for (text, expected) in [
        ("not JSON".to_owned(), "invalid inbound TCP snapshot"),
        (
            r#"{"scope":"linux_inbound_tcp","snapshot_version":2}"#.to_owned(),
            "unsupported inbound TCP snapshot version 2",
        ),
        (wrong_flow.to_string(), "different TCP flow"),
    ] {
        let error = fixture.with_stdout(&text).unwrap_err();
        assert!(render_chain(&error).contains(expected), "{error:?}");
        fixture.assert_did_not_probe();
    }
}

#[test]
fn partial_evidence_preserves_permission_diagnostics_and_the_actual_observation() {
    let fixture = Fixture::new("audit-partial", "127.0.0.1");
    let mut snapshot = fixture.snapshot();
    snapshot["evidence"]["nftables"] = json!({
        "status":"failed", "reason":"nft: Operation not permitted"
    });
    let (report, status) = fixture.with_stdout(&snapshot.to_string()).unwrap();
    assert_eq!(status, 2);
    assert_eq!(report["comparison"]["reason"], "prediction_inconclusive");
    assert_eq!(report["observation"]["outcome"]["kind"], "open");
    assert_eq!(
        report["evidence_gaps"],
        json!([
            {"collector": "nftables", "reason": "nft: Operation not permitted"}
        ])
    );
    fixture.listener.accept().unwrap();
}

#[test]
fn a_handshake_that_disagrees_with_the_prediction_exits_one() {
    let fixture = Fixture::new("audit-disagreement", "127.0.0.1");
    let mut snapshot = fixture.snapshot();
    snapshot["evidence"]["listeners"]["data"] = json!([]);
    let (report, status) = fixture.with_stdout(&snapshot.to_string()).unwrap();
    assert_eq!(status, 1);
    assert_eq!(report["prediction"]["verdict"], "no_listener");
    assert_eq!(report["observation"]["outcome"]["kind"], "open");
    assert_eq!(report["comparison"]["status"], "disagrees");
    fixture.listener.accept().unwrap();
}

#[test]
fn a_hanging_transport_and_oversized_streams_prevent_the_probe() {
    let fixture = Fixture::new("audit-bounds", "127.0.0.1");
    for (body, limit, expected) in [
        (
            "exec /bin/sleep 20",
            Duration::from_millis(200),
            "did not finish",
        ),
        (
            "/usr/bin/head -c 67108865 /dev/zero",
            Duration::from_secs(10),
            "output exceeded",
        ),
        (
            "/usr/bin/head -c 16385 /dev/zero >&2",
            Duration::from_secs(5),
            "output exceeded",
        ),
    ] {
        let error = fixture.run(body, limit).unwrap_err();
        assert!(render_chain(&error).contains(expected), "{error:?}");
        fixture.assert_did_not_probe();
    }
}

#[test]
fn a_missing_confirmation_or_invalid_ssh_argument_fails_before_execution() {
    let fixture = Fixture::new("audit-confirm", "127.0.0.1");
    for (flag, value) in [
        ("--ssh-host", "host.example; id"),
        ("--ssh-user", "auditor@other.example"),
        ("--ingress", "lo; id"),
        ("--known-hosts", "/tmp/%h"),
        ("--endpoint", "127.0.0.1:100-200"),
    ] {
        let mut args = fixture.args.clone();
        let index = args.iter().position(|arg| arg == flag).unwrap();
        args[index + 1] = value.to_owned();
        assert!(
            Cli::try_parse_from(args).is_err(),
            "{flag} accepted {value}"
        );
    }
    assert!(Cli::try_parse_from(&fixture.args[..fixture.args.len() - 1]).is_err());
}
