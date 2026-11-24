# Verify macOS pf verdicts

Use a fresh, disposable GitHub-hosted macOS runner to verify `reachmap scan`
verdicts against real `pf` packet filtering and live TCP/UDP connection
attempts. Never run the lab on a developer workstation or production Mac.
`reachmap` itself stays strictly read-only: only [test-pf.sh](../scripts/test-pf.sh)
modifies `pf` rules inside a dedicated test anchor and restores the stock
runner `pf` state on exit.

## Run the disposable macOS lab

Trigger the manually dispatched workflow [.github/workflows/pf-lab.yml](../.github/workflows/pf-lab.yml)
on GitHub Actions:

```sh
gh workflow run pf-lab.yml --ref main
```

The workflow checks out the repository with `contents: read` permissions and no
secrets, builds `reachmap`, and runs `scripts/test-pf.sh target/debug/reachmap`
on `macos-26`.

Automatic execution is limited to GitHub-hosted runners (`GITHUB_ACTIONS=true`
and `RUNNER_ENVIRONMENT=github-hosted`). To reproduce the lab inside a
disposable local macOS VM with a stock `/etc/pf.conf` baseline, pass
`--allow-pf-changes` explicitly:

```sh
cargo build --locked
scripts/test-pf.sh --allow-pf-changes target/debug/reachmap
```

Before changing anything, the script verifies that only the stock `com.apple`
anchors and rules are active and refuses to run against a custom ruleset.
All test rules scope strictly to loopback interface `lo0` and temporary alias
`127.0.0.2` (either matching all ports on `127.0.0.2` in Cases 3 and 5, or
ports `24443` and `24444` specifically; Case 5 also applies `set skip on lo0`)
inside the `reachmap-test` anchor, so traffic on `en0` and `127.0.0.1` stays
unaffected. On exit (including `INT`/`TERM`), cleanup stops the test listeners,
flushes `reachmap-test`, kills only `127.0.0.2` state entries via `pfctl -k`,
reloads `/etc/pf.conf`, verifies the original `pf` enabled/disabled status is
restored, removes the temporary loopback alias, and fails the run if any
restoration step fails.

## Expected test matrix (unverified until first runner dispatch)

Every case runs against live TCP and UDP echo listeners bound to `127.0.0.2`
and compares the `lo0` verdict in `reachmap scan --json` with an observed
loopback connection attempt. Unexpected probe errors fail immediately rather
than counting as `blocked`, and expected drops are corroborated against
incremented `pfctl -a reachmap-test -v -sr` packet counters.

| Case | Ruleset configuration | Expected `reachmap` verdict | Expected probe | What it verifies |
| --- | --- | --- | --- | --- |
| 1. `pf` disabled | `pfctl -d` | `macos.pf.status == "disabled"` | `open` (TCP & UDP `24443`, `24444`) | Disabled `pf` does not claim filtering and leaves loopback reachable |
| 2. Default anchors | Stock `/etc/pf.conf` enabled | `pass` on `lo0` (TCP & UDP `24443`, `24444`) | `open` | Default `com.apple/*` anchor tree evaluates cleanly without false blocks |
| 3. `block in` + `pass` exception | `block drop in on lo0 ... to 127.0.0.2` with `pass in ... port 24443` | `pass` on `24443`, `block` on `24444` | `open` on `24443`, `blocked` on `24444` | Default block and port-specific pass exception agree for TCP and UDP |
| 4. `quick` ordering | `block drop in quick ... port 24444` before `pass`; non-quick `block` before `pass` on `24443` | `pass` on `24443`, `block` on `24444` | `open` on `24443`, `blocked` on `24444` | `quick` short-circuits later rules while non-quick follows last-match-wins |
| 5. `set skip on lo0` | `set skip on lo0` in main ruleset with `block drop in on lo0 ... to 127.0.0.2` in anchor | `pass` (`set skip`) on `24443` and `24444` | `open` on both ports | Skipped loopback interface bypasses filter rules in both `pf` and `reachmap` |
| 6. Table rule | `pass in quick ... port 24443`; `block drop in ... to <lab_targets> port 24444` | `pass` on `24443`, `unknown` (`table`) on `24444` | `open` on `24443`, `blocked` on `24444` | Unmodeled `<table>` addresses fail closed as `unknown` rather than guessing |
| 7. Unprivileged scan | `pf` enabled (Case 3 rules), `reachmap scan --json` run without `sudo` | `macos.pf.status == "unknown"` (reason cites `sudo` / root privileges) | `open` on `24443`, `blocked` on `24444` | Missing `/dev/pf` permission surfaces an explicit evidence gap instead of `pass` |

## Scope and evidence limits

- **Loopback ingress only.** The lab exercises `127.0.0.2` on `lo0` so it never
  interferes with the runner's external network interface (`en0`) or SSH/runner
  control plane. Non-loopback weak-host multi-interface ingress, link-local IPv6
  zones, and IPv4 wildcard UDP broadcast rules are verified separately by unit
  and fixture tests.
- **IPv4 test sockets.** Live runner checks cover IPv4 TCP and UDP sockets; IPv6
  pf rules and `IPV6_V6ONLY` uncertainty are covered by unit tests over recorded
  fixtures.
- **Unmodeled `pf` constructs.** Features outside the evaluator's supported
  subset—such as tables, source address/port restrictions, `rdr`/`nat`/`binat`
  translation rules, inline anchors, dynamic `(iface)` addresses, interface
  groups, user/group/OS-fingerprint filters, and state limits—intentionally
  produce `unknown` rather than guessing.
- **Application firewall separation.** `reachmap` reports the macOS Application
  Firewall global state separately from `pf`; per-app Application Firewall rules
  are outside scope.

## Verification record

Target runner: GitHub Actions `macos-26` via `.github/workflows/pf-lab.yml`.
This document is still unverified against a live runner: `workflow_dispatch`
requires `.github/workflows/pf-lab.yml` on `main` before it can run. The first
post-merge run on `main` will record the verified `sw_vers`, `uname -a`,
`/sbin/pfctl` binary identity, `reachmap` version, and workflow run URL here.
