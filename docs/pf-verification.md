# Verify macOS pf verdicts

Use a fresh, disposable GitHub-hosted macOS runner to verify `reachmap scan`
verdicts against real `pf` packet filtering and live TCP/UDP connection
attempts. Never run the lab on a developer workstation or production Mac.
`reachmap` itself stays strictly read-only: only [test-pf.sh](../scripts/test-pf.sh)
modifies `pf` rules inside a dedicated test anchor and restores the runner's
original `pf` state on exit.

## Run the disposable macOS lab

Trigger the manually dispatched workflow [.github/workflows/pf-lab.yml](../.github/workflows/pf-lab.yml)
on GitHub Actions:

```sh
gh workflow run pf-lab.yml --ref main
```

The workflow checks out the repository with `contents: read` permissions and no
secrets, builds `reachmap`, and runs `scripts/test-pf.sh target/debug/reachmap`
on `macos-26`.

To reproduce the lab inside a disposable local macOS VM, pass `--allow-pf-changes`
explicitly (without it or `GITHUB_ACTIONS=true`, the script exits immediately
without calling `pfctl`):

```sh
cargo build --locked
scripts/test-pf.sh --allow-pf-changes target/debug/reachmap
```

All test rules scope strictly to loopback interface `lo0` and a temporary alias
`127.0.0.2` on ports `24443` and `24444` inside the `reachmap-test` anchor, so
traffic on other interfaces is unaffected. On exit, the cleanup trap stops the
test listeners, flushes `reachmap-test` and state entries, reloads
`/etc/pf.conf`, restores the initial `pf` enabled/disabled status, and removes
the temporary loopback alias.

## Test matrix

Every case runs against both TCP and UDP echo listeners bound to `127.0.0.2` and
compares the `lo0` verdict in `reachmap scan --json` with an observed loopback
connection attempt. Any mismatch fails the script with both values printed.

| Case | Ruleset configuration | Expected `reachmap` verdict | Observed probe | What it verifies |
| --- | --- | --- | --- | --- |
| 1. `pf` disabled | `pfctl -d` | `macos.pf.status == "disabled"` | `open` (TCP & UDP `24443`, `24444`) | Disabled `pf` does not claim filtering and leaves loopback reachable |
| 2. Default anchors | Stock `/etc/pf.conf` enabled | `pass` on `lo0` (TCP & UDP `24443`, `24444`) | `open` | Default `com.apple/*` anchor tree evaluates cleanly without false blocks |
| 3. `block in` + `pass` exception | `block in on lo0 ... to 127.0.0.2` with `pass in ... port 24443` | `pass` on `24443`, `block` on `24444` | `open` on `24443`, `blocked` on `24444` | Default block and port-specific pass exception agree for TCP and UDP |
| 4. `quick` ordering | `block in quick ... port 24444` before `pass`; non-quick `block` before `pass` on `24443` | `pass` on `24443`, `block` on `24444` | `open` on `24443`, `blocked` on `24444` | `quick` short-circuits later rules while non-quick follows last-match-wins |
| 5. `set skip on lo0` | `set skip on lo0` in main ruleset with `block in on lo0` in anchor | `pass` (`set skip`) on `24443` and `24444` | `open` on both ports | Skipped loopback interface bypasses filter rules in both `pf` and `reachmap` |
| 6. Table rule | `pass in quick ... port 24443`; `block in ... to <lab_targets> port 24444` | `pass` on `24443`, `unknown` (`table`) on `24444` | `open` on `24443`, `blocked` on `24444` | Unmodeled `<table>` addresses fail closed as `unknown` rather than guessing |
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
Verified macOS (`sw_vers`, `uname -a`), `pfctl`, and `reachmap` versions will be
recorded here after the first post-merge `workflow_dispatch` run on `main`.
