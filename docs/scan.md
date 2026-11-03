# reachmap scan

`reachmap scan` lists every TCP socket on this host that is waiting for
connections (the LISTEN state), sorted by port, with the program behind it.

```
$ sudo reachmap scan
PORT  PROTO  ADDRESS       SERVICE
22    tcp    0.0.0.0       sshd (812)
22    tcp6   ::            sshd (812)
53    tcp    127.0.0.53    systemd-resolve (640)
631   tcp6   ::1           cupsd (1033)
3306  tcp    127.0.0.1     mysqld (1201)
8080  tcp    192.168.0.87  python3 (4410)
```

## Columns

| Column  | Meaning |
|---------|---------|
| PORT    | The TCP port the service listens on. |
| PROTO   | `tcp` for IPv4, `tcp6` for IPv6. |
| ADDRESS | The local address the socket is bound to (see below). |
| SERVICE | The program that has the socket open, as `name (pid)` (see below). |

## Reading the address

The bind address is the first clue to who can connect:

| Address | Bound to |
|---------|----------|
| `0.0.0.0`, `::` | every interface: loopback, LAN, VPN, Docker bridges |
| `127.0.0.1`, `::1`, `127.0.0.53` | loopback only: this host |
| a specific address, e.g. `192.168.0.87` | that interface only |
| `::ffff:a.b.c.d` | an IPv4 address seen through an IPv6 socket |

A `tcp6` socket bound to `::` usually accepts IPv4 connections as well (unless
the kernel setting `net.ipv6.bindv6only` is on), even though it is listed only
once, as `tcp6`. Services such as sshd open one socket per protocol, so their
port appears as both `tcp` and `tcp6`.

The address alone does not tell you whether a firewall lets traffic through.
Later versions of reachmap combine it with interfaces, Docker and UFW facts
into a verdict.

## Reading the service

The name is the short program name the kernel keeps for each process (at most
15 characters, so `systemd-resolved` shows as `systemd-resolve`). When several
processes share one socket, such as a web server and the workers it started,
the one with the lowest process ID is shown; that is usually the parent.

| SERVICE | Meaning |
|---------|---------|
| `sshd (812)` | Process 812, named `sshd`, has the socket open. |
| `unknown (run with sudo for details)` | Some processes belong to other users and could not be inspected; run `sudo reachmap scan` to see them. |
| `unknown` | No process holds the socket, even though every process was inspected. This happens for sockets the kernel opens itself (for example NFS) and for a process that exited during the scan. |

## Requirements and limits

- **Linux only for now.** On other systems `scan` prints
  `reachmap scan is Linux only for now` and exits with status 1.
- **Root shows more.** The sockets come from `/proc/net/tcp` and
  `/proc/net/tcp6`, which every user can read. Finding the process behind a
  socket means reading `/proc/<pid>/fd`, which only works for your own
  processes unless you run `scan` with `sudo`. reachmap only reads; it never
  changes anything, with or without root.
- **Hidden processes.** When `/proc` is mounted with `hidepid=2`, other users'
  processes are invisible rather than locked, so their sockets show `unknown`
  without the sudo hint. Running with `sudo` still finds them.
- **One network namespace.** `scan` sees the sockets of the namespace it runs
  in. Docker containers on their own network have separate sockets; ports
  that Docker publishes show up through `docker-proxy` on the host. Container
  details arrive in a later version.
- **TCP only.** UDP is planned for v0.2.
- When IPv6 is disabled in the kernel, `/proc/net/tcp6` does not exist and
  only IPv4 sockets are listed.

## Exit status

| Status | Meaning |
|--------|---------|
| 0 | The scan finished (also when nothing is listening). |
| 1 | The scan failed; the reason is printed on stderr. |
| 2 | Invalid arguments. |
