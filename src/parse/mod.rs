//! Pure parsers: text or bytes in, typed values out. No file or system access here,
//! so every parser is tested on any OS with fixture files.

pub mod docker;
pub mod ip_addr;
pub mod iptables;
pub mod probe_args;
pub mod proc_net;
pub mod proc_pid;
pub mod proc_self;
pub mod sock_diag;
pub mod tailscale;
pub mod ufw;
