//! Pure parsers: text in, typed values out. No file or system access here,
//! so every parser is tested on any OS with fixture files.

pub mod docker;
pub mod ip_addr;
pub mod iptables;
pub mod proc_net;
pub mod proc_pid;
pub mod ufw;
