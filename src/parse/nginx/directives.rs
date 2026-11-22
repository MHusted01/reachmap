//! Directive classification, location headers, and include-glob matching.

use std::borrow::Cow;

use crate::nginx::{AuthSignals, LocationModifier, SslVerifyClient, Uncertainty, UncertaintyKind};
use crate::sanitize::sanitize;

use super::listen::push_uncertainty;
use super::parser::Directive;

#[derive(Clone, Copy)]
pub(super) enum ScopeKind {
    Http,
    Server,
    Location,
}

pub(super) enum LocationHeader {
    Parsed(LocationModifier, String),
    Regex,
    Named,
    Invalid,
}

pub(super) fn parse_location_header(args: &[Cow<'_, str>]) -> LocationHeader {
    match args {
        [path] => {
            let raw = path.as_ref();
            if raw.starts_with('@') {
                LocationHeader::Named
            } else if raw.is_empty() {
                LocationHeader::Invalid
            } else {
                LocationHeader::Parsed(LocationModifier::Prefix, sanitize(raw))
            }
        }
        [modifier, path] => {
            let path_raw = path.as_ref();
            if path_raw.is_empty() {
                return LocationHeader::Invalid;
            }
            match modifier.as_ref() {
                "=" => LocationHeader::Parsed(LocationModifier::Exact, sanitize(path_raw)),
                "^~" => {
                    LocationHeader::Parsed(LocationModifier::PreferentialPrefix, sanitize(path_raw))
                }
                "~" | "~*" => LocationHeader::Regex,
                _ => LocationHeader::Invalid,
            }
        }
        _ => LocationHeader::Invalid,
    }
}

pub(super) fn apply_shared_directive(
    directive: &Directive<'_>,
    source_file: Option<&str>,
    auth: &mut AuthSignals,
    scope: ScopeKind,
    uncertainties: &mut Vec<Uncertainty>,
) {
    let name = directive.name.as_ref();
    match name {
        "auth_basic" => match directive.args.first().map(Cow::as_ref) {
            Some("off") if directive.args.len() == 1 => auth.auth_basic = Some(false),
            Some(_) if directive.args.len() == 1 => auth.auth_basic = Some(true),
            _ => push_uncertainty(
                uncertainties,
                UncertaintyKind::InvalidDirective,
                "auth_basic",
                source_file,
                directive.line,
            ),
        },
        "auth_request" => match directive.args.first().map(Cow::as_ref) {
            Some("off") if directive.args.len() == 1 => auth.auth_request = false,
            Some(_) if directive.args.len() == 1 => {
                auth.auth_request = true;
                push_uncertainty(
                    uncertainties,
                    UncertaintyKind::SubrequestAuth,
                    "auth_request",
                    source_file,
                    directive.line,
                );
            }
            _ => push_uncertainty(
                uncertainties,
                UncertaintyKind::InvalidDirective,
                "auth_request",
                source_file,
                directive.line,
            ),
        },
        "ssl_verify_client" => match directive.args.first().map(Cow::as_ref) {
            Some("off") if directive.args.len() == 1 => {
                auth.ssl_verify_client = Some(SslVerifyClient::Off);
            }
            Some("on") if directive.args.len() == 1 => {
                auth.ssl_verify_client = Some(SslVerifyClient::On);
            }
            Some("optional") if directive.args.len() == 1 => {
                auth.ssl_verify_client = Some(SslVerifyClient::Optional);
            }
            Some("optional_no_ca") if directive.args.len() == 1 => {
                auth.ssl_verify_client = Some(SslVerifyClient::OptionalNoCa);
            }
            _ => push_uncertainty(
                uncertainties,
                UncertaintyKind::InvalidDirective,
                "ssl_verify_client",
                source_file,
                directive.line,
            ),
        },
        "allow" | "deny" => {
            auth.access_control = true;
            push_uncertainty(
                uncertainties,
                UncertaintyKind::AccessControl,
                name,
                source_file,
                directive.line,
            );
        }
        "limit_except" if matches!(scope, ScopeKind::Location) => {
            push_uncertainty(
                uncertainties,
                UncertaintyKind::DynamicControlFlow,
                name,
                source_file,
                directive.line,
            );
        }
        _ if is_secret_bearing(name) || is_benign_http_directive(name) => {}
        _ => record_common_uncertainty(name, source_file, directive.line, uncertainties),
    }
}

pub(super) fn record_common_uncertainty(
    name: &str,
    source_file: Option<&str>,
    line: usize,
    uncertainties: &mut Vec<Uncertainty>,
) {
    let kind = match name {
        "if" | "return" => UncertaintyKind::DynamicControlFlow,
        "rewrite" | "try_files" | "error_page" => UncertaintyKind::DynamicRouting,
        "map" | "geo" | "split_clients" => UncertaintyKind::DynamicVariable,
        "stream" | "mail" => UncertaintyKind::UnsupportedContext,
        "fastcgi_pass" | "grpc_pass" | "uwsgi_pass" | "scgi_pass" | "memcached_pass" => {
            UncertaintyKind::UnsupportedBackend
        }
        _ => UncertaintyKind::UnmodeledDirective,
    };
    push_uncertainty(uncertainties, kind, name, source_file, line);
}

pub(super) fn resolve_relative_pattern(source_file: Option<&str>, pattern: &str) -> Option<String> {
    if pattern.starts_with('/') {
        return None;
    }
    let dir = source_file?.rsplit_once('/')?.0;
    if dir.is_empty() {
        Some(format!("/{pattern}"))
    } else {
        Some(format!("{dir}/{pattern}"))
    }
}

pub(super) fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star_p, mut star_t) = (None, 0usize);

    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star_p = Some(pi);
            pi += 1;
            star_t = ti;
        } else if let Some(sp) = star_p {
            pi = sp + 1;
            star_t += 1;
            ti = star_t;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

pub(super) fn is_secret_bearing(name: &str) -> bool {
    matches!(
        name,
        "proxy_set_header"
            | "add_header"
            | "ssl_certificate_key"
            | "ssl_password_file"
            | "auth_basic_user_file"
            | "env"
            | "proxy_pass_header"
            | "proxy_hide_header"
            | "ssl_certificate"
            | "ssl_trusted_certificate"
            | "ssl_client_certificate"
            | "ssl_crl"
            | "ssl_dhparam"
    )
}

pub(super) fn is_benign_top_level(name: &str) -> bool {
    matches!(
        name,
        "user"
            | "worker_processes"
            | "worker_rlimit_nofile"
            | "worker_cpu_affinity"
            | "pid"
            | "lock_file"
            | "error_log"
            | "events"
            | "pcre_jit"
            | "daemon"
            | "master_process"
            | "load_module"
    )
}

pub(super) fn is_benign_upstream_directive(name: &str) -> bool {
    matches!(
        name,
        "least_conn"
            | "ip_hash"
            | "hash"
            | "random"
            | "keepalive"
            | "keepalive_requests"
            | "keepalive_time"
            | "keepalive_timeout"
            | "zone"
    )
}

fn is_benign_http_directive(name: &str) -> bool {
    matches!(
        name,
        "access_log"
            | "error_log"
            | "log_format"
            | "sendfile"
            | "tcp_nopush"
            | "tcp_nodelay"
            | "keepalive_timeout"
            | "keepalive_requests"
            | "types_hash_max_size"
            | "server_tokens"
            | "types"
            | "default_type"
            | "gzip"
            | "ssl_protocols"
            | "ssl_ciphers"
            | "ssl_prefer_server_ciphers"
            | "ssl_ecdh_curve"
            | "ssl_verify_depth"
            | "client_max_body_size"
            | "proxy_http_version"
            | "proxy_read_timeout"
            | "proxy_connect_timeout"
            | "proxy_send_timeout"
            | "proxy_buffering"
            | "proxy_buffer_size"
            | "proxy_buffers"
            | "proxy_busy_buffers_size"
            | "proxy_redirect"
            | "charset"
            | "index"
            | "root"
            | "large_client_header_buffers"
            | "server_names_hash_bucket_size"
            | "variables_hash_max_size"
            | "send_timeout"
            | "reset_timedout_connection"
    ) || name.starts_with("gzip_")
        || name.starts_with("ssl_session_")
        || name.starts_with("ssl_stapling")
        || name.starts_with("client_body_")
        || name.starts_with("client_header_")
        || name.starts_with("proxy_ssl_")
        || name.starts_with("proxy_next_upstream")
        || name.starts_with("open_file_cache")
        || name.starts_with("lingering_")
}
