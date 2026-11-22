//! Secret-minimized domain model for a bounded subset of Nginx configuration.
//!
//! Parsing lives in [`crate::parse::nginx`]. Types here capture only routing,
//! listener, upstream, proxy-layer authentication/ACL presence indicators, and
//! explicit uncertainties—never raw configuration text, comments, credentials,
//! headers, key/password paths, or response bodies.

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use serde::{Deserialize, Serialize};

pub mod audit;
pub mod routes;

/// Minimized route, upstream, and uncertainty summary extracted from an
/// expanded `nginx -T` configuration dump.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NginxConfig {
    /// Parsed `http` server blocks in configuration order.
    pub servers: Vec<ServerBlock>,
    /// Named static `upstream` groups referenced or defined in `http` scope.
    pub upstreams: Vec<UpstreamGroup>,
    /// Explicit uncertainties where dynamic, unsupported, or unmodeled
    /// constructs could alter routing or access.
    pub uncertainties: Vec<Uncertainty>,
}

/// One `server {}` block inside `http` scope.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerBlock {
    /// Sanitized path of the file that defined this block, when known.
    pub source_file: Option<String>,
    /// Parsed `listen` endpoints configured on this server.
    pub listens: Vec<ListenEndpoint>,
    /// Parsed `server_name` matchers configured on this server.
    pub server_names: Vec<ServerName>,
    /// Modeled `location` routes within this server.
    pub locations: Vec<LocationRoute>,
    /// Proxy-layer authentication and access-control presence indicators.
    pub auth: AuthSignals,
}

/// One parsed `listen` directive endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListenEndpoint {
    /// Bound IP address or family wildcard.
    pub address: ListenAddress,
    /// Listening TCP port.
    pub port: u16,
    /// Whether `ssl` was enabled on this `listen` directive.
    pub ssl: bool,
    /// Whether `default_server` (or `default`) was set.
    pub default_server: bool,
    /// Explicit `ipv6only=on` (`Some(true)`) or `ipv6only=off` (`Some(false)`).
    pub ipv6only: Option<bool>,
}

/// Bound address of a [`ListenEndpoint`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ListenAddress {
    /// Wildcard IPv4 bind (`0.0.0.0` or omitted address).
    AnyIpv4 {},
    /// Wildcard IPv6 bind (`[::]`).
    AnyIpv6 {},
    /// Specific IPv4 address.
    Ipv4 {
        /// Bound IPv4 address.
        ip: Ipv4Addr,
    },
    /// Specific IPv6 address.
    Ipv6 {
        /// Bound IPv6 address.
        ip: Ipv6Addr,
    },
}

/// Modeled `server_name` entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ServerName {
    /// Exact lowercase host name, e.g. `app.example.test`.
    Exact {
        /// Sanitized host name.
        host: String,
    },
    /// Leading wildcard host name, e.g. `*.example.test` or `.example.test`.
    LeadingWildcard {
        /// Sanitized suffix after the leading `*` or `.`.
        suffix: String,
    },
    /// Trailing wildcard host name, e.g. `app.*`.
    TrailingWildcard {
        /// Sanitized prefix before the trailing `.*`.
        prefix: String,
    },
    /// Catch-all server name (`_` or `""`).
    CatchAll {},
}

/// One modeled `location` block inside a [`ServerBlock`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocationRoute {
    /// Sanitized path of the file that defined this location, when known.
    pub source_file: Option<String>,
    /// Nginx location matching modifier.
    pub modifier: LocationModifier,
    /// Sanitized URI path prefix or exact match string.
    pub path: String,
    /// Parsed `proxy_pass` target, if present in this location.
    pub target: Option<ProxyTarget>,
    /// Effective proxy-layer authentication and ACL indicators (including inherited server/http signals).
    pub auth: AuthSignals,
}

/// Matching precedence modifier for a `location` directive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocationModifier {
    /// Exact match (`location = /path`).
    Exact,
    /// Preferential prefix match (`location ^~ /path`).
    PreferentialPrefix,
    /// Standard prefix match (`location /path`).
    Prefix,
}

/// Transport scheme of a `proxy_pass` URL.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProxyScheme {
    /// Plain HTTP upstream (`http://`).
    Http,
    /// TLS-encrypted upstream (`https://`).
    Https,
}

/// Backend target parsed from a `proxy_pass` directive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProxyTarget {
    /// Static HTTP or HTTPS IP/localhost target.
    ///
    /// When the target host is `localhost`, `targets` lists both `127.0.0.1`
    /// and `[::1]` without performing host DNS/NSS resolution; listener
    /// correlation must verify which address families actually bind locally.
    StaticHttp {
        /// Upstream scheme.
        scheme: ProxyScheme,
        /// Sanitized `scheme://authority[/path]` without credentials, query, or fragment.
        endpoint: String,
        /// Resolved socket addresses (`localhost` assumes both IPv4 and IPv6 loopback).
        targets: Vec<SocketAddr>,
    },
    /// Reference to a static named `upstream` group.
    Upstream {
        /// Upstream scheme.
        scheme: ProxyScheme,
        /// Sanitized upstream block name.
        name: String,
        /// Active (`!down`) static socket targets collected from the upstream group.
        targets: Vec<SocketAddr>,
        /// Whether every `server` entry in the upstream group resolved statically.
        complete: bool,
    },
    /// Static HTTP/HTTPS target using a non-IP hostname that requires DNS resolution.
    UnresolvedHost {
        /// Upstream scheme.
        scheme: ProxyScheme,
        /// Sanitized hostname.
        host: String,
        /// Explicit or scheme-default port.
        port: u16,
    },
    /// Dynamic, non-HTTP, Unix-socket, or malformed `proxy_pass` target.
    Unsupported {
        /// Classification of why the target could not be statically resolved.
        reason: UnsupportedProxyReason,
    },
}

/// Reason a `proxy_pass` target is classified as [`ProxyTarget::Unsupported`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnsupportedProxyReason {
    /// Target contains an Nginx `$variable`.
    Variable,
    /// Target points to a `unix:` socket path.
    UnixSocket,
    /// Target uses an unsupported URL scheme.
    UnsupportedScheme,
    /// Target could not be parsed as a valid URL or host/port.
    InvalidTarget,
}

/// Named `upstream {}` block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpstreamGroup {
    /// Sanitized path of the file that defined this upstream, when known.
    pub source_file: Option<String>,
    /// Sanitized upstream group name.
    pub name: String,
    /// Statically resolved upstream server entries.
    pub servers: Vec<UpstreamServer>,
    /// `true` when all directives in the upstream block resolved statically.
    pub complete: bool,
}

/// One statically resolved `server` directive inside an [`UpstreamGroup`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpstreamServer {
    /// Resolved socket addresses (`localhost` assumes both `127.0.0.1` and `[::1]`
    /// without host DNS/NSS lookup; verify bound families against local sockets).
    pub targets: Vec<SocketAddr>,
    /// Whether `backup` was specified.
    pub backup: bool,
    /// Whether `down` was specified.
    pub down: bool,
}

/// Proxy-layer authentication and access-control presence signals.
///
/// Only boolean/enum presence is recorded—realm strings, user file paths, and
/// CIDR rules are discarded at parse time.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthSignals {
    /// `Some(true)` when `auth_basic` is enabled, `Some(false)` for `auth_basic off`, `None` if unset.
    pub auth_basic: Option<bool>,
    /// `true` when `auth_request` is configured in this scope (and not `off`).
    pub auth_request: bool,
    /// Configured `ssl_verify_client` mode in scope, if set.
    pub ssl_verify_client: Option<SslVerifyClient>,
    /// `true` when one or more `allow` or `deny` rules apply in scope.
    pub access_control: bool,
}

/// Mode for Nginx's `ssl_verify_client` directive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SslVerifyClient {
    /// Client certificate verification disabled (`off`).
    Off,
    /// Client certificate required and verified (`on`).
    On,
    /// Client certificate requested and verified if presented (`optional`).
    Optional,
    /// Client certificate requested without CA chain verification (`optional_no_ca`).
    OptionalNoCa,
}

/// Explicit uncertainty where unmodeled or dynamic Nginx configuration could
/// alter routing or access decisions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Uncertainty {
    /// Category of the unmodeled or dynamic construct.
    pub kind: UncertaintyKind,
    /// Sanitized, bounded directive name (never raw directive arguments).
    pub directive: String,
    /// Sanitized file provenance from `# configuration file <path>:`, when known.
    pub source_file: Option<String>,
    /// 1-based line number within `source_file` (or input), when known.
    pub line: Option<usize>,
}

/// Category of an [`Uncertainty`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UncertaintyKind {
    /// Control-flow directive such as `if` or `return`.
    DynamicControlFlow,
    /// Routing-altering directive such as `rewrite`, `try_files`, `error_page`, or wildcard `server_name` with `$`.
    DynamicRouting,
    /// Variable-producing block such as `map`, `geo`, or `split_clients`.
    DynamicVariable,
    /// Dynamic `$variable` in a backend target (`proxy_pass` or `upstream` `server`).
    DynamicTarget,
    /// `include` pattern containing a `$variable`.
    DynamicInclude,
    /// Literal `include` path not found among `nginx -T` file markers.
    UnresolvedInclude,
    /// Unsupported top-level context such as `stream {}` or `mail {}`.
    UnsupportedContext,
    /// Regular-expression `server_name` or `location` matcher.
    RegexMatch,
    /// Unsupported location form such as a named `@location`.
    UnsupportedLocation,
    /// Nested `location` block inside another `location`.
    NestedLocation,
    /// Non-TCP/HTTP transport such as `unix:` socket or unsupported URL scheme.
    UnsupportedTransport,
    /// Non-HTTP proxy backend (`fastcgi_pass`, `grpc_pass`, `uwsgi_pass`, `scgi_pass`, `memcached_pass`).
    UnsupportedBackend,
    /// `allow` or `deny` access-control directive whose effective runtime order is unmodeled.
    AccessControl,
    /// `auth_request` subrequest authentication whose upstream policy is unmodeled.
    SubrequestAuth,
    /// Hostname target requiring DNS resolution (`listen`, `proxy_pass`, or `upstream` `server`).
    UnresolvedHost,
    /// Unsupported or unmodeled option on a `listen` directive.
    UnsupportedListenOption,
    /// `server {}` block with no explicit `listen` directive (defaults to 80 / 8000 at runtime).
    ImplicitListen,
    /// Conflicting or duplicate single-value directive such as multiple `proxy_pass` in one `location`.
    AmbiguousDirective,
    /// Malformed directive arguments in an otherwise syntactically valid config.
    InvalidDirective,
    /// Any other unrecognized or third-party directive in a modeled scope.
    UnmodeledDirective,
}

impl fmt::Display for UncertaintyKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::DynamicControlFlow => "dynamic control flow",
            Self::DynamicRouting => "dynamic routing",
            Self::DynamicVariable => "dynamic variable mapping",
            Self::DynamicTarget => "dynamic variable in backend target",
            Self::DynamicInclude => "dynamic include pattern",
            Self::UnresolvedInclude => "unresolved include file",
            Self::UnsupportedContext => "unsupported configuration context",
            Self::RegexMatch => "regular expression match",
            Self::UnsupportedLocation => "unsupported location form",
            Self::NestedLocation => "nested location block",
            Self::UnsupportedTransport => "unsupported transport",
            Self::UnsupportedBackend => "unsupported proxy backend",
            Self::AccessControl => "IP/network access control directive",
            Self::SubrequestAuth => "subrequest authentication",
            Self::UnresolvedHost => "hostname requiring DNS resolution",
            Self::UnsupportedListenOption => "unsupported listen option",
            Self::ImplicitListen => "implicit default listen port",
            Self::AmbiguousDirective => "ambiguous directive",
            Self::InvalidDirective => "invalid directive arguments",
            Self::UnmodeledDirective => "unmodeled directive",
        })
    }
}

impl fmt::Display for Uncertainty {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (`{}`)", self.kind, self.directive)?;
        match (&self.source_file, self.line) {
            (Some(file), Some(line)) => write!(f, " at {file}:{line}"),
            (Some(file), None) => write!(f, " in {file}"),
            (None, Some(line)) => write!(f, " at line {line}"),
            (None, None) => Ok(()),
        }
    }
}
