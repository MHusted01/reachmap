//! Turning a raw server into a [`CaddyServer`].

use super::Projector;
use crate::caddy::listen::ListenAddress;
use crate::caddy::location::JsonPath;
use crate::caddy::raw::{RawAutomaticHttps, RawClientAuth, RawServer, RawTlsPolicy};
use crate::caddy::{AutomaticHttps, CaddyServer, ClientAuthMode, TlsPolicy, UncertaintyKind};

/// The `listener_wrappers` entry that only marks where TLS is handled.
const TLS_WRAPPER: &str = "tls";

/// The `protocols` entry that turns on HTTP/3.
const HTTP3: &str = "h3";

impl Projector<'_> {
    pub(super) fn server(&mut self, name: &str, raw: RawServer, at: &JsonPath) -> CaddyServer {
        self.groups.clear();
        let listen = self.listen(raw.listen.as_deref(), &at.field("listen"));
        self.server_features(&raw, at);
        let policies_at = at.field("tls_connection_policies");
        let tls_policies: Vec<TlsPolicy> = raw
            .tls_connection_policies
            .into_iter()
            .enumerate()
            .map(|(index, policy)| self.tls_policy(policy, &policies_at.index(index)))
            .collect();
        let client_auth = tls_policies
            .iter()
            .any(|policy| policy.client_auth.is_some());
        if client_auth && raw.strict_sni_host == Some(false) {
            let field = "strict_sni_host";
            self.note(
                UncertaintyKind::UnmodeledServerFeature,
                field,
                &at.field(field),
            );
        }
        CaddyServer {
            name: self.name(name),
            listen,
            automatic_https: raw
                .automatic_https
                .as_ref()
                .map(automatic_https)
                .unwrap_or_default(),
            http3: http3(raw.protocols.as_deref()),
            tls_policies,
            routes: self.routes(raw.routes, &at.field("routes"), 0),
        }
    }

    /// Notes server fields that can route requests or change how the
    /// listener accepts connections.
    fn server_features(&mut self, raw: &RawServer, at: &JsonPath) {
        let fields = [
            ("errors", raw.errors.is_some()),
            ("named_routes", raw.named_routes.is_some()),
            ("listen_protocols", !raw.listen_protocols.is_empty()),
        ];
        for (field, _) in fields.into_iter().filter(|(_, present)| *present) {
            self.note(
                UncertaintyKind::UnmodeledServerFeature,
                field,
                &at.field(field),
            );
        }
        let wrappers_at = at.field("listener_wrappers");
        for (index, _) in raw
            .listener_wrappers
            .iter()
            .enumerate()
            .filter(|(_, wrapper)| wrapper.wrapper.as_deref() != Some(TLS_WRAPPER))
        {
            let kind = UncertaintyKind::UnmodeledServerFeature;
            self.note(kind, "listener_wrappers", &wrappers_at.index(index));
        }
    }

    /// The statically understood addresses; a missing or empty `listen` is
    /// uncertain because Caddy then picks the ports itself.
    fn listen(&mut self, raw: Option<&[String]>, at: &JsonPath) -> Vec<ListenAddress> {
        let Some(addresses) = raw.filter(|addresses| !addresses.is_empty()) else {
            self.note(UncertaintyKind::ImplicitListen, "listen", at);
            return Vec::new();
        };
        addresses
            .iter()
            .enumerate()
            .filter_map(|(index, text)| {
                let at = at.index(index);
                if self.substituted(text, "listen", &at) {
                    return None;
                }
                ListenAddress::parse(text)
                    .map_err(|problem| self.note(problem.kind(), "listen", &at))
                    .ok()
            })
            .collect()
    }

    fn tls_policy(&mut self, raw: RawTlsPolicy, at: &JsonPath) -> TlsPolicy {
        let client_auth = raw
            .client_authentication
            .and_then(|auth| self.client_auth(&auth, &at.field("client_authentication")));
        TlsPolicy {
            scoped: raw.matcher.is_some(),
            client_auth,
        }
    }

    fn client_auth(&mut self, raw: &RawClientAuth, at: &JsonPath) -> Option<ClientAuthMode> {
        if !raw.verifiers.is_empty() {
            let field = "verifiers";
            self.note(
                UncertaintyKind::ClientCertificateVerifier,
                field,
                &at.field(field),
            );
        }
        match raw.mode.as_deref() {
            Some("request") => Some(ClientAuthMode::Request),
            Some("require") => Some(ClientAuthMode::Require),
            Some("verify_if_given") => Some(ClientAuthMode::VerifyIfGiven),
            Some("require_and_verify") => Some(ClientAuthMode::RequireAndVerify),
            None | Some("") => raw.has_trust().then_some(ClientAuthMode::Implicit),
            Some(_) => {
                let kind = UncertaintyKind::UnknownClientAuthMode;
                self.note(kind, "mode", &at.field("mode"));
                None
            }
        }
    }
}

/// The `automatic_https` switches.
fn automatic_https(raw: &RawAutomaticHttps) -> AutomaticHttps {
    AutomaticHttps {
        disabled: raw.disable,
        redirects_disabled: raw.disable_redirects,
        hosts_skipped: raw.skip.is_some() || raw.skip_certificates.is_some(),
    }
}

/// Whether HTTP/3 is on: Caddy treats a missing or empty `protocols` list
/// as its default set, which includes `h3`.
fn http3(protocols: Option<&[String]>) -> bool {
    protocols.is_none_or(|protocols| {
        protocols.is_empty() || protocols.iter().any(|protocol| protocol == HTTP3)
    })
}
