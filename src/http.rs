//! The one HTTP client every remote provider shares.
//!
//! Three properties matter here, and each of them is a decision rather than a default.
//!
//! *Built once, and only when needed.* A deployment whose references are all `seal:v1` never
//! builds an agent at all, so a malformed client certificate cannot fail a run that never opens a
//! socket. A deployment with ten `seal:vault` references builds one agent and reuses one TLS
//! connection instead of performing ten handshakes.
//!
//! *Redirects are refused.* None of Vault, Conjur or the CyberArk Central Credential Provider
//! redirect an API call. A redirect from one of them is either an HTTP-to-HTTPS upgrade, in which
//! case the credential has already travelled in cleartext and the run should fail loudly, or it is
//! an attack. Following one would resend `X-Vault-Token`, or repost a Conjur API key on a 307, to
//! whichever host the redirect named. `ureq` strips `Authorization` across hosts by default but
//! knows nothing about the vendor-specific headers, so the whole behaviour is turned off.
//!
//! *Trust is explicit.* `SEALREF_CA_FILE` replaces the built-in roots rather than adding to them,
//! because a trust store that can only grow is not a control. See the module docs on
//! [`tls_config`].

use std::sync::OnceLock;
use std::time::Duration;

use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

use crate::{Error, Result};

/// Connect and per-read timeout for every provider request.
pub const TIMEOUT: Duration = Duration::from_secs(15);

/// PEM roots that replace the built-in Mozilla bundle.
pub const CA_FILE_VAR: &str = "SEALREF_CA_FILE";

/// PEM certificate chain presented for mutual TLS.
pub const CLIENT_CERT_VAR: &str = "SEALREF_CLIENT_CERT";

/// PEM private key for [`CLIENT_CERT_VAR`].
pub const CLIENT_KEY_VAR: &str = "SEALREF_CLIENT_KEY";

/// Vendor TLS variables that SealRef does not read.
///
/// Every one of these configures TLS for some other client of the same server, and an operator who
/// sets one has every reason to assume SealRef obeys it. Silently ignoring a variable whose whole
/// purpose is to narrow trust is the worst available outcome, so the first time an agent is built
/// SealRef says on stderr that it is not reading them. It is a notice rather than a failure: these
/// variables belong to Vault Agent and to the Conjur clients that legitimately share the
/// environment, and refusing to start because a neighbour is configured would be wrong.
pub const IGNORED_TLS_VARS: &[&str] = &[
    "VAULT_CACERT",
    "VAULT_CAPATH",
    "VAULT_SKIP_VERIFY",
    "CONJUR_CERT_FILE",
];

static AGENT: OnceLock<std::result::Result<ureq::Agent, String>> = OnceLock::new();

/// The shared agent, built from the environment on first use.
pub fn agent() -> Result<ureq::Agent> {
    match AGENT.get_or_init(|| build_agent().map_err(|e| e.to_string())) {
        Ok(agent) => Ok(agent.clone()),
        Err(reason) => Err(Error::Tls(reason.clone())),
    }
}

fn build_agent() -> Result<ureq::Agent> {
    warn_about_ignored_tls_vars();
    Ok(ureq::AgentBuilder::new()
        .timeout_connect(TIMEOUT)
        .timeout_read(TIMEOUT)
        .redirects(0)
        .tls_config(std::sync::Arc::new(tls_config()?))
        .build())
}

fn warn_about_ignored_tls_vars() {
    if env_path(CA_FILE_VAR).is_some() {
        return;
    }
    for name in IGNORED_TLS_VARS {
        if std::env::var_os(name).is_some_and(|v| !v.is_empty()) {
            eprintln!(
                "sealref: {name} is set but SealRef does not read it; use {CA_FILE_VAR} instead"
            );
        }
    }
}

/// Build the rustls configuration from the environment.
///
/// `SEALREF_CA_FILE` replaces the compiled-in Mozilla roots instead of extending them. Additive
/// trust can only widen: an operator who points SealRef at a private CA and still leaves roughly a
/// hundred and fifty public roots able to vouch for `vault.internal.example.com` has a control that
/// does nothing, and believes otherwise. Replacement is also the more general primitive, because
/// additive behaviour can be rebuilt by concatenating a public bundle into the same file, while
/// pinning cannot be rebuilt from additive behaviour at all.
pub fn tls_config() -> Result<ClientConfig> {
    let mut roots = RootCertStore::empty();
    match env_path(CA_FILE_VAR) {
        Some(path) => {
            let mut added = 0usize;
            for certificate in CertificateDer::pem_file_iter(&path)
                .map_err(|e| Error::Tls(format!("{CA_FILE_VAR} {path}: {e}")))?
            {
                let certificate =
                    certificate.map_err(|e| Error::Tls(format!("{CA_FILE_VAR} {path}: {e}")))?;
                roots
                    .add(certificate)
                    .map_err(|e| Error::Tls(format!("{CA_FILE_VAR} {path}: {e}")))?;
                added += 1;
            }
            if added == 0 {
                return Err(Error::Tls(format!(
                    "{CA_FILE_VAR} {path} holds no certificate"
                )));
            }
        }
        None => roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
    }

    let builder = ClientConfig::builder_with_provider(std::sync::Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(rustls::DEFAULT_VERSIONS)
    .map_err(|e| Error::Tls(e.to_string()))?
    .with_root_certificates(roots);

    match client_identity()? {
        Some((chain, key)) => builder
            .with_client_auth_cert(chain, key)
            .map_err(|e| Error::Tls(format!("{CLIENT_CERT_VAR}: {e}"))),
        None => Ok(builder.with_no_client_auth()),
    }
}

/// Load the client certificate chain and private key, which must be given together or not at all.
fn client_identity() -> Result<Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>> {
    let cert_path = env_path(CLIENT_CERT_VAR);
    let key_path = env_path(CLIENT_KEY_VAR);
    let (cert_path, key_path) = match (cert_path, key_path) {
        (Some(cert), Some(key)) => (cert, key),
        (None, None) => return Ok(None),
        (Some(_), None) => {
            return Err(Error::Tls(format!(
                "{CLIENT_CERT_VAR} is set but {CLIENT_KEY_VAR} is not"
            )))
        }
        (None, Some(_)) => {
            return Err(Error::Tls(format!(
                "{CLIENT_KEY_VAR} is set but {CLIENT_CERT_VAR} is not"
            )))
        }
    };

    let mut chain = Vec::new();
    for certificate in CertificateDer::pem_file_iter(&cert_path)
        .map_err(|e| Error::Tls(format!("{CLIENT_CERT_VAR} {cert_path}: {e}")))?
    {
        chain.push(
            certificate.map_err(|e| Error::Tls(format!("{CLIENT_CERT_VAR} {cert_path}: {e}")))?,
        );
    }
    if chain.is_empty() {
        return Err(Error::Tls(format!(
            "{CLIENT_CERT_VAR} {cert_path} holds no certificate"
        )));
    }

    // The error carries the path only. A private key file that fails to parse must not have any
    // part of its contents quoted back, and `PrivateKeyDer` zeroizes itself on drop.
    let key = PrivateKeyDer::from_pem_file(&key_path)
        .map_err(|e| Error::Tls(format!("{CLIENT_KEY_VAR} {key_path}: {e}")))?;
    Ok(Some((chain, key)))
}

/// Why a provider request did not produce a usable response.
pub enum Failure {
    /// The server answered, but not with a 2xx.
    Status {
        /// The status code.
        code: u16,
        /// The response, for a provider that can safely read a vendor error code out of it.
        response: Box<ureq::Response>,
    },
    /// The request never completed. The text names the transport problem, never a credential.
    Transport(String),
}

/// A trailing clause for a 3xx, which is a configuration error rather than a server refusal.
///
/// Redirects are turned off, so a provider that answers with one is either being upgraded from
/// HTTP to HTTPS, in which case the credential has already travelled in cleartext, or is not the
/// server the operator thinks it is. Either way the message should say why nothing was followed.
pub fn redirect_note(code: u16) -> &'static str {
    if (300..400).contains(&code) {
        ", and redirects are never followed"
    } else {
        ""
    }
}

/// Classify the outcome of a request, treating everything outside 2xx as a failure.
///
/// `ureq` reports 4xx and 5xx as errors but hands back a 3xx as an ordinary response once
/// redirects are turned off, which would otherwise leave each provider trying to parse a redirect
/// body as a secret. One place decides what "the request worked" means.
pub fn check(
    outcome: std::result::Result<ureq::Response, ureq::Error>,
) -> std::result::Result<ureq::Response, Failure> {
    match outcome {
        Ok(response) if (200..300).contains(&response.status()) => Ok(response),
        Ok(response) => Err(Failure::Status {
            code: response.status(),
            response: Box::new(response),
        }),
        Err(ureq::Error::Status(code, response)) => Err(Failure::Status {
            code,
            response: Box::new(response),
        }),
        Err(e) => Err(Failure::Transport(e.to_string())),
    }
}

fn env_path(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

/// Percent-encode one path or query component.
///
/// Everything outside the unreserved set of RFC 3986 is escaped, `/` included. Callers that mean
/// `/` as a separator join already-encoded components themselves.
pub fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char)
            }
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

/// Percent-encode each `/`-separated segment and rejoin them with literal separators.
pub fn percent_encode_path(value: &str) -> String {
    value
        .split('/')
        .map(percent_encode)
        .collect::<Vec<_>>()
        .join("/")
}

/// Trim the trailing slashes from a base URL so joining a path never doubles the separator.
pub fn normalise_base_url(value: &str) -> String {
    value.trim().trim_end_matches('/').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_encodes_the_reserved_set() {
        assert_eq!(percent_encode("host/myapp"), "host%2Fmyapp");
        assert_eq!(percent_encode("a b&c"), "a%20b%26c");
        assert_eq!(percent_encode("plain-._~09AZ"), "plain-._~09AZ");
        assert_eq!(percent_encode("100%"), "100%25");
    }

    #[test]
    fn percent_encodes_path_segments_but_keeps_the_separators() {
        assert_eq!(
            percent_encode_path("prod/db/pass word"),
            "prod/db/pass%20word"
        );
        assert_eq!(percent_encode_path("single"), "single");
    }

    #[test]
    fn normalises_a_base_url() {
        assert_eq!(normalise_base_url("https://x/"), "https://x");
        assert_eq!(normalise_base_url("  https://x/api//  "), "https://x/api");
        assert_eq!(normalise_base_url("https://x"), "https://x");
    }

    #[test]
    fn the_default_configuration_uses_the_built_in_roots() {
        // No environment is touched here: with no CA file set the configuration must build, which
        // is what proves the ring provider and the compiled-in bundle are wired together.
        assert!(tls_config().is_ok());
    }
}
