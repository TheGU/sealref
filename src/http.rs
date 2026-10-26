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
//! whichever host the redirect named. `ureq` drops `Authorization` across hosts by default but
//! knows nothing about the vendor-specific headers, so the whole behaviour is turned off.
//!
//! *Proxy variables are not read.* Releases before this one never consulted `HTTPS_PROXY`,
//! `HTTP_PROXY` or `ALL_PROXY`, and `ureq` 3 would, by default. A proxy named by `HTTP_PROXY` sees
//! an `http://` Vault token in cleartext, and the variable is commonly set image-wide by someone
//! other than whoever configured SealRef, so ignoring it is a setting rather than an absence.
//!
//! *Trust is explicit.* `SEALREF_CA_FILE` replaces the built-in roots rather than adding to them,
//! because a trust store that can only grow is not a control. See the module docs on
//! [`tls_config`].

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use rustls::crypto::CryptoProvider;
use rustls::sign::CertifiedKey;
use rustls::RootCertStore;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use ureq::tls::{Certificate, ClientCert, PrivateKey, RootCerts, TlsConfig};
use ureq::Body;
use zeroize::Zeroizing;

use crate::{Error, Result};

/// Connect, read and write timeout for every provider request.
pub const TIMEOUT: Duration = Duration::from_secs(15);

/// Deadline for a whole request, however slowly it is being fed.
pub const DEADLINE: Duration = Duration::from_secs(60);

/// The most a response body may hold. No secret or token is anywhere near this large, so a server
/// that sends more is misbehaving and is refused rather than read in full.
pub const BODY_LIMIT: u64 = 10 * 1024 * 1024;

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
/// SealRef says on stderr that it is not reading them, whether or not `SEALREF_CA_FILE` is also
/// set: `VAULT_SKIP_VERIFY` in particular is not answered by setting a CA file, and an operator
/// who set it believes verification is off. It is a notice rather than a failure, because these
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
    let config = ureq::Agent::config_builder()
        // A 4xx or 5xx is handed back as a response, because the CyberArk provider reads the
        // vendor error code out of its body. `check` decides what counts as success.
        .http_status_as_error(false)
        .max_redirects(0)
        // `ureq` 3 reads the proxy variables unless told otherwise; see the module docs.
        .proxy(None)
        .timeout_connect(Some(TIMEOUT))
        .timeout_per_read(Some(TIMEOUT))
        .timeout_per_write(Some(TIMEOUT))
        // The three above are per-operation, so a server that trickles one byte at a time would
        // hold a container's start-up open indefinitely. This is the deadline for the whole
        // exchange.
        .timeout_global(Some(DEADLINE))
        .tls_config(tls_config()?)
        .build();
    Ok(ureq::Agent::new_with_config(config))
}

fn warn_about_ignored_tls_vars() {
    for name in IGNORED_TLS_VARS {
        if std::env::var_os(name).is_some_and(|v| !v.is_empty()) {
            eprintln!(
                "sealref: {name} is set but SealRef does not read it; use {CA_FILE_VAR} instead"
            );
        }
    }
}

/// Build the TLS configuration from the environment.
///
/// `SEALREF_CA_FILE` replaces the compiled-in Mozilla roots instead of extending them. Additive
/// trust can only widen: an operator who points SealRef at a private CA and still leaves roughly a
/// hundred and fifty public roots able to vouch for `vault.internal.example.com` has a control that
/// does nothing, and believes otherwise. Replacement is also the more general primitive, because
/// additive behaviour can be rebuilt by concatenating a public bundle into the same file, while
/// pinning cannot be rebuilt from additive behaviour at all.
pub fn tls_config() -> Result<TlsConfig> {
    assemble(root_certs(env_path(CA_FILE_VAR))?, client_identity()?)
}

/// The trust anchors: the CA file when there is one, otherwise `ureq`'s compiled-in bundle.
///
/// The file is parsed here rather than handed to `ureq`, which skips a certificate it cannot use
/// without saying so. That would turn a corrupt CA file into a smaller trust store instead of an
/// error, so every certificate must be accepted or the run fails.
fn root_certs(ca_file: Option<String>) -> Result<RootCerts> {
    let Some(path) = ca_file else {
        return Ok(RootCerts::WebPki);
    };
    let mut accepted = RootCertStore::empty();
    let mut certificates = Vec::new();
    for certificate in CertificateDer::pem_file_iter(&path)
        .map_err(|e| Error::Tls(format!("{CA_FILE_VAR} {path}: {e}")))?
    {
        let certificate =
            certificate.map_err(|e| Error::Tls(format!("{CA_FILE_VAR} {path}: {e}")))?;
        accepted
            .add(certificate.clone())
            .map_err(|e| Error::Tls(format!("{CA_FILE_VAR} {path}: {e}")))?;
        certificates.push(Certificate::from_der(certificate.as_ref()).to_owned());
    }
    if certificates.is_empty() {
        return Err(Error::Tls(format!(
            "{CA_FILE_VAR} {path} holds no certificate"
        )));
    }
    Ok(RootCerts::new_with_certs(&certificates))
}

/// The client certificate chain and private key, in the two forms that need them.
struct Identity {
    chain: Vec<CertificateDer<'static>>,
    /// The key as rustls parsed it, which is what validation runs against.
    key: PrivateKeyDer<'static>,
    /// The same key as `ureq` parsed it, which is what is handed over.
    ureq_key: PrivateKey<'static>,
}

fn assemble(roots: RootCerts, identity: Option<Identity>) -> Result<TlsConfig> {
    let client_cert = match identity {
        Some(identity) => {
            validate_identity(&identity)?;
            let chain: Vec<_> = identity
                .chain
                .iter()
                .map(|c| Certificate::from_der(c.as_ref()).to_owned())
                .collect();
            Some(ClientCert::new_with_certs(&chain, identity.ureq_key))
        }
        None => None,
    };
    Ok(TlsConfig::builder()
        .root_certs(roots)
        .client_cert(client_cert)
        .build())
}

/// Prove that `ureq` will be able to use this identity before it is handed over.
///
/// `ureq` builds its rustls configuration lazily, at the first connection, and `expect`s the
/// client certificate to be usable. With `panic = "abort"` an unusable key would therefore end the
/// process mid-run instead of failing as an ordinary error when the agent is built. This does the
/// same work with the same provider selection, so passing here means `ureq`'s own build passes.
///
/// `ureq` cannot be given a key as bytes plus an encoding (its encoding type is not exported), so
/// it parses the key file itself. The two parses must agree on the bytes, otherwise what was
/// validated is not what will be used.
fn validate_identity(identity: &Identity) -> Result<()> {
    if identity.ureq_key.der() != identity.key.secret_der() {
        return Err(Error::Tls(format!(
            "{CLIENT_KEY_VAR}: the key did not parse the same way twice"
        )));
    }
    let provider = CryptoProvider::get_default()
        .cloned()
        .unwrap_or_else(|| Arc::new(rustls::crypto::ring::default_provider()));
    CertifiedKey::from_der(identity.chain.clone(), identity.key.clone_key(), &provider)
        .map(|_| ())
        .map_err(|e| Error::Tls(format!("{CLIENT_CERT_VAR}: {e}")))
}

/// Load the client certificate chain and private key, which must be given together or not at all.
fn client_identity() -> Result<Option<Identity>> {
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

    // The error carries the path only: a private key file that fails to parse must not have any
    // part of its contents quoted back. `ureq` keeps its own plain copy of the key for the life of
    // the process in the shared agent, as the rustls configuration did before it, so this is a
    // promise that no error or log line holds the key, not that memory is wiped.
    //
    // The file is read once and both forms are parsed from the same bytes, so nothing can change
    // between them.
    let pem = Zeroizing::new(
        std::fs::read(&key_path)
            .map_err(|e| Error::Tls(format!("{CLIENT_KEY_VAR} {key_path}: {e}")))?,
    );
    let key = PrivateKeyDer::from_pem_slice(&pem)
        .map_err(|e| Error::Tls(format!("{CLIENT_KEY_VAR} {key_path}: {e}")))?;
    let ureq_key = PrivateKey::from_pem(&pem).map_err(|_| {
        Error::Tls(format!(
            "{CLIENT_KEY_VAR} {key_path}: not a usable private key"
        ))
    })?;
    Ok(Some(Identity {
        chain,
        key,
        ureq_key,
    }))
}

/// Why a provider request did not produce a usable response.
pub enum Failure {
    /// The server answered, but not with a 2xx.
    Status {
        /// The status code.
        code: u16,
        /// The response, for a provider that can safely read a vendor error code out of it.
        response: Box<ureq::http::Response<Body>>,
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
/// The agent is configured to return every status as a response, so a 4xx or 5xx and a 3xx (which
/// is not followed) arrive the same way and would otherwise leave each provider trying to parse an
/// error or redirect body as a secret. One place decides what "the request worked" means.
pub fn check(
    outcome: std::result::Result<ureq::http::Response<Body>, ureq::Error>,
) -> std::result::Result<ureq::http::Response<Body>, Failure> {
    match outcome {
        Ok(response) if response.status().is_success() => Ok(response),
        Ok(response) => Err(Failure::Status {
            code: response.status().as_u16(),
            response: Box::new(response),
        }),
        Err(error) => Err(Failure::Transport(describe(&error))),
    }
}

/// Describe a transport failure without anything that could be a credential.
///
/// `ureq`'s `Display` is not safe to pass through. `BadUri` and `RequireHttpsOnly` quote the whole
/// request URL, and for the CyberArk provider that carries the application id in its query string;
/// `ConnectProxyFailed` quotes text a proxy sent back; `Pem` can carry a line of a PEM file; and
/// the protocol errors can quote a header. So this is an allowlist. A variant is printed only when
/// its payload is known to be a fixed phrase, an I/O error or a TLS verdict, and a variant added
/// by a later release gets generic text until someone has read it, because the failure to avoid
/// is disclosure.
fn describe(error: &ureq::Error) -> String {
    use ureq::Error as E;
    match error {
        E::Io(_)
        | E::Timeout(_)
        | E::Rustls(_)
        | E::Http(_)
        | E::BodyExceedsLimit(_)
        | E::LargeResponseHeader(..)
        | E::Tls(_)
        | E::HostNotFound
        | E::RedirectFailed
        | E::InvalidProxyUrl
        | E::ConnectionFailed
        | E::TooManyRedirects
        | E::TlsRequired => error.to_string(),
        E::BadUri(_) => "the URL is not valid".to_string(),
        E::RequireHttpsOnly(_) => "the URL is not https".to_string(),
        E::ConnectProxyFailed(_) => "the proxy refused the connection".to_string(),
        E::Pem(_) => "a PEM file could not be read".to_string(),
        // Header and chunk framing errors can quote what the server (or a header we sent) held.
        E::Protocol(_) => "the HTTP exchange was malformed".to_string(),
        _ => "the request failed".to_string(),
    }
}

/// Read a response body as text, refusing anything that could be incomplete or altered.
///
/// The body of a Conjur read is the secret, so a body that was cut short or had bytes replaced
/// would resolve to a different password and start the application with it. Two things guard
/// against that. `ureq` treats a connection reset or EOF while reading a body with no declared
/// length as a normal end, so a response with neither `Content-Length` nor chunked framing is
/// refused outright. And the text is decoded strictly, since `Body::read_to_string` would swap
/// invalid bytes for a replacement character without saying so.
///
/// The error is a reason a provider can append to its own message: it holds no URL and no part of
/// the body.
pub fn read_text(
    response: &mut ureq::http::Response<Body>,
) -> std::result::Result<Zeroizing<String>, String> {
    if !has_framing(response) {
        return Err("the response has no length and may have been cut short".to_string());
    }
    let bytes = Zeroizing::new(
        response
            .body_mut()
            .with_config()
            .limit(BODY_LIMIT)
            .read_to_vec()
            .map_err(|e| describe(&e))?,
    );
    std::str::from_utf8(&bytes)
        .map(|text| Zeroizing::new(text.to_string()))
        .map_err(|_| "the body is not valid UTF-8".to_string())
}

/// Whether the end of the body is announced by the message rather than by the connection closing.
fn has_framing(response: &ureq::http::Response<Body>) -> bool {
    use ureq::http::{header, StatusCode};
    // These statuses have no body by definition, so there is nothing to cut short.
    if matches!(
        response.status(),
        StatusCode::NO_CONTENT | StatusCode::NOT_MODIFIED
    ) {
        return true;
    }
    let headers = response.headers();
    if headers.contains_key(header::CONTENT_LENGTH) {
        return true;
    }
    headers
        .get_all(header::TRANSFER_ENCODING)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .any(|coding| coding.trim().eq_ignore_ascii_case("chunked"))
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
///
/// A component that is entirely dots is escaped as well, even though `.` is unreserved. Nothing
/// between SealRef and the server removes `.` and `..` segments for it, but the server, or a
/// reverse proxy in front of it, may, and a path containing one would then address somewhere other
/// than where it says. The parsers reject those segments already; this is the second lock, so that
/// a future caller cannot reintroduce the problem by forgetting the first. In a query string the
/// escape is harmless.
pub fn percent_encode(value: &str) -> String {
    if !value.is_empty() && value.bytes().all(|b| b == b'.') {
        return value.replace('.', "%2E");
    }
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
    fn escapes_a_dot_only_segment_so_it_cannot_traverse() {
        assert_eq!(percent_encode_path("a/../b"), "a/%2E%2E/b");
        assert_eq!(percent_encode_path("a/./b"), "a/%2E/b");
        assert_eq!(percent_encode_path("a/.../b"), "a/%2E%2E%2E/b");
        // A dot inside a segment is an ordinary character and stays one.
        assert_eq!(percent_encode_path("a/db.password"), "a/db.password");
    }

    #[test]
    fn normalises_a_base_url() {
        assert_eq!(normalise_base_url("https://x/"), "https://x");
        assert_eq!(normalise_base_url("  https://x/api//  "), "https://x/api");
        assert_eq!(normalise_base_url("https://x"), "https://x");
    }

    #[test]
    fn escapes_a_dot_only_component_so_it_cannot_traverse() {
        assert_eq!(percent_encode(".."), "%2E%2E");
        assert_eq!(percent_encode("."), "%2E");
        assert_eq!(percent_encode("a.b"), "a.b");
        assert_eq!(percent_encode(""), "");
    }

    #[test]
    fn the_default_configuration_uses_the_built_in_roots_and_no_client_certificate() {
        // No environment is touched here: the pieces `tls_config` assembles from the environment
        // are called directly with "nothing set".
        let config = assemble(root_certs(None).unwrap(), None).unwrap();
        assert!(matches!(config.root_certs(), RootCerts::WebPki));
        assert!(config.client_cert().is_none());
    }

    #[test]
    fn an_unusable_client_key_is_an_error_not_a_later_panic() {
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine;
        let der = vec![0u8; 16];
        let pem = format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
            STANDARD.encode(&der)
        );
        let identity = Identity {
            chain: vec![CertificateDer::from(vec![0u8; 8])],
            key: PrivateKeyDer::Pkcs8(der.into()),
            ureq_key: PrivateKey::from_pem(pem.as_bytes()).unwrap(),
        };
        let err = assemble(RootCerts::WebPki, Some(identity)).unwrap_err();
        assert!(err.to_string().contains(CLIENT_CERT_VAR), "{err}");
    }

    #[test]
    fn a_transport_error_never_prints_the_url_it_carries() {
        let url = "https://x.example/?AppID=secretapp";
        for error in [
            ureq::Error::BadUri(url.to_string()),
            ureq::Error::RequireHttpsOnly(url.to_string()),
            ureq::Error::ConnectProxyFailed(format!("407 for {url}")),
        ] {
            let text = describe(&error);
            assert!(!text.contains("secretapp"), "{text}");
            assert!(!text.contains("x.example"), "{text}");
        }
    }

    #[test]
    fn an_io_error_is_described_by_its_cause() {
        let error = ureq::Error::Io(std::io::Error::from(std::io::ErrorKind::ConnectionRefused));
        assert!(describe(&error).contains("refused"));
    }
}
