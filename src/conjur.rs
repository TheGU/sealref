//! A deliberately thin CyberArk Conjur reader.
//!
//! One read shape, two ways to hold an identity. Either something else already obtained an access
//! token, which is what the Conjur Kubernetes authenticator sidecar and Conjur Cloud arrange, or
//! SealRef exchanges a host API key for one. `authn-jwt`, `authn-oidc`, `authn-iam` and the rest
//! are out of scope for the same reason the Vault provider speaks only one auth method: obtaining
//! an identity is the platform's job, and doing it here would turn a small helper into a second
//! Conjur client.
//!
//! Note that a Conjur read returns the secret as the response body. Nothing in this module may
//! format a response body into an error.

use std::fs;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use zeroize::Zeroizing;

use crate::http;
use crate::reference::ConjurRef;
use crate::{Error, Result};

/// Base URL of the Conjur appliance, for example `https://conjur.example`.
pub const URL_VAR: &str = "CONJUR_APPLIANCE_URL";

/// The Conjur account, for example `myorg`.
pub const ACCOUNT_VAR: &str = "CONJUR_ACCOUNT";

/// An access token obtained by something else, inline.
pub const TOKEN_VAR: &str = "CONJUR_AUTHN_TOKEN";

/// A file holding an access token obtained by something else.
pub const TOKEN_FILE_VAR: &str = "CONJUR_AUTHN_TOKEN_FILE";

/// The workload identity to authenticate as, for example `host/myapp`.
pub const LOGIN_VAR: &str = "CONJUR_AUTHN_LOGIN";

/// The API key for [`LOGIN_VAR`], inline.
pub const API_KEY_VAR: &str = "CONJUR_AUTHN_API_KEY";

/// A file holding the API key for [`LOGIN_VAR`].
pub const API_KEY_FILE_VAR: &str = "CONJUR_AUTHN_API_KEY_FILE";

/// Conjur connection settings and whatever credential was found.
pub struct ConjurConfig {
    url: String,
    account: String,
    credential: Credential,
    /// The access token, once obtained. A run resolves many references and authenticates once.
    token: std::cell::RefCell<Option<Zeroizing<String>>>,
}

enum Credential {
    /// An access token, already normalised to the base64 form the header needs.
    Token(Zeroizing<String>),
    /// A login and API key to exchange for one.
    ApiKey {
        login: String,
        key: Zeroizing<String>,
    },
}

impl std::fmt::Debug for ConjurConfig {
    /// Never render the API key or the access token, not even in a panic message.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let credential = match &self.credential {
            Credential::Token(_) => "token <redacted>",
            Credential::ApiKey { .. } => "api key <redacted>",
        };
        f.debug_struct("ConjurConfig")
            .field("url", &self.url)
            .field("account", &self.account)
            .field("credential", &credential)
            .finish()
    }
}

impl ConjurConfig {
    /// Read the Conjur settings from the environment.
    pub fn from_env() -> Result<Self> {
        let url =
            env_value(URL_VAR).ok_or_else(|| Error::Conjur(format!("{URL_VAR} is not set")))?;
        let account = env_value(ACCOUNT_VAR)
            .ok_or_else(|| Error::Conjur(format!("{ACCOUNT_VAR} is not set")))?;
        Ok(ConjurConfig {
            url: http::normalise_base_url(&url),
            account,
            credential: Credential::from_env()?,
            token: std::cell::RefCell::new(None),
        })
    }

    /// The URL a variable is read from.
    pub fn secret_url(&self, id: &str) -> String {
        format!(
            "{}/secrets/{}/variable/{}",
            self.url,
            http::percent_encode(&self.account),
            http::percent_encode_path(id)
        )
    }

    /// The URL an API key is exchanged at.
    pub fn authenticate_url(&self, login: &str) -> String {
        format!(
            "{}/authn/{}/{}/authenticate",
            self.url,
            http::percent_encode(&self.account),
            http::percent_encode(login)
        )
    }

    /// Read one variable.
    pub fn read_variable(&self, reference: &ConjurRef) -> Result<Zeroizing<String>> {
        let token = self.access_token()?;
        let url = self.secret_url(&reference.id);
        let response = http::agent()?
            .get(&url)
            .set(
                "Authorization",
                &Zeroizing::new(format!("Token token=\"{}\"", *token)),
            )
            .call();
        let response = match http::check(response) {
            Ok(response) => response,
            // Conjur answers 404 both for a variable that does not exist and for one the identity
            // is not permitted to read, on purpose, so the message must not claim either.
            Err(http::Failure::Status { code, .. }) => {
                return Err(Error::Conjur(format!(
                    "{} returned HTTP {code} for {}{}",
                    self.url,
                    reference.locator(),
                    http::redirect_note(code)
                )))
            }
            Err(http::Failure::Transport(reason)) => {
                return Err(Error::Conjur(format!(
                    "cannot reach {} for {}: {reason}",
                    self.url,
                    reference.locator()
                )))
            }
        };
        // The body IS the secret. `into_string` fails on invalid UTF-8 without quoting the bytes,
        // and no arm below may include the body or its length.
        let value = Zeroizing::new(response.into_string().map_err(|_| {
            Error::Conjur(format!(
                "{}: the value is not valid UTF-8",
                reference.locator()
            ))
        })?);
        // A 200 with no body would otherwise resolve to an empty string and start the application
        // with an empty password, which is the one outcome a tool that fails closed must not have.
        if value.is_empty() {
            return Err(Error::Conjur(format!(
                "{}: the server returned an empty value",
                reference.locator()
            )));
        }
        Ok(value)
    }

    /// The access token, obtained once per run.
    fn access_token(&self) -> Result<Zeroizing<String>> {
        if let Some(token) = self.token.borrow().as_ref() {
            return Ok(token.clone());
        }
        let token = match &self.credential {
            Credential::Token(token) => token.clone(),
            Credential::ApiKey { login, key } => self.authenticate(login, key)?,
        };
        *self.token.borrow_mut() = Some(token.clone());
        Ok(token)
    }

    fn authenticate(&self, login: &str, key: &str) -> Result<Zeroizing<String>> {
        let url = self.authenticate_url(login);
        let response = http::agent()?
            .post(&url)
            .set("Accept-Encoding", "base64")
            .set("Content-Type", "text/plain")
            .send_string(key);
        let response = match http::check(response) {
            Ok(response) => response,
            Err(http::Failure::Status { code, .. }) => {
                return Err(Error::Conjur(format!(
                    "{} returned HTTP {code} authenticating {login}{}",
                    self.url,
                    http::redirect_note(code)
                )))
            }
            Err(http::Failure::Transport(reason)) => {
                return Err(Error::Conjur(format!(
                    "cannot reach {} to authenticate {login}: {reason}",
                    self.url
                )))
            }
        };
        // The body is an access token, which is a credential: never quote it back.
        let body = Zeroizing::new(response.into_string().map_err(|_| {
            Error::Conjur(format!("the access token for {login} is not valid UTF-8"))
        })?);
        normalise_token(&body, "the authenticate response")
    }
}

impl Credential {
    fn from_env() -> Result<Self> {
        if let Some(path) = env_value(TOKEN_FILE_VAR) {
            let text =
                Zeroizing::new(fs::read_to_string(&path).map_err(|e| {
                    Error::Conjur(format!("cannot read {TOKEN_FILE_VAR} {path}: {e}"))
                })?);
            return Ok(Credential::Token(normalise_token(
                &text,
                &format!("{TOKEN_FILE_VAR} {path}"),
            )?));
        }
        if let Some(token) = env_secret(TOKEN_VAR) {
            return Ok(Credential::Token(normalise_token(&token, TOKEN_VAR)?));
        }
        if let Some(login) = env_value(LOGIN_VAR) {
            let key = match env_value(API_KEY_FILE_VAR) {
                Some(path) => {
                    let text = Zeroizing::new(fs::read_to_string(&path).map_err(|e| {
                        Error::Conjur(format!("cannot read {API_KEY_FILE_VAR} {path}: {e}"))
                    })?);
                    let key = Zeroizing::new(text.trim().to_string());
                    if key.is_empty() {
                        return Err(Error::Conjur(format!("{API_KEY_FILE_VAR} {path} is empty")));
                    }
                    key
                }
                None => env_secret(API_KEY_VAR).ok_or_else(|| {
                    Error::Conjur(format!(
                        "{LOGIN_VAR} is set but neither {API_KEY_VAR} nor {API_KEY_FILE_VAR} is"
                    ))
                })?,
            };
            return Ok(Credential::ApiKey { login, key });
        }
        Err(Error::Conjur(format!(
            "no credential: set {TOKEN_FILE_VAR}, {TOKEN_VAR}, or {LOGIN_VAR} with \
             {API_KEY_FILE_VAR} or {API_KEY_VAR}"
        )))
    }
}

/// Turn whatever an access token source holds into the exact base64 the header needs.
///
/// Two forms are accepted, and nothing else. A raw JSON token, which is what the Conjur Kubernetes
/// authenticator sidecar writes to `/run/conjur/access-token`, is base64-encoded here. An already
/// encoded token must be single-line standard base64 that decodes to a JSON object.
///
/// The strictness is the point. This value goes straight into an `Authorization` header, so
/// accepting arbitrary text would splice an operator's line-wrapped `base64` output, complete with
/// its newlines, into the request. It would also accept an API key pasted into the wrong variable
/// and transmit that long-lived credential in a header that appliance logs and reverse proxies
/// routinely record. The error never quotes the content.
pub fn normalise_token(raw: &str, source: &str) -> Result<Zeroizing<String>> {
    let trimmed = raw.trim_start_matches('\u{feff}').trim();
    if trimmed.is_empty() {
        return Err(Error::Conjur(format!("{source} is empty")));
    }
    if trimmed.starts_with('{') {
        if !is_json_object(trimmed.as_bytes()) {
            return Err(Error::Conjur(format!(
                "{source} starts like a JSON access token but is not a complete JSON object"
            )));
        }
        return Ok(Zeroizing::new(STANDARD.encode(trimmed.as_bytes())));
    }
    if !trimmed
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=')
    {
        return Err(Error::Conjur(format!(
            "{source} is neither a JSON access token nor single-line base64"
        )));
    }
    let decoded = Zeroizing::new(
        STANDARD
            .decode(trimmed.as_bytes())
            .map_err(|_| Error::Conjur(format!("{source} is not valid base64")))?,
    );
    if !is_json_object(&decoded) {
        return Err(Error::Conjur(format!(
            "{source} does not decode to a Conjur access token"
        )));
    }
    Ok(Zeroizing::new(trimmed.to_string()))
}

fn is_json_object(bytes: &[u8]) -> bool {
    matches!(
        serde_json::from_slice::<serde_json::Value>(bytes),
        Ok(serde_json::Value::Object(_))
    )
}

fn env_value(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

/// The same, for a variable that holds a credential, so every copy is cleared on drop.
fn env_secret(name: &str) -> Option<Zeroizing<String>> {
    let raw = Zeroizing::new(std::env::var(name).ok()?);
    let trimmed = Zeroizing::new(raw.trim().to_string());
    if trimmed.is_empty() {
        return None;
    }
    Some(trimmed)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN_JSON: &str = r#"{"protected":"eyJhbGciOiJjb25qdXIub3JnL3Nsb3NpbG8vdjIifQ==","payload":"eyJzdWIiOiJob3N0L215YXBwIn0=","signature":"c2lnbmF0dXJl"}"#;

    fn config() -> ConjurConfig {
        ConjurConfig {
            url: "https://conjur.example".to_string(),
            account: "myorg".to_string(),
            credential: Credential::Token(Zeroizing::new("dG9rZW4".to_string())),
            token: std::cell::RefCell::new(None),
        }
    }

    #[test]
    fn builds_the_secret_url() {
        assert_eq!(
            config().secret_url("prod/db/password"),
            "https://conjur.example/secrets/myorg/variable/prod/db/password"
        );
    }

    #[test]
    fn escapes_awkward_characters_in_a_variable_id() {
        assert_eq!(
            config().secret_url("prod/db name/pass word"),
            "https://conjur.example/secrets/myorg/variable/prod/db%20name/pass%20word"
        );
    }

    #[test]
    fn fully_escapes_the_login_because_it_is_one_path_segment() {
        assert_eq!(
            config().authenticate_url("host/myapp"),
            "https://conjur.example/authn/myorg/host%2Fmyapp/authenticate"
        );
    }

    #[test]
    fn a_json_token_is_base64_encoded() {
        let normalised = normalise_token(TOKEN_JSON, "test").unwrap();
        assert_eq!(&*normalised, &STANDARD.encode(TOKEN_JSON));
    }

    #[test]
    fn a_json_token_with_a_byte_order_mark_is_accepted() {
        let raw = format!("\u{feff}{TOKEN_JSON}\n");
        assert_eq!(
            &*normalise_token(&raw, "test").unwrap(),
            &STANDARD.encode(TOKEN_JSON)
        );
    }

    #[test]
    fn an_already_encoded_token_is_passed_through() {
        let encoded = STANDARD.encode(TOKEN_JSON);
        assert_eq!(&*normalise_token(&encoded, "test").unwrap(), &encoded);
    }

    #[test]
    fn a_line_wrapped_token_is_rejected() {
        // `base64 file` wraps at 76 columns by default, and those newlines would be spliced into
        // an Authorization header.
        let encoded = STANDARD.encode(TOKEN_JSON);
        let wrapped = format!("{}\n{}", &encoded[..40], &encoded[40..]);
        let err = normalise_token(&wrapped, "test").unwrap_err();
        assert!(err.to_string().contains("single-line base64"));
    }

    #[test]
    fn an_api_key_in_the_token_variable_is_rejected() {
        // API keys are opaque alphanumeric strings, so a charset test alone would let one through
        // and send a long-lived credential in an Authorization header.
        let err = normalise_token("1vbkm9x2q8j7y3nw5tzp", "test").unwrap_err();
        assert!(err.to_string().contains("does not decode"));
    }

    #[test]
    fn a_truncated_json_token_is_rejected() {
        let err = normalise_token(&TOKEN_JSON[..40], "test").unwrap_err();
        assert!(err.to_string().contains("not a complete JSON object"));
    }

    #[test]
    fn an_empty_token_is_rejected() {
        assert!(normalise_token("   \n", "test").is_err());
    }

    #[test]
    fn a_rejected_token_is_never_quoted_back() {
        let secret = "this-should-never-appear";
        let err = normalise_token(secret, "test").unwrap_err().to_string();
        assert!(!err.contains(secret));
    }

    #[test]
    fn debug_does_not_leak_the_credential() {
        let rendered = format!("{:?}", config());
        assert!(rendered.contains("redacted"));
        assert!(!rendered.contains("dG9rZW4"));
    }
}
