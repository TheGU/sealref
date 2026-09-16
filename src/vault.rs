//! A deliberately thin HashiCorp Vault KV v2 reader.
//!
//! One request shape, one auth mechanism: a token that something else obtained. Vault Agent, the
//! Kubernetes integration, or the platform is expected to put a token in `VAULT_TOKEN_FILE`. Every
//! other Vault auth method is out of scope on purpose; supporting them turns a small helper into a
//! second Vault CLI.

use std::fs;

use serde::Deserialize;
use zeroize::Zeroizing;

use crate::http;
use crate::reference::VaultRef;
use crate::{Error, Result};

/// Vault connection settings, read from the standard environment variables.
pub struct VaultConfig {
    addr: String,
    namespace: Option<String>,
    token: Zeroizing<String>,
}

impl std::fmt::Debug for VaultConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultConfig")
            .field("addr", &self.addr)
            .field("namespace", &self.namespace)
            .field("token", &"<redacted>")
            .finish()
    }
}

impl VaultConfig {
    /// Read `VAULT_ADDR`, `VAULT_NAMESPACE`, and `VAULT_TOKEN` or `VAULT_TOKEN_FILE`.
    pub fn from_env() -> Result<Self> {
        let addr = std::env::var("VAULT_ADDR")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .ok_or_else(|| Error::Vault("VAULT_ADDR is not set".to_string()))?;
        let namespace = std::env::var("VAULT_NAMESPACE")
            .ok()
            .filter(|v| !v.trim().is_empty());
        let token = match std::env::var("VAULT_TOKEN")
            .ok()
            .filter(|v| !v.trim().is_empty())
        {
            Some(token) => Zeroizing::new(token),
            None => {
                let path = std::env::var("VAULT_TOKEN_FILE")
                    .ok()
                    .filter(|v| !v.trim().is_empty())
                    .ok_or_else(|| {
                        Error::Vault("neither VAULT_TOKEN nor VAULT_TOKEN_FILE is set".to_string())
                    })?;
                let text = fs::read_to_string(&path).map_err(|e| {
                    Error::Vault(format!("cannot read VAULT_TOKEN_FILE {path}: {e}"))
                })?;
                let token = Zeroizing::new(text.trim().to_string());
                if token.is_empty() {
                    return Err(Error::Vault(format!("VAULT_TOKEN_FILE {path} is empty")));
                }
                token
            }
        };
        Ok(VaultConfig {
            addr: http::normalise_base_url(&addr),
            namespace,
            token,
        })
    }

    /// The KV v2 data URL for a mount and path.
    pub fn data_url(&self, mount: &str, path: &str) -> String {
        format!(
            "{}/v1/{}/data/{}",
            self.addr,
            http::percent_encode(mount),
            http::percent_encode_path(path)
        )
    }

    /// Read one field of one KV v2 secret.
    pub fn read_field(&self, reference: &VaultRef) -> Result<Zeroizing<String>> {
        let url = self.data_url(&reference.mount, &reference.path);
        let mut request = http::agent()?.get(&url).set("X-Vault-Token", &self.token);
        if let Some(namespace) = &self.namespace {
            request = request.set("X-Vault-Namespace", namespace);
        }
        let response = match http::check(request.call()) {
            Ok(response) => response,
            // Vault error bodies name paths and policies, never the secret, but the safe habit is
            // to report the status and the locator and nothing else.
            Err(http::Failure::Status { code, .. }) => {
                return Err(Error::Vault(format!(
                    "{} returned HTTP {code} for {}{}",
                    self.addr,
                    reference.locator(),
                    http::redirect_note(code)
                )))
            }
            Err(http::Failure::Transport(reason)) => {
                return Err(Error::Vault(format!(
                    "cannot reach {} for {}: {reason}",
                    self.addr,
                    reference.locator()
                )))
            }
        };
        let body = Zeroizing::new(response.into_string().map_err(|_| {
            Error::Vault(format!("unreadable response for {}", reference.locator()))
        })?);
        extract_field(&body, &reference.field, &reference.locator())
    }
}

#[derive(Deserialize)]
struct KvV2Response {
    data: KvV2Data,
}

#[derive(Deserialize)]
struct KvV2Data {
    data: serde_json::Map<String, serde_json::Value>,
}

/// Pull `data.data.<field>` out of a KV v2 response body.
///
/// Split out from the HTTP call so the response contract is testable without a live Vault.
pub fn extract_field(body: &str, field: &str, locator: &str) -> Result<Zeroizing<String>> {
    let parsed: KvV2Response = serde_json::from_str(body)
        .map_err(|e| Error::Vault(format!("{locator}: response is not a KV v2 secret: {e}")))?;
    let value =
        parsed.data.data.get(field).ok_or_else(|| {
            Error::Vault(format!("{locator}: the secret has no field \"{field}\""))
        })?;
    match value {
        serde_json::Value::String(s) => Ok(Zeroizing::new(s.clone())),
        serde_json::Value::Null => Err(Error::Vault(format!(
            "{locator}: field \"{field}\" is null"
        ))),
        _ => Err(Error::Vault(format!(
            "{locator}: field \"{field}\" is not a string"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BODY: &str = r#"{
        "request_id": "9f0c6b4e-0000-0000-0000-000000000000",
        "lease_id": "",
        "renewable": false,
        "lease_duration": 0,
        "data": {
            "data": { "password": "hunter2", "username": "myapp", "port": 5432, "empty": null },
            "metadata": { "created_time": "2026-01-01T00:00:00Z", "version": 3 }
        },
        "warnings": null
    }"#;

    #[test]
    fn extracts_a_string_field() {
        let value = extract_field(BODY, "password", "secret/app#password").unwrap();
        assert_eq!(&*value, "hunter2");
    }

    #[test]
    fn rejects_a_missing_field() {
        let err = extract_field(BODY, "api_key", "secret/app#api_key").unwrap_err();
        assert!(err.to_string().contains("has no field"));
    }

    #[test]
    fn rejects_a_non_string_field() {
        let err = extract_field(BODY, "port", "secret/app#port").unwrap_err();
        assert!(err.to_string().contains("is not a string"));
    }

    #[test]
    fn rejects_a_null_field() {
        let err = extract_field(BODY, "empty", "secret/app#empty").unwrap_err();
        assert!(err.to_string().contains("is null"));
    }

    #[test]
    fn rejects_a_kv_v1_shaped_body() {
        let body = r#"{"data": {"password": "hunter2"}}"#;
        assert!(extract_field(body, "password", "secret/app#password").is_err());
    }

    #[test]
    fn builds_the_kv_v2_data_url() {
        let cfg = VaultConfig {
            addr: "https://vault.example".to_string(),
            namespace: None,
            token: Zeroizing::new("t".to_string()),
        };
        assert_eq!(
            cfg.data_url("secret", "myapp/prod/database"),
            "https://vault.example/v1/secret/data/myapp/prod/database"
        );
    }

    #[test]
    fn debug_does_not_leak_the_token() {
        let cfg = VaultConfig {
            addr: "https://vault.example".to_string(),
            namespace: Some("team-a".to_string()),
            token: Zeroizing::new("s.supersecret".to_string()),
        };
        let rendered = format!("{cfg:?}");
        assert!(rendered.contains("redacted"));
        assert!(!rendered.contains("supersecret"));
    }
}
