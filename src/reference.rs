//! Parsing and formatting of `seal:` references.
//!
//! Two shapes exist in v0.1:
//!
//! ```text
//! seal:v1:<kid>:<base64url-no-pad(nonce || ciphertext || tag)>
//! seal:vault:<mount>/<path>#<field>
//! ```
//!
//! Anything else that starts with `seal:` is an error. Anything that does not start with `seal:`
//! is not a reference at all and passes through untouched.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

use crate::{Error, Result};

/// The prefix that marks a value as a reference.
pub const PREFIX: &str = "seal:";

/// XChaCha20-Poly1305 nonce length.
pub const NONCE_LEN: usize = 24;

/// Poly1305 authentication tag length.
pub const TAG_LEN: usize = 16;

/// Shortest possible `seal:v1` payload: a nonce, a tag, and an empty plaintext.
pub const MIN_BLOB_LEN: usize = NONCE_LEN + TAG_LEN;

/// True when the value carries the reference prefix.
pub fn is_reference(value: &str) -> bool {
    value.starts_with(PREFIX)
}

/// True when `kid` is `[A-Za-z0-9._-]{1,64}`.
pub fn is_valid_kid(kid: &str) -> bool {
    !kid.is_empty()
        && kid.len() <= 64
        && kid
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-')
}

/// Render a sealed blob as a `seal:v1` reference.
pub fn format_v1(kid: &str, blob: &[u8]) -> String {
    format!("{PREFIX}v1:{kid}:{}", URL_SAFE_NO_PAD.encode(blob))
}

/// A locally encrypted secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V1Ref {
    /// Key id naming the keyring entry that can open this reference.
    pub kid: String,
    /// `nonce || ciphertext || tag`, already base64url-decoded.
    pub blob: Vec<u8>,
}

/// A HashiCorp Vault KV v2 lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultRef {
    /// KV v2 mount point, for example `secret`.
    pub mount: String,
    /// Path under the mount, for example `myapp/prod/database`.
    pub path: String,
    /// Field to read out of `data.data`.
    pub field: String,
}

impl VaultRef {
    /// `<mount>/<path>#<field>`, safe to print: it names a location, not a secret.
    pub fn locator(&self) -> String {
        format!("{}/{}#{}", self.mount, self.path, self.field)
    }
}

/// A parsed `seal:` reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reference {
    V1(V1Ref),
    Vault(VaultRef),
}

impl Reference {
    /// Parse a whole value. The value must start with `seal:`.
    pub fn parse(value: &str) -> Result<Self> {
        let rest = value.strip_prefix(PREFIX).ok_or(Error::NotAReference)?;
        let (provider, body) = rest.split_once(':').ok_or_else(|| Error::Malformed {
            kind: "seal",
            reason: "expected seal:<provider>:<body>".to_string(),
        })?;
        match provider {
            "v1" => Ok(Reference::V1(parse_v1(body)?)),
            "vault" => Ok(Reference::Vault(parse_vault(body)?)),
            other => Err(Error::UnknownProvider(other.to_string())),
        }
    }

    /// The provider name, for diagnostics.
    pub fn provider(&self) -> &'static str {
        match self {
            Reference::V1(_) => "v1",
            Reference::Vault(_) => "vault",
        }
    }
}

fn parse_v1(body: &str) -> Result<V1Ref> {
    let (kid, encoded) = body.split_once(':').ok_or_else(|| Error::Malformed {
        kind: "seal:v1",
        reason: "expected seal:v1:<kid>:<ciphertext>".to_string(),
    })?;
    if !is_valid_kid(kid) {
        return Err(Error::InvalidKid(kid.to_string()));
    }
    let blob = URL_SAFE_NO_PAD
        .decode(encoded.as_bytes())
        .map_err(|_| Error::Malformed {
            kind: "seal:v1",
            reason: "ciphertext is not unpadded base64url".to_string(),
        })?;
    if blob.len() < MIN_BLOB_LEN {
        return Err(Error::Malformed {
            kind: "seal:v1",
            reason: format!("ciphertext is shorter than {MIN_BLOB_LEN} bytes"),
        });
    }
    Ok(V1Ref {
        kid: kid.to_string(),
        blob,
    })
}

fn parse_vault(body: &str) -> Result<VaultRef> {
    let malformed = |reason: &str| Error::Malformed {
        kind: "seal:vault",
        reason: reason.to_string(),
    };
    let (locator, field) = body
        .split_once('#')
        .ok_or_else(|| malformed("expected seal:vault:<mount>/<path>#<field>"))?;
    if field.contains('#') {
        return Err(malformed("field name must not contain \"#\""));
    }
    if field.is_empty() {
        return Err(malformed("field name is empty"));
    }
    let (mount, path) = locator
        .split_once('/')
        .ok_or_else(|| malformed("expected a mount and a path separated by \"/\""))?;
    if mount.is_empty() {
        return Err(malformed("mount is empty"));
    }
    if path.is_empty() {
        return Err(malformed("path is empty"));
    }
    if body.chars().any(char::is_whitespace) {
        return Err(malformed("reference contains whitespace"));
    }
    Ok(VaultRef {
        mount: mount.to_string(),
        path: path.to_string(),
        field: field.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_the_prefix() {
        assert!(is_reference("seal:v1:k:AAAA"));
        assert!(!is_reference("plain-value"));
        assert!(!is_reference("sealed:v1:k:AAAA"));
    }

    #[test]
    fn validates_key_ids() {
        assert!(is_valid_kid("k20260101"));
        assert!(is_valid_kid("prod.a-1_2"));
        assert!(!is_valid_kid(""));
        assert!(!is_valid_kid("has space"));
        assert!(!is_valid_kid("has:colon"));
        assert!(!is_valid_kid(&"x".repeat(65)));
    }

    #[test]
    fn parses_a_v1_reference() {
        let blob = vec![7u8; MIN_BLOB_LEN + 3];
        let text = format_v1("k1", &blob);
        match Reference::parse(&text).unwrap() {
            Reference::V1(r) => {
                assert_eq!(r.kid, "k1");
                assert_eq!(r.blob, blob);
            }
            other => panic!("expected a v1 reference, got {other:?}"),
        }
    }

    #[test]
    fn rejects_an_unknown_provider() {
        let err = Reference::parse("seal:aws-sm:whatever").unwrap_err();
        assert!(matches!(err, Error::UnknownProvider(p) if p == "aws-sm"));
    }

    #[test]
    fn rejects_malformed_base64() {
        let err = Reference::parse("seal:v1:k1:not base64!!").unwrap_err();
        assert!(matches!(
            err,
            Error::Malformed {
                kind: "seal:v1",
                ..
            }
        ));
    }

    #[test]
    fn rejects_a_short_blob() {
        let err = Reference::parse(&format_v1("k1", &[0u8; 8])).unwrap_err();
        assert!(matches!(
            err,
            Error::Malformed {
                kind: "seal:v1",
                ..
            }
        ));
    }

    #[test]
    fn rejects_a_bad_key_id() {
        let err = Reference::parse("seal:v1::AAAA").unwrap_err();
        assert!(matches!(err, Error::InvalidKid(_)));
    }

    #[test]
    fn parses_a_vault_reference() {
        let r = Reference::parse("seal:vault:secret/myapp/prod/database#password").unwrap();
        match r {
            Reference::Vault(v) => {
                assert_eq!(v.mount, "secret");
                assert_eq!(v.path, "myapp/prod/database");
                assert_eq!(v.field, "password");
                assert_eq!(v.locator(), "secret/myapp/prod/database#password");
            }
            other => panic!("expected a vault reference, got {other:?}"),
        }
    }

    #[test]
    fn rejects_incomplete_vault_references() {
        for bad in [
            "seal:vault:secret/path",
            "seal:vault:secret#field",
            "seal:vault:/path#field",
            "seal:vault:secret/path#",
            "seal:vault:secret/path#a#b",
            "seal:vault:secret/pa th#field",
        ] {
            assert!(
                Reference::parse(bad).is_err(),
                "expected {bad} to be rejected"
            );
        }
    }

    #[test]
    fn rejects_a_non_reference() {
        assert!(matches!(
            Reference::parse("hunter2").unwrap_err(),
            Error::NotAReference
        ));
    }
}
