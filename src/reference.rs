//! Parsing and formatting of `seal:` references.
//!
//! Four shapes exist:
//!
//! ```text
//! seal:v1:<kid>:<base64url-no-pad(nonce || ciphertext || tag)>
//! seal:vault:<mount>/<path>#<field>
//! seal:conjur:<variable-id>
//! seal:ccp:<safe>/<object>#<field>
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

/// A CyberArk Conjur variable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConjurRef {
    /// The variable id, for example `prod/db/password`. The Conjur account and appliance URL are
    /// deployment facts and live in the environment, not in the reference.
    pub id: String,
}

impl ConjurRef {
    /// The variable id, safe to print: it names a location, not a secret.
    pub fn locator(&self) -> String {
        self.id.clone()
    }
}

/// A CyberArk Central Credential Provider account lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CcpRef {
    /// The safe holding the account.
    pub safe: String,
    /// The object name of the account inside the safe.
    pub object: String,
    /// The account property to read. The password is the property named `Content`.
    pub field: String,
}

impl CcpRef {
    /// `<safe>/<object>#<field>`, safe to print. The application id is deliberately not part of
    /// it, so it cannot reach a log through an error message.
    pub fn locator(&self) -> String {
        format!("{}/{}#{}", self.safe, self.object, self.field)
    }
}

/// A parsed `seal:` reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reference {
    V1(V1Ref),
    Vault(VaultRef),
    Conjur(ConjurRef),
    Ccp(CcpRef),
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
            "conjur" => Ok(Reference::Conjur(parse_conjur(body)?)),
            "ccp" => Ok(Reference::Ccp(parse_ccp(body)?)),
            other => Err(Error::UnknownProvider(other.to_string())),
        }
    }

    /// True when resolving this reference needs the network.
    pub fn is_remote(&self) -> bool {
        !matches!(self, Reference::V1(_))
    }

    /// The provider name, for diagnostics.
    pub fn provider(&self) -> &'static str {
        match self {
            Reference::V1(_) => "v1",
            Reference::Vault(_) => "vault",
            Reference::Conjur(_) => "conjur",
            Reference::Ccp(_) => "ccp",
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
    if has_dot_segment(mount) || has_dot_segment(path) {
        return Err(malformed(
            "the path has a \".\" or \"..\" segment, which would address another location",
        ));
    }
    Ok(VaultRef {
        mount: mount.to_string(),
        path: path.to_string(),
        field: field.to_string(),
    })
}

/// Characters the CyberArk Central Credential Provider cannot carry in a URL value.
///
/// `+` decodes to a space, `&` ends the parameter, and `%` starts an escape. CyberArk documents
/// all three as unsupported, so a reference that contains one is rejected at parse time rather
/// than producing a lookup that silently reads the wrong account.
const CCP_FORBIDDEN: &[char] = &['+', '&', '%'];

/// True when any `/`-separated segment is `.` or `..`.
///
/// Both are removed by URL normalisation before a request goes out, so a reference containing one
/// does not address the location it appears to address: `seal:conjur:../../other/variable/x` would
/// read a different account, and `seal:vault:secret/../../sys/seal-status#x` would leave the KV
/// mount entirely, in both cases carrying the run's token. The reference file is the artefact this
/// tool asks you to commit and review in a diff, so it must mean what it reads as.
fn has_dot_segment(path: &str) -> bool {
    path.split('/')
        .any(|segment| segment == "." || segment == "..")
}

fn parse_conjur(body: &str) -> Result<ConjurRef> {
    let malformed = |reason: &str| Error::Malformed {
        kind: "seal:conjur",
        reason: reason.to_string(),
    };
    if body.is_empty() {
        return Err(malformed("the variable id is empty"));
    }
    if body.chars().any(char::is_whitespace) {
        return Err(malformed("the variable id contains whitespace"));
    }
    if body.contains('#') {
        return Err(malformed(
            "a Conjur variable holds one value, so it takes no \"#field\"",
        ));
    }
    if body.starts_with('/') || body.ends_with('/') || body.contains("//") {
        return Err(malformed("the variable id has an empty path segment"));
    }
    if has_dot_segment(body) {
        return Err(malformed(
            "the variable id has a \".\" or \"..\" segment, which would address another location",
        ));
    }
    Ok(ConjurRef {
        id: body.to_string(),
    })
}

fn parse_ccp(body: &str) -> Result<CcpRef> {
    let malformed = |reason: &str| Error::Malformed {
        kind: "seal:ccp",
        reason: reason.to_string(),
    };
    let (locator, field) = body
        .split_once('#')
        .ok_or_else(|| malformed("expected seal:ccp:<safe>/<object>#<field>"))?;
    if field.is_empty() {
        return Err(malformed("the property name is empty"));
    }
    if field.contains('#') {
        return Err(malformed("the property name must not contain \"#\""));
    }
    let (safe, object) = locator
        .split_once('/')
        .ok_or_else(|| malformed("expected a safe and an object separated by \"/\""))?;
    if safe.is_empty() {
        return Err(malformed("the safe is empty"));
    }
    if object.is_empty() {
        return Err(malformed("the object is empty"));
    }
    if object.contains('/') {
        return Err(malformed(
            "the object name must not contain \"/\": subfolders are out of scope",
        ));
    }
    if field.contains('/') {
        return Err(malformed("the property name must not contain \"/\""));
    }
    for (name, value) in [("safe", safe), ("object", object), ("property", field)] {
        if value.trim() != value {
            return Err(malformed(&format!(
                "the {name} has leading or trailing whitespace"
            )));
        }
        if let Some(bad) = value.chars().find(|c| CCP_FORBIDDEN.contains(c)) {
            return Err(malformed(&format!(
                "the {name} contains \"{bad}\", which CyberArk cannot carry in a URL value"
            )));
        }
    }
    Ok(CcpRef {
        safe: safe.to_string(),
        object: object.to_string(),
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
            "seal:vault:secret/../../sys/seal-status#x",
            "seal:vault:../secret/app#password",
            "seal:vault:secret/./app#password",
        ] {
            assert!(
                Reference::parse(bad).is_err(),
                "expected {bad} to be rejected"
            );
        }
    }

    #[test]
    fn parses_a_conjur_reference() {
        match Reference::parse("seal:conjur:prod/db/password").unwrap() {
            Reference::Conjur(c) => {
                assert_eq!(c.id, "prod/db/password");
                assert_eq!(c.locator(), "prod/db/password");
            }
            other => panic!("expected a conjur reference, got {other:?}"),
        }
        assert!(Reference::parse("seal:conjur:single").is_ok());
        // A dot inside a segment is an ordinary character; only a whole "." or ".." segment is a
        // traversal.
        assert!(Reference::parse("seal:conjur:prod/db.password").is_ok());
        assert!(Reference::parse("seal:conjur:...").is_ok());
    }

    #[test]
    fn rejects_malformed_conjur_references() {
        for bad in [
            "seal:conjur:",
            "seal:conjur:has space",
            "seal:conjur:prod/db#password",
            "seal:conjur:/leading",
            "seal:conjur:trailing/",
            "seal:conjur:double//slash",
            "seal:conjur:../../otheracct/variable/prod/db",
            "seal:conjur:prod/../../../v1/sys/anything",
            "seal:conjur:prod/./db",
            "seal:conjur:..",
        ] {
            assert!(
                Reference::parse(bad).is_err(),
                "expected {bad} to be rejected"
            );
        }
    }

    #[test]
    fn parses_a_ccp_reference() {
        match Reference::parse("seal:ccp:MySafe/MyObject#Content").unwrap() {
            Reference::Ccp(c) => {
                assert_eq!(c.safe, "MySafe");
                assert_eq!(c.object, "MyObject");
                assert_eq!(c.field, "Content");
                assert_eq!(c.locator(), "MySafe/MyObject#Content");
            }
            other => panic!("expected a ccp reference, got {other:?}"),
        }
    }

    #[test]
    fn a_ccp_safe_may_contain_a_space() {
        // Safe names with spaces are ordinary in CyberArk, and a space percent-encodes cleanly.
        match Reference::parse("seal:ccp:Prod Databases/pg-main#Content").unwrap() {
            Reference::Ccp(c) => assert_eq!(c.safe, "Prod Databases"),
            other => panic!("expected a ccp reference, got {other:?}"),
        }
    }

    #[test]
    fn rejects_malformed_ccp_references() {
        for bad in [
            "seal:ccp:MySafe/MyObject",
            "seal:ccp:MySafe#Content",
            "seal:ccp:/MyObject#Content",
            "seal:ccp:MySafe/#Content",
            "seal:ccp:MySafe/MyObject#",
            "seal:ccp:MySafe/Folder/Object#Content",
            "seal:ccp:My&Safe/MyObject#Content",
            "seal:ccp:MySafe/My+Object#Content",
            "seal:ccp:MySafe/MyObject#Con%tent",
            "seal:ccp: MySafe/MyObject#Content",
            "seal:ccp:MySafe/MyObject#a/b",
        ] {
            assert!(
                Reference::parse(bad).is_err(),
                "expected {bad} to be rejected"
            );
        }
    }

    #[test]
    fn knows_which_references_need_the_network() {
        assert!(!Reference::parse(&format_v1("k1", &[0u8; MIN_BLOB_LEN]))
            .unwrap()
            .is_remote());
        for remote in [
            "seal:vault:secret/app#password",
            "seal:conjur:prod/db/password",
            "seal:ccp:MySafe/MyObject#Content",
        ] {
            assert!(Reference::parse(remote).unwrap().is_remote());
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
