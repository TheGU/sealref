//! The keyring: where master keys come from and how they are written down.
//!
//! Keyring text is one key per line:
//!
//! ```text
//! # comment
//! k20260101 QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWY
//! dev       argon2id:not-a-real-secret
//! ```
//!
//! The first key line is the default key used by `sealref seal`. The `argon2id:` form exists so a
//! development keyring can be committed without holding anything that looks like a secret to a
//! scanner; production keys must be random keys from `sealref keygen`.

use std::fs;
use std::path::Path;
#[cfg(unix)]
use std::sync::atomic::{AtomicBool, Ordering};

use argon2::{Algorithm, Argon2, Params, Version};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::reference;
use crate::{Error, Result};

/// Read when `SEALREF_KEY_FILE` is unset and this path exists.
pub const DEFAULT_KEY_FILE: &str = "/run/secrets/sealref_key";

/// The environment variables that can carry a keyring into this process.
///
/// `exec` strips these from the environment it hands to the application. A master key that opens
/// every sealed value is a larger prize than the one password the application asked for, and no
/// application has a reason to read it.
pub const KEY_SOURCE_VARS: &[&str] = &["SEALREF_KEY", "SEALREF_KEY_FILE", "SEALREF_KEY_FD"];

/// Set once the `SEALREF_KEY_FD` descriptor has been taken ownership of, so it is never closed
/// twice. A double close would be worse than a leak: the number can already have been reused by
/// another open file by then.
#[cfg(unix)]
static KEY_FD_TAKEN: AtomicBool = AtomicBool::new(false);

/// Argon2id memory cost, in KiB (64 MiB).
pub const ARGON2_MEMORY_KIB: u32 = 65_536;

/// Argon2id time cost.
pub const ARGON2_TIME: u32 = 3;

/// Argon2id parallelism.
pub const ARGON2_LANES: u32 = 1;

/// One entry of the keyring.
pub struct Key {
    kid: String,
    secret: Zeroizing<[u8; 32]>,
}

impl Key {
    /// The key id this entry answers to.
    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// The raw 32-byte key.
    pub fn bytes(&self) -> &[u8; 32] {
        &self.secret
    }
}

impl std::fmt::Debug for Key {
    /// Never render the key material, not even in a panic message.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Key")
            .field("kid", &self.kid)
            .field("secret", &"<redacted>")
            .finish()
    }
}

/// An ordered set of keys. The first one is the default for sealing.
#[derive(Debug, Default)]
pub struct Keyring {
    keys: Vec<Key>,
}

impl Keyring {
    /// Parse keyring text. Blank lines and `#` comments are ignored.
    pub fn parse(text: &str) -> Result<Self> {
        let mut keys: Vec<Key> = Vec::new();
        for (index, raw) in text.lines().enumerate() {
            let line = index + 1;
            let trimmed = raw.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let (kid, rest) =
                trimmed
                    .split_once(char::is_whitespace)
                    .ok_or_else(|| Error::KeyringSyntax {
                        line,
                        reason: "expected \"<kid> <key>\"".to_string(),
                    })?;
            let rest = rest.trim();
            if !reference::is_valid_kid(kid) {
                return Err(Error::KeyringSyntax {
                    line,
                    reason: format!(
                        "invalid key id \"{kid}\": expected 1 to 64 characters from [A-Za-z0-9._-]"
                    ),
                });
            }
            if keys.iter().any(|k| k.kid == kid) {
                return Err(Error::DuplicateKid {
                    line,
                    kid: kid.to_string(),
                });
            }
            let secret = if let Some(passphrase) = rest.strip_prefix("argon2id:") {
                if passphrase.is_empty() {
                    return Err(Error::KeyringSyntax {
                        line,
                        reason: "argon2id passphrase is empty".to_string(),
                    });
                }
                derive_key(kid, passphrase)?
            } else {
                decode_key(rest).map_err(|reason| Error::KeyringSyntax { line, reason })?
            };
            keys.push(Key {
                kid: kid.to_string(),
                secret,
            });
        }
        if keys.is_empty() {
            return Err(Error::EmptyKeyring);
        }
        Ok(Keyring { keys })
    }

    /// Look up a key by id.
    pub fn get(&self, kid: &str) -> Result<&Key> {
        self.keys
            .iter()
            .find(|k| k.kid == kid)
            .ok_or_else(|| Error::UnknownKid(kid.to_string()))
    }

    /// The first key line, used by `seal` when no `--kid` is given.
    pub fn default_key(&self) -> Result<&Key> {
        self.keys.first().ok_or(Error::EmptyKeyring)
    }

    /// Number of keys held.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// True when no key is held. A parsed keyring is never empty.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// The key ids held, in keyring order.
    pub fn kids(&self) -> impl Iterator<Item = &str> {
        self.keys.iter().map(|k| k.kid.as_str())
    }
}

fn decode_key(encoded: &str) -> std::result::Result<Zeroizing<[u8; 32]>, String> {
    let bytes = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(encoded.as_bytes())
            .map_err(|_| "key is not unpadded base64url".to_string())?,
    );
    if bytes.len() != 32 {
        return Err(format!("key is {} bytes, expected 32", bytes.len()));
    }
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Stretch a passphrase into a 32-byte key with Argon2id.
///
/// The salt is `SHA-256("sealref:argon2id:<kid>")`, which is deterministic on purpose: the same
/// keyring line must produce the same key on every host, or a committed development keyring would
/// be useless. That determinism is exactly why this form is for development only.
pub fn derive_key(kid: &str, passphrase: &str) -> Result<Zeroizing<[u8; 32]>> {
    let salt = Sha256::digest(format!("sealref:argon2id:{kid}").as_bytes());
    let params =
        Params::new(ARGON2_MEMORY_KIB, ARGON2_TIME, ARGON2_LANES, Some(32)).map_err(|e| {
            Error::KeyDerivation {
                kid: kid.to_string(),
                reason: e.to_string(),
            }
        })?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(passphrase.as_bytes(), &salt, &mut *out)
        .map_err(|e| Error::KeyDerivation {
            kid: kid.to_string(),
            reason: e.to_string(),
        })?;
    Ok(out)
}

/// Load the keyring from the first source that is present.
///
/// Order: `SEALREF_KEY_FD`, then `SEALREF_KEY_FILE` (or [`DEFAULT_KEY_FILE`] when it exists), then
/// `SEALREF_KEY`.
pub fn load() -> Result<Keyring> {
    let text = load_text()?;
    Keyring::parse(&text)
}

fn load_text() -> Result<Zeroizing<String>> {
    if let Ok(fd) = std::env::var("SEALREF_KEY_FD") {
        return read_fd(&fd);
    }
    if let Ok(path) = std::env::var("SEALREF_KEY_FILE") {
        return read_file(Path::new(&path));
    }
    if Path::new(DEFAULT_KEY_FILE).exists() {
        return read_file(Path::new(DEFAULT_KEY_FILE));
    }
    if let Ok(inline) = std::env::var("SEALREF_KEY") {
        return Ok(Zeroizing::new(inline.replace(';', "\n")));
    }
    Err(Error::NoKeySource)
}

fn read_file(path: &Path) -> Result<Zeroizing<String>> {
    let text = fs::read_to_string(path).map_err(|e| Error::io(path.display().to_string(), e))?;
    Ok(Zeroizing::new(text))
}

#[cfg(unix)]
fn parse_fd(fd: &str) -> Result<i32> {
    let raw: i32 = fd
        .trim()
        .parse()
        .map_err(|_| Error::Msg(format!("SEALREF_KEY_FD is not a file descriptor: \"{fd}\"")))?;
    if raw < 0 {
        return Err(Error::Msg(format!(
            "SEALREF_KEY_FD is not a file descriptor: \"{fd}\""
        )));
    }
    Ok(raw)
}

#[cfg(unix)]
fn read_fd(fd: &str) -> Result<Zeroizing<String>> {
    use std::io::Read;
    use std::os::fd::FromRawFd;

    let raw = parse_fd(fd)?;
    if KEY_FD_TAKEN.swap(true, Ordering::SeqCst) {
        return Err(Error::Msg(
            "SEALREF_KEY_FD has already been read: a descriptor can only be consumed once"
                .to_string(),
        ));
    }
    // Safety: the caller states this descriptor is open and holds keyring text, and the swap above
    // guarantees nothing else has taken it. Taking ownership means it is closed once the keyring
    // is parsed, which is what we want for key material.
    let mut file = unsafe { std::fs::File::from_raw_fd(raw) };
    let mut text = Zeroizing::new(String::new());
    file.read_to_string(&mut text)
        .map_err(|e| Error::io(format!("SEALREF_KEY_FD={raw}"), e))?;
    Ok(text)
}

#[cfg(not(unix))]
fn read_fd(_fd: &str) -> Result<Zeroizing<String>> {
    Err(Error::Msg(
        "SEALREF_KEY_FD is not supported on Windows: use SEALREF_KEY_FILE or SEALREF_KEY"
            .to_string(),
    ))
}

/// Close the `SEALREF_KEY_FD` descriptor if nothing has consumed it yet.
///
/// Removing `SEALREF_KEY_FD` from the environment handed to the application is not enough on its
/// own. The descriptor itself is inherited across `execvp` unless something closes it, and the
/// shell or supervisor that opened it did not set close-on-exec, so an application could simply
/// read the whole keyring from descriptor 3. A run whose references are all remote never loads the
/// keyring at all, so the descriptor would still be open at handover.
///
/// Call this after every reference has been resolved and immediately before handing the process
/// over. Calling it earlier would close the descriptor out from under a `seal:v1` reference that
/// has not been resolved yet.
pub fn close_key_fd() {
    #[cfg(unix)]
    {
        use std::os::fd::FromRawFd;

        let Ok(fd) = std::env::var("SEALREF_KEY_FD") else {
            return;
        };
        let Ok(raw) = parse_fd(&fd) else {
            return;
        };
        if KEY_FD_TAKEN.swap(true, Ordering::SeqCst) {
            return;
        }
        // Safety: the swap above guarantees this descriptor has not been taken, so nothing else
        // owns it. Dropping the File closes it.
        drop(unsafe { std::fs::File::from_raw_fd(raw) });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RAW: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";

    #[test]
    fn parses_a_raw_key_line() {
        let ring = Keyring::parse(&format!("k1 {RAW}")).unwrap();
        assert_eq!(ring.len(), 1);
        assert_eq!(ring.default_key().unwrap().kid(), "k1");
        assert_eq!(ring.get("k1").unwrap().bytes()[0], 0);
        assert_eq!(ring.get("k1").unwrap().bytes()[31], 31);
    }

    #[test]
    fn ignores_comments_and_blank_lines() {
        let text = format!("# a comment\n\n   \nk1 {RAW}\n# trailing\n");
        let ring = Keyring::parse(&text).unwrap();
        assert_eq!(ring.len(), 1);
    }

    #[test]
    fn the_first_line_is_the_default_key() {
        let text = format!("old {RAW}\nnew argon2id:dev-only\n");
        let ring = Keyring::parse(&text).unwrap();
        assert_eq!(ring.default_key().unwrap().kid(), "old");
        assert_eq!(ring.kids().collect::<Vec<_>>(), vec!["old", "new"]);
    }

    #[test]
    fn rejects_a_duplicate_key_id() {
        let text = format!("k1 {RAW}\nk1 argon2id:dev-only\n");
        assert!(matches!(
            Keyring::parse(&text).unwrap_err(),
            Error::DuplicateKid { kid, .. } if kid == "k1"
        ));
    }

    #[test]
    fn rejects_a_wrong_length_key() {
        assert!(matches!(
            Keyring::parse("k1 AAEC").unwrap_err(),
            Error::KeyringSyntax { .. }
        ));
    }

    #[test]
    fn rejects_an_empty_keyring() {
        assert!(matches!(
            Keyring::parse("# nothing here\n").unwrap_err(),
            Error::EmptyKeyring
        ));
    }

    #[test]
    fn rejects_an_unknown_key_id_lookup() {
        let ring = Keyring::parse(&format!("k1 {RAW}")).unwrap();
        assert!(matches!(ring.get("k2").unwrap_err(), Error::UnknownKid(_)));
    }

    #[test]
    fn argon2id_derivation_is_deterministic() {
        let a = derive_key("dev", "correct horse battery staple").unwrap();
        let b = derive_key("dev", "correct horse battery staple").unwrap();
        assert_eq!(*a, *b);
    }

    /// The `argon2id:` form must derive the same key it derived in earlier releases.
    ///
    /// A committed development keyring is only useful because this derivation is fixed, and the
    /// two tests around this one would both still pass if an upgrade of `argon2` or `sha2` changed
    /// the salt or the parameters. These vectors were produced once and are never regenerated.
    #[test]
    fn argon2id_derivation_matches_frozen_vectors() {
        fn hex(bytes: &[u8]) -> String {
            bytes.iter().map(|b| format!("{b:02x}")).collect()
        }

        let dev = derive_key("dev", "correct horse battery staple").unwrap();
        assert_eq!(
            hex(&*dev),
            "26080f33732ff86cf90649745fe23f58ab70f62bd1af726873d4adc0bdc0a3a6"
        );

        let stage = derive_key("stage", "correct horse battery staple").unwrap();
        assert_eq!(
            hex(&*stage),
            "565721cae6aaed6d0b47ff9d5d8d22d194cf5c60991da8d62cfe8892c44913a2"
        );
    }

    #[test]
    fn argon2id_derivation_is_bound_to_the_key_id() {
        let a = derive_key("dev", "same passphrase").unwrap();
        let b = derive_key("stage", "same passphrase").unwrap();
        assert_ne!(*a, *b);
    }

    #[test]
    fn argon2id_keyring_lines_match_direct_derivation() {
        let ring = Keyring::parse("dev argon2id:correct horse battery staple").unwrap();
        let direct = derive_key("dev", "correct horse battery staple").unwrap();
        assert_eq!(ring.get("dev").unwrap().bytes(), &*direct);
    }

    #[test]
    fn rejects_an_empty_passphrase() {
        assert!(matches!(
            Keyring::parse("dev argon2id:").unwrap_err(),
            Error::KeyringSyntax { .. }
        ));
    }

    #[test]
    fn semicolon_separated_text_parses_after_normalisation() {
        let text = format!("k1 {RAW};k2 argon2id:dev-only").replace(';', "\n");
        assert_eq!(Keyring::parse(&text).unwrap().len(), 2);
    }

    #[test]
    fn debug_does_not_leak_key_material() {
        let ring = Keyring::parse(&format!("k1 {RAW}")).unwrap();
        let rendered = format!("{:?}", ring.get("k1").unwrap());
        assert!(rendered.contains("redacted"));
        assert!(!rendered.contains("31"));
    }
}
