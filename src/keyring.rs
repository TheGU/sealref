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

use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
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

/// Domain separation for key fingerprints, so a fingerprint is never the same hash as anything
/// else computed over a key.
pub const FINGERPRINT_LABEL: &[u8] = b"sealref:fingerprint:";

/// How a keyring line wrote its key down.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyForm {
    /// A base64url line holding 32 random bytes, as `keygen` prints.
    Random,
    /// An `argon2id:<passphrase>` line, for development keyrings.
    Argon2id,
}

impl fmt::Display for KeyForm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            KeyForm::Random => "random",
            KeyForm::Argon2id => "argon2id",
        })
    }
}

/// One entry of the keyring.
pub struct Key {
    kid: String,
    form: KeyForm,
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

    /// How the keyring line wrote this key down.
    pub fn form(&self) -> KeyForm {
        self.form
    }

    /// A short public identifier of the key material: the first 8 bytes of
    /// `SHA-256(FINGERPRINT_LABEL || key)` as 16 lowercase hex characters.
    ///
    /// It lets two hosts confirm they hold the same key without either one revealing it. For a
    /// random key, a 64-bit truncation of a domain-separated hash of 256 random bits reveals
    /// nothing usable. For an argon2id key it is an offline test for passphrase guesses, but any
    /// sealed value already offers the same test through its AEAD tag, every guess still costs a
    /// full Argon2id run, and that form is for development keyrings by design.
    pub fn fingerprint(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(FINGERPRINT_LABEL);
        // The hasher buffers these bytes and is not zeroized when it is dropped. That copy lives
        // for the rest of one short command, which is acceptable here.
        hasher.update(self.secret.as_slice());
        let digest = hasher.finalize();
        digest[..8].iter().map(|b| format!("{b:02x}")).collect()
    }
}

impl std::fmt::Debug for Key {
    /// Never render the key material, not even in a panic message.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Key")
            .field("kid", &self.kid)
            .field("form", &self.form)
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
            // The offending text is not echoed: on a line written the wrong way round, such as
            // `argon2id:<passphrase> dev`, it is the passphrase.
            if !reference::is_valid_kid(kid) {
                return Err(Error::KeyringSyntax {
                    line,
                    reason: "invalid key id: expected 1 to 64 characters from [A-Za-z0-9._-]"
                        .to_string(),
                });
            }
            if keys.iter().any(|k| k.kid == kid) {
                return Err(Error::DuplicateKid {
                    line,
                    kid: kid.to_string(),
                });
            }
            let (form, secret) = if let Some(passphrase) = rest.strip_prefix("argon2id:") {
                if passphrase.is_empty() {
                    return Err(Error::KeyringSyntax {
                        line,
                        reason: "argon2id passphrase is empty".to_string(),
                    });
                }
                (KeyForm::Argon2id, derive_key(kid, passphrase)?)
            } else {
                let secret =
                    decode_key(rest).map_err(|reason| Error::KeyringSyntax { line, reason })?;
                (KeyForm::Random, secret)
            };
            keys.push(Key {
                kid: kid.to_string(),
                form,
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

    /// The keys held, in keyring order.
    pub fn keys(&self) -> impl Iterator<Item = &Key> {
        self.keys.iter()
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

/// Where a keyring comes from.
///
/// It names the source and never carries keyring text: `Inline` in particular holds nothing, so
/// rendering a source can never print a key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeySource {
    /// `SEALREF_KEY_FD`, with the descriptor number as written.
    Fd(String),
    /// `SEALREF_KEY_FILE`, with the path it names.
    File(PathBuf),
    /// [`DEFAULT_KEY_FILE`], used when `SEALREF_KEY_FILE` is unset and the file exists.
    DefaultFile,
    /// `SEALREF_KEY`.
    Inline,
}

impl fmt::Display for KeySource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeySource::Fd(fd) => write!(f, "SEALREF_KEY_FD {fd}"),
            KeySource::File(path) => write!(f, "SEALREF_KEY_FILE {}", path.display()),
            KeySource::DefaultFile => write!(f, "{DEFAULT_KEY_FILE} (default path)"),
            KeySource::Inline => f.write_str("SEALREF_KEY (environment variable)"),
        }
    }
}

/// Every source that is present, in precedence order, named as `info` reports it.
///
/// `detect_source` and `ignored_sources` both come from this one list, so what `info` reports as
/// used and as ignored cannot drift from what `load` actually reads.
fn present_sources(
    env: &dyn Fn(&str) -> Option<String>,
    default_file_exists: bool,
) -> Vec<(&'static str, KeySource)> {
    let mut present = Vec::new();
    if let Some(fd) = env("SEALREF_KEY_FD") {
        present.push(("SEALREF_KEY_FD", KeySource::Fd(fd)));
    }
    if let Some(path) = env("SEALREF_KEY_FILE") {
        present.push(("SEALREF_KEY_FILE", KeySource::File(PathBuf::from(path))));
    }
    if default_file_exists {
        present.push((DEFAULT_KEY_FILE, KeySource::DefaultFile));
    }
    // Only presence is needed, but the lookup copies the keyring text, so the copy is zeroized.
    if env("SEALREF_KEY").map(Zeroizing::new).is_some() {
        present.push(("SEALREF_KEY", KeySource::Inline));
    }
    present
}

/// The source `load` reads, if any.
///
/// Order: `SEALREF_KEY_FD`, then `SEALREF_KEY_FILE`, then [`DEFAULT_KEY_FILE`] when it exists,
/// then `SEALREF_KEY`. A variable set to the empty string counts as set. `env` looks a variable up;
/// taking it as a parameter keeps this testable without touching the process environment.
pub fn detect_source(
    env: &dyn Fn(&str) -> Option<String>,
    default_file_exists: bool,
) -> Option<KeySource> {
    present_sources(env, default_file_exists)
        .into_iter()
        .next()
        .map(|(_, source)| source)
}

/// The sources that are present but outranked by the one `load` reads, in precedence order.
///
/// These answer the question "why is my key not being used". The default path is named
/// [`DEFAULT_KEY_FILE`].
pub fn ignored_sources(
    env: &dyn Fn(&str) -> Option<String>,
    default_file_exists: bool,
) -> Vec<&'static str> {
    present_sources(env, default_file_exists)
        .into_iter()
        .skip(1)
        .map(|(name, _)| name)
        .collect()
}

/// Look a variable up in the process environment the way [`load`] does, for callers that need
/// [`detect_source`] or [`ignored_sources`] to agree with it.
pub fn process_env(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

/// Load the keyring from the first source that is present. See [`detect_source`] for the order.
pub fn load() -> Result<Keyring> {
    let source = detect_source(&process_env, Path::new(DEFAULT_KEY_FILE).exists())
        .ok_or(Error::NoKeySource)?;
    load_from(&source)
}

/// Read and parse the keyring from one source.
pub fn load_from(source: &KeySource) -> Result<Keyring> {
    let text = match source {
        KeySource::Fd(fd) => read_fd(fd)?,
        KeySource::File(path) => read_file(path)?,
        KeySource::DefaultFile => read_file(Path::new(DEFAULT_KEY_FILE))?,
        KeySource::Inline => {
            let inline = Zeroizing::new(process_env("SEALREF_KEY").ok_or(Error::NoKeySource)?);
            Zeroizing::new(inline.replace(';', "\n"))
        }
    };
    Keyring::parse(&text)
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
    fn a_swapped_line_does_not_echo_the_passphrase() {
        let err = Keyring::parse("argon2id:mypass dev\n").unwrap_err();
        assert!(matches!(err, Error::KeyringSyntax { line: 1, .. }));
        let message = err.to_string();
        assert!(message.contains("invalid key id"), "{message}");
        assert!(!message.contains("mypass"), "{message}");
    }

    #[test]
    fn records_the_form_of_each_key() {
        let ring = Keyring::parse(&format!("k1 {RAW}\ndev argon2id:dev-only\n")).unwrap();
        assert_eq!(ring.get("k1").unwrap().form(), KeyForm::Random);
        assert_eq!(ring.get("dev").unwrap().form(), KeyForm::Argon2id);
        assert_eq!(KeyForm::Random.to_string(), "random");
        assert_eq!(KeyForm::Argon2id.to_string(), "argon2id");
    }

    /// A fingerprint is compared across hosts and releases, so it must never change for a given
    /// key. These vectors were produced once and are never regenerated.
    #[test]
    fn fingerprints_match_frozen_vectors() {
        let ring = Keyring::parse(&format!(
            "k1 {RAW}\ndev argon2id:correct horse battery staple\n"
        ))
        .unwrap();
        assert_eq!(ring.get("k1").unwrap().fingerprint(), "f9d9eb43a1454ce3");
        assert_eq!(ring.get("dev").unwrap().fingerprint(), "29868f8a7931ceaa");
    }

    #[test]
    fn a_fingerprint_is_sixteen_hex_characters_and_not_the_key() {
        let ring = Keyring::parse(&format!("k1 {RAW}")).unwrap();
        let key = ring.get("k1").unwrap();
        let fingerprint = key.fingerprint();
        assert_eq!(fingerprint.len(), 16);
        assert!(fingerprint
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)));
        let key_hex: String = key.bytes().iter().map(|b| format!("{b:02x}")).collect();
        assert!(!key_hex.contains(&fingerprint));
    }

    fn env_of(vars: &'static [(&'static str, &'static str)]) -> impl Fn(&str) -> Option<String> {
        move |name| {
            vars.iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| v.to_string())
        }
    }

    #[test]
    fn detects_sources_in_precedence_order() {
        let all = env_of(&[
            ("SEALREF_KEY", "k1 x"),
            ("SEALREF_KEY_FILE", "/k/file"),
            ("SEALREF_KEY_FD", "3"),
        ]);
        assert_eq!(
            detect_source(&all, true),
            Some(KeySource::Fd("3".to_string()))
        );
        assert_eq!(
            ignored_sources(&all, true),
            vec!["SEALREF_KEY_FILE", DEFAULT_KEY_FILE, "SEALREF_KEY"]
        );

        let file = env_of(&[("SEALREF_KEY_FILE", "/k/file"), ("SEALREF_KEY", "k1 x")]);
        assert_eq!(
            detect_source(&file, false),
            Some(KeySource::File(PathBuf::from("/k/file")))
        );
        assert_eq!(ignored_sources(&file, false), vec!["SEALREF_KEY"]);

        let inline = env_of(&[("SEALREF_KEY", "k1 x")]);
        assert_eq!(detect_source(&inline, true), Some(KeySource::DefaultFile));
        assert_eq!(ignored_sources(&inline, true), vec!["SEALREF_KEY"]);
        assert_eq!(detect_source(&inline, false), Some(KeySource::Inline));
        assert!(ignored_sources(&inline, false).is_empty());

        let none = env_of(&[]);
        assert_eq!(detect_source(&none, false), None);
        assert!(ignored_sources(&none, false).is_empty());
    }

    #[test]
    fn a_variable_set_to_the_empty_string_is_a_source() {
        let empty = env_of(&[("SEALREF_KEY_FILE", ""), ("SEALREF_KEY", "k1 x")]);
        assert_eq!(
            detect_source(&empty, false),
            Some(KeySource::File(PathBuf::new()))
        );
        assert_eq!(ignored_sources(&empty, false), vec!["SEALREF_KEY"]);
    }

    #[test]
    fn key_sources_render_their_names_only() {
        assert_eq!(
            KeySource::Fd("3".to_string()).to_string(),
            "SEALREF_KEY_FD 3"
        );
        assert_eq!(
            KeySource::File(PathBuf::from("/home/app/dev.key")).to_string(),
            "SEALREF_KEY_FILE /home/app/dev.key"
        );
        assert_eq!(
            KeySource::DefaultFile.to_string(),
            "/run/secrets/sealref_key (default path)"
        );
        assert_eq!(
            KeySource::Inline.to_string(),
            "SEALREF_KEY (environment variable)"
        );
    }

    #[test]
    fn loads_from_a_file_source() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("test.key");
        fs::write(&path, format!("k1 {RAW}\n")).unwrap();
        let ring = load_from(&KeySource::File(path)).unwrap();
        assert_eq!(ring.kids().collect::<Vec<_>>(), vec!["k1"]);
    }

    #[test]
    fn debug_does_not_leak_key_material() {
        let ring = Keyring::parse(&format!("k1 {RAW}")).unwrap();
        let rendered = format!("{:?}", ring.get("k1").unwrap());
        assert!(rendered.contains("redacted"));
        assert!(!rendered.contains("31"));
    }
}
