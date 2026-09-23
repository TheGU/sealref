//! `sealref info`: explain the effective keyring without revealing anything in it.
//!
//! The question this answers is "which key is sealref actually using, and why not mine". So the
//! report names the source that wins, every source it outranks, and each key by id, form and
//! fingerprint. It is built from plain data rather than from the process environment, so the tests
//! can feed it any environment and any keyring, and it never holds keyring text or key bytes: only
//! what it is going to print.
//!
//! Providers and TLS settings are deliberately not reported yet.

use std::fmt;

use crate::keyring::{KeyForm, KeySource, Keyring};
use crate::{Error, Result};

/// What `info` prints about one key.
struct KeyLine {
    kid: String,
    form: KeyForm,
    fingerprint: String,
}

/// What `info` knows about the keyring.
enum Keys {
    /// No source is present. Not an error: a deployment that only uses remote references has no
    /// keyring at all.
    NoSource,
    /// A source is present but could not be read or parsed. Holds the rendered error, which names
    /// paths, lines and key ids only.
    Failed(String),
    /// The keys, in keyring order.
    Loaded(Vec<KeyLine>),
}

/// The `info` report.
pub struct Info {
    version: String,
    source: Option<KeySource>,
    ignored: Vec<&'static str>,
    keys: Keys,
}

impl Info {
    /// Build the report. `keyring` is the result of loading `source`, or `None` when there is no
    /// source. The keyring is reduced to ids, forms and fingerprints here and not kept.
    pub fn new(
        version: &str,
        source: Option<KeySource>,
        ignored: Vec<&'static str>,
        keyring: Option<Result<Keyring>>,
    ) -> Self {
        let keys = match keyring {
            None => Keys::NoSource,
            Some(Err(error)) => Keys::Failed(error.to_string()),
            Some(Ok(keyring)) => Keys::Loaded(
                keyring
                    .keys()
                    .map(|key| KeyLine {
                        kid: key.kid().to_string(),
                        form: key.form(),
                        fingerprint: key.fingerprint(),
                    })
                    .collect(),
            ),
        };
        Info {
            version: version.to_string(),
            source,
            ignored,
            keys,
        }
    }

    /// The process exit code: 2 when a keyring source is present but failed to load, else 0.
    pub fn exit_code(&self) -> i32 {
        match self.keys {
            Keys::Failed(_) => 2,
            Keys::NoSource | Keys::Loaded(_) => 0,
        }
    }
}

impl fmt::Display for Info {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "sealref {}", self.version)?;
        let source = match &self.source {
            Some(source) => source,
            None => return writeln!(f, "keyring: none ({})", Error::NoKeySource),
        };
        match &self.keys {
            Keys::Failed(error) => writeln!(f, "keyring: {source}: {error}")?,
            _ => writeln!(f, "keyring: {source}")?,
        }
        if !self.ignored.is_empty() {
            writeln!(
                f,
                "  ignored: {} (a higher-precedence source is set)",
                self.ignored.join(", ")
            )?;
        }
        if let Keys::Loaded(keys) = &self.keys {
            let width = keys.iter().map(|k| k.kid.len()).max().unwrap_or(0);
            for (index, key) in keys.iter().enumerate() {
                // `argon2id` is the longer form name, so the fingerprints line up.
                let form = key.form.to_string();
                write!(
                    f,
                    "  {:<width$}  {form:<8}  fingerprint {}",
                    key.kid, key.fingerprint
                )?;
                if index == 0 {
                    write!(f, "  default for seal")?;
                }
                writeln!(f)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    const RAW: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
    const PASSPHRASE: &str = "correct horse battery staple";

    fn ring() -> Keyring {
        Keyring::parse(&format!("k20260829 {RAW}\ndev argon2id:{PASSPHRASE}\n")).unwrap()
    }

    fn fingerprint_of(kid: &str) -> String {
        ring().get(kid).unwrap().fingerprint()
    }

    #[test]
    fn lists_every_key_by_id_form_and_fingerprint() {
        let info = Info::new(
            "0.2.0",
            Some(KeySource::File(PathBuf::from("/home/app/dev.key"))),
            vec![],
            Some(Ok(ring())),
        );
        assert_eq!(
            info.to_string(),
            format!(
                "sealref 0.2.0\n\
                 keyring: SEALREF_KEY_FILE /home/app/dev.key\n  \
                 k20260829  random    fingerprint {}  default for seal\n  \
                 dev        argon2id  fingerprint {}\n",
                fingerprint_of("k20260829"),
                fingerprint_of("dev"),
            )
        );
        assert_eq!(info.exit_code(), 0);
    }

    #[test]
    fn names_each_source_shape() {
        for (source, line) in [
            (
                KeySource::Fd("3".to_string()),
                "keyring: SEALREF_KEY_FD 3\n",
            ),
            (
                KeySource::File(PathBuf::from("/k")),
                "keyring: SEALREF_KEY_FILE /k\n",
            ),
            (
                KeySource::DefaultFile,
                "keyring: /run/secrets/sealref_key (default path)\n",
            ),
            (
                KeySource::Inline,
                "keyring: SEALREF_KEY (environment variable)\n",
            ),
        ] {
            let rendered = Info::new("0.2.0", Some(source), vec![], Some(Ok(ring()))).to_string();
            assert!(rendered.contains(line), "{rendered}");
        }
    }

    #[test]
    fn lists_the_ignored_sources_on_one_line() {
        let rendered = Info::new(
            "0.2.0",
            Some(KeySource::Fd("3".to_string())),
            vec!["SEALREF_KEY_FILE", "SEALREF_KEY"],
            Some(Ok(ring())),
        )
        .to_string();
        assert!(
            rendered.contains(
                "\n  ignored: SEALREF_KEY_FILE, SEALREF_KEY (a higher-precedence source is set)\n"
            ),
            "{rendered}"
        );
    }

    #[test]
    fn no_keyring_is_not_an_error() {
        let info = Info::new("0.2.0", None, vec![], None);
        assert_eq!(
            info.to_string(),
            format!("sealref 0.2.0\nkeyring: none ({})\n", Error::NoKeySource)
        );
        assert_eq!(info.exit_code(), 0);
    }

    #[test]
    fn a_load_error_is_reported_with_its_source_and_exits_two() {
        let info = Info::new(
            "0.2.0",
            Some(KeySource::Inline),
            vec![],
            Some(Keyring::parse("k1 AAEC")),
        );
        assert_eq!(
            info.to_string(),
            "sealref 0.2.0\nkeyring: SEALREF_KEY (environment variable): keyring line 1: key is 3 bytes, expected 32\n"
        );
        assert_eq!(info.exit_code(), 2);
    }

    #[test]
    fn never_prints_key_material() {
        let rendered =
            Info::new("0.2.0", Some(KeySource::Inline), vec![], Some(Ok(ring()))).to_string();
        assert!(!rendered.contains(RAW));
        assert!(!rendered.contains(PASSPHRASE));
        assert!(!rendered.contains("correct"));
        let key_hex: String = ring()
            .get("k20260829")
            .unwrap()
            .bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert!(!rendered.contains(&key_hex));
    }

    #[test]
    fn a_swapped_passphrase_line_is_not_echoed() {
        let rendered = Info::new(
            "0.2.0",
            Some(KeySource::Inline),
            vec![],
            Some(Keyring::parse("argon2id:mypass dev\n")),
        )
        .to_string();
        assert!(rendered.contains("invalid key id"), "{rendered}");
        assert!(!rendered.contains("mypass"), "{rendered}");
    }
}
