//! SealRef resolves `seal:` secret references at process start-up.
//!
//! The library half of the `sealref` binary. Every module here is deliberately small: the whole
//! point of the tool is that a security team can read it end to end.

pub mod ccp;
pub mod check;
pub mod conjur;
pub mod crypto;
pub mod dotenv;
pub mod exec;
pub mod http;
pub mod keyring;
pub mod reference;
pub mod resolve;
pub mod template;
pub mod vault;

use std::time::{SystemTime, UNIX_EPOCH};

use thiserror::Error;

/// The result type used across the crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Every failure SealRef can report.
///
/// No variant ever carries a decrypted secret. Messages name variables, key ids, files and Vault
/// locators only, because they are printed to stderr and to CI logs.
#[derive(Debug, Error)]
pub enum Error {
    #[error("value is not a reference: it does not start with \"seal:\"")]
    NotAReference,

    #[error("unknown reference provider \"{0}\": known providers are v1, vault, conjur and ccp")]
    UnknownProvider(String),

    #[error("malformed {kind} reference: {reason}")]
    Malformed { kind: &'static str, reason: String },

    #[error("invalid key id \"{0}\": expected 1 to 64 characters from [A-Za-z0-9._-]")]
    InvalidKid(String),

    #[error("no key with id \"{0}\" in the keyring")]
    UnknownKid(String),

    #[error("the keyring is empty: it needs at least one key line")]
    EmptyKeyring,

    #[error("keyring line {line}: duplicate key id \"{kid}\"")]
    DuplicateKid { line: usize, kid: String },

    #[error("keyring line {line}: {reason}")]
    KeyringSyntax { line: usize, reason: String },

    #[error(
        "no key source: set SEALREF_KEY_FD, SEALREF_KEY_FILE or SEALREF_KEY \
         (or mount a keyring at /run/secrets/sealref_key)"
    )]
    NoKeySource,

    #[error("key derivation failed for key id \"{kid}\": {reason}")]
    KeyDerivation { kid: String, reason: String },

    #[error("cannot decrypt reference with key id \"{0}\": wrong key or altered ciphertext")]
    DecryptFailed(String),

    #[error("encryption failed")]
    EncryptFailed,

    #[error("the resolved value is not valid UTF-8")]
    NotUtf8,

    #[error("{context}: {source}")]
    Io {
        context: String,
        #[source]
        source: std::io::Error,
    },

    #[error("{path}: line {line}: {reason}")]
    Dotenv {
        path: String,
        line: usize,
        reason: String,
    },

    #[error("vault: {0}")]
    Vault(String),

    #[error("conjur: {0}")]
    Conjur(String),

    #[error("ccp: {0}")]
    Ccp(String),

    #[error("tls: {0}")]
    Tls(String),

    #[error("{name}: {reason}")]
    Resolution { name: String, reason: String },

    #[error("{0}")]
    Msg(String),
}

impl Error {
    /// Attach a filesystem context to an I/O failure.
    pub fn io(context: impl Into<String>, source: std::io::Error) -> Self {
        Error::Io {
            context: context.into(),
            source,
        }
    }

    /// Attach the name of the variable, placeholder or file position being resolved.
    pub fn at(self, name: impl Into<String>) -> Self {
        Error::Resolution {
            name: name.into(),
            reason: self.to_string(),
        }
    }
}

/// Today's UTC date as `YYYYMMDD`.
///
/// Used for the default `keygen` key id. Computing it here keeps a date crate out of the
/// dependency list for what is one format string.
pub fn utc_date_stamp() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let (y, m, d) = civil_from_days(secs.div_euclid(86_400));
    format!("{y:04}{m:02}{d:02}")
}

/// Convert days since the Unix epoch into a proleptic Gregorian calendar date.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::civil_from_days;

    #[test]
    fn civil_from_days_matches_known_dates() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(19_723), (2024, 1, 1));
        assert_eq!(civil_from_days(19_782), (2024, 2, 29));
        assert_eq!(civil_from_days(-1), (1969, 12, 31));
    }
}
