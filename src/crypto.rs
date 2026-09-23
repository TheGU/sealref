//! XChaCha20-Poly1305 sealing and opening.
//!
//! The construction is deliberately fixed: a 32-byte key, a 24-byte random nonce, and the bytes
//! `sealref:v1:<kid>` as associated data so the key id cannot be swapped without failing the tag
//! check. There are no negotiable parameters and no algorithm agility inside `v1`; a new
//! construction would be a new provider name.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

use crate::reference::{self, NONCE_LEN};
use crate::{Error, Result};

/// The associated data bound into every `seal:v1` ciphertext.
pub fn associated_data(kid: &str) -> String {
    format!("sealref:v1:{kid}")
}

/// Encrypt `plaintext` under `key` and return a complete `seal:v1:<kid>:...` reference.
pub fn seal(key: &[u8; 32], kid: &str, plaintext: &[u8]) -> Result<String> {
    if !reference::is_valid_kid(kid) {
        return Err(Error::InvalidKid(kid.to_string()));
    }
    let cipher = XChaCha20Poly1305::new(<&Key>::from(key));
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(Error::rng)?;
    let aad = associated_data(kid);
    let ciphertext = cipher
        .encrypt(
            <&XNonce>::from(&nonce),
            Payload {
                msg: plaintext,
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| Error::EncryptFailed)?;
    let mut blob = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ciphertext);
    Ok(reference::format_v1(kid, &blob))
}

/// Decrypt a `nonce || ciphertext || tag` blob produced by [`seal`].
pub fn open(key: &[u8; 32], kid: &str, blob: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if blob.len() < reference::MIN_BLOB_LEN {
        return Err(Error::Malformed {
            kind: "seal:v1",
            reason: format!(
                "ciphertext is shorter than {} bytes",
                reference::MIN_BLOB_LEN
            ),
        });
    }
    let (nonce, ciphertext) = blob.split_at(NONCE_LEN);
    let nonce: &[u8; NONCE_LEN] = nonce
        .try_into()
        .expect("blob was just checked to be at least NONCE_LEN bytes long");
    let cipher = XChaCha20Poly1305::new(<&Key>::from(key));
    let aad = associated_data(kid);
    let plaintext = cipher
        .decrypt(
            <&XNonce>::from(nonce),
            Payload {
                msg: ciphertext,
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| Error::DecryptFailed(kid.to_string()))?;
    Ok(Zeroizing::new(plaintext))
}

/// Decrypt to a UTF-8 string, which is what an environment variable or a template needs.
pub fn open_string(key: &[u8; 32], kid: &str, blob: &[u8]) -> Result<Zeroizing<String>> {
    let bytes = open(key, kid, blob)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| Error::NotUtf8)?;
    Ok(Zeroizing::new(text.to_string()))
}

/// 32 fresh bytes from the operating system CSPRNG.
pub fn random_key() -> Result<Zeroizing<[u8; 32]>> {
    let mut key = Zeroizing::new([0u8; 32]);
    getrandom::fill(&mut *key).map_err(Error::rng)?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reference::Reference;

    fn key() -> [u8; 32] {
        let mut k = [0u8; 32];
        for (i, b) in k.iter_mut().enumerate() {
            *b = i as u8;
        }
        k
    }

    fn blob_of(text: &str) -> Vec<u8> {
        match Reference::parse(text).unwrap() {
            Reference::V1(r) => r.blob,
            other => panic!("expected a v1 reference, got {other:?}"),
        }
    }

    #[test]
    fn round_trips() {
        let sealed = seal(&key(), "k1", b"hunter2").unwrap();
        assert!(sealed.starts_with("seal:v1:k1:"));
        let opened = open(&key(), "k1", &blob_of(&sealed)).unwrap();
        assert_eq!(&*opened, b"hunter2");
    }

    #[test]
    fn round_trips_an_empty_plaintext() {
        let sealed = seal(&key(), "k1", b"").unwrap();
        let opened = open(&key(), "k1", &blob_of(&sealed)).unwrap();
        assert!(opened.is_empty());
    }

    #[test]
    fn nonce_is_fresh_per_call() {
        let a = seal(&key(), "k1", b"same").unwrap();
        let b = seal(&key(), "k1", b"same").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn a_flipped_byte_fails() {
        let sealed = seal(&key(), "k1", b"hunter2").unwrap();
        let mut blob = blob_of(&sealed);
        let last = blob.len() - 1;
        blob[last] ^= 0x01;
        assert!(matches!(
            open(&key(), "k1", &blob).unwrap_err(),
            Error::DecryptFailed(_)
        ));
    }

    #[test]
    fn a_flipped_nonce_byte_fails() {
        let sealed = seal(&key(), "k1", b"hunter2").unwrap();
        let mut blob = blob_of(&sealed);
        blob[0] ^= 0x80;
        assert!(open(&key(), "k1", &blob).is_err());
    }

    #[test]
    fn a_different_key_id_fails_because_it_is_authenticated() {
        let sealed = seal(&key(), "k1", b"hunter2").unwrap();
        assert!(matches!(
            open(&key(), "k2", &blob_of(&sealed)).unwrap_err(),
            Error::DecryptFailed(_)
        ));
    }

    #[test]
    fn a_different_key_fails() {
        let sealed = seal(&key(), "k1", b"hunter2").unwrap();
        let other = [9u8; 32];
        assert!(open(&other, "k1", &blob_of(&sealed)).is_err());
    }

    #[test]
    fn refuses_an_invalid_key_id() {
        assert!(matches!(
            seal(&key(), "bad kid", b"x").unwrap_err(),
            Error::InvalidKid(_)
        ));
    }

    #[test]
    fn random_keys_differ() {
        assert_ne!(*random_key().unwrap(), *random_key().unwrap());
    }

    /// A reference sealed by an earlier release must still open.
    ///
    /// Every other test here seals and opens in the same process, so they would all still pass if
    /// an upgrade of `chacha20poly1305` quietly changed the construction. The value below was
    /// produced once and is never regenerated: it is the only thing standing between a dependency
    /// bump and every secret already sealed in the field becoming unreadable.
    #[test]
    fn opens_a_reference_sealed_by_an_earlier_release() {
        const FROZEN: &str =
            "seal:v1:k1:RuBKP03xTLp0BKcR2xXMmS1H0-MZkTsnycj0bwXDGrYfOvo64lrDuFnyefLBTm8";
        let opened = open(&key(), "k1", &blob_of(FROZEN)).unwrap();
        assert_eq!(&*opened, b"hunter2");
    }
}
