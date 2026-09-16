//! Dispatch a parsed reference to the provider that can answer it.
//!
//! The keyring and the Vault configuration are both loaded lazily and at most once. That is not an
//! optimisation: it means a deployment that only uses `seal:vault` references never needs a
//! keyring, and one that only uses `seal:v1` references never needs `VAULT_ADDR`.

use zeroize::Zeroizing;

use crate::ccp::CcpConfig;
use crate::conjur::ConjurConfig;
use crate::keyring::{self, Keyring};
use crate::reference::Reference;
use crate::vault::VaultConfig;
use crate::{Error, Result};

/// Resolves references, holding whatever provider state it has needed so far.
#[derive(Default)]
pub struct Resolver {
    keyring: Option<Keyring>,
    vault: Option<VaultConfig>,
    conjur: Option<ConjurConfig>,
    ccp: Option<CcpConfig>,
}

impl Resolver {
    /// A resolver that will load its providers on first use.
    pub fn new() -> Self {
        Self::default()
    }

    /// A resolver with the keyring already supplied, for tests and for `rewrap`.
    pub fn with_keyring(keyring: Keyring) -> Self {
        Resolver {
            keyring: Some(keyring),
            ..Self::default()
        }
    }

    /// The keyring, loading it from the environment on first use.
    pub fn keyring(&mut self) -> Result<&Keyring> {
        if self.keyring.is_none() {
            self.keyring = Some(keyring::load()?);
        }
        Ok(self.keyring.as_ref().expect("keyring was just loaded"))
    }

    fn vault(&mut self) -> Result<&VaultConfig> {
        if self.vault.is_none() {
            self.vault = Some(VaultConfig::from_env()?);
        }
        Ok(self.vault.as_ref().expect("vault config was just loaded"))
    }

    fn conjur(&mut self) -> Result<&ConjurConfig> {
        if self.conjur.is_none() {
            self.conjur = Some(ConjurConfig::from_env()?);
        }
        Ok(self.conjur.as_ref().expect("conjur config was just loaded"))
    }

    fn ccp(&mut self) -> Result<&CcpConfig> {
        if self.ccp.is_none() {
            self.ccp = Some(CcpConfig::from_env()?);
        }
        Ok(self.ccp.as_ref().expect("ccp config was just loaded"))
    }

    /// Resolve a parsed reference through its provider.
    pub fn resolve(&mut self, reference: &Reference) -> Result<Zeroizing<String>> {
        match reference {
            Reference::V1(r) => {
                let key = self.keyring()?.get(&r.kid)?;
                crate::crypto::open_string(key.bytes(), &r.kid, &r.blob)
            }
            Reference::Vault(r) => self.vault()?.read_field(r),
            Reference::Conjur(r) => self.conjur()?.read_variable(r),
            Reference::Ccp(r) => self.ccp()?.read_field(r),
        }
    }

    /// Resolve a `seal:v1` reference only. Used by `unseal`, which is a local-only debugging aid.
    pub fn unseal(&mut self, reference: &Reference) -> Result<Zeroizing<String>> {
        match reference {
            Reference::V1(_) => self.resolve(reference),
            remote => Err(Error::Msg(format!(
                "unseal handles seal:v1 references only: use \"sealref resolve\" for seal:{}",
                remote.provider()
            ))),
        }
    }

    /// Parse and resolve a whole value.
    pub fn resolve_value(&mut self, value: &str) -> Result<Zeroizing<String>> {
        self.resolve(&Reference::parse(value)?)
    }

    /// Parse and unseal a whole value.
    pub fn unseal_value(&mut self, value: &str) -> Result<Zeroizing<String>> {
        self.unseal(&Reference::parse(value)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto;
    use crate::keyring::Keyring;

    const RAW: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";

    fn resolver() -> Resolver {
        Resolver::with_keyring(Keyring::parse(&format!("k1 {RAW}\nk2 argon2id:dev-only")).unwrap())
    }

    fn sealed(kid: &str, plaintext: &str) -> String {
        let ring = Keyring::parse(&format!("k1 {RAW}\nk2 argon2id:dev-only")).unwrap();
        let key = ring.get(kid).unwrap();
        crypto::seal(key.bytes(), kid, plaintext.as_bytes()).unwrap()
    }

    #[test]
    fn resolves_a_v1_reference() {
        let text = sealed("k1", "hunter2");
        assert_eq!(&*resolver().resolve_value(&text).unwrap(), "hunter2");
    }

    #[test]
    fn resolves_a_reference_under_a_passphrase_key() {
        let text = sealed("k2", "from-a-passphrase");
        assert_eq!(
            &*resolver().resolve_value(&text).unwrap(),
            "from-a-passphrase"
        );
    }

    #[test]
    fn fails_on_an_unknown_key_id() {
        let text = sealed("k1", "hunter2").replace("seal:v1:k1:", "seal:v1:k9:");
        assert!(matches!(
            resolver().resolve_value(&text).unwrap_err(),
            Error::UnknownKid(kid) if kid == "k9"
        ));
    }

    #[test]
    fn unseal_refuses_a_vault_reference() {
        let err = resolver()
            .unseal_value("seal:vault:secret/app#password")
            .unwrap_err();
        assert!(err.to_string().contains("seal:v1 references only"));
    }

    #[test]
    fn fails_on_a_non_reference() {
        assert!(matches!(
            resolver().resolve_value("plain").unwrap_err(),
            Error::NotAReference
        ));
    }
}
