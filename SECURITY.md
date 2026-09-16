# Security policy

## Reporting a vulnerability

Report privately through GitHub: open a draft advisory at
<https://github.com/TheGU/sealref/security/advisories/new>. Please do not open a public issue for
a vulnerability.

Include what you have: the version or commit, the configuration, and whatever reproduces the
problem. You will get an acknowledgement within a week. If the report is confirmed, a fix and an
advisory follow, and you are credited unless you prefer otherwise.

## Supported versions

SealRef is pre-1.0. Fixes go to the latest released minor version.

| Version | Supported |
| --- | --- |
| 0.2.x | yes |
| 0.1.x | no |

## What SealRef claims, and what it does not

The claim is narrow and worth stating exactly, because it decides what counts as a vulnerability.

SealRef provides **no plaintext secret at rest**: not in git, not in a `.env` file, not in a
container image, not in a deployment manifest, not in a backup. It does **not** provide "the
plaintext never exists". An application that takes its password in an environment variable has
that password in its environment, and anyone who can read `/proc/<pid>/environ`, attach a debugger
or take a core dump can read it. See
[What this does not protect](README.md#what-this-does-not-protect).

So the following are **in scope**:

- Any path by which a decrypted value, a master key, a Vault or Conjur token, or a CyberArk
  application id reaches stderr, stdout, a log, or an error message.
- The master key reaching the environment of the command `sealref exec` runs.
- A `seal:` reference that resolves to the wrong value, or that resolves at all when it should
  fail closed.
- A credential sent to a host other than the configured provider address.
- Weaknesses in the `seal:v1` construction: XChaCha20-Poly1305, a 32-byte key, a 24-byte random
  nonce per encryption, and `sealref:v1:<kid>` as associated data.
- A keyring, a rendered template, or a rewrapped file created with permissions wider than
  intended.

The following are **out of scope**, because they are the documented boundary rather than defects:

- Reading a resolved secret out of the running application's memory or environment.
- Recovering a key from a keyring that was deliberately delivered through `SEALREF_KEY`, which the
  README describes as the lower-security fallback.
- Guessing the passphrase of an `argon2id:` keyring entry. That form is documented as development
  only; the salt is deterministic by design, so the passphrase is the key.
- Anything that requires write access to the keyring, the binary, or the host.

## Cryptography

`seal:v1` is XChaCha20-Poly1305 from the `chacha20poly1305` crate, with keys from the operating
system CSPRNG. Passphrase entries are stretched with Argon2id at m=64 MiB, t=3, p=1. TLS is rustls
with the ring provider. There is no home-grown cryptography, and `v1` has no negotiable parameters
and no algorithm agility: a different construction would be a different provider name.
