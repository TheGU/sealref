# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-08-29

First release.

### Added

- Reference format `seal:v1:<kid>:<base64url(nonce || ciphertext || tag)>`, using
  XChaCha20-Poly1305 with a 24-byte random nonce and `sealref:v1:<kid>` as associated data.
- Reference format `seal:vault:<mount>/<path>#<field>`, reading HashiCorp Vault KV v2 through
  `VAULT_ADDR`, `VAULT_NAMESPACE`, and `VAULT_TOKEN` or `VAULT_TOKEN_FILE`.
- Keyring with multiple key ids, loaded from `SEALREF_KEY_FD`, `SEALREF_KEY_FILE`
  (defaulting to `/run/secrets/sealref_key`), or `SEALREF_KEY`, in that order.
- Passphrase keyring entries of the form `<kid> argon2id:<passphrase>`, stretched with Argon2id
  (m=64 MiB, t=3, p=1) for development keyrings that can be committed.
- `sealref keygen`, which prints one keyring line with a fresh random 256-bit key.
- `sealref seal`, which reads plaintext on stdin only, never as an argument.
- `sealref unseal` for local references and `sealref resolve` for every provider.
- `sealref exec`, which resolves the environment, renders templates, and replaces itself with the
  target command through `execvp` on unix. On Windows the command is spawned and its exit code is
  passed through.
- `sealref render`, which replaces `{{seal:...}}` placeholders in a file.
- `sealref check`, which reports where each value comes from without decrypting anything, and
  fails with exit code 2 under `--require-sealed` when a secret-looking name holds plaintext or a
  file holds a raw private key block.
- `sealref rewrap --from <kid> --to <kid>`, which re-encrypts references in place for key
  rotation and leaves every other byte of the file unchanged.
- A `scratch` Docker image holding only the static musl binary, for `COPY --from=` into an
  application image.

[0.1.0]: https://github.com/sealref/sealref/releases/tag/v0.1.0
