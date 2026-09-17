# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-09-17

### Added

- Reference format `seal:conjur:<variable-id>`, reading CyberArk Conjur through
  `CONJUR_APPLIANCE_URL` and `CONJUR_ACCOUNT`, with either an access token from
  `CONJUR_AUTHN_TOKEN_FILE` or `CONJUR_AUTHN_TOKEN`, or a `CONJUR_AUTHN_LOGIN` and API key
  exchanged once per run.
- Reference format `seal:ccp:<safe>/<object>#<property>`, reading the CyberArk Central Credential
  Provider AIM web service through `SEALREF_CCP_URL` and `SEALREF_CCP_APP_ID`.
- TLS configuration shared by every remote provider: `SEALREF_CA_FILE` replaces the built-in
  Mozilla roots, and `SEALREF_CLIENT_CERT` with `SEALREF_CLIENT_KEY` presents a client certificate
  for mutual TLS, which is how the Central Credential Provider usually identifies a caller.
- `check` reports `conjur` and `ccp` values by locator, still without decrypting or contacting
  anything.

### Changed

- `exec` no longer passes `SEALREF_KEY`, `SEALREF_KEY_FILE` or `SEALREF_KEY_FD` to the command it
  runs. The master key opens every sealed value in the deployment, so it does not belong in the
  environment of an application that asked for one password.
- Every remote provider shares one HTTP client, built on first use, so a run with ten references
  performs one TLS handshake instead of ten and a run with only `seal:v1` references still builds
  no client at all.
- Redirects are no longer followed. Vault's `X-Vault-Token` is not an `Authorization` header, so
  it was not covered by the HTTP client's cross-host header stripping and would have been resent
  to whatever host a redirect named.
- Any status outside 2xx is a failure. A 3xx was previously handed to the provider as an ordinary
  response and its body parsed as a secret.
- SealRef reports on stderr when `VAULT_CACERT`, `VAULT_CAPATH`, `VAULT_SKIP_VERIFY` or
  `CONJUR_CERT_FILE` is set, rather than ignoring a variable meant to narrow trust.
- Argon2, XChaCha20-Poly1305 and SHA-256 move to their new major versions. The sealed format
  and the `argon2id:` derivation are byte for byte what they were, and both are now held to
  frozen test vectors so no later dependency bump can change them without the suite noticing.

### Fixed

- `exec` closes the `SEALREF_KEY_FD` descriptor before handing the process over. Removing the
  variable from the child's environment was not enough on its own: a descriptor survives `execvp`
  unless something closes it, so an application could read the whole keyring from descriptor 3.
- A `.` or `..` segment in a `seal:conjur` or `seal:vault` reference is refused. URL normalisation
  removed it before the request went out, so such a reference addressed a different Conjur account
  or a path outside the Vault KV mount, carrying the run's token with it.
- A transport failure no longer prints the request URL. For the Central Credential Provider that
  URL carries the application id in its query string, so a refused connection wrote it to stderr.
- A rendered template or `--out` file is narrowed to mode 0600 even when the destination already
  exists. The mode passed at open time applies only when a file is created, so writing over a path
  left at the umask by an earlier run produced a world-readable secret.
- `rewrap` refuses to write its temporary file if the path already exists, rather than following
  what is there, and creates it owner-only before widening it to the original's permissions.
- A Conjur variable that reads back empty is an error rather than an empty resolved value.
- `--template a:/run/app.ini` now splits correctly on unix. A single-letter source name was read
  as a Windows drive letter on every platform.
- The HTTP client has a deadline for the whole request, not only per-operation timeouts, so a
  server feeding one byte at a time can no longer hold a container's start-up open indefinitely.

### Security

- rustls moves to 0.23.45, closing RUSTSEC-2026-0285: TLS 1.3 handshake messages were accepted
  across encryption level boundaries. Release binaries are built from the lockfile, so the
  binaries published for 0.1.0 carry the affected version.

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

[0.2.0]: https://github.com/TheGU/sealref/releases/tag/v0.2.0
[0.1.0]: https://github.com/TheGU/sealref/releases/tag/v0.1.0
