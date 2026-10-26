# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- A `VAULT_TOKEN` or `VAULT_NAMESPACE` that cannot be sent as an HTTP header, such as a token
  with a trailing newline from a mounted Kubernetes secret, no longer has its value printed in the
  error. The previous HTTP client validated the header as the whole line `X-Vault-Token: <token>`
  and quoted that line when it refused it, so the token reached stderr and from there a CI log. The
  run still fails, and the value is not trimmed: a token that is not valid as given is better
  reported than silently altered.

### Fixed

- A response with neither a `Content-Length` nor chunked framing is refused. Such a body ends only
  when the connection closes, so a value cut short in transit is indistinguishable from a whole
  one, and `ureq` 3 also accepts a reset, or a TLS close without `close_notify`, as that end. A
  Conjur variable arriving that way could have resolved to a truncated password.
- A Conjur value that is not valid UTF-8 now fails instead of resolving to a copy with the
  offending bytes replaced, which was a different password with no sign that it was.
- A `..` account name or login in a Conjur URL is escaped like a `..` path segment. The previous
  HTTP client collapsed `..` itself before sending, so `CONJUR_ACCOUNT=..` addressed a different
  path than the one written. Nothing between SealRef and the server collapses it now, but a server
  or proxy might, hence the escape.

### Changed

- `ureq` moves to 3.5 and `base64` to 0.23, which `ureq` no longer holds back. The `ureq` 3 line
  keeps the behaviour that matters here by setting it explicitly: redirects are still refused,
  proxy variables (`HTTPS_PROXY`, `HTTP_PROXY`, `ALL_PROXY`) are still never read, a 4xx or 5xx
  still reports the vendor error code but not the body, and the timeouts are unchanged. `ureq`
  3 would otherwise read the proxy variables, which would send an `http://` Vault token through
  whatever proxy the image names. `webpki-roots` is no longer a direct dependency, because the
  Mozilla bundle now comes through `ureq`. The dependency tree loses `url`, `idna`, `idna_adapter`,
  the `icu_*` crates and their helpers (`yoke`, `zerovec`, `zerofrom`, `tinystr`, `litemap`,
  `writeable`, `smallvec`, `displaydoc`, `form_urlencoded`, `utf8_iter`, `potential_utf`,
  `stable_deref_trait`, `zerotrie`), the second `webpki-roots` and `synstructure`; it gains
  `http`, `httparse`, `bytes`, `ureq-proto` and `utf8-zero`. The release binary is 2,216,864
  bytes, down from 2,253,680.
- The `User-Agent` is now `ureq/3.x` rather than `ureq/2.x`.
- A hostname written with non-ASCII characters in `VAULT_ADDR`, `CONJUR_APPLIANCE_URL` or
  `SEALREF_CCP_URL` is now rejected rather than converted to its ASCII form. Write the punycode
  name instead.
- Error text for a transport failure is chosen from a fixed list of what is safe to print, so a
  future `ureq` release cannot add a message that quotes a URL.

## [0.2.4] - 2026-09-24

### Added

- `sealref protect <file>...` seals every plaintext secret in a dotenv file in place: the values
  `check --require-sealed` would fail, or every non-empty plaintext value with `--all`. Quotes,
  comments, `export` prefixes and line endings are kept, the keyring is only loaded when something
  needs sealing, and no file is written unless every file transforms. Files that hold
  `{{seal:...}}` placeholders are refused.
- `sealref info` shows the effective keyring: the source in use, the sources it outranks, and each
  key by id, form (`random` or `argon2id`) and fingerprint, without printing any key material. It
  exits 2 when a keyring source is set but cannot be loaded.

### Changed

- Random bytes for nonces and `keygen` come straight from `getrandom`, which the cipher and the
  password hash already pull in, rather than through `rand`. `rand` 0.10 renamed the operating
  system generator and the trait behind it, and nothing here needed more than one call to fill a
  buffer. The dependency tree loses `rand`, `rand_chacha`, `rand_core` 0.6, `ppv-lite86`,
  `zerocopy` and one `syn`.
- `webpki-roots` moves to 1.x. 0.26.11, the version already locked, is a shim over 1.x, so the
  Mozilla bundle was already the 1.x one and is still compiled in once.
- A failure of the operating system random number generator is reported as such rather than
  aborting the process.
- The minimum supported Rust version is now 1.98, up from 1.88. It follows the current stable
  release rather than trailing it, so a build from source carries current compiler and standard
  library security fixes.

### Fixed

- A keyring line with an invalid key id no longer echoes that text in the error. On a line written
  the wrong way round, such as `argon2id:<passphrase> dev`, the text was the passphrase.

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

[0.2.4]: https://github.com/TheGU/sealref/releases/tag/v0.2.4
[0.2.0]: https://github.com/TheGU/sealref/releases/tag/v0.2.0
[0.1.0]: https://github.com/TheGU/sealref/releases/tag/v0.1.0
