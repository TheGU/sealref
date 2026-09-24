# SealRef

[![CI](https://github.com/TheGU/sealref/actions/workflows/ci.yml/badge.svg)](https://github.com/TheGU/sealref/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A tiny runtime secret-reference resolver for software that cannot natively use a secret manager.
Configuration files and environment variables hold a reference such as
`seal:v1:k20260101:qIb7Q9...` or `seal:vault:secret/myapp/prod/database#password` instead of a
password. At start-up `sealref` resolves those references, puts the plaintext in the environment
of the process it is about to run, or in a rendered configuration file, and hands over. The
application is unchanged and has no idea whether its password came from a locally encrypted `.env`
file, from HashiCorp Vault, or from CyberArk. SealRef is not a replacement for Vault, SOPS, or
External Secrets; it is the compatibility shim that lets a third-party container image you cannot
modify take part in the secret management you already have.

- One portable reference syntax across a local key, HashiCorp Vault, CyberArk Conjur and the
  CyberArk Central Credential Provider.
- Fails closed. An unresolvable reference stops the process before the application starts.
- No plaintext secret in git, in a `.env` file, in an image, in a compose file, or in a backup.
- One small static binary with no shell and no package manager around it.

## Contents

- [Install](#install)
- [Quick start](#quick-start)
- [Reference formats](#reference-formats)
- [Keys and the keyring](#keys-and-the-keyring)
- [Commands](#commands)
- [Docker](#docker)
- [Key rotation](#key-rotation)
- [Vault](#vault)
- [CyberArk Conjur](#cyberark-conjur)
- [CyberArk Central Credential Provider](#cyberark-central-credential-provider)
- [TLS](#tls)
- [What this does not protect](#what-this-does-not-protect)
- [What SealRef deliberately does not do](#what-sealref-deliberately-does-not-do)
- [Development](#development)
- [Contributing](#contributing)
- [License](#license)

## Install

From source, with Rust 1.98 or newer:

```bash
cargo build --release
# target/release/sealref (target\release\sealref.exe on Windows)
```

From a release, which carries a prebuilt binary for Linux, Windows and macOS with a `.sha256`
beside each archive:

```bash
curl -fsSLO https://github.com/TheGU/sealref/releases/download/v0.2.0/sealref-v0.2.0-x86_64-unknown-linux-musl.tar.gz
curl -fsSL  https://github.com/TheGU/sealref/releases/download/v0.2.0/sealref-v0.2.0-x86_64-unknown-linux-musl.tar.gz.sha256   | tr -d '
' | sed 's/$/  sealref-v0.2.0-x86_64-unknown-linux-musl.tar.gz/' | sha256sum -c -
tar -xzf sealref-v0.2.0-x86_64-unknown-linux-musl.tar.gz
```

As a container image, which builds a static `x86_64-unknown-linux-musl` binary and ships it in a
`scratch` image that contains nothing else. Every release publishes one to GHCR, and that is what
another Dockerfile's `COPY --from` needs:

```bash
docker run --rm ghcr.io/thegu/sealref:0.2.0 --version
```

To build the same image yourself:

```bash
docker build -t sealref:0.2.0 .
docker run --rm sealref:0.2.0 --version
```

You can use the image without installing anything, for example to check an env file in CI:

```bash
docker run --rm -v "$PWD":/w sealref:0.2.0 check /w/x.env
```

## Quick start

```bash
# 1. Create a key and keep it somewhere the repository cannot reach.
sealref keygen > ~/.config/sealref/dev.key
export SEALREF_KEY_FILE=~/.config/sealref/dev.key

# 2. Write the env file as usual, plaintext included.
cat .env
DB_HOST=localhost
DB_PASSWORD=my-password

# 3. Seal every secret-looking value in place, then commit the file.
sealref protect .env
OK DB_HOST plaintext
SEALED DB_PASSWORD kid=k20260829
.env 1
cat .env
DB_HOST=localhost
DB_PASSWORD=seal:v1:k20260829:qIb7Q9...

# 4. Run the application with the reference resolved.
sealref exec --env-file .env -- ./myapp
```

To seal one value on its own, pipe it to `sealref seal`. The plaintext arrives on stdin, never as
an argument:

```bash
printf '%s' 'my-password' | sealref seal
seal:v1:k20260829:qIb7Q9...
```

Run `sealref check --require-sealed .env` before every commit, ideally as a pre-commit hook, so a
plaintext secret never reaches the repository in the first place. `protect` only rewrites the file
as it is now: it does not remove plaintext that is already in git history, in editor backups or
in old disk blocks. A secret that was ever committed in plaintext must be rotated.

In production the same `.env` line can point at Vault instead, and step 4 does not change:

```dotenv
DB_PASSWORD=seal:vault:secret/myapp/prod/database#password
```

## Reference formats

Any value that starts with `seal:` is a reference. Anything else is passed through untouched.
A `seal:` value that SealRef does not understand is an error, never a warning.

### Locally encrypted secret

```text
seal:v1:<kid>:<base64url-no-pad(nonce || ciphertext || tag)>
```

- Cipher: XChaCha20-Poly1305.
- Key: 32 bytes.
- Nonce: 24 random bytes, fresh for every `seal`.
- Associated data: the bytes `sealref:v1:<kid>`, so the key id is authenticated and cannot be
  swapped without failing the tag check.
- `<kid>` is `[A-Za-z0-9._-]{1,64}` and names a line in the keyring. It exists so keys can be
  rotated: SealRef can hold the old and the new key at the same time.

### Remote secret

| Provider | Reference | Reads |
| --- | --- | --- |
| HashiCorp Vault KV v2 | `seal:vault:<mount>/<path>#<field>` | `GET $VAULT_ADDR/v1/<mount>/data/<path>`, field `data.data.<field>` |
| CyberArk Conjur | `seal:conjur:<variable-id>` | `GET $CONJUR_APPLIANCE_URL/secrets/<account>/variable/<variable-id>` |
| CyberArk Central Credential Provider | `seal:ccp:<safe>/<object>#<property>` | `GET $SEALREF_CCP_URL/AIMWebService/api/Accounts`, the named property |

```dotenv
DB_PASSWORD=seal:vault:secret/myapp/prod/database#password
API_TOKEN=seal:conjur:prod/myapp/api-token
SMTP_PASSWORD=seal:ccp:Prod Databases/smtp-relay#Content
```

A Conjur variable holds one opaque value, so its reference takes no `#field`. A Vault secret and a
CyberArk account both hold several, so theirs names the one to read. For CyberArk the password is
the property called `Content`; `UserName`, `Address` and the rest of the account are reachable the
same way.

No server address is part of any reference. That is what lets the identical config line work in
staging and in production, with only the environment differing between them.

A `.` or `..` path segment is refused. URL normalisation would remove it before the request went
out, so `seal:conjur:../../other/variable/x` would read a different Conjur account and
`seal:vault:secret/../../sys/seal-status#x` would leave the KV mount, in both cases carrying the
run's token. A reference is the artefact you commit and review in a diff, so it has to mean what
it reads as.

## Keys and the keyring

The keyring is text. One key per line, blank lines and `#` comments ignored:

```text
# The first key line is the default key used by "sealref seal".
k20260829 8Zt7Q0nGm6d4xkYm4t2VzZq1nJ0lQ7oX9rPzS3tWbVc
k20260101 QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWY
dev       argon2id:local-development-only
```

Each line is `<kid> <base64url-no-pad of 32 bytes>` or `<kid> argon2id:<passphrase>`. A duplicate
key id is an error.

### Where the keyring comes from

The first source that is present wins:

1. `SEALREF_KEY_FD=<n>` reads the keyring from an already-open file descriptor. Unix only; on
   Windows this is an error. This is the best option when a supervisor can pass a descriptor,
   because the key never becomes a path or an environment variable.
2. `SEALREF_KEY_FILE=<path>` reads the keyring from a file. When the variable is unset and
   `/run/secrets/sealref_key` exists, that path is used, which is where a Docker secret lands.
3. `SEALREF_KEY=<keyring text>` reads the keyring from the environment, with lines separated by
   newlines or by semicolons.

`SEALREF_KEY` is the lower-security fallback. An environment variable is visible in
`/proc/<pid>/environ`, in `docker inspect`, and in an orchestrator's API, so a key delivered that
way is only as protected as the deployment manifest that carries it. Prefer a mounted file or a
file descriptor, and remember the point of the whole exercise: the encrypted values and the master
key must not travel together. Sealing `DB_PASSWORD` and then storing `SEALREF_KEY` in the same
compose file solves nothing.

### The argon2id development form

`<kid> argon2id:<passphrase>` stretches the passphrase with Argon2id (m=64 MiB, t=3, p=1, 32-byte
output). The salt is `SHA-256("sealref:argon2id:<kid>")`, which is deterministic on purpose: the
same keyring line must produce the same key on every developer machine and in CI, or a shared
development keyring would be useless.

This form exists so a development keyring can be committed to the repository without holding
anything that looks like a secret to a scanner. It is not a substitute for a real key: the
passphrase is the key, and a deterministic salt means an attacker who guesses the passphrase
guesses the key. Production keyrings must hold random keys from `sealref keygen`.

## Commands

Global flags: `--version`, and `-q` / `--quiet` to suppress informational output on stdout.
Errors go to stderr with exit code 1. `check` uses exit code 2 for a policy failure, and `info`
uses exit code 2 when a keyring source is set but cannot be loaded. No command ever prints a
plaintext secret in a log or an error message.

### `sealref keygen [--kid <kid>]`

Prints one keyring line with 32 fresh bytes from the operating system CSPRNG, and nothing else, so
the output can be redirected straight into a file. The key id defaults to `k` plus today's UTC
date.

```bash
sealref keygen --kid prod-a > /run/secrets/sealref_key
```

### `sealref seal [--kid <kid>] [--trim]`

Reads the plaintext from stdin and prints a `seal:v1` reference. The whole of stdin is the secret,
including any trailing newline; pass `--trim` to strip trailing whitespace. Without `--kid` the
first key in the keyring is used.

```bash
printf '%s' 'my-password' | sealref seal --kid prod-a
```

A plaintext argument is refused. It would be recorded in the shell history and visible in the
process list of every other user on the machine.

### `sealref unseal [--ref <value>] [--newline]`

Decrypts a `seal:v1` reference, read from `--ref` or from stdin, and prints the plaintext with no
trailing newline unless `--newline` is given. Local references only; this is the debugging and
admin path.

```bash
sealref unseal --ref 'seal:v1:prod-a:qIb7Q9...'
```

### `sealref resolve [--ref <value>] [--newline]`

The same, but dispatches to whichever provider owns the reference, Vault included.

```bash
sealref resolve --ref 'seal:vault:secret/myapp/prod/database#password'
```

### `sealref exec [--env-file <path>]... [--template <src>:<dst>]... -- <cmd> [args...]`

The production command. It builds the environment from the inherited process environment, layers
each `--env-file` over it in order, resolves every value that starts with `seal:`, renders each
template to its destination with mode 0600, and then runs the command. On unix the command
replaces the SealRef process through `execvp`, so the PID does not change and the container gets
normal SIGTERM behaviour with no supervisor in the way. On Windows the command is spawned and its
exit code is passed through.

```bash
sealref exec -- /opt/keycloak/bin/kc.sh start

sealref exec --env-file /config/app.env -- ./myapp

sealref exec \
    --template config.ini.template:/run/sealref/config.ini \
    -- myprogram --config /run/sealref/config.ini
```

Every reference is resolved and every template is rendered in memory before anything starts. A
failure prints the variable name and the reason, never the value, and exits 1 without running the
command. The keyring variables are removed from the environment the command receives; see
[what the command SealRef runs can see](#what-the-command-sealref-runs-can-see).

Point `--template` at a `tmpfs` so the rendered plaintext never reaches a disk. In compose:

```yaml
tmpfs:
  - /run/sealref
```

### `sealref render <src> [--out <dst>]`

Replaces every `{{seal:...}}` occurrence in a file with its resolved value, for software that
takes a configuration file rather than environment variables. Writes to stdout, or to `--out` with
mode 0600, which is applied even when the destination already exists. Braces that do not contain a `seal:` reference are left alone. An unresolved reference
is an error and no file is written.

```ini
# config.ini.template
username = foo
password = {{seal:vault:secret/foo#password}}
api_key  = {{seal:conjur:prod/myapp/api-token}}
bind_pw  = {{seal:ccp:Prod Databases/ldap-bind#Content}}
legacy   = {{seal:v1:prod-a:qIb7Q9...}}
```

```bash
sealref render config.ini.template --out /run/sealref/config.ini
```

### `sealref check [--env-file <path>]... [<file>...] [--require-sealed] [--pattern <regex>]...`

Reports where each value comes from, and never prints a value. A `seal:` value must parse, but it
is not decrypted, so `check` runs on a build agent that holds no keyring and cannot reach Vault.

```bash
sealref check --env-file production.env
OK DB_PASSWORD sealed kid=prod-a
OK SMTP_PASSWORD vault secret/myapp/smtp#password
OK API_TOKEN conjur prod/myapp/api-token
OK LDAP_PASSWORD ccp Prod Databases/ldap-bind#Content
OK LOG_LEVEL plaintext
```

A positional file that contains `{{seal:...}}` placeholders is treated as a template and reported
by file and line; any other positional file is parsed as dotenv. Files given with `--env-file` are
always parsed as dotenv.

`--require-sealed` turns it into a policy gate that exits 2 when it finds a problem:

- a non-empty plaintext value whose variable name matches `PASS`, `PASSWORD`, `PASSWD`, `SECRET`,
  `TOKEN`, `API_KEY`, `APIKEY`, `PRIVATE_KEY`, `PRIVATE`, `CREDENTIAL`, or any extra `--pattern`.
  All patterns are matched case-insensitively anywhere in the name.
- a raw `-----BEGIN ... PRIVATE KEY-----` block in a positional file.

A malformed `seal:` reference fails the check whether or not `--require-sealed` is given.

```bash
sealref check --require-sealed --pattern '^LICENSE_' production.env
FAIL DB_PASSWORD plaintext
```

### `sealref protect [--kid <kid>] [--all] [--pattern <regex>]... <file>...`

Seals every plaintext secret in each dotenv file, in place, so an admin can write the password
into `.env`, run one command, and commit. A value is sealed when `check --require-sealed` would
fail it as plaintext: a non-empty plaintext under a secret-looking name, with the same default
patterns and the same `--pattern` extras. `--all` seals every non-empty plaintext value instead.
That makes `check --require-sealed` the dry run for `protect`. Without `--kid` the first key in
the keyring is used, and the keyring is only loaded when something actually needs sealing, so
running it over a file that is already protected needs no key and changes nothing.

```bash
sealref protect production.env
OK DB_HOST plaintext
SEALED DB_PASSWORD kid=prod-a
OK SMTP_PASSWORD vault secret/myapp/smtp#password
SEALED API_TOKEN kid=prod-a
production.env 2
```

What is sealed is the value `exec` would hand to the application: quotes removed and escapes
applied. A quoted value keeps its quotes around the new reference, and every other byte of the
file, comments, `export` prefixes, spacing and line endings included, is unchanged. Note that
`KEY= # note` is not an empty value followed by a comment: the value is the text `# note`, so that
is what gets sealed. Every file is processed in memory first and nothing is written unless all of
them transform, so a malformed `seal:` reference in any one of them leaves all of them untouched.
An I/O failure while the results are being written can still leave the files before it already
protected; that state is a valid one, and running the command again is safe.

It will not touch a file that holds `{{seal:...}}` placeholders: it handles dotenv files only,
and a bare reference written into an INI or YAML file is one nothing would resolve. Like `rewrap`,
it writes through a temporary file and a rename, so a symlinked `.env` is replaced by a regular
file. And it only changes the file as it is now; see the note under
[Quick start](#quick-start) about plaintext that was already committed.

### `sealref rewrap --from <kid> --to <kid> <file>...`

Re-encrypts every `seal:v1:<from>:...` reference in each file under `<to>`, in place, and prints
the count per file. It edits the raw text, so every other byte of the file, comments and quoting
and line endings included, is unchanged. The write goes through a temporary file in the same
directory and a rename, and the original permissions are carried over.

```bash
sealref rewrap --from k20260101 --to k20260829 production.env config.ini.template
production.env 3
config.ini.template 1
```

### `sealref info`

Shows the effective keyring: which source it comes from, which other sources are set but
outranked, and every key by id, form and fingerprint. It answers "why is my key not the one being
used" without revealing anything: no key, no passphrase and no keyring text is ever printed.

```bash
sealref info
sealref 0.2.0
keyring: SEALREF_KEY_FILE /home/app/dev.key
  ignored: SEALREF_KEY (a higher-precedence source is set)
  k20260829  random    fingerprint 8f3c2a1e9b0d4c77  default for seal
  dev        argon2id  fingerprint 1a2b3c4d5e6f7081
```

The form is `random` for a base64 key line and `argon2id` for a passphrase line. The fingerprint
is the first 8 bytes of `SHA-256("sealref:fingerprint:" || key)` in hex, so two hosts can confirm
they hold the same key by comparing it. No keyring at all is not an error, since a deployment that
only uses remote references has none; a source that is set but cannot be read or parsed is
reported with its error and exits 2. `--quiet` does not apply, because this output is the result.
It does not report providers or TLS settings.

## Docker

### Adding SealRef to an image you did not build

```dockerfile
FROM quay.io/keycloak/keycloak:latest

COPY --from=ghcr.io/thegu/sealref:0.2.0 /sealref /usr/local/bin/sealref

ENTRYPOINT ["sealref", "exec", "--"]
CMD ["/opt/keycloak/bin/kc.sh", "start"]
```

The original `ENTRYPOINT` becomes the `CMD`, and nothing else about the image changes.

### Delivering the keyring as a Docker secret

```yaml
services:
  keycloak:
    image: my-keycloak
    env_file:
      - production.env
    secrets:
      - sealref_key
    tmpfs:
      - /run/sealref

secrets:
  sealref_key:
    file: ./sealref.key
```

The secret lands at `/run/secrets/sealref_key`, which is the path SealRef reads when
`SEALREF_KEY_FILE` is unset. `production.env` holds references only, so Docker never sees a
password:

```dotenv
KC_DB=postgres
KC_DB_URL=jdbc:postgresql://postgres/keycloak
KC_DB_USERNAME=keycloak
KC_DB_PASSWORD=seal:vault:secret/keycloak/prod/database#password
```

### Checking a file without installing anything

```bash
docker run --rm -v "$PWD":/w sealref:0.2.0 check /w/x.env
docker run --rm -v "$PWD":/w sealref:0.2.0 check --require-sealed /w/x.env
```

### A round trip through the image

```bash
KEY=$(docker run --rm sealref:0.2.0 keygen --kid demo)
REF=$(printf '%s' 'hunter2' | docker run --rm -i -e SEALREF_KEY="$KEY" sealref:0.2.0 seal)
docker run --rm -e SEALREF_KEY="$KEY" sealref:0.2.0 unseal --ref "$REF" --newline
hunter2
```

## Key rotation

Key ids exist so this is a routine operation rather than a migration.

1. Create the new key and append it to the keyring. Keep the old line: SealRef can open references
   under either key while the rotation is in flight.

   ```bash
   sealref keygen --kid k20260829 >> sealref.key
   ```

2. Re-encrypt every reference that uses the old key. This touches nothing else in the files.

   ```bash
   sealref rewrap --from k20260101 --to k20260829 production.env config.ini.template
   ```

3. Confirm that nothing still names the old key.

   ```bash
   grep -c 'seal:v1:k20260101:' production.env
   ```

4. Remove the old line from the keyring and redeploy the keyring.

Making the new key the first line of the keyring also makes it the default for `sealref seal`.

## Vault

SealRef speaks the smallest possible amount of Vault: one KV v2 read, with a token that something
else obtained.

| Variable | Meaning |
| --- | --- |
| `VAULT_ADDR` | Required. Base address, for example `https://vault.example`. |
| `VAULT_NAMESPACE` | Optional. Sent as the `X-Vault-Namespace` header. |
| `VAULT_TOKEN` | The token, sent as the `X-Vault-Token` header. |
| `VAULT_TOKEN_FILE` | A file holding the token. Contents are trimmed. Used when `VAULT_TOKEN` is unset. |

One of `VAULT_TOKEN` and `VAULT_TOKEN_FILE` is required. `VAULT_TOKEN_FILE` is the better one:
it lets Vault Agent, the Kubernetes integration, or the platform own authentication and renewal,
which is exactly the split that keeps this tool small. AppRole, Kubernetes auth, LDAP, OIDC, AWS
auth and the rest are out of scope, permanently.

The read is `GET $VAULT_ADDR/v1/<mount>/data/<path>` and the value is `data.data.<field>`. A
missing path, a missing field, a non-string field, an unreachable server, or any status outside
2xx is a failure that stops the process.

## CyberArk Conjur

One variable read, and either a token that something else obtained or one API key exchange.

| Variable | Meaning |
| --- | --- |
| `CONJUR_APPLIANCE_URL` | Required. Base address, for example `https://conjur.example`. Conjur Cloud URLs end in `/api`. |
| `CONJUR_ACCOUNT` | Required. The Conjur account, for example `myorg`. |
| `CONJUR_AUTHN_TOKEN_FILE` | A file holding an access token. This is what the Conjur Kubernetes authenticator sidecar writes to `/run/conjur/access-token`. |
| `CONJUR_AUTHN_TOKEN` | The same, inline. |
| `CONJUR_AUTHN_LOGIN` | A workload identity, for example `host/myapp`. Used when no token is given. |
| `CONJUR_AUTHN_API_KEY_FILE` | A file holding the API key for that identity. |
| `CONJUR_AUTHN_API_KEY` | The same, inline. |

The first source that is present wins, in that order. An access token is accepted either as the
raw JSON that Conjur issues or as single-line standard base64 of it, and nothing else: the value
goes into an `Authorization` header, so a line-wrapped `base64` output or an API key pasted into
the wrong variable is refused rather than transmitted.

With a login and an API key, SealRef posts once to
`$CONJUR_APPLIANCE_URL/authn/<account>/<login>/authenticate` and reuses the resulting token for
every reference in the run. That branch is Conjur OSS and Conjur Enterprise; a workload created
natively in Conjur Cloud authenticates with JWT or OIDC and should hand SealRef a token file
instead. `authn-jwt`, `authn-oidc`, `authn-iam` and `authn-k8s` are out of scope for the same
reason the Vault provider speaks only one auth method.

The read is `GET $CONJUR_APPLIANCE_URL/secrets/<account>/variable/<variable-id>`. Conjur answers
404 both for a variable that does not exist and for one the identity may not read, deliberately,
so SealRef reports the status rather than guessing which it was. A Conjur access token is valid
for about eight minutes; SealRef is a start-up process and does not renew one, so a cold start
before the authenticator sidecar is ready fails closed rather than waiting.

## CyberArk Central Credential Provider

One account read from the AIM web service, for the deployments where "CyberArk" means the Central
Credential Provider rather than Conjur.

| Variable | Meaning |
| --- | --- |
| `SEALREF_CCP_URL` | Required. Base address of the web service, for example `https://ccp.example`. |
| `SEALREF_CCP_APP_ID` | Required. The application id registered in CyberArk. |

These two are named by SealRef rather than by the vendor, because CyberArk defines no environment
variables for the Central Credential Provider.

The read is
`GET $SEALREF_CCP_URL/AIMWebService/api/Accounts?AppID=<app-id>&Safe=<safe>&Object=<object>`, and
the reference names the property to take from the JSON account. Safe and object names are
percent-encoded, so a safe called `Prod Databases` works; `+`, `&` and `%` are rejected at parse
time because CyberArk cannot carry them in a URL value.

The application id is not a credential. The Central Credential Provider identifies the calling
application by client certificate, allowed machine, path or OS user, and from a container the
client certificate is the one that travels. Set `SEALREF_CLIENT_CERT` and `SEALREF_CLIENT_KEY`,
below. `Folder` is left at the server-side default of `Root`, so an account filed in a subfolder
is not reachable; the query, regular-expression and `FailRequestOnPasswordChange` modes are out of
scope. CyberArk's own error text names the application id, the safe and the requesting machine, so
SealRef reports only the HTTP status and the stable error code such as `APPAP004E`.

## TLS

TLS is rustls with the Mozilla root bundle compiled into the binary, so there is no OpenSSL
dependency and no CA bundle to mount into a `scratch` image. Three variables change that.

| Variable | Meaning |
| --- | --- |
| `SEALREF_CA_FILE` | A PEM file of certificate authorities that **replaces** the built-in roots. |
| `SEALREF_CLIENT_CERT` | A PEM certificate chain presented for mutual TLS. |
| `SEALREF_CLIENT_KEY` | The PEM private key for it. Must be set together with the certificate. |

`SEALREF_CA_FILE` replaces rather than extends, because a trust store that can only grow is not a
control: an operator who points SealRef at an internal CA and leaves every public root able to
vouch for `vault.internal.example.com` has configured something that does nothing. Replacement is
also the more general setting. To trust an internal CA *and* a public one, concatenate them:

```dockerfile
COPY --from=alpine:3 /etc/ssl/certs/ca-certificates.crt /etc/ssl/bundle.pem
COPY internal-ca.pem /tmp/internal-ca.pem
RUN cat /tmp/internal-ca.pem >> /etc/ssl/bundle.pem && rm /tmp/internal-ca.pem
ENV SEALREF_CA_FILE=/etc/ssl/bundle.pem
```

SealRef does not read `VAULT_CACERT`, `VAULT_CAPATH`, `VAULT_SKIP_VERIFY` or `CONJUR_CERT_FILE`.
Those belong to Vault Agent and to the Conjur clients that legitimately share the environment, so
setting one is not an error, but SealRef says on stderr that it is not obeying it. There is no way
to skip certificate verification, and there will not be one.

Redirects are never followed. A redirect from Vault, Conjur or the Central Credential Provider is
either an HTTP-to-HTTPS upgrade, in which case the token has already travelled in cleartext, or it
is not the server you think it is. Either way SealRef fails rather than resending the credential
to wherever the redirect pointed.

## What this does not protect

SealRef provides "no plaintext secret at rest". It cannot provide "plaintext secret never exists".

An application such as Keycloak accepts its database password only as an environment variable. To
start it, something has to put the plaintext in its environment. Anyone with enough access to the
container or the host can therefore still read it from `/proc/<pid>/environ`, from process memory,
from a core dump, or with a debugger. No wrapper can prevent that while still giving a legacy
application the password it demands.

What is actually solved:

| Location | Plaintext |
| --- | --- |
| git | no |
| `.env` file | no |
| container image | no |
| compose file or deployment manifest | no |
| backup | no |
| running process memory | yes |

That is a real and defensible boundary, and it is the whole claim. The master key must be
delivered by a path the encrypted files do not travel on, or the boundary does not exist.

### What the command SealRef runs can see

`exec` removes `SEALREF_KEY`, `SEALREF_KEY_FILE` and `SEALREF_KEY_FD` from the environment it
hands to the application, and closes the `SEALREF_KEY_FD` descriptor itself before handing over.
Removing the variable alone would not have been enough: a descriptor survives `execvp` unless
something closes it, so an application could have read the whole keyring from descriptor 3. The
master key opens every sealed value in the deployment, so leaving it beside the one password the
application asked for would have given away far more than the application needed.

The provider credentials are a different case and are passed through. `VAULT_TOKEN`,
`CONJUR_AUTHN_API_KEY` and the rest may belong to the application as much as to SealRef: plenty of
workloads read from Vault themselves after start-up. Removing them would break those deployments
silently. If the application does not need them, unset them in its own manifest, or deliver them
through a file that only SealRef can read.

Anything SealRef resolves is in the application's environment by design, and a rendered template
is a plaintext file for as long as it exists. Point `--template` at a `tmpfs`.

## What SealRef deliberately does not do

| Not implemented | Reason |
| --- | --- |
| A secret database | That is Vault's job. |
| Secret synchronisation | That is another product. |
| A daemon or a watcher | Restart the workload when secrets rotate. |
| A web UI or user management | Not this tool's job. |
| Every Vault auth method | Let Vault Agent or the platform handle authentication. |
| Every Conjur authenticator | The same reason. Hand SealRef a token or an API key. |
| CyberArk query and regex lookup | A reference should name one account, not a search. |
| Skipping certificate verification | There is no safe deployment where this is the right answer. |
| Following redirects | A redirected credential has already gone somewhere it should not. |
| Automatic secret rotation | A backend concern. |
| Plugins | Attack surface. |
| Shell interpolation in env files | Escaping and injection problems. |
| Plaintext command arguments | They leak through shell history and the process list. |
| `--allow-unresolved` | Failing closed is the point. |

The binary should stay small enough that a security team can read all of it.

## Development

```bash
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
cargo build --release
```

The test suite is self-contained: it passes its own keyring to every invocation, clears the other
key sources, and never needs a network, a live Vault or a live CyberArk. The remote providers are
covered end to end in `tests/providers.rs`, which starts a local HTTP server and asserts on the
request SealRef actually sends: the path, the query, and the vendor authentication header.

Source layout:

| Module | Responsibility |
| --- | --- |
| `reference` | Parsing and formatting of `seal:` references. |
| `crypto` | XChaCha20-Poly1305 seal and open. |
| `keyring` | Key sources, keyring text, Argon2id derivation. |
| `vault` | The Vault KV v2 read. |
| `conjur` | The CyberArk Conjur read and the one API key exchange. |
| `ccp` | The CyberArk Central Credential Provider read. |
| `http` | The shared HTTP client: TLS configuration, timeouts, no redirects. |
| `dotenv` | The env file parser. |
| `template` | Placeholder rendering, `rewrap` text rewriting, private key scanning. |
| `resolve` | Dispatch to the provider that owns a reference. |
| `exec` | Environment assembly and process handover. |
| `check` | The reporting and policy gate. |
| `protect` | In-place sealing of plaintext secrets in a dotenv file. |
| `info` | The keyring report. |

## Contributing

Bug reports and documentation fixes are welcome. Open an issue before building a feature: SealRef
has a narrow scope on purpose, and several obvious-looking additions have already been decided
against for reasons written down in [ROADMAP.md](ROADMAP.md). See
[CONTRIBUTING.md](CONTRIBUTING.md).

Vulnerabilities are reported privately. See [SECURITY.md](SECURITY.md).

## License

MIT. See [LICENSE](LICENSE).
