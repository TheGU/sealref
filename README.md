# SealRef

A tiny runtime secret-reference resolver for software that cannot natively use a secret manager.
Configuration files and environment variables hold a reference such as
`seal:v1:k20260101:qIb7Q9...` or `seal:vault:secret/myapp/prod/database#password` instead of a
password. At start-up `sealref` resolves those references, puts the plaintext in the environment
of the process it is about to run, or in a rendered configuration file, and hands over. The
application is unchanged and has no idea whether its password came from a locally encrypted `.env`
file or from HashiCorp Vault. SealRef is not a replacement for Vault, SOPS, or External Secrets;
it is the compatibility shim that lets a third-party container image you cannot modify take part
in the secret management you already have.

- One portable reference syntax, deliberately boring and stable.
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
- [What this does not protect](#what-this-does-not-protect)
- [What SealRef deliberately does not do](#what-sealref-deliberately-does-not-do)
- [Development](#development)
- [License](#license)

## Install

From source, with Rust 1.88 or newer (built and tested with 1.98):

```bash
cargo build --release
# target/release/sealref (target\release\sealref.exe on Windows)
```

As a container image, which builds a static `x86_64-unknown-linux-musl` binary and ships it in a
`scratch` image that contains nothing else:

```bash
docker build -t sealref:0.1.0 .
docker run --rm sealref:0.1.0 --version
```

You can use the image without installing anything, for example to check an env file in CI:

```bash
docker run --rm -v "$PWD":/w sealref:0.1.0 check /w/x.env
```

## Quick start

```bash
# 1. Create a key and keep it somewhere the repository cannot reach.
sealref keygen > ~/.config/sealref/dev.key
export SEALREF_KEY_FILE=~/.config/sealref/dev.key

# 2. Seal a secret. The plaintext arrives on stdin, never as an argument.
printf '%s' 'my-password' | sealref seal
seal:v1:k20260829:qIb7Q9...

# 3. Put the reference in the env file and commit it.
cat .env
DB_HOST=localhost
DB_PASSWORD=seal:v1:k20260829:qIb7Q9...

# 4. Run the application with the reference resolved.
sealref exec --env-file .env -- ./myapp
```

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

### Vault secret

```text
seal:vault:<mount>/<path>#<field>
```

For example `seal:vault:secret/myapp/prod/database#password` reads
`GET $VAULT_ADDR/v1/secret/data/myapp/prod/database` and takes `data.data.password`.

The Vault address is deliberately not part of the reference. That is what lets the identical
config line work in staging and in production, with only `VAULT_ADDR` differing between them.

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
Errors go to stderr with exit code 1. `check` uses exit code 2 for a policy failure. No command
ever prints a plaintext secret in a log or an error message.

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
command.

Point `--template` at a `tmpfs` so the rendered plaintext never reaches a disk. In compose:

```yaml
tmpfs:
  - /run/sealref
```

### `sealref render <src> [--out <dst>]`

Replaces every `{{seal:...}}` occurrence in a file with its resolved value, for software that
takes a configuration file rather than environment variables. Writes to stdout, or to `--out` with
mode 0600. Braces that do not contain a `seal:` reference are left alone. An unresolved reference
is an error and no file is written.

```ini
# config.ini.template
username = foo
password = {{seal:vault:secret/foo#password}}
api_key  = {{seal:v1:prod-a:qIb7Q9...}}
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
OK API_TOKEN vault secret/myapp/api#token
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

## Docker

### Adding SealRef to an image you did not build

```dockerfile
FROM quay.io/keycloak/keycloak:latest

COPY --from=sealref:0.1.0 /sealref /usr/local/bin/sealref

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
docker run --rm -v "$PWD":/w sealref:0.1.0 check /w/x.env
docker run --rm -v "$PWD":/w sealref:0.1.0 check --require-sealed /w/x.env
```

### A round trip through the image

```bash
KEY=$(docker run --rm sealref:0.1.0 keygen --kid demo)
REF=$(printf '%s' 'hunter2' | docker run --rm -i -e SEALREF_KEY="$KEY" sealref:0.1.0 seal)
docker run --rm -e SEALREF_KEY="$KEY" sealref:0.1.0 unseal --ref "$REF" --newline
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
auth and the rest are out of scope, permanently. TLS is rustls with the Mozilla root bundle
compiled in, so there is no OpenSSL dependency and no CA bundle to mount into a `scratch` image.

The read is `GET $VAULT_ADDR/v1/<mount>/data/<path>` and the value is `data.data.<field>`. A
missing path, a missing field, a non-string field, an unreachable server, or any non-2xx status is
a failure that stops the process.

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

## What SealRef deliberately does not do

| Not implemented | Reason |
| --- | --- |
| A secret database | That is Vault's job. |
| Secret synchronisation | That is another product. |
| A daemon or a watcher | Restart the workload when secrets rotate. |
| A web UI or user management | Not this tool's job. |
| Every Vault auth method | Let Vault Agent or the platform handle authentication. |
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
key sources, and never needs a network or a live Vault. The Vault provider is covered by unit
tests over the reference parser and a fixed KV v2 response body.

Source layout:

| Module | Responsibility |
| --- | --- |
| `reference` | Parsing and formatting of `seal:` references. |
| `crypto` | XChaCha20-Poly1305 seal and open. |
| `keyring` | Key sources, keyring text, Argon2id derivation. |
| `vault` | The KV v2 read. |
| `dotenv` | The env file parser. |
| `template` | Placeholder rendering, `rewrap` text rewriting, private key scanning. |
| `resolve` | Dispatch to the provider that owns a reference. |
| `exec` | Environment assembly and process handover. |
| `check` | The reporting and policy gate. |

## License

MIT. See [LICENSE](LICENSE).
