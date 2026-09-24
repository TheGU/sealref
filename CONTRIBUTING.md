# Contributing

Thanks for looking. SealRef is small on purpose, so the most useful contribution is usually a
sharp bug report or a case the documentation gets wrong.

## Before you build a feature

Open an issue first. SealRef has a deliberately narrow scope, and the
[What SealRef deliberately does not do](README.md#what-sealref-deliberately-does-not-do) table is
a list of things that have already been decided against rather than a list of gaps. A pull request
that adds a provider, a daemon, a plugin mechanism or a new auth method is likely to be declined
on scope even when the code is good, and neither of us wants to find that out after you have
written it.

The bar for a new secret backend is roughly: it is a single HTTP read, it needs no new
authentication machinery beyond a token or a key that the platform already provides, and it adds
no dependency that a `scratch` image cannot carry.

## Working on it

```bash
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

All three must pass; CI runs them on Linux and Windows, and also builds the `scratch` image. The
minimum supported Rust version is 1.88 and is checked in CI, so keep away from newer language
features.

The test suite needs no network, no live Vault and no live CyberArk. `tests/providers.rs` starts a
local HTTP server and asserts on the request that actually goes out, which is where a new provider
belongs.

## What review will ask about

- **No secret in any output.** Not in an error message, not in a `Debug` impl, not in a panic.
  Error text may name a variable, a key id, a file, a line or a provider locator, and nothing
  else. Every config type that holds a credential has a hand-written `Debug` and a test that
  proves it redacts; a new one needs both.
- **Fail closed.** An unresolvable reference stops the process. There is no partial success, no
  warning-and-continue and no `--allow-unresolved`.
- **Plaintext lives in `Zeroizing`.** Decrypted values, keys and tokens are wrapped so they are
  cleared on drop.
- **Tests that state the rule.** Test names here read as sentences about behaviour, and the ones
  that matter most are the ones asserting something is *absent* from the output.
- **Comments explain decisions, not mechanics.** Most of the comments in this codebase say why
  something is the way it is, usually because the obvious alternative is wrong in a way that is
  not obvious. Keep that.

A security team should be able to read the whole binary's source in an afternoon. That is a real
constraint, not a slogan: it is why there is no plugin system and why the dependency list is short.

## Commits and pull requests

One logical change per pull request. Write the commit message so it explains why, not what; the
diff already says what. Update `CHANGELOG.md` under an `Unreleased` heading, and update the README
when behaviour or configuration changes.

## Releasing

On an up-to-date, clean `main`, run `.\release.ps1 v1.2.3`. It moves the `Unreleased` changelog
section under the new version, bumps the version in `Cargo.toml`, `Cargo.lock`, the README and the
bug report template, and makes the release commit and tag. It pushes nothing; push with
`git push --atomic origin main v1.2.3`, and the tag starts the Release workflow. It needs either a
local cargo matching `rust-version` or Docker.

## Reporting a vulnerability

Do not open a public issue. See [SECURITY.md](SECURITY.md).

## License

Contributions are licensed under the MIT License, the same as the project.
