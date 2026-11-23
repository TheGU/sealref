# AGENTS.md

SealRef is a small Rust CLI that resolves secret references at runtime. It is a security tool
whose whole source a reviewer should be able to read in an afternoon, so most of the rules below
are about keeping it current, not growing it, and not leaking from it.

Read [CONTRIBUTING.md](CONTRIBUTING.md) first. Its scope rules, review checklist (no secret in any
output, fail closed, plaintext in `Zeroizing`) and commit conventions apply to agents unchanged.
This file adds only what an agent needs on top of it.

## Newest that passes the tests

SealRef runs on the newest stable release of everything it depends on: the Rust toolchain
(`rust-version` in `Cargo.toml` is the current stable, not an older floor), the Rust edition,
every crate, the GitHub Actions in the workflows and the Docker base image. Pre-releases are not
taken. CI fails when the `Dockerfile` builds with a Rust version other than `rust-version`, and
the weekly Audit run fails once a newer stable Rust is out.

The test suite is the contract with the previous release. An update that passes it is taken. An
update that makes a test fail has changed behaviour, and whether that ships as a breaking change,
and in which version, is the maintainer's decision, not the agent's:

- Never edit, weaken, skip or delete a test to get an update through.
- Leave the update out of the pull request that is meant to merge. Put it on its own branch, open
  it as a draft pull request with the failing test output, and say what changed upstream.
- The frozen crypto vectors are the strictest case. `opens_a_reference_sealed_by_an_earlier_release`
  in `src/crypto.rs` and `argon2id_derivation_matches_frozen_vectors` in `src/keyring.rs` hold
  values produced by an earlier release. If either fails, the sealed format moved and every
  secret already sealed in the field would stop opening. Their expected values are never edited.

[.claude/skills/tech-refresh/SKILL.md](.claude/skills/tech-refresh/SKILL.md) is the procedure for
a refresh. Run it as `/tech-refresh` in Claude Code; other agents can follow it as a plain
document.

## Checks

CI is the definition of done: [ci.yml](.github/workflows/ci.yml) on every pull request, and
[audit.yml](.github/workflows/audit.yml) when `Cargo.toml` or `Cargo.lock` change. Run what they
run, with `--locked`, so a stray lock change fails instead of riding along:

```bash
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
cargo audit
```

CI also tests on Windows, builds with `rust-version` and builds the `scratch` image from the
[Dockerfile](Dockerfile). Report the output you saw, not a summary of it.

Before any push, CI runs locally. Enable the gate once per clone with
`git config core.hooksPath .githooks`: the pre-push hook runs
[scripts/ci-local.sh](scripts/ci-local.sh), which runs the Linux jobs of both workflows with `act`
on the commit being pushed, and refuses the push if one fails. Never bypass it with
`git push --no-verify`. A refused push is a failing check: fix the cause, or report it.

Without a working native toolchain, commit first, then run the checks in a
`rust:<rust-version>-slim` container on an export of the commit, written outside the repository:
`git -c core.autocrlf=false archive -o <outside-path>/src.tar HEAD`. The export holds only
committed content, with LF line endings as CI checks it out.

## Rules no test can enforce

- **Dependencies stay few.** A new crate in the shipped dependency graph needs a reason in the pull
  request, has to build into the static musl binary, and is added with `default-features = false`
  unless a default feature is needed.
- **A lockfile refresh is its own commit.** `cargo update` output is committed alone. A version
  change made in `Cargo.toml` takes its `Cargo.lock` change, code and tests in the same commit.
- **User-visible changes go in `CHANGELOG.md`** under `Unreleased`, including behaviour that
  arrives through a dependency update. Test-only changes do not.

## Workflow

- Work on a branch and open a pull request. Pull requests are squash-merged, and GitHub deletes
  the branch on merge.
- Never push to `main` and never push a tag. A tag starting with `v` starts the Release workflow,
  which publishes binaries and the GHCR image: that step is the maintainer's. Releasing is
  described in [CONTRIBUTING.md](CONTRIBUTING.md#releasing).
- Stage files by name. Never commit key material, rendered secrets or client certificates.
  [.gitignore](.gitignore) covers the usual names; tests generate what they need at run time.
- A vulnerability report goes through [SECURITY.md](SECURITY.md), not a public issue or pull
  request description.
