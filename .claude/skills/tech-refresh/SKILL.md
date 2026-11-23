---
name: tech-refresh
description: Move SealRef to the newest stable release of everything that still passes its tests (Rust toolchain and edition, crates, GitHub Actions, Docker base image) in one pull request, and fix open RustSec or Dependabot advisories on the way. Inventories advisories and newer releases first, takes each update in its own commit, verifies the way CI does, and splits any update that fails a test into a draft PR for the maintainer to decide on. Use for a tech refresh, a dependency or toolchain update, a CVE or RustSec fix, or when Dependabot PRs pile up.
---

# Tech refresh

The rule is in [AGENTS.md](../../../AGENTS.md): the newest stable release of everything that
passes the tests. The tests are the contract with the previous release. This file is the
procedure.

A refresh is one logical change in CONTRIBUTING's sense: one pull request that brings the
repository current, with each update in its own commit so any one of them can be reviewed or
reverted alone.

## 1. Inventory, before changing anything

Start from an up-to-date `main`. Collect all of this, then report it before editing:

| Question | Command |
|---|---|
| Open Dependabot PRs (cargo and actions) | `gh pr list --author app/dependabot` |
| Open Dependabot alerts | `gh api 'repos/{owner}/{repo}/dependabot/alerts?state=open'` |
| RustSec advisories | `cargo audit` (fetches a fresh advisory database) |
| Semver-compatible updates | `cargo update --dry-run --verbose` |
| Newer major versions | `cargo info <crate>` for every crate in `[dependencies]` and `[dev-dependencies]` |
| Current stable Rust | `rustup check`, or the Rust release blog |
| Newest Rust edition | the edition guide; compare with `edition` in `Cargo.toml` |
| Newer GitHub Actions | `gh api repos/<owner>/<action>/releases/latest --jq .tag_name` for each `uses:` |

For every advisory, find out whether it reaches what ships:

```bash
cargo tree -i <crate> --target all -e normal
```

When cargo answers `nothing to print`, the crate is reached only through dev or build
dependencies, so no released binary or image ever carried it. Say which case applies.

`cargo audit` fails only on vulnerabilities. `unsound` and `unmaintained` advisories are warnings,
which the [Audit workflow](../../../.github/workflows/audit.yml) reports without failing. Take the
fix, but do not call a warning a CVE. `cargo audit` does not cover the Rust standard library; Rust's
own advisories are announced on the Rust blog.

## 2. Branch and commits

Branch from `main` as `deps/<yyyy-mm>`. Make one commit per step, in this order, skipping any step
with nothing to do. Each commit message says why, as CONTRIBUTING asks. Run the tests after each
step, so a failure points at one update.

1. **Semver-compatible crate updates.** `cargo update`, and commit `Cargo.lock` alone. This also
   covers the open Dependabot cargo PRs for the same versions. Dependabot closes those itself once
   `main` has the versions, so leave them open.
2. **Rust toolchain, when stable has moved past `rust-version`.** Find every place that names the
   old version, and review each hit, since a crate version or date can match too:

   ```bash
   git grep -n '<old-version>' -- . ':!CHANGELOG.md' ':!Cargo.lock'
   ```

   That is `rust-version` in `Cargo.toml`, `FROM rust:<version>-alpine` in the `Dockerfile` (the
   compiler that builds the GHCR image), and the version named in `CONTRIBUTING.md` and the README
   install section.
3. **Rust edition, when a newer one exists.** `cargo fix --edition --all-targets` on the old
   edition, then set `edition` in `Cargo.toml`, then `cargo fmt`, whose style follows the edition.
   One commit for all three.
4. **One major crate version per commit.** `Cargo.toml`, `Cargo.lock`, code and tests together.
   Before writing code, read the crate's changelog for changed defaults. The ones that matter here
   change what happens to a credential: proxy environment variables, redirects, error `Display`
   text that quotes a URL or header, lossy decoding of a body, and default features. Set each such
   behaviour explicitly, and add a test that fails without the setting. Keep
   `default-features = false` where the manifest has it. List crates that enter or leave the
   shipped graph in the pull request.
5. **GitHub Actions.** Move each `uses:` in `.github/workflows/` to the newest major tag, one
   commit for all of them. Read each action's release notes for removed inputs.
6. **Changelog.** Under `Unreleased` in `CHANGELOG.md`, record the toolchain and edition changes,
   and any behaviour that changes for users through a dependency: read each updated crate's
   release notes for stricter parsing, removed features or changed defaults. Updates that only
   touch tests stay out.

## 3. When an update fails a test

The test is right until the maintainer says otherwise. Do not edit, weaken, skip or delete it.

1. Drop that update from the refresh branch, so the refresh pull request stays green and can
   merge.
2. Put the update alone on `deps/<yyyy-mm>-<crate-or-tool>`, unchanged tests included, and open it
   as a draft pull request. Its body names the failing tests with their output, the upstream
   change that causes it (with a link to the release note), and what would break for users.
3. Name the draft pull request in the refresh pull request. Whether it ships as a breaking change,
   and in which version, is decided there.

A failing frozen crypto vector always takes this path, and its expected values are never edited:
see AGENTS.md. A compile error caused by a changed API is not a behaviour change; adapting the
code to the new API is part of the update, as long as every test still passes unchanged.

## 4. Verify the branch tip

Commit first. Then run every check on the branch tip with the toolchain at `rust-version`:

```bash
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
cargo audit
cargo run --locked --quiet -- --version
docker build -t sealref:refresh . && docker run --rm sealref:refresh --version
```

Confirm in the test output that both frozen vector tests ran and passed, and that `cargo audit`
reports no vulnerabilities and no warnings, or name each warning left and why.

Windows: CI runs the tests on `windows-latest`. To catch Windows-only lints before CI does, lint
the library for the GNU target. `ring`'s build script needs the MinGW C compiler for this, even
for clippy:

```bash
apt-get install -y --no-install-recommends gcc-mingw-w64-x86-64
rustup target add x86_64-pc-windows-gnu
cargo clippy --target x86_64-pc-windows-gnu --lib --locked -- -D warnings
```

Without a native toolchain, export the commit as AGENTS.md describes and run the commands in a
`rust:<rust-version>-slim` container. `rustup component add clippy rustfmt` and `rustup target add`
do not persist between container runs, so repeat them in each run: a missing component fails in a
way that looks like a real error. Mount a named volume at `/usr/local/cargo/registry` and set
`CARGO_TARGET_DIR` to another volume, so each run is not a cold build. A step that rewrites
sources in the container, such as `cargo fix --edition`, comes back as a patch: extract a second
copy, diff the two, and apply the patch to the index with `git apply --cached`.

## 5. Pull request

Title it after what moved, for example `Take the November 2026 updates: Rust 1.100, edition 2024`.
The body covers:

- **Inventory:** each advisory by ID, the affected and fixed version, and whether it reached the
  shipped build. If the Dependabot alerts list is empty, say so.
- **What changed:** the commits in order, and the Dependabot PRs this supersedes.
- **Held back:** each update split into a draft pull request, with its link and failing tests.
- **Behaviour changes:** the same entries as the changelog.
- **Verification:** the commands run, the toolchain version, the test counts, and the
  `cargo audit` result.

The refresh ends at the pull request. Releasing is a separate step for the maintainer.
