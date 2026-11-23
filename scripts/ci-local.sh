#!/usr/bin/env bash
# Runs the Linux jobs of the CI and Audit workflows on one commit with act, the way GitHub runs them
# on a pull request. Usage: scripts/ci-local.sh [<commit>]   (default HEAD)
set -euo pipefail

root=$(git rev-parse --show-toplevel)
sha=$(git -C "$root" rev-parse --verify "${1:-HEAD}^{commit}")
image=sealref-act-runner:latest

for tool in act docker; do
    command -v "$tool" >/dev/null || { echo "ci-local: $tool is not installed; see CONTRIBUTING.md" >&2; exit 2; }
done

echo "ci-local: building the runner image"
docker build --pull --quiet --tag "$image" "$root/.github/act" >/dev/null

work=$(mktemp -d "${TMPDIR:-/tmp}/sealref-ci.XXXXXX")
trap 'rm -rf "$work"' EXIT

# CI checks out LF line endings on Linux, whatever this checkout uses.
git clone --quiet --no-checkout --config core.autocrlf=false "$root" "$work/src"
git -C "$work/src" checkout --quiet --detach "$sha"

echo "ci-local: running CI on $(git -C "$work/src" log -1 --format='%h %s')"
cd "$work/src"
# Git Bash on Windows would otherwise rewrite the container paths below into Windows paths.
MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*' act pull_request \
    --platform "ubuntu-latest=$image" \
    --pull=false \
    --matrix os:ubuntu-latest \
    --container-daemon-socket /var/run/docker.sock \
    --env CARGO_TARGET_DIR=/ctarget \
    --container-options "--volume sealref-act-cargo-registry:/usr/local/cargo/registry --volume sealref-act-target:/ctarget" \
    --concurrent-jobs 2 \
    --rm
echo "ci-local: every Linux job passed on $sha. Windows jobs run only on GitHub."
