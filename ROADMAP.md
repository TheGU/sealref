# Roadmap

What is likely to happen, what is being considered, and what has been decided against. The last
list is the important one: SealRef's usefulness depends on staying small enough that a security
team can read it.

## Likely

- **Release binaries for more targets.** Today the release workflow builds `x86_64` Linux (musl),
  `x86_64` Windows and Apple Silicon macOS. `aarch64` Linux and Intel macOS are the gaps.
- **A multi-architecture container image.** The published image is `linux/amd64` only.
- **`check --format json`.** The current output is one line per finding, which is easy to read and
  awkward to consume. A machine-readable form would make the CI gate more useful.

## Under consideration

These need a real use case before they get built. Open an issue if you have one.

- **CyberArk CCP subfolders.** `Folder` is left at the server-side default of `Root`, so an
  account filed in a subfolder is not reachable.
- **CyberArk CCP by user name.** Looking an account up by `UserName` and `Address` rather than by
  object name. This edges toward the query mode that is deliberately out of scope, so it needs a
  reference syntax that still names one account rather than a search.
- **Conjur batch retrieval.** Conjur can return several variables in one request. Worth it only
  for deployments with many references, and it changes the error semantics when one of them is not
  permitted.
- **A key id in the keyring marked as sealing-only.** Today the first keyring line is the default
  for `sealref seal`, which is implicit. An explicit marker would be clearer during a rotation.

## Decided against

Not gaps. See also the table in the
[README](README.md#what-sealref-deliberately-does-not-do).

- **A daemon, a watcher, or secret refresh.** SealRef resolves once, at start-up, and hands over.
  Restart the workload when secrets rotate. A long-lived process holding decrypted secrets is a
  different and much larger security problem.
- **A plugin mechanism.** Attack surface, in a binary whose value is that it can be read end to
  end.
- **Every Vault auth method, and every Conjur authenticator.** Obtaining an identity is the
  platform's job. Hand SealRef a token, or a key it can exchange in one request.
- **Skipping certificate verification.** There is no deployment where this is the right answer.
- **Following redirects.** A credential that followed a redirect has already gone somewhere it
  should not.
- **Shell interpolation in env files.** Escaping and injection problems that a secret loader
  should not be answering.
- **`--allow-unresolved`, or any partial success.** Failing closed is the point.
- **Plaintext as a command-line argument.** It lands in the shell history and in the process list.
