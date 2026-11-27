# Contributing to 99passwords

Thanks for helping. This is a small password manager, so the bar is
"simple, auditable and tested" rather than "feature-rich".

## Before you start

- For anything bigger than a bug fix, open an issue first and describe the
  change. Changes to the on-card format, crypto or bridge protocol must update
  [`docs/SPEC.md`](docs/SPEC.md) in the same pull request.
- Security problems go through [`SECURITY.md`](SECURITY.md), never a public
  issue.
- Coding agents: read [`AGENTS.md`](AGENTS.md). It has the commands and the
  rules in one place.

## Setup

- Rust stable 1.85 or newer (`rustup`), a C compiler, Node.js 20+ for the
  extension tests.
- macOS 14+ with the Xcode Command Line Tools for the app, the PC/SC transport
  and the Swift tests.
- Optional: `npm install playwright` (anywhere on the module path) to run the
  extension's end-to-end test in Chromium.

The tests do not need a YubiKey: the core ships `MockYubiKey`, an in-memory
YubiKey 5. Running the app needs a real YubiKey 5; **use a spare one** for
development, since setting it up takes over its PIV application.

## Checks

GitHub Actions runs these on every pull request, but run them locally first
and paste the summary into the PR description:

```sh
scripts/check.sh                                      # Linux or macOS
cargo test -p ykvault-pcsc && scripts/swift-tests.sh  # macOS
macos/build-app.sh                                    # macOS, if you touched the app
```


## Pull requests

- One topic per pull request, small diffs preferred.
- Add or update tests with every behaviour change. Core changes are tested
  against `MockYubiKey`; extension logic in `extension/test/`.
- No new dependencies without discussion. The Rust core must stay offline and
  minimal (no async runtime, no network or TLS crates, no proc-macros, no
  build scripts); `scripts/check.sh` enforces a deny list.
- Never commit real secrets, vault exports, YubiKey serials or personal paths.
  Test data uses `example.com` addresses and made-up names.
- Write commit messages in the imperative ("Add TOTP period field").

By contributing you agree that your contribution is licensed under the MIT
License of this project.
