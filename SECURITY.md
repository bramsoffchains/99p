# Security policy

99passwords stores passwords, so security reports are the most valuable
contribution you can make. Thank you.

## Reporting a vulnerability

**Do not open a public issue.** Report privately through GitHub:
**Security → Report a vulnerability** on this repository (private
vulnerability reporting). Include:

- what an attacker can do, and under which conditions (see the threat model
  in [`docs/SPEC.md` §14](docs/SPEC.md#14-threat-model-summary));
- steps or a proof of concept, ideally as a test against `MockYubiKey`;
- affected version or commit, macOS and YubiKey firmware version if relevant.

We aim to answer within 7 days. Please give us 90 days, or until a fix
ships if that is sooner, before disclosing publicly. We will credit you unless
you prefer otherwise.

## Supported versions

The project is an early prototype. Only the latest commit on `main` gets
security fixes.

## Scope

In scope, for example:

- recovering vault contents or the master password without the YubiKey, the
  PIN-checked ECDH or the master password;
- offline guessing of the master password from data on the card or the Mac;
- secrets written to disk, logs, crash reports or left on the clipboard
  beyond what SPEC describes;
- the Chrome extension filling credentials into the wrong origin or frame, or
  any web page reading them;
- other local processes talking to the bridge socket or native host without
  the peer checks;
- memory safety bugs in the FFI or the TLV/container parsers.

Out of scope (documented trade-offs, see SPEC §14):

- an attacker who already runs code as your user while the vault is unlocked;
- denial of service by someone holding your YubiKey (255 wrong tries block the
  vault on that card by design; keep a backup key);
- attacks that need extracting keys from the YubiKey's secure element;
- weak master passwords.

## Handling secrets in reports

Never send a real vault, `.ykv` file, master password or YubiKey you care
about. Reproduce with `MockYubiKey` in a test or with a spare YubiKey.
