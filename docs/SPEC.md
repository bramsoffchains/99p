# 99passwords: format and crypto spec (v1)

> "I got 99passwords, but a breach ain't one."

Status: **draft v1**, for review before the core is implemented. Normative
words (MUST, SHOULD) are used loosely but on purpose. All integers are
little-endian unless stated. `||` is concatenation. "Card" means a YubiKey 5
running the PIV application.

Contents: 1 Principles · 2 Layout on the card · 3 Manifest · 4 Bank image ·
5 Keys and crypto · 6 Payload and schema · 7 PIV APDU profile · 8 Provisioning
and management key · 9 Save, load, tearing, clones · 10 Favicon cache ·
11 FFI · 12 Browser bridge · 13 Export / import · 14 Threat model ·
15 Open questions to verify on hardware

---

## 1. Principles

- The vault exists only on YubiKeys (and in optional user-initiated `.ykv`
  exports). Nothing else persists on disk except: the encrypted favicon cache
  (§10), the Chrome native-messaging host manifest (no secrets, §12.1), and app
  preferences that contain no vault data (window position, chosen reader).
- The Rust core is offline by construction: no async runtime, no HTTP, no TLS,
  no sockets (the socket lives in the app and the bridge, not the core), no
  proc-macros, no C build scripts. `scripts/check.sh` rejects these crates.
- Dependencies (pinned, all pure Rust, one version of each RustCrypto trait crate):
  `chacha20poly1305 0.11`, `p256 0.14` (arithmetic, ecdh), `hkdf 0.13`,
  `hmac 0.13`, `sha2 0.11`, `sha1 0.11` (TOTP only), `aes 0.9` / `des 0.9` (management-key auth only),
  `zeroize 1.9` (no derive), `getrandom 0.4`, `miniz_oxide 0.9`.
  No password-stretching KDF: the card's PIN counter limits guessing (§5.1).
  Total: 59 crates in `cargo tree`, none of them proc-macros.
- FFI is a hand-written plain C ABI (§11), not UniFFI: UniFFI pulls in
  `syn`/proc-macros, a scaffolding generator and a runtime, which conflicts
  with the minimal, auditable goal. The surface the app needs is small (~20
  functions).

## 2. Layout on the card

Yubico documents that PUT DATA stores any tag in `0x5F0000..=0x5FFFFF`
(except Discovery, Printed and BITGT), that each object holds at most
**3,052 bytes**, and that all certificates and data objects share **51,200
bytes** of NVM, including the attestation certificate and any certificates the
user already has.

| Object | Purpose |
|---|---|
| `0x5FC200` | Manifest, 88 bytes (§3) |
| `0x5FC210`..`0x5FC217` | Bank A, chunks 0..7 |
| `0x5FC220`..`0x5FC227` | Bank B, chunks 0..7 |
| Slot `0x82` | P-256 vault key, PIN policy ALWAYS, touch policy ALWAYS |
| PIN | 8 characters derived from the passphrase (§5.1), 255 tries |
| PUK | blocked at provisioning: there is no way to reset the PIN |

- `OBJ_MAX = 3052` is the maximum bytes stored per object (the value inside
  tag `53`). Verify on hardware in phase 3 (§15); keep it a constant.
- Objects use exactly the size of their content, so a small vault uses little
  NVM even with two banks.
- **A/B mode** (default): bank capacity 8 × 3052 = 24,416 bytes of image.
  After the 216-byte header and 1 KiB padding the ciphertext can be at most
  23 KiB (23,552 bytes), which is 23,536 bytes of compressed plaintext.
- **Single-bank mode** (explicit opt-in, manifest flag): one bank spans
  `0x5FC210..17` then `0x5FC220..27`, 16 chunks, 48,832 bytes, so up to 47 KiB
  of ciphertext. Writes overwrite the live vault and are **not tear-safe**; the
  UI must say so and recommend a synced backup key.
- Measured (core `benchmark` test): 500 logins with 20-character random
  passwords, one in five with TOTP, need about 26 KB of ciphertext when their
  timestamps differ, so an A/B bank holds roughly 450 such entries. A bulk
  import (shared timestamps) of 500 still fits A/B. Beyond that, single-bank
  mode is the documented opt-in.
- Measured (core `capacity` test, saving one item at a time until full):

  | Content | A/B | Single-bank |
  |---|---|---|
  | Logins, 1 in 5 with TOTP | 438 | 918 |
  | Logins, all with TOTP | 323 | 676 |
  | Mixed: per 20 items, 16 logins, 2 notes, 1 card, 1 API key | 376 | 795 |
  | Notes only (~300 characters each) | 227 | 480 |
  | Mixed, key already holding 4.5 KB of other certificates | 360 | 759 |

- If a single-bank save runs out of NVM partway (`6A84`), it has already
  overwritten part of the only copy, so the core immediately saves the
  previous vault again before reporting `Error::Capacity`.
- The UI capacity meter shows `image_len / bank_capacity`. Warn at 80%. When a
  save would not fit, refuse it and offer single-bank mode. The core reports
  `Error::Capacity`; a `6A84` from the card (NVM full because of other
  certificates) is reported the same way.

## 3. Manifest (`0x5FC200`, 88 bytes)

The manifest is a **hint**, not a single point of failure. Each bank is
self-describing, so a torn or missing manifest is recovered by scanning (§9.3).
At 88 bytes it fits in one short APDU without command chaining.

| Off | Len | Field |
|---|---|---|
| 0 | 4 | magic `"99PM"` |
| 4 | 1 | `manifest_v` = 1 |
| 5 | 1 | flags: bit0 = single-bank mode; others 0 |
| 6 | 1 | `active_bank`: 0 = A, 1 = B (always 0 in single-bank mode) |
| 7 | 1 | reserved, 0 |
| 8 | 16 | `vault_uuid` (random at creation, same on all clones) |
| 24 | 8 | `revision` (u64) of the active bank |
| 32 | 4 | `image_len` (u32) of the active bank |
| 36 | 1 | `chunk_count` |
| 37 | 3 | reserved, 0 |
| 40 | 32 | `image_digest`, copied from the active bank header |
| 72 | 16 | `check` = SHA-256(`"99p/v1/manifest"` \|\| bytes[0..72])[0..16] |

A manifest is valid iff the length is 88, the magic matches, `manifest_v` is 1
and `check` verifies.

## 4. Bank image

`image = header (216 bytes) || ciphertext (ct_len bytes)`. It is split into
`ceil(image_len / OBJ_MAX)` chunks; chunk *i* is stored verbatim as the value
of object `bank_base + i`. There is no per-chunk header: integrity comes from
`image_digest` and the AEAD tags.

### 4.1 Header

| Off | Len | Field |
|---|---|---|
| 0 | 4 | magic `"99PV"` |
| 4 | 2 | `container_v` = 1 (u16) |
| 6 | 1 | flags: bit0 = single-bank mode |
| 7 | 1 | PIV `slot` of the vault key (0x82) |
| 8 | 16 | `vault_uuid` |
| 24 | 8 | `revision` (u64) |
| 32 | 1 | `kdf_id`: 2 = HKDF-SHA256, no stretching (§5.1) |
| 33 | 11 | reserved, 0 (were Argon2 parameters under `kdf_id` 1) |
| 44 | 16 | `salt` |
| 60 | 8 | `card_fpr` = SHA-256(card pubkey, SEC1 uncompressed)[0..8] |
| 68 | 4 | `card_serial` (u32) |
| 72 | 33 | `eph_pub`: ephemeral P-256 public key, SEC1 compressed |
| 105 | 12 | `wrap_nonce` |
| 117 | 12 | `payload_nonce` |
| 129 | 3 | reserved, 0 |
| 132 | 4 | `ct_len` (u32), a multiple of 1024 |
| **136** | 48 | `wrapped_dek` (32-byte DEK + 16-byte tag) |
| **184** | 32 | `image_digest` = SHA-256(header[0..184] \|\| ciphertext) |

- `AAD_wrap = header[0..136]`. `AAD_payload = header[0..184]`, which covers
  `wrapped_dek`. The revision, salt, KDF id and layout flags are
  therefore authenticated, so an older bank relabelled with a higher revision
  does not decrypt.
- A decoder MUST reject: unknown magic, `container_v` > 1 (read-only "newer
  version" error), `kdf_id` ≠ 2,
  `ct_len` = 0, not a multiple of 1024 or larger than the bank allows, and
  non-zero reserved bytes.

## 5. Keys and crypto

### 5.1 Inputs

- `Q_card`: P-256 public key of slot 0x82, generated on-chip, never exportable.
- `pass`: master passphrase as UTF-8. The app NFC-normalises it before it
  crosses the FFI (`precomposedStringWithCanonicalMapping`); the core does not
  normalise.
- `P = HKDF-SHA256(salt = salt, ikm = pass, info = "99p/v1/pass")`. The
  salt is random per vault and changes only when the passphrase changes.
  There is **no stretching** (Argon2 was dropped): every guess has to go
  through the card's PIN check, and the card blocks for good after 255 wrong
  ones (§8.1, §14), so a slow KDF would only slow down honest unlocks.
- `PIN = map(HKDF-SHA256(salt = "99p/v1/pin", ikm = P, info = "")[0..8])`,
  each byte `b` becoming `ALPHABET[b & 63]` with
  `ALPHABET = A–Z a–z 0–9 - _` (48 bits). The card's PIV PIN is 6 to 8
  bytes, so the passphrase itself cannot be the PIN; deriving it lets a
  passphrase of any length work. The PIN is one-way from `P`, so seeing it
  (for example in an APDU trace) does not reveal `P`. It is never shown.

### 5.2 Per save (software only, no touch)

```
DEK          = random(32)                      # rotates every save
e            = random non-zero scalar; E = e·G  # rotates every save
Z            = x-coordinate(e · Q_card)         # 32 bytes, computed in software
KEK          = HKDF-SHA256(salt = "99p/v1/kek",
                           ikm  = Z || P,
                           info = vault_uuid || card_fpr || E(33, compressed) || revision(u64))
wrapped_dek  = ChaCha20-Poly1305(KEK, wrap_nonce, DEK, AAD_wrap)
ciphertext   = ChaCha20-Poly1305(DEK, payload_nonce, plaintext, AAD_payload)
```

Nonces come from the OS CSPRNG. Both keys are fresh every save, so a nonce is
never reused under a key. `e`, `Z` and `KEK` are wiped once the image is
built.

**Saving never needs a touch or the PIN.** It only needs `Q_card` (stored in `known_keys`
and readable from slot metadata), `P` (kept in locked RAM while unlocked) and
the management key (in the vault) for PUT DATA. Only unlock uses the card's
private key.

### 5.3 Unlock (PIN, then hardware ECDH with one touch)

1. Read the active bank (§9.3) without touching the card or using the PIN.
2. `P`, then `PIN` (§5.1).
3. VERIFY `PIN`. A wrong passphrase is refused here, before any touch, and
   costs one of the 255 tries (`Error::WrongPin { tries_left }`; the app
   shows the count after 10 wrong ones). At 0 the PIN is blocked (`Error::PinBlocked`) for good:
   the PUK is blocked too, so the vault on this card is lost.
4. `Z = GENERAL AUTHENTICATE ECDH(slot 0x82, E)`, right after the VERIFY
   (PIN policy ALWAYS). The card blinks; the user touches.
5. Derive `KEK`, open `wrapped_dek`, then open the ciphertext. Any failure
   gives `Error::Decrypt` (wrong passphrase, wrong card and tampering look the
   same).
6. Keep `DEK`-independent state in locked RAM: `P`, the decoded `Vault`, and
   per-card management keys. Do not keep `Z` or `DEK`.

### 5.4 Locked RAM

Secrets live in `SecretBytes` (mlock'd, zeroized on drop). Model strings are
zeroized on drop. macOS has no `mlockall`, so heap copies made by the system
allocator cannot all be page-locked. The app SHOULD set `RLIMIT_CORE = 0`, and
macOS encrypts swap. The session is wiped on: explicit lock, idle timeout
(`settings.idle_lock_secs`), screen lock or sleep, and **card removal** (PC/SC
watcher, §7.5).

## 6. Payload and schema

### 6.1 Plaintext (before AEAD), `ct_len − 16` bytes

| Off | Len | Field |
|---|---|---|
| 0 | 2 | `schema_v` = 1 (u16) |
| 2 | 1 | compression: 0 = none, 1 = raw DEFLATE (RFC 1951, `miniz_oxide` level 10) |
| 3 | 1 | reserved, 0 |
| 4 | 4 | `body_len` (u32), stored body length |
| 8 | 4 | `raw_len` (u32), uncompressed length; inflate is capped to this value and to 1 MiB |
| 12 | body_len | body |
| … | | zero padding to `ct_len − 16` |

`ct_len = 1024 · ceil((12 + body_len + 16) / 1024)`. Padding hides the entry
count and the size of edits to within 1 KiB. A reader with `schema_v` newer
than it supports opens the vault **read-only**.

### 6.2 TLV encoding

`item = tag: u8 || len: LEB128 || value[len]`. Integers are LEB128 varints,
strings are UTF-8, and booleans are one byte (1). Unknown tags at every level
are kept verbatim and re-emitted on save (`extra`). Order of repeated items is
significant.

### 6.3 Body tags (top level)

| Tag | Type | Field |
|---|---|---|
| 0x01 | 32 bytes | `vault_secret`: stable, never rotated, root of derived keys (§10) |
| 0x02 | varint | `created_at` |
| 0x03 | 8 bytes | `head`: random save id, new on every save |
| 0x04 | n × 8 bytes | `ancestors`: previous heads, newest first, at most 32 |
| 0x05 | nested | settings: 0x01 `idle_lock_secs`, 0x02 `clipboard_clear_secs`, 0x03 `single_bank` (bool) |
| 0x10 | nested | entry (repeated, §6.4) |
| 0x20 | nested | known key (repeated, §6.5) |

### 6.4 Entry and field

Entry: 0x01 `id` (varint u64, random), 0x02 `kind` (u8: 1 Login, 2 Card,
3 Note, 4 Custom, 5 Identity), 0x03 `name`, 0x04 `host` (repeated), 0x05 `updated_at`
(varint, Unix seconds), 0x06 field (nested, repeated), 0x07 `deleted` (bool;
a tombstone keeps only id, kind, updated_at, deleted), 0x08 `created_at`.

Field: 0x01 `kind` (u8), 0x02 `label` (custom kinds only), 0x03 `value`
(bytes).

| Kind | Value |
|---|---|
| 0x01 Username, 0x02 Password, 0x07 CardHolder, 0x08 PIN, 0x09 Note, 0x10 CustomText, 0x11 CustomSecret, 0x04 CardNumber, 0x06 CardCVV | UTF-8 |
| 0x20 FirstName, 0x21 LastName, 0x22 Email, 0x23 Phone, 0x24 Street (lines separated by `\n`), 0x25 City, 0x26 Postcode, 0x27 Region, 0x28 Country | UTF-8, not secret (Identity entries, for form autofill) |
| 0x05 CardExpiry | UTF-8 `YYYY-MM` |
| 0x03 TOTP | `flags: u8 \|\| period: u8 \|\| secret` where flags bits 0-1 are the algorithm (0 SHA-1, 1 SHA-256, 2 SHA-512), bits 2-3 are digits − 6 (6, 7 or 8), bits 4-7 are 0; period 0 means 30 s; `secret` is the raw decoded key (not base32, not an `otpauth://` URI) |

`otpauth://totp/...` URIs are parsed on import and generated on export only.
HOTP is out of scope for v1.

### 6.5 Known key (one per provisioned YubiKey)

0x01 `serial` (varint), 0x02 `label`, 0x03 `piv_pubkey` (65 bytes, SEC1
uncompressed), 0x04 `slot`, 0x05 `mgmt_alg` (u8: 0x03 3DES, 0x0A AES-192, 0x0C AES-256; AES-192 only appears as `mgmt_key_prev` when the factory default key of fw 5.7+ is being replaced),
0x06 `mgmt_key`, 0x07 `last_synced_rev` (varint), 0x08 `firmware` (3 bytes),
0x09 `added_at`, 0x0A `mgmt_key_prev` (nested: 0x01 alg, 0x02 key; present only
during a rotation, §8.2).

### 6.6 Hosts

Stored normalised: lowercase ASCII, IDNA labels kept in punycode form as the
browser reports them, no scheme, port, path, userinfo or trailing dot. The
leading `www.` is kept as entered but ignored when matching. Request host
`h` matches entry host `e` if `h == e` (rank 0) or `h` ends with `"." + e`
(rank 1, subdomain). An entry for `example.com` therefore matches
`app.example.com`, but not `example.com.evil.net`. Entries are never matched
on registrable-domain heuristics alone (no public-suffix list in v1); the UI
always shows "Fill into `<host>`?".

## 7. PIV APDU profile

All commands use CLA 00 on the PIV application (AID `A0 00 00 03 08`).
Responses with `61xx` are drained with GET RESPONSE (`00 C0 00 00 xx`). Data
longer than 255 bytes is sent with command chaining (CLA `10` on all but the
last block, 255-byte blocks). Extended APDUs are not used. The
`SmartCard::transmit` trait (`crates/core/src/card.rs`) moves raw APDUs; everything
below is in the core's PIV client, so `MockYubiKey` covers it all.

| Operation | APDU | Data / response |
|---|---|---|
| SELECT | `00 A4 04 00 05 A0 00 00 03 08` | |
| Version | `00 FD 00 00` | 3 bytes major.minor.patch |
| Serial | `00 F8 00 00` | 4 bytes big-endian (fw ≥ 5) |
| Metadata | `00 F7 00 <slot>` | TLV: 01 alg, 02 policy (pin, touch), 03 origin, 04 public key (`86 41 04..`), 05 is-default (slot 9B) (fw ≥ 5.3) |
| GET DATA | `00 CB 3F FF` | `5C 03 <tag>` → `53 <len> <value>`; `6A82` if absent. No PIN for our tags |
| PUT DATA | `00 DB 3F FF` | `5C 03 <tag> 53 <len> <value>`; empty `53 00` deletes. Needs management key auth |
| Mgmt auth step 1 | `00 87 <alg> 9B` | `7C 02 80 00` → `7C .. 80 <n> witness` |
| Mgmt auth step 2 | `00 87 <alg> 9B` | `7C .. 80 <n> dec(witness) 81 <n> challenge` → `7C .. 82 <n> enc(challenge)` (host checks it) |
| Set mgmt key | `00 FF FF FF` | `<alg> 9B <len> <key>`; P2 = FF means no touch for mgmt ops |
| Generate key | `00 47 00 82` | `AC 09 80 01 11 AA 01 03 AB 01 02` (P-256, PIN always, touch always) → `7F 49 .. 86 41 04 X Y` |
| VERIFY PIN | `00 20 00 80` | PIN padded with `FF` to 8 bytes; no data asks for the tries left (`63Cx`, capped at 15) |
| PIN / PUK metadata | `00 F7 00 80` / `81` | 05 is-default, 06 (total, remaining) tries (fw ≥ 5.3) |
| Change PIN / PUK | `00 24 00 80` / `81` | old (8) \|\| new (8), padded |
| Unblock PIN | `00 2C 00 80` | PUK (8) \|\| new PIN (8), padded |
| Set PIN retries | `00 FA <pin> <puk>` | YubiKey only; needs mgmt auth **and** a verified PIN; resets PIN and PUK to `123456` / `12345678` |
| (Block the PUK) | `00 2C 00 80` | a wrong PUK after SET PIN RETRIES with 1 PUK try → `6983` / `63C0` |
| PIV reset | `00 FB 00 00` | YubiKey only; needs PIN and PUK blocked |
| ECDH | `00 87 11 82` | `7C 45 82 00 85 41 04 X Y` → `7C 22 82 20 Z` |

Lengths are BER-TLV (`81 xx`, `82 xx xx` beyond 127). The block cipher for
management-key auth is single-block ECB (n = 8 for 3DES, 16 for AES), using the
`des` / `aes` crates.

Status words: `9000` ok; `6982` security status not satisfied (no mgmt auth, or
touch timeout on ECDH, which maps to `TOUCH_TIMEOUT` when it follows an ECDH);
`6A80` bad data; `6A82` not found; `6A84` NVM full; `63Cx` wrong PIN/PUK
with x tries left; `6983` PIN/PUK blocked; `6D00` / `6E00` wrong app.

### 7.5 macOS transport (phase 3, `crates/pcsc/`)

`PCSC.framework` via `#[link(name = "PCSC", kind = "framework")]` and
hand-declared externs: `SCardEstablishContext`, `SCardListReaders`,
`SCardConnect` (T=1, shared), `SCardBeginTransaction` / `SCardEndTransaction`
around every multi-APDU operation, `SCardTransmit`, `SCardDisconnect`,
`SCardGetStatusChange` (removal watcher on a dedicated thread, reported to the
app through a callback). Note: on macOS `DWORD` is `u32`. Reader filter: name
contains "YubiKey" and the PIV SELECT succeeds.

API (`ykvault-pcsc`): `yubikey_readers()`, `PcscCard::open(Option<&str>)`,
`PcscCard::transaction(|card| ...)` (begins the transaction and re-selects PIV,
since another app may have selected a different applet in between),
`PcscCard::watch_removal(callback)` returning a `RemovalWatcher` (dropping it
stops the thread; the callback fires at most once). Every transport failure
after connect, including a reset by another app, maps to `CardRemoved` and the
card stays dead. Disconnect uses `SCARD_RESET_CARD` so the card forgets the
management key authentication.

## 8. Provisioning and management key

### 8.1 New vault on a fresh card

1. SELECT, read version and serial. Read metadata for slot 9B on fw ≥ 5.3.
2. **Management key**: if metadata says default, use the default key
   (`010203040506070801020304050607080102030405060708`; 3DES before 5.7,
   AES-192 on 5.7+). If it is **not** default, ask the user for the current key
   (hex). Never overwrite blindly. On fw < 5.3, try the default, and prompt on
   failure.
3. **Slot 0x82**: if metadata shows a key already there, stop and ask (it might
   be the user's). The UI may offer another retired slot (82..95).
4. **PIN and PUK** must be the factory defaults (metadata `05` on fw ≥ 5.3;
   otherwise the default PIN must verify). If not, stop: the user resets PIV
   (`ykvault piv-reset <serial>`) or uses another key.
5. Create the salt; derive `P` and `PIN`.
6. Authenticate the management key, VERIFY `123456`, SET PIN RETRIES 255 / 1
   (this resets PIN and PUK to the defaults, which is why it comes first),
   send one wrong PUK so the PUK is **blocked**, and change the PIN to `PIN`.
   With no PUK, nothing can reset the PIN: the 255th wrong passphrase bricks
   the vault on this card (the PIV application can still be reset, empty).
7. Generate the P-256 key (PIN always, touch always). Store `Q_card`.
8. Create the vault: random `vault_uuid` and `vault_secret`.
9. Management key rotation, §8.2.

A crash after step 6 leaves a card with a non-default PIN and no vault;
setting it up again needs a PIV reset first.

### 8.2 Crash-safe management key rotation

Changing the management key and saving the vault cannot be atomic together.
A crash between them would leave a key that is in neither place, so the PIV
application would need a reset. Order:

1. Generate `M_new`: AES-256 on fw ≥ 5.4.2, otherwise 3DES (24 random bytes).
2. Save the vault with `mgmt_key = M_new`, `mgmt_key_prev = M_old`,
   authenticated with `M_old`.
3. SET MANAGEMENT KEY to `M_new`.
4. Save again without `mgmt_key_prev`, authenticated with `M_new`.

When authenticating, try `mgmt_key`, then `mgmt_key_prev`. Every crash point
leaves one of them valid.

## 9. Save, load, tearing, clones

### 9.1 Is PUT DATA atomic?

**Not documented.** Yubico's PIV docs describe object limits and auth, but
not power-loss behaviour. Chained PUT DATA is presumably committed only after
the final block, but that is not guaranteed either. The design therefore
**assumes a PUT DATA can tear** (leaving the object old, new, missing or
partial) and does not depend on any single write being atomic, the manifest
included. Phase 3 still tests on hardware what really happens (§15).

### 9.2 Save algorithm (A/B mode)

```
r_new  = max(revision of every valid bank seen on this card, vault max) + 1
target = the bank that is NOT the one in use (single-bank: the only bank)
1. build image (§4, §5.2) with revision r_new, fresh head, ancestors = [old head] + ancestors[..31]
2. authenticate the management key
3. PUT DATA chunks 0..n-1 of target, in order; then delete target objects n..7 if present
4. GET DATA every chunk; SHA-256 must equal image_digest (one retry, else fail)
5. PUT DATA manifest {active_bank = target, revision = r_new, digest, ...}
6. GET DATA manifest; it must match byte for byte
7. only now report "saved" to the UI
```

The bank in use is never touched before step 5, so at any interruption the
card holds a complete old vault, and from step 4 on also a complete new one.

### 9.3 Load algorithm

```
1. read manifest M
2. if M valid: read bank M.active_bank; accept if its header parses,
   uuid == M.uuid, revision == M.revision and SHA-256 check == M.digest == header.digest
3. otherwise (manifest missing, torn, or pointing at a bad bank):
   read both banks; keep those whose header parses and whose digest verifies;
   pick the highest revision (tie: the manifest's bank, else A);
   uuid must match M.uuid when M is valid
4. none valid -> Error::NoValidVault
```

Steps 1 to 3 need no PIN, no touch and no key, so a torn bank never costs the
user a touch. If step 3 fires, the next save rewrites the manifest.

**Tearing outcomes, all covered by MockYubiKey tests:** for every PUT DATA
index *k* in a save, and each tear mode (write not applied, object deleted,
object truncated to a random length, object filled with garbage), unplug,
replug and load. The result MUST be exactly the old or exactly the new vault,
never an error and never a mix. In single-bank mode the test instead asserts
that the failure is detected (`NoValidVault`), not silently mixed.

### 9.4 Clones and backup keys

- Every card has its own non-exportable slot-0x82 key and its own management
  key. All of them are listed in `known_keys`, inside the vault.
- **Clone** (vault unlocked from card A, card B inserted): provision B (§8.1,
  steps 1 to 7, with the session's `P`, so B gets the same derived PIN and
  its own 255 tries), add B to `known_keys`, save to B (wrapped to `Q_B`), then save
  to A so A knows about B. Both carry the same `vault_uuid`, salt and
  passphrase. Only one card needs to be inserted at a time: the app keeps the
  unlocked vault in RAM and prompts "insert backup key".
- **On plug-in** of a card with the same `vault_uuid` while unlocked, read its
  manifest (no touch). If its revision ≥ ours, unlocking it costs one touch.
  Compare heads:
  - same head: in sync;
  - their head is in our `ancestors`: they are stale, so offer "update backup";
  - our head is in their `ancestors`: we are stale, so adopt theirs;
  - otherwise they have **diverged**: merge.
- **Merge**: union of entries by `id`. For the same id, the higher `updated_at`
  wins; on a tie, the lexicographically greater TLV encoding wins
  (deterministic). Tombstones take part like entries, so deletions propagate.
  `known_keys` are unioned by serial, keeping the record with the greater
  `added_at`. The new head's `ancestors` start with both old heads. Tombstones
  older than 365 days are pruned on save.
- `last_synced_rev` is updated for each card written in the session. The UI
  shows backup keys that are more than N revisions behind.

## 10. Favicon cache

```
fk      = HKDF-SHA256(salt = "99p/v1/favicons", ikm = vault_secret, info = "")
k_name  = HKDF-Expand(fk, "name", 32);  k_enc = HKDF-Expand(fk, "enc", 32)
file    = ~/Library/Caches/app.99passwords/favicons/hex(HMAC-SHA256(k_name, host))[0..32]
content = nonce(12) || ChaCha20-Poly1305(k_enc, nonce, png, AAD = filename)
```

Only 32×32 PNGs (≤ 8 KiB) are accepted. The app checks the PNG signature and
IHDR size before caching. The cache directory is 0700. A locked or foreign
cache reveals no domain names. It does reveal how many sites have icons and
when they were written, which is acceptable.

## 11. FFI (plain C ABI)

- Header: `crates/ffi/include/ykvault.h` (hand-written, draft). Opaque
  `YkvSession*`; every call returns `YkvStatus`; outputs are `YkvBuf`, owned by
  Rust and freed with `ykv_buf_free` (which zeroizes).
- Every entry point wraps its body in `catch_unwind` and returns
  `YKV_ERR_PANIC` instead of unwinding into Swift. Release builds use
  `panic = "abort"`, so this is defence in depth.
- Structured, non-secret data (entry lists, capacity, card list) is returned as
  JSON written by a ~100-line encoder in the FFI crate (no serde). Secrets are
  only returned one at a time (`ykv_reveal_field`, `ykv_totp_now`), so the app
  never holds the whole decrypted vault.
- Blocking calls (unlock waits for a touch, saves take about 1 s of APDUs) are
  made by the app on a background queue. A session is not thread-safe; the app
  serialises access.
- Removal events: `ykv_set_removal_callback(fn(void *ctx, const char *reader))`
  locks the session before it calls back.
- `ykv_set_touch_callback` fires inside `ykv_unlock` after the PIN check, right before the ECDH that waits for a touch, so the UI can
  prompt at the right moment. `ykv_unlock` returns `YKV_ERR_WRONG_PIN` for a
  wrong passphrase and `YKV_ERR_PIN_BLOCKED` once tries run out;
  `ykv_pin_tries` reads the count without using one. `ykv_provision` creates a vault (§8.1) and returns an unlocked
  session. `ykv_mock_enable` / `ykv_mock_set_present` drive in-memory cards
  for development and UI tests; they never touch real hardware.

### 11.3 Entry JSON (`ykv_upsert_entry`)

```
{"id":"123" (optional; absent or null creates a new entry),
 "kind":1, "name":"GitHub", "hosts":["github.com"],
 "fields":[{"kind":1,"value":"octocat"},
           {"kind":2,"value":"secret"},
           {"kind":3,"value":"JBSWY3DPEHPK3PXP"},
           {"kind":16,"label":"Recovery email","value":"a@b.c"}]}
```

`kind` values are §6.4's numbers (decimal in JSON). The id is a decimal
string because it is a full u64. Hosts are lowercased and deduplicated. A
TOTP value is a base32 secret with default parameters (SHA-1, 6 digits,
30 s). The fields array replaces the entry's fields, so the app reveals
the old values before editing. Username, CardHolder, CardExpiry and
CustomText are not secret and appear in `ykv_list_entries`; every other
kind only through `ykv_reveal_field`.

## 12. Browser bridge

### 12.1 Topology

```
Chrome MV3 extension --native messaging--> ykvault-bridge --Unix socket--> menu bar app
   (service worker)      (stdin/stdout)    (.app/Contents/MacOS/)         (owns the session)
```

- Native host name `app.99passwords.bridge`. Manifest at
  `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/app.99passwords.bridge.json`,
  with `path` pointing into the app bundle and `allowed_origins` set to the
  extension id. It contains no secrets, and the app rewrites it at launch if
  the bundle moved.
- Socket: `~/Library/Application Support/99Passwords/bridge.sock`; directory
  0700, socket 0600. The app checks the peer with `LOCAL_PEERCRED` (same uid)
  and `LOCAL_PEERPID` plus `SecCodeCheckValidity` against the bridge's
  designated requirement (same team id). The bridge checks the app the same
  way. (Prototype: both sides check the uid only, with `getpeereid` /
  `LOCAL_PEERCRED`; the code-signature check is added once the app is signed.)
  If the socket is absent, the bridge runs `open -b <bundle id> --args
  --background` and retries for 5 s.
- Framing on both legs: u32 length (native-endian for Chrome, little-endian on
  the socket) followed by UTF-8 JSON. Maximum message 64 KiB (Chrome allows
  1 MiB to the host).

### 12.2 Messages (`"v": 1` on every message)

Bridge to app, first message on every connection:
- `{"type":"bridge_hello","bridge_version":"…","caller_origin":"chrome-extension://<id>/"}`.
  The app drops the connection if the id is not one it allows.

Extension to app:
- `{"type":"cancel","req_id":"r1"}` when the extension gives up (3 min timeout).
- `{"type":"hello","ext_version":"1.0.0"}` → `{"type":"hello","app_version":"…","locked":true}`
- `{"type":"fill_request","req_id":"r1","mode":"login"|"signup"|"totp"|"identity","host":"github.com","origin":"https://github.com","username":"optional","favicon_png":"base64, optional"}`
  - `host` and `origin` are taken by the **service worker** from
    `sender.tab.url` / `sender.origin`, never from page script. The app
    normalises the host again and displays it.
  - App reply: `{"type":"fill","req_id":"r1","host":"github.com","username":"…","password":"…","totp":"123456"}`,
    `{"type":"cancel","req_id":"r1"}` or `{"type":"error","req_id":"r1","code":"locked"}`.
  - For `signup`, the app shows Create Login with the generator; "Fill & Save"
    saves to the card **before** replying with `fill`. Regenerating updates the
    same entry id.
  - `identity` is sent for forms with two or more name, email, phone or address
    fields and no password or code field. The app lists Identity entries and
    replies `{"type":"fill",…,"identity":{"first_name","last_name","email","phone","street","city","postcode","region","country"}}`
    (present keys only). The page fills empty fields by `autocomplete` token,
    then by name/id/placeholder/label hints.
- `{"type":"has_match","req_id":"m1","host":"github.com"}` →
  `{"type":"has_match","req_id":"m1","match":true,"locked":false,"logins":[{"id":"7","name":"GitHub","username":"alice"}]}`.
  Drives the red dot on the toolbar icon and the dropdown under a login
  field. `logins` are the host's login entries (same rule as the panel's
  suggestions, at most 20) with name and username only, never a secret.
  While the vault is locked, `match` is false and `logins` is empty.
- `fill_request` may carry `"entry_id":"7"`, the login picked in that
  dropdown. If the vault is unlocked and that entry matches the host, the app
  fills it without showing the panel; otherwise it shows the panel as usual.
- Clicking the 99passwords icon in a field opens a menu: the site's logins,
  then "Generate a strong password", "Save new login" and "Open 99passwords".
  "Save new login" sends a `signup` request with `"password"` set to what the
  user typed in the page (the only case where the extension sends a password
  to the app); Create Login then uses it instead of a generated one.
- A new login's default name is the site's main domain without the TLD,
  capitalised: `github.com` → "Github", `app.example.co.uk` → "Example".
- Signup or login: the extension scores the page (new-password or
  current-password autocomplete, number of password fields, button and
  heading words like "Sign up"/"Create account" vs "Log in"/"Sign in", the URL
  path, and name, birthday or terms fields). When the score is in between, the
  dropdown offers both the saved logins and "Generate a strong password".
- The bridge answers `{"type":"error","code":"app_unavailable"|"app_untrusted"}`
  (no `req_id`) if it cannot reach or trust the app.
- The extension fills only into the top frame, and only if its origin still
  matches `origin` after the panel closes (cross-origin iframes are not
  filled in v1), then
  drops its references. It never stores credentials and has no popup.
  Permissions: `nativeMessaging`, `activeTab`, `scripting`, `storage`
  (settings only), `commands` and `favicon` (the 32×32 icon comes from
  Chrome's local favicon cache, never from the network). Chrome commands cannot
  bind `\`, so the command defaults to Cmd+Shift+L; Cmd+\ works inside pages
  through the content script. The inline field icon, the fill and "generate a
  password" offers, and the toolbar dot need a content script and the tab URL
  on every site, so the extension asks for `<all_urls>` at install. The
  content script never receives credentials; clicking it asks the service
  worker to start a normal fill.

## 13. Export / import

### 13.1 `.ykv` (encrypted)

```
"99PX" | container_v u16 = 1 | flags u8 | reserved u8 | vault_uuid[16] | revision u64
| kdf_id u8 = 2 | reserved[11] | salt[16]
| recipient_count u8 | recipients[n] | payload_nonce[12] | ct_len u32 | ciphertext
recipient = type u8 (1 YubiKey, 2 recovery key) | id[8] | eph_pub[33] | wrap_nonce[12] | wrapped_dek[48]   (102 bytes)
```

- YubiKey recipient: as §5.2, with `id = card_fpr` and info
  `vault_uuid || id || eph_pub || revision`. Opening it verifies the PIN
  derived from the file's salt first (§5.3).
- Recovery-key recipient: `R = random(20)`, shown once as 8 groups of 4
  Crockford base32 characters plus one group of check characters
  (SHA-256(R)[0..2]); `id = SHA-256("99p/v1/rk-id" || R)[0..8]`; eph_pub is all
  zero; `KEK = HKDF(salt = "99p/v1/recovery", ikm = R || P, info = vault_uuid)`.
  **The recovery key also needs the passphrase** (two factors: paper plus
  memory). Without stretching, someone holding the file and this recovery
  key can guess the passphrase offline at full speed. (This file recovery
  key is separate from the YubiKey PIN; YubiKeys have no PUK.)
- AAD for each wrap: every byte before `recipients`, plus the recipient's
  first 54 bytes. Payload AAD: every byte before the ciphertext. The plaintext
  format is §6.1, without the 1 KiB padding requirement.
- Import of `.ykv`: unlock with a known card (touch) or a recovery key, then
  merge (§9.4) or replace.

### 13.2 Plaintext (behind a typed confirmation and a warning)

- CSV, Chrome-compatible: `name,url,username,password,note`, plus an optional
  `otpauth` column. Import also accepts the 1Password and Bitwarden CSV column
  names.
- JSON (own schema, `"format":"99p-v1"`), lossless.
  `{"format":"99p-v1","exported_at":n,"entries":[{"id":"<16 hex>","kind":"login|card|note|custom|identity",
  "name","hosts":[],"created_at","updated_at","deleted","fields":[{"kind":"username|password|totp|card_number|
  card_expiry|card_cvv|card_holder|pin|note|custom_text|custom_secret|first_name|last_name|email|phone|street|city|postcode|region|country","label"?,"value"|"value_b64"}],
  "extra":[{"tag","value_b64"}]}]}`. TOTP fields carry the packed bytes (§6.4) in `value_b64` plus an
  informational `otpauth` URI. Known keys and settings are not exported. Import keeps entry ids.
- CSV export covers live logins only (lossy); app links (`androidapp://`) become a `URL` custom field.
- Written by a small encoder in the core (no serde). Files are created 0600,
  and the UI recommends deleting them afterwards.

## 14. Threat model (summary)

| Attacker | Gets | Does not get |
|---|---|---|
| Steals the Mac, no YubiKey | favicon cache (opaque), prefs | anything in the vault |
| Malware on the Mac, key plugged in, vault locked | **the ciphertext** (PIV data objects are readable without PIN) | `Z`: ECDH needs the PIN and a touch |
| Same, vault unlocked | process memory, so everything (same-user code execution is out of scope); clipboard | |
| Steals the YubiKey | ciphertext, unlimited touches, **255 passphrase guesses** checked by the card, then the vault on it is gone | `Z` for any guess the card refuses, so no offline guessing |
| Extracts the key from the chip (lab attack, firmware bug) | `Z`, then offline guessing at SHA-256 speed | nothing, if the passphrase is weak |
| Network | nothing; the core has no network code | |

1. **The PIN turns passphrase guessing into an online attack.** In earlier
   builds slot 0x82 had PIN policy NEVER, so one touch gave `Z` for the current
   bank and every guess after that ran offline (ECDH is linear, so no public
   tweak to `E` can force one touch per guess). Now the PIN is derived from
   the passphrase and the key has PIN policy ALWAYS, so each guess must be
   checked by the card, which blocks after 255 wrong ones. The touch still
   defends against remote attackers, who can now neither touch nor know the
   PIN.
2. **No PUK, no Argon2.** The PUK is blocked at provisioning, so nobody,
   the owner included, can reset the PIN: the 255th wrong passphrase makes
   the vault on that card unreadable for good (the app shows the count once
   10 have been used). Backup keys and `.ykv` exports are the only recovery.
   With guessing capped at 255 by the card, Argon2 was dropped (§5.1). The
   cost: if the card's secret is ever extracted from the chip, the
   passphrase is all that remains and it can be guessed fast.
3. `P` stays in the KEK (`HKDF(Z || P)`, unchanged): it costs nothing, keeps
   the bank and `.ykv` formats stable, and means `Z` alone does not open
   the vault.
4. **Denial of service**: anyone holding the card can make 255 wrong guesses,
   which blocks the PIN, and reset the PIV application, which destroys the
   vault. Mitigation: synced backup keys and `.ykv` exports.
5. Writing objects needs the management key, which only exists inside the
   vault. So without a prior unlock, malware cannot overwrite the vault with
   chosen content. It could delete objects only by resetting PIV (point 4).
6. Malware that watches the PC/SC traffic during an unlock sees the derived
   PIN. That gives it future ECDH (with a touch), but not `P`, since the PIN
   is one-way from `P` and `P` is never sent to the card.
7. Phishing: the host shown in the panel comes from the browser's tab URL
   through the service worker, and entries match only exact hosts or parent
   domains (§6.6).
8. Clipboard: copies are marked `org.nspasteboard.ConcealedType` and
   `TransientType`, and cleared after `clipboard_clear_secs` if `changeCount`
   has not changed.

## 15. To verify on a physical YubiKey (phase 3)

1. Largest value accepted in tag `53` for a custom data object (expected
   3,052; yb reports 3,063).
2. NVM left for the vault given the attestation certificate and the user's
   other certificates. Report free space via a probe write of the largest
   object if needed.
3. Tearing: pull the key during a chained PUT DATA (about 100 trials) and
   record whether the object ends up old, new, missing or partial. The design
   is safe either way; this only checks the assumption.
4. Touch timeout duration and status word for ECDH; whether a touch-cached
   policy is offered on the firmware (we use ALWAYS).
5. Management key default and algorithm on fw 5.7 (AES-192) versus 5.4 to 5.6
   (3DES), and metadata `05` default flag.
6. SET PIN RETRIES 255 / 1 and blocking the PUK with one wrong try, then
   VERIFY and ECDH with PIN policy ALWAYS (fw 5.7.4).
7. Speed of a full 24 KB save (8 chained PUT DATA plus read-back) and of an
   unlock including the touch.
