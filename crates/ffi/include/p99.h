/* p99.h: C ABI between p99-ffi (Rust) and the macOS app (Swift).
 * The contract; see docs/SPEC.md section 11. Hand-written (no cbindgen,
 * to keep syn/proc-macros out of the build). */
#ifndef P99_H
#define P99_H
#include <stdint.h>
#include <stddef.h>

typedef struct P99Session P99Session;          /* opaque */

typedef struct { uint8_t *ptr; size_t len; } P99Buf;  /* Rust-owned */

typedef enum {
  P99_OK = 0, P99_ERR_CARD_REMOVED = 1, P99_ERR_CARD = 2, P99_ERR_NOT_FOUND = 3,
  P99_ERR_CAPACITY = 4, P99_ERR_MGMT_KEY = 5, P99_ERR_DECRYPT = 6,
  P99_ERR_NO_VAULT = 7, P99_ERR_FORMAT = 8, P99_ERR_UNSUPPORTED = 9,
  P99_ERR_INVALID = 10, P99_ERR_RNG = 11, P99_ERR_LOCKED = 12,
  P99_ERR_TOUCH_TIMEOUT = 13, P99_ERR_WRONG_PIN = 14, P99_ERR_PIN_BLOCKED = 15,
  P99_ERR_PANIC = 255
} P99Status;

/* Zeroizes then frees. Safe on {NULL,0}. */
void p99_buf_free(P99Buf buf);
/* Text of the most recent error (free with p99_buf_free). */
void p99_last_error(P99Buf *out);

/* JSON array of readers: [{"id":"...","serial":123,"has_vault":true,"mock":false}] */
P99Status p99_list_cards(P99Buf *out_json);

/* Opens the card; no touch, no passphrase. */
P99Status p99_open(const char *reader_id, P99Session **out);
void      p99_close(P99Session *s);          /* locks + zeroizes + frees */

/* New vault on a card without one (SPEC 8.1). Returns an unlocked session.
 * label may be NULL. P99_ERR_MGMT_KEY: non-default management key. */
P99Status p99_provision(const char *reader_id, const uint8_t *pass, size_t pass_len,
                        const char *label, P99Session **out);

/* Blocks until touch or timeout. passphrase: NFC-normalised UTF-8.
 * P99_ERR_WRONG_PIN: wrong passphrase (refused by the card, before the touch;
 * see p99_pin_tries). P99_ERR_PIN_BLOCKED: 255 wrong passphrases; the vault
 * on this card is gone for good. */
P99Status p99_unlock(P99Session *s, const uint8_t *pass, size_t pass_len);
/* PIN tries left on the card (255 when fresh). Costs no try. */
P99Status p99_pin_tries(P99Session *s, uint32_t *out_left);
void      p99_lock(P99Session *s);
_Bool     p99_is_unlocked(P99Session *s);

/* Called from inside p99_unlock (its thread) once the PIN is accepted, just
 * before the card waits for a touch, so the UI can say "Touch your YubiKey". */
typedef void (*P99TouchFn)(void *ctx);
void p99_set_touch_callback(P99Session *s, P99TouchFn fn, void *ctx);

/* Non-secret listing: [{"id":"..","kind":1,"name":"..","hosts":[..],
 *   "username":"..","has_totp":true,"updated_at":0,"rank":0,
 *   "fields":[{"kind":2,"secret":true,"label":null,"value":null}]}].
 *   Secret field values are always null here. Filtered by host if
 *   host != NULL (exact + parent-domain matches, ranked). */
P99Status p99_list_entries(P99Session *s, const char *host, P99Buf *out_json);

/* Single secret value on demand. field_index is the position in fields[].
 * A TOTP field is revealed as its base32 secret (for editing). */
P99Status p99_reveal_field(P99Session *s, uint64_t entry_id, uint32_t field_index,
                           P99Buf *out);
P99Status p99_totp_now(P99Session *s, uint64_t entry_id, uint64_t unix_time,
                       P99Buf *out_code, uint32_t *out_seconds_left);

/* Entry JSON as in SPEC 11.3, secrets included. Writes to the card; no touch. */
P99Status p99_upsert_entry(P99Session *s, const uint8_t *json, size_t len,
                           uint64_t *out_id);
P99Status p99_delete_entry(P99Session *s, uint64_t entry_id);

/* Called from the PC/SC watcher thread after the session was locked. */
typedef void (*P99RemovalFn)(void *ctx, const char *reader_id);
void p99_set_removal_callback(P99Session *s, P99RemovalFn fn, void *ctx);

/* {"used":12288,"capacity":23552,"mode":"ab","revision":42,"updated_at":1764250000}
 * updated_at: unix seconds of the last change to the vault content. */
P99Status p99_capacity(P99Session *s, P99Buf *out_json);

/* Backup keys (SPEC 9.4). Every multi-APDU call holds one PC/SC transaction
 * on each card it uses.
 * {"revision":42,"keys":[{"serial":123,"label":"..","last_synced_rev":42,
 *   "added_at":0,"this":true}]}  A key with last_synced_rev < revision is behind. */
P99Status p99_known_keys(P99Session *s, P99Buf *out_json);

/* Turns the YubiKey in backup_reader (no vault on it yet) into a clone of
 * this vault. No touch. label may be NULL. P99_ERR_MGMT_KEY: custom key. */
P99Status p99_clone_to(P99Session *s, const char *backup_reader, const char *label);

/* Reconciles with another YubiKey holding this vault (one touch on it).
 * out_relation: 0 already in sync, 1 the other key was updated,
 * 2 this key was updated from it, 3 both had changes and were merged. */
P99Status p99_sync_with(P99Session *s, const char *other_reader, uint32_t *out_relation);

/* Encrypted .99p backup (SPEC 13.1), readable by every known YubiKey plus the
 * passphrase. with_recovery_key also wraps it to a new printable recovery key,
 * returned once in out_recovery ({NULL,0} otherwise). */
P99Status p99_export_backup(P99Session *s, _Bool with_recovery_key, P99Buf *out_file,
                         P99Buf *out_recovery);

/* Merges a .99p into this vault and saves. pass: the passphrase at export
 * time. recovery_key NULL: decrypt with this YubiKey (one touch).
 * out_count: items in the file. */
P99Status p99_import_backup(P99Session *s, const uint8_t *file, size_t len,
                         const uint8_t *pass, size_t pass_len,
                         const char *recovery_key, uint32_t *out_count);

/* Plaintext export, secrets in the clear. format 0: CSV (logins only, for
 * Chrome/1Password/Bitwarden), 1: lossless 99p-v1 JSON. */
P99Status p99_export_plain(P99Session *s, uint32_t format, P99Buf *out);

/* Plaintext import (99p-v1 JSON or CSV, detected) in one save.
 * {"imported":12,"skipped":[{"line":4,"reason":".."}]} */
P99Status p99_import_plain(P99Session *s, const uint8_t *data, size_t len, P99Buf *out_json);

/* Generators (no session needed). class_flags: 1 lower, 2 upper, 4 digits,
 * 8 symbols, 16 avoid ambiguous characters. length 4..128, words 3..20. */
P99Status p99_gen_password(uint32_t length, uint32_t class_flags, P99Buf *out);
P99Status p99_gen_passphrase(uint32_t words, uint8_t separator, P99Buf *out);

/* Favicon cache keys: name = HMAC filename (hex), enc/dec of PNG blobs. */
P99Status p99_favicon_name(P99Session *s, const char *host, P99Buf *out_hex);
P99Status p99_favicon_seal(P99Session *s, const char *host, const uint8_t *png,
                           size_t len, P99Buf *out);
P99Status p99_favicon_open(P99Session *s, const char *host, const uint8_t *blob,
                           size_t len, P99Buf *out_png);

/* Development only: in-memory YubiKeys (the core's MockYubiKey, full PIV
 * emulation) listed by p99_list_cards as
 * "mock:N". flags bit0 seeds the first new card with a demo vault
 * (passphrase "correct horse battery staple"). touch_ms simulates the touch.
 * p99_mock_set_present(.., false) behaves like pulling the key. */
P99Status p99_mock_enable(uint32_t cards, uint32_t flags, uint32_t touch_ms);
P99Status p99_mock_set_present(const char *reader_id, _Bool present);

#endif
