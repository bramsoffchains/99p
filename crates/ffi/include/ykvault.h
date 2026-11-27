/* ykvault.h: C ABI between ykvault-ffi (Rust) and the macOS app (Swift).
 * The contract; see docs/SPEC.md section 11. Hand-written (no cbindgen,
 * to keep syn/proc-macros out of the build). */
#ifndef YKVAULT_H
#define YKVAULT_H
#include <stdint.h>
#include <stddef.h>

typedef struct YkvSession YkvSession;          /* opaque */

typedef struct { uint8_t *ptr; size_t len; } YkvBuf;  /* Rust-owned */

typedef enum {
  YKV_OK = 0, YKV_ERR_CARD_REMOVED = 1, YKV_ERR_CARD = 2, YKV_ERR_NOT_FOUND = 3,
  YKV_ERR_CAPACITY = 4, YKV_ERR_MGMT_KEY = 5, YKV_ERR_DECRYPT = 6,
  YKV_ERR_NO_VAULT = 7, YKV_ERR_FORMAT = 8, YKV_ERR_UNSUPPORTED = 9,
  YKV_ERR_INVALID = 10, YKV_ERR_RNG = 11, YKV_ERR_LOCKED = 12,
  YKV_ERR_TOUCH_TIMEOUT = 13, YKV_ERR_WRONG_PIN = 14, YKV_ERR_PIN_BLOCKED = 15,
  YKV_ERR_PANIC = 255
} YkvStatus;

/* Zeroizes then frees. Safe on {NULL,0}. */
void ykv_buf_free(YkvBuf buf);
/* Text of the most recent error (free with ykv_buf_free). */
void ykv_last_error(YkvBuf *out);

/* JSON array of readers: [{"id":"...","serial":123,"has_vault":true,"mock":false}] */
YkvStatus ykv_list_cards(YkvBuf *out_json);

/* Opens the card; no touch, no passphrase. */
YkvStatus ykv_open(const char *reader_id, YkvSession **out);
void      ykv_close(YkvSession *s);          /* locks + zeroizes + frees */

/* New vault on a card without one (SPEC 8.1). Returns an unlocked session.
 * label may be NULL. YKV_ERR_MGMT_KEY: non-default management key. */
YkvStatus ykv_provision(const char *reader_id, const uint8_t *pass, size_t pass_len,
                        const char *label, YkvSession **out);

/* Blocks until touch or timeout. passphrase: NFC-normalised UTF-8.
 * YKV_ERR_WRONG_PIN: wrong passphrase (refused by the card, before the touch;
 * see ykv_pin_tries). YKV_ERR_PIN_BLOCKED: 255 wrong passphrases; the vault
 * on this card is gone for good. */
YkvStatus ykv_unlock(YkvSession *s, const uint8_t *pass, size_t pass_len);
/* PIN tries left on the card (255 when fresh). Costs no try. */
YkvStatus ykv_pin_tries(YkvSession *s, uint32_t *out_left);
void      ykv_lock(YkvSession *s);
_Bool     ykv_is_unlocked(YkvSession *s);

/* Called from inside ykv_unlock (its thread) once the PIN is accepted, just
 * before the card waits for a touch, so the UI can say "Touch your YubiKey". */
typedef void (*YkvTouchFn)(void *ctx);
void ykv_set_touch_callback(YkvSession *s, YkvTouchFn fn, void *ctx);

/* Non-secret listing: [{"id":"..","kind":1,"name":"..","hosts":[..],
 *   "username":"..","has_totp":true,"updated_at":0,"rank":0,
 *   "fields":[{"kind":2,"secret":true,"label":null,"value":null}]}].
 *   Secret field values are always null here. Filtered by host if
 *   host != NULL (exact + parent-domain matches, ranked). */
YkvStatus ykv_list_entries(YkvSession *s, const char *host, YkvBuf *out_json);

/* Single secret value on demand. field_index is the position in fields[].
 * A TOTP field is revealed as its base32 secret (for editing). */
YkvStatus ykv_reveal_field(YkvSession *s, uint64_t entry_id, uint32_t field_index,
                           YkvBuf *out);
YkvStatus ykv_totp_now(YkvSession *s, uint64_t entry_id, uint64_t unix_time,
                       YkvBuf *out_code, uint32_t *out_seconds_left);

/* Entry JSON as in SPEC 11.3, secrets included. Writes to the card; no touch. */
YkvStatus ykv_upsert_entry(YkvSession *s, const uint8_t *json, size_t len,
                           uint64_t *out_id);
YkvStatus ykv_delete_entry(YkvSession *s, uint64_t entry_id);

/* Called from the PC/SC watcher thread after the session was locked. */
typedef void (*YkvRemovalFn)(void *ctx, const char *reader_id);
void ykv_set_removal_callback(YkvSession *s, YkvRemovalFn fn, void *ctx);

/* {"used":12288,"capacity":23552,"mode":"ab","revision":42,"updated_at":1764250000}
 * updated_at: unix seconds of the last change to the vault content. */
YkvStatus ykv_capacity(YkvSession *s, YkvBuf *out_json);

/* Backup keys (SPEC 9.4). Every multi-APDU call holds one PC/SC transaction
 * on each card it uses.
 * {"revision":42,"keys":[{"serial":123,"label":"..","last_synced_rev":42,
 *   "added_at":0,"this":true}]}  A key with last_synced_rev < revision is behind. */
YkvStatus ykv_known_keys(YkvSession *s, YkvBuf *out_json);

/* Turns the YubiKey in backup_reader (no vault on it yet) into a clone of
 * this vault. No touch. label may be NULL. YKV_ERR_MGMT_KEY: custom key. */
YkvStatus ykv_clone_to(YkvSession *s, const char *backup_reader, const char *label);

/* Reconciles with another YubiKey holding this vault (one touch on it).
 * out_relation: 0 already in sync, 1 the other key was updated,
 * 2 this key was updated from it, 3 both had changes and were merged. */
YkvStatus ykv_sync_with(YkvSession *s, const char *other_reader, uint32_t *out_relation);

/* Encrypted .ykv backup (SPEC 13.1), readable by every known YubiKey plus the
 * passphrase. with_recovery_key also wraps it to a new printable recovery key,
 * returned once in out_recovery ({NULL,0} otherwise). */
YkvStatus ykv_export_ykv(YkvSession *s, _Bool with_recovery_key, YkvBuf *out_file,
                         YkvBuf *out_recovery);

/* Merges a .ykv into this vault and saves. pass: the passphrase at export
 * time. recovery_key NULL: decrypt with this YubiKey (one touch).
 * out_count: items in the file. */
YkvStatus ykv_import_ykv(YkvSession *s, const uint8_t *file, size_t len,
                         const uint8_t *pass, size_t pass_len,
                         const char *recovery_key, uint32_t *out_count);

/* Plaintext export, secrets in the clear. format 0: CSV (logins only, for
 * Chrome/1Password/Bitwarden), 1: lossless 99p-v1 JSON. */
YkvStatus ykv_export_plain(YkvSession *s, uint32_t format, YkvBuf *out);

/* Plaintext import (99p-v1 JSON or CSV, detected) in one save.
 * {"imported":12,"skipped":[{"line":4,"reason":".."}]} */
YkvStatus ykv_import_plain(YkvSession *s, const uint8_t *data, size_t len, YkvBuf *out_json);

/* Generators (no session needed). class_flags: 1 lower, 2 upper, 4 digits,
 * 8 symbols, 16 avoid ambiguous characters. length 4..128, words 3..20. */
YkvStatus ykv_gen_password(uint32_t length, uint32_t class_flags, YkvBuf *out);
YkvStatus ykv_gen_passphrase(uint32_t words, uint8_t separator, YkvBuf *out);

/* Favicon cache keys: name = HMAC filename (hex), enc/dec of PNG blobs. */
YkvStatus ykv_favicon_name(YkvSession *s, const char *host, YkvBuf *out_hex);
YkvStatus ykv_favicon_seal(YkvSession *s, const char *host, const uint8_t *png,
                           size_t len, YkvBuf *out);
YkvStatus ykv_favicon_open(YkvSession *s, const char *host, const uint8_t *blob,
                           size_t len, YkvBuf *out_png);

/* Development only: in-memory YubiKeys (the core's MockYubiKey, full PIV
 * emulation) listed by ykv_list_cards as
 * "mock:N". flags bit0 seeds the first new card with a demo vault
 * (passphrase "correct horse battery staple"). touch_ms simulates the touch.
 * ykv_mock_set_present(.., false) behaves like pulling the key. */
YkvStatus ykv_mock_enable(uint32_t cards, uint32_t flags, uint32_t touch_ms);
YkvStatus ykv_mock_set_present(const char *reader_id, _Bool present);

#endif
