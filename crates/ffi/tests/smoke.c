/* Checks that ykvault.h matches the Rust staticlib: compiled and run in CI. */
#include <stdio.h>
#include <string.h>
#include "ykvault.h"

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, #x); return 1; } } while (0)

static int touches = 0;
static void on_touch(void *ctx) { (void)ctx; touches++; }

int main(void) {
  YkvBuf b = {0};
  CHECK(ykv_mock_enable(1, 1, 0) == YKV_OK);
  CHECK(ykv_list_cards(&b) == YKV_OK);
  CHECK(strstr((char *)b.ptr, "\"has_vault\":true") != NULL);
  ykv_buf_free(b);

  YkvSession *s = NULL;
  CHECK(ykv_open("mock:0", &s) == YKV_OK);
  ykv_set_touch_callback(s, on_touch, NULL);
  const char *pass = "correct horse battery staple";
  CHECK(ykv_unlock(s, (const uint8_t *)pass, strlen(pass)) == YKV_OK);
  CHECK(touches == 1 && ykv_is_unlocked(s));

  const char *entry = "{\"kind\":1,\"name\":\"C\",\"hosts\":[\"c.example\"],"
                      "\"fields\":[{\"kind\":2,\"value\":\"pw\"}]}";
  uint64_t id = 0;
  CHECK(ykv_upsert_entry(s, (const uint8_t *)entry, strlen(entry), &id) == YKV_OK);
  CHECK(ykv_reveal_field(s, id, 0, &b) == YKV_OK);
  CHECK(b.len == 2 && memcmp(b.ptr, "pw", 2) == 0);
  ykv_buf_free(b);

  /* Backup key, sync, .ykv and plaintext round trips. */
  CHECK(ykv_mock_enable(1, 0, 0) == YKV_OK);
  CHECK(ykv_clone_to(s, "mock:1", "Backup") == YKV_OK);
  CHECK(ykv_known_keys(s, &b) == YKV_OK);
  CHECK(strstr((char *)b.ptr, "\"label\":\"Backup\"") != NULL);
  ykv_buf_free(b);
  uint32_t rel = 9;
  CHECK(ykv_sync_with(s, "mock:1", &rel) == YKV_OK && rel == 0);
  YkvBuf file = {0}, rk = {0};
  CHECK(ykv_export_ykv(s, 1, &file, &rk) == YKV_OK && rk.len > 0);
  char rks[128] = {0};
  memcpy(rks, rk.ptr, rk.len < 127 ? rk.len : 127);
  uint32_t count = 0;
  CHECK(ykv_import_ykv(s, file.ptr, file.len, (const uint8_t *)pass, strlen(pass), rks, &count) == YKV_OK);
  CHECK(count == 5);
  ykv_buf_free(file);
  ykv_buf_free(rk);
  CHECK(ykv_export_plain(s, 1, &b) == YKV_OK);
  YkvBuf res = {0};
  CHECK(ykv_import_plain(s, b.ptr, b.len, &res) == YKV_OK);
  CHECK(strstr((char *)res.ptr, "\"imported\":5") != NULL);
  ykv_buf_free(res);
  ykv_buf_free(b);

  CHECK(ykv_gen_passphrase(6, '-', &b) == YKV_OK);
  ykv_buf_free(b);
  CHECK(ykv_mock_set_present("mock:0", 0) == YKV_OK);
  CHECK(!ykv_is_unlocked(s));
  ykv_close(s);
  puts("ffi smoke ok");
  return 0;
}
