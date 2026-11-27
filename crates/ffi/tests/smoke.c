/* Checks that p99.h matches the Rust staticlib: compiled and run in CI. */
#include <stdio.h>
#include <string.h>
#include "p99.h"

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, #x); return 1; } } while (0)

static int touches = 0;
static void on_touch(void *ctx) { (void)ctx; touches++; }

int main(void) {
  P99Buf b = {0};
  CHECK(p99_mock_enable(1, 1, 0) == P99_OK);
  CHECK(p99_list_cards(&b) == P99_OK);
  CHECK(strstr((char *)b.ptr, "\"has_vault\":true") != NULL);
  p99_buf_free(b);

  P99Session *s = NULL;
  CHECK(p99_open("mock:0", &s) == P99_OK);
  p99_set_touch_callback(s, on_touch, NULL);
  const char *pass = "correct horse battery staple";
  CHECK(p99_unlock(s, (const uint8_t *)pass, strlen(pass)) == P99_OK);
  CHECK(touches == 1 && p99_is_unlocked(s));

  const char *entry = "{\"kind\":1,\"name\":\"C\",\"hosts\":[\"c.example\"],"
                      "\"fields\":[{\"kind\":2,\"value\":\"pw\"}]}";
  uint64_t id = 0;
  CHECK(p99_upsert_entry(s, (const uint8_t *)entry, strlen(entry), &id) == P99_OK);
  CHECK(p99_reveal_field(s, id, 0, &b) == P99_OK);
  CHECK(b.len == 2 && memcmp(b.ptr, "pw", 2) == 0);
  p99_buf_free(b);

  /* Backup key, sync, .99p and plaintext round trips. */
  CHECK(p99_mock_enable(1, 0, 0) == P99_OK);
  CHECK(p99_clone_to(s, "mock:1", "Backup") == P99_OK);
  CHECK(p99_known_keys(s, &b) == P99_OK);
  CHECK(strstr((char *)b.ptr, "\"label\":\"Backup\"") != NULL);
  p99_buf_free(b);
  uint32_t rel = 9;
  CHECK(p99_sync_with(s, "mock:1", &rel) == P99_OK && rel == 0);
  P99Buf file = {0}, rk = {0};
  CHECK(p99_export_backup(s, 1, &file, &rk) == P99_OK && rk.len > 0);
  char rks[128] = {0};
  memcpy(rks, rk.ptr, rk.len < 127 ? rk.len : 127);
  uint32_t count = 0;
  CHECK(p99_import_backup(s, file.ptr, file.len, (const uint8_t *)pass, strlen(pass), rks, &count) == P99_OK);
  CHECK(count == 5);
  p99_buf_free(file);
  p99_buf_free(rk);
  CHECK(p99_export_plain(s, 1, &b) == P99_OK);
  P99Buf res = {0};
  CHECK(p99_import_plain(s, b.ptr, b.len, &res) == P99_OK);
  CHECK(strstr((char *)res.ptr, "\"imported\":5") != NULL);
  p99_buf_free(res);
  p99_buf_free(b);

  CHECK(p99_gen_passphrase(6, '-', &b) == P99_OK);
  p99_buf_free(b);
  CHECK(p99_mock_set_present("mock:0", 0) == P99_OK);
  CHECK(!p99_is_unlocked(s));
  p99_close(s);
  puts("ffi smoke ok");
  return 0;
}
