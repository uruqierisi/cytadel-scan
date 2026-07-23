#include "cytadel/kb/kb.h"

#include <string.h>

#include "cytadel_test.h"

static void test_set_get_string(void) {
    cytadel_kb_t *kb = cytadel_kb_create();
    CYTADEL_ASSERT(kb != NULL);

    CYTADEL_ASSERT_EQ(cytadel_kb_set_str(kb, "Banner/22", "SSH-2.0-OpenSSH_9.6"), 0);

    cytadel_kb_value_t value;
    cytadel_kb_get_status_t status = cytadel_kb_get(kb, "Banner/22", &value);
    CYTADEL_ASSERT_EQ(status, CYTADEL_KB_GET_FOUND);
    CYTADEL_ASSERT_EQ(value.type, CYTADEL_KB_TYPE_STRING);
    CYTADEL_ASSERT_STREQ(value.v.str, "SSH-2.0-OpenSSH_9.6");
    CYTADEL_ASSERT_STREQ(cytadel_kb_get_str(kb, "Banner/22"), "SSH-2.0-OpenSSH_9.6");

    cytadel_kb_free(kb);
}

static void test_set_get_int(void) {
    cytadel_kb_t *kb = cytadel_kb_create();
    CYTADEL_ASSERT(kb != NULL);

    CYTADEL_ASSERT_EQ(cytadel_kb_set_int(kb, "Ports/tcp/443", 1), 0);

    cytadel_kb_value_t value;
    CYTADEL_ASSERT_EQ(cytadel_kb_get(kb, "Ports/tcp/443", &value), CYTADEL_KB_GET_FOUND);
    CYTADEL_ASSERT_EQ(value.type, CYTADEL_KB_TYPE_INT);
    CYTADEL_ASSERT_EQ(value.v.i64, 1);

    cytadel_kb_free(kb);
}

static void test_set_get_bool(void) {
    cytadel_kb_t *kb = cytadel_kb_create();
    CYTADEL_ASSERT(kb != NULL);

    CYTADEL_ASSERT_EQ(cytadel_kb_set_bool(kb, "TLS/443/enabled", true), 0);

    cytadel_kb_value_t value;
    CYTADEL_ASSERT_EQ(cytadel_kb_get(kb, "TLS/443/enabled", &value), CYTADEL_KB_GET_FOUND);
    CYTADEL_ASSERT_EQ(value.type, CYTADEL_KB_TYPE_BOOL);
    CYTADEL_ASSERT_EQ(value.v.b, true);

    /* Bool is never conflated with int (kb-schema.md §3): a bool-typed
     * entry must not be readable as CYTADEL_KB_TYPE_INT. */
    CYTADEL_ASSERT(value.type != CYTADEL_KB_TYPE_INT);

    cytadel_kb_free(kb);
}

static void test_absent_key_is_not_found(void) {
    cytadel_kb_t *kb = cytadel_kb_create();
    CYTADEL_ASSERT(kb != NULL);

    cytadel_kb_value_t value;
    memset(&value, 0xAA, sizeof(value)); /* poison to ensure it gets zeroed */
    CYTADEL_ASSERT_EQ(cytadel_kb_get(kb, "Host/hostname", &value), CYTADEL_KB_GET_NOT_FOUND);
    CYTADEL_ASSERT(cytadel_kb_get_str(kb, "Host/hostname") == NULL);

    cytadel_kb_free(kb);
}

static void test_overwrite_last_write_wins(void) {
    cytadel_kb_t *kb = cytadel_kb_create();
    CYTADEL_ASSERT(kb != NULL);

    CYTADEL_ASSERT_EQ(cytadel_kb_set_str(kb, "HTTP/80/server", "nginx/1.24.0"), 0);
    CYTADEL_ASSERT_EQ(cytadel_kb_set_str(kb, "HTTP/80/server", "Apache/2.4.58"), 0);
    CYTADEL_ASSERT_STREQ(cytadel_kb_get_str(kb, "HTTP/80/server"), "Apache/2.4.58");

    /* Overwriting a string key with a different type must also work (no
     * stale union member leaking through). */
    CYTADEL_ASSERT_EQ(cytadel_kb_set_int(kb, "HTTP/80/server", 42), 0);
    cytadel_kb_value_t value;
    CYTADEL_ASSERT_EQ(cytadel_kb_get(kb, "HTTP/80/server", &value), CYTADEL_KB_GET_FOUND);
    CYTADEL_ASSERT_EQ(value.type, CYTADEL_KB_TYPE_INT);
    CYTADEL_ASSERT_EQ(value.v.i64, 42);

    CYTADEL_ASSERT_EQ(cytadel_kb_count(kb), (size_t)1);

    cytadel_kb_free(kb);
}

static void test_key_validation_rejections(void) {
    cytadel_kb_t *kb = cytadel_kb_create();
    CYTADEL_ASSERT(kb != NULL);

    CYTADEL_ASSERT(!cytadel_kb_key_is_valid(NULL));
    CYTADEL_ASSERT(!cytadel_kb_key_is_valid(""));
    CYTADEL_ASSERT(!cytadel_kb_key_is_valid("/leading/slash"));
    CYTADEL_ASSERT(!cytadel_kb_key_is_valid("trailing/slash/"));
    CYTADEL_ASSERT(!cytadel_kb_key_is_valid("empty//segment"));
    CYTADEL_ASSERT(!cytadel_kb_key_is_valid("bad char"));       /* whitespace */
    CYTADEL_ASSERT(!cytadel_kb_key_is_valid("bad\tchar"));      /* control char */
    CYTADEL_ASSERT(!cytadel_kb_key_is_valid("bad$char"));       /* not in charset */
    CYTADEL_ASSERT(!cytadel_kb_key_is_valid("bad//"));

    CYTADEL_ASSERT(cytadel_kb_key_is_valid("Host/ip"));
    CYTADEL_ASSERT(cytadel_kb_key_is_valid("Services/www/8080"));
    CYTADEL_ASSERT(cytadel_kb_key_is_valid("HTTP/443/headers/x-frame-options"));
    CYTADEL_ASSERT(cytadel_kb_key_is_valid("A"));
    CYTADEL_ASSERT(cytadel_kb_key_is_valid("a.b-c_d"));

    /* Case sensitivity (kb-schema.md §2): "HTTP/80/server" and
     * "http/80/server" are different keys. */
    CYTADEL_ASSERT_EQ(cytadel_kb_set_str(kb, "HTTP/80/server", "nginx"), 0);
    CYTADEL_ASSERT(cytadel_kb_get_str(kb, "http/80/server") == NULL);

    /* Max key length is 255 bytes; 256 must be rejected, 255 must not. */
    char key_255[256];
    memset(key_255, 'a', sizeof(key_255) - 1);
    key_255[255] = '\0';
    CYTADEL_ASSERT(cytadel_kb_key_is_valid(key_255));
    CYTADEL_ASSERT_EQ(cytadel_kb_set_str(kb, key_255, "ok"), 0);

    char key_256[258];
    memset(key_256, 'a', 256);
    key_256[256] = '\0';
    CYTADEL_ASSERT(!cytadel_kb_key_is_valid(key_256));
    CYTADEL_ASSERT_EQ(cytadel_kb_set_str(kb, key_256, "should not be stored"), -1);
    /* Rejected, not truncated: no entry at all must be created. */
    CYTADEL_ASSERT(cytadel_kb_get_str(kb, key_256) == NULL);

    /* Invalid-key rejections apply uniformly to every setter. */
    CYTADEL_ASSERT_EQ(cytadel_kb_set_int(kb, "/bad", 1), -1);
    CYTADEL_ASSERT_EQ(cytadel_kb_set_bool(kb, "/bad", true), -1);

    cytadel_kb_get_status_t status = cytadel_kb_get(kb, "/bad", &(cytadel_kb_value_t){0});
    CYTADEL_ASSERT_EQ(status, CYTADEL_KB_GET_INVALID_KEY);

    cytadel_kb_free(kb);
}

static void test_value_rejections_are_not_truncated(void) {
    cytadel_kb_t *kb = cytadel_kb_create();
    CYTADEL_ASSERT(kb != NULL);

    /* Oversized string value (> CYTADEL_KB_VALUE_MAX_LEN) is rejected, not
     * truncated -- no entry created at all. */
    char *big = malloc(CYTADEL_KB_VALUE_MAX_LEN + 2);
    CYTADEL_ASSERT(big != NULL);
    memset(big, 'x', CYTADEL_KB_VALUE_MAX_LEN + 1);
    big[CYTADEL_KB_VALUE_MAX_LEN + 1] = '\0';
    CYTADEL_ASSERT_EQ(strlen(big), (size_t)(CYTADEL_KB_VALUE_MAX_LEN + 1));
    CYTADEL_ASSERT_EQ(cytadel_kb_set_str(kb, "Banner/9999", big), -1);
    CYTADEL_ASSERT(cytadel_kb_get_str(kb, "Banner/9999") == NULL);
    free(big);

    /* Exactly CYTADEL_KB_VALUE_MAX_LEN bytes is the boundary and must be
     * accepted. */
    char *max_ok = malloc(CYTADEL_KB_VALUE_MAX_LEN + 1);
    CYTADEL_ASSERT(max_ok != NULL);
    memset(max_ok, 'y', CYTADEL_KB_VALUE_MAX_LEN);
    max_ok[CYTADEL_KB_VALUE_MAX_LEN] = '\0';
    CYTADEL_ASSERT_EQ(cytadel_kb_set_str(kb, "Banner/9998", max_ok), 0);
    free(max_ok);

    /* Embedded NUL: only representable via the explicit-length entry
     * point (cytadel_kb_set_str_n), since a plain NUL-terminated
     * cytadel_kb_set_str() call cannot smuggle one through. Must be
     * rejected, not silently truncated at the embedded NUL. */
    char embedded[8] = {'a', 'b', '\0', 'c', 'd', '\0', '\0', '\0'};
    CYTADEL_ASSERT_EQ(cytadel_kb_set_str_n(kb, "Banner/7", embedded, 5), -1);
    CYTADEL_ASSERT(cytadel_kb_get_str(kb, "Banner/7") == NULL);

    /* Invalid UTF-8 (a lone continuation byte) is rejected. */
    char bad_utf8[3] = {(char)0x80, 'x', '\0'};
    CYTADEL_ASSERT_EQ(cytadel_kb_set_str(kb, "Banner/6", bad_utf8), -1);

    /* Valid multi-byte UTF-8 is accepted (e.g. "caf\xc3\xa9" = "café"). */
    CYTADEL_ASSERT_EQ(cytadel_kb_set_str(kb, "HTTP/80/title", "caf\xc3\xa9"), 0);
    CYTADEL_ASSERT_STREQ(cytadel_kb_get_str(kb, "HTTP/80/title"), "caf\xc3\xa9");

    /* NULL kb / NULL value are rejected, not crashes. */
    CYTADEL_ASSERT_EQ(cytadel_kb_set_str(NULL, "Banner/1", "x"), -1);
    CYTADEL_ASSERT_EQ(cytadel_kb_set_str(kb, "Banner/1", NULL), -1);

    cytadel_kb_free(kb);
}

typedef struct {
    size_t count;
    bool saw_host_ip;
    bool saw_port_state;
} foreach_ctx_t;

static void foreach_collect(const char *key, const cytadel_kb_value_t *value, void *user_data) {
    foreach_ctx_t *ctx = (foreach_ctx_t *)user_data;
    ctx->count++;
    if (strcmp(key, "Host/ip") == 0 && value->type == CYTADEL_KB_TYPE_STRING &&
        strcmp(value->v.str, "10.0.0.5") == 0) {
        ctx->saw_host_ip = true;
    }
    if (strcmp(key, "Ports/tcp/22") == 0 && value->type == CYTADEL_KB_TYPE_INT &&
        value->v.i64 == 1) {
        ctx->saw_port_state = true;
    }
}

static void test_enumeration(void) {
    cytadel_kb_t *kb = cytadel_kb_create();
    CYTADEL_ASSERT(kb != NULL);

    CYTADEL_ASSERT_EQ(cytadel_kb_set_str(kb, "Host/ip", "10.0.0.5"), 0);
    CYTADEL_ASSERT_EQ(cytadel_kb_set_str(kb, "Host/state", "up"), 0);
    CYTADEL_ASSERT_EQ(cytadel_kb_set_int(kb, "Ports/tcp/22", 1), 0);
    CYTADEL_ASSERT_EQ(cytadel_kb_set_bool(kb, "TLS/443/enabled", false), 0);

    CYTADEL_ASSERT_EQ(cytadel_kb_count(kb), (size_t)4);

    foreach_ctx_t ctx = {0};
    cytadel_kb_foreach(kb, foreach_collect, &ctx);
    CYTADEL_ASSERT_EQ(ctx.count, (size_t)4);
    CYTADEL_ASSERT(ctx.saw_host_ip);
    CYTADEL_ASSERT(ctx.saw_port_state);

    cytadel_kb_free(kb);
}

static void test_many_keys_growth_and_free(void) {
    /* Exercises the hash table's growth path (initial capacity is 64
     * buckets) and gives ASan/Valgrind a large number of allocations to
     * verify are all released by cytadel_kb_free(). */
    cytadel_kb_t *kb = cytadel_kb_create();
    CYTADEL_ASSERT(kb != NULL);

    for (int i = 0; i < 500; i++) {
        char key[64];
        snprintf(key, sizeof(key), "Ports/tcp/%d", i + 1);
        CYTADEL_ASSERT_EQ(cytadel_kb_set_int(kb, key, 1), 0);
    }
    CYTADEL_ASSERT_EQ(cytadel_kb_count(kb), (size_t)500);

    char probe_key[64];
    snprintf(probe_key, sizeof(probe_key), "Ports/tcp/%d", 250);
    cytadel_kb_value_t value;
    CYTADEL_ASSERT_EQ(cytadel_kb_get(kb, probe_key, &value), CYTADEL_KB_GET_FOUND);
    CYTADEL_ASSERT_EQ(value.v.i64, 1);

    cytadel_kb_free(kb);
}

static void test_free_null_is_safe(void) {
    cytadel_kb_free(NULL); /* must not crash */
}

int main(void) {
    test_set_get_string();
    test_set_get_int();
    test_set_get_bool();
    test_absent_key_is_not_found();
    test_overwrite_last_write_wins();
    test_key_validation_rejections();
    test_value_rejections_are_not_truncated();
    test_enumeration();
    test_many_keys_growth_and_free();
    test_free_null_is_safe();

    CYTADEL_TEST_PASS();
}
