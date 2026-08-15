/* store_check.c — standalone check for the store layer (slice S2).
 *
 * Exercises, against a fresh tmp database: schema declaration (via
 * store_open), alias add/resolve with two destinations, alias remove,
 * revmap add/resolve round-trip, next_msgid monotonicity, and log append +
 * count.  Prints a PASS/FAIL line per check and returns 0 iff every check
 * passes. */
#include "visage.h"
#include "store.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures;

static void check(int cond, const char *what) {
    if (cond) {
        printf("PASS: %s\n", what);
    } else {
        printf("FAIL: %s\n", what);
        failures++;
    }
}

int main(void) {
    char tpl[] = "/tmp/visage_store_XXXXXX";
    char *dir = mkdtemp(tpl);
    Store *s;
    char **dests;
    size_t ndests;
    char *sender, *alias_addr;
    uint32_t m1, m2;

    if (!dir) {
        fprintf(stderr, "store_check: mkdtemp failed\n");
        return 1;
    }
    printf("store_check: db dir = %s\n", dir);

    s = store_open(dir);
    check(s != NULL, "store_open creates schema");
    if (!s) return 1;

    /* alias with two destinations (and an idempotent re-add). */
    check(store_alias_add(s, "jane@example.com", "jane@realmail.example") == VISAGE_OK,
          "alias_add dest1");
    check(store_alias_add(s, "jane@example.com", "bob@realmail.example") == VISAGE_OK,
          "alias_add dest2");
    check(store_alias_add(s, "jane@example.com", "jane@realmail.example") == VISAGE_OK,
          "alias_add dest1 again (idempotent)");

    dests = NULL;
    ndests = 0;
    check(store_resolve(s, "jane@example.com", &dests, &ndests) == VISAGE_OK,
          "resolve returns OK");
    check(ndests == 2, "resolve ndests == 2");
    if (ndests == 2) {
        int has_jane = 0, has_bob = 0;
        size_t i;
        for (i = 0; i < ndests; i++) {
            if (dests[i] && strcmp(dests[i], "jane@realmail.example") == 0)
                has_jane = 1;
            if (dests[i] && strcmp(dests[i], "bob@realmail.example") == 0)
                has_bob = 1;
        }
        check(has_jane && has_bob, "resolve returns both destinations");
    }
    store_free_strvec(dests, ndests);

    /* unknown alias resolves to zero destinations. */
    dests = NULL;
    ndests = 99;
    check(store_resolve(s, "nobody@example.com", &dests, &ndests) == VISAGE_OK,
          "resolve unknown alias returns OK");
    check(ndests == 0 && dests == NULL, "resolve unknown alias has 0 dests");

    /* alias remove drops exactly one destination. */
    check(store_alias_rm(s, "jane@example.com", "bob@realmail.example") == VISAGE_OK,
          "alias_rm dest2");
    dests = NULL;
    ndests = 0;
    check(store_resolve(s, "jane@example.com", &dests, &ndests) == VISAGE_OK,
          "resolve after rm returns OK");
    check(ndests == 1, "resolve after rm ndests == 1");
    if (ndests == 1) {
        check(dests && dests[0] && strcmp(dests[0], "jane@realmail.example") == 0,
              "resolve after rm keeps dest1");
    }
    store_free_strvec(dests, ndests);

    /* revmap round-trip. */
    check(store_revmap_add(s, "deadbeefcafe", "orig@foo.org", "jane@example.com")
              == VISAGE_OK,
          "revmap_add");
    sender = NULL;
    alias_addr = NULL;
    check(store_revmap_resolve(s, "deadbeefcafe", &sender, &alias_addr) == VISAGE_OK,
          "revmap_resolve returns OK");
    check(sender != NULL && strcmp(sender, "orig@foo.org") == 0,
          "revmap sender round-trip");
    check(alias_addr != NULL && strcmp(alias_addr, "jane@example.com") == 0,
          "revmap alias_addr round-trip");
    free(sender);
    free(alias_addr);

    /* unknown revmap token yields NULLs. */
    sender = NULL;
    alias_addr = NULL;
    check(store_revmap_resolve(s, "unknown-token", &sender, &alias_addr) == VISAGE_OK,
          "revmap_resolve unknown returns OK");
    check(sender == NULL && alias_addr == NULL,
          "revmap unknown yields NULL sender/alias");

    /* next_msgid monotonic. */
    m1 = store_next_msgid(s);
    m2 = store_next_msgid(s);
    check(m1 != 0, "next_msgid first call != 0");
    check(m2 == m1 + 1, "next_msgid increments");

    /* log append + count. */
    check(store_log_count(s) == 0, "log count initially 0");
    check(store_log_add(s, m1, 1700000000u, 1u, "jane@example.com",
                        "orig@foo.org", "ok") == VISAGE_OK, "log_add #1");
    check(store_log_count(s) == 1, "log count == 1 after one append");
    check(store_log_add(s, m2, 1700000001u, 2u, "jane@example.com",
                        "other@foo.org", "rejected") == VISAGE_OK, "log_add #2");
    check(store_log_count(s) == 2, "log count == 2 after two appends");

    check(store_close(s) == VISAGE_OK, "store_close returns OK");

    if (failures) {
        printf("store_check: %d FAILURE(S)\n", failures);
        return 1;
    }
    printf("store_check: ALL PASS\n");
    return 0;
}
