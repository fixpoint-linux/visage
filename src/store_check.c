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

/* --- queue due-walk collector ---------------------------------------- */

typedef struct {
    uint32_t msgid;
    uint32_t k;
    char     from[128];
    char     to[128];
    uint32_t attempts;
} QueueDueHit;

static QueueDueHit qhit;
static int qhits;

static int due_cb(uint32_t msgid, uint32_t k, const char *from, const char *to,
                  uint32_t attempts, void *user) {
    (void)user;
    qhits++;
    qhit.msgid = msgid;
    qhit.k = k;
    snprintf(qhit.from, sizeof qhit.from, "%s", from);
    snprintf(qhit.to, sizeof qhit.to, "%s", to);
    qhit.attempts = attempts;
    return 0;
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

    /* case-insensitive resolution: stored lowercase, resolved with mixed case. */
    dests = NULL;
    ndests = 0;
    check(store_resolve(s, "JaNe@Example.COM", &dests, &ndests) == VISAGE_OK,
          "resolve mixed-case alias returns OK");
    check(ndests == 2, "resolve mixed-case alias ndests == 2 (case-insensitive)");
    store_free_strvec(dests, ndests);

    /* mixed-case add also stores lowercase (idempotent with the lowercase add). */
    check(store_alias_add(s, "Shopping@Example.COM", "bob@realmail.example") == VISAGE_OK,
          "alias_add mixed-case");
    dests = NULL;
    ndests = 0;
    check(store_resolve(s, "shopping@example.com", &dests, &ndests) == VISAGE_OK,
          "resolve lowercase of a mixed-case-add alias");
    check(ndests == 1, "mixed-case add + lowercase resolve == 1 dest");
    store_free_strvec(dests, ndests);

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

    /* --- queue: add + count_by_status round-trip --- */
    check(store_queue_add(s, 100, 0, "jane@example.com", "dest1@realmail.example")
              == VISAGE_OK, "queue_add delivery k=0");
    check(store_queue_add(s, 100, 1, "jane@example.com", "dest2@realmail.example")
              == VISAGE_OK, "queue_add delivery k=1");
    check(store_queue_count_by_status(s, "queued") == 2, "queue count queued == 2");
    check(store_queue_count_by_status(s, "delivering") == 0,
          "queue count delivering == 0");
    check(store_queue_count_by_status(s, "delivered") == 0,
          "queue count delivered == 0");
    check(store_queue_count_by_status(s, "permfail") == 0,
          "queue count permfail == 0");

    /* fresh entries have next_ts 0 => due at now==0 */
    qhits = 0;
    check(store_queue_due(s, 0, due_cb, NULL) == VISAGE_OK, "queue_due returns OK");
    check(qhits == 2, "queue_due sees both queued entries (next_ts 0)");

    /* set_status: queued -> delivering (k=0), future next_ts */
    check(store_queue_set_status(s, 100, 0, "delivering", 1, 5000) == VISAGE_OK,
          "queue_set_status to delivering");
    check(store_queue_count_by_status(s, "delivering") == 1,
          "queue count delivering == 1 after transition");
    check(store_queue_count_by_status(s, "queued") == 1,
          "queue count queued == 1 after transition");

    /* delivering entries are never due (status filter), even at huge now */
    qhits = 0;
    check(store_queue_due(s, 999999, due_cb, NULL) == VISAGE_OK,
          "queue_due returns OK (delivering present)");
    check(qhits == 1, "due-walk skips delivering, sees only queued");

    /* queued entry (k=1) with a future next_ts is due only after next_ts */
    check(store_queue_set_status(s, 100, 1, "queued", 2, 3000) == VISAGE_OK,
          "queue_set_status queued next_ts=3000");
    qhits = 0;
    check(store_queue_due(s, 2999, due_cb, NULL) == VISAGE_OK, "queue_due now=2999");
    check(qhits == 0, "due-walk skips queued when next_ts > now");

    qhits = 0;
    check(store_queue_due(s, 3000, due_cb, NULL) == VISAGE_OK, "queue_due now=3000");
    check(qhits == 1, "due-walk sees queued when next_ts <= now");
    if (qhits == 1) {
        check(qhit.msgid == 100 && qhit.k == 1, "due msgid/k round-trip");
        check(strcmp(qhit.from, "jane@example.com") == 0, "due from round-trip");
        check(strcmp(qhit.to, "dest2@realmail.example") == 0, "due to round-trip");
        check(qhit.attempts == 2, "due attempts round-trip");
    }

    /* queued -> delivered removes from due */
    check(store_queue_set_status(s, 100, 1, "delivered", 2, 3000) == VISAGE_OK,
          "queue_set_status to delivered");
    check(store_queue_count_by_status(s, "delivered") == 1,
          "queue count delivered == 1");
    check(store_queue_count_by_status(s, "queued") == 0,
          "queue count queued == 0 after delivered");
    qhits = 0;
    check(store_queue_due(s, 999999, due_cb, NULL) == VISAGE_OK,
          "queue_due after delivered");
    check(qhits == 0, "due-walk empty after queued->delivered");

    check(store_close(s) == VISAGE_OK, "store_close returns OK");

    /* --- queue persistence across close/reopen (delete+add durability) --- */
    s = store_open(dir);
    check(s != NULL, "store_open reopen for queue persistence");
    if (s) {
        /* S3: the msgid counter persists across reopen — no reuse of a
           previously-issued msgid (which would collide with the queue key). */
        check(store_next_msgid(s) == m2 + 1,
              "next_msgid persists across reopen (no reuse)");
        check(store_queue_count_by_status(s, "delivering") == 1,
              "queue delivering persists across reopen");
        check(store_queue_count_by_status(s, "delivered") == 1,
              "queue delivered persists across reopen");
        check(store_queue_count_by_status(s, "queued") == 0,
              "queue queued == 0 after reopen (delete persisted)");

        /* next_due: nothing queued -> UINT32_MAX */
        check(store_queue_next_due(s) == UINT32_MAX,
              "queue next_due == UINT32_MAX when nothing queued");

        /* reset_delivering: recover the crash-stuck delivering -> queued */
        check(store_queue_reset_delivering(s) == VISAGE_OK,
              "queue reset_delivering returns OK");
        check(store_queue_count_by_status(s, "delivering") == 0,
              "queue delivering == 0 after reset");
        check(store_queue_count_by_status(s, "queued") == 1,
              "queue queued == 1 after reset");
        check(store_queue_next_due(s) == 0,
              "queue next_due == 0 after reset (due now)");
        qhits = 0;
        check(store_queue_due(s, 0, due_cb, NULL) == VISAGE_OK,
              "queue_due sees recovered item");
        check(qhits == 1, "recovered item is due at now==0");
        if (qhits == 1) {
            check(qhit.msgid == 100 && qhit.k == 0, "recovered msgid/k");
            check(qhit.attempts == 1, "recovered attempts preserved");
        }

        /* next_due returns the MINIMUM next_ts across queued deliveries */
        check(store_queue_add(s, 200, 0, "a@x.org", "b@y.org") == VISAGE_OK,
              "queue_add for next_due min test");
        check(store_queue_set_status(s, 200, 0, "queued", 0, 1234) == VISAGE_OK,
              "set second queued next_ts=1234");
        check(store_queue_next_due(s) == 0, "next_due min (0 vs 1234) == 0");
        check(store_queue_set_status(s, 100, 0, "queued", 1, 5000) == VISAGE_OK,
              "push recovered item to next_ts=5000");
        check(store_queue_next_due(s) == 1234, "next_due min (5000 vs 1234) == 1234");

        /* B1/S3 self-heal: two rows sharing (msgid,k) — as a reused msgid or a
           crash in the add-first window leaves — collapse to one via
           set_status instead of erroring or losing the delivery. */
        check(store_queue_add(s, 300, 0, "p@x.org", "q@y.org") == VISAGE_OK,
              "self-heal: queue_add dup-key #1");
        check(store_queue_add(s, 300, 0, "r@x.org", "s@y.org") == VISAGE_OK,
              "self-heal: queue_add dup-key #2");
        check(store_queue_set_status(s, 300, 0, "delivering", 1, 0) == VISAGE_OK,
              "self-heal: set_status collapses dup-key to 1 row");
        check(store_queue_count_by_status(s, "delivering") == 1,
              "self-heal: 1 delivering row after collapse");
        check(store_queue_set_status(s, 300, 0, "delivering", 1, 0) == VISAGE_OK,
              "self-heal: idempotent re-set_status");
        check(store_queue_count_by_status(s, "delivering") == 1,
              "self-heal: still 1 delivering row after idempotent re-set");

        check(store_close(s) == VISAGE_OK, "store_close after reopen");
    }

    if (failures) {
        printf("store_check: %d FAILURE(S)\n", failures);
        return 1;
    }
    printf("store_check: ALL PASS\n");
    return 0;
}
