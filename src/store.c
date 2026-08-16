/* store.c — datalog-dafsa store wrapper for visage (slice S2).
 *
 * Owns the single-writer dl_db handle and exposes the fixed schema (see
 * store.h) as typed calls.  The int/sym discipline is load-bearing: string
 * columns are interned sym_ids (1-based) via dl_intern_str / dl_intern_str_of,
 * integer columns are raw u32, and the two are never mixed within a column or
 * compared across columns. */
#include "visage.h"
#include "store.h"
#include <dl.h>
#include <time.h>

struct Store {
    dl_db *db;
};

/* --- relation names + fixed arities (must match store.h exactly) --- */
#define REL_DOMAIN "domain"
#define REL_ALIAS  "alias"
#define REL_REVMAP "revmap"
#define REL_LOG    "log"
#define REL_META   "meta"
#define REL_QUEUE  "queue"

#define AR_DOMAIN 1u
#define AR_ALIAS  3u
#define AR_REVMAP 4u
#define AR_LOG    6u
#define AR_META   2u
#define AR_QUEUE  7u

/* meta key that holds the monotonic next-msgid counter (raw u32 value). */
#define META_KEY_NEXT_MSGID "next_msgid"

/* Queue status strings (interned; they join ok/tempfail/error/rejected as the
 * shared string table already holds those from the log relation). */
#define QUEUE_STATUS_QUEUED     "queued"
#define QUEUE_STATUS_DELIVERING "delivering"
#define QUEUE_STATUS_DELIVERED  "delivered"
#define QUEUE_STATUS_PERMFAIL   "permfail"

/* --- small helpers ---------------------------------------------------- */

/* Split "local@domain" into freshly-malloc'd local and domain.  Splits at the
 * first '@'.  Rejects a missing '@', an empty local, or an empty domain. */
static int split_addr(const char *addr, char **local, char **domain) {
    const char *at;
    size_t llen, dlen;

    if (!addr) return VISAGE_EPARAM;
    at = strchr(addr, '@');
    if (!at) return VISAGE_EPARAM;
    if (at == addr) return VISAGE_EPARAM;        /* empty local part */
    if (at[1] == '\0') return VISAGE_EPARAM;     /* empty domain part */

    llen = (size_t)(at - addr);
    dlen = strlen(at + 1);

    *local = malloc(llen + 1);
    *domain = malloc(dlen + 1);
    if (!*local || !*domain) {
        free(*local);
        free(*domain);
        *local = NULL;
        *domain = NULL;
        return VISAGE_ENOMEM;
    }
    memcpy(*local, addr, llen);
    (*local)[llen] = '\0';
    memcpy(*domain, at + 1, dlen);
    (*domain)[dlen] = '\0';
    return VISAGE_OK;
}

/* --- query callbacks -------------------------------------------------- */

typedef struct { long count; } CountCtx;
static int count_cb(const uint32_t *cols, uint8_t arity, void *user) {
    CountCtx *c = (CountCtx *)user;
    (void)cols;
    (void)arity;
    c->count++;
    return 0;
}

/* store_resolve collection: copy the dest column (col 2) of each alias tuple
 * into a pre-sized string array. */
typedef struct {
    dl_db  *db;
    char  **arr;
    size_t  idx;
    size_t  cap;
    int     err;
} DestCollectCtx;

static int dest_collect_cb(const uint32_t *cols, uint8_t arity, void *user) {
    DestCollectCtx *c = (DestCollectCtx *)user;
    const char *s;
    (void)arity;

    if (c->idx >= c->cap) { c->err = 1; return 1; }
    s = dl_intern_str_of(c->db, cols[2]);
    if (!s) { c->err = 1; return 1; }
    c->arr[c->idx] = strdup(s);
    if (!c->arr[c->idx]) { c->err = 1; return 1; }
    c->idx++;
    return 0;
}

/* revmap lookup: capture sender (col 1) and alias_addr (col 2). */
typedef struct { uint32_t sender, alias_addr; int found; } RevmapCtx;
static int revmap_cb(const uint32_t *cols, uint8_t arity, void *user) {
    RevmapCtx *c = (RevmapCtx *)user;
    (void)arity;
    if (!c->found) {
        c->sender = cols[1];
        c->alias_addr = cols[2];
        c->found = 1;
    }
    return 0;
}

/* meta read: collect every raw-u32 value (col 1) for the key.  Normally
 * exactly 1; 2+ is a recoverable duplicate left by a crash in the
 * add-first window (self-healed by taking the max in store_next_msgid). */
enum { META_MAX_ROWS = 16 };
typedef struct { uint32_t vals[META_MAX_ROWS]; size_t n; } MetaReadCtx;
static int meta_read_cb(const uint32_t *cols, uint8_t arity, void *user) {
    MetaReadCtx *c = (MetaReadCtx *)user;
    (void)arity;
    if (c->n < META_MAX_ROWS) {
        c->vals[c->n] = cols[1];   /* raw u32, NOT a sym_id */
        c->n++;
    }
    return 0;
}

/* --- lifecycle -------------------------------------------------------- */

Store *store_open(const char *path) {
    Store *s;
    dl_db *db;

    if (!path || !path[0]) return NULL;

    db = dl_open(path);
    if (!db) return NULL;

    if (dl_declare_relation(db, REL_DOMAIN, AR_DOMAIN) != 0) goto fail;
    if (dl_declare_relation(db, REL_ALIAS,  AR_ALIAS)  != 0) goto fail;
    if (dl_declare_relation(db, REL_REVMAP, AR_REVMAP) != 0) goto fail;
    if (dl_declare_relation(db, REL_LOG,    AR_LOG)    != 0) goto fail;
    if (dl_declare_relation(db, REL_META,   AR_META)   != 0) goto fail;
    if (dl_declare_relation(db, REL_QUEUE,  AR_QUEUE)  != 0) goto fail;

    s = calloc(1, sizeof *s);
    if (!s) { dl_close(db); return NULL; }
    s->db = db;
    return s;

fail:
    dl_close(db);
    return NULL;
}

int store_close(Store *s) {
    if (!s) return VISAGE_EPARAM;
    dl_close(s->db);
    free(s);
    return VISAGE_OK;
}

/* --- aliases / domains ------------------------------------------------ */

static int alias_add_impl(Store *s, const char *alias, const char *dest) {
    char *local = NULL, *domain = NULL;
    uint32_t d_id, l_id, dest_id;
    uint32_t cols[3];
    int rc;

    if (!alias || !alias[0] || !dest || !dest[0]) return VISAGE_EPARAM;
    rc = split_addr(alias, &local, &domain);
    if (rc != VISAGE_OK) return rc;

    d_id = dl_intern_str(s->db, domain);
    l_id = dl_intern_str(s->db, local);
    dest_id = dl_intern_str(s->db, dest);
    free(local);
    free(domain);
    if (!d_id || !l_id || !dest_id) return VISAGE_ENOMEM;

    cols[0] = d_id;
    cols[1] = l_id;
    cols[2] = dest_id;
    rc = dl_add_fact(s->db, REL_ALIAS, cols, AR_ALIAS);
    if (rc < 0) return VISAGE_ESTORE;
    return VISAGE_OK;
}

int store_alias_add(Store *s, const char *alias, const char *dest) {
    if (!s || !s->db) return VISAGE_EPARAM;
    return alias_add_impl(s, alias, dest);
}

int store_alias_rm(Store *s, const char *alias, const char *dest) {
    char *local = NULL, *domain = NULL;
    uint32_t d_id, l_id, dest_id;
    uint32_t cols[3];
    int rc;

    if (!s || !s->db || !alias || !dest) return VISAGE_EPARAM;
    rc = split_addr(alias, &local, &domain);
    if (rc != VISAGE_OK) return rc;

    d_id = dl_intern_str(s->db, domain);
    l_id = dl_intern_str(s->db, local);
    dest_id = dl_intern_str(s->db, dest);
    free(local);
    free(domain);
    if (!d_id || !l_id || !dest_id) return VISAGE_ENOMEM;

    cols[0] = d_id;
    cols[1] = l_id;
    cols[2] = dest_id;
    rc = dl_delete_fact(s->db, REL_ALIAS, cols, AR_ALIAS);
    if (rc < 0) return VISAGE_ESTORE;
    return VISAGE_OK;
}

int store_seed_aliases(Store *s, const Config *cfg) {
    size_t i, j;
    int rc;

    if (!s || !s->db || !cfg) return VISAGE_EPARAM;

    for (i = 0; i < cfg->ndomains; i++) {
        uint32_t d_id;
        uint32_t cols[1];
        if (!cfg->domains[i] || !cfg->domains[i][0]) continue;
        d_id = dl_intern_str(s->db, cfg->domains[i]);
        if (!d_id) return VISAGE_ENOMEM;
        cols[0] = d_id;
        if (dl_add_fact(s->db, REL_DOMAIN, cols, AR_DOMAIN) < 0)
            return VISAGE_ESTORE;
    }

    for (i = 0; i < cfg->naliases; i++) {
        const char *alias = cfg->aliases[i].alias;
        if (!alias) continue;
        for (j = 0; j < cfg->aliases[i].ndestinations; j++) {
            rc = alias_add_impl(s, alias, cfg->aliases[i].destinations[j]);
            if (rc != VISAGE_OK) return rc;
        }
    }
    return VISAGE_OK;
}

int store_resolve(Store *s, const char *alias, char ***dests, size_t *ndests) {
    char *local = NULL, *domain = NULL;
    uint32_t d_id, l_id;
    uint32_t leading[2];
    CountCtx cc = {0};
    long n;
    int rc;

    if (!s || !s->db || !alias || !dests || !ndests) return VISAGE_EPARAM;
    *dests = NULL;
    *ndests = 0;

    rc = split_addr(alias, &local, &domain);
    if (rc != VISAGE_OK) return rc;

    d_id = dl_intern_str(s->db, domain);
    l_id = dl_intern_str(s->db, local);
    free(local);
    free(domain);
    if (!d_id || !l_id) return VISAGE_ENOMEM;

    /* Enumerate alias(domain, local, dest) via a 2-column prefix walk. */
    leading[0] = d_id;
    leading[1] = l_id;

    n = dl_prefix(s->db, REL_ALIAS, leading, 2, count_cb, &cc);
    if (n < 0) return VISAGE_ESTORE;
    if (n == 0) return VISAGE_OK;   /* alias unknown: *dests=NULL, *ndests=0 */

    {
        DestCollectCtx dc;
        char **arr = calloc((size_t)n, sizeof(char *));
        if (!arr) return VISAGE_ENOMEM;
        dc.db = s->db;
        dc.arr = arr;
        dc.idx = 0;
        dc.cap = (size_t)n;
        dc.err = 0;

        if (dl_prefix(s->db, REL_ALIAS, leading, 2, dest_collect_cb, &dc) < 0 ||
            dc.err) {
            store_free_strvec(arr, dc.idx);
            return dc.err ? VISAGE_ENOMEM : VISAGE_ESTORE;
        }
        *dests = arr;
        *ndests = dc.idx;
    }
    return VISAGE_OK;
}

void store_free_strvec(char **vec, size_t n) {
    size_t i;
    if (!vec) return;
    for (i = 0; i < n; i++) free(vec[i]);
    free(vec);
}

/* --- reverse-alias reply map ------------------------------------------ */

int store_revmap_add(Store *s, const char *token, const char *sender,
                     const char *alias_addr) {
    uint32_t cols[4];
    int rc;

    if (!s || !s->db || !token || !token[0] || !sender || !sender[0] ||
        !alias_addr || !alias_addr[0])
        return VISAGE_EPARAM;

    cols[0] = dl_intern_str(s->db, token);
    cols[1] = dl_intern_str(s->db, sender);
    cols[2] = dl_intern_str(s->db, alias_addr);
    if (!cols[0] || !cols[1] || !cols[2]) return VISAGE_ENOMEM;
    cols[3] = (uint32_t)time(NULL);   /* raw u32 unix-seconds */

    rc = dl_add_fact(s->db, REL_REVMAP, cols, AR_REVMAP);
    if (rc < 0) return VISAGE_ESTORE;
    return VISAGE_OK;
}

int store_revmap_resolve(Store *s, const char *token, char **sender,
                         char **alias_addr) {
    uint32_t tok_id;
    uint32_t leading[1];
    RevmapCtx rc = {0, 0, 0};
    long n;
    const char *s_sender, *s_alias;

    if (!s || !s->db || !token || !sender || !alias_addr) return VISAGE_EPARAM;
    *sender = NULL;
    *alias_addr = NULL;

    if (!token[0]) return VISAGE_OK;   /* empty token: not found */

    tok_id = dl_intern_str(s->db, token);
    if (!tok_id) return VISAGE_ENOMEM;

    leading[0] = tok_id;
    n = dl_prefix(s->db, REL_REVMAP, leading, 1, revmap_cb, &rc);
    if (n < 0) return VISAGE_ESTORE;
    if (n == 0) return VISAGE_OK;      /* unknown token: both out-params NULL */

    s_sender = dl_intern_str_of(s->db, rc.sender);
    s_alias = dl_intern_str_of(s->db, rc.alias_addr);
    if (!s_sender || !s_alias) return VISAGE_ESTORE;   /* corrupt db */

    *sender = strdup(s_sender);
    *alias_addr = strdup(s_alias);
    if (!*sender || !*alias_addr) {
        free(*sender);
        free(*alias_addr);
        *sender = NULL;
        *alias_addr = NULL;
        return VISAGE_ENOMEM;
    }
    return VISAGE_OK;
}

/* --- message id + log -------------------------------------------------- */

uint32_t store_next_msgid(Store *s) {
    uint32_t key, cur = 0, next;
    uint32_t leading[1], cols[2];
    MetaReadCtx mc;
    long n;
    size_t i;
    int rc;

    if (!s || !s->db) return 0;

    key = dl_intern_str(s->db, META_KEY_NEXT_MSGID);
    if (!key) return 0;

    leading[0] = key;
    memset(&mc, 0, sizeof mc);
    n = dl_prefix(s->db, REL_META, leading, 1, meta_read_cb, &mc);
    if (n < 0) return 0;

    /* Self-heal post-crash duplicates by taking the max: the counter skips
     * ahead monotonically and never reuses a msgid. */
    for (i = 0; i < mc.n; i++)
        if (mc.vals[i] > cur) cur = mc.vals[i];

    next = cur + 1;
    if (next == 0) return 0;        /* 32-bit counter wrapped */

    cols[0] = key;
    cols[1] = next;
    /* ADD first (durable), THEN delete the old rows.  A crash between the add
     * and the deletes leaves a duplicate (new + old), never a loss; the next
     * call self-heals via the max above. */
    rc = dl_add_fact(s->db, REL_META, cols, AR_META);
    if (rc < 0) return 0;
    for (i = 0; i < mc.n; i++) {
        cols[0] = key;
        cols[1] = mc.vals[i];
        (void)dl_delete_fact(s->db, REL_META, cols, AR_META);
    }

    return next;
}

int store_log_add(Store *s, uint32_t msgid, uint32_t ts, uint32_t dir,
                  const char *local, const char *remote, const char *status) {
    uint32_t cols[6];
    int rc;

    if (!s || !s->db || !local || !local[0] || !remote || !remote[0] ||
        !status || !status[0])
        return VISAGE_EPARAM;

    cols[0] = msgid;                 /* raw u32 */
    cols[1] = ts;                    /* raw u32 */
    cols[2] = dir;                   /* raw u32 */
    cols[3] = dl_intern_str(s->db, local);    /* sym */
    cols[4] = dl_intern_str(s->db, remote);   /* sym */
    cols[5] = dl_intern_str(s->db, status);   /* sym */
    if (!cols[3] || !cols[4] || !cols[5]) return VISAGE_ENOMEM;

    rc = dl_add_fact(s->db, REL_LOG, cols, AR_LOG);
    if (rc < 0) return VISAGE_ESTORE;
    return VISAGE_OK;
}

long store_log_count(Store *s) {
    CountCtx cc = {0};
    if (!s || !s->db) return -1;
    return dl_prefix(s->db, REL_LOG, NULL, 0, count_cb, &cc);
}

/* --- log scan for the admin /log endpoint --------------------------- */

/* Collect log tuples into a pre-sized raw array. */
typedef struct { uint32_t (*rows)[6]; size_t count, cap; int err; } LogCollectCtx;
static int log_collect_cb(const uint32_t *cols, uint8_t arity, void *user) {
    LogCollectCtx *c = (LogCollectCtx *)user;
    (void)arity;
    if (c->count >= c->cap) { c->err = 1; return 1; }
    memcpy(c->rows[c->count], cols, sizeof(uint32_t) * 6);
    c->count++;
    return 0;
}

/* Skip the first `skip` tuples, then collect the rest. */
typedef struct { LogCollectCtx *inner; size_t skip; } LogSkipCtx;
static int log_skip_cb(const uint32_t *cols, uint8_t arity, void *user) {
    LogSkipCtx *c = (LogSkipCtx *)user;
    if (c->skip > 0) { c->skip--; return 0; }
    return log_collect_cb(cols, arity, c->inner);
}

int store_log_recent(Store *s, size_t max, StoreLogEntry **out, size_t *nout) {
    long total;
    size_t want, skip, i;
    uint32_t (*raw)[6] = NULL;
    StoreLogEntry *arr;
    LogCollectCtx cc;
    LogSkipCtx sc;

    if (!s || !s->db || !out || !nout) return VISAGE_EPARAM;
    *out = NULL;
    *nout = 0;

    total = store_log_count(s);
    if (total < 0) return VISAGE_ESTORE;

    want = ((size_t)total <= max) ? (size_t)total : max;
    if (want == 0) return VISAGE_OK;
    skip = (size_t)total - want;

    raw = malloc(want * sizeof *raw);
    if (!raw) return VISAGE_ENOMEM;

    cc.rows = raw;
    cc.count = 0;
    cc.cap = want;
    cc.err = 0;
    sc.inner = &cc;
    sc.skip = skip;

    if (dl_prefix(s->db, REL_LOG, NULL, 0, log_skip_cb, &sc) < 0 ||
        cc.err || cc.count != want) {
        free(raw);
        return VISAGE_ESTORE;
    }

    arr = calloc(want, sizeof *arr);
    if (!arr) { free(raw); return VISAGE_ENOMEM; }

    for (i = 0; i < want; i++) {
        const char *local, *remote, *status;
        arr[i].msgid = raw[i][0];
        arr[i].ts    = raw[i][1];
        arr[i].dir   = raw[i][2];
        local  = dl_intern_str_of(s->db, raw[i][3]);
        remote = dl_intern_str_of(s->db, raw[i][4]);
        status = dl_intern_str_of(s->db, raw[i][5]);
        arr[i].local  = strdup(local  ? local  : "");
        arr[i].remote = strdup(remote ? remote : "");
        arr[i].status = strdup(status ? status : "");
        if (!arr[i].local || !arr[i].remote || !arr[i].status) {
            store_log_entries_free(arr, want);
            free(raw);
            return VISAGE_ENOMEM;
        }
    }
    free(raw);
    *out = arr;
    *nout = want;
    return VISAGE_OK;
}

void store_log_entries_free(StoreLogEntry *e, size_t n) {
    size_t i;
    if (!e) return;
    for (i = 0; i < n; i++) {
        free(e[i].local);
        free(e[i].remote);
        free(e[i].status);
    }
    free(e);
}

/* --- durable outbound delivery queue ----------------------------------- */

/* Collect every queue tuple matching (msgid,k) for the set_status
 * transition.  Normally exactly 1; 2+ is a recoverable duplicate left by a
 * crash in the add-first window (self-healed below). */
enum { QUEUE_SET_MAX_ROWS = 16 };
typedef struct { uint32_t rows[QUEUE_SET_MAX_ROWS][7]; size_t n; } QueueReadCtx;
static int queue_read_cb(const uint32_t *cols, uint8_t arity, void *user) {
    QueueReadCtx *c = (QueueReadCtx *)user;
    (void)arity;
    if (c->n < QUEUE_SET_MAX_ROWS) {
        memcpy(c->rows[c->n], cols, sizeof(uint32_t) * 7);
        c->n++;
    }
    return 0;
}

int store_queue_add(Store *s, uint32_t msgid, uint32_t k,
                    const char *from, const char *to) {
    uint32_t cols[7];
    int rc;

    if (!s || !s->db || !from || !from[0] || !to || !to[0])
        return VISAGE_EPARAM;

    cols[0] = msgid;                                   /* raw u32 */
    cols[1] = k;                                       /* raw u32 */
    cols[2] = dl_intern_str(s->db, from);              /* sym */
    cols[3] = dl_intern_str(s->db, to);                /* sym */
    cols[4] = 0;                                       /* attempts */
    cols[5] = 0;                                       /* next_ts  */
    cols[6] = dl_intern_str(s->db, QUEUE_STATUS_QUEUED); /* sym    */
    if (!cols[2] || !cols[3] || !cols[6]) return VISAGE_ENOMEM;

    rc = dl_add_fact(s->db, REL_QUEUE, cols, AR_QUEUE);
    if (rc < 0) return VISAGE_ESTORE;
    return VISAGE_OK;
}

int store_queue_set_status(Store *s, uint32_t msgid, uint32_t k,
                           const char *status, uint32_t attempts,
                           uint32_t next_ts) {
    uint32_t leading[2], next[7];
    QueueReadCtx qc;
    long n;
    size_t i, match;
    int rc;

    if (!s || !s->db || !status || !status[0]) return VISAGE_EPARAM;

    /* Intern the new status BEFORE mutating, so an OOM cannot strand the
     * delivery in a half-deleted state. */
    next[6] = dl_intern_str(s->db, status);
    if (!next[6]) return VISAGE_ENOMEM;

    leading[0] = msgid;
    leading[1] = k;
    memset(&qc, 0, sizeof qc);
    n = dl_prefix(s->db, REL_QUEUE, leading, 2, queue_read_cb, &qc);
    if (n < 0) return VISAGE_ESTORE;
    if (qc.n == 0) return VISAGE_ESTORE;   /* no such delivery */
    /* (qc.n > 1 is a recoverable post-crash duplicate; self-heal below.) */

    next[0] = msgid;
    next[1] = k;
    next[2] = qc.rows[0][2];   /* from (preserved sym) */
    next[3] = qc.rows[0][3];   /* to   (preserved sym) */
    next[4] = attempts;
    next[5] = next_ts;

    /* CRASH-SAFETY (at-least-once): each dl_add_fact / dl_delete_fact is
     * independently WAL-appended + fsync'd, so a delete-then-add sequence
     * has a window in which a crash LOSES the row (delete persists, add
     * does not) -> silent message drop, violating at-least-once.  If the
     * desired `next` row already exists (idempotent transition, or a
     * crash-dup already holding the target state), keep that one and drop
     * the rest; otherwise ADD `next` FIRST, THEN delete every old row.
     * A crash between the add and the deletes now leaves a duplicate
     * (new + old), which is at-least-once-safe and is collapsed back to a
     * single row by the next set_status call (self-heal).  No window loses
     * the delivery. */
    match = qc.n;
    for (i = 0; i < qc.n; i++)
        if (memcmp(next, qc.rows[i], sizeof next) == 0) { match = i; break; }
    if (match < qc.n) {
        for (i = 0; i < qc.n; i++)
            if (i != match)
                (void)dl_delete_fact(s->db, REL_QUEUE, qc.rows[i], AR_QUEUE);
        return VISAGE_OK;
    }

    rc = dl_add_fact(s->db, REL_QUEUE, next, AR_QUEUE);
    if (rc < 0) return VISAGE_ESTORE;
    for (i = 0; i < qc.n; i++)
        (void)dl_delete_fact(s->db, REL_QUEUE, qc.rows[i], AR_QUEUE);
    return VISAGE_OK;
}

/* due-walk: filter status == 'queued' && next_ts <= now, then hand
 * (msgid, k, from, to, attempts) to the caller's callback. */
typedef struct {
    Store   *s;
    uint32_t now;
    uint32_t queued_id;
    int    (*cb)(uint32_t msgid, uint32_t k, const char *from, const char *to,
                 uint32_t attempts, void *user);
    void   *user;
    int      err;
} QueueDueCtx;

static int queue_due_cb(const uint32_t *cols, uint8_t arity, void *user) {
    QueueDueCtx *c = (QueueDueCtx *)user;
    const char *from, *to;
    (void)arity;

    if (cols[6] != c->queued_id) return 0;   /* status != queued */
    if (cols[5] > c->now) return 0;          /* not yet due */

    from = dl_intern_str_of(c->s->db, cols[2]);
    to   = dl_intern_str_of(c->s->db, cols[3]);
    if (!from || !to) { c->err = 1; return 1; }

    if (c->cb(cols[0], cols[1], from, to, cols[4], c->user) != 0) return 1;
    return 0;
}

int store_queue_due(Store *s, uint32_t now,
                    int (*cb)(uint32_t msgid, uint32_t k, const char *from,
                              const char *to, uint32_t attempts, void *user),
                    void *user) {
    QueueDueCtx c;
    long n;

    if (!s || !s->db || !cb) return VISAGE_EPARAM;

    memset(&c, 0, sizeof c);
    c.s = s;
    c.now = now;
    c.queued_id = dl_intern_str(s->db, QUEUE_STATUS_QUEUED);
    if (!c.queued_id) return VISAGE_ENOMEM;
    c.cb = cb;
    c.user = user;

    n = dl_prefix(s->db, REL_QUEUE, NULL, 0, queue_due_cb, &c);
    if (n < 0 || c.err) return VISAGE_ESTORE;
    return VISAGE_OK;
}

/* count_by_status: full walk, count tuples whose status column matches. */
typedef struct { uint32_t status_id; long count; } QueueCountCtx;
static int queue_count_cb(const uint32_t *cols, uint8_t arity, void *user) {
    QueueCountCtx *c = (QueueCountCtx *)user;
    (void)arity;
    if (cols[6] == c->status_id) c->count++;
    return 0;
}

long store_queue_count_by_status(Store *s, const char *status) {
    QueueCountCtx c;
    long n;

    if (!s || !s->db || !status || !status[0]) return -1;

    c.status_id = dl_intern_str(s->db, status);
    if (!c.status_id) return -1;
    c.count = 0;

    n = dl_prefix(s->db, REL_QUEUE, NULL, 0, queue_count_cb, &c);
    if (n < 0) return -1;
    return c.count;
}

/* reset_delivering: full walk collecting (msgid, k, attempts) for status ==
 * "delivering", then (AFTER the walk returns) reset each back to "queued".
 * Collect-then-mutate is load-bearing: dafsa add/delete realloc the states
 * array, so mutating the relation inside a dl_prefix walk is a use-after-free.
 */
typedef struct { uint32_t msgid, k, attempts; } DeliveringItem;
typedef struct {
    uint32_t        delivering_id;
    DeliveringItem *items;
    size_t          n, cap;
    int             err;
} DeliveringCtx;

static int delivering_collect_cb(const uint32_t *cols, uint8_t arity,
                                 void *user) {
    DeliveringCtx *c = (DeliveringCtx *)user;
    (void)arity;
    if (cols[6] != c->delivering_id) return 0;
    if (c->n == c->cap) {
        size_t nc = c->cap ? c->cap * 2 : 8;
        DeliveringItem *na = realloc(c->items, nc * sizeof *na);
        if (!na) { c->err = 1; return 1; }
        c->items = na;
        c->cap = nc;
    }
    c->items[c->n].msgid = cols[0];
    c->items[c->n].k = cols[1];
    c->items[c->n].attempts = cols[4];
    c->n++;
    return 0;
}

int store_queue_reset_delivering(Store *s) {
    DeliveringCtx c;
    long n;
    size_t i;

    if (!s || !s->db) return VISAGE_EPARAM;

    memset(&c, 0, sizeof c);
    c.delivering_id = dl_intern_str(s->db, QUEUE_STATUS_DELIVERING);
    if (!c.delivering_id) return VISAGE_ENOMEM;

    n = dl_prefix(s->db, REL_QUEUE, NULL, 0, delivering_collect_cb, &c);
    if (n < 0 || c.err) {
        free(c.items);
        return c.err ? VISAGE_ENOMEM : VISAGE_ESTORE;
    }

    for (i = 0; i < c.n; i++) {
        int rc = store_queue_set_status(s, c.items[i].msgid, c.items[i].k,
                                        QUEUE_STATUS_QUEUED,
                                        c.items[i].attempts, 0);
        if (rc != VISAGE_OK) { free(c.items); return rc; }
    }
    free(c.items);
    return VISAGE_OK;
}

/* next_due: full walk tracking the minimum next_ts among status == "queued".
 * Read-only — never mutates the relation. */
typedef struct { uint32_t queued_id, min_next; } NextDueCtx;
static int next_due_cb(const uint32_t *cols, uint8_t arity, void *user) {
    NextDueCtx *c = (NextDueCtx *)user;
    (void)arity;
    if (cols[6] == c->queued_id && cols[5] < c->min_next)
        c->min_next = cols[5];
    return 0;
}

uint32_t store_queue_next_due(Store *s) {
    NextDueCtx c;

    if (!s || !s->db) return UINT32_MAX;
    c.queued_id = dl_intern_str(s->db, QUEUE_STATUS_QUEUED);
    if (!c.queued_id) return UINT32_MAX;
    c.min_next = UINT32_MAX;

    if (dl_prefix(s->db, REL_QUEUE, NULL, 0, next_due_cb, &c) < 0)
        return UINT32_MAX;
    return c.min_next;
}
