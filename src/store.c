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

#define AR_DOMAIN 1u
#define AR_ALIAS  3u
#define AR_REVMAP 4u
#define AR_LOG    6u
#define AR_META   2u

/* meta key that holds the monotonic next-msgid counter (raw u32 value). */
#define META_KEY_NEXT_MSGID "next_msgid"

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

/* meta read: capture the raw-u32 value (col 1). */
typedef struct { uint32_t val; int found; } MetaReadCtx;
static int meta_read_cb(const uint32_t *cols, uint8_t arity, void *user) {
    MetaReadCtx *c = (MetaReadCtx *)user;
    (void)arity;
    if (!c->found) {
        c->val = cols[1];   /* raw u32, NOT a sym_id */
        c->found = 1;
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
    MetaReadCtx mc = {0, 0};
    long n;
    int rc;

    if (!s || !s->db) return 0;

    key = dl_intern_str(s->db, META_KEY_NEXT_MSGID);
    if (!key) return 0;

    leading[0] = key;
    n = dl_prefix(s->db, REL_META, leading, 1, meta_read_cb, &mc);
    if (n < 0 || n > 1) return 0;   /* >1 => corrupt meta */
    if (n == 1) cur = mc.val;

    next = cur + 1;
    if (next == 0) return 0;        /* 32-bit counter wrapped */

    if (n == 1) {
        cols[0] = key;
        cols[1] = cur;
        rc = dl_delete_fact(s->db, REL_META, cols, AR_META);
        if (rc < 0) return 0;
    }
    cols[0] = key;
    cols[1] = next;
    rc = dl_add_fact(s->db, REL_META, cols, AR_META);
    if (rc < 0) return 0;

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
