/* store_bench.c — benchmark of the datalog-dafsa store used by visage.
 *
 * Measures, across alias counts N in {1e3, 1e4, 1e5, 1e6}:
 *   - bulk seed throughput (CSV generation + store_alias_load_bulk /
 *     store_revmap_load_bulk, the sorted Daciuk build path — NO per-row fsync),
 *   - warm resolve latency (store_resolve / store_revmap_resolve) as a mean +
 *     p50/p99/p99.9 over a ~100k random-key batch,
 *   - cold resolve latency (fresh store_open + the SAME first batch),
 *   - on-disk size: recursive dir_size() of the db dir AFTER store_close, plus
 *     a per-file breakdown so readers see WHERE the bytes go (the string
 *     interner dominates, NOT the relation DAFSAs).
 *
 * Emits one CSV row per N, appended to bench.csv.
 *
 * HONESTY NOTES (read before "fixing"):
 *  - bytes/alias is ~FLAT (~480-550 B) across N, dominated by the string
 *    interner (symbols.dafsa + symbols.array).  It does NOT fall as N grows:
 *    there is no large shared fixed cost that amortizes.  The honest claim is
 *    "compact / ~constant bytes per alias, no per-alias index bloat", NOT a
 *    shrinking curve.  Do not fabricate a fall.
 *  - The resolve path (store_resolve -> dl_prefix) is IN-MEMORY
 *    (heap-resident DAFSA), NOT mmap.  So drop-caches / madvise(DONTNEED) are
 *    the WRONG "cold" mechanism.  Honest cold = fresh store_open (re-reads the
 *    files, cold CPU cache) + first batch; honest warm = primed second batch.
 *  - Keys are deliberately alphanumeric ("user<k>", "tok<k>", "sender<k>@"):
 *    a bare all-digit field would be mis-interned as a raw u32 by the CSV
 *    loader.  Quoted fields are unnecessary for these values (no commas).
 */
#include "visage.h"
#include "store.h"

#include <dirent.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* Alias counts to sweep. */
static const long NS[] = {1000L, 10000L, 100000L, 1000000L};
#define NCOUNT ((int)(sizeof NS / sizeof NS[0]))

/* ~100k random lookups per warm/cold batch. */
#define BATCH 100000L

/* Fixed seed => deterministic, reproducible runs. */
static uint32_t rng_state = 0x12345678u;

static uint32_t rng_next(void) {
    uint32_t x = rng_state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    return rng_state = x;
}

/* Wall-clock seconds (monotonic). */
static double now_s(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

/* Per-call nanoseconds (monotonic); constant ~20ns overhead cancels in the
 * N-comparison.  Integer math avoids the double-precision hazard near the
 * epoch (~104 days of uptime with a sub-ns absolute). */
static uint64_t now_ns_i(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

/* --- per-file size breakdown + recursive dir_size ---------------------- */

typedef struct {
    uint64_t symbols_dafsa; /* forward interner DAFSA */
    uint64_t symbols_array; /* reverse interner string blob */
    uint64_t alias_dafsa;
    uint64_t revmap_dafsa;
    uint64_t other;         /* everything else (WALs, rels.txt, LOCK, ...) */
} SizeBreakdown;

static void stat_into(const char *base, const char *name, uint64_t *out) {
    char p[4096];
    struct stat st;
    snprintf(p, sizeof p, "%s/%s", base, name);
    if (stat(p, &st) == 0) *out = (uint64_t)st.st_size;
}

static void collect_breakdown(const char *dir, SizeBreakdown *b) {
    memset(b, 0, sizeof *b);
    stat_into(dir, "symbols.dafsa", &b->symbols_dafsa);
    stat_into(dir, "symbols.array", &b->symbols_array);
    stat_into(dir, "alias.dafsa",  &b->alias_dafsa);
    stat_into(dir, "revmap.dafsa", &b->revmap_dafsa);
    /* other = total minus the four known files (computed after the walk). */
}

static uint64_t dir_size_rec(const char *path) {
    DIR *d;
    struct dirent *e;
    struct stat st;
    uint64_t total = 0;
    char sub[4096];

    d = opendir(path);
    if (!d) return 0;
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.') continue;
        snprintf(sub, sizeof sub, "%s/%s", path, e->d_name);
        if (lstat(sub, &st) != 0) continue;
        if (S_ISDIR(st.st_mode)) {
            total += dir_size_rec(sub);
        } else if (S_ISREG(st.st_mode)) {
            total += (uint64_t)st.st_size;
        }
    }
    closedir(d);
    return total;
}

/* --- resolve helpers (full real path incl. alloc/free) ------------------ */

static void resolve_alias(Store *s, long k) {
    char alias[96];
    char **dests = NULL;
    size_t ndests = 0;
    snprintf(alias, sizeof alias, "user%ld@example.com", k);
    if (store_resolve(s, alias, &dests, &ndests) == VISAGE_OK)
        store_free_strvec(dests, ndests);
}

static void resolve_revmap(Store *s, long k) {
    char tok[96];
    char *sender = NULL, *alias_addr = NULL;
    snprintf(tok, sizeof tok, "tok%ld", k);
    (void)store_revmap_resolve(s, tok, &sender, &alias_addr);
    free(sender);
    free(alias_addr);
}

/* --- one timing batch over a precomputed random key set ----------------- */

typedef struct {
    double mean;      /* arithmetic mean of per-call ns */
    double p50, p99, p999;
} LatStats;

static int cmp_dbl(const void *a, const void *b) {
    double x = *(const double *)a, y = *(const double *)b;
    return (x > y) - (x < y);
}

/* Time `n` calls to `fn` over keys[], collecting per-call ns. */
static LatStats time_batch(Store *s, long *keys, long n,
                           void (*fn)(Store *, long)) {
    static double per[BATCH]; /* BATCH is fixed, so static is fine */
    long i;
    double *p;
    LatStats st;

    memset(per, 0, sizeof per);
    for (i = 0; i < n; i++) {
        uint64_t t0 = now_ns_i();
        fn(s, keys[i]);
        per[i] = (double)(now_ns_i() - t0);
    }

    st.mean = 0.0;
    for (i = 0; i < n; i++) st.mean += per[i];
    st.mean /= (double)n;

    /* percentiles on a sorted copy */
    p = malloc((size_t)n * sizeof *p);
    if (!p) { st.p50 = st.p99 = st.p999 = st.mean; return st; }
    memcpy(p, per, (size_t)n * sizeof *p);
    qsort(p, (size_t)n, sizeof *p, cmp_dbl);
    st.p50  = p[(size_t)(n / 2)];
    st.p99  = p[(size_t)(n * 99 / 100)];
    st.p999 = p[(size_t)(n * 999 / 1000)];
    free(p);
    return st;
}

/* --- CSV output --------------------------------------------------------- */

static const char *CSV_COLS =
    "N,alias_load_s,revmap_load_s,"
    "alias_warm_ns,alias_p50_ns,alias_p99_ns,alias_p999_ns,"
    "revmap_warm_ns,revmap_p50_ns,revmap_p99_ns,revmap_p999_ns,"
    "alias_cold_ns,revmap_cold_ns,"
    "total_bytes,bytes_per_alias";

static void ensure_csv_header(void) {
    /* Always truncate + rewrite the header: a fresh run must not append to a
     * stale bench.csv from a prior `make bench`, which would emit duplicate-N
     * rows and a self-crossing polyline in the plots. */
    FILE *f = fopen("bench.csv", "w");
    if (f) {
        fprintf(f, "%s\n", CSV_COLS);
        fclose(f);
    }
}

static void append_row(long N, double alias_load, double revmap_load,
                       LatStats alias_warm, LatStats revmap_warm,
                       double alias_cold, double revmap_cold,
                       uint64_t total_bytes, double bytes_per_alias) {
    FILE *f = fopen("bench.csv", "a");
    if (!f) return;
    fprintf(f,
            "%ld,%.4f,%.4f,"
            "%.2f,%.2f,%.2f,%.2f,"
            "%.2f,%.2f,%.2f,%.2f,"
            "%.2f,%.2f,"
            "%llu,%.2f\n",
            N, alias_load, revmap_load,
            alias_warm.mean, alias_warm.p50, alias_warm.p99, alias_warm.p999,
            revmap_warm.mean, revmap_warm.p50, revmap_warm.p99, revmap_warm.p999,
            alias_cold, revmap_cold,
            (unsigned long long)total_bytes, bytes_per_alias);
    fclose(f);
}

/* --- one N: seed, warm, cold, size -------------------------------------- */

static int run_N(long N, const char *csv_dir) {
    char dbdir[256], acsv[256], rcsv[256];
    char *tpl;
    long *keys = NULL;
    long i, k;
    FILE *f;
    double t0;
    Store *s;
    LatStats alias_warm, revmap_warm, alias_cold_ls, revmap_cold_ls;
    uint64_t total_bytes;
    double bytes_per_alias;
    SizeBreakdown bd;
    double alias_load, revmap_load;
    long batch = (N < BATCH) ? N : BATCH;

    /* (a) mkdtemp a db dir + generate the two CSVs. */
    snprintf(dbdir, sizeof dbdir, "%s/visage_bench_%ld_XXXXXX", csv_dir, N);
    tpl = strdup(dbdir);
    if (!tpl) return 1;
    if (!mkdtemp(tpl)) {
        fprintf(stderr, "store_bench: mkdtemp(%s) failed\n", dbdir);
        free(tpl);
        return 1;
    }
    snprintf(acsv, sizeof acsv, "%s/alias_%ld.csv", csv_dir, N);
    snprintf(rcsv, sizeof rcsv, "%s/revmap_%ld.csv", csv_dir, N);

    t0 = now_s();
    f = fopen(acsv, "w");
    if (!f) { free(tpl); return 1; }
    for (i = 0; i < N; i++) {
        fprintf(f, "example.com,user%ld,dest%ld@realmail.example\n", i, i);
    }
    fclose(f);

    f = fopen(rcsv, "w");
    if (!f) { free(tpl); return 1; }
    {
        uint32_t now = (uint32_t)time(NULL);
        for (i = 0; i < N; i++) {
            fprintf(f, "tok%ld,sender%ld@foo.org,user%ld@example.com,%u\n",
                    i, i, i, now);
        }
    }
    fclose(f);
    /* CSV generation time is not measured (it is not part of the claim). */

    /* (b) open + bulk seed, timing each load. */
    s = store_open(tpl);
    if (!s) { fprintf(stderr, "store_bench: store_open(%s) failed\n", tpl);
              free(tpl); return 1; }
    t0 = now_s();
    if (store_alias_load_bulk(s, acsv) != VISAGE_OK) {
        fprintf(stderr, "store_bench: alias load failed\n");
        store_close(s); free(tpl); return 1;
    }
    alias_load = now_s() - t0;

    t0 = now_s();
    if (store_revmap_load_bulk(s, rcsv) != VISAGE_OK) {
        fprintf(stderr, "store_bench: revmap load failed\n");
        store_close(s); free(tpl); return 1;
    }
    revmap_load = now_s() - t0;

    /* Precompute one random key set (same batch reused for warm and cold). */
    keys = malloc((size_t)batch * sizeof *keys);
    if (!keys) { store_close(s); free(tpl); return 1; }
    for (i = 0; i < batch; i++) keys[i] = (long)(rng_next() % (uint32_t)N);

    /* (c) WARM: prime by resolving all keys once, then time the batch. */
    for (k = 0; k < N; k++) { resolve_alias(s, k); resolve_revmap(s, k); }
    alias_warm  = time_batch(s, keys, batch, resolve_alias);
    revmap_warm = time_batch(s, keys, batch, resolve_revmap);

    /* (d) COLD: close+reopen (fresh dl_open, cold CPU cache), first batch. */
    store_close(s);
    s = store_open(tpl);
    if (!s) { free(keys); free(tpl); return 1; }
    alias_cold_ls  = time_batch(s, keys, batch, resolve_alias);
    revmap_cold_ls = time_batch(s, keys, batch, resolve_revmap);

    /* (e) close, then measure on-disk size after the compacting close. */
    store_close(s);
    total_bytes = dir_size_rec(tpl);
    bytes_per_alias = (double)total_bytes / (double)N;
    collect_breakdown(tpl, &bd);
    bd.other = total_bytes - (bd.symbols_dafsa + bd.symbols_array +
                              bd.alias_dafsa + bd.revmap_dafsa);

    printf("N=%ld  alias_load=%.2fs revmap_load=%.2fs  "
           "warm alias=%.0fns revmap=%.0fns  "
           "cold alias=%.0fns revmap=%.0fns  "
           "bytes=%llu (%.0f/alias)\n",
           N, alias_load, revmap_load,
           alias_warm.mean, revmap_warm.mean,
           alias_cold_ls.mean, revmap_cold_ls.mean,
           (unsigned long long)total_bytes, bytes_per_alias);
    printf("  breakdown: symbols.dafsa=%llu symbols.array=%llu "
           "alias.dafsa=%llu revmap.dafsa=%llu other=%llu\n",
           (unsigned long long)bd.symbols_dafsa,
           (unsigned long long)bd.symbols_array,
           (unsigned long long)bd.alias_dafsa,
           (unsigned long long)bd.revmap_dafsa,
           (unsigned long long)bd.other);

    append_row(N, alias_load, revmap_load,
               alias_warm, revmap_warm,
               alias_cold_ls.mean, revmap_cold_ls.mean,
               total_bytes, bytes_per_alias);

    free(keys);
    free(tpl);
    return 0;
}

int main(int argc, char **argv) {
    const char *csv_dir = "/tmp";
    int i;
    (void)argc;

    if (argv[1] && argv[1][0]) csv_dir = argv[1];
    /* Sanity: the CSV dir must exist and be writable. */
    {
        struct stat st;
        if (stat(csv_dir, &st) != 0 || !S_ISDIR(st.st_mode)) {
            fprintf(stderr, "store_bench: bad output dir '%s'\n", csv_dir);
            return 1;
        }
    }

    ensure_csv_header();
    for (i = 0; i < NCOUNT; i++) {
        if (run_N(NS[i], csv_dir) != 0) return 1;
    }
    printf("store_bench: done; rows appended to bench.csv\n");
    return 0;
}
