/* jmap_state.c — jmapd's per-account state counters and the /changes answers.
 *
 * JMAP state strings are opaque, so what they MEAN is this server's business.
 * Here they mean "a monotone counter per data type, persisted beside the
 * account's maildir".  Two things bump a counter:
 *
 *   (1) a commit jmapd itself makes (Email/set create/update/destroy), and
 *   (2) a request that observes the maildir has moved under it — an imapd
 *       delivery, a flag change from another client, a delete.
 *
 * (2) is what makes the state honest in a tree TWO daemons write.  It rests on
 * a fingerprint (jmapd_state_fingerprint) rather than a change log: per mailbox
 * the new//cur/ entry counts plus the uidlist sidecar's (mtime, size).  A
 * delivery adds an entry, a flag change rewrites the sidecar at close, and
 * nothing else disturbs it — so the fingerprint moves exactly when a client
 * could observe a difference.  Cost is one readdir + two stats per mailbox,
 * which is less than the per-mailbox scan the read methods already do.
 *
 * /changes and /queryChanges answer the RFC-legal method error
 * cannotCalculateChanges: there is no per-object change log to diff against, and
 * a client ACTS on a claimed diff, so an invented one is worse than an honest
 * refusal.  The mail-hub client's response is a full refresh (plan DECISIONS 4).
 */
#include "visage.h"
#include "jmapd.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#define STATE_FILE "jmapd-state"

/* ------------------------------------------------------------------ */
/* Sidecar path + I/O                                                  */
/* ------------------------------------------------------------------ */

static int state_path(JmapdServer *srv, const char *user, char *out,
                      size_t outsz) {
    int n;
    if (!srv || !user || imapd_user_ok(user) != 1) return -1;
    n = snprintf(out, outsz, "%s/%s/%s", srv->icfg.root, user, STATE_FILE);
    if (n < 0 || (size_t)n >= outsz) return -1;
    return 0;
}

void jmapd_state_load(JmapdServer *srv, const char *user, JmapdState *st) {
    char path[4096 + IMAPD_MAX_USER + 32];
    char buf[1024];
    size_t got = 0;
    int fd;
    char *p;

    if (!st) return;
    memset(st, 0, sizeof *st);
    if (state_path(srv, user, path, sizeof path) != 0) return;
    fd = open(path, O_RDONLY);
    if (fd < 0) return;
    while (got < sizeof buf - 1) {
        ssize_t r = read(fd, buf + got, sizeof buf - 1 - got);
        if (r < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (r == 0) break;
        got += (size_t)r;
    }
    close(fd);
    buf[got] = '\0';
    /* "key value" lines; anything unrecognised is ignored (a sidecar from a
       newer version must not stop this one from starting). */
    for (p = buf; *p;) {
        char *nl = strchr(p, '\n');
        char key[32];
        unsigned long long v = 0;
        if (nl) *nl = '\0';
        if (sscanf(p, "%31s %llu", key, &v) == 2) {
            if (strcmp(key, "email") == 0) st->email = (uint64_t)v;
            else if (strcmp(key, "mailbox") == 0) st->mailbox = (uint64_t)v;
            else if (strcmp(key, "thread") == 0) st->thread = (uint64_t)v;
            else if (strcmp(key, "submission") == 0) st->submission = (uint64_t)v;
            else if (strcmp(key, "fp") == 0) {
                st->fp = (uint64_t)v;
                st->have_fp = true;
            }
        }
        if (!nl) break;
        p = nl + 1;
    }
}

int jmapd_state_save(JmapdServer *srv, const char *user, const JmapdState *st) {
    char path[4096 + IMAPD_MAX_USER + 32], tmp[4096 + IMAPD_MAX_USER + 64];
    char buf[256];
    int fd, n;
    size_t len;

    if (!st) return -1;
    if (state_path(srv, user, path, sizeof path) != 0) return -1;
    n = snprintf(buf, sizeof buf,
                 "email %llu\nmailbox %llu\nthread %llu\nsubmission %llu\n"
                 "fp %llu\n",
                 (unsigned long long)st->email,
                 (unsigned long long)st->mailbox,
                 (unsigned long long)st->thread,
                 (unsigned long long)st->submission,
                 (unsigned long long)st->fp);
    if (n < 0 || (size_t)n >= sizeof buf) return -1;
    len = (size_t)n;
    /* tmp + rename: a reader never sees a half-written sidecar. */
    n = snprintf(tmp, sizeof tmp, "%s.tmp.%ld", path, (long)getpid());
    if (n < 0 || (size_t)n >= sizeof tmp) return -1;
    fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return -1;
    {
        size_t off = 0;
        while (off < len) {
            ssize_t w = write(fd, buf + off, len - off);
            if (w < 0) {
                if (errno == EINTR) continue;
                close(fd);
                (void)unlink(tmp);
                return -1;
            }
            off += (size_t)w;
        }
    }
    if (close(fd) != 0 || rename(tmp, path) != 0) {
        (void)unlink(tmp);
        return -1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Maildir fingerprint                                                 */
/* ------------------------------------------------------------------ */

static void fp_mix(uint64_t *h, const void *p, size_t n) {
    const unsigned char *b = p;
    size_t i;
    for (i = 0; i < n; i++) {
        *h ^= b[i];
        *h *= 1099511628211ull;      /* FNV-1a */
    }
}

/* Entry count of <dir>/<sub> (names only, no stat per file: a readdir is the
   cheapest honest "did the set of messages change" probe). */
static void fp_count(uint64_t *h, const char *dir, const char *sub) {
    char path[4096 + 8];
    DIR *d;
    struct dirent *e;
    uint64_t n = 0;
    if (snprintf(path, sizeof path, "%s/%s", dir, sub) >= (int)sizeof path) {
        fp_mix(h, "?", 1);
        return;
    }
    d = opendir(path);
    if (!d) {
        fp_mix(h, "-", 1);
        return;
    }
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.') continue;
        n++;
    }
    closedir(d);
    fp_mix(h, &n, sizeof n);
}

/* qsort comparator for mailbox names (a set, not an order). */
static int fp_name_cmp(const void *a, const void *b) {
    return strcmp(*(const char *const *)a, *(const char *const *)b);
}

static void fp_mbox(uint64_t *h, const char *name, const char *dir) {
    static const char sep = '\0';
    char path[4096 + 64];
    struct stat sb;
    fp_mix(h, name, strlen(name));
    fp_mix(h, &sep, 1);
    fp_count(h, dir, "new");
    fp_count(h, dir, "cur");
    /* The uidlist sidecar carries the per-message modseqs, and imapd rewrites
       it at mailbox close whenever a flag changed — so its (mtime, size) is
       what makes a flag-only change visible to the fingerprint. */
    if (snprintf(path, sizeof path, "%s/%s", dir, IMAPD_UIDLIST_FILE)
            >= (int)sizeof path)
        return;
    if (stat(path, &sb) == 0) {
        fp_mix(h, &sb.st_mtim.tv_sec, sizeof sb.st_mtim.tv_sec);
        fp_mix(h, &sb.st_mtim.tv_nsec, sizeof sb.st_mtim.tv_nsec);
        fp_mix(h, &sb.st_size, sizeof sb.st_size);
    }
}

uint64_t jmapd_state_fingerprint(JmapdServer *srv, const char *user) {
    uint64_t h = 1469598103934665603ull;
    char dir[4096 + IMAPD_MAX_USER + IMAPD_MAX_MBOX + 8];
    char **names = NULL;
    size_t nnames = 0, i;

    if (!srv || !user || imapd_user_ok(user) != 1) return 0;
    if (imapd_mbox_dir(&srv->icfg, user, "Inbox", dir, sizeof dir) == 0)
        fp_mbox(&h, "Inbox", dir);
    if (imapd_mbox_list(&srv->icfg, user, "*", &names, &nnames) == 0) {
        /* The mix order must depend on the SET of mailboxes, not on the
           order imapd_mbox_list happened to see them in (raw readdir order,
           which a local filesystem keeps stable but NFS does not): two
           equivalent trees must not fingerprint differently. */
        if (nnames > 1) qsort(names, nnames, sizeof *names, fp_name_cmp);
        for (i = 0; i < nnames; i++) {
            if (strcmp(names[i], "Inbox") == 0) {
                free(names[i]);
                continue;
            }
            if (imapd_mbox_dir(&srv->icfg, user, names[i], dir, sizeof dir) == 0)
                fp_mbox(&h, names[i], dir);
            free(names[i]);
        }
        free(names);
    }
    return h;
}

void jmapd_state_sync(JmapdServer *srv, const char *user, JmapdState *st) {
    uint64_t fp;
    if (!st) return;
    fp = jmapd_state_fingerprint(srv, user);
    if (!st->have_fp) {
        /* First observation: ADOPT.  Bumping here would move every state on
           every daemon restart and force a full refresh for nothing. */
        st->fp = fp;
        st->have_fp = true;
        return;
    }
    if (fp == st->fp) return;
    st->email++;
    st->mailbox++;
    st->thread++;
    st->fp = fp;
    /* A failed save (read-only root) is not fatal for this request, but it does
       mean the next request re-observes the same change and bumps again: on a
       root jmapd cannot write, every read reports a moved state.  Named rather
       than hidden — such a root cannot take Email/set either. */
    (void)jmapd_state_save(srv, user, st);
}

void jmapd_state_bump(JmapdServer *srv, const char *user, JmapdState *st,
                      unsigned types) {
    if (!st) return;
    if (types & JMAPD_ST_EMAIL) st->email++;
    if (types & JMAPD_ST_MAILBOX) st->mailbox++;
    if (types & JMAPD_ST_THREAD) st->thread++;
    /* Adopt the fingerprint as it is NOW, so the next sync does not count our
       own write as somebody else's change. */
    st->fp = jmapd_state_fingerprint(srv, user);
    st->have_fp = true;
    (void)jmapd_state_save(srv, user, st);
}

/* ------------------------------------------------------------------ */
/* /changes                                                            */
/* ------------------------------------------------------------------ */

/* Every one of these answers the same RFC-legal method error.  `sinceState` is
   not validated first: an uncomputable diff is the answer whether or not the
   caller's state is one we ever issued (RFC 8620 5.2).

   Logged once per call.  A refusal is the REASON a client full-refreshes, so
   "why did the client re-download the mailbox" has to be answerable from the
   journal — a silent 200 that a client reads as "nothing changed" is the
   failure this line exists to make impossible to hide. */
static int changes_refused(JmapdCtx *ctx, const char *method,
                           const char *state_key, const JmapJsonNode *args,
                           JsonBuilder *out) {
    char detail[160];
    /* /queryChanges takes `sinceQueryState`, not `sinceState` (RFC 8620 5.6);
       reading the wrong key logged sinceState=- for every one of those calls,
       whatever the client named.  The key is the caller's to state. */
    const JmapJsonNode *since = args ? jmap_json_get(args, state_key) : NULL;
    const char *s = NULL;
    size_t sl = 0;

    if (jmap_json_str(since, &s, &sl) != 0) {
        s = "-";
        sl = 1;
    }
    if (sl > 64) sl = 64;
    snprintf(detail, sizeof detail, "method=%s %s=%.*s reason=no-log",
             method, state_key, (int)sl, s);
    jmapd_log_ctx(ctx, "changes-refused", detail);
    jmapd_jb_method_error(out, "cannotCalculateChanges");
    return 0;
}

int jmapd_method_email_changes(JmapdCtx *ctx, const JmapJsonNode *args,
                               JsonBuilder *out) {
    return changes_refused(ctx, "Email/changes", "sinceState", args, out);
}

int jmapd_method_mailbox_changes(JmapdCtx *ctx, const JmapJsonNode *args,
                                 JsonBuilder *out) {
    return changes_refused(ctx, "Mailbox/changes", "sinceState", args, out);
}

int jmapd_method_thread_changes(JmapdCtx *ctx, const JmapJsonNode *args,
                                JsonBuilder *out) {
    return changes_refused(ctx, "Thread/changes", "sinceState", args, out);
}

int jmapd_method_email_query_changes(JmapdCtx *ctx, const JmapJsonNode *args,
                                     JsonBuilder *out) {
    return changes_refused(ctx, "Email/queryChanges", "sinceQueryState", args, out);
}
