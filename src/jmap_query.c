/* jmap_query.c — Email/query (RFC 8621 4.4) for jmapd.
 *
 * The query runs over the SAME maildir tree imapd serves, one bounded scan
 * per mailbox (what STATUS does), with the per-mailbox header cache for
 * from/to/subject.  Nothing is cached across requests: imapd and jmapd share
 * this tree, so a cached view would be a second source of truth.
 *
 * Sorting is by receivedAt only (the one sort option the session document
 * advertises).  Rather than materialise every match — a 100k-message mailbox
 * would cost tens of megabytes — the query keeps a bounded heap of the first
 * (position + limit) entries in sort order and counts the rest: `total` stays
 * exact and the page is exact, for a window up to JMAPD_QUERY_MAX_WINDOW.
 * Deeper paging than that is refused rather than answered wrong.
 *
 * Filters: inMailbox, text (raw headers+body bytes, like IMAP SEARCH TEXT),
 * from, to, subject, keyword, notKeyword.  The keyword conditions test the
 * maildir flags the mailbox scan already parsed out of the FILENAME, so
 * "which messages in this mailbox are unread" ({inMailbox, notKeyword:
 * "$seen"}) costs one bounded directory scan and reads no message bodies —
 * with an exact `total`.  A filter this server cannot evaluate, or a keyword
 * no flag backs ($forwarded), is answered with the RFC-legal described
 * unsupportedFilter method error — never silently ignored, and never an empty
 * list, which would return the wrong set to a bulk action.
 */
#include "visage.h"
#include "jmapd.h"

#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

typedef struct QueryEntry {
    int64_t date;
    char    mbox[IMAPD_MAX_MBOX + 1];
    char    base[IMAPD_MAX_MBOX + 1];
} QueryEntry;

/* ASCII case-insensitive substring search. */
static bool ci_contains(const char *hay, size_t hl, const char *needle) {
    size_t nl = strlen(needle), i;
    if (nl == 0) return true;
    if (nl > hl) return false;
    for (i = 0; i + nl <= hl; i++) {
        size_t k;
        bool ok = true;
        for (k = 0; k < nl; k++) {
            unsigned char a = (unsigned char)hay[i + k];
            unsigned char b = (unsigned char)needle[k];
            if (a >= 'A' && a <= 'Z') a = (unsigned char)(a - 'A' + 'a');
            if (b >= 'A' && b <= 'Z') b = (unsigned char)(b - 'A' + 'a');
            if (a != b) { ok = false; break; }
        }
        if (ok) return true;
    }
    return false;
}

/* ------------------------------------------------------------------ */
/* Sort order                                                          */
/* ------------------------------------------------------------------ */

/* Negative when a sorts before b.  The tie-breakers (mailbox, base) make the
   order TOTAL, which is what keeps position/limit paging stable across
   requests that see the same mailbox. */
static int entry_cmp(const QueryEntry *a, const QueryEntry *b, bool desc) {
    int r;
    if (a->date != b->date) r = a->date < b->date ? -1 : 1;
    else if ((r = strcmp(a->mbox, b->mbox)) == 0)
        r = strcmp(a->base, b->base);
    return desc ? -r : r;
}

/* Max-heap over the sort order: the root is the WORST entry kept, so a
   better entry replaces it and the heap never grows past the window. */
static void heap_sift_down(QueryEntry *v, size_t n, size_t i, bool desc) {
    for (;;) {
        size_t l = 2 * i + 1, r = l + 1, big = i;
        if (l < n && entry_cmp(&v[l], &v[big], desc) > 0) big = l;
        if (r < n && entry_cmp(&v[r], &v[big], desc) > 0) big = r;
        if (big == i) return;
        {
            QueryEntry t = v[i];
            v[i] = v[big];
            v[big] = t;
        }
        i = big;
    }
}

static void heap_sift_up(QueryEntry *v, size_t i, bool desc) {
    while (i > 0) {
        size_t p = (i - 1) / 2;
        QueryEntry t;
        if (entry_cmp(&v[i], &v[p], desc) <= 0) return;
        t = v[i];
        v[i] = v[p];
        v[p] = t;
        i = p;
    }
}

/* Offer one entry to the bounded window. */
static void heap_offer(QueryEntry *v, size_t *n, size_t cap, const QueryEntry *e,
                       bool desc) {
    if (*n < cap) {
        v[*n] = *e;
        heap_sift_up(v, *n, desc);
        (*n)++;
        return;
    }
    if (cap == 0) return;
    if (entry_cmp(e, &v[0], desc) < 0) {
        v[0] = *e;
        heap_sift_down(v, *n, 0, desc);
    }
}

/* Drain the heap into best-first order: heapsort against the SAME comparator
   leaves the best entry at v[0] (the root is the worst kept entry, so each
   swap moves the worst to the end). */
static void heap_drain(QueryEntry *v, size_t n, bool desc) {
    size_t end;
    for (end = n; end > 1; end--) {
        QueryEntry t = v[0];
        v[0] = v[end - 1];
        v[end - 1] = t;
        heap_sift_down(v, end - 1, 0, desc);
    }
}

/* ------------------------------------------------------------------ */
/* Filter parsing                                                      */
/* ------------------------------------------------------------------ */

/* Parse one FilterCondition (RFC 8621 4.4.1).  A condition this server cannot
   evaluate, a value of the wrong JSON type, or a keyword no maildir flag backs
   all fill `why` and return -1: the caller answers a described
   unsupportedFilter, because an empty result set would claim "no mail
   matches", which is a different and wrong answer. */
int jmapd_query_filter_parse(const JmapJsonNode *f, JmapdQueryFilter *q,
                             char *why, size_t whysz) {
    size_t n, i;
    memset(q, 0, sizeof *q);
    if (why && whysz) why[0] = '\0';
    if (!f || f->type == JMAP_JSON_NULL) return 0;
    if (f->type != JMAP_JSON_OBJ) {
        if (why) snprintf(why, whysz, "filter must be an object");
        return -1;
    }
    n = jmap_json_count(f);
    for (i = 0; i < n; i++) {
        const JmapJsonNode *m = jmap_json_at(f, i);
        const char *s;
        if (!m || !m->key) {
            if (why) snprintf(why, whysz, "filter condition has no name");
            return -1;
        }
        if (!strcmp(m->key, "inMailbox")) {
            if (jmap_json_str(m, &s, NULL) != 0) {
                if (why) snprintf(why, whysz, "inMailbox must be an id string");
                return -1;
            }
            if (jmapd_id_mailbox_parse(s, q->mbox, sizeof q->mbox) != 0) {
                if (why) snprintf(why, whysz, "inMailbox is not a mailbox id");
                return -1;
            }
            q->in_mailbox = true;
        } else if (!strcmp(m->key, "text")) {
            if (jmap_json_str(m, &s, NULL) != 0) {
                if (why) snprintf(why, whysz, "text must be a string");
                return -1;
            }
            snprintf(q->text_s, sizeof q->text_s, "%s", s);
            q->text = true;
        } else if (!strcmp(m->key, "from")) {
            if (jmap_json_str(m, &s, NULL) != 0) {
                if (why) snprintf(why, whysz, "from must be a string");
                return -1;
            }
            snprintf(q->from_s, sizeof q->from_s, "%s", s);
            q->from = true;
        } else if (!strcmp(m->key, "to")) {
            if (jmap_json_str(m, &s, NULL) != 0) {
                if (why) snprintf(why, whysz, "to must be a string");
                return -1;
            }
            snprintf(q->to_s, sizeof q->to_s, "%s", s);
            q->to = true;
        } else if (!strcmp(m->key, "subject")) {
            if (jmap_json_str(m, &s, NULL) != 0) {
                if (why) snprintf(why, whysz, "subject must be a string");
                return -1;
            }
            snprintf(q->subject_s, sizeof q->subject_s, "%s", s);
            q->subject = true;
        } else if (!strcmp(m->key, "keyword") ||
                   !strcmp(m->key, "notKeyword")) {
            bool neg = m->key[0] == 'n';
            uint8_t flag = 0;
            if (jmap_json_str(m, &s, NULL) != 0) {
                if (why) snprintf(why, whysz,
                                  "%s must be a single keyword string",
                                  m->key);
                return -1;
            }
            if (jmapd_kw_flag(s, strlen(s), &flag) != 0) {
                if (why) snprintf(why, whysz,
                                  "keyword '%s' is not one this server can "
                                  "test; it supports $seen, $flagged, "
                                  "$answered, $draft and $deleted", s);
                return -1;
            }
            if (neg) {
                q->not_kw_flag = flag;
                q->not_keyword = true;
            } else {
                q->kw_flag = flag;
                q->keyword = true;
            }
        } else {
            if (why) snprintf(why, whysz,
                              "filter condition '%s' is not supported by this "
                              "server", m->key);
            return -1;   /* a condition this server cannot evaluate */
        }
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Mailbox enumeration (Inbox first, like Mailbox/get)                 */
/* ------------------------------------------------------------------ */

static int query_mbox_names(JmapdServer *srv, const char *user, char ***out,
                            size_t *nout) {
    char **names = NULL;
    size_t nnames = 0, i, o = 0;
    if (imapd_mbox_list(&srv->icfg, user, "*", &names, &nnames) != 0) {
        names = NULL;
        nnames = 0;
    }
    *out = calloc(nnames + 1, sizeof **out);
    if (!*out) {
        for (i = 0; i < nnames; i++) free(names[i]);
        free(names);
        return -1;
    }
    (*out)[o++] = strdup("Inbox");
    for (i = 0; i < nnames; i++) {
        if (!strcmp(names[i], "Inbox")) {
            free(names[i]);
            continue;
        }
        (*out)[o++] = names[i];
    }
    free(names);
    *nout = o;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Email/query                                                         */
/* ------------------------------------------------------------------ */

/* Search one message's raw bytes (headers + body) for the needle, charging
   the cost against *budget.  Returns 1 on a match, 0 on a clean miss, -1 when
   the budget is exhausted, -2 when the message could not be read in full, or
   -3 when this server could not allocate the buffer.  None of the negatives is
   a miss: answering "no match" for a message nobody read — or read only
   halfway, which a short read from a failing disk gives — is the silent wrong
   result this filter must never produce. */
static int msg_text_match(JmapdServer *srv, const Imail *m,
                          const JmapdQueryFilter *q, size_t *budget) {
    char *buf;
    size_t cap, got = 0;
    int fd, hit;
    cap = m->size;
    if (cap > srv->icfg.max_msg) cap = srv->icfg.max_msg;
    if (cap > *budget) return -1;
    buf = malloc(cap + 1);
    /* Out of memory is not "the scan budget": the client cannot narrow its way
       out of an allocation failure, so the refusal has to say so. */
    if (!buf) return -3;
    fd = open(m->path, O_RDONLY);
    if (fd < 0) { free(buf); return -2; }
    while (got < cap) {
        ssize_t r = read(fd, buf + got, cap - got);
        if (r < 0) {
            if (errno == EINTR) continue;
            close(fd);
            free(buf);
            return -2;
        }
        if (r == 0) break;
        got += (size_t)r;
    }
    close(fd);
    if (got < cap) {
        /* A short read is a PARTIAL message: scanning what arrived would turn
           a match past the cut into a silent non-match. */
        free(buf);
        return -2;
    }
    *budget -= got;
    hit = ci_contains(buf, got, q->text_s) ? 1 : 0;
    free(buf);
    return hit;
}

int jmapd_method_email_query(JmapdCtx *ctx, const JmapJsonNode *args,
                             JsonBuilder *out) {
    JmapdServer *srv = ctx->srv;
    const char *user = ctx->user;
    const JmapJsonNode *fnode = jmapd_arg(ctx, args, "filter");
    const JmapJsonNode *snode = jmapd_arg(ctx, args, "sort");
    const JmapJsonNode *pnode = jmapd_arg(ctx, args, "position");
    const JmapJsonNode *lnode = jmapd_arg(ctx, args, "limit");
    JmapdQueryFilter q;
    bool desc = true;             /* RFC 8621 4.4.2 default: receivedAt desc */
    uint64_t position = 0, limit = JMAPD_QUERY_DEFAULT_LIMIT;
    size_t window, total = 0, heap_n = 0, i, k;
    QueryEntry *heap = NULL;
    char **names = NULL;
    size_t nnames = 0;
    char state[32];
    JmapdState st;
    /* 0 in the config means "the default" — a server struct built without a
       full config (jmap_check.c) must not silently get a zero budget. */
    const size_t budget_max = srv->cfg.text_scan_max
                                  ? srv->cfg.text_scan_max
                                  : JMAPD_TEXT_SCAN_MAX;
    size_t budget = budget_max;
    size_t unreadable = 0;
    char why[256];

    if (ctx->argerr) { jmapd_jb_method_error(out, ctx->argerr); return 0; }
    if (jmapd_query_filter_parse(fnode, &q, why, sizeof why) != 0) {
        /* A described refusal, never an empty list: the client's bulk action
           ("mark all read") must not run over a set it wrongly read as empty. */
        jmapd_log_ctx(ctx, "query-unsupported-filter", why);
        jmapd_jb_method_error_desc(out, "unsupportedFilter", why);
        return 0;
    }
    if (snode && snode->type != JMAP_JSON_NULL) {
        size_t ns, j;
        if (snode->type != JMAP_JSON_ARR) {
            jmapd_jb_method_error(out, "unsupportedSort");
            return 0;
        }
        ns = jmap_json_count(snode);
        for (j = 0; j < ns; j++) {
            const JmapJsonNode *c = jmap_json_at(snode, j);
            const JmapJsonNode *prop, *asc;
            const char *s;
            bool a = false;
            if (!c || c->type != JMAP_JSON_OBJ) {
                jmapd_jb_method_error(out, "unsupportedSort");
                return 0;
            }
            prop = jmap_json_get(c, "property");
            if (jmap_json_str(prop, &s, NULL) != 0 ||
                strcmp(s, "receivedAt") != 0) {
                /* Only the advertised sort option exists (the maildir store
                   has no cheap relevance/date-header ordering). */
                jmapd_jb_method_error(out, "unsupportedSort");
                return 0;
            }
            asc = jmap_json_get(c, "isAscending");
            if (asc) (void)jmap_json_bool(asc, &a);
            desc = !a;
        }
    }
    if (pnode && jmap_json_u64(pnode, &position) != 0) position = 0;
    if (lnode) {
        if (lnode->type == JMAP_JSON_NULL) limit = JMAPD_QUERY_DEFAULT_LIMIT;
        else if (jmap_json_u64(lnode, &limit) != 0) limit = 0;
    }
    if (limit > JMAPD_MAX_OBJECTS) limit = JMAPD_MAX_OBJECTS;
    /* The window is what the heap holds: position + limit.  Paging deeper
       than that is refused rather than answered with a short page. */
    if (position + limit > JMAPD_QUERY_MAX_WINDOW) {
        snprintf(why, sizeof why,
                 "paging window position+limit=%llu exceeds this server's "
                 "limit of %u; page with a smaller position/limit",
                 (unsigned long long)(position + limit),
                 (unsigned)JMAPD_QUERY_MAX_WINDOW);
        jmapd_log_ctx(ctx, "query-over-window", why);
        jmapd_jb_method_error_desc(out, "serverLimit", why);
        return 0;
    }
    window = (size_t)(position + limit);
    jmapd_state_load(srv, user, &st);
    jmapd_state_sync(srv, user, &st);
    if (jmapd_state_fmt('e', st.email, state, sizeof state) != 0) return -1;

    if (window > 0) {
        heap = calloc(window, sizeof *heap);
        if (!heap) return -1;
    }
    if (query_mbox_names(srv, user, &names, &nnames) != 0) {
        free(heap);
        return -1;
    }
    for (i = 0; i < nnames; i++) {
        Mbox mb;
        if (q.in_mailbox && strcmp(q.mbox, names[i]) != 0) continue;
        if (imapd_mbox_peek(&srv->icfg, user, names[i], &mb) != 0) {
            /* A mailbox the query was supposed to search could not be opened:
               its messages are NOT "no match", and a result set missing them
               is a lie the client would render as "no mail here". */
            snprintf(why, sizeof why,
                     "mailbox '%s' could not be read; the query was not "
                     "answered rather than answered short", names[i]);
            jmapd_log_ctx(ctx, "query-unreadable-mailbox", why);
            free(heap);
            for (k = 0; k < nnames; k++) free(names[k]);
            free(names);
            jmapd_jb_method_error_desc(out, "serverFail", why);
            return 0;
        }
        for (k = 0; k < mb.nmsgs; k++) {
            Imail *m = &mb.msgs[k];
            QueryEntry e;
            bool ok = true;
            /* Keyword conditions test the maildir flags the SCAN already read
               off the filename, so they cost no I/O and no scan budget, and
               they run FIRST: a keyword miss skips the header load below. */
            if (q.keyword && (m->flags & q.kw_flag) == 0) ok = false;
            if (ok && q.not_keyword && (m->flags & q.not_kw_flag) != 0)
                ok = false;
            if (!ok) continue;
            if (q.from || q.to || q.subject) {
                /* An unreadable message is counted, not treated as a miss: see
                   the refusal after the scan. */
                if (imapd_mail_ensure_hdrs(&mb, m, NULL) != 1) {
                    unreadable++;
                    continue;
                }
            }
            if (q.from) {
                const char *v = imapd_mail_hdr_field(m, IH_FROM);
                if (!v || !ci_contains(v, strlen(v), q.from_s)) ok = false;
            }
            if (ok && q.to) {
                const char *v = imapd_mail_hdr_field(m, IH_TO);
                if (!v || !ci_contains(v, strlen(v), q.to_s)) ok = false;
            }
            if (ok && q.subject) {
                const char *v = imapd_mail_hdr_field(m, IH_SUBJ);
                if (!v || !ci_contains(v, strlen(v), q.subject_s)) ok = false;
            }
            if (ok && q.text) {
                int hit = msg_text_match(srv, m, &q, &budget);
                if (hit < 0) {
                    /* The description is built BEFORE the view is closed:
                       imapd_mbox_close frees the message names it would name
                       (measured: the refusal carried freed bytes). */
                    const char *ev, *ty;
                    if (hit == -2) {
                        ev = "query-unreadable-message";
                        ty = "serverFail";
                        snprintf(why, sizeof why,
                                 "message '%s' could not be read in full; the "
                                 "text filter was not answered rather than "
                                 "answered with a short list",
                                 m->base ? m->base : "?");
                    } else if (hit == -3) {
                        ev = "query-out-of-memory";
                        ty = "serverFail";
                        snprintf(why, sizeof why,
                                 "not enough memory to read a message for the "
                                 "text filter; scope the search with inMailbox "
                                 "or retry");
                    } else {
                        ev = "query-over-budget";
                        ty = "serverLimit";
                        snprintf(why, sizeof why,
                                 "text filter exceeded this server's scan "
                                 "budget of %llu bytes; scope the search with "
                                 "inMailbox, or raise --text-scan-max",
                                 (unsigned long long)budget_max);
                    }
                    imapd_mbox_close(&mb);
                    free(heap);
                    for (k = 0; k < nnames; k++) free(names[k]);
                    free(names);
                    /* Honest refusal beats a wrong (partial) result set: the
                       text filter reads whole messages and one request may not
                       hold the poll loop for minutes.  `serverLimit` is the
                       RFC 8620 3.6.2 type for "the work this request asks for
                       is beyond this server" — the client can narrow it (a
                       mailbox scope, a smaller page) and retry.  A message
                       that could not be read, or a failed allocation, is not
                       that: it is this server's fault, so `serverFail`. */
                    jmapd_log_ctx(ctx, ev, why);
                    jmapd_jb_method_error_desc(out, ty, why);
                    return 0;
                }
                if (!hit) ok = false;
            }
            if (!ok) continue;
            total++;
            if (!m->base || !heap) continue;
            memset(&e, 0, sizeof e);
            e.date = (int64_t)m->internal_date;
            snprintf(e.mbox, sizeof e.mbox, "%s", names[i]);
            snprintf(e.base, sizeof e.base, "%s", m->base);
            heap_offer(heap, &heap_n, window, &e, desc);
        }
        imapd_mbox_close(&mb);
    }
    for (k = 0; k < nnames; k++) free(names[k]);
    free(names);
    if (unreadable) {
        free(heap);
        snprintf(why, sizeof why,
                 "%llu message(s) could not be read; the query was not answered "
                 "rather than answered short",
                 (unsigned long long)unreadable);
        jmapd_log_ctx(ctx, "query-unreadable-message", why);
        jmapd_jb_method_error_desc(out, "serverFail", why);
        return 0;
    }
    heap_drain(heap, heap_n, desc);

    jsonb_begin_object(out);
    jsonb_key(out, "accountId"); jsonb_str(out, user);
    jsonb_comma(out);
    jsonb_key(out, "queryState"); jsonb_str(out, state);
    jsonb_comma(out);
    /* M2 answers cannotCalculateChanges: the client falls back to a full
       refresh (plan DECISIONS 4).  Claiming otherwise would be a lie the
       client acts on. */
    jsonb_key(out, "canCalculateChanges"); jsonb_bool(out, 0);
    jsonb_comma(out);
    jsonb_key(out, "position");
    jmapd_jb_u64(out, position);
    jsonb_comma(out);
    jsonb_key(out, "total");
    jmapd_jb_u64(out, (uint64_t)total);
    jsonb_comma(out);
    jsonb_key(out, "ids");
    jsonb_begin_array(out);
    {
        int first = 1;
        for (i = 0; i < heap_n; i++) {
            char id[JMAPD_ID_MAX];
            if ((uint64_t)i < position) continue;
            if ((uint64_t)i >= position + limit) break;
            if (jmapd_id_email(heap[i].base, NULL, id, sizeof id) != 0) continue;
            /* A base name that also exists in an earlier mailbox of the same
               result set gets the disambiguated "f" form (plan DECISIONS 3):
               only an IMAP COPY can produce that collision. */
            {
                size_t j;
                bool dup = false;
                for (j = 0; j < i; j++)
                    if (!strcmp(heap[j].base, heap[i].base) &&
                        strcmp(heap[j].mbox, heap[i].mbox)) {
                        dup = true;
                        break;
                    }
                if (dup)
                    (void)jmapd_id_email(heap[i].base, heap[i].mbox, id,
                                         sizeof id);
            }
            if (!first) jsonb_comma(out);
            first = 0;
            jsonb_str(out, id);
        }
    }
    jsonb_end_array(out);
    jsonb_end_object(out);
    free(heap);
    return 0;
}
