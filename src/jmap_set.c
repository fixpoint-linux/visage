/* jmap_set.c — Email/set (RFC 8621 4.6): update, create and destroy.
 *
 * What each operation does to the maildir:
 *
 *   update   a JSON-Patch (RFC 8620 5.3) over the Email's two MUTABLE
 *            properties.  "keywords/<kw>" flips one maildir flag letter;
 *            "mailboxIds/<id>" or a whole-object "mailboxIds" replace is a
 *            maildir MOVE (imapd_mbox_file), which RENAMES the file and keeps
 *            its base name — so the Email id survives a move, exactly as it
 *            survives a flag rename (plan DECISIONS 3, RISKS 1).
 *   create   an RFC 5322 message built from the JMAP body (multipart/alternative
 *            for text+html, a single part otherwise) and delivered with
 *            imapd_mbox_deliver_uid, so the uidlist sidecar knows it at once and
 *            the new Email id (the base name) is known before the reply.
 *   destroy  imapd_mbox_expunge: unlink the file and prune the uidlist.
 *
 * Two honest limits, both named where they are enforced:
 *   - one mailbox per Email.  The store is a maildir tree, so an Email in two
 *     Mailboxes would need two files with the same id; a patch that would put
 *     it in more than one answers "tooManyMailboxes", and one that would leave
 *     it in none answers "invalidProperties" (RFC 8621 4.1.1: an Email MUST
 *     belong to one or more Mailboxes until it is destroyed).
 *   - only the five keywords IMAP can carry ($seen/$flagged/$answered/$draft/
 *     $deleted) are representable; any other keyword is refused with
 *     "invalidProperties" rather than silently dropped.
 */
#include "visage.h"
#include "jmapd.h"
#include "mail.h"

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <strings.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* ------------------------------------------------------------------ */
/* Keywords <-> maildir flags                                          */
/* ------------------------------------------------------------------ */

/* The one keyword table: Email/set writes through it, Email/query filters on
   it, Email/get renders it.  A keyword absent here is one no maildir filename
   can carry ($forwarded has no flag letter), so it is refused rather than
   accepted and dropped. */
static const struct {
    const char *kw;
    uint8_t     flag;
} KEYWORDS[] = {
    { "$seen",     IMAIL_SEEN     },
    { "$flagged",  IMAIL_FLAGGED  },
    { "$answered", IMAIL_ANSWERED },
    { "$draft",    IMAIL_DRAFT    },
    { "$deleted",  IMAIL_TRASHED  },
};

#define NKEYWORDS (sizeof KEYWORDS / sizeof KEYWORDS[0])

int jmapd_kw_flag(const char *kw, size_t kwlen, uint8_t *out) {
    size_t i;
    for (i = 0; i < NKEYWORDS; i++)
        if (strlen(KEYWORDS[i].kw) == kwlen &&
            memcmp(KEYWORDS[i].kw, kw, kwlen) == 0) {
            *out = KEYWORDS[i].flag;
            return 0;
        }
    return -1;
}

/* ------------------------------------------------------------------ */
/* Patch paths (RFC 6901 escapes inside RFC 8620 5.3 patch keys)       */
/* ------------------------------------------------------------------ */

#define PATCH_SEG_MAX 1024
#define PATCH_SEGS    2

/* Split one patch key into unescaped segments.  Returns the segment count
   (1..max), or -1 for a deeper path or a dangling "~" escape. */
static int path_split(const char *key, char seg[][PATCH_SEG_MAX], size_t max) {
    size_t n = 0, o = 0;
    const char *p = key;
    for (;;) {
        char c = *p;
        if (c == '\0') {
            seg[n][o] = '\0';
            return (int)(n + 1);
        }
        if (c == '/') {
            seg[n][o] = '\0';
            if (++n >= max) return -1;
            o = 0;
            p++;
            continue;
        }
        if (c == '~') {
            if (p[1] == '0') c = '~';
            else if (p[1] == '1') c = '/';
            else return -1;
            p++;
        }
        if (o + 1 >= PATCH_SEG_MAX) return -1;
        seg[n][o++] = c;
        p++;
    }
}

/* ------------------------------------------------------------------ */
/* The patch applier (pure: src/jmap_check.c drives it directly)       */
/* ------------------------------------------------------------------ */

static void patch_bad(JmapdEmailPatch *out, const char *key) {
    snprintf(out->bad, sizeof out->bad, "%s", key ? key : "");
}

JmapdPatchErr jmapd_patch_apply(const JmapJsonNode *patch, const char *cur_mbox,
                                uint8_t cur_flags, JmapdEmailPatch *out) {
    char seg[PATCH_SEGS][PATCH_SEG_MAX];
    size_t i, n;
    if (!out) return JMAPD_PATCH_E_PATH;
    memset(out, 0, sizeof *out);
    out->flags = cur_flags;
    if (cur_mbox) snprintf(out->mbox, sizeof out->mbox, "%s", cur_mbox);
    if (!patch || patch->type != JMAP_JSON_OBJ) {
        patch_bad(out, "");
        return JMAPD_PATCH_E_TYPE;
    }
    n = jmap_json_count(patch);
    for (i = 0; i < n; i++) {
        const JmapJsonNode *m = jmap_json_at(patch, i);
        const char *key;
        size_t keylen;
        const JmapJsonNode *val;
        int nseg;
        if (!m || !m->key) continue;
        key = m->key;
        keylen = m->keylen;
        val = m;
        (void)keylen;
        nseg = path_split(key, seg, PATCH_SEGS);
        if (nseg < 1) {
            patch_bad(out, key);
            return JMAPD_PATCH_E_PATH;
        }
        if (strcmp(seg[0], "keywords") == 0) {
            if (nseg == 1) {
                /* Whole-object replace: the new keyword set is exactly this
                   object's true-valued members. */
                uint8_t flags = 0;
                size_t k, nk;
                if (val->type != JMAP_JSON_OBJ) {
                    patch_bad(out, key);
                    return JMAPD_PATCH_E_TYPE;
                }
                nk = jmap_json_count(val);
                for (k = 0; k < nk; k++) {
                    const JmapJsonNode *e = jmap_json_at(val, k);
                    uint8_t f = 0;
                    bool on = false;
                    if (!e || !e->key) continue;
                    if (jmapd_kw_flag(e->key, e->keylen, &f) != 0) {
                        patch_bad(out, key);
                        return JMAPD_PATCH_E_KEYWORD;
                    }
                    if (e->type != JMAP_JSON_BOOL) {
                        patch_bad(out, key);
                        return JMAPD_PATCH_E_TYPE;
                    }
                    (void)jmap_json_bool(e, &on);
                    if (on) flags |= f;
                }
                out->flags = flags;
            } else {
                uint8_t f = 0;
                if (jmapd_kw_flag(seg[1], strlen(seg[1]), &f) != 0) {
                    patch_bad(out, key);
                    return JMAPD_PATCH_E_KEYWORD;
                }
                if (val->type == JMAP_JSON_NULL) {
                    out->flags &= (uint8_t)~f;
                } else if (val->type == JMAP_JSON_BOOL) {
                    bool on = false;
                    (void)jmap_json_bool(val, &on);
                    if (on) out->flags |= f;
                    else out->flags &= (uint8_t)~f;
                } else {
                    patch_bad(out, key);
                    return JMAPD_PATCH_E_TYPE;
                }
            }
        } else if (strcmp(seg[0], "mailboxIds") == 0) {
            if (nseg == 1) {
                char name[IMAPD_MAX_MBOX + 1];
                size_t k, nk, ntrue = 0;
                if (val->type != JMAP_JSON_OBJ) {
                    patch_bad(out, key);
                    return JMAPD_PATCH_E_TYPE;
                }
                nk = jmap_json_count(val);
                for (k = 0; k < nk; k++) {
                    const JmapJsonNode *e = jmap_json_at(val, k);
                    bool on = false;
                    if (!e || !e->key) continue;
                    if (e->type != JMAP_JSON_BOOL) {
                        patch_bad(out, key);
                        return JMAPD_PATCH_E_TYPE;
                    }
                    (void)jmap_json_bool(e, &on);
                    if (!on) continue;
                    if (jmapd_id_mailbox_parse(e->key, name, sizeof name) != 0) {
                        patch_bad(out, key);
                        return JMAPD_PATCH_E_PATH;
                    }
                    ntrue++;
                    if (ntrue > 1) {
                        patch_bad(out, key);
                        return JMAPD_PATCH_E_MULTI;
                    }
                    snprintf(out->mbox, sizeof out->mbox, "%s", name);
                }
                if (ntrue == 0) {
                    patch_bad(out, key);
                    return JMAPD_PATCH_E_EMPTY;
                }
            } else {
                char name[IMAPD_MAX_MBOX + 1];
                bool on = false;
                if (jmapd_id_mailbox_parse(seg[1], name, sizeof name) != 0) {
                    patch_bad(out, key);
                    return JMAPD_PATCH_E_PATH;
                }
                if (val->type == JMAP_JSON_NULL) {
                    on = false;
                } else if (val->type == JMAP_JSON_BOOL) {
                    (void)jmap_json_bool(val, &on);
                } else {
                    patch_bad(out, key);
                    return JMAPD_PATCH_E_TYPE;
                }
                if (on) {
                    if (out->mbox[0] && strcmp(out->mbox, name) != 0) {
                        patch_bad(out, key);
                        return JMAPD_PATCH_E_MULTI;
                    }
                    snprintf(out->mbox, sizeof out->mbox, "%s", name);
                } else {
                    if (out->mbox[0] && strcmp(out->mbox, name) == 0) {
                        patch_bad(out, key);
                        return JMAPD_PATCH_E_EMPTY;
                    }
                    /* Removing a mailbox the Email is not in: no-op. */
                }
            }
        } else {
            /* Every other Email property is immutable through /set (RFC 8621
               4.6: only mailboxIds and keywords may be updated). */
            patch_bad(out, key);
            return JMAPD_PATCH_E_PATH;
        }
    }
    out->mbox_moved = cur_mbox && strcmp(cur_mbox, out->mbox) != 0;
    return JMAPD_PATCH_OK;
}

/* ------------------------------------------------------------------ */
/* A growable message buffer, capped by the server's max message size  */
/* ------------------------------------------------------------------ */

typedef struct Buf {
    char  *p;
    size_t n, cap;
    size_t max;      /* 0 = unbounded */
    bool   err;
} Buf;

static void buf_need(Buf *b, size_t extra) {
    size_t need, nc;
    char *np;
    if (b->err) return;
    if (extra > SIZE_MAX - b->n) { b->err = true; return; }
    need = b->n + extra;
    if (b->max && need > b->max) { b->err = true; return; }
    if (need + 1 <= b->cap) return;
    nc = b->cap ? b->cap : 1024;
    while (nc < need + 1) {
        if (nc > SIZE_MAX / 2) { b->err = true; return; }
        nc *= 2;
    }
    np = realloc(b->p, nc);
    if (!np) { b->err = true; return; }
    b->p = np;
    b->cap = nc;
}

static void buf_add(Buf *b, const void *s, size_t n) {
    buf_need(b, n);
    if (b->err) return;
    memcpy(b->p + b->n, s, n);
    b->n += n;
    b->p[b->n] = '\0';
}

static void buf_str(Buf *b, const char *s) { buf_add(b, s, strlen(s)); }

static void buf_fmt(Buf *b, const char *fmt, ...) {
    char tmp[2048];
    va_list ap;
    int n;
    va_start(ap, fmt);
    n = vsnprintf(tmp, sizeof tmp, fmt, ap);
    va_end(ap);
    if (n < 0 || (size_t)n >= sizeof tmp) { b->err = true; return; }
    buf_add(b, tmp, (size_t)n);
}

/* ------------------------------------------------------------------ */
/* Header values: no CR/LF, no control bytes (header injection)        */
/* ------------------------------------------------------------------ */

static bool hdr_ok(const char *s) {
    size_t i;
    if (!s) return false;
    for (i = 0; s[i]; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c == '\r' || c == '\n') return false;
        if (c < 0x20 && c != '\t') return false;
        if (c == 0x7f) return false;
    }
    return true;
}

/* A display name, quoted only when RFC 5322 requires it. */
static void buf_display(Buf *b, const char *name) {
    static const char specials[] = "()<>@,;:\\\".[]";
    bool quote = false;
    size_t i;
    if (!name || !name[0]) return;
    if (name[0] == ' ' || name[strlen(name) - 1] == ' ') quote = true;
    for (i = 0; name[i] && !quote; i++)
        if (strchr(specials, name[i])) quote = true;
    if (!quote) {
        buf_str(b, name);
        return;
    }
    buf_str(b, "\"");
    for (i = 0; name[i]; i++) {
        if (name[i] == '"' || name[i] == '\\') buf_str(b, "\\");
        buf_add(b, &name[i], 1);
    }
    buf_str(b, "\"");
}

/* One JMAP address list -> an RFC 5322 header.  Returns NULL on success or the
   offending JMAP property name when an address is not a valid addr-spec. */
static const char *addr_header(Buf *b, const char *hdr, const char *prop,
                               const JmapJsonNode *arr) {
    size_t i, n;
    if (!arr || arr->type == JMAP_JSON_NULL) return NULL;
    if (arr->type != JMAP_JSON_ARR) return prop;
    n = jmap_json_count(arr);
    if (n == 0) return NULL;
    buf_fmt(b, "%s: ", hdr);
    for (i = 0; i < n; i++) {
        const JmapJsonNode *e = jmap_json_at(arr, i);
        const JmapJsonNode *em, *nm;
        const char *email, *name = NULL;
        char *local = NULL, *domain = NULL;
        if (!e || e->type != JMAP_JSON_OBJ) return prop;
        em = jmap_json_get(e, "email");
        nm = jmap_json_get(e, "name");
        if (jmap_json_str(em, &email, NULL) != 0) return prop;
        if (nm && nm->type != JMAP_JSON_NULL) {
            if (jmap_json_str(nm, &name, NULL) != 0) return prop;
            if (!hdr_ok(name)) return prop;
        }
        if (!hdr_ok(email)) return prop;
        if (mail_addr_parse(email, &local, &domain) != 0) return prop;
        free(local);
        free(domain);
        if (i) buf_str(b, ", ");
        if (name && name[0]) {
            buf_display(b, name);
            buf_fmt(b, " <%s>", email);
        } else {
            buf_str(b, email);
        }
    }
    buf_str(b, "\r\n");
    return NULL;
}

/* An Id[] header value (In-Reply-To / References): space-joined. */
static const char *id_header(Buf *b, const char *hdr, const char *prop,
                             const JmapJsonNode *arr) {
    size_t i, n;
    if (!arr || arr->type == JMAP_JSON_NULL) return NULL;
    if (arr->type != JMAP_JSON_ARR) return prop;
    n = jmap_json_count(arr);
    if (n == 0) return NULL;
    buf_fmt(b, "%s:", hdr);
    for (i = 0; i < n; i++) {
        const char *s;
        if (jmap_json_str(jmap_json_at(arr, i), &s, NULL) != 0) return prop;
        if (!hdr_ok(s)) return prop;
        buf_fmt(b, " %s", s);
    }
    buf_str(b, "\r\n");
    return NULL;
}

/* ------------------------------------------------------------------ */
/* Message body: text and/or html -> one MIME body                     */
/* ------------------------------------------------------------------ */

/* The value of bodyValues[partId].value for a body list's first part, or NULL
   when the list is absent/empty or the value is missing. */
static const char *body_part_value(const JmapJsonNode *email,
                                   const char *listkey) {
    const JmapJsonNode *list, *bv, *p0, *pid, *val;
    const char *s;
    list = jmap_json_get(email, listkey);
    if (!list || list->type != JMAP_JSON_ARR) return NULL;
    if (jmap_json_count(list) == 0) return NULL;
    p0 = jmap_json_at(list, 0);
    if (!p0 || p0->type != JMAP_JSON_OBJ) return NULL;
    pid = jmap_json_get(p0, "partId");
    if (jmap_json_str(pid, &s, NULL) != 0) return NULL;
    bv = jmap_json_get(email, "bodyValues");
    if (!bv || bv->type != JMAP_JSON_OBJ) return NULL;
    val = jmap_json_get(bv, s);
    if (!val || val->type != JMAP_JSON_OBJ) return NULL;
    if (jmap_json_str(jmap_json_get(val, "value"), &s, NULL) != 0) return NULL;
    return s;
}

/* A body value is a C0-free, CRLF-normalized octet stream: imapd's delivery
   rejects NUL/C0 controls outright, so a body carrying one is refused here
   rather than failing later with no explanation. */
static bool body_ok(const char *s) {
    size_t i;
    for (i = 0; s[i]; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c == '\t' || c == '\r' || c == '\n') continue;
        if (c < 0x20 || c == 0x7f) return false;
    }
    return true;
}

static void buf_body_text(Buf *b, const char *s) {
    size_t i, start = 0;
    for (i = 0; s[i]; i++) {
        if (s[i] != '\n' && s[i] != '\r') continue;
        buf_add(b, s + start, i - start);
        if (s[i] == '\r' && s[i + 1] == '\n') i++;
        buf_str(b, "\r\n");
        start = i + 1;
    }
    if (s[start]) buf_str(b, s + start);
}

/* Does the body contain a line that would be read as this boundary? */
static bool boundary_collides(const char *text, const char *html,
                              const char *boundary) {
    char needle[128];
    const char *bodies[2];
    size_t i;
    snprintf(needle, sizeof needle, "--%s", boundary);
    bodies[0] = text;
    bodies[1] = html;
    for (i = 0; i < 2; i++) {
        const char *p = bodies[i];
        if (!p) continue;
        if (strncmp(p, needle, strlen(needle)) == 0) return true;
        while ((p = strstr(p, needle)) != NULL) {
            if (p > bodies[i] && (p[-1] == '\n' || p[-1] == '\r')) return true;
            p++;
        }
    }
    return false;
}

/* ------------------------------------------------------------------ */
/* Creating one Email                                                  */
/* ------------------------------------------------------------------ */

typedef struct Created {
    char   id[JMAPD_ID_MAX];
    char   thread[JMAPD_ID_MAX];
    size_t size;
} Created;

/* A mailbox name from a JMAP mailbox id, provided the mailbox exists. */
static int mailbox_by_id(JmapdServer *srv, const char *user, const char *id,
                         char *name, size_t namesz) {
    char dir[4096];
    struct stat sb;
    if (jmapd_id_mailbox_parse(id, name, namesz) != 0) return -1;
    if (imapd_mbox_dir(&srv->icfg, user, name, dir, sizeof dir) != 0) return -1;
    if (stat(dir, &sb) != 0 || !S_ISDIR(sb.st_mode)) return -1;
    return 0;
}

/* The mailbox a create puts the message in: exactly one, and it must exist. */
static const char *create_mailbox(JmapdServer *srv, const char *user,
                                  const JmapJsonNode *email, char *name,
                                  size_t namesz) {
    const JmapJsonNode *mbs = jmap_json_get(email, "mailboxIds");
    size_t n, i, ntrue = 0;
    if (!mbs || mbs->type != JMAP_JSON_OBJ) return "invalidProperties";
    n = jmap_json_count(mbs);
    for (i = 0; i < n; i++) {
        const JmapJsonNode *e = jmap_json_at(mbs, i);
        bool on = false;
        char nm[IMAPD_MAX_MBOX + 1];
        if (!e || !e->key) continue;
        if (e->type != JMAP_JSON_BOOL) return "invalidProperties";
        (void)jmap_json_bool(e, &on);
        if (!on) continue;
        if (mailbox_by_id(srv, user, e->key, nm, sizeof nm) != 0)
            return "invalidProperties";
        ntrue++;
        if (ntrue > 1) return "tooManyMailboxes";
        snprintf(name, namesz, "%s", nm);
    }
    if (ntrue == 0) return "invalidProperties";
    return NULL;
}

/* Keywords of a create -> maildir flags.  NULL on success. */
static const char *create_flags(const JmapJsonNode *email, uint8_t *flags) {
    const JmapJsonNode *kw = jmap_json_get(email, "keywords");
    size_t n, i;
    *flags = 0;
    if (!kw || kw->type == JMAP_JSON_NULL) return NULL;
    if (kw->type != JMAP_JSON_OBJ) return "invalidProperties";
    n = jmap_json_count(kw);
    for (i = 0; i < n; i++) {
        const JmapJsonNode *e = jmap_json_at(kw, i);
        uint8_t f = 0;
        bool on = false;
        if (!e || !e->key) continue;
        if (jmapd_kw_flag(e->key, e->keylen, &f) != 0) return "invalidProperties";
        if (e->type != JMAP_JSON_BOOL) return "invalidProperties";
        (void)jmap_json_bool(e, &on);
        if (on) *flags |= f;
    }
    return NULL;
}

/* Build the message.  Returns NULL on success (with *out / *outlen set) or a
   SetError type name, with *propp naming the offending property. */
static const char *create_message(JmapdServer *srv, const JmapJsonNode *email,
                                  const char *user, char **out, size_t *outlen,
                                  const char **propp) {
    Buf b;
    const JmapJsonNode *v;
    const char *text, *html, *bad;
    char boundary[96];
    char hostname[256];
    char date[64];
    time_t now = time(NULL);
    struct tm tm;
    int attempt;

    *out = NULL;
    *outlen = 0;
    *propp = NULL;
    memset(&b, 0, sizeof b);
    b.max = srv->icfg.max_msg ? srv->icfg.max_msg : IMAPD_DEFAULT_MAX_MSG;

    /* The client sends no attachments; a non-empty list is refused rather than
       silently dropped (maxSizeAttachmentsPerEmail is advertised as 0). */
    v = jmap_json_get(email, "attachments");
    if (v && v->type == JMAP_JSON_ARR && jmap_json_count(v) > 0) {
        *propp = "attachments";
        return "invalidProperties";
    }

    text = body_part_value(email, "textBody");
    html = body_part_value(email, "htmlBody");
    if (text && !body_ok(text)) { *propp = "bodyValues"; return "invalidProperties"; }
    if (html && !body_ok(html)) { *propp = "bodyValues"; return "invalidProperties"; }

    /* Boundary: unique per message and never collidable with the body. */
    snprintf(hostname, sizeof hostname, "%s",
             (srv->cfg.hostname && srv->cfg.hostname[0]) ? srv->cfg.hostname
                                                         : "localhost");
    for (attempt = 0; ; attempt++) {
        snprintf(boundary, sizeof boundary, "=_jmapd_%lx_%lx_%x",
                 (unsigned long)now, (unsigned long)getpid(), (unsigned)attempt);
        if (!boundary_collides(text, html, boundary)) break;
        if (attempt >= 3) { *propp = "bodyValues"; return "invalidProperties"; }
    }

    if (!gmtime_r(&now, &tm)) return "serverFail";
    snprintf(date, sizeof date, "%s, %02d %s %04d %02d:%02d:%02d +0000",
             (const char *[]){ "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" }
                 [tm.tm_wday],
             tm.tm_mday,
             (const char *[]){ "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul",
                               "Aug", "Sep", "Oct", "Nov", "Dec" }[tm.tm_mon],
             tm.tm_year + 1900, tm.tm_hour, tm.tm_min, tm.tm_sec);

    /* ---- headers ---- */
    bad = addr_header(&b, "From", "from", jmap_json_get(email, "from"));
    if (!bad) bad = addr_header(&b, "To", "to", jmap_json_get(email, "to"));
    if (!bad) bad = addr_header(&b, "Cc", "cc", jmap_json_get(email, "cc"));
    if (!bad) bad = addr_header(&b, "Bcc", "bcc", jmap_json_get(email, "bcc"));
    if (!bad)
        bad = addr_header(&b, "Reply-To", "replyTo",
                          jmap_json_get(email, "replyTo"));
    if (bad) {
        free(b.p);
        *propp = bad;
        return "invalidProperties";
    }

    v = jmap_json_get(email, "subject");
    if (v && v->type != JMAP_JSON_NULL) {
        const char *s;
        if (jmap_json_str(v, &s, NULL) != 0 || !hdr_ok(s)) {
            free(b.p);
            *propp = "subject";
            return "invalidProperties";
        }
        if (s[0]) buf_fmt(&b, "Subject: %s\r\n", s);
    }
    buf_fmt(&b, "Date: %s\r\n", date);

    /* Message-ID: the client's, when it named exactly one, else ours. */
    v = jmap_json_get(email, "messageId");
    if (v && v->type == JMAP_JSON_ARR && jmap_json_count(v) == 1) {
        const char *s;
        if (jmap_json_str(jmap_json_at(v, 0), &s, NULL) == 0 && hdr_ok(s) && s[0])
            buf_fmt(&b, "Message-ID: %s\r\n", s);
        else
            buf_fmt(&b, "Message-ID: <jmapd.%lx.%lx@%s>\r\n",
                    (unsigned long)now, (unsigned long)getpid(), hostname);
    } else {
        buf_fmt(&b, "Message-ID: <jmapd.%lx.%lx@%s>\r\n", (unsigned long)now,
                (unsigned long)getpid(), hostname);
    }
    bad = id_header(&b, "In-Reply-To", "inReplyTo",
                    jmap_json_get(email, "inReplyTo"));
    if (!bad)
        bad = id_header(&b, "References", "references",
                        jmap_json_get(email, "references"));
    if (bad) {
        free(b.p);
        *propp = bad;
        return "invalidProperties";
    }

    buf_str(&b, "MIME-Version: 1.0\r\n");

    /* ---- body ---- */
    if (text && html) {
        buf_fmt(&b, "Content-Type: multipart/alternative; boundary=\"%s\"\r\n"
                    "\r\n", boundary);
        buf_fmt(&b, "--%s\r\nContent-Type: text/plain; charset=utf-8\r\n"
                    "Content-Transfer-Encoding: 8bit\r\n\r\n", boundary);
        buf_body_text(&b, text);
        buf_str(&b, "\r\n");
        buf_fmt(&b, "--%s\r\nContent-Type: text/html; charset=utf-8\r\n"
                    "Content-Transfer-Encoding: 8bit\r\n\r\n", boundary);
        buf_body_text(&b, html);
        buf_fmt(&b, "\r\n--%s--\r\n", boundary);
    } else if (html) {
        buf_str(&b, "Content-Type: text/html; charset=utf-8\r\n"
                    "Content-Transfer-Encoding: 8bit\r\n\r\n");
        buf_body_text(&b, html);
    } else {
        buf_str(&b, "Content-Type: text/plain; charset=utf-8\r\n"
                    "Content-Transfer-Encoding: 8bit\r\n\r\n");
        if (text) buf_body_text(&b, text);
    }
    if (b.err) {
        free(b.p);
        /* The buffer cap is the server's max message size: the honest answer
           for an oversized create (RFC 8620 5.3 SetError). */
        return "tooLarge";
    }
    *out = b.p;
    *outlen = b.n;
    (void)user;
    return NULL;
}

/* Find the message just delivered: by uid when the registration worked, else
   the newest message in the mailbox. */
static int create_locate(JmapdServer *srv, const char *user, const char *mbox,
                         uint32_t uid, time_t t0, JmapdEmail *e) {
    Mbox mb;
    size_t i;
    Imail *pick = NULL;
    memset(e, 0, sizeof *e);
    if (imapd_mbox_peek(&srv->icfg, user, mbox, &mb) != 0) return -1;
    for (i = 0; i < mb.nmsgs; i++) {
        Imail *m = &mb.msgs[i];
        if (uid && m->uid != uid) continue;
        if (!uid && m->internal_date < t0) continue;
        if (!pick || m->uid > pick->uid) pick = m;
    }
    if (!pick) {
        imapd_mbox_close(&mb);
        return -1;
    }
    snprintf(e->base, sizeof e->base, "%s", pick->base ? pick->base : "");
    snprintf(e->mbox, sizeof e->mbox, "%s", mbox);
    snprintf(e->path, sizeof e->path, "%s", pick->path ? pick->path : "");
    e->size = pick->size;
    e->internal_date = pick->internal_date;
    e->flags = pick->flags;
    e->uid = pick->uid;
    if (pick->mid) snprintf(e->mid, sizeof e->mid, "%s", pick->mid);
    e->found = true;
    imapd_mbox_close(&mb);
    return e->base[0] ? 0 : -1;
}

/* Build, deliver and identify one created Email.  Returns NULL on success or a
   SetError type name. */
static const char *create_one(JmapdServer *srv, const char *user,
                              const JmapJsonNode *email, Created *cr,
                              const char **propp) {
    char mbox[IMAPD_MAX_MBOX + 1];
    char *msg = NULL;
    size_t msglen = 0;
    uint8_t flags = 0;
    uint32_t uv = 0, uid = 0;
    time_t t0 = time(NULL);
    JmapdEmail e;
    const char *err;

    memset(cr, 0, sizeof *cr);
    *propp = NULL;
    if (!email || email->type != JMAP_JSON_OBJ) return "invalidProperties";
    err = create_mailbox(srv, user, email, mbox, sizeof mbox);
    if (err) {
        *propp = "mailboxIds";
        return err;
    }
    err = create_flags(email, &flags);
    if (err) {
        *propp = "keywords";
        return err;
    }
    err = create_message(srv, email, user, &msg, &msglen, propp);
    if (err) return err;
    /* The thread id comes from the message we built (its References decide it),
       not from a second read of the file we just wrote. */
    jmapd_thread_id_of(msg, msglen, mbox, cr->thread, sizeof cr->thread);
    if (imapd_mbox_deliver_uid(&srv->icfg, user, mbox, msg, msglen, flags, "",
                               &uv, &uid) != 0) {
        free(msg);
        return "serverFail";
    }
    free(msg);
    if (create_locate(srv, user, mbox, uid, t0, &e) != 0) return "serverFail";
    if (jmapd_id_email(e.base, NULL, cr->id, sizeof cr->id) != 0)
        return "serverFail";
    cr->size = e.size;
    return NULL;
}

/* ------------------------------------------------------------------ */
/* Response sections                                                   */
/* ------------------------------------------------------------------ */

typedef struct SetOut {
    JsonBuilder created, updated, destroyed;
    JsonBuilder notCreated, notUpdated, notDestroyed;
    size_t ncreated, nupdated, ndestroyed;
    size_t nnotc, nnotu, nnotd;
} SetOut;

static void setout_init(SetOut *so) {
    memset(so, 0, sizeof *so);
    jsonb_init(&so->created);
    jsonb_init(&so->updated);
    jsonb_init(&so->destroyed);
    jsonb_init(&so->notCreated);
    jsonb_init(&so->notUpdated);
    jsonb_init(&so->notDestroyed);
    jsonb_begin_object(&so->created);
    jsonb_begin_object(&so->updated);
    jsonb_begin_array(&so->destroyed);
    jsonb_begin_object(&so->notCreated);
    jsonb_begin_object(&so->notUpdated);
    jsonb_begin_object(&so->notDestroyed);
}

/* Close every section builder: a section is spliced into the response as
   finished JSON, so its container must be ended first. */
static void setout_finish(SetOut *so) {
    jsonb_end_object(&so->created);
    jsonb_end_object(&so->updated);
    jsonb_end_array(&so->destroyed);
    jsonb_end_object(&so->notCreated);
    jsonb_end_object(&so->notUpdated);
    jsonb_end_object(&so->notDestroyed);
}

/* jsonb_detach() HANDS BACK the buffer (it does not free it), so discarding a
   builder means detaching and freeing. */
static void jb_discard(JsonBuilder *b) {
    char *p = jsonb_detach(b, NULL);
    free(p);
}

static void setout_free(SetOut *so) {
    jb_discard(&so->created);
    jb_discard(&so->updated);
    jb_discard(&so->destroyed);
    jb_discard(&so->notCreated);
    jb_discard(&so->notUpdated);
    jb_discard(&so->notDestroyed);
}

/* One SetError object: {"type":...,"properties":[...],"description":...}. */
static void set_error(JsonBuilder *b, const char *type, const char *prop,
                      const char *desc) {
    jsonb_begin_object(b);
    jsonb_key(b, "type");
    jsonb_str(b, type);
    if (prop && prop[0]) {
        jsonb_comma(b);
        jsonb_key(b, "properties");
        jsonb_begin_array(b);
        jsonb_str(b, prop);
        jsonb_end_array(b);
    }
    if (desc && desc[0]) {
        jsonb_comma(b);
        jsonb_key(b, "description");
        jsonb_str(b, desc);
    }
    jsonb_end_object(b);
}

/* The property name of a patch path ("keywords/$seen" -> "keywords"). */
static void path_prop(const char *path, char *out, size_t outsz) {
    size_t i;
    for (i = 0; path[i] && path[i] != '/' && i + 1 < outsz; i++) out[i] = path[i];
    out[i] = '\0';
}

/* ------------------------------------------------------------------ */
/* Email/set                                                           */
/* ------------------------------------------------------------------ */

/* An open mailbox view, reused while consecutive operations name the same
   mailbox: one scan per mailbox per request, not one per Email. */
typedef struct SetMbox {
    Mbox mb;
    char name[IMAPD_MAX_MBOX + 1];
    bool open;
} SetMbox;

static void setmbox_close(SetMbox *m) {
    if (m->open) {
        imapd_mbox_close(&m->mb);
        m->open = false;
    }
}

static int setmbox_open(JmapdServer *srv, const char *user, SetMbox *m,
                        const char *name) {
    if (m->open && strcmp(m->name, name) == 0) return 0;
    setmbox_close(m);
    if (imapd_mbox_peek(&srv->icfg, user, name, &m->mb) != 0) return -1;
    snprintf(m->name, sizeof m->name, "%s", name);
    m->open = true;
    return 0;
}

static Imail *mbox_find_base(Mbox *mb, const char *base) {
    size_t i;
    for (i = 0; i < mb->nmsgs; i++)
        if (mb->msgs[i].base && strcmp(mb->msgs[i].base, base) == 0)
            return &mb->msgs[i];
    return NULL;
}

/* Does the account have this mailbox?  (Inbox always does.) */
static bool mailbox_exists(JmapdServer *srv, const char *user, const char *name) {
    char dir[4096];
    struct stat sb;
    if (imapd_mbox_dir(&srv->icfg, user, name, dir, sizeof dir) != 0)
        return false;
    return stat(dir, &sb) == 0 && S_ISDIR(sb.st_mode);
}

/* The WRITE half of an Email update: apply `patch` to the Email `loc` names,
   writing the maildir flags and/or moving the file.  `view` is a mailbox view
   the caller keeps open across a loop (Email/set's update section) or NULL
   (then one is opened and closed here, which is what EmailSubmission/set's
   implicit Email/set does).  Returns 0, or -1 with *err_type set to an RFC
   8621 SetError type and err_desc filled in.  Pure of any response builder,
   so both callers report the same failure the same way. */
static int update_write(JmapdServer *srv, const char *user,
                        const JmapdEmail *loc, const JmapJsonNode *patch,
                        SetMbox *view, const char **err_type, char *err_desc,
                        size_t descsz, unsigned *changed) {
    JmapdEmailPatch np;
    JmapdPatchErr perr;
    SetMbox local;
    Imail *m;
    char prop[64];
    bool wrote = false, own_view = false;

    if (err_type) *err_type = "invalidProperties";
    if (err_desc && descsz) err_desc[0] = '\0';
    if (!patch || patch->type != JMAP_JSON_OBJ) {
        if (err_type) *err_type = "invalidPatch";
        return -1;
    }
    if (!view) {
        memset(&local, 0, sizeof local);
        view = &local;
        own_view = true;
    }
    perr = jmapd_patch_apply(patch, loc->mbox, loc->flags, &np);
    if (perr != JMAPD_PATCH_OK) {
        const char *type = "invalidProperties";
        if (perr == JMAPD_PATCH_E_MULTI) type = "tooManyMailboxes";
        if (perr == JMAPD_PATCH_E_TYPE) type = "invalidPatch";
        if (err_type) *err_type = type;
        path_prop(np.bad, prop, sizeof prop);
        if (err_desc && descsz) snprintf(err_desc, descsz, "%s", np.bad);
        if (own_view) setmbox_close(view);
        return -1;
    }
    if (np.mbox_moved && !mailbox_exists(srv, user, np.mbox)) {
        if (err_desc && descsz) snprintf(err_desc, descsz, "no such mailbox");
        if (own_view) setmbox_close(view);
        return -1;
    }
    if (setmbox_open(srv, user, view, loc->mbox) != 0) {
        if (err_type) *err_type = "serverFail";
        if (err_desc && descsz) snprintf(err_desc, descsz, "mailbox unreadable");
        if (own_view) setmbox_close(view);
        return -1;
    }
    m = mbox_find_base(&view->mb, loc->base);
    if (!m) {
        if (err_type) *err_type = "notFound";
        if (own_view) setmbox_close(view);
        return -1;
    }
    if (!np.mbox_moved && np.flags == m->flags) {
        if (own_view) setmbox_close(view);  /* nothing to write: success */
        return 0;
    }
    if (np.flags != m->flags) {
        if (imapd_mbox_store(&view->mb, m->uid, np.flags) != 0) {
            if (err_type) *err_type = "serverFail";
            if (err_desc && descsz)
                snprintf(err_desc, descsz, "could not set keywords");
            if (own_view) setmbox_close(view);
            return -1;
        }
        wrote = true;
    }
    if (np.mbox_moved) {
        /* MOVE: the base name (the Email id) survives, by construction. */
        uint32_t uv = 0, uid = 0;
        if (imapd_mbox_file(&srv->icfg, user, &view->mb, m->uid, np.mbox, true,
                            &uv, &uid) != 0) {
            /* A half-applied patch (flags written, move failed) still changed
               the maildir, so the state must move even though this object is
               reported as not updated: the client refetches and sees the
               truth. */
            if (wrote && changed) (*changed)++;
            if (err_type) *err_type = "serverFail";
            if (err_desc && descsz) snprintf(err_desc, descsz, "could not move");
            if (own_view) setmbox_close(view);
            return -1;
        }
        wrote = true;
    }
    if (own_view) setmbox_close(view);
    if (wrote && changed) (*changed)++;
    return 0;
}

/* Exported for EmailSubmission/set: RFC 8621 7.5's onSuccessUpdateEmail is an
   implicit Email/set call, so it applies the SAME patch applier and the same
   maildir writes as Email/set's update. */
int jmapd_email_update(JmapdServer *srv, const char *user,
                       const JmapdEmail *loc, const JmapJsonNode *patch,
                       const char **err_type, char *err_desc, size_t descsz,
                       unsigned *changed) {
    return update_write(srv, user, loc, patch, NULL, err_type, err_desc, descsz,
                        changed);
}

static void set_update_one(JmapdServer *srv, const char *user,
                           const JmapdEmail *loc, const JmapJsonNode *patch,
                           SetMbox *view, SetOut *so, const char *id,
                           unsigned *changed) {
    const char *err_type = NULL;
    char desc[320];

    if (update_write(srv, user, loc, patch, view, &err_type, desc, sizeof desc,
                     changed) != 0) {
        char prop[64];
        JmapdEmailPatch np;
        memset(&np, 0, sizeof np);
        /* Re-derive the offending path for the SetError's `properties`: the
           applier is pure, so a second call on the same patch costs nothing
           and keeps update_write free of response-builder knowledge. */
        (void)jmapd_patch_apply(patch, loc->mbox, loc->flags, &np);
        path_prop(np.bad, prop, sizeof prop);
        jsonb_key(&so->notUpdated, id);
        set_error(&so->notUpdated, err_type ? err_type : "serverFail",
                  prop[0] ? prop : NULL, desc[0] ? desc : NULL);
        so->nnotu++;
        return;
    }
    jsonb_key(&so->updated, id);
    jmapd_jb_lit(&so->updated, "null");
    so->nupdated++;
}

static void set_destroy_one(JmapdServer *srv, const char *user,
                            const JmapdEmail *loc, SetMbox *view, SetOut *so,
                            const char *id, unsigned *changed) {
    Imail *m;
    if (setmbox_open(srv, user, view, loc->mbox) != 0) {
        jsonb_key(&so->notDestroyed, id);
        set_error(&so->notDestroyed, "serverFail", NULL, "mailbox unreadable");
        so->nnotd++;
        return;
    }
    m = mbox_find_base(&view->mb, loc->base);
    if (!m) {
        jsonb_key(&so->notDestroyed, id);
        set_error(&so->notDestroyed, "notFound", NULL, NULL);
        so->nnotd++;
        return;
    }
    if (imapd_mbox_expunge(&view->mb, m->uid) != 0) {
        jsonb_key(&so->notDestroyed, id);
        set_error(&so->notDestroyed, "serverFail", NULL, "could not delete");
        so->nnotd++;
        return;
    }
    if (so->ndestroyed) jsonb_comma(&so->destroyed);
    jsonb_str(&so->destroyed, id);
    so->ndestroyed++;
    (*changed)++;
}

int jmapd_method_email_set(JmapdCtx *ctx, const JmapJsonNode *args,
                           JsonBuilder *out) {
    JmapdServer *srv = ctx->srv;
    const char *user = ctx->user;
    const JmapJsonNode *create = jmapd_arg(ctx, args, "create");
    const JmapJsonNode *update = jmapd_arg(ctx, args, "update");
    const JmapJsonNode *destroy = jmapd_arg(ctx, args, "destroy");
    const JmapJsonNode *ifstate = jmapd_arg(ctx, args, "ifInState");
    JmapdState st;
    char old_state[32], new_state[32];
    SetOut so;
    SetMbox view;
    JmapdEmail *want = NULL;
    unsigned changed = 0;
    size_t i, n;

    if (ctx->argerr) { jmapd_jb_method_error(out, ctx->argerr); return 0; }
    memset(&view, 0, sizeof view);
    jmapd_state_load(srv, user, &st);
    jmapd_state_sync(srv, user, &st);
    if (jmapd_state_fmt('e', st.email, old_state, sizeof old_state) != 0)
        return -1;
    if (ifstate && ifstate->type != JMAP_JSON_NULL) {
        const char *s;
        if (jmap_json_str(ifstate, &s, NULL) != 0) {
            jmapd_jb_method_error(out, "invalidArguments");
            return 0;
        }
        if (strcmp(s, old_state) != 0) {
            /* RFC 8620 5.3: the set call is rejected WHOLE — a method-level
               error in this call's response, not a per-object one, and not a
               request-level (HTTP 400) failure: the rest of the request still
               runs. */
            jmapd_jb_method_error(out, "stateMismatch");
            return 0;
        }
    }
    if (create && create->type == JMAP_JSON_NULL) create = NULL;
    if (update && update->type == JMAP_JSON_NULL) update = NULL;
    if (destroy && destroy->type == JMAP_JSON_NULL) destroy = NULL;
    if ((create && create->type != JMAP_JSON_OBJ) ||
        (update && update->type != JMAP_JSON_OBJ) ||
        (destroy && destroy->type != JMAP_JSON_ARR)) {
        jmapd_jb_method_error(out, "invalidArguments");
        return 0;
    }
    /* Every destroy id must be a string: a non-string one cannot be echoed in
       destroyed/notDestroyed, and dropping it silently would lose a request the
       client believes it made.  Checked BEFORE any write. */
    if (destroy) {
        size_t k, nd = jmap_json_count(destroy);
        for (k = 0; k < nd; k++) {
            const char *s;
            if (jmap_json_str(jmap_json_at(destroy, k), &s, NULL) != 0) {
                jmapd_jb_method_error(out, "invalidArguments");
                return 0;
            }
        }
    }
    n = (create ? jmap_json_count(create) : 0) +
        (update ? jmap_json_count(update) : 0) +
        (destroy ? jmap_json_count(destroy) : 0);
    if (n > JMAPD_MAX_SET) {
        jmapd_jb_method_error(out, "requestTooLarge");
        return 0;
    }

    /* The role mailboxes must exist before a create can name one. */
    jmapd_account_prepare(srv, user);
    setout_init(&so);

    /* ---- create: deliver each message, then identify it by base name ---- */
    if (create) {
        n = jmap_json_count(create);
        for (i = 0; i < n; i++) {
            const JmapJsonNode *e = jmap_json_at(create, i);
            const char *cid = (e && e->key) ? e->key : "";
            Created cr;
            const char *err, *prop = NULL;
            if (!e || !e->key) continue;
            err = create_one(srv, user, e, &cr, &prop);
            if (err) {
                jsonb_key(&so.notCreated, cid);
                set_error(&so.notCreated, err, prop, NULL);
                so.nnotc++;
                continue;
            }
            jsonb_key(&so.created, cid);
            jsonb_begin_object(&so.created);
            jsonb_key(&so.created, "id");
            jsonb_str(&so.created, cr.id);
            jsonb_comma(&so.created);
            jsonb_key(&so.created, "threadId");
            jsonb_str(&so.created, cr.thread);
            jsonb_comma(&so.created);
            jsonb_key(&so.created, "size");
            jmapd_jb_u64(&so.created, (uint64_t)cr.size);
            jsonb_end_object(&so.created);
            so.ncreated++;
            changed++;
        }
    }

    /* ---- update: locate every id first (one pass over the account) ---- */
    want = calloc(JMAPD_MAX_SET, sizeof *want);
    if (!want) {
        setout_free(&so);
        return -1;
    }
    if (update && jmap_json_count(update) > 0) {
        size_t nu = jmap_json_count(update), k;
        if (nu > JMAPD_MAX_SET) nu = JMAPD_MAX_SET;
        memset(want, 0, JMAPD_MAX_SET * sizeof *want);
        for (k = 0; k < nu; k++) {
            const JmapJsonNode *e = jmap_json_at(update, k);
            const char *id;
            size_t idlen;
            if (!e || !e->key) continue;
            id = e->key;
            idlen = e->keylen;
            if (jmapd_id_email_parse(id, want[k].base, sizeof want[k].base,
                                     want[k].mbox, sizeof want[k].mbox) != 0)
                continue;
            snprintf(want[k].id, sizeof want[k].id, "%.*s", (int)idlen, id);
        }
        (void)jmapd_email_locate(srv, user, want, nu);
        for (k = 0; k < nu; k++) {
            const JmapJsonNode *e = jmap_json_at(update, k);
            if (!e || !e->key) continue;
            if (!want[k].found || !want[k].id[0]) {
                jsonb_key(&so.notUpdated, e->key);
                set_error(&so.notUpdated, "notFound", NULL, NULL);
                so.nnotu++;
                continue;
            }
            set_update_one(srv, user, &want[k], e, &view, &so, want[k].id,
                           &changed);
        }
    }

    /* ---- destroy ---- */
    if (destroy && jmap_json_count(destroy) > 0) {
        size_t nd = jmap_json_count(destroy), k;
        if (nd > JMAPD_MAX_SET) nd = JMAPD_MAX_SET;
        memset(want, 0, JMAPD_MAX_SET * sizeof *want);
        for (k = 0; k < nd; k++) {
            const char *id;
            size_t idlen;
            if (jmap_json_str(jmap_json_at(destroy, k), &id, &idlen) != 0)
                continue;
            if (jmapd_id_email_parse(id, want[k].base, sizeof want[k].base,
                                     want[k].mbox, sizeof want[k].mbox) != 0)
                continue;
            snprintf(want[k].id, sizeof want[k].id, "%.*s", (int)idlen, id);
        }
        (void)jmapd_email_locate(srv, user, want, nd);
        for (k = 0; k < nd; k++) {
            const char *id;
            if (jmap_json_str(jmap_json_at(destroy, k), &id, NULL) != 0) continue;
            if (!want[k].found || !want[k].id[0]) {
                jsonb_key(&so.notDestroyed, id);
                set_error(&so.notDestroyed, "notFound", NULL, NULL);
                so.nnotd++;
                continue;
            }
            set_destroy_one(srv, user, &want[k], &view, &so, want[k].id,
                            &changed);
        }
    }
    setmbox_close(&view);
    free(want);

    if (changed) {
        jmapd_state_bump(srv, user, &st, JMAPD_ST_EMAIL | JMAPD_ST_MAILBOX |
                                           JMAPD_ST_THREAD);
    }
    if (jmapd_state_fmt('e', st.email, new_state, sizeof new_state) != 0) {
        setout_free(&so);
        return -1;
    }

    setout_finish(&so);
    jsonb_begin_object(out);
    jsonb_key(out, "accountId"); jsonb_str(out, user);
    jsonb_comma(out);
    jsonb_key(out, "oldState"); jsonb_str(out, old_state);
    jsonb_comma(out);
    jsonb_key(out, "newState"); jsonb_str(out, new_state);
    if (so.ncreated) {
        jsonb_comma(out);
        jsonb_key(out, "created");
        jmapd_jb_lit(out, so.created.buf);
    }
    if (so.nupdated) {
        jsonb_comma(out);
        jsonb_key(out, "updated");
        jmapd_jb_lit(out, so.updated.buf);
    }
    if (so.ndestroyed) {
        jsonb_comma(out);
        jsonb_key(out, "destroyed");
        jmapd_jb_lit(out, so.destroyed.buf);
    }
    if (so.nnotc) {
        jsonb_comma(out);
        jsonb_key(out, "notCreated");
        jmapd_jb_lit(out, so.notCreated.buf);
    }
    if (so.nnotu) {
        jsonb_comma(out);
        jsonb_key(out, "notUpdated");
        jmapd_jb_lit(out, so.notUpdated.buf);
    }
    if (so.nnotd) {
        jsonb_comma(out);
        jsonb_key(out, "notDestroyed");
        jmapd_jb_lit(out, so.notDestroyed.buf);
    }
    jsonb_end_object(out);
    setout_free(&so);
    return 0;
}
