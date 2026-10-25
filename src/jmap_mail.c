/* jmap_mail.c — jmapd's mail data methods and the id codec.
 *
 * Serves Mailbox/get, Identity/get, Email/get and Thread/get.  All of them read
 * the SAME maildir tree imapd serves (imapd_mbox_peek / imapd_mbox_list /
 * imapd_mbox_create), so a mailbox created over IMAP shows up here and the
 * counts match STATUS.  Thread ids come from each message's own References
 * header (root first), so a conversation groups without a cross-message walk.
 *
 * Id scheme (plan DECISIONS 3), all of it inside RFC 8620's Id charset
 * (ALPHA / DIGIT / "-" / "_") by construction — every payload is base64url:
 *   Mailbox  "m" + b64url(maildir folder name)
 *   Email    "e" + b64url(maildir base name), or
 *            "f" + b64url(mailbox "\0" base) for the duplicate-base case (the
 *            only way two maildirs can hold the same base name is an IMAP
 *            COPY; the NUL separator cannot occur inside a component, so the
 *            split is unambiguous and a traversal attempt cannot be expressed
 *            — the decoder rejects anything that is not base64url BEFORE a
 *            byte reaches a path).
 *   Identity "i" + b64url(user)
 * The base name is what survives a flag rename, a MOVE and a uidlist rebuild
 * (imap_maildir.c keeps the base across all three), which is why it — not the
 * uid — is the Email identity. */
#include "visage.h"
#include "jmapd.h"
#include "mail.h"

#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <strings.h>
#include <unistd.h>

/* ------------------------------------------------------------------ */
/* base64url (RFC 4648 5, unpadded)                                    */
/* ------------------------------------------------------------------ */

static const char B64URL[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

int jmapd_b64url_encode(const unsigned char *in, size_t inlen, char *out,
                        size_t outsz) {
    size_t i = 0, o = 0;
    while (i + 3 <= inlen) {
        unsigned v = ((unsigned)in[i] << 16) | ((unsigned)in[i + 1] << 8) |
                     (unsigned)in[i + 2];
        if (o + 4 + 1 > outsz) return -1;
        out[o++] = B64URL[(v >> 18) & 63];
        out[o++] = B64URL[(v >> 12) & 63];
        out[o++] = B64URL[(v >> 6) & 63];
        out[o++] = B64URL[v & 63];
        i += 3;
    }
    if (inlen - i == 1) {
        unsigned v = (unsigned)in[i] << 16;
        if (o + 2 + 1 > outsz) return -1;
        out[o++] = B64URL[(v >> 18) & 63];
        out[o++] = B64URL[(v >> 12) & 63];
    } else if (inlen - i == 2) {
        unsigned v = ((unsigned)in[i] << 16) | ((unsigned)in[i + 1] << 8);
        if (o + 3 + 1 > outsz) return -1;
        out[o++] = B64URL[(v >> 18) & 63];
        out[o++] = B64URL[(v >> 12) & 63];
        out[o++] = B64URL[(v >> 6) & 63];
    }
    out[o] = '\0';
    return 0;
}

static int b64url_val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '-') return 62;
    if (c == '_') return 63;
    return -1;
}

int jmapd_b64url_decode(const char *in, size_t inlen, unsigned char *out,
                        size_t outsz, size_t *outlen) {
    size_t i, o = 0;
    unsigned acc = 0;
    int bits = 0;
    if (outlen) *outlen = 0;
    if (!in || !out) return -1;
    if (inlen % 4 == 1) return -1;          /* impossible base64url length */
    for (i = 0; i < inlen; i++) {
        int v = b64url_val(in[i]);
        if (v < 0) return -1;
        acc = (acc << 6) | (unsigned)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (o >= outsz) return -1;
            out[o++] = (unsigned char)((acc >> bits) & 0xFFu);
        }
    }
    /* Leftover bits must be zero, or two distinct ids decode to the same
       value and the id space stops being canonical. */
    if (bits > 0 && (acc & ((1u << bits) - 1u)) != 0) return -1;
    if (outlen) *outlen = o;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Id codec                                                            */
/* ------------------------------------------------------------------ */

/* A decoded maildir component must be usable as a path component: nonempty,
   bounded, no separator, no NUL/control byte, never "." or "..". */
static int component_ok(const char *s, size_t n) {
    size_t i;
    if (n == 0 || n > IMAPD_MAX_MBOX) return -1;
    if ((n == 1 && s[0] == '.') || (n == 2 && s[0] == '.' && s[1] == '.'))
        return -1;
    for (i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c == '/' || c == '\\' || c == '\0' || c < 0x20 || c == 0x7f)
            return -1;
    }
    return 0;
}

int jmapd_id_mailbox(const char *name, char *out, size_t outsz) {
    size_t n;
    if (!name || !out || outsz < 3) return -1;
    n = strlen(name);
    if (component_ok(name, n) != 0) return -1;
    out[0] = 'm';
    return jmapd_b64url_encode((const unsigned char *)name, n, out + 1,
                               outsz - 1);
}

int jmapd_id_mailbox_parse(const char *id, char *name, size_t namesz) {
    size_t n = 0;
    if (!id || id[0] != 'm' || !name || namesz < 2) return -1;
    if (jmapd_b64url_decode(id + 1, strlen(id + 1), (unsigned char *)name,
                            namesz - 1, &n) != 0)
        return -1;
    name[n] = '\0';
    return component_ok(name, n);
}

int jmapd_id_email(const char *base, const char *mbox, char *out, size_t outsz) {
    size_t bl;
    if (!base || !out || outsz < 3) return -1;
    bl = strlen(base);
    if (component_ok(base, bl) != 0) return -1;
    if (!mbox || !mbox[0]) {
        out[0] = 'e';
        return jmapd_b64url_encode((const unsigned char *)base, bl, out + 1,
                                   outsz - 1);
    }
    {
        /* "f" + b64url(mbox "\0" base): the NUL keeps the split unambiguous
           while every encoded byte stays inside the Id charset. */
        size_t ml = strlen(mbox), total = ml + 1 + bl;
        unsigned char *raw;
        int rc;
        if (component_ok(mbox, ml) != 0 || outsz < total * 4 / 3 + 3) return -1;
        raw = malloc(total);
        if (!raw) return -1;
        memcpy(raw, mbox, ml);
        raw[ml] = '\0';
        memcpy(raw + ml + 1, base, bl);
        out[0] = 'f';
        rc = jmapd_b64url_encode(raw, total, out + 1, outsz - 1);
        free(raw);
        return rc;
    }
}

int jmapd_id_email_parse(const char *id, char *base, size_t basesz,
                         char *mbox, size_t mboxsz) {
    unsigned char raw[JMAPD_ID_MAX + 1];
    size_t n = 0, i;
    if (!id || !base || basesz < 2) return -1;
    if (mbox) mbox[0] = '\0';
    if (id[0] != 'e' && id[0] != 'f') return -1;
    if (jmapd_b64url_decode(id + 1, strlen(id + 1), raw, sizeof raw - 1, &n)
            != 0)
        return -1;
    if (id[0] == 'e') {
        if (n + 1 > basesz) return -1;
        memcpy(base, raw, n);
        base[n] = '\0';
        return component_ok(base, n);
    }
    /* "f": split at the NUL. */
    for (i = 0; i < n; i++)
        if (raw[i] == '\0') break;
    if (i == n) return -1;                   /* no separator */
    if (mbox) {
        if (i + 1 > mboxsz) return -1;
        memcpy(mbox, raw, i);
        mbox[i] = '\0';
        if (component_ok(mbox, i) != 0) return -1;
    }
    if (n - i - 1 + 1 > basesz) return -1;
    memcpy(base, raw + i + 1, n - i - 1);
    base[n - i - 1] = '\0';
    return component_ok(base, n - i - 1);
}

/* Identity ids are per-user: "i" + b64url(user). */
int jmapd_identity_id(const char *user, char *out, size_t outsz) {
    if (!user || !out || outsz < 3) return -1;
    out[0] = 'i';
    return jmapd_b64url_encode((const unsigned char *)user, strlen(user),
                               out + 1, outsz - 1);
}

/* The account's own address: --identity/JMAPD_IDENTITY when configured, else
   <user>@<hostname>.  This is the address EmailSubmission defaults its
   envelope's MAIL FROM to (RFC 8621 7.5) and the one Identity/get reports. */
int jmapd_identity_email(JmapdServer *srv, const char *user, char *out,
                         size_t outsz) {
    const char *id;
    int n;
    if (!srv || !user || !out || outsz == 0) return -1;
    id = srv->cfg.identity;
    if (id && id[0]) {
        n = snprintf(out, outsz, "%s", id);
        return (n < 0 || (size_t)n >= outsz) ? -1 : 0;
    }
    n = snprintf(out, outsz, "%s@%s", user,
                 (srv->cfg.hostname && srv->cfg.hostname[0])
                     ? srv->cfg.hostname
                     : "localhost");
    return (n < 0 || (size_t)n >= outsz) ? -1 : 0;
}

/* ------------------------------------------------------------------ */
/* Mailboxes                                                           */
/* ------------------------------------------------------------------ */

/* The role mailboxes JMAP clients expect, in the order they are shown.  The
   maildir names are the ones imapd already uses (Inbox + dot-folders). */
static const struct {
    const char *mbox;   /* maildir folder name */
    const char *role;   /* RFC 8621 2 role */
} ROLES[] = {
    { "Inbox",   "inbox"   },
    { "Sent",    "sent"    },
    { "Drafts",  "drafts"  },
    { "Trash",   "trash"   },
    { "Junk",    "junk"    },
    { "Archive", "archive" },
};

#define NROLES (sizeof ROLES / sizeof ROLES[0])

int jmapd_account_prepare(JmapdServer *srv, const char *user) {
    size_t i;
    for (i = 0; i < NROLES; i++) {
        char dir[4096];
        if (imapd_mbox_dir(&srv->icfg, user, ROLES[i].mbox, dir, sizeof dir)
                != 0)
            continue;   /* invalid user: auth already vetted it */
        if (imapd_mbox_create(dir) != 0)
            continue;   /* read-only root: report what exists, not what should */
    }
    return 0;
}

static const char *role_of(const char *name) {
    size_t i;
    for (i = 0; i < NROLES; i++)
        if (strcmp(ROLES[i].mbox, name) == 0) return ROLES[i].role;
    return NULL;
}

/* The maildir folder name of a role.  In this store the folder names ARE the
   roles (ROLES above), so a role lookup is a table scan, not a mailbox read. */
const char *jmapd_role_mbox(const char *role) {
    size_t i;
    if (!role) return NULL;
    for (i = 0; i < NROLES; i++)
        if (strcmp(ROLES[i].role, role) == 0) return ROLES[i].mbox;
    return NULL;
}

static uint32_t sortorder_of(const char *name) {
    size_t i;
    for (i = 0; i < NROLES; i++)
        if (strcmp(ROLES[i].mbox, name) == 0) return (uint32_t)i;
    return (uint32_t)NROLES;
}

typedef struct MboxRow {
    char        name[IMAPD_MAX_MBOX + 1];
    char        id[JMAPD_ID_MAX];
    const char *role;
    uint32_t    total;
    uint32_t    unread;
    uint32_t    sort;
} MboxRow;

static int row_cmp(const void *pa, const void *pb) {
    const MboxRow *a = pa, *b = pb;
    if (a->sort != b->sort) return a->sort < b->sort ? -1 : 1;
    return strcmp(a->name, b->name);
}

/* One mailbox's counts, from the maildir (bounded disk work: one scan of one
   mailbox, exactly what IMAP STATUS does). */
static void row_fill(JmapdServer *srv, const char *user, MboxRow *r) {
    Mbox mb;
    size_t i;
    r->total = 0;
    r->unread = 0;
    if (imapd_mbox_peek(&srv->icfg, user, r->name, &mb) != 0) return;
    r->total = (uint32_t)mb.nmsgs;
    for (i = 0; i < mb.nmsgs; i++)
        if (!(mb.msgs[i].flags & IMAIL_SEEN)) r->unread++;
    imapd_mbox_close(&mb);
}

/* Is this id in the caller's `ids` filter?  filter == NULL means "all". */
static bool id_selected(const JmapJsonNode *filter, const char *id) {
    size_t i, n, l;
    if (!filter) return true;
    n = jmap_json_count(filter);
    l = strlen(id);
    for (i = 0; i < n; i++) {
        const char *s;
        size_t sl;
        if (jmap_json_str(jmap_json_at(filter, i), &s, &sl) == 0 && sl == l &&
            memcmp(s, id, l) == 0)
            return true;
    }
    return false;
}

static void write_mailbox(JsonBuilder *b, const MboxRow *r) {
    jsonb_begin_object(b);
    jsonb_key(b, "id");       jsonb_str(b, r->id);
    jsonb_comma(b);
    jsonb_key(b, "name");     jsonb_str(b, r->name);
    jsonb_comma(b);
    /* The maildir store is flat (imapd has no mailbox hierarchy). */
    jsonb_key(b, "parentId"); jmapd_jb_lit(b, "null");
    jsonb_comma(b);
    jsonb_key(b, "role");
    if (r->role) jsonb_str(b, r->role);
    else jmapd_jb_lit(b, "null");
    jsonb_comma(b);
    jsonb_key(b, "sortOrder"); jsonb_u32(b, r->sort);
    jsonb_comma(b);
    jsonb_key(b, "totalEmails");  jsonb_u32(b, r->total);
    jsonb_comma(b);
    jsonb_key(b, "unreadEmails"); jsonb_u32(b, r->unread);
    jsonb_comma(b);
    /* GAP, stated rather than papered over: these are the EMAIL counts.  An
       exact Thread count needs every message's References header, i.e. one
       header read per message on a call the client makes every 60 s; a
       conversation therefore counts once per message here.  Thread/get and
       Email/get's threadId are exact. */
    jsonb_key(b, "totalThreads");  jsonb_u32(b, r->total);
    jsonb_comma(b);
    jsonb_key(b, "unreadThreads"); jsonb_u32(b, r->unread);
    jsonb_comma(b);
    jsonb_key(b, "isSubscribed"); jsonb_bool(b, 1);
    jsonb_comma(b);
    jsonb_key(b, "myRights");
    jsonb_begin_object(b);
    jsonb_key(b, "mayReadItems");   jsonb_bool(b, 1);
    jsonb_comma(b);
    jsonb_key(b, "mayAddItems");    jsonb_bool(b, 1);
    jsonb_comma(b);
    jsonb_key(b, "mayRemoveItems"); jsonb_bool(b, 1);
    jsonb_comma(b);
    jsonb_key(b, "maySetSeen");     jsonb_bool(b, 1);
    jsonb_comma(b);
    jsonb_key(b, "maySetKeywords"); jsonb_bool(b, 1);
    jsonb_comma(b);
    jsonb_key(b, "mayCreateChild"); jsonb_bool(b, 1);
    jsonb_comma(b);
    /* Mailbox/set is not implemented in v1: say so rather than claim a right
       the daemon will refuse. */
    jsonb_key(b, "mayRename");      jsonb_bool(b, 0);
    jsonb_comma(b);
    jsonb_key(b, "mayDelete");      jsonb_bool(b, 0);
    jsonb_comma(b);
    jsonb_key(b, "maySubmit");      jsonb_bool(b, 1);
    jsonb_end_object(b);
    jsonb_end_object(b);
}

/* ------------------------------------------------------------------ */
/* Mailbox/get (RFC 8621 2.2)                                          */
/* ------------------------------------------------------------------ */

int jmapd_method_mailbox_get(JmapdCtx *ctx, const JmapJsonNode *args,
                             JsonBuilder *out) {
    JmapdServer *srv = ctx->srv;
    const char *user = ctx->user;
    const JmapJsonNode *ids = jmapd_arg(ctx, args, "ids");
    MboxRow *rows;
    size_t nrows = 0, i;
    char **names = NULL;
    size_t nnames = 0;
    char state[32];
    JmapdState st;

    if (ctx->argerr) { jmapd_jb_method_error(out, ctx->argerr); return 0; }
    if (ids && ids->type == JMAP_JSON_NULL) ids = NULL;
    if (ids && ids->type != JMAP_JSON_ARR) {
        jmapd_jb_method_error(out, "invalidArguments");
        return 0;
    }
    jmapd_state_load(srv, user, &st);
    jmapd_state_sync(srv, user, &st);
    if (jmapd_state_fmt('m', st.mailbox, state, sizeof state) != 0) return -1;

    jmapd_account_prepare(srv, user);
    rows = calloc(JMAPD_MAX_OBJECTS, sizeof *rows);
    if (!rows) return -1;

    /* Inbox first, then every dot-folder. */
    snprintf(rows[nrows].name, sizeof rows[nrows].name, "Inbox");
    rows[nrows].role = role_of("Inbox");
    rows[nrows].sort = sortorder_of("Inbox");
    nrows++;

    if (imapd_mbox_list(&srv->icfg, user, "*", &names, &nnames) == 0) {
        for (i = 0; i < nnames; i++) {
            if (nrows >= JMAPD_MAX_OBJECTS) break;
            if (strcmp(names[i], "Inbox") == 0) continue;   /* the INBOX dir */
            snprintf(rows[nrows].name, sizeof rows[nrows].name, "%s",
                     names[i]);
            rows[nrows].role = role_of(names[i]);
            rows[nrows].sort = sortorder_of(names[i]);
            nrows++;
        }
        for (i = 0; i < nnames; i++) free(names[i]);
        free(names);
    }
    qsort(rows, nrows, sizeof *rows, row_cmp);

    jsonb_begin_object(out);
    jsonb_key(out, "accountId"); jsonb_str(out, user);
    jsonb_comma(out);
    jsonb_key(out, "state");     jsonb_str(out, state);
    jsonb_comma(out);
    jsonb_key(out, "list");
    jsonb_begin_array(out);
    {
        int first = 1;
        for (i = 0; i < nrows; i++) {
            if (jmapd_id_mailbox(rows[i].name, rows[i].id, sizeof rows[i].id)
                    != 0)
                continue;
            if (!id_selected(ids, rows[i].id)) continue;
            row_fill(srv, user, &rows[i]);
            if (!first) jsonb_comma(out);
            first = 0;
            write_mailbox(out, &rows[i]);
        }
    }
    jsonb_end_array(out);
    jsonb_comma(out);
    jsonb_key(out, "notFound");
    jsonb_begin_array(out);
    if (ids) {
        size_t n = jmap_json_count(ids), k;
        int first = 1;
        for (k = 0; k < n; k++) {
            const char *s;
            size_t sl;
            bool found = false;
            if (jmap_json_str(jmap_json_at(ids, k), &s, &sl) != 0) continue;
            for (i = 0; i < nrows; i++)
                if (strlen(rows[i].id) == sl &&
                    memcmp(rows[i].id, s, sl) == 0) {
                    found = true;
                    break;
                }
            if (!found) {
                /* The parser NUL-terminates and rejects embedded NULs, so the
                   requested id is emitted exactly as given (no 64-byte copy:
                   a legitimate mailbox id can be ~684 chars). */
                if (!first) jsonb_comma(out);
                first = 0;
                jsonb_str(out, s);
            }
        }
    }
    jsonb_end_array(out);
    jsonb_end_object(out);

    free(rows);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Identity/get (RFC 8621 5.2)                                         */
/* ------------------------------------------------------------------ */

int jmapd_method_identity_get(JmapdCtx *ctx, const JmapJsonNode *args,
                              JsonBuilder *out) {
    JmapdServer *srv = ctx->srv;
    const char *user = ctx->user;
    char id[JMAPD_ID_MAX];
    char email[IMAPD_MAX_USER + 256];
    char state[32];
    const JmapJsonNode *ids = jmapd_arg(ctx, args, "ids");

    if (ctx->argerr) { jmapd_jb_method_error(out, ctx->argerr); return 0; }
    if (ids && ids->type == JMAP_JSON_NULL) ids = NULL;
    if (ids && ids->type != JMAP_JSON_ARR) {
        jmapd_jb_method_error(out, "invalidArguments");
        return 0;
    }
    if (jmapd_identity_id(user, id, sizeof id) != 0) return -1;
    if (jmapd_state_fmt('i', 0, state, sizeof state) != 0) return -1;
    /* The address this account sends as: --identity when configured, else
       <user>@<hostname> (the same value EmailSubmission defaults MAIL FROM
       to, so Identity/get and the envelope can never disagree). */
    if (jmapd_identity_email(srv, user, email, sizeof email) != 0) return -1;

    jsonb_begin_object(out);
    jsonb_key(out, "accountId"); jsonb_str(out, user);
    jsonb_comma(out);
    jsonb_key(out, "state");     jsonb_str(out, state);
    jsonb_comma(out);
    jsonb_key(out, "list");
    jsonb_begin_array(out);
    if (id_selected(ids, id)) {
        jsonb_begin_object(out);
        jsonb_key(out, "id");            jsonb_str(out, id);
        jsonb_comma(out);
        jsonb_key(out, "name");          jsonb_str(out, user);
        jsonb_comma(out);
        jsonb_key(out, "email");         jsonb_str(out, email);
        jsonb_comma(out);
        jsonb_key(out, "replyTo");       jmapd_jb_lit(out, "null");
        jsonb_comma(out);
        jsonb_key(out, "bcc");           jmapd_jb_lit(out, "null");
        jsonb_comma(out);
        jsonb_key(out, "textSignature"); jsonb_str(out, "");
        jsonb_comma(out);
        jsonb_key(out, "htmlSignature"); jsonb_str(out, "");
        jsonb_comma(out);
        /* The identity comes from the passwd file; JMAP cannot delete it. */
        jsonb_key(out, "mayDelete");     jsonb_bool(out, 0);
        jsonb_end_object(out);
    }
    jsonb_end_array(out);
    jsonb_comma(out);
    jsonb_key(out, "notFound");
    jsonb_begin_array(out);
    if (ids) {
        /* Echo the ids GIVEN IN THE REQUEST that were not found (RFC 8620
           5.1) — not the server's own id.  The parser NUL-terminates every
           string and rejects embedded NULs, so the value can be emitted as
           is; no copy, and nothing is truncated. */
        size_t n = jmap_json_count(ids), k;
        int first = 1;
        for (k = 0; k < n; k++) {
            const char *s;
            size_t sl;
            if (jmap_json_str(jmap_json_at(ids, k), &s, &sl) != 0) continue;
            if (sl == strlen(id) && memcmp(s, id, sl) == 0) continue;
            if (!first) jsonb_comma(out);
            first = 0;
            jsonb_str(out, s);
        }
    }
    jsonb_end_array(out);
    jsonb_end_object(out);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Email: locating one message on disk                                 */
/*                                                                    */
/* A JMAP Email id is the maildir BASE name (plan DECISIONS 3), so      */
/* locating it means scanning the account's mailboxes for that base —  */
/* one bounded scan per mailbox, exactly what STATUS does, never a     */
/* cached view (two daemons share this tree).                          */
/* ------------------------------------------------------------------ */

/* The account's mailbox names, Inbox first (heap-allocated; caller frees). */
static int mbox_names(JmapdServer *srv, const char *user, char ***out,
                      size_t *nout) {
    char **names = NULL;
    size_t nnames = 0, i, o = 0;
    *out = NULL;
    *nout = 0;
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
        if (strcmp(names[i], "Inbox") == 0) {
            free(names[i]);
            continue;
        }
        (*out)[o++] = names[i];
    }
    free(names);
    *nout = o;
    return 0;
}

static void mbox_names_free(char **names, size_t n) {
    size_t i;
    for (i = 0; i < n; i++) free(names[i]);
    free(names);
}

/* Fill every not-yet-found entry whose base matches a message in mb. */
static void locate_in_mbox(JmapdServer *srv, const char *user,
                           const char *mboxname, Mbox *mb, JmapdEmail *want,
                           size_t n) {
    size_t i, k;
    for (i = 0; i < mb->nmsgs; i++) {
        const Imail *m = &mb->msgs[i];
        for (k = 0; k < n; k++) {
            if (want[k].found || !m->base) continue;
            if (strcmp(want[k].base, m->base) != 0) continue;
            want[k].found = true;
            snprintf(want[k].mbox, sizeof want[k].mbox, "%s", mboxname);
            snprintf(want[k].path, sizeof want[k].path, "%s", m->path);
            want[k].size = m->size;
            want[k].internal_date = m->internal_date;
            want[k].flags = m->flags;
            want[k].uid = m->uid;
            if (m->mid)
                snprintf(want[k].mid, sizeof want[k].mid, "%s", m->mid);
            if (jmapd_id_email(want[k].base, NULL, want[k].id,
                               sizeof want[k].id) != 0)
                want[k].id[0] = '\0';
        }
    }
    (void)srv;
    (void)user;
}

/* Locate every entry.  A mailbox that cannot be opened is skipped (a
   vanished folder is not an error for the other ids).  Exported: Email/set
   (jmap_set.c) locates the same way, so one id resolves to one message for
   both the read and the write path. */
int jmapd_email_locate(JmapdServer *srv, const char *user, JmapdEmail *want,
                       size_t n) {
    char **names = NULL;
    size_t nnames = 0, i, k;
    if (n == 0) return 0;
    for (k = 0; k < n; k++) want[k].found = false;
    if (mbox_names(srv, user, &names, &nnames) != 0) return -1;
    for (i = 0; i < nnames; i++) {
        Mbox mb;
        bool needed = false;
        for (k = 0; k < n; k++)
            if (!want[k].found &&
                (want[k].mbox[0] == '\0' ||
                 strcmp(want[k].mbox, names[i]) == 0))
                needed = true;
        if (!needed) continue;
        if (imapd_mbox_peek(&srv->icfg, user, names[i], &mb) != 0) continue;
        locate_in_mbox(srv, user, names[i], &mb, want, n);
        imapd_mbox_close(&mb);
    }
    mbox_names_free(names, nnames);
    return 0;
}

/* Read one message file (bounded by the server's max message size). */
int jmapd_read_file(JmapdServer *srv, const char *path, size_t size,
                    char **out, size_t *outlen) {
    size_t cap, got = 0;
    char *buf;
    int fd;
    *out = NULL;
    *outlen = 0;
    cap = size;
    if (cap > srv->icfg.max_msg) cap = srv->icfg.max_msg;
    buf = malloc(cap + 1);
    if (!buf) return -1;
    fd = open(path, O_RDONLY);
    if (fd < 0) { free(buf); return -1; }
    while (got < cap) {
        ssize_t r = read(fd, buf + got, cap - got);
        if (r < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (r == 0) break;
        got += (size_t)r;
    }
    close(fd);
    buf[got] = '\0';
    *out = buf;
    *outlen = got;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Address lists                                                       */
/* ------------------------------------------------------------------ */

#define JMAPD_MAX_ADDRS 32

typedef struct JmapdAddr {
    char name[128];
    char email[256];
} JmapdAddr;

/* Split an RFC 5322 address-list header value into {name,email} pairs.  This
   is deliberately small: display names (quoted or not) and addr-specs, with
   group syntax and comments flattened away.  It never allocates and never
   reads past the value, so a hostile header cannot cost more than the value
   itself. */
static size_t addr_list_parse(const char *v, JmapdAddr *out, size_t max) {
    size_t n = 0, i = 0;
    if (!v) return 0;
    while (v[i] && n < max) {
        char name[128], email[256];
        size_t nl = 0, el = 0;
        bool in_quote = false, have_angle = false;
        size_t j = i;
        char buf[512];
        size_t bl = 0;
        /* one element: up to a top-level ',' (outside quotes and <>) */
        while (v[j]) {
            char c = v[j];
            if (c == '"') in_quote = !in_quote;
            else if (!in_quote && c == '<') have_angle = true;
            else if (!in_quote && c == '>') have_angle = false;
            else if (!in_quote && !have_angle && c == ',') break;
            if (bl + 1 < sizeof buf) buf[bl++] = c;
            j++;
        }
        buf[bl] = '\0';
        i = v[j] ? j + 1 : j;
        /* element -> (name, addr-spec) */
        {
            char *lt = strchr(buf, '<');
            char *gt = lt ? strchr(lt + 1, '>') : NULL;
            char *at;
            if (lt && gt) {
                char *s = buf, *e = lt;
                *gt = '\0';
                while (s < e && (*s == ' ' || *s == '\t')) s++;
                while (e > s && (e[-1] == ' ' || e[-1] == '\t')) e--;
                if (e - s >= 2 && *s == '"' && e[-1] == '"') { s++; e--; }
                nl = (size_t)(e - s);
                if (nl >= sizeof name) nl = sizeof name - 1;
                memcpy(name, s, nl);
                name[nl] = '\0';
                at = lt + 1;
                while (*at == ' ' || *at == '\t') at++;
                el = strlen(at);
                while (el > 0 && (at[el - 1] == ' ' || at[el - 1] == '\t')) el--;
                if (el >= sizeof email) el = sizeof email - 1;
                memcpy(email, at, el);
                email[el] = '\0';
            } else {
                char *s = buf, *e = buf + bl;
                while (s < e && (*s == ' ' || *s == '\t')) s++;
                while (e > s && (e[-1] == ' ' || e[-1] == '\t')) e--;
                nl = 0;
                name[0] = '\0';
                el = (size_t)(e - s);
                if (el >= sizeof email) el = sizeof email - 1;
                memcpy(email, s, el);
                email[el] = '\0';
            }
        }
        if (email[0] == '\0' && name[0] == '\0') continue;
        memcpy(out[n].name, name, nl + 1);
        memcpy(out[n].email, email, el + 1);
        n++;
    }
    return n;
}

static void write_addr_list(JsonBuilder *b, const char *v) {
    JmapdAddr a[JMAPD_MAX_ADDRS];
    size_t n = addr_list_parse(v, a, JMAPD_MAX_ADDRS), i;
    jsonb_begin_array(b);
    for (i = 0; i < n; i++) {
        char name[sizeof a[i].name];
        if (i) jsonb_comma(b);
        /* A display name is DISPLAY TEXT, so RFC 2047 encoded-words are
           decoded here (the addr-spec itself is never encoded).  Decoding
           never expands, so a name buffer the size of the field is enough. */
        if (jmapd_rfc2047_decode(a[i].name, name, sizeof name) != 0)
            snprintf(name, sizeof name, "%s", a[i].name);
        jsonb_begin_object(b);
        jsonb_key(b, "name");
        if (name[0]) jsonb_str(b, name);
        else jmapd_jb_lit(b, "null");
        jsonb_comma(b);
        jsonb_key(b, "email");
        jsonb_str(b, a[i].email);
        jsonb_end_object(b);
    }
    jsonb_end_array(b);
}

/* Split an address-list value into deduplicated addr-specs (no display
   names): the SMTP envelope of a submission (RFC 8621 7.5).  Bounded by
   `max`; a duplicate is dropped because RCPT TO for the same address twice
   would deliver the message twice to that mailbox. */
size_t jmapd_addr_list(const char *value, char out[][256], size_t max) {
    JmapdAddr a[JMAPD_MAX_ADDRS];
    size_t n, i, k, got = 0;
    if (!value || !out || max == 0) return 0;
    n = addr_list_parse(value, a, JMAPD_MAX_ADDRS);
    for (i = 0; i < n && got < max; i++) {
        bool dup = false;
        if (!a[i].email[0]) continue;
        for (k = 0; k < got; k++)
            if (strcasecmp(out[k], a[i].email) == 0) { dup = true; break; }
        if (dup) continue;
        snprintf(out[got], 256, "%s", a[i].email);
        got++;
    }
    return got;
}

/* The first addr-spec of an address-list value ("" when none). */
int jmapd_first_addr(const char *value, char *out, size_t outsz) {
    JmapdAddr a[JMAPD_MAX_ADDRS];
    size_t n;
    if (!value || !out || outsz == 0) return -1;
    out[0] = '\0';
    n = addr_list_parse(value, a, JMAPD_MAX_ADDRS);
    if (n == 0 || !a[0].email[0]) return -1;
    snprintf(out, outsz, "%s", a[0].email);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Email/get (RFC 8621 4.1)                                            */
/* ------------------------------------------------------------------ */

typedef struct EmailProps {
    bool threadId, receivedAt, from, to, cc, bcc, subject, preview, keywords,
         hasAttachment, size, mailboxIds, textBody, htmlBody, attachments,
         messageId, bodyStructure;
} EmailProps;

static void props_set(EmailProps *p, const char *name) {
    if (!strcmp(name, "threadId")) p->threadId = true;
    else if (!strcmp(name, "receivedAt")) p->receivedAt = true;
    else if (!strcmp(name, "from")) p->from = true;
    else if (!strcmp(name, "to")) p->to = true;
    else if (!strcmp(name, "cc")) p->cc = true;
    else if (!strcmp(name, "bcc")) p->bcc = true;
    else if (!strcmp(name, "subject")) p->subject = true;
    else if (!strcmp(name, "preview")) p->preview = true;
    else if (!strcmp(name, "keywords")) p->keywords = true;
    else if (!strcmp(name, "hasAttachment")) p->hasAttachment = true;
    else if (!strcmp(name, "size")) p->size = true;
    else if (!strcmp(name, "mailboxIds")) p->mailboxIds = true;
    else if (!strcmp(name, "textBody")) p->textBody = true;
    else if (!strcmp(name, "htmlBody")) p->htmlBody = true;
    else if (!strcmp(name, "attachments")) p->attachments = true;
    else if (!strcmp(name, "messageId")) p->messageId = true;
    else if (!strcmp(name, "bodyStructure")) p->bodyStructure = true;
    /* Anything else is a property this server does not have: omitted, which
       RFC 8620 5.1 explicitly allows. */
}

/* "YYYY-MM-DDTHH:MM:SSZ" — the client parses exactly this shape
   (cache.parseIso8601 indexes s[4] and s[7]), so it is rendered from UTC
   directly rather than through strftime's locale. */
void jmapd_iso8601_utc(time_t t, char *out, size_t outsz) {
    struct tm tm;
    char buf[64];
    if (outsz == 0) return;
    out[0] = '\0';
    if (!gmtime_r(&t, &tm)) return;
    snprintf(buf, sizeof buf, "%04d-%02d-%02dT%02d:%02d:%02dZ",
             tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour,
             tm.tm_min, tm.tm_sec);
    if (strlen(buf) >= outsz) return;
    strcpy(out, buf);
}

static void write_keywords(JsonBuilder *b, uint8_t flags) {
    int first = 1;
    jsonb_begin_object(b);
    if (flags & IMAIL_SEEN) {
        jsonb_key(b, "$seen"); jsonb_bool(b, 1); first = 0;
    }
    if (flags & IMAIL_FLAGGED) {
        if (!first) jsonb_comma(b);
        jsonb_key(b, "$flagged"); jsonb_bool(b, 1); first = 0;
    }
    if (flags & IMAIL_ANSWERED) {
        if (!first) jsonb_comma(b);
        jsonb_key(b, "$answered"); jsonb_bool(b, 1); first = 0;
    }
    if (flags & IMAIL_DRAFT) {
        if (!first) jsonb_comma(b);
        jsonb_key(b, "$draft"); jsonb_bool(b, 1); first = 0;
    }
    if (flags & IMAIL_TRASHED) {
        if (!first) jsonb_comma(b);
        jsonb_key(b, "$deleted"); jsonb_bool(b, 1);
    }
    jsonb_end_object(b);
}

/* The FIRST Message-ID in a header value: References lists the ancestry
   root-first (RFC 5322 3.6.4), so its first entry is the thread root.  Accepts
   the angle-bracket form and, for MUAs that omit them, a bare token. */
static bool first_msgid(const char *v, char *out, size_t outsz) {
    const char *lt, *gt;
    size_t n;
    if (!v || !out || outsz < 2) return false;
    lt = strchr(v, '<');
    if (lt) {
        gt = strchr(lt + 1, '>');
        n = gt ? (size_t)(gt - lt + 1) : strlen(lt);
        if (n >= outsz) n = outsz - 1;
        if (n == 0) return false;
        memcpy(out, lt, n);
        out[n] = '\0';
        return true;
    }
    while (*v == ' ' || *v == '\t') v++;
    n = 0;
    while (v[n] && v[n] != ' ' && v[n] != '\t' && v[n] != ',') n++;
    if (n == 0) return false;
    if (n >= outsz) n = outsz - 1;
    memcpy(out, v, n);
    out[n] = '\0';
    return true;
}

/* The thread ROOT key of a message: the first Message-ID in its References
   header, else its In-Reply-To, else its own Message-ID, else `fallback` (the
   uidlist's Message-ID or the maildir base).  Root-first References is why a
   whole conversation shares one Thread id WITHOUT reading any other message:
   every reply names the same root.  A message whose References header is
   absent or truncated groups by its parent instead — a separate Thread, which
   is the honest answer for what the message actually says. */
static void thread_root_key(const char *msg, size_t msglen, const char *fallback,
                            char *out, size_t outsz) {
    char v[1024];
    if (outsz == 0) return;
    out[0] = '\0';
    if (msg && msglen) {
        if (mail_header_get(msg, msglen, "References", v, sizeof v) == 0 &&
            first_msgid(v, out, outsz))
            return;
        if (mail_header_get(msg, msglen, "In-Reply-To", v, sizeof v) == 0 &&
            first_msgid(v, out, outsz))
            return;
        if (mail_header_get(msg, msglen, "Message-ID", v, sizeof v) == 0 &&
            first_msgid(v, out, outsz))
            return;
    }
    if (fallback && fallback[0]) {
        snprintf(out, outsz, "%s", fallback);
        return;
    }
    snprintf(out, outsz, "unknown");
}

/* A Thread id from a root key: "t" + base64url(key).  The key is bounded so
   the encoded form always fits JMAPD_ID_MAX; an id longer than that is
   truncated (Message-IDs that long do not occur outside synthetic input). */
static void thread_id_from_key(const char *key, char *out, size_t outsz) {
    out[0] = 't';
    out[1] = '\0';
    (void)jmapd_b64url_encode((const unsigned char *)key, strlen(key), out + 1,
                              outsz - 1);
}

/* Thread id of one message.  Exported so Email/set's created-email answer and
   Thread/get derive the SAME id Email/get reports. */
void jmapd_thread_id_of(const char *msg, size_t msglen, const char *fallback,
                        char *out, size_t outsz) {
    char key[JMAPD_THREAD_KEY_MAX + 1];
    thread_root_key(msg, msglen, fallback, key, sizeof key);
    thread_id_from_key(key, out, outsz);
}

/* One BodyPart object (RFC 8621 4.1.4). */
static void write_body_part(JsonBuilder *b, const JmapdEmail *e,
                            const char *msg, const JmapdTree *t, int idx,
                            bool with_subparts) {
    const JmapdPart *p = &t->parts[idx];
    char blob[JMAPD_BLOB_MAX];
    size_t decoded;
    bool bad = false;
    int i;

    jsonb_begin_object(b);
    jsonb_key(b, "partId");
    if (p->info.id[0]) jsonb_str(b, p->info.id);
    else jsonb_str(b, "");
    jsonb_comma(b);
    jsonb_key(b, "blobId");
    if (jmapd_id_blob(e->id, p->info.id, blob, sizeof blob) == 0)
        jsonb_str(b, blob);
    else
        jmapd_jb_lit(b, "null");
    jsonb_comma(b);
    decoded = jmapd_decoded_size(msg + p->info.hdr_end,
                                 p->info.end - p->info.hdr_end, p->cte_kind,
                                 &bad);
    jsonb_key(b, "size");
    jmapd_jb_u64(b, (uint64_t)decoded);
    jsonb_comma(b);
    jsonb_key(b, "name");
    if (p->info.filename[0]) jsonb_str(b, p->info.filename);
    else jmapd_jb_lit(b, "null");
    jsonb_comma(b);
    jsonb_key(b, "type");
    {
        char typebuf[112];
        snprintf(typebuf, sizeof typebuf, "%s/%s", p->info.type,
                 p->info.subtype);
        jsonb_str(b, typebuf);
    }
    jsonb_comma(b);
    jsonb_key(b, "charset");
    if (p->info.charset[0]) jsonb_str(b, p->info.charset);
    else jmapd_jb_lit(b, "null");
    jsonb_comma(b);
    jsonb_key(b, "disposition");
    if (p->info.disp[0]) jsonb_str(b, p->info.disp);
    else jmapd_jb_lit(b, "null");
    jsonb_comma(b);
    jsonb_key(b, "cid");      jmapd_jb_lit(b, "null");
    jsonb_comma(b);
    jsonb_key(b, "language"); jmapd_jb_lit(b, "null");
    jsonb_comma(b);
    jsonb_key(b, "location"); jmapd_jb_lit(b, "null");
    if (with_subparts && p->info.multipart) {
        int first = 1;
        jsonb_comma(b);
        jsonb_key(b, "subParts");
        jsonb_begin_array(b);
        for (i = 0; i < t->nparts; i++) {
            if (t->parts[i].parent != idx) continue;
            if (!first) jsonb_comma(b);
            first = 0;
            write_body_part(b, e, msg, t, i, true);
        }
        jsonb_end_array(b);
    }
    jsonb_end_object(b);
}

/* The list of leaves with body_kind == want (1 text/plain, 2 text/html). */
static void write_body_list(JsonBuilder *b, const JmapdEmail *e,
                            const char *msg, const JmapdTree *t, int want) {
    int i, first = 1;
    jsonb_begin_array(b);
    for (i = 0; i < t->nparts; i++) {
        if (t->parts[i].body_kind != want) continue;
        if (!first) jsonb_comma(b);
        first = 0;
        write_body_part(b, e, msg, t, i, false);
    }
    jsonb_end_array(b);
}

static void write_attachments(JsonBuilder *b, const JmapdEmail *e,
                              const char *msg, const JmapdTree *t) {
    int i, first = 1;
    jsonb_begin_array(b);
    for (i = 0; i < t->nparts; i++) {
        if (!t->parts[i].attachment) continue;
        if (!first) jsonb_comma(b);
        first = 0;
        write_body_part(b, e, msg, t, i, false);
    }
    jsonb_end_array(b);
}

typedef struct BodyFetch {
    bool text, html, all;
    size_t maxbytes;
} BodyFetch;

/* bodyValues: one entry per requested body part, keyed by partId.  `truncated`
   counts the bodyValues that carry isTruncated, so the caller can journal what
   the response actually cut instead of what it MIGHT have cut. */
static void write_body_values(JsonBuilder *b, const char *msg,
                              const JmapdTree *t, const BodyFetch *bf,
                              size_t *truncated) {
    int i, first = 1;
    jsonb_begin_object(b);
    for (i = 0; i < t->nparts; i++) {
        const JmapdPart *p = &t->parts[i];
        JmapdBodyValue bv;
        bool want = bf->all ||
                    (p->body_kind == 1 && bf->text) ||
                    (p->body_kind == 2 && bf->html);
        if (!want) continue;
        memset(&bv, 0, sizeof bv);
        if (jmapd_body_value(msg, t, i, bf->maxbytes, &bv) != 0) continue;
        if (!first) jsonb_comma(b);
        first = 0;
        jsonb_key(b, p->info.id);
        jsonb_begin_object(b);
        jsonb_key(b, "value");
        jsonb_str(b, bv.value ? bv.value : "");
        jsonb_comma(b);
        jsonb_key(b, "isEncodingProblem");
        jsonb_bool(b, bv.problem ? 1 : 0);
        jsonb_comma(b);
        jsonb_key(b, "isTruncated");
        jsonb_bool(b, bv.truncated ? 1 : 0);
        if (bv.truncated && truncated) (*truncated)++;
        jsonb_end_object(b);
        jmapd_body_value_free(&bv);
    }
    jsonb_end_object(b);
}

/* Render one Email object.  `msg` is the whole message file: the caller refuses
   the call when it cannot read it, because every property here is derived from
   those bytes.  `truncated`, when non-NULL, counts the bodyValues this object
   emitted with isTruncated set. */
static void write_email(JsonBuilder *b, JmapdServer *srv, const JmapdEmail *e,
                        const char *msg, size_t msglen, const EmailProps *pr,
                        const BodyFetch *bf, size_t *truncated) {
    JmapdTree *t = NULL;
    char received[32];
    int i;

    if (msg) {
        t = malloc(sizeof *t);
        if (t && jmapd_tree_build(msg, msglen, t) != 0) {
            free(t);
            t = NULL;
        }
    }
    jsonb_begin_object(b);
    jsonb_key(b, "id"); jsonb_str(b, e->id);

    if (pr->threadId) {
        char tid[JMAPD_ID_MAX];
        jmapd_thread_id_of(msg, msglen, e->mid[0] ? e->mid : e->base, tid,
                           sizeof tid);
        jsonb_comma(b);
        jsonb_key(b, "threadId"); jsonb_str(b, tid);
    }
    if (pr->receivedAt) {
        jmapd_iso8601_utc(e->internal_date, received, sizeof received);
        jsonb_comma(b);
        jsonb_key(b, "receivedAt"); jsonb_str(b, received);
    }
    if (pr->size) {
        jsonb_comma(b);
        jsonb_key(b, "size"); jmapd_jb_u64(b, (uint64_t)e->size);
    }
    if (pr->mailboxIds) {
        char mid[JMAPD_ID_MAX];
        jsonb_comma(b);
        jsonb_key(b, "mailboxIds");
        jsonb_begin_object(b);
        if (jmapd_id_mailbox(e->mbox, mid, sizeof mid) == 0) {
            jsonb_key(b, mid);
            jsonb_bool(b, 1);
        }
        jsonb_end_object(b);
    }
    if (pr->keywords) {
        jsonb_comma(b);
        jsonb_key(b, "keywords");
        write_keywords(b, e->flags);
    }
    if (pr->from || pr->to || pr->cc || pr->bcc || pr->subject || pr->messageId ||
        pr->preview) {
        char from[1024], to[1024], cc[1024], bcc[1024], subj[1024], midhdr[1024];
        const char *m = msg ? msg : "";
        size_t ml = msg ? msglen : 0;
        from[0] = to[0] = cc[0] = bcc[0] = subj[0] = midhdr[0] = '\0';
        (void)mail_header_get(m, ml, "From", from, sizeof from);
        (void)mail_header_get(m, ml, "To", to, sizeof to);
        (void)mail_header_get(m, ml, "Cc", cc, sizeof cc);
        (void)mail_header_get(m, ml, "Bcc", bcc, sizeof bcc);
        (void)mail_header_get(m, ml, "Subject", subj, sizeof subj);
        (void)mail_header_get(m, ml, "Message-ID", midhdr, sizeof midhdr);
        if (pr->from) {
            jsonb_comma(b);
            jsonb_key(b, "from");
            if (from[0]) write_addr_list(b, from);
            else jmapd_jb_lit(b, "null");
        }
        if (pr->to) {
            jsonb_comma(b);
            jsonb_key(b, "to");
            if (to[0]) write_addr_list(b, to);
            else jmapd_jb_lit(b, "null");
        }
        if (pr->cc) {
            jsonb_comma(b);
            jsonb_key(b, "cc");
            if (cc[0]) write_addr_list(b, cc);
            else jmapd_jb_lit(b, "null");
        }
        if (pr->bcc) {
            jsonb_comma(b);
            jsonb_key(b, "bcc");
            if (bcc[0]) write_addr_list(b, bcc);
            else jmapd_jb_lit(b, "null");
        }
        if (pr->subject) {
            char subjd[sizeof subj];
            jsonb_comma(b);
            jsonb_key(b, "subject");
            /* RFC 2047: a Subject is display text, so encoded-words are
               decoded (charset passthrough, like every body part). */
            if (jmapd_rfc2047_decode(subj, subjd, sizeof subjd) != 0)
                snprintf(subjd, sizeof subjd, "%s", subj);
            if (subjd[0]) jsonb_str(b, subjd);
            else jmapd_jb_lit(b, "null");
        }
        if (pr->messageId) {
            jsonb_comma(b);
            jsonb_key(b, "messageId");
            jsonb_begin_array(b);
            if (midhdr[0]) jsonb_str(b, midhdr);
            jsonb_end_array(b);
        }
        if (pr->preview) {
            char prev[256];
            prev[0] = '\0';
            if (t) jmapd_preview(msg, t, prev, sizeof prev);
            jsonb_comma(b);
            jsonb_key(b, "preview"); jsonb_str(b, prev);
        }
    }
    if (pr->hasAttachment) {
        bool has = false;
        if (t)
            for (i = 0; i < t->nparts; i++)
                if (t->parts[i].attachment) has = true;
        jsonb_comma(b);
        jsonb_key(b, "hasAttachment"); jsonb_bool(b, has ? 1 : 0);
    }
    if (pr->textBody) {
        jsonb_comma(b);
        jsonb_key(b, "textBody");
        if (t) write_body_list(b, e, msg, t, 1);
        else jsonb_begin_array(b), jsonb_end_array(b);
    }
    if (pr->htmlBody) {
        jsonb_comma(b);
        jsonb_key(b, "htmlBody");
        if (t) write_body_list(b, e, msg, t, 2);
        else jsonb_begin_array(b), jsonb_end_array(b);
    }
    if (pr->attachments) {
        jsonb_comma(b);
        jsonb_key(b, "attachments");
        if (t) write_attachments(b, e, msg, t);
        else jsonb_begin_array(b), jsonb_end_array(b);
    }
    if (pr->bodyStructure) {
        jsonb_comma(b);
        jsonb_key(b, "bodyStructure");
        if (t && t->nparts > 0) write_body_part(b, e, msg, t, 0, true);
        else jmapd_jb_lit(b, "null");
    }
    if (bf->text || bf->html || bf->all) {
        jsonb_comma(b);
        jsonb_key(b, "bodyValues");
        if (t) write_body_values(b, msg, t, bf, truncated);
        else jsonb_begin_object(b), jsonb_end_object(b);
    }
    (void)srv;
    jsonb_end_object(b);
    free(t);
}

int jmapd_method_email_get(JmapdCtx *ctx, const JmapJsonNode *args,
                           JsonBuilder *out) {
    JmapdServer *srv = ctx->srv;
    const char *user = ctx->user;
    const JmapJsonNode *ids = jmapd_arg(ctx, args, "ids");
    const JmapJsonNode *props = jmapd_arg(ctx, args, "properties");
    const JmapJsonNode *mbb = jmapd_arg(ctx, args, "maxBodyValueBytes");
    const JmapJsonNode *fbv;
    EmailProps pr;
    BodyFetch bf;
    JmapdEmail want[JMAPD_MAX_OBJECTS];
    size_t nids = 0, i, k, start;
    char state[32];
    JmapdState st;

    memset(&pr, 0, sizeof pr);
    memset(&bf, 0, sizeof bf);
    if (ctx->argerr) { jmapd_jb_method_error(out, ctx->argerr); return 0; }
    if (!ids || ids->type != JMAP_JSON_ARR) {
        jmapd_jb_method_error(out, "invalidArguments");
        return 0;
    }
    nids = jmap_json_count(ids);
    if (nids > JMAPD_MAX_OBJECTS) {
        jmapd_jb_method_error(out, "tooManyObjects");
        return 0;
    }
    /* `properties` is EXACT: the client asks for a specific list, and a
       property it did not ask for must not appear (M1 ignored it). */
    if (props && props->type == JMAP_JSON_ARR) {
        size_t np = jmap_json_count(props), j;
        for (j = 0; j < np; j++) {
            const char *s;
            if (jmap_json_str(jmap_json_at(props, j), &s, NULL) == 0)
                props_set(&pr, s);
        }
    } else {
        pr.threadId = pr.receivedAt = pr.from = pr.to = pr.cc = pr.bcc =
            pr.subject = pr.preview = pr.keywords = pr.hasAttachment = pr.size =
            pr.mailboxIds = pr.textBody = pr.htmlBody = pr.attachments =
            pr.messageId = pr.bodyStructure = true;
    }
    fbv = jmapd_arg(ctx, args, "fetchTextBodyValues");
    if (fbv) (void)jmap_json_bool(fbv, &bf.text);
    fbv = jmapd_arg(ctx, args, "fetchHTMLBodyValues");
    if (fbv) (void)jmap_json_bool(fbv, &bf.html);
    fbv = jmapd_arg(ctx, args, "fetchAllBodyValues");
    if (fbv) (void)jmap_json_bool(fbv, &bf.all);
    if (mbb) {
        uint64_t v = 0;
        if (jmap_json_u64(mbb, &v) == 0) bf.maxbytes = (size_t)v;
    }
    if (ctx->argerr) { jmapd_jb_method_error(out, ctx->argerr); return 0; }
    jmapd_state_load(srv, user, &st);
    jmapd_state_sync(srv, user, &st);
    if (jmapd_state_fmt('e', st.email, state, sizeof state) != 0) return -1;

    memset(want, 0, sizeof want);
    for (i = 0; i < nids; i++) {
        const char *s;
        size_t sl;
        char base[IMAPD_MAX_MBOX + 1], mbox[IMAPD_MAX_MBOX + 1];
        if (jmap_json_str(jmap_json_at(ids, i), &s, &sl) != 0) continue;
        if (jmapd_id_email_parse(s, base, sizeof base, mbox, sizeof mbox) != 0)
            continue;
        snprintf(want[i].base, sizeof want[i].base, "%s", base);
        snprintf(want[i].mbox, sizeof want[i].mbox, "%s", mbox);
        snprintf(want[i].id, sizeof want[i].id, "%s", s);
        want[i].found = false;
    }
    (void)jmapd_email_locate(srv, user, want, nids);

    start = out->len;      /* rollback point for a refused read, below */
    jsonb_begin_object(out);
    jsonb_key(out, "accountId"); jsonb_str(out, user);
    jsonb_comma(out);
    jsonb_key(out, "state"); jsonb_str(out, state);
    jsonb_comma(out);
    jsonb_key(out, "list");
    jsonb_begin_array(out);
    {
        int first = 1;
        /* Bodies are rendered inline, so a page of large messages can outgrow
           ONE reply (JMAPD_MAX_RESP would then replace the whole answer with an
           error — measured: a 32k-message archive whose newest page holds big
           newsletters answered 500 for every page request).  Bound the rendered
           bytes per response and let the tail of the page arrive TRUNCATED
           instead: RFC 8621 4.2 says maxBodyValueBytes is a hint the server may
           undercut, and every cut bodyValue carries isTruncated, so the client
           sees exactly what it got. */
        size_t budget = srv->cfg.get_body_budget ? srv->cfg.get_body_budget
                                                 : JMAPD_GET_BODY_BUDGET;
        size_t cut = 0;
        char why[1024];
        for (i = 0; i < nids; i++) {
            char *msg = NULL;
            size_t msglen = 0, before, expect, tr = 0;
            BodyFetch cur = bf;
            if (!want[i].found || !want[i].id[0]) continue;
            /* Everything this object says about the message — the headers,
               preview, hasAttachment, bodyStructure, every bodyValue — comes
               from these bytes.  A file that cannot be opened (or a short
               read: a partial body is a cut body with no isTruncated) used to
               leave msg NULL and emit the object with textBody:[] and
               bodyValues:{}: a 200 whose body is silently empty.  Refuse the
               call instead, like Email/query's unreadable-message refusal
               (jmap_query.c).  RFC 8620 5.1 has no per-object error, so the
               whole call is the only place to say it. */
            expect = want[i].size > srv->icfg.max_msg ? srv->icfg.max_msg
                                                      : want[i].size;
            if (jmapd_read_file(srv, want[i].path, want[i].size, &msg,
                                &msglen) != 0 || msglen < expect) {
                free(msg);
                if (out->err) return -1;   /* the buffer is already broken */
                if (out->buf) {
                    /* Roll the half-built response back before refusing: a
                       method error must be the whole result. */
                    out->len = start;
                    out->buf[start] = '\0';
                }
                snprintf(why, sizeof why,
                         "message '%s' could not be read; Email/get was not "
                         "answered rather than answered with an empty body",
                         want[i].id);
                jmapd_log_ctx(ctx, "get-unreadable-message", why);
                jmapd_jb_method_error_desc(out, "serverFail", why);
                return 0;
            }
            if (cur.text || cur.html || cur.all) {
                size_t client_max = bf.maxbytes ? bf.maxbytes
                                                : JMAPD_MAX_BODY_VALUE;
                size_t lim = budget < client_max ? budget : client_max;
                if (lim < 1) lim = 1;      /* 0 means "server default" to
                                              jmapd_body_value: never pass 0 */
                cur.maxbytes = lim;
            }
            if (!first) jsonb_comma(out);
            first = 0;
            before = out->len;
            /* Counted from the response, not predicted from the budget: a
               reduced limit with a body that fits under it cuts nothing, and
               the journal line must not claim otherwise. */
            write_email(out, srv, &want[i], msg, msglen, &pr, &cur, &tr);
            if (tr) cut++;
            if (out->len > before) {
                size_t used = out->len - before;
                budget = used >= budget ? 0 : budget - used;
            }
            free(msg);
        }
        if (cut) {
            char why[160];
            snprintf(why, sizeof why,
                     "method=Email/get budget=%llu objects=%llu truncated",
                     (unsigned long long)(srv->cfg.get_body_budget
                                              ? srv->cfg.get_body_budget
                                              : JMAPD_GET_BODY_BUDGET),
                     (unsigned long long)cut);
            jmapd_log_ctx(ctx, "get-truncated", why);
        }
    }
    jsonb_end_array(out);
    jsonb_comma(out);
    jsonb_key(out, "notFound");
    jsonb_begin_array(out);
    {
        int first = 1;
        for (k = 0; k < nids; k++) {
            const char *s;
            if (want[k].found && want[k].id[0]) continue;
            if (jmap_json_str(jmap_json_at(ids, k), &s, NULL) != 0) continue;
            if (!first) jsonb_comma(out);
            first = 0;
            jsonb_str(out, s);
        }
    }
    jsonb_end_array(out);
    jsonb_end_object(out);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Thread/get (RFC 8621 3.2)                                           */
/*                                                                    */
/* A Thread is the set of Emails sharing a root Message-ID.  The root is  */
/* read from each message's own References header (root-first, RFC 5322   */
/* 3.6.4), so grouping needs no mid->message map and no cross-message     */
/* walk: one bounded HEADER read per message (imapd_read_hdr), never the  */
/* whole file.  A get WITHOUT ids therefore costs one header read per     */
/* message in the account — linear, and the only way to answer it         */
/* honestly; the client on this path always names ids (they come from     */
/* Email/get's threadId).                                                */
/* ------------------------------------------------------------------ */

typedef struct ThrGroup {
    char   *id;      /* owned: the thread id */
    char  **eids;    /* owned array of owned Email ids */
    size_t  n, cap;
} ThrGroup;

typedef struct ThrSet {
    ThrGroup *g;
    size_t    n, cap;
    size_t   *idx;   /* open-addressed index into g (SIZE_MAX = empty slot) */
    size_t    idxcap;
} ThrSet;

static uint64_t thr_hash(const char *s) {
    uint64_t h = 1469598103934665603ull;
    for (; *s; s++) {
        h ^= (unsigned char)*s;
        h *= 1099511628211ull;
    }
    return h;
}

static void thr_free(ThrSet *s) {
    size_t i;
    for (i = 0; i < s->n; i++) {
        size_t k;
        for (k = 0; k < s->g[i].n; k++) free(s->g[i].eids[k]);
        free(s->g[i].eids);
        free(s->g[i].id);
    }
    free(s->g);
    free(s->idx);
    memset(s, 0, sizeof *s);
}

/* Rebuild the index at the next power-of-two size. */
static int thr_reindex(ThrSet *s) {
    size_t nc = s->idxcap ? s->idxcap * 2 : 64, i;
    size_t *nv = malloc(nc * sizeof *nv);
    if (!nv) return -1;
    for (i = 0; i < nc; i++) nv[i] = SIZE_MAX;
    for (i = 0; i < s->n; i++) {
        size_t slot = (size_t)(thr_hash(s->g[i].id) & (nc - 1));
        while (nv[slot] != SIZE_MAX) slot = (slot + 1) & (nc - 1);
        nv[slot] = i;
    }
    free(s->idx);
    s->idx = nv;
    s->idxcap = nc;
    return 0;
}

/* Find (or with `create`, insert) the group for a thread id.  NULL only on
   allocation failure. */
static ThrGroup *thr_find(ThrSet *s, const char *id, bool create) {
    size_t slot;
    if (s->idxcap == 0 || s->n * 2 >= s->idxcap) {
        if (thr_reindex(s) != 0) return NULL;
    }
    slot = (size_t)(thr_hash(id) & (s->idxcap - 1));
    while (s->idx[slot] != SIZE_MAX) {
        ThrGroup *g = &s->g[s->idx[slot]];
        if (strcmp(g->id, id) == 0) return g;
        slot = (slot + 1) & (s->idxcap - 1);
    }
    if (!create) return NULL;
    if (s->n == s->cap) {
        size_t nc = s->cap ? s->cap * 2 : 16;
        ThrGroup *nv = realloc(s->g, nc * sizeof *nv);
        if (!nv) return NULL;
        s->g = nv;
        s->cap = nc;
    }
    memset(&s->g[s->n], 0, sizeof s->g[s->n]);
    s->g[s->n].id = strdup(id);
    if (!s->g[s->n].id) return NULL;
    s->idx[slot] = s->n;
    return &s->g[s->n++];
}

static int thr_add(ThrGroup *g, const char *eid) {
    if (g->n == g->cap) {
        size_t nc = g->cap ? g->cap * 2 : 8;
        char **nv = realloc(g->eids, nc * sizeof *nv);
        if (!nv) return -1;
        g->eids = nv;
        g->cap = nc;
    }
    g->eids[g->n] = strdup(eid);
    if (!g->eids[g->n]) return -1;
    g->n++;
    return 0;
}

static int thr_cmp(const void *pa, const void *pb) {
    const ThrGroup *a = pa, *b = pb;
    return strcmp(a->id, b->id);
}

int jmapd_method_thread_get(JmapdCtx *ctx, const JmapJsonNode *args,
                            JsonBuilder *out) {
    JmapdServer *srv = ctx->srv;
    const char *user = ctx->user;
    const JmapJsonNode *ids = jmapd_arg(ctx, args, "ids");
    char **names = NULL;
    size_t nnames = 0, i, k;
    ThrSet set;
    char state[32];
    JmapdState st;

    if (ctx->argerr) { jmapd_jb_method_error(out, ctx->argerr); return 0; }
    if (ids && ids->type == JMAP_JSON_NULL) ids = NULL;
    if (ids && ids->type != JMAP_JSON_ARR) {
        jmapd_jb_method_error(out, "invalidArguments");
        return 0;
    }
    if (ids && jmap_json_count(ids) > JMAPD_MAX_OBJECTS) {
        jmapd_jb_method_error(out, "tooManyObjects");
        return 0;
    }
    memset(&set, 0, sizeof set);
    jmapd_state_load(srv, user, &st);
    jmapd_state_sync(srv, user, &st);
    if (jmapd_state_fmt('t', st.thread, state, sizeof state) != 0) return -1;

    if (mbox_names(srv, user, &names, &nnames) != 0) return -1;
    for (i = 0; i < nnames; i++) {
        Mbox mb;
        if (imapd_mbox_peek(&srv->icfg, user, names[i], &mb) != 0) continue;
        for (k = 0; k < mb.nmsgs; k++) {
            Imail *m = &mb.msgs[k];
            char *hdr = NULL, tid[JMAPD_ID_MAX], eid[JMAPD_ID_MAX];
            size_t hdrlen = 0;
            ThrGroup *g;
            if (!m->base) continue;
            if (jmapd_id_email(m->base, NULL, eid, sizeof eid) != 0) continue;
            /* HEADER only: the grouping key lives in References. */
            if (imapd_read_hdr(m->path, &hdr, &hdrlen) != 0) {
                hdr = NULL;
                hdrlen = 0;
            }
            jmapd_thread_id_of(hdr, hdrlen, m->mid ? m->mid : m->base, tid,
                               sizeof tid);
            free(hdr);
            g = thr_find(&set, tid, true);
            if (!g || thr_add(g, eid) != 0) {
                thr_free(&set);
                mbox_names_free(names, nnames);
                return -1;
            }
        }
        imapd_mbox_close(&mb);
    }
    mbox_names_free(names, nnames);

    jsonb_begin_object(out);
    jsonb_key(out, "accountId"); jsonb_str(out, user);
    jsonb_comma(out);
    jsonb_key(out, "state"); jsonb_str(out, state);
    jsonb_comma(out);
    jsonb_key(out, "list");
    jsonb_begin_array(out);
    {
        int first = 1;
        if (ids) {
            /* Request order, and a requested id with no member is notFound. */
            size_t n = jmap_json_count(ids);
            for (k = 0; k < n; k++) {
                const char *s;
                ThrGroup *g;
                size_t j;
                if (jmap_json_str(jmap_json_at(ids, k), &s, NULL) != 0) continue;
                g = thr_find(&set, s, false);
                if (!g) continue;
                if (!first) jsonb_comma(out);
                first = 0;
                jsonb_begin_object(out);
                jsonb_key(out, "id"); jsonb_str(out, g->id);
                jsonb_comma(out);
                jsonb_key(out, "emailIds");
                jsonb_begin_array(out);
                for (j = 0; j < g->n; j++) {
                    if (j) jsonb_comma(out);
                    jsonb_str(out, g->eids[j]);
                }
                jsonb_end_array(out);
                jsonb_end_object(out);
            }
        } else {
            qsort(set.g, set.n, sizeof *set.g, thr_cmp);
            for (k = 0; k < set.n; k++) {
                size_t j;
                if (!first) jsonb_comma(out);
                first = 0;
                jsonb_begin_object(out);
                jsonb_key(out, "id"); jsonb_str(out, set.g[k].id);
                jsonb_comma(out);
                jsonb_key(out, "emailIds");
                jsonb_begin_array(out);
                for (j = 0; j < set.g[k].n; j++) {
                    if (j) jsonb_comma(out);
                    jsonb_str(out, set.g[k].eids[j]);
                }
                jsonb_end_array(out);
                jsonb_end_object(out);
            }
        }
    }
    jsonb_end_array(out);
    jsonb_comma(out);
    jsonb_key(out, "notFound");
    jsonb_begin_array(out);
    if (ids) {
        size_t n = jmap_json_count(ids), j;
        int first = 1;
        for (j = 0; j < n; j++) {
            const char *s;
            if (jmap_json_str(jmap_json_at(ids, j), &s, NULL) != 0) continue;
            if (thr_find(&set, s, false)) continue;
            if (!first) jsonb_comma(out);
            first = 0;
            jsonb_str(out, s);
        }
    }
    jsonb_end_array(out);
    jsonb_end_object(out);
    thr_free(&set);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Blob download (RFC 8621 4.1.4)                                      */
/*                                                                    */
/* The URL serves the DECODED bytes of one part — the same bytes a      */
/* bodyValue of that part carries, because it is the same decoder.      */
/* The body is never buffered: the part's file range is pread'd in      */
/* 16 KiB chunks, decoded, and appended to the connection's output as   */
/* the poll loop drains it (imapd_imap.c's FetchGen stream_lit is the   */
/* model).  Content-Length is exact, computed by a counting decode pass */
/* before the first byte is queued.                                     */
/* ------------------------------------------------------------------ */

#define BLOB_CHUNK 16384u

struct JmapdBlob {
    int      fd;
    size_t   off;         /* next encoded byte offset in the file */
    size_t   left;        /* encoded bytes still to read */
    int      kind;        /* JMAPD_CTE_* */
    JmapdDec dec;
    size_t   total;       /* decoded length (Content-Length) */
    size_t   sent;        /* decoded bytes already queued */
    char     ctype[256];
    char     disposition[512];
};

static int blob_append(Conn *c, const void *src, size_t n) {
    size_t need, nc;
    char *nb;
    if (n == 0) return 0;
    need = c->out_len + n;
    if (need + 1 > c->out_cap) {
        nc = c->out_cap ? c->out_cap : 256;
        while (nc < need + 1) {
            if (nc > SIZE_MAX / 2) return -1;
            nc *= 2;
        }
        nb = realloc(c->out, nc);
        if (!nb) return -1;
        c->out = nb;
        c->out_cap = nc;
    }
    memcpy(c->out + c->out_len, src, n);
    c->out_len = need;
    c->out[need] = '\0';
    return 0;
}

/* Counting decode pass over a file range: the exact decoded length without
   holding the body. */
static size_t blob_count_decoded(int fd, size_t off, size_t len, int kind) {
    char enc[BLOB_CHUNK];
    unsigned char dec[BLOB_CHUNK];
    JmapdDec d;
    size_t total = 0, done = 0;
    jmapd_dec_init(&d, kind);
    while (done < len) {
        size_t want = len - done;
        size_t got = 0, in, w;
        if (want > sizeof enc) want = sizeof enc;
        while (got < want) {
            ssize_t r = pread(fd, enc + got, want - got, (off_t)(off + done + got));
            if (r < 0) {
                if (errno == EINTR) continue;
                return total;
            }
            if (r == 0) break;
            got += (size_t)r;
        }
        if (got == 0) break;
        in = got;
        w = jmapd_dec_feed(&d, enc, &in, dec, sizeof dec);
        total += w;
        done += got;
    }
    total += jmapd_dec_finish(&d, dec, sizeof dec);
    return total;
}

/* A Content-Disposition value for a download: the part's filename when it has
   one, else the URL's last segment.  Path separators and quotes cannot reach
   the header, and a non-ASCII name also carries the RFC 5987 form. */
static void blob_disposition(const char *name, char *out, size_t outsz) {
    char clean[256];
    size_t i, o = 0;
    bool nonascii = false;
    for (i = 0; name && name[i] && o + 1 < sizeof clean; i++) {
        unsigned char ch = (unsigned char)name[i];
        if (ch == '/' || ch == '\\' || ch == '"' || ch < 0x20 || ch == 0x7f)
            continue;
        if (ch >= 0x80) nonascii = true;
        clean[o++] = (char)ch;
    }
    clean[o] = '\0';
    if (o == 0) snprintf(clean, sizeof clean, "download");
    snprintf(out, outsz, "attachment; filename=\"%s\"", clean);
    if (nonascii) {
        char pct[512];
        size_t p = 0, k;
        for (k = 0; clean[k] && p + 4 < sizeof pct; k++) {
            unsigned char ch = (unsigned char)clean[k];
            if (ch >= 0x80 || ch == '%' || ch == '\'' || ch == ' ') {
                p += (size_t)snprintf(pct + p, sizeof pct - p, "%%%02X", ch);
            } else {
                pct[p++] = (char)ch;
            }
        }
        pct[p] = '\0';
        {
            size_t l = strlen(out);
            snprintf(out + l, outsz - l, "; filename*=UTF-8''%s", pct);
        }
    }
}

void jmapd_download_free(JmapdConn *c) {
    JmapdBlob *b;
    if (!c || !c->blob) return;
    b = c->blob;
    if (b->fd >= 0) close(b->fd);
    free(b);
    c->blob = NULL;
}

const char *jmapd_download_ctype(const JmapdBlob *b) {
    return b ? b->ctype : "application/octet-stream";
}

const char *jmapd_download_disposition(const JmapdBlob *b) {
    return b ? b->disposition : "attachment";
}

size_t jmapd_download_length(const JmapdBlob *b) {
    return b ? b->total : 0;
}

int jmapd_download_open(JmapdServer *srv, const char *user, const char *blob_id,
                        const char *name, JmapdBlob **out) {
    char email_id[JMAPD_ID_MAX], part_id[IMAPD_MAX_PART_ID];
    char base[IMAPD_MAX_MBOX + 1], mbox[IMAPD_MAX_MBOX + 1];
    JmapdEmail want[1];
    JmapdPartRef ref;
    JmapdBlob *b;
    int fd, kind;
    size_t total;

    if (!out) return 500;
    *out = NULL;
    /* The id is parsed BEFORE anything is opened: a traversal attempt, a
       malformed base64url payload or an impossible part path stops here. */
    if (jmapd_id_blob_parse(blob_id, email_id, sizeof email_id, part_id,
                            sizeof part_id) != 0)
        return 404;
    if (jmapd_id_email_parse(email_id, base, sizeof base, mbox,
                             sizeof mbox) != 0)
        return 404;
    memset(want, 0, sizeof want);
    snprintf(want[0].base, sizeof want[0].base, "%s", base);
    snprintf(want[0].mbox, sizeof want[0].mbox, "%s", mbox);
    if (jmapd_email_locate(srv, user, want, 1) != 0 || !want[0].found) return 404;

    fd = open(want[0].path, O_RDONLY);
    if (fd < 0) return 404;
    if (jmapd_file_part(fd, (uint64_t)want[0].size, part_id, &ref) != 0) {
        close(fd);
        return 404;
    }
    kind = jmapd_cte_kind(ref.cte);
    if (kind < 0) kind = JMAPD_CTE_7BIT;
    total = blob_count_decoded(fd, ref.hdr_end, ref.end - ref.hdr_end, kind);
    if (total > JMAPD_MAX_BLOB_BYTES) {
        close(fd);
        return 413;
    }
    b = calloc(1, sizeof *b);
    if (!b) {
        close(fd);
        return 500;
    }
    b->fd = fd;
    b->off = ref.hdr_end;
    b->left = ref.end - ref.hdr_end;
    b->kind = kind;
    b->total = total;
    b->sent = 0;
    jmapd_dec_init(&b->dec, kind);
    {
        char type[112];
        snprintf(type, sizeof type, "%s/%s",
                 ref.type[0] ? ref.type : "application",
                 ref.subtype[0] ? ref.subtype : "octet-stream");
        if (ref.charset[0] && !strcasecmp(ref.type, "text"))
            snprintf(b->ctype, sizeof b->ctype, "%s; charset=%s", type,
                     ref.charset);
        else
            snprintf(b->ctype, sizeof b->ctype, "%s", type);
    }
    blob_disposition(ref.filename[0] ? ref.filename : (name ? name : ""),
                     b->disposition, sizeof b->disposition);
    *out = b;
    return 0;
}

void jmapd_download_pump(JmapdConn *c) {
    JmapdBlob *b;
    char enc[BLOB_CHUNK];
    unsigned char dec[BLOB_CHUNK];
    if (!c || !c->blob) return;
    b = c->blob;
    while (b->sent < b->total) {
        size_t used = c->c.out_len - c->c.out_off;
        size_t room, want, got, in, w;
        if (used >= JMAPD_MAX_OUT / 2) return;   /* wait for POLLOUT */
        room = JMAPD_MAX_OUT / 2 - used;
        want = b->left;
        if (want > sizeof enc) want = sizeof enc;
        if (want > room) want = room;
        if (want == 0) {
            /* The encoded range is exhausted before the counted total: the
               file changed under us.  Closing is the only honest answer —
               the Content-Length already promised more bytes. */
            c->c.closed = true;
            jmapd_download_free(c);
            return;
        }
        got = 0;
        while (got < want) {
            ssize_t r = pread(b->fd, enc + got, want - got,
                              (off_t)(b->off + got));
            if (r < 0) {
                if (errno == EINTR) continue;
                break;
            }
            if (r == 0) break;
            got += (size_t)r;
        }
        if (got == 0) {
            c->c.closed = true;
            jmapd_download_free(c);
            return;
        }
        b->off += got;
        b->left -= got;
        in = got;
        w = jmapd_dec_feed(&b->dec, enc, &in, dec, sizeof dec);
        if (w && blob_append(&c->c, dec, w) != 0) {
            c->c.closed = true;
            jmapd_download_free(c);
            return;
        }
        b->sent += w;
        c->c.last_act = time(NULL);   /* a long transfer is not an idle conn */
    }
    jmapd_download_free(c);
}
