/* imapd_imap.c — RFC 3501 subset IMAP4rev1 server for imapd.
 *
 * State machine NOT_AUTH -> AUTH -> SELECTED (one selected mailbox per
 * session).  The reader assembles whole commands INCLUDING {n} literals
 * (each literal is announced with a "+ " continuation, collected into the
 * command buffer quote-wrapped with backslash escapes, then the rest of the
 * command line continues) so LOGIN/APPEND arguments tokenize uniformly.
 *
 * Commands: CAPABILITY NOOP LOGOUT LOGIN AUTHENTICATE PLAIN LIST LSUB
 * SELECT EXAMINE CREATE DELETE SUBSCRIBE UNSUBSCRIBE STATUS APPEND CLOSE
 * CHECK EXPUNGE FETCH STORE SEARCH (+ the UID variants).  FETCH responses
 * stream through a bounded resume-state generator (FetchGen) so a large
 * message body never has to fit in memory or in the reply buffer.
 *
 * STARTTLS (RFC 2595) is offered when the daemon was started with
 * --cert/--key (imapd_tls.c): it is valid only pre-auth and with no
 * pipelined command buffered; after the handshake the session resets to
 * NOT_AUTH.  Per RFC 3501 11.1, cleartext LOGIN/AUTHENTICATE are refused
 * with [PRIVACYREQUIRED] on a non-loopback IMAP bind until STARTTLS
 * completes (loopback binds keep the plaintext default).
 *
 * Deferred (clients get tagged NO/BAD): ENVELOPE, BODYSTRUCTURE, MIME part
 * fetches, RENAME, quotas/ACL.  IDLE is supported (RFC 2177). */
#include "imapd.h"
#include "mail.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

/* Debug tracing: enabled by IMAPD_DEBUG=1.  Logs every IMAP command and
   every connection close to stderr (systemd journal), so a client's exact
   command sequence and the moment a connection is dropped are visible. */
static int imapd_debug_on(void) {
    static int v = -1;
    if (v < 0) {
        const char *e = getenv("IMAPD_DEBUG");
        v = (e && e[0] && e[0] != '0') ? 1 : 0;
    }
    return v;
}
static void imapd_dbg(const char *fmt, ...) {
    va_list ap;
    if (!imapd_debug_on()) return;
    fprintf(stderr, "imapd ");
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    fflush(stderr);
}
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <poll.h>
#include <time.h>

/* ------------------------------------------------------------------ */
/* Small helpers (duplicated per house style; cf. smtp_in.c)           */
/* ------------------------------------------------------------------ */

static int ascii_strncasecmp(const char *a, const char *b, size_t n) {
    while (n-- > 0) {
        char ca = *a++;
        char cb = *b++;
        if (ca >= 'A' && ca <= 'Z') ca = (char)(ca + 32);
        if (cb >= 'A' && cb <= 'Z') cb = (char)(cb + 32);
        if (ca != cb) return (unsigned char)ca - (unsigned char)cb;
        if (ca == '\0') return 0;
    }
    return 0;
}

static bool ascii_ieq_str(const char *a, const char *b) {
    while (*a && *b) {
        char ca = *a++, cb = *b++;
        if (ca >= 'A' && ca <= 'Z') ca = (char)(ca + 32);
        if (cb >= 'A' && cb <= 'Z') cb = (char)(cb + 32);
        if (ca != cb) return false;
    }
    return *a == *b;
}

/* Case-insensitive substring search (naive; v1 bounded workloads). */
static const char *ci_strstr(const char *hay, size_t haylen,
                             const char *needle) {
    size_t nl;
    size_t i;
    if (!hay || !needle) return NULL;
    nl = strlen(needle);
    if (nl == 0) return hay;
    if (haylen < nl) return NULL;
    for (i = 0; i + nl <= haylen; i++) {
        if (ascii_strncasecmp(hay + i, needle, nl) == 0) return hay + i;
    }
    return NULL;
}

/* Read a whole file into a freshly-malloc'd, NUL-terminated buffer
   (duplicated from smtp_in.c / imap_maildir.c per house style). */
static int read_file(const char *path, char **out, size_t *outlen) {
    struct stat st;
    int fd;
    char *buf;
    size_t off = 0;
    if (!path || !out || !outlen) return -1;
    *out = NULL;
    *outlen = 0;
    fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    if (fstat(fd, &st) != 0 || st.st_size < 0) { close(fd); return -1; }
    buf = malloc((size_t)st.st_size + 1);
    if (!buf) { close(fd); return -1; }
    while (off < (size_t)st.st_size) {
        ssize_t r = read(fd, buf + off, (size_t)st.st_size - off);
        if (r < 0) {
            if (errno == EINTR) continue;
            free(buf);
            close(fd);
            return -1;
        }
        if (r == 0) break;
        off += (size_t)r;
    }
    close(fd);
    buf[off] = '\0';
    *out = buf;
    *outlen = off;
    return 0;
}

static int buf_append(char **buf, size_t *len, size_t *cap,
                      const char *src, size_t n) {
    size_t need, nc;
    char *nb;
    if (n == 0) return 0;
    need = *len + n;
    if (need + 1 > *cap) {
        nc = *cap ? *cap : 256;
        while (nc < need + 1) {
            if (nc > SIZE_MAX / 2) return -1;
            nc *= 2;
        }
        nb = realloc(*buf, nc);
        if (!nb) return -1;
        *buf = nb;
        *cap = nc;
    }
    memcpy(*buf + *len, src, n);
    *len = need;
    (*buf)[*len] = '\0';
    return 0;
}

static void conn_flush(Conn *c) {
    if (c->tls && !imapd_tls_pending(c)) {
        /* TLS up (or mid-handshake): the backlog must go out encrypted. */
        while (c->out_off < c->out_len) {
            int n = imapd_tls_send(c, c->out + c->out_off,
                                   c->out_len - c->out_off);
            if (n < 0) {
                c->closed = true;
                c->out_len = c->out_off = 0;   /* undeliverable: let it die */
                return;
            }
            if (n == 0) return;   /* socket full: retry on POLLOUT */
            c->out_off += (size_t)n;
        }
        c->out_len = c->out_off = 0;
        return;
    }
    while (c->out_off < c->out_len) {
        ssize_t n = send(c->fd, c->out + c->out_off, c->out_len - c->out_off,
                         MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) return;
            c->closed = true;
            return;
        }
        if (n == 0) { c->closed = true; return; }
        c->out_off += (size_t)n;
    }
    c->out_len = c->out_off = 0;
}

static void conn_reply(Conn *c, const char *text) {
    if (c->out_len > IMAPD_MAX_OUT) { c->closed = true; return; }
    if (buf_append(&c->out, &c->out_len, &c->out_cap, text, strlen(text)) != 0) {
        c->closed = true;
        return;
    }
    conn_flush(c);
}

static void conn_replyf(Conn *c, const char *fmt, ...) {
    char buf[1024];
    va_list ap;
    int n;
    va_start(ap, fmt);
    n = vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    if (n < 0) return;
    if ((size_t)n >= sizeof buf) {
        conn_reply(c, "* BAD reply too long\r\n");
        c->closed = true;
        return;
    }
    conn_reply(c, buf);
}

/* ------------------------------------------------------------------ */
/* Tokenizer (assembled commands; literals appear as quoted strings)   */
/* ------------------------------------------------------------------ */

int imapd_lit_marker(const char *line) {
    size_t n = strlen(line);
    const char *q, *d;
    unsigned long v = 0;
    if (n == 0 || line[n - 1] != '}') return 0;
    /* Find the '{' that opens the trailing "{<digits>}" block. */
    q = line + n - 1;
    while (q > line && q[-1] >= '0' && q[-1] <= '9') q--;
    if (q == line || q[-1] != '{') return -1;   /* junk between the braces */
    if (q == line + n - 1) return -1;           /* "{}" -> empty */
    for (d = q; d < line + n - 1; d++) {
        v = v * 10 + (unsigned long)(*d - '0');
        if (v > 0x7fffffffUL) return -1;
    }
    if (v == 0) return -1;                      /* {0} is not useful */
    return (int)v;
}

int imapd_next_astring(const char **p, char **out, size_t *outlen) {
    const char *s;
    char *buf = NULL;
    size_t n = 0, cap = 0;
    *out = NULL;
    *outlen = 0;
    s = *p;
    while (*s == ' ') s++;
    if (*s == '\0') { *p = s; return 0; }
    if (*s == '"') {
        s++;
        for (;;) {
            char ch = *s;
            if (ch == '\0') return -1;   /* unterminated */
            if (ch == '\\') {
                s++;
                if (*s == '\0') return -1;
                ch = *s++;
            } else if (ch == '"') {
                s++;
                break;
            } else {
                s++;
            }
            if (buf_append(&buf, &n, &cap, &ch, 1) != 0) { free(buf); return -1; }
        }
        *p = s;
        if (!buf) { buf = strdup(""); if (!buf) return -1; }  /* empty string */
        *out = buf;
        *outlen = n;
        return 1;
    }
    /* atom: printable run excluding delimiters */
    {
        const char *start = s;
        while (*s && (unsigned char)*s > 0x20 && *s < 0x7f &&
               *s != '(' && *s != ')' && *s != '"' && *s != '{')
            s++;
        if (s == start) return -1;   /* stray delimiter byte */
        buf = malloc((size_t)(s - start) + 1);
        if (!buf) return -1;
        memcpy(buf, start, (size_t)(s - start));
        buf[s - start] = '\0';
        *outlen = (size_t)(s - start);
        *p = s;
        *out = buf;
        return 1;
    }
}

int imapd_parse_plain_list(const char **p, char ***out, size_t *nout) {
    const char *s = *p;
    char **v = NULL;
    size_t n = 0, cap = 0;
    *out = NULL;
    *nout = 0;
    while (*s == ' ') s++;
    if (*s != '(') return -1;
    s++;
    for (;;) {
        char *atom;
        size_t alen;
        while (*s == ' ') s++;
        if (*s == ')') { s++; break; }
        if (*s == '\0') { free(v); return -1; }
        {
            const char *start = s;
            while (*s && *s != ' ' && *s != ')') s++;
            alen = (size_t)(s - start);
            atom = malloc(alen + 1);
            if (!atom) { free(v); return -1; }
            memcpy(atom, start, alen);
            atom[alen] = '\0';
        }
        if (n == cap) {
            size_t nc = cap ? cap * 2 : 4;
            char **nv = realloc(v, nc * sizeof *nv);
            if (!nv) { free(atom); free(v); return -1; }
            v = nv;
            cap = nc;
        }
        v[n++] = atom;
    }
    *p = s;
    *out = v;
    *nout = n;
    return 0;
}

/* ------------------------------------------------------------------ */
/* SEARCH key parse / match                                            */
/* ------------------------------------------------------------------ */

static SearchKey *sk_new(SearchKind kind) {
    SearchKey *k = calloc(1, sizeof *k);
    if (k) k->kind = kind;
    return k;
}

void imapd_search_free(SearchKey *k) {
    if (!k) return;
    free(k->set);
    free(k->hdr);
    free(k->str);
    imapd_search_free(k->a);
    imapd_search_free(k->b);
    free(k);
}

/* One bare search key from *p (caller looped for implicit AND). */
int imapd_search_parse(const char **p, SearchKey **out) {
    const char *s = *p;
    char *tok = NULL;
    size_t tlen = 0;
    SearchKey *k;
    int r;

    *out = NULL;
    while (*s == ' ') s++;
    if (*s == '\0') { *p = s; return 0; }

    if (*s == '(') {   /* paren group == implicit AND of its keys */
        SearchKey *grp = NULL, *tail = NULL;
        s++;
        for (;;) {
            SearchKey *sub;
            while (*s == ' ') s++;
            if (*s == ')') { s++; break; }
            if (*s == '\0') return -1;
            r = imapd_search_parse(&s, &sub);
            if (r <= 0) return -1;
            if (!grp) {
                grp = sk_new(SK_AND);
                if (!grp) { imapd_search_free(sub); return -1; }
                grp->a = sub;
                tail = grp;
            } else {
                SearchKey *nn = sk_new(SK_AND);
                if (!nn) { imapd_search_free(sub); imapd_search_free(grp); return -1; }
                tail->b = nn;
                nn->a = sub;
                tail = nn;
            }
        }
        if (!grp) return -1;   /* empty group */
        *p = s;
        *out = grp;
        return 1;
    }

    /* seq-set key: starts with a digit or '*' */
    if ((*s >= '0' && *s <= '9') || *s == '*') {
        const char *st = s;
        while (*s && *s != ' ' && *s != '(' && *s != ')') s++;
        k = sk_new(SK_SEQ);
        if (!k) return -1;
        k->set = malloc((size_t)(s - st) + 1);
        if (!k->set) { free(k); return -1; }
        memcpy(k->set, st, (size_t)(s - st));
        k->set[s - st] = '\0';
        if (!imapd_seqset_valid(k->set)) {
            imapd_search_free(k);
            return -1;
        }
        *p = s;
        *out = k;
        return 1;
    }

    {
        const char *st = s;
        while (*s && *s != ' ' && *s != '(' && *s != ')') s++;
        tlen = (size_t)(s - st);
        tok = malloc(tlen + 1);
        if (!tok) return -1;
        memcpy(tok, st, tlen);
        tok[tlen] = '\0';
    }
    *p = s;

    if (ascii_ieq_str(tok, "ALL")) {
        k = sk_new(SK_ALL);
    } else if (ascii_ieq_str(tok, "ANSWERED")) {
        k = sk_new(SK_ANSWERED);
    } else if (ascii_ieq_str(tok, "DELETED")) {
        k = sk_new(SK_DELETED);
    } else if (ascii_ieq_str(tok, "DRAFT")) {
        k = sk_new(SK_DRAFT);
    } else if (ascii_ieq_str(tok, "FLAGGED")) {
        k = sk_new(SK_FLAGGED);
    } else if (ascii_ieq_str(tok, "NEW")) {
        k = sk_new(SK_NEW);
    } else if (ascii_ieq_str(tok, "OLD")) {
        k = sk_new(SK_OLD);
    } else if (ascii_ieq_str(tok, "RECENT")) {
        k = sk_new(SK_RECENT);
    } else if (ascii_ieq_str(tok, "SEEN")) {
        k = sk_new(SK_SEEN);
    } else if (ascii_ieq_str(tok, "UNSEEN")) {
        k = sk_new(SK_UNSEEN);
    } else if (ascii_ieq_str(tok, "UID") || ascii_ieq_str(tok, "SEQSET")) {
        k = sk_new(ascii_ieq_str(tok, "UID") ? SK_UID : SK_SEQ);
    } else if (ascii_ieq_str(tok, "FROM")) {
        k = sk_new(SK_FROM);
    } else if (ascii_ieq_str(tok, "TO")) {
        k = sk_new(SK_TO);
    } else if (ascii_ieq_str(tok, "SUBJECT")) {
        k = sk_new(SK_SUBJECT);
    } else if (ascii_ieq_str(tok, "BODY")) {
        k = sk_new(SK_BODY);
    } else if (ascii_ieq_str(tok, "TEXT")) {
        k = sk_new(SK_TEXT);
    } else if (ascii_ieq_str(tok, "HEADER")) {
        k = sk_new(SK_HEADER);
    } else if (ascii_ieq_str(tok, "SINCE")) {
        k = sk_new(SK_SINCE);
    } else if (ascii_ieq_str(tok, "BEFORE")) {
        k = sk_new(SK_BEFORE);
    } else if (ascii_ieq_str(tok, "ON")) {
        k = sk_new(SK_ON);
    } else if (ascii_ieq_str(tok, "SENTSINCE")) {
        k = sk_new(SK_SENTSINCE);
    } else if (ascii_ieq_str(tok, "SENTBEFORE")) {
        k = sk_new(SK_SENTBEFORE);
    } else if (ascii_ieq_str(tok, "SENTON")) {
        k = sk_new(SK_SENTON);
    } else if (ascii_ieq_str(tok, "NOT")) {
        k = sk_new(SK_NOT);
    } else if (ascii_ieq_str(tok, "OR")) {
        k = sk_new(SK_OR);
    } else {
        free(tok);
        return -1;
    }
    if (!k) { free(tok); return -1; }

    switch (k->kind) {
    case SK_UID:
    case SK_SEQ: {
        char *set = NULL;
        size_t slen;
        r = imapd_next_astring(p, &set, &slen);
        if (r != 1 || !imapd_seqset_valid(set)) {
            free(set);
            imapd_search_free(k);
            free(tok);
            return -1;
        }
        k->set = set;
        break;
    }
    case SK_FROM:
    case SK_TO:
    case SK_SUBJECT:
    case SK_BODY:
    case SK_TEXT: {
        char *str = NULL;
        size_t slen;
        r = imapd_next_astring(p, &str, &slen);
        if (r != 1) {
            free(str);
            imapd_search_free(k);
            free(tok);
            return -1;
        }
        k->str = str;
        break;
    }
    case SK_HEADER: {
        char *hdr = NULL, *str = NULL;
        size_t hl, sl;
        if (imapd_next_astring(p, &hdr, &hl) != 1 ||
            imapd_next_astring(p, &str, &sl) != 1) {
            free(hdr);
            free(str);
            imapd_search_free(k);
            free(tok);
            return -1;
        }
        k->hdr = hdr;
        k->str = str;
        break;
    }
    case SK_SINCE:
    case SK_BEFORE:
    case SK_ON:
    case SK_SENTSINCE:
    case SK_SENTBEFORE:
    case SK_SENTON: {
        /* Parse a "dd-Mon-yyyy" date into a UTC time_t at midnight. */
        char *ds = NULL;
        size_t dl;
        int dd = 0, yy = 0;
        char mon[4] = {0};
        static const char *mons[12] = { "Jan","Feb","Mar","Apr","May","Jun",
            "Jul","Aug","Sep","Oct","Nov","Dec" };
        int mi = -1, j;
        r = imapd_next_astring(p, &ds, &dl);
        if (r != 1 ||
            sscanf(ds, "%2d-%3s-%4d", &dd, mon, &yy) != 3) {
            free(ds);
            imapd_search_free(k);
            free(tok);
            return -1;
        }
        for (j = 0; j < 12; j++)
            if (ascii_ieq_str(mon, mons[j])) { mi = j; break; }
        if (mi < 0 || dd < 1 || dd > 31 || yy < 1970) {
            free(ds);
            imapd_search_free(k);
            free(tok);
            return -1;
        }
        /* days from epoch to Jan 1 of `yy`, then add day-of-year */
        {
            long y = yy - 1900;
            long days = 365 * (y - 70) + (y - 69 + (yy % 4 == 0)) / 4
                        - ((yy % 100 == 0) ? ((yy - 70 + 99) / 100) : 0)
                        + ((yy % 400 == 0) ? ((yy - 70 + 399) / 400) : 0);
            static const int mdays[12] = {31,28,31,30,31,30,31,31,30,31,30,31};
            int dm = 0, leap = (yy % 4 == 0 && yy % 100 != 0) || yy % 400 == 0;
            for (j = 0; j < mi; j++) dm += mdays[j];
            if (leap && mi > 1) dm++;
            k->date = (time_t)((days + dm + (dd - 1)) * 86400L);
        }
        free(ds);
        break;
    }
    case SK_NOT:
        r = imapd_search_parse(p, &k->a);
        if (r != 1) { imapd_search_free(k); free(tok); return -1; }
        break;
    case SK_OR:
        if (imapd_search_parse(p, &k->a) != 1 ||
            imapd_search_parse(p, &k->b) != 1) {
            imapd_search_free(k);
            free(tok);
            return -1;
        }
        break;
    default:
        break;
    }
    free(tok);
    *out = k;
    return 1;
}

int imapd_search_parse_program(const char **p, SearchKey **out) {
    SearchKey *grp = NULL, *tail = NULL;
    *out = NULL;
    for (;;) {
        SearchKey *sub;
        int r = imapd_search_parse(p, &sub);
        if (r < 0) { imapd_search_free(grp); return -1; }
        if (r == 0) break;
        if (!grp) {
            grp = sub;                       /* single key: return as-is */
            tail = NULL;
            continue;
        }
        if (!tail) {                          /* second key: start AND chain */
            SearchKey *nn = sk_new(SK_AND);
            if (!nn) { imapd_search_free(sub); imapd_search_free(grp); return -1; }
            nn->a = grp;
            nn->b = sub;
            grp = nn;
            tail = nn;
        } else {
            SearchKey *nn = sk_new(SK_AND);
            if (!nn) { imapd_search_free(sub); imapd_search_free(grp); return -1; }
            nn->a = sub;
            tail->b = nn;
            tail = nn;
        }
    }
    if (!grp) return 0;
    *out = grp;
    return 1;
}

bool imapd_search_needs_body(const SearchKey *k) {
    if (!k) return false;
    switch (k->kind) {
    case SK_FROM: case SK_TO: case SK_SUBJECT: case SK_HEADER:
    case SK_BODY: case SK_TEXT:
        return true;
    case SK_NOT:
        return imapd_search_needs_body(k->a);
    case SK_OR:
        return imapd_search_needs_body(k->a) || imapd_search_needs_body(k->b);
    case SK_AND:
        return imapd_search_needs_body(k->a) || imapd_search_needs_body(k->b);
    default:
        return false;
    }
}

/* Byte offset just past the header block (incl. the blank separator line). */
static size_t msg_hdr_end(const char *msg, size_t len) {
    size_t i;
    for (i = 0; i + 4 <= len; i++)
        if (msg[i] == '\r' && msg[i+1] == '\n' && msg[i+2] == '\r' &&
            msg[i+3] == '\n')
            return i + 4;
    for (i = 0; i + 2 <= len; i++)
        if (msg[i] == '\n' && msg[i+1] == '\n')
            return i + 2;
    return len;
}

bool imapd_search_match(const SearchKey *k, const ImailDoc *d,
                        uint32_t uidnext, size_t nmsgs) {
    char hdr[4096];
    if (!k) return false;
    switch (k->kind) {
    case SK_ALL:      return true;
    case SK_ANSWERED: return (d->m->flags & IMAIL_ANSWERED) != 0;
    case SK_DELETED:  return (d->m->flags & IMAIL_TRASHED) != 0;
    case SK_DRAFT:    return (d->m->flags & IMAIL_DRAFT) != 0;
    case SK_FLAGGED:  return (d->m->flags & IMAIL_FLAGGED) != 0;
    case SK_SEEN:     return (d->m->flags & IMAIL_SEEN) != 0;
    case SK_UNSEEN:   return (d->m->flags & IMAIL_SEEN) == 0;
    case SK_RECENT:   return d->m->recent;
    case SK_NEW:      return d->m->recent && !(d->m->flags & IMAIL_SEEN);
    case SK_OLD:      return !d->m->recent;
    case SK_SEQ:      return imapd_seqset_has(k->set, (uint32_t)d->seq,
                                              (uint32_t)nmsgs);
    case SK_UID:      return imapd_seqset_has(k->set, d->m->uid, uidnext);
    case SK_FROM:
    case SK_TO:
    case SK_SUBJECT:
    case SK_HEADER:
        if (!d->msg) return false;
        if (mail_header_get(d->msg, d->msglen,
                            k->hdr ? k->hdr :
                            (k->kind == SK_FROM ? "From" :
                             k->kind == SK_TO ? "To" : "Subject"),
                            hdr, sizeof hdr) != 0)
            return false;
        return ci_strstr(hdr, strlen(hdr), k->str) != NULL;
    case SK_BODY:
        if (!d->msg) return false;
        {
            size_t he = msg_hdr_end(d->msg, d->msglen);
            return ci_strstr(d->msg + he, d->msglen - he, k->str) != NULL;
        }
    case SK_TEXT:
        if (!d->msg) return false;
        return ci_strstr(d->msg, d->msglen, k->str) != NULL;
    /* Date keys: compare the message's internal date (UTC midnight) against
       the search date.  SINCE/ON/BEFORE and SENT* are both matched on the
       internal date here (the maildir migration stored each message's
       original date as its internal date, so they are equivalent). */
    case SK_SINCE:
        return d->m->internal_date >= k->date;
    case SK_ON:
        return d->m->internal_date >= k->date &&
               d->m->internal_date < k->date + 86400;
    case SK_BEFORE:
        return d->m->internal_date < k->date;
    case SK_SENTSINCE:
        return d->m->internal_date >= k->date;
    case SK_SENTON:
        return d->m->internal_date >= k->date &&
               d->m->internal_date < k->date + 86400;
    case SK_SENTBEFORE:
        return d->m->internal_date < k->date;
    case SK_NOT:
        return !imapd_search_match(k->a, d, uidnext, nmsgs);
    case SK_OR:
        return imapd_search_match(k->a, d, uidnext, nmsgs) ||
               imapd_search_match(k->b, d, uidnext, nmsgs);
    case SK_AND:
        return imapd_search_match(k->a, d, uidnext, nmsgs) &&
               imapd_search_match(k->b, d, uidnext, nmsgs);
    }
    return false;
}

/* ------------------------------------------------------------------ */
/* Session helpers                                                     */
/* ------------------------------------------------------------------ */

static void close_selected(Conn *c) {
    if (c->mb_open) {
        imapd_mbox_close(&c->mb);
        c->mb_open = false;
        c->mbname[0] = '\0';
    }
    c->ist = IST_AUTH;
    c->examine = false;
}

/* NOOP/CHECK: re-scan the selected mailbox and announce count changes. */
static void refresh_selected(ImapdServer *srv, Conn *c) {
    Mbox mb;
    if (!c->mb_open || c->fg) return;
    /* Skip the expensive full re-scan unless something actually arrived in
       new/: on a 30k-message mailbox re-scanning every IDLE/NOOP tick is
       O(n^2) (scan_subdir linear uidlist lookup) and pins the CPU.  When the
       client is NOT in IDLE (plain NOOP/CHECK), fall through so a full
       refresh still catches changes. */
    if (c->idle && !imapd_mbox_has_new(&srv->cfg, c->user, c->mbname))
        return;
    if (imapd_mbox_open(&srv->cfg, c->user, c->mbname, &mb) != 0) return;
    {
        size_t old_n = c->mb.nmsgs, old_r = 0, new_r = 0, i;
        for (i = 0; i < old_n; i++) if (c->mb.msgs[i].recent) old_r++;
        for (i = 0; i < mb.nmsgs; i++) if (mb.msgs[i].recent) new_r++;
        if (mb.nmsgs != old_n || new_r != old_r) {
            conn_replyf(c, "* %zu EXISTS\r\n* %zu RECENT\r\n", mb.nmsgs, new_r);
        }
        imapd_mbox_close(&c->mb);
        c->mb = mb;
    }
}

/* Map one flag name to its bitmask.  Returns the bit, 0 for an ignorable
   keyword, or IMAIL_RECENT when the name is \Recent (not settable). */
static uint32_t flag_from_name(const char *n) {
    if (*n == '\\') {
        n++;
        if (ascii_ieq_str(n, "Seen"))     return IMAIL_SEEN;
        if (ascii_ieq_str(n, "Answered")) return IMAIL_ANSWERED;
        if (ascii_ieq_str(n, "Flagged"))  return IMAIL_FLAGGED;
        if (ascii_ieq_str(n, "Deleted"))  return IMAIL_TRASHED;
        if (ascii_ieq_str(n, "Draft"))    return IMAIL_DRAFT;
        if (ascii_ieq_str(n, "Recent"))   return IMAIL_RECENT;
        return 0;
    }
    return 0;   /* keywords: accepted, not persisted (v1) */
}

static void flags_str(uint8_t flags, char *out, size_t outsz) {
    static const struct { uint8_t bit; const char *nm; } tab[] = {
        { IMAIL_ANSWERED, "\\Answered" },
        { IMAIL_FLAGGED,  "\\Flagged" },
        { IMAIL_TRASHED,  "\\Deleted" },
        { IMAIL_SEEN,     "\\Seen" },
        { IMAIL_DRAFT,    "\\Draft" },
        { IMAIL_RECENT,   "\\Recent" },
    };
    size_t i, n = 0;
    out[0] = '\0';
    for (i = 0; i < 6; i++) {
        if (!(flags & tab[i].bit)) continue;
        if (n && n + 1 < outsz) out[n++] = ' ';
        n += (size_t)snprintf(out + n, outsz - n, "%s", tab[i].nm);
        if (n >= outsz - 1) break;
    }
}

static void idate_str(time_t t, char *out, size_t outsz) {
    static const char *const mon[12] = { "Jan", "Feb", "Mar", "Apr", "May",
        "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
    struct tm tm;
    gmtime_r(&t, &tm);
    snprintf(out, outsz, "\"%02d-%s-%04d %02d:%02d:%02d +0000\"",
             tm.tm_mday, (tm.tm_mon >= 0 && tm.tm_mon < 12)
                         ? mon[tm.tm_mon] : "Jan",
             tm.tm_year + 1900, tm.tm_hour, tm.tm_min, tm.tm_sec);
}

static int buf_appendf(char **buf, size_t *len, size_t *cap,
                       const char *fmt, ...) {
    char tmp[512];
    va_list ap;
    int n;
    va_start(ap, fmt);
    n = vsnprintf(tmp, sizeof tmp, fmt, ap);
    va_end(ap);
    if (n < 0) return -1;
    if ((size_t)n >= sizeof tmp) return -1;
    return buf_append(buf, len, cap, tmp, (size_t)n);
}

/* ------------------------------------------------------------------ */
/* Capability                                                          */
/* ------------------------------------------------------------------ */

/* Canonical CAPABILITY string (pure; unit-tested by imap_check.c). */
const char *imapd_capability(bool tls_active, bool tls_avail,
                             bool plain_auth_ok) {
    if (tls_active)   return "IMAP4rev1 AUTH=PLAIN IDLE UIDPLUS CONDSTORE";   /* RFC 2595: no STARTTLS once TLS is up */
    if (!tls_avail)   return "IMAP4rev1 AUTH=PLAIN IDLE UIDPLUS CONDSTORE";   /* no cert: legacy plaintext default */
    if (plain_auth_ok) return "IMAP4rev1 STARTTLS AUTH=PLAIN IDLE UIDPLUS CONDSTORE";
    return "IMAP4rev1 STARTTLS LOGINDISABLED IDLE UIDPLUS CONDSTORE";         /* RFC 3501 11.1 */
}

/* Loopback bind-address classifier (pure; unit-tested by imap_check.c).
   Unknown/unset addresses are treated as non-loopback (fail-closed). */
bool imapd_addr_loopback(const char *addr) {
    if (!addr || !addr[0]) return false;
    if (strcmp(addr, "localhost") == 0 || strcmp(addr, "::1") == 0)
        return true;
    return strncmp(addr, "127.", 4) == 0;
}

/* This session's CAPABILITY string (RFC 3501 7.1 / RFC 2595): STARTTLS is
   advertised only while still in cleartext with a cert loaded, and
   LOGINDISABLED replaces AUTH=PLAIN pre-TLS on non-loopback binds. */
static const char *cap_of(ImapdServer *srv, Conn *c) {
    return imapd_capability(imapd_tls_established(c),
                            imapd_tls_available(srv),
                            !srv->tls_ready || srv->imap_loopback);
}

/* ------------------------------------------------------------------ */
/* Authentication                                                      */
/* ------------------------------------------------------------------ */

static void auth_apply(ImapdServer *srv, Conn *c, const char *tag,
                       const char *user, const char *pass) {
    if (imapd_auth_check(srv, user, pass)) {
        free(c->user);
        c->user = strdup(user);
        if (!c->user) { conn_replyf(c, "%s NO out of memory\r\n", tag); return; }
        c->ist = IST_AUTH;
        conn_replyf(c, "%s OK [CAPABILITY %s] authentication completed\r\n",
                    tag, cap_of(srv, c));
    } else {
        conn_replyf(c, "%s NO [AUTHENTICATIONFAILED] "
                       "Authentication failed\r\n", tag);
    }
}

/* SASL PLAIN: base64("authzid\0authcid\0password"). */
static void auth_plain_b64(ImapdServer *srv, Conn *c, const char *tag,
                           const char *b64, size_t blen) {
    unsigned char msg[512];
    size_t mlen = 0;
    const char *authzid, *authcid, *pass;
    char *z = NULL;
    if (blen == 1 && b64[0] == '=') { b64 = ""; blen = 0; }   /* empty resp */
    if (imapd_b64_decode(b64, blen, msg, sizeof msg, &mlen) != 0) {
        conn_replyf(c, "%s NO [AUTHENTICATIONFAILED] Invalid SASL response\r\n",
                    tag);
        return;
    }
    authzid = (const char *)msg;
    {
        size_t i = strlen(authzid);
        if (i + 1 >= mlen) {
            conn_replyf(c, "%s NO [AUTHENTICATIONFAILED] Invalid SASL response\r\n",
                        tag);
            return;
        }
        authcid = (const char *)msg + i + 1;
        i += strlen(authcid) + 1;
        if (i >= mlen) {
            conn_replyf(c, "%s NO [AUTHENTICATIONFAILED] Invalid SASL response\r\n",
                        tag);
            return;
        }
        pass = (const char *)msg + i;
    }
    /* authzid, when present, must equal the authcid (proxy logins unsupported) */
    if (authzid[0] && strcmp(authzid, authcid) != 0) {
        conn_replyf(c, "%s NO [AUTHENTICATIONFAILED] Authentication failed\r\n",
                    tag);
        return;
    }
    z = strdup(authcid);
    if (!z) { conn_replyf(c, "%s NO out of memory\r\n", tag); return; }
    auth_apply(srv, c, tag, z, pass);
    free(z);
}

static void auth_cont(ImapdServer *srv, Conn *c, const char *line) {
    if (strcmp(line, "*") == 0) {
        conn_replyf(c, "%s BAD authentication aborted\r\n", c->auth_tag);
        return;
    }
    auth_plain_b64(srv, c, c->auth_tag, line, strlen(line));
}

/* ------------------------------------------------------------------ */
/* Commands                                                            */
/* ------------------------------------------------------------------ */

/* RFC 3501 11.1: no cleartext credentials on a non-loopback bind until
   STARTTLS has completed (bind-based gating, not peer-based). */
static bool privacy_required(ImapdServer *srv, Conn *c) {
    return !imapd_tls_established(c) && srv->tls_ready && !srv->imap_loopback;
}

static void do_login(ImapdServer *srv, Conn *c, const char *tag,
                     const char *rest) {
    char *user = NULL, *pass = NULL;
    size_t ul, pl;
    if (c->ist != IST_NOT_AUTH) {
        conn_replyf(c, "%s BAD LOGIN not allowed now\r\n", tag);
        return;
    }
    if (privacy_required(srv, c)) {
        conn_replyf(c, "%s NO [PRIVACYREQUIRED] Cleartext login disabled; "
                       "use STARTTLS first\r\n", tag);
        return;
    }
    if (imapd_next_astring(&rest, &user, &ul) != 1 ||
        imapd_next_astring(&rest, &pass, &pl) != 1) {
        conn_replyf(c, "%s BAD LOGIN requires user and password\r\n", tag);
        free(user);
        free(pass);
        return;
    }
    auth_apply(srv, c, tag, user, pass);
    free(user);
    free(pass);
}

static void do_authenticate(ImapdServer *srv, Conn *c, const char *tag,
                            const char *rest) {
    char *mech = NULL, *init = NULL;
    size_t ml, il;
    int r1, r2;
    if (c->ist != IST_NOT_AUTH) {
        conn_replyf(c, "%s BAD AUTHENTICATE not allowed now\r\n", tag);
        return;
    }
    if (privacy_required(srv, c)) {
        conn_replyf(c, "%s NO [PRIVACYREQUIRED] Cleartext auth disabled; "
                       "use STARTTLS first\r\n", tag);
        return;
    }
    r1 = imapd_next_astring(&rest, &mech, &ml);
    if (r1 != 1 || !ascii_ieq_str(mech, "PLAIN")) {
        conn_replyf(c, "%s NO unsupported authentication mechanism\r\n", tag);
        free(mech);
        return;
    }
    r2 = imapd_next_astring(&rest, &init, &il);
    if (r2 == 1) {
        auth_plain_b64(srv, c, tag, init, il);
    } else if (r2 == 0) {
        snprintf(c->auth_tag, sizeof c->auth_tag, "%s", tag);
        c->cont_auth = true;
        conn_reply(c, "+ \r\n");
    } else {
        conn_replyf(c, "%s BAD AUTHENTICATE invalid arguments\r\n", tag);
    }
    free(mech);
    free(init);
}

/* RFC 6154 SPECIAL-USE attribute for a well-known mailbox name, or NULL.
   Case-insensitive; lets clients auto-route Sent/Trash/Archive/Junk/Drafts. */
static const char *special_use(const char *name) {
    if (!name) return NULL;
    if (ascii_ieq_str(name, "INBOX"))   return "\\Inbox";
    if (ascii_ieq_str(name, "Sent"))    return "\\Sent";
    if (ascii_ieq_str(name, "Archive")) return "\\Archive";
    if (ascii_ieq_str(name, "Spam") || ascii_ieq_str(name, "Junk"))
        return "\\Junk";
    if (ascii_ieq_str(name, "Trash"))   return "\\Trash";
    if (ascii_ieq_str(name, "Drafts"))  return "\\Drafts";
    return NULL;
}

/* LIST "" pattern  /  LSUB "" pattern. */
static void do_list(ImapdServer *srv, Conn *c, const char *tag,
                    const char *rest, bool sub) {
    char *ref = NULL, *pat = NULL;
    size_t rl, pl;
    char *full;
    char **names = NULL;
    size_t nnames = 0, i;
    if (imapd_next_astring(&rest, &ref, &rl) != 1 ||
        imapd_next_astring(&rest, &pat, &pl) != 1) {
        conn_replyf(c, "%s BAD LIST requires reference and pattern\r\n", tag);
        free(ref);
        free(pat);
        return;
    }
    full = malloc(strlen(ref) + strlen(pat) + 1);
    if (!full) { free(ref); free(pat); return; }
    strcpy(full, ref);
    strcat(full, pat);
    if (full[0] == '\0') {
        conn_replyf(c, "* %s (\\Noselect) \".\" \"\"\r\n", sub ? "LSUB" : "LIST");
        conn_replyf(c, "%s OK %s completed\r\n", tag, sub ? "LSUB" : "LIST");
        free(full);
        free(ref);
        free(pat);
        return;
    }
    if (imapd_wildmat(full, "INBOX")) {
        conn_replyf(c, "* %s (\\HasNoChildren %s) \".\" INBOX\r\n",
                    sub ? "LSUB" : "LIST",
                    special_use("INBOX") ? special_use("INBOX") : "");
    }
    if (!sub) {
        if (imapd_mbox_list(&srv->cfg, c->user, full, &names, &nnames) == 0) {
            for (i = 0; i < nnames; i++) {
                const char *su = special_use(names[i]);
                conn_replyf(c, "* LIST (\\HasNoChildren %s) \".\" %s\r\n",
                            su ? su : "", names[i]);
            }
        }
    } else {
        char subfile[4096 + IMAPD_MAX_USER];
        char *buf = NULL;
        size_t buflen = 0;
        const char *p;
        if (snprintf(subfile, sizeof subfile, "%s/%s/%s", srv->cfg.root,
                     c->user, IMAPD_SUBS_FILE) < (int)sizeof subfile &&
            read_file(subfile, &buf, &buflen) == 0) {
            p = buf;
            while (*p) {
                size_t ll = strcspn(p, "\n");
                char *name = malloc(ll + 1);
                if (!name) break;
                memcpy(name, p, ll);
                name[ll] = '\0';
                p += ll;
                if (*p == '\n') p++;
                if (imapd_wildmat(full, name)) {
                    bool exists = ascii_ieq_str(name, "INBOX");
                    char dir[4096];
                    struct stat st;
                    if (!exists &&
                        imapd_mbox_dir(&srv->cfg, c->user, name, dir,
                                       sizeof dir) == 0 &&
                        stat(dir, &st) == 0 && S_ISDIR(st.st_mode))
                        exists = true;
                    if (exists)
                        conn_replyf(c, "* LSUB (\\HasNoChildren) \".\" %s\r\n",
                                    name);
                }
                free(name);
            }
            free(buf);
        }
    }
    conn_replyf(c, "%s OK %s completed\r\n", tag, sub ? "LSUB" : "LIST");
    if (names) {
        for (i = 0; i < nnames; i++) free(names[i]);
        free(names);
    }
    free(full);
    free(ref);
    free(pat);
}

static void do_select(ImapdServer *srv, Conn *c, const char *tag,
                      const char *rest, bool examine) {
    char *name = NULL;
    size_t nl;
    Mbox mb;
    char dir[4096];
    struct stat st;
    if (c->ist == IST_NOT_AUTH) {
        conn_replyf(c, "%s BAD %s not allowed now\r\n", tag,
                    examine ? "EXAMINE" : "SELECT");
        return;
    }
    if (imapd_next_astring(&rest, &name, &nl) != 1) {
        conn_replyf(c, "%s BAD %s requires a mailbox name\r\n", tag,
                    examine ? "EXAMINE" : "SELECT");
        return;
    }
    imapd_fetch_free(c);
    {
        bool is_inbox = ascii_ieq_str(name, "INBOX");
        if (imapd_mbox_dir(&srv->cfg, c->user, name, dir, sizeof dir) != 0 ||
            (!is_inbox && (stat(dir, &st) != 0 || !S_ISDIR(st.st_mode))) ||
            imapd_mbox_open(&srv->cfg, c->user, name, &mb) != 0) {
            close_selected(c);
            conn_replyf(c, "%s NO Mailbox doesn't exist: %s\r\n", tag, name);
            free(name);
            return;
        }
    }
    close_selected(c);
    c->mb = mb;
    c->mb_open = true;
    snprintf(c->mbname, sizeof c->mbname, "%s",
             ascii_ieq_str(name, "INBOX") ? "INBOX" : name);
    c->ist = IST_SELECTED;
    c->examine = examine;
    {
        size_t recent = 0, unseen = 0, i;
        bool have_unseen = false;
        char flags[128], idbuf[64];
        for (i = 0; i < c->mb.nmsgs; i++) {
            if (c->mb.msgs[i].recent) recent++;
            if (!have_unseen && !(c->mb.msgs[i].flags & IMAIL_SEEN)) {
                have_unseen = true;
                unseen = i + 1;
            }
        }
        conn_replyf(c, "* %zu EXISTS\r\n", c->mb.nmsgs);
        conn_replyf(c, "* %zu RECENT\r\n", recent);
        if (have_unseen)
            conn_replyf(c, "* OK [UNSEEN %zu] First unseen\r\n", unseen);
        conn_replyf(c, "* OK [UIDVALIDITY %u] UIDs valid\r\n",
                    c->mb.uidvalidity);
        conn_replyf(c, "* OK [UIDNEXT %u] Predicted next UID\r\n",
                    c->mb.uidnext);
        conn_replyf(c, "* OK [HIGHESTMODSEQ %llu] Highest modseq\r\n",
                    (unsigned long long)c->mb.highestmodseq);
        conn_reply(c, "* FLAGS (\\Answered \\Flagged \\Deleted \\Seen "
                      "\\Draft)\r\n");
        conn_reply(c, "* OK [PERMANENTFLAGS (\\Answered \\Flagged \\Deleted "
                      "\\Seen \\Draft)] Limited\r\n");
        (void)flags;
        (void)idbuf;
        conn_replyf(c, "%s OK [%s] %s completed\r\n", tag,
                    examine ? "READ-ONLY" : "READ-WRITE",
                    examine ? "EXAMINE" : "SELECT");
    }
    free(name);
}

static void do_create(ImapdServer *srv, Conn *c, const char *tag,
                      const char *rest) {
    char *name = NULL;
    size_t nl;
    char dir[4096];
    struct stat st;
    if (c->ist == IST_NOT_AUTH) {
        conn_replyf(c, "%s BAD CREATE not allowed now\r\n", tag);
        return;
    }
    if (imapd_next_astring(&rest, &name, &nl) != 1) {
        conn_replyf(c, "%s BAD CREATE requires a mailbox name\r\n", tag);
        return;
    }
    if (ascii_ieq_str(name, "INBOX")) {
        conn_replyf(c, "%s NO INBOX exists\r\n", tag);
    } else if (imapd_mbox_dir(&srv->cfg, c->user, name, dir, sizeof dir) != 0) {
        conn_replyf(c, "%s NO Invalid mailbox name\r\n", tag);
    } else if (stat(dir, &st) == 0) {
        conn_replyf(c, "%s NO Mailbox already exists\r\n", tag);
    } else if (imapd_mbox_create(dir) != 0) {
        conn_replyf(c, "%s NO CREATE failed\r\n", tag);
    } else {
        conn_replyf(c, "%s OK CREATE completed\r\n", tag);
    }
    free(name);
}

static void do_delete(ImapdServer *srv, Conn *c, const char *tag,
                      const char *rest) {
    char *name = NULL;
    size_t nl;
    char dir[4096];
    if (c->ist == IST_NOT_AUTH) {
        conn_replyf(c, "%s BAD DELETE not allowed now\r\n", tag);
        return;
    }
    if (imapd_next_astring(&rest, &name, &nl) != 1) {
        conn_replyf(c, "%s BAD DELETE requires a mailbox name\r\n", tag);
        return;
    }
    if (ascii_ieq_str(name, "INBOX")) {
        conn_replyf(c, "%s NO INBOX cannot be deleted\r\n", tag);
    } else if (imapd_mbox_dir(&srv->cfg, c->user, name, dir, sizeof dir) != 0 ||
               imapd_mbox_delete(dir) != 0) {
        conn_replyf(c, "%s NO DELETE failed\r\n", tag);
    } else {
        conn_replyf(c, "%s OK DELETE completed\r\n", tag);
    }
    free(name);
}

static void do_rename(ImapdServer *srv, Conn *c, const char *tag,
                      const char *rest) {
    char *oldname = NULL, *newname = NULL;
    size_t ol = 0, nl = 0;
    char odir[4096], ndir[4096];
    struct stat st;
    if (c->ist == IST_NOT_AUTH) {
        conn_replyf(c, "%s BAD RENAME not allowed now\r\n", tag);
        return;
    }
    if (imapd_next_astring(&rest, &oldname, &ol) != 1 ||
        imapd_next_astring(&rest, &newname, &nl) != 1) {
        conn_replyf(c, "%s BAD RENAME requires old and new mailbox\r\n", tag);
        goto out;
    }
    if (ascii_ieq_str(oldname, "INBOX")) {
        conn_replyf(c, "%s NO INBOX cannot be renamed\r\n", tag);
    } else if (ascii_ieq_str(newname, "INBOX")) {
        conn_replyf(c, "%s NO INBOX is a reserved name\r\n", tag);
    } else if (imapd_mbox_dir(&srv->cfg, c->user, oldname, odir,
                              sizeof odir) != 0 ||
               imapd_mbox_dir(&srv->cfg, c->user, newname, ndir,
                              sizeof ndir) != 0) {
        conn_replyf(c, "%s NO Invalid mailbox name\r\n", tag);
    } else if (stat(odir, &st) != 0) {
        conn_replyf(c, "%s NO Source mailbox does not exist\r\n", tag);
    } else if (stat(ndir, &st) == 0) {
        conn_replyf(c, "%s NO Destination mailbox already exists\r\n", tag);
    } else if (rename(odir, ndir) != 0) {
        conn_replyf(c, "%s NO RENAME failed\r\n", tag);
    } else {
        conn_replyf(c, "%s OK RENAME completed\r\n", tag);
    }
out:
    free(oldname);
    free(newname);
}

static void do_subscribe(ImapdServer *srv, Conn *c, const char *tag,
                         const char *rest, bool add) {
    char *name = NULL;
    size_t nl;
    char path[4096 + IMAPD_MAX_USER];
    if (c->ist == IST_NOT_AUTH) {
        conn_replyf(c, "%s BAD %s not allowed now\r\n", tag,
                    add ? "SUBSCRIBE" : "UNSUBSCRIBE");
        return;
    }
    if (imapd_next_astring(&rest, &name, &nl) != 1) {
        conn_replyf(c, "%s BAD %s requires a mailbox name\r\n", tag,
                    add ? "SUBSCRIBE" : "UNSUBSCRIBE");
        return;
    }
    if (snprintf(path, sizeof path, "%s/%s/%s", srv->cfg.root, c->user,
                 IMAPD_SUBS_FILE) >= (int)sizeof path ||
        imapd_sub_write(path, ascii_ieq_str(name, "INBOX") ? "INBOX" : name,
                        add) != 0)
        conn_replyf(c, "%s NO %s failed\r\n", tag,
                    add ? "SUBSCRIBE" : "UNSUBSCRIBE");
    else
        conn_replyf(c, "%s OK %s completed\r\n", tag,
                    add ? "SUBSCRIBE" : "UNSUBSCRIBE");
    free(name);
}

static void do_status(ImapdServer *srv, Conn *c, const char *tag,
                      const char *rest) {
    char *name = NULL;
    size_t nl;
    char **items = NULL;
    size_t nitems = 0, i;
    Mbox mb;
    if (c->ist == IST_NOT_AUTH) {
        conn_replyf(c, "%s BAD STATUS not allowed now\r\n", tag);
        return;
    }
    if (imapd_next_astring(&rest, &name, &nl) != 1 ||
        imapd_parse_plain_list(&rest, &items, &nitems) != 0) {
        conn_replyf(c, "%s BAD STATUS requires a mailbox and an item list\r\n",
                    tag);
        free(name);
        return;
    }
    if (imapd_mbox_peek(&srv->cfg, c->user, name, &mb) != 0) {
        conn_replyf(c, "%s NO Mailbox doesn't exist: %s\r\n", tag, name);
        free(name);
        return;
    }
    {
        char *out = NULL;
        size_t outlen = 0, outcap = 0;
        size_t recent = 0, unseen = 0;
        for (i = 0; i < mb.nmsgs; i++) {
            if (mb.msgs[i].recent) recent++;
            if (!(mb.msgs[i].flags & IMAIL_SEEN)) unseen++;
        }
        if (buf_appendf(&out, &outlen, &outcap, "* STATUS %s (", name) == 0) {
            bool first = true;
            for (i = 0; i < nitems; i++) {
                const char *it = items[i];
                const char *frag = NULL;
                char val[64];
                if (ascii_ieq_str(it, "MESSAGES")) {
                    snprintf(val, sizeof val, "MESSAGES %zu", mb.nmsgs);
                    frag = val;
                } else if (ascii_ieq_str(it, "RECENT")) {
                    snprintf(val, sizeof val, "RECENT %zu", recent);
                    frag = val;
                } else if (ascii_ieq_str(it, "UIDNEXT")) {
                    snprintf(val, sizeof val, "UIDNEXT %u", mb.uidnext);
                    frag = val;
                } else if (ascii_ieq_str(it, "UIDVALIDITY")) {
                    snprintf(val, sizeof val, "UIDVALIDITY %u",
                             mb.uidvalidity);
                    frag = val;
                } else if (ascii_ieq_str(it, "UNSEEN")) {
                    snprintf(val, sizeof val, "UNSEEN %zu", unseen);
                    frag = val;
                }
                if (frag) {
                    (void)buf_appendf(&out, &outlen, &outcap, "%s%s",
                                      first ? "" : " ", frag);
                    first = false;
                }
            }
            (void)buf_append(&out, &outlen, &outcap, ")\r\n", 3);
            conn_reply(c, out);
        }
        free(out);
    }
    imapd_mbox_close(&mb);
    conn_replyf(c, "%s OK STATUS completed\r\n", tag);
    for (i = 0; i < nitems; i++) free(items[i]);
    free(items);
    free(name);
}

static void do_append(ImapdServer *srv, Conn *c, const char *tag,
                      const char *rest) {
    char *name = NULL, *a1 = NULL, *a2 = NULL;
    size_t nl, a1l, a2l;
    uint8_t flags = 0;
    char dir[4096];
    if (c->ist == IST_NOT_AUTH) {
        conn_replyf(c, "%s BAD APPEND not allowed now\r\n", tag);
        return;
    }
    if (imapd_next_astring(&rest, &name, &nl) != 1) {
        conn_replyf(c, "%s BAD APPEND requires a mailbox name\r\n", tag);
        return;
    }
    while (*rest == ' ') rest++;
    if (*rest == '(') {
        char **fl = NULL;
        size_t nfl = 0, i;
        if (imapd_parse_plain_list(&rest, &fl, &nfl) != 0) {
            conn_replyf(c, "%s BAD APPEND invalid flag list\r\n", tag);
            free(name);
            return;
        }
        for (i = 0; i < nfl; i++) {
            uint32_t b = flag_from_name(fl[i]);
            if (b == IMAIL_RECENT) continue;   /* never settable */
            flags |= (uint8_t)b;
        }
        for (i = 0; i < nfl; i++) free(fl[i]);
        free(fl);
        while (*rest == ' ') rest++;
    }
    /* a1 may be the optional date-time OR the message; a message literal is
       always the LAST argument, so a following astring demotes a1 to date. */
    if (imapd_next_astring(&rest, &a1, &a1l) != 1) {
        conn_replyf(c, "%s BAD APPEND requires a message literal\r\n", tag);
        free(name);
        return;
    }
    while (*rest == ' ') rest++;
    if (*rest != '\0' && imapd_next_astring(&rest, &a2, &a2l) == 1) {
        free(a1);   /* was the date-time (ignored; internal date = now) */
        a1 = a2;
        a1l = a2l;
    }
    if (imapd_mbox_dir(&srv->cfg, c->user,
                       ascii_ieq_str(name, "INBOX") ? "INBOX" : name,
                       dir, sizeof dir) != 0 ||
        imapd_mbox_deliver(dir, a1, a1l, flags, NULL) != 0) {
        conn_replyf(c, "%s NO APPEND failed\r\n", tag);
    } else {
        conn_replyf(c, "%s OK APPEND completed\r\n", tag);
    }
    free(name);
    free(a1);
}

/* COPY (move=false) / MOVE (move=true): file the selected messages into
   the named mailbox.  MOVE additionally expunges them from the selected
   mailbox (RFC 6851), sending an EXPUNGE response per removed message. */
static void do_file(ImapdServer *srv, Conn *c, const char *tag,
                    const char *rest, bool uid, bool move) {
    char *set = NULL, *name = NULL;
    size_t sl, nl;
    const char *p = rest;
    const char *cmd = move ? "MOVE" : "COPY";
    if (c->ist != IST_SELECTED) {
        conn_replyf(c, "%s BAD %s not allowed now\r\n", tag, cmd);
        return;
    }
    if (c->examine) {
        conn_replyf(c, "%s NO Mailbox is read-only\r\n", tag);
        return;
    }
    while (*p == ' ') p++;
    if (imapd_next_astring(&p, &set, &sl) != 1 || !imapd_seqset_valid(set)) {
        conn_replyf(c, "%s BAD %s invalid sequence set\r\n", tag, cmd);
        free(set);
        return;
    }
    while (*p == ' ') p++;
    if (imapd_next_astring(&p, &name, &nl) != 1) {
        conn_replyf(c, "%s BAD %s requires a mailbox name\r\n", tag, cmd);
        free(set);
        free(name);
        return;
    }
    if (ascii_ieq_str(name, c->mbname)) {
        conn_replyf(c, "%s NO cannot %s into the selected mailbox\r\n",
                    tag, move ? "move" : "copy");
        free(set);
        free(name);
        return;
    }
    imapd_fetch_free(c);
    {
        uint32_t star = uid ? c->mb.uidnext : (uint32_t)c->mb.nmsgs;
        if (move) {
            size_t i;
            for (i = c->mb.nmsgs; i > 0; i--) {
                Imail *m = &c->mb.msgs[i - 1];
                uint32_t v = uid ? m->uid : (uint32_t)i;
                if (!imapd_seqset_has(set, v, star)) continue;
                if (imapd_mbox_file(&srv->cfg, c->user, &c->mb, m->uid,
                                    name, true) == 0)
                    conn_replyf(c, "* %zu EXPUNGE\r\n", i);
            }
        } else {
            size_t i;
            for (i = 0; i < c->mb.nmsgs; i++) {
                Imail *m = &c->mb.msgs[i];
                uint32_t v = uid ? m->uid : (uint32_t)(i + 1);
                if (!imapd_seqset_has(set, v, star)) continue;
                imapd_mbox_file(&srv->cfg, c->user, &c->mb, m->uid, name,
                                false);
            }
        }
    }
    conn_replyf(c, "%s OK %s completed\r\n", tag, cmd);
    free(set);
    free(name);
}

static void do_close(ImapdServer *srv, Conn *c, const char *tag) {
    (void)srv;
    if (c->ist != IST_SELECTED) {
        conn_replyf(c, "%s BAD CLOSE not allowed now\r\n", tag);
        return;
    }
    imapd_fetch_free(c);
    if (!c->examine) {
        size_t i;
        for (i = c->mb.nmsgs; i > 0; i--) {
            if (c->mb.msgs[i - 1].flags & IMAIL_TRASHED)
                imapd_mbox_expunge(&c->mb, c->mb.msgs[i - 1].uid);
        }
    }
    close_selected(c);
    conn_replyf(c, "%s OK CLOSE completed\r\n", tag);
}

static void do_expunge(ImapdServer *srv, Conn *c, const char *tag,
                       const char *set, bool is_uid) {
    size_t i;
    (void)srv;
    if (c->ist != IST_SELECTED) {
        conn_replyf(c, "%s BAD EXPUNGE not allowed now\r\n", tag);
        return;
    }
    if (c->examine) {
        conn_replyf(c, "%s NO Mailbox is read-only\r\n", tag);
        return;
    }
    imapd_fetch_free(c);
    if (is_uid && set && !imapd_seqset_valid(set)) {
        conn_replyf(c, "%s BAD invalid sequence set\r\n", tag);
        return;
    }
    for (i = c->mb.nmsgs; i > 0; i--) {
        Imail *m = &c->mb.msgs[i - 1];
        if (!(m->flags & IMAIL_TRASHED)) continue;
        if (is_uid && set &&
            !imapd_seqset_has(set, m->uid, c->mb.uidnext))
            continue;
        conn_replyf(c, "* %zu EXPUNGE\r\n", i);
        imapd_mbox_expunge(&c->mb, m->uid);
    }
    conn_replyf(c, "%s OK EXPUNGE completed\r\n", tag);
}

static void do_store(ImapdServer *srv, Conn *c, const char *tag,
                     const char *rest, bool uid) {
    char *set = NULL;
    (void)srv;
    size_t sl;
    const char *p = rest;
    char item[32];
    size_t ilen;
    bool silent = false;
    int op = 0;   /* +1 set, -1 clear, 0 replace */
    uint8_t bits = 0, mask = 0;
    if (c->ist != IST_SELECTED) {
        conn_replyf(c, "%s BAD STORE not allowed now\r\n", tag);
        return;
    }
    if (imapd_next_astring(&p, &set, &sl) != 1 || !imapd_seqset_valid(set)) {
        conn_replyf(c, "%s BAD STORE invalid sequence set\r\n", tag);
        free(set);
        return;
    }
    while (*p == ' ') p++;
    ilen = 0;
    while (p[ilen] && p[ilen] != ' ' && p[ilen] != '(') ilen++;
    if (ilen == 0 || ilen >= sizeof item) {
        conn_replyf(c, "%s BAD STORE invalid store operation\r\n", tag);
        free(set);
        return;
    }
    memcpy(item, p, ilen);
    item[ilen] = '\0';
    p += ilen;
    if (ascii_ieq_str(item, "FLAGS")) op = 0;
    else if (ascii_ieq_str(item, "+FLAGS")) op = 1;
    else if (ascii_ieq_str(item, "-FLAGS")) op = -1;
    else if (ascii_ieq_str(item, "FLAGS.SILENT")) { op = 0; silent = true; }
    else if (ascii_ieq_str(item, "+FLAGS.SILENT")) { op = 1; silent = true; }
    else if (ascii_ieq_str(item, "-FLAGS.SILENT")) { op = -1; silent = true; }
    else {
        conn_replyf(c, "%s BAD STORE invalid store operation\r\n", tag);
        free(set);
        return;
    }
    while (*p == ' ') p++;
    if (*p == '(') p++;
    for (;;) {
        char *fl = NULL;
        size_t fll;
        uint32_t b;
        while (*p == ' ') p++;
        if (*p == ')') { p++; break; }
        if (*p == '\0') break;
        if (imapd_next_astring(&p, &fl, &fll) != 1) {
            conn_replyf(c, "%s BAD STORE invalid flag list\r\n", tag);
            free(set);
            return;
        }
        b = flag_from_name(fl);
        if (b == IMAIL_RECENT) {
            conn_replyf(c, "%s NO can't change \\Recent flag\r\n", tag);
            free(fl);
            free(set);
            return;
        }
        if (b) {
            bits |= (uint8_t)b;
            mask |= (uint8_t)b;
        }
        free(fl);
    }
    if (c->examine) {
        conn_replyf(c, "%s NO Mailbox is read-only\r\n", tag);
        free(set);
        return;
    }
    imapd_fetch_free(c);
    {
        size_t i;
        uint32_t star = uid ? c->mb.uidnext : (uint32_t)c->mb.nmsgs;
        for (i = 0; i < c->mb.nmsgs; i++) {
            Imail *m = &c->mb.msgs[i];
            uint32_t v = uid ? m->uid : (uint32_t)(i + 1);
            if (!imapd_seqset_has(set, v, star)) continue;
            {
                uint8_t nf = m->flags;
                if (op > 0) nf |= bits;
                else if (op < 0) nf &= (uint8_t)~bits;
                else nf = bits;
                if (imapd_mbox_store(&c->mb, m->uid, nf) == 0 && !silent) {
                    char fb[128];
                    flags_str(m->flags | (m->recent ? IMAIL_RECENT : 0),
                              fb, sizeof fb);
                    if (uid)
                        conn_replyf(c, "* %zu FETCH (FLAGS (%s) UID %u)\r\n",
                                    i + 1, fb, m->uid);
                    else
                        conn_replyf(c, "* %zu FETCH (FLAGS (%s))\r\n",
                                    i + 1, fb);
                }
            }
        }
    }
    conn_replyf(c, "%s OK %sSTORE completed\r\n", tag, uid ? "UID " : "");
    free(set);
}

static void do_search(ImapdServer *srv, Conn *c, const char *tag,
                      const char *rest, bool uid) {
    const char *p = rest;
    (void)srv;
    SearchKey *prog = NULL;
    char *out = NULL;
    size_t outlen = 0, outcap = 0;
    size_t i;
    bool needs;
    int r;
    if (c->ist != IST_SELECTED) {
        conn_replyf(c, "%s BAD SEARCH not allowed now\r\n", tag);
        return;
    }
    while (*p == ' ') p++;
    if (ascii_strncasecmp(p, "CHARSET ", 8) == 0) {
        char *cs = NULL;
        size_t csl;
        p += 8;
        if (imapd_next_astring(&p, &cs, &csl) != 1 ||
            (!ascii_ieq_str(cs, "UTF-8") && !ascii_ieq_str(cs, "US-ASCII"))) {
            conn_replyf(c, "%s NO [BADCHARSET (US-ASCII UTF-8)] "
                           "Charset not supported\r\n", tag);
            free(cs);
            return;
        }
        free(cs);
    }
    r = imapd_search_parse_program(&p, &prog);
    if (r != 1) {
        conn_replyf(c, "%s BAD invalid search program\r\n", tag);
        imapd_search_free(prog);
        return;
    }
    needs = imapd_search_needs_body(prog);
    (void)buf_append(&out, &outlen, &outcap, "* SEARCH", 8);
    for (i = 0; i < c->mb.nmsgs; i++) {
        Imail *m = &c->mb.msgs[i];
        char *msg = NULL;
        size_t ml = 0;
        ImailDoc doc;
        if (needs && read_file(m->path, &msg, &ml) != 0) {
            msg = NULL;
            ml = 0;
        }
        doc.m = m;
        doc.seq = i + 1;
        doc.msg = msg;
        doc.msglen = ml;
        if (imapd_search_match(prog, &doc, c->mb.uidnext, c->mb.nmsgs)) {
            char num[16];
            snprintf(num, sizeof num, " %u",
                     uid ? m->uid : (uint32_t)(i + 1));
            (void)buf_append(&out, &outlen, &outcap, num, strlen(num));
        }
        free(msg);
    }
    (void)buf_append(&out, &outlen, &outcap, "\r\n", 2);
    conn_reply(c, out);
    free(out);
    imapd_search_free(prog);
    conn_replyf(c, "%s OK %sSEARCH completed\r\n", tag, uid ? "UID " : "");
}

/* ------------------------------------------------------------------ */
/* Streaming FETCH generator                                           */
/* ------------------------------------------------------------------ */

enum {
    FI_FLAGS = 0, FI_UID, FI_INTERNALDATE, FI_SIZE, FI_RFC822,
    FI_HEADER, FI_TEXT, FI_BODY, FI_HF, FI_HFNOT, FI_ENVELOPE,
    FI_BODYSTRUCTURE, FI_PART, FI_MODSEQ
};

/* BODY[<section>] part keywords. */
enum { PS_WHOLE = 0, PS_HEADER, PS_TEXT, PS_MIME };

typedef struct FetchItem {
    int    kind;
    bool   peek;
    const char *rname;  /* response item name (RFC822/BODY[..] variants) */
    char **hf;          /* HEADER.FIELDS names (owned) */
    size_t nhf;
    bool   partial;     /* <o.n> present */
    size_t p_off, p_len;
    int    part[8];     /* MIME part path (BODY[<section>]) */
    int    npart;
    int    psec;        /* PS_* keyword */
    char   sec[64];     /* echoed section, e.g. "2.MIME" */
} FetchItem;

enum { FG_MSGSTART = 0, FG_ITEMS, FG_LIT, FG_DONE };

static int gen_puts_buf(FetchGen *g, const char *s, size_t n);

struct FetchGen {
    char     tag[IMAPD_MAX_TAG + 1];
    bool     uid;
    uint64_t changedsince;   /* CONDSTORE: skip msgs with modseq <= this */
    size_t  *msgs;      /* 0-based indices into mb.msgs (owned) */
    size_t   nmsgs, msg_i;
    FetchItem *items;   /* owned */
    size_t   nitems;
    size_t   item_i;
    int      phase;
    bool     need_sep;
    int      lit_fd;    /* -1 when streaming from lit_buf */
    char    *lit_buf;   /* owned literal source buffer (HEADER.FIELDS) */
    size_t   lit_buf_off;
    size_t   lit_skip, lit_left;
    char    *gen;       /* small response fragments (owned) */
    size_t   gen_len, gen_cap;
    char    *hdrbuf;    /* per-message header scan buffer (owned) */
    size_t   hdrlen, hdr_end;
    bool     hdr_loaded;
};

static int gen_puts(FetchGen *g, const char *s) {
    return buf_append(&g->gen, &g->gen_len, &g->gen_cap, s, strlen(s));
}

static int gen_printf(FetchGen *g, const char *fmt, ...) {
    char tmp[512];
    va_list ap;
    int n;
    va_start(ap, fmt);
    n = vsnprintf(tmp, sizeof tmp, fmt, ap);
    va_end(ap);
    if (n < 0 || (size_t)n >= sizeof tmp) return -1;
    return buf_append(&g->gen, &g->gen_len, &g->gen_cap, tmp, (size_t)n);
}

static void fetch_fail(Conn *c, FetchGen *g) {
    conn_replyf(c, "%s NO FETCH failed\r\n", g->tag);
    imapd_fetch_free(c);
}

static void fetch_item_free(FetchItem *it) {
    size_t i;
    for (i = 0; i < it->nhf; i++) free(it->hf[i]);
    free(it->hf);
}

/* Parse "<o.n>" (the text right after a fetch section's closing ']'). */
static bool parse_partial(const char *s, FetchItem *it) {
    const char *p = s;
    unsigned long long off = 0, len = 0;
    if (*p == '\0') return true;
    if (*p != '<') return false;
    p++;
    if (*p < '0' || *p > '9') return false;
    while (*p >= '0' && *p <= '9') { off = off * 10 + (unsigned)(*p - '0'); p++; }
    if (*p != '.') return false;
    p++;
    if (*p < '0' || *p > '9') return false;
    while (*p >= '0' && *p <= '9') { len = len * 10 + (unsigned)(*p - '0'); p++; }
    if (*p != '>' || p[1] != '\0') return false;
    it->partial = true;
    it->p_off = (size_t)off;
    it->p_len = (size_t)len;
    return true;
}

/* Parse the section between '[' and ']' (NUL-terminated slice s). */
static int section_parse(const char *s, FetchItem *it) {
    const char *q;
    if (!*s) { it->kind = FI_BODY; return 0; }
    if (ascii_ieq_str(s, "HEADER")) { it->kind = FI_HEADER; return 0; }
    if (ascii_ieq_str(s, "TEXT")) { it->kind = FI_TEXT; return 0; }
    if (ascii_strncasecmp(s, "HEADER.FIELDS", 13) == 0) {
        q = s + 13;
        if (ascii_strncasecmp(q, ".NOT", 4) == 0) {
            it->kind = FI_HFNOT;
            q += 4;
        } else {
            it->kind = FI_HF;
        }
        while (*q == ' ') q++;
        if (*q != '(') return -1;
        if (imapd_parse_plain_list(&q, &it->hf, &it->nhf) != 0) return -1;
        while (*q == ' ') q++;
        return *q == '\0' ? 0 : -1;
    }
    /* MIME part section: "1", "1.2", "1.TEXT", "2.MIME", "1.HEADER",
       "1.2.TEXT", with optional "<o.n>" partial handled by the caller. */
    {
        const char *p = s;
        int npart = 0;
        while (npart < 8) {
            int v = 0;
            if (*p < '0' || *p > '9') return -1;
            while (*p >= '0' && *p <= '9') {
                v = v * 10 + (unsigned)(*p - '0');
                p++;
            }
            if (v <= 0) return -1;
            it->part[npart++] = v;
            if (*p == '.' && p[1] >= '0' && p[1] <= '9') {
                p++;
                continue;
            }
            break;
        }
        it->npart = npart;
        it->psec = PS_WHOLE;
        if (*p == '.') p++;
        if (*p && ascii_ieq_str(p, "TEXT")) {
            it->psec = PS_TEXT;
        } else if (*p && ascii_ieq_str(p, "MIME")) {
            it->psec = PS_MIME;
        } else if (*p && ascii_ieq_str(p, "HEADER")) {
            it->psec = PS_HEADER;
        } else if (*p) {
            return -1;   /* unsupported part keyword (e.g. HEADER.FIELDS) */
        }
        snprintf(it->sec, sizeof it->sec, "%s", s);
        it->kind = FI_PART;
        return 0;
    }
    return -1;
}

/* One fetch item token (paren- AND bracket-aware, so BODY[..HEADER.FIELDS
   (a b)] stays one token). */
static char *fetch_token(const char **p) {
    const char *s = *p, *st;
    int depth = 0, bdepth = 0;
    while (*s == ' ') s++;
    if (*s == '\0' || *s == ')') { *p = s; return NULL; }
    st = s;
    while (*s) {
        if (*s == '(') depth++;
        else if (*s == '[') bdepth++;
        else if (*s == ')') {
            if (depth == 0) break;
            depth--;
        } else if (*s == ']') {
            if (bdepth > 0) bdepth--;
        } else if (*s == ' ' && depth == 0 && bdepth == 0) break;
        s++;
    }
    *p = s;
    {
        size_t n = (size_t)(s - st);
        char *tok = malloc(n + 1);
        if (!tok) return NULL;
        memcpy(tok, st, n);
        tok[n] = '\0';
        return tok;
    }
}

static int item_push(FetchItem **arr, size_t *n, size_t *cap, FetchItem it) {
    if (*n == *cap) {
        size_t nc = *cap ? *cap * 2 : 8;
        FetchItem *na = realloc(*arr, nc * sizeof *na);
        if (!na) return -1;
        *arr = na;
        *cap = nc;
    }
    (*arr)[(*n)++] = it;
    return 0;
}

/* Parse the item list of a FETCH command.  0 ok, -1 malformed, -2 item
   kind unsupported in v1. */
static int fetch_parse_items(const char **p, FetchItem **out, size_t *nout) {
    const char *s = *p;
    FetchItem *arr = NULL;
    size_t n = 0, cap = 0;
    char *tok = NULL;
    int rc = -1;
    *out = NULL;
    *nout = 0;
    while (*s == ' ') s++;
    if (*s == '(') s++;
    for (;;) {
        while (*s == ' ') s++;
        if (*s == ')') { s++; break; }
        if (*s == '\0') break;
        tok = fetch_token(&s);
        if (!tok) goto out;
        if (ascii_ieq_str(tok, "ALL") || ascii_ieq_str(tok, "FAST") ||
            ascii_ieq_str(tok, "FULL")) {
            FetchItem f;
            memset(&f, 0, sizeof f);
            f.kind = FI_FLAGS;
            if (item_push(&arr, &n, &cap, f) != 0) goto out;
            f.kind = FI_INTERNALDATE;
            if (item_push(&arr, &n, &cap, f) != 0) goto out;
            f.kind = FI_SIZE;
            if (item_push(&arr, &n, &cap, f) != 0) goto out;
        } else if (ascii_ieq_str(tok, "ENVELOPE")) {
            FetchItem f;
            memset(&f, 0, sizeof f);
            f.kind = FI_ENVELOPE;
            if (item_push(&arr, &n, &cap, f) != 0) goto out;
        } else if (ascii_ieq_str(tok, "BODYSTRUCTURE")) {
            FetchItem f;
            memset(&f, 0, sizeof f);
            f.kind = FI_BODYSTRUCTURE;
            if (item_push(&arr, &n, &cap, f) != 0) goto out;
        } else if (ascii_ieq_str(tok, "BODY")) {
            rc = -2;
            goto out;
        } else {
            FetchItem f;
            int sr;
            memset(&f, 0, sizeof f);
            if (ascii_ieq_str(tok, "FLAGS")) {
                f.kind = FI_FLAGS;
                if (item_push(&arr, &n, &cap, f) != 0) goto out;
            } else if (ascii_ieq_str(tok, "UID")) {
                f.kind = FI_UID;
                if (item_push(&arr, &n, &cap, f) != 0) goto out;
            } else if (ascii_ieq_str(tok, "INTERNALDATE")) {
                f.kind = FI_INTERNALDATE;
                if (item_push(&arr, &n, &cap, f) != 0) goto out;
            } else if (ascii_ieq_str(tok, "RFC822.SIZE")) {
                f.kind = FI_SIZE;
                if (item_push(&arr, &n, &cap, f) != 0) goto out;
            } else if (ascii_ieq_str(tok, "MODSEQ")) {
                f.kind = FI_MODSEQ;
                if (item_push(&arr, &n, &cap, f) != 0) goto out;
            } else if (ascii_ieq_str(tok, "RFC822")) {
                f.kind = FI_RFC822;
                f.rname = "RFC822";
                if (item_push(&arr, &n, &cap, f) != 0) goto out;
            } else if (ascii_ieq_str(tok, "RFC822.HEADER")) {
                f.kind = FI_HEADER;
                f.peek = true;
                f.rname = "RFC822.HEADER";
                if (item_push(&arr, &n, &cap, f) != 0) goto out;
            } else if (ascii_ieq_str(tok, "RFC822.TEXT")) {
                f.kind = FI_TEXT;
                f.rname = "RFC822.TEXT";
                if (item_push(&arr, &n, &cap, f) != 0) goto out;
            } else if (ascii_strncasecmp(tok, "BODY.PEEK[", 10) == 0 ||
                       ascii_strncasecmp(tok, "BODY[", 5) == 0) {
                bool peek = ascii_strncasecmp(tok, "BODY.PEEK[", 10) == 0;
                const char *sect = tok + (peek ? 10 : 5);
                const char *close = strchr(sect, ']');
                char *slice;
                size_t slen;
                if (!close) goto out;
                slen = (size_t)(close - sect);
                slice = malloc(slen + 1);
                if (!slice) goto out;
                memcpy(slice, sect, slen);
                slice[slen] = '\0';
                f.peek = peek;
                sr = section_parse(slice, &f);
                free(slice);
                if (sr == -2) { rc = -2; goto out; }
                if (sr != 0 || !parse_partial(close + 1, &f)) goto out;
                f.rname = "BODY[]";
                if (item_push(&arr, &n, &cap, f) != 0) goto out;
            } else {
                goto out;
            }
        }
        free(tok);
        tok = NULL;
    }
    if (n == 0) goto out;
    *out = arr;
    *nout = n;
    *p = s;
    rc = 0;
out:
    free(tok);
    if (rc != 0) {
        size_t i;
        for (i = 0; i < n; i++) fetch_item_free(&arr[i]);
        free(arr);
    }
    return rc;
}

/* Load (once per message) up to IMAPD_HDR_CAP header bytes and locate the
   header/body separator. */
static int ensure_hdr(FetchGen *g, const Imail *m) {
    int fd;
    size_t want, got = 0;
    if (g->hdr_loaded) return 0;
    g->hdr_loaded = true;
    g->hdr_end = m->size;
    if (m->size == 0) return 0;
    want = m->size < IMAPD_HDR_CAP ? m->size : IMAPD_HDR_CAP;
    g->hdrbuf = malloc(want);
    if (!g->hdrbuf) return -1;
    fd = open(m->path, O_RDONLY);
    if (fd < 0) return -1;
    while (got < want) {
        ssize_t r = read(fd, g->hdrbuf + got, want - got);
        if (r < 0) {
            if (errno == EINTR) continue;
            close(fd);
            return -1;
        }
        if (r == 0) break;
        got += (size_t)r;
    }
    close(fd);
    g->hdrlen = got;
    g->hdr_end = msg_hdr_end(g->hdrbuf, got);
    if (g->hdr_end > got) g->hdr_end = got;
    return 0;
}

/* Build the BODY[HEADER.FIELDS[.NOT]] literal content (owned). */
static char *build_hf(FetchGen *g, const FetchItem *it, size_t *outlen) {
    char *buf = NULL;
    size_t bl = 0, bc = 0;
    *outlen = 0;
    if (it->kind == FI_HF) {
        size_t i;
        char val[4096];
        for (i = 0; i < it->nhf; i++) {
            if (mail_header_get(g->hdrbuf, g->hdr_end, it->hf[i],
                                val, sizeof val) == 0) {
                if (buf_appendf(&buf, &bl, &bc, "%s: %s\r\n", it->hf[i], val) != 0)
                    goto fail;
            }
        }
    } else {
        /* HEADER.FIELDS.NOT: walk logical header lines */
        size_t pos = 0;
        while (pos < g->hdr_end) {
            size_t ls = pos, le, nend;
            bool keep = true;
            size_t k;
            while (pos < g->hdr_end && g->hdrbuf[pos] != '\n') pos++;
            le = pos < g->hdr_end ? pos + 1 : pos;
            /* blank line terminates the header block */
            if (le - ls <= 2 && (le == ls ||
                (g->hdrbuf[ls] == '\r' || g->hdrbuf[ls] == '\n'))) {
                if (le == ls || g->hdrbuf[ls] == '\r' || g->hdrbuf[ls] == '\n')
                    break;
            }
            /* continuations */
            while (le < g->hdr_end &&
                   (g->hdrbuf[le] == ' ' || g->hdrbuf[le] == '\t')) {
                while (le < g->hdr_end && g->hdrbuf[le] != '\n') le++;
                if (le < g->hdr_end) le++;
            }
            nend = ls;
            while (nend < pos && g->hdrbuf[nend] != ':') nend++;
            if (nend < pos) {
                for (k = 0; k < it->nhf && keep; k++) {
                    if ((size_t)(nend - ls) == strlen(it->hf[k]) &&
                        ascii_strncasecmp(g->hdrbuf + ls, it->hf[k],
                                          nend - ls) == 0)
                        keep = false;
                }
            }
            if (keep &&
                buf_append(&buf, &bl, &bc, g->hdrbuf + ls, le - ls) != 0)
                goto fail;
            pos = le;
        }
    }
    if (buf_append(&buf, &bl, &bc, "\r\n", 2) != 0) goto fail;
    *outlen = bl;
    return buf;
fail:
    free(buf);
    return NULL;
}

/* Region (skip,len) + response name for one literal item. */
static int lit_region(ImapdServer *srv, Conn *c, FetchGen *g,
                      const Imail *m, const FetchItem *it,
                      size_t *skip, size_t *len, const char **name,
                      char *namebuf, size_t namebufsz, char **hfbuf) {
    (void)srv;
    (void)c;
    *hfbuf = NULL;
    *skip = 0;
    *len = 0;
    switch (it->kind) {
    case FI_RFC822:
        *len = m->size;
        *name = "RFC822";
        break;
    case FI_BODY:
        *len = m->size;
        *name = "BODY[]";
        break;
    case FI_HEADER:
        *len = g->hdr_end;
        *name = it->rname ? it->rname : "RFC822.HEADER";
        break;
    case FI_TEXT:
        *skip = g->hdr_end;
        *len = m->size > g->hdr_end ? m->size - g->hdr_end : 0;
        *name = it->rname ? it->rname : "RFC822.TEXT";
        break;
    case FI_HF:
    case FI_HFNOT: {
        size_t hl;
        *hfbuf = build_hf(g, it, &hl);
        if (!*hfbuf) return -1;
        *len = hl;
        snprintf(namebuf, namebufsz, "BODY[HEADER.FIELDS%s (",
                 it->kind == FI_HFNOT ? ".NOT" : "");
        {
            size_t i;
            for (i = 0; i < it->nhf; i++) {
                snprintf(namebuf + strlen(namebuf),
                         namebufsz - strlen(namebuf), "%s%s",
                         i ? " " : "", it->hf[i]);
            }
        }
        snprintf(namebuf + strlen(namebuf), namebufsz - strlen(namebuf),
                 ")]");
        *name = namebuf;
        break;
    }
    case FI_PART: {
        char *msg = NULL;
        size_t got = 0, ps = 0, pe = 0, phe = 0;
        int fd = -1, r;
        if (m->size > 0) {
            msg = malloc(m->size);
            if (!msg) return -1;
            fd = open(m->path, O_RDONLY);
            if (fd < 0) { free(msg); return -1; }
            while (got < m->size) {
                ssize_t n = read(fd, msg + got, m->size - got);
                if (n < 0) {
                    if (errno == EINTR) continue;
                    break;
                }
                if (n == 0) break;
                got += (size_t)n;
            }
            close(fd);
        }
        r = imapd_mime_part(msg ? msg : "", got, it->part, it->npart,
                            &ps, &pe, &phe);
        free(msg);
        if (r != 0) return -1;
        switch (it->psec) {
        case PS_HEADER:
        case PS_MIME:
            *skip = ps;
            *len = phe > ps ? phe - ps : 0;
            break;
        case PS_TEXT:
            *skip = phe;
            *len = pe > phe ? pe - phe : 0;
            break;
        default:
            *skip = ps;
            *len = pe > ps ? pe - ps : 0;
            break;
        }
        snprintf(namebuf, namebufsz, "BODY[%s]", it->sec);
        *name = namebuf;
        break;
    }
    default:
        return -1;
    }
    if (it->partial) {
        if (it->p_off >= *len) {
            *skip += *len;
            *len = 0;
        } else {
            *skip += it->p_off;
            *len -= it->p_off;
            if (it->p_len > 0 && it->p_len < *len) *len = it->p_len;
        }
    }
    return 0;
}

/* Read a byte range from the message file into the gen buffer. */
static int gen_append_file(FetchGen *g, const Imail *m, size_t skip,
                           size_t len) {
    int fd = open(m->path, O_RDONLY);
    char chunk[16384];
    size_t got = 0;
    if (fd < 0) return -1;
    while (got < len) {
        ssize_t r;
        size_t want = len - got;
        if (want > sizeof chunk) want = sizeof chunk;
        r = pread(fd, chunk, want, (off_t)(skip + got));
        if (r < 0) {
            if (errno == EINTR) continue;
            close(fd);
            return -1;
        }
        if (r == 0) break;
        if (gen_puts_buf(g, chunk, (size_t)r) != 0) { close(fd); return -1; }
        got += (size_t)r;
    }
    close(fd);
    return got == len ? 0 : -1;
}

static int gen_puts_buf(FetchGen *g, const char *s, size_t n) {
    return buf_append(&g->gen, &g->gen_len, &g->gen_cap, s, n);
}

/* Body-ish fetches set \Seen (unless .PEEK / read-only session). */
static void fetch_set_seen(ImapdServer *srv, Conn *c, const FetchItem *it,
                           Imail *m) {
    (void)srv;
    if (it->peek || c->examine || (m->flags & IMAIL_SEEN)) return;
    if (it->kind != FI_RFC822 && it->kind != FI_BODY && it->kind != FI_TEXT)
        return;
    m->flags |= IMAIL_SEEN;
    (void)imapd_mbox_store(&c->mb, m->uid, m->flags);
}

/* Emit one item: small values go to the gen buffer; large literals switch
   the generator into its streaming phase. */
/* --- ENVELOPE (RFC 3501) ----------------------------------------------- */

/* nstring from a byte slice: quoted string, or NIL when empty. */
static int env_nstr(char **b, size_t *l, size_t *c, const char *s, size_t n) {
    size_t i;
    if (n == 0) return buf_append(b, l, c, "NIL", 3);
    if (buf_append(b, l, c, "\"", 1) != 0) return -1;
    for (i = 0; i < n; i++) {
        char ch = s[i];
        if (ch == '"' || ch == '\\')
            if (buf_append(b, l, c, "\\", 1) != 0) return -1;
        if (buf_append(b, l, c, &ch, 1) != 0) return -1;
    }
    return buf_append(b, l, c, "\"", 1);
}

/* One address "[(name) NIL mailbox host]". Handles "Name <a@b>" and bare
   "a@b"; no routes (adl=NIL), no group syntax in v1. */
static int env_addr(char **b, size_t *l, size_t *c, const char *a,
                    const char *aend) {
    const char *p, *lt = NULL, *at = NULL;
    const char *mail, *dom;
    if (buf_append(b, l, c, "(", 1) != 0) return -1;
    for (p = a; p < aend; p++) if (*p == '<') lt = p;
    if (lt) {
        const char *gt = lt + 1, *ns = a, *ne = lt;
        while (gt < aend && *gt != '>') gt++;
        if (gt >= aend) return -1;
        while (ns < ne && (*ns == ' ' || *ns == '\t')) ns++;
        while (ne > ns && (ne[-1] == ' ' || ne[-1] == '\t')) ne--;
        if (ns < ne && *ns == '"' && ne[-1] == '"') { ns++; ne--; }
        if (ns < ne) {
            if (env_nstr(b, l, c, ns, (size_t)(ne - ns)) != 0) return -1;
        } else if (buf_append(b, l, c, "NIL", 3) != 0) return -1;
        if (buf_append(b, l, c, " NIL ", 5) != 0) return -1;
        mail = lt + 1; dom = gt;
    } else {
        if (buf_append(b, l, c, "NIL NIL ", 8) != 0) return -1;
        mail = a; dom = aend;
    }
    for (p = mail; p < dom; p++) if (*p == '@') at = p;
    if (at) {
        if (env_nstr(b, l, c, mail, (size_t)(at - mail)) != 0) return -1;
        if (buf_append(b, l, c, " ", 1) != 0) return -1;
        if (env_nstr(b, l, c, at + 1, (size_t)(dom - (at + 1))) != 0) return -1;
    } else {
        if (env_nstr(b, l, c, mail, (size_t)(dom - mail)) != 0) return -1;
        if (buf_append(b, l, c, " NIL", 4) != 0) return -1;
    }
    return buf_append(b, l, c, ")", 1);
}

/* Address-list -> "( (addr) (addr) ... )" (NIL-safe). Splits on top-level
   commas (ignoring those inside quoted strings / <angle>). */
static int env_addrlist(char **b, size_t *l, size_t *c, const char *val) {
    const char *start, *p;
    int count = 0, inq = 0, inang = 0;
    if (buf_append(b, l, c, "(", 1) != 0) return -1;
    if (!val) return buf_append(b, l, c, ")", 1);
    start = val;
    for (p = val;; p++) {
        char ch = *p;
        if (ch == '\0' || (ch == ',' && !inq && !inang)) {
            const char *e = p;
            while (e > start && (e[-1] == ' ' || e[-1] == '\t')) e--;
            if (e > start) {
                if (count && buf_append(b, l, c, " ", 1) != 0) return -1;
                if (env_addr(b, l, c, start, e) != 0) return -1;
                count++;
            }
            if (ch == '\0') break;
            start = p + 1;
        } else if (ch == '"' && !inang) {
            inq = !inq;
        } else if (ch == '<' && !inq) {
            inang = 1;
        } else if (ch == '>' && inang) {
            inang = 0;
        }
    }
    return buf_append(b, l, c, ")", 1);
}

/* Build the full ENVELOPE (...) response for a message. */
static int emit_envelope(FetchGen *g, Imail *m, char **out, size_t *ol,
                         size_t *oc) {
    static const char *alist[6] = {
        "From", "Sender", "Reply-To", "To", "Cc", "Bcc" };
    char val[4096];
    int i;
    if (ensure_hdr(g, m) != 0) return -1;
    if (buf_appendf(out, ol, oc, "ENVELOPE (") != 0) return -1;
    if (mail_header_get(g->hdrbuf, g->hdr_end, "Date", val, sizeof val) == 0)
        (void)env_nstr(out, ol, oc, val, strlen(val));
    else if (buf_append(out, ol, oc, "NIL", 3) != 0) return -1;
    if (buf_append(out, ol, oc, " ", 1) != 0) return -1;
    if (mail_header_get(g->hdrbuf, g->hdr_end, "Subject", val, sizeof val) == 0)
        (void)env_nstr(out, ol, oc, val, strlen(val));
    else if (buf_append(out, ol, oc, "NIL", 3) != 0) return -1;
    for (i = 0; i < 6; i++) {
        if (buf_append(out, ol, oc, " ", 1) != 0) return -1;
        if (mail_header_get(g->hdrbuf, g->hdr_end, alist[i], val,
                            sizeof val) == 0)
            (void)env_addrlist(out, ol, oc, val);
        else if (buf_append(out, ol, oc, "NIL", 3) != 0) return -1;
    }
    if (buf_append(out, ol, oc, " ", 1) != 0) return -1;
    if (mail_header_get(g->hdrbuf, g->hdr_end, "In-Reply-To", val,
                        sizeof val) == 0)
        (void)env_nstr(out, ol, oc, val, strlen(val));
    else if (buf_append(out, ol, oc, "NIL", 3) != 0) return -1;
    if (buf_append(out, ol, oc, " ", 1) != 0) return -1;
    if (mail_header_get(g->hdrbuf, g->hdr_end, "Message-ID", val,
                        sizeof val) == 0)
        (void)env_nstr(out, ol, oc, val, strlen(val));
    else if (buf_append(out, ol, oc, "NIL", 3) != 0) return -1;
    return buf_append(out, ol, oc, ")", 1);
}

static int emit_item(ImapdServer *srv, Conn *c, FetchGen *g) {
    Imail *m = &c->mb.msgs[g->msgs[g->msg_i]];
    FetchItem *it = &g->items[g->item_i];
    size_t skip = 0, len = 0;
    const char *name = "";
    char namebuf[512];
    char *hfbuf = NULL;

    switch (it->kind) {
    case FI_FLAGS: {
        char fb[128];
        flags_str(m->flags | (m->recent ? IMAIL_RECENT : 0), fb, sizeof fb);
        return gen_printf(g, "FLAGS (%s)", fb);
    }
    case FI_UID:
        return gen_printf(g, "UID %u", m->uid);
    case FI_INTERNALDATE: {
        char idbuf[64];
        idate_str(m->internal_date, idbuf, sizeof idbuf);
        return gen_printf(g, "INTERNALDATE %s", idbuf);
    }
    case FI_SIZE:
        return gen_printf(g, "RFC822.SIZE %zu", m->size);
    case FI_MODSEQ:
        return gen_printf(g, "MODSEQ (%llu)",
                          (unsigned long long)m->modseq);
    case FI_ENVELOPE: {
        char *eb = NULL;
        size_t el = 0, ec = 0;
        int r;
        if (emit_envelope(g, m, &eb, &el, &ec) != 0) { free(eb); return -1; }
        r = gen_puts_buf(g, eb, el);
        free(eb);
        return r;
    }
    case FI_BODYSTRUCTURE: {
        char *msg = NULL, *bs = NULL;
        size_t bslen = 0, got = 0;
        int fd = -1, r;
        if (m->size > 0) {
            msg = malloc(m->size);
            if (!msg) return -1;
            fd = open(m->path, O_RDONLY);
            if (fd < 0) { free(msg); return -1; }
            while (got < m->size) {
                ssize_t n = read(fd, msg + got, m->size - got);
                if (n < 0) {
                    if (errno == EINTR) continue;
                    break;
                }
                if (n == 0) break;
                got += (size_t)n;
            }
            close(fd);
        }
        r = imapd_bodystructure(msg ? msg : "", got, &bs, &bslen);
        free(msg);
        if (r != 0) return -1;
        r = gen_puts(g, "BODYSTRUCTURE ");
        if (r == 0) r = gen_puts_buf(g, bs, bslen);
        free(bs);
        return r;
    }
    default:
        break;
    }

    if (ensure_hdr(g, m) != 0) return -1;
    if (lit_region(srv, c, g, m, it, &skip, &len, &name,
                   namebuf, sizeof namebuf, &hfbuf) != 0) {
        free(hfbuf);
        return -1;
    }
    fetch_set_seen(srv, c, it, m);
    if (gen_printf(g, "%s {%zu}\r\n", name, len) != 0) {
        free(hfbuf);
        return -1;
    }
    if (len == 0) {
        free(hfbuf);
        return 0;
    }
    if (hfbuf) {
        /* HEADER.FIELDS content was built in memory (bounded by
           IMAPD_HDR_CAP): inline small ones, stream big ones. */
        if (len <= IMAPD_INLINE_LIT) {
            if (gen_puts_buf(g, hfbuf + skip, len) != 0) {
                free(hfbuf);
                return -1;
            }
            free(hfbuf);
            return 0;
        }
        g->lit_buf = hfbuf;
        g->lit_buf_off = 0;
        g->lit_skip = skip;
        g->lit_left = len;
        g->lit_fd = -1;
        g->phase = FG_LIT;
        return 0;
    }
    if (len <= IMAPD_INLINE_LIT)
        return gen_append_file(g, m, skip, len);
    g->lit_fd = open(m->path, O_RDONLY);
    if (g->lit_fd < 0) return -1;
    g->lit_buf = NULL;
    g->lit_buf_off = 0;
    g->lit_skip = skip;
    g->lit_left = len;
    g->phase = FG_LIT;
    return 0;
}

/* Move up to one chunk of the pending literal straight into c->out. */
static void gen_flush(Conn *c, FetchGen *g);
static void stream_lit(Conn *c, FetchGen *g) {
    char chunk[16384];
    /* emit_item left the "BODY[...] {N}\r\n" header in the gen buffer; it
       must go out BEFORE the literal bytes, or the response has no framing
       and clients abort on the raw content. */
    gen_flush(c, g);
    while (g->lit_left > 0) {
        size_t used = c->out_len - c->out_off;
        size_t room, want, got = 0;
        if (used >= IMAPD_MAX_OUT / 2) return;
        room = IMAPD_MAX_OUT / 2 - used;
        want = g->lit_left;
        if (want > sizeof chunk) want = sizeof chunk;
        if (want > room) want = room;
        if (g->lit_fd >= 0) {
            while (got < want) {
                ssize_t r = pread(g->lit_fd, chunk + got, want - got,
                                  (off_t)(g->lit_skip + g->lit_buf_off + got));
                if (r < 0) {
                    if (errno == EINTR) continue;
                    break;
                }
                if (r == 0) break;
                got += (size_t)r;
            }
        } else {
            got = want;
            memcpy(chunk, g->lit_buf + g->lit_buf_off + g->lit_skip, got);
        }
        if (got == 0) { c->closed = true; return; }
        if (buf_append(&c->out, &c->out_len, &c->out_cap, chunk, got) != 0) {
            c->closed = true;
            return;
        }
        g->lit_skip += got;
        g->lit_left -= got;
    }
    /* literal finished */
    if (g->lit_fd >= 0) { close(g->lit_fd); g->lit_fd = -1; }
    free(g->lit_buf);
    g->lit_buf = NULL;
    g->lit_buf_off = 0;
    g->lit_skip = 0;
    g->item_i++;
    g->need_sep = true;
    g->phase = FG_ITEMS;
}

static void gen_flush(Conn *c, FetchGen *g) {
    if (g->gen_len == 0) return;
    if (c->out_len > IMAPD_MAX_OUT) { c->closed = true; return; }
    if (buf_append(&c->out, &c->out_len, &c->out_cap,
                   g->gen, g->gen_len) != 0) {
        c->closed = true;
        return;
    }
    g->gen_len = 0;
    /* Only force an actual TLS/raw send when the output buffer is full:
       emitting one small FETCH per message then flushing each would cost a
       mbedtls_ssl_write syscall per message (30k messages => 30k encrypts,
       ~30s for a 1.2MB UID FLAGS sync).  Batching into IMAPD_MAX_OUT chunks
       makes the wire send amortized; the poll loop flushes leftovers on
       POLLOUT and the FG_DONE path flushes the tail. */
    if (c->out_len - c->out_off >= IMAPD_MAX_OUT / 2) conn_flush(c);
}

void imapd_fetch_pump(ImapdServer *srv, Conn *c) {
    FetchGen *g = c->fg;
    if (!g) return;
    while (!c->closed && g->phase != FG_DONE &&
           (c->out_len - c->out_off) < IMAPD_MAX_OUT / 2) {
        switch (g->phase) {
        case FG_MSGSTART:
            g->gen_len = 0;
            if (gen_printf(g, "* %zu FETCH (", g->msgs[g->msg_i] + 1) != 0) {
                fetch_fail(c, g);
                return;
            }
            g->item_i = 0;
            g->need_sep = false;
            g->hdr_loaded = false;
            free(g->hdrbuf);
            g->hdrbuf = NULL;
            g->hdrlen = g->hdr_end = 0;
            g->phase = FG_ITEMS;
            break;
        case FG_ITEMS:
            if (g->item_i < g->nitems) {
                if (g->need_sep) gen_puts(g, " ");
                if (emit_item(srv, c, g) != 0) {
                    fetch_fail(c, g);
                    return;
                }
                if (g->phase == FG_ITEMS) {   /* fully emitted inline */
                    g->item_i++;
                    g->need_sep = true;
                }
            } else {
                if (gen_puts(g, ")\r\n") != 0) { fetch_fail(c, g); return; }
                gen_flush(c, g);
                if (c->closed) return;
                g->msg_i++;
                g->phase = (g->msg_i < g->nmsgs) ? FG_MSGSTART : FG_DONE;
            }
            break;
        case FG_LIT:
            stream_lit(c, g);
            if (c->closed) return;
            break;
        default:
            g->phase = FG_DONE;
            break;
        }
    }
    if (!c->closed && g->phase == FG_DONE) {
        gen_flush(c, g);
        conn_replyf(c, "%s OK FETCH completed\r\n", g->tag);
        imapd_fetch_free(c);
    }
}

void imapd_fetch_free(Conn *c) {
    FetchGen *g = c->fg;
    size_t i;
    if (!g) return;
    if (g->lit_fd >= 0) close(g->lit_fd);
    free(g->lit_buf);
    for (i = 0; i < g->nitems; i++) fetch_item_free(&g->items[i]);
    free(g->items);
    free(g->msgs);
    free(g->gen);
    free(g->hdrbuf);
    free(g);
    c->fg = NULL;
}

/* Build the per-message index list for the FETCH set. */
static int fetch_build_msgs(Conn *c, FetchGen *g, const char *set) {
    size_t i;
    uint32_t star = g->uid ? c->mb.uidnext : (uint32_t)c->mb.nmsgs;
    g->msgs = NULL;
    g->nmsgs = 0;
    for (i = 0; i < c->mb.nmsgs; i++) {
        uint32_t v = g->uid ? c->mb.msgs[i].uid : (uint32_t)(i + 1);
        size_t *nl;
        if (!imapd_seqset_has(set, v, star)) continue;
        if (g->changedsince && c->mb.msgs[i].modseq <= g->changedsince)
            continue;   /* CONDSTORE: unchanged since the given modseq */
        nl = realloc(g->msgs, (g->nmsgs + 1) * sizeof *nl);
        if (!nl) return -1;
        g->msgs = nl;
        g->msgs[g->nmsgs++] = i;
    }
    return 0;
}

static void do_fetch(ImapdServer *srv, Conn *c, const char *tag,
                     const char *rest, bool uid) {
    const char *p = rest;
    char *set = NULL;
    size_t sl;
    FetchGen *g;
    int r;
    if (c->ist != IST_SELECTED) {
        conn_replyf(c, "%s BAD FETCH not allowed now\r\n", tag);
        return;
    }
    if (c->fg) {
        conn_replyf(c, "%s BAD FETCH already in progress\r\n", tag);
        return;
    }
    if (imapd_next_astring(&p, &set, &sl) != 1 || !imapd_seqset_valid(set)) {
        conn_replyf(c, "%s BAD FETCH invalid sequence set\r\n", tag);
        free(set);
        return;
    }
    g = calloc(1, sizeof *g);
    if (!g) { free(set); return; }
    snprintf(g->tag, sizeof g->tag, "%s", tag);
    g->uid = uid;
    g->lit_fd = -1;
    r = fetch_parse_items(&p, &g->items, &g->nitems);
    if (r != 0) {
        conn_replyf(c, "%s %s\r\n", tag,
                    r == -2 ? "NO unsupported FETCH item (v1 serves no "
                            "ENVELOPE/BODYSTRUCTURE/MIME parts)"
                            : "BAD invalid FETCH items");
        c->fg = g;
        imapd_fetch_free(c);
        free(set);
        return;
    }
    /* Optional CONDSTORE modifier: FETCH ... (CHANGEDSINCE <n> [VANISHED]).
       Must be parsed BEFORE fetch_build_msgs so the filter applies. */
    while (*p == ' ') p++;
    if (*p == '(') {
        const char *q = p + 1;
        while (*q == ' ') q++;
        if (ascii_strncasecmp(q, "CHANGEDSINCE", 12) == 0 &&
            (q[12] == ' ' || q[12] == '\t')) {
            q += 12;
            while (*q == ' ' || *q == '\t') q++;
            g->changedsince = 0;
            while (*q >= '0' && *q <= '9') {
                if (g->changedsince <= (UINT64_MAX - 9) / 10)
                    g->changedsince = g->changedsince * 10 + (uint64_t)(*q - '0');
                q++;
            }
        }
    }
    if (fetch_build_msgs(c, g, set) != 0) {
        conn_replyf(c, "%s NO FETCH out of memory\r\n", tag);
        imapd_fetch_free(c);
        c->fg = g;   /* fetch_free expects it attached */
        imapd_fetch_free(c);
        free(set);
        return;
    }
    free(set);
    if (g->nmsgs == 0) {
        conn_replyf(c, "%s OK FETCH completed\r\n", g->tag);
        c->fg = g;
        imapd_fetch_free(c);
        return;
    }
    c->fg = g;
    imapd_fetch_pump(srv, c);
}

/* ------------------------------------------------------------------ */
/* Command reader (literal assembly) + dispatcher                      */
/* ------------------------------------------------------------------ */

static void dispatch(ImapdServer *srv, Conn *c);

/* Assemble complete commands (collecting {n} literals) and dispatch them. */
static void imap_process(ImapdServer *srv, Conn *c, time_t now) {
    (void)now;
    for (;;) {
        size_t i;
        if (c->closed) return;
        if (c->fg) return;   /* a streaming FETCH owns the connection */
        if (c->tls && !imapd_tls_established(c)) return;   /* handshaking */
        if (c->mode == IC_LIT) {
            size_t take;
            size_t k = 0;
            take = c->in_len < c->lit_left ? c->in_len : c->lit_left;
            while (k < take) {
                char ch = c->in[k];
                if (ch == '"' || ch == '\\') {
                    char esc[2];
                    esc[0] = '\\';
                    esc[1] = ch;
                    if (buf_append(&c->cmd, &c->cmd_len, &c->cmd_cap,
                                   esc, 2) != 0) goto oom;
                } else if (buf_append(&c->cmd, &c->cmd_len, &c->cmd_cap,
                                      &ch, 1) != 0) {
                    goto oom;
                }
                k++;
            }
            memmove(c->in, c->in + take, c->in_len - take);
            c->in_len -= take;
            c->lit_left -= take;
            if (c->lit_left > 0) return;
            if (buf_append(&c->cmd, &c->cmd_len, &c->cmd_cap, "\"", 1) != 0)
                goto oom;
            c->mode = IC_LINE;
            continue;
        }
        i = 0;
        while (i < c->in_len && c->in[i] != '\n') i++;
        if (i == c->in_len) {
            size_t lim = c->cont_auth ? 8192 : IMAPD_MAX_LINE;
            if (c->in_len > lim) {
                if (c->cont_auth) c->cont_auth = false;
                conn_reply(c, "* BAD line too long\r\n");
                c->closed = true;
            }
            return;
        }
        {
            size_t linelen = i;
            size_t consumed = i + 1;
            char *line;
            if (linelen > 0 && c->in[linelen - 1] == '\r') linelen--;
            line = malloc(linelen + 1);
            if (!line) goto oom;
            memcpy(line, c->in, linelen);
            line[linelen] = '\0';
            memmove(c->in, c->in + consumed, c->in_len - consumed);
            c->in_len -= consumed;
            if (c->cont_auth) {
                c->cont_auth = false;
                auth_cont(srv, c, line);
                free(line);
                continue;
            }
            {
                int lm = imapd_lit_marker(line);
                if (lm > 0) {
                    size_t mstart = strlen(line);
                    if ((uint64_t)lm > srv->cfg.max_msg) {
                        /* the bytes are promised either way: drop the conn */
                        conn_reply(c, "* BYE literal too large\r\n");
                        c->closed = true;
                        free(line);
                        return;
                    }
                    while (mstart > 0 && line[mstart] != '{') mstart--;
                    line[mstart] = '\0';   /* strip the {n} marker */
                    if (buf_append(&c->cmd, &c->cmd_len, &c->cmd_cap,
                                   line, strlen(line)) != 0 ||
                        buf_append(&c->cmd, &c->cmd_len, &c->cmd_cap,
                                   " \"", 2) != 0) {
                        free(line);
                        goto oom;
                    }
                    c->lit_left = (size_t)lm;
                    c->mode = IC_LIT;
                    conn_reply(c, "+ \r\n");
                    free(line);
                    continue;
                }
            }
            if (buf_append(&c->cmd, &c->cmd_len, &c->cmd_cap,
                           line, strlen(line)) != 0) {
                free(line);
                goto oom;
            }
            free(line);
            dispatch(srv, c);
            /* dispatch resets c->cmd */
        }
    }
oom:
    conn_reply(c, "* BYE out of memory\r\n");
    c->closed = true;
}

static void do_uid(ImapdServer *srv, Conn *c, const char *tag,
                   const char *rest) {
    char *sub = NULL;
    size_t sl;
    const char *p = rest;
    if (c->ist != IST_SELECTED) {
        conn_replyf(c, "%s BAD UID not allowed now\r\n", tag);
        return;
    }
    while (*p == ' ') p++;
    if (imapd_next_astring(&p, &sub, &sl) != 1) {
        conn_replyf(c, "%s BAD UID requires a command\r\n", tag);
        return;
    }
    while (*p == ' ') p++;
    if (ascii_ieq_str(sub, "FETCH")) {
        do_fetch(srv, c, tag, p, true);
    } else if (ascii_ieq_str(sub, "STORE")) {
        do_store(srv, c, tag, p, true);
    } else if (ascii_ieq_str(sub, "SEARCH")) {
        do_search(srv, c, tag, p, true);
    } else if (ascii_ieq_str(sub, "EXPUNGE")) {
        do_expunge(srv, c, tag, p, true);
    } else if (ascii_ieq_str(sub, "COPY")) {
        do_file(srv, c, tag, p, true, false);
    } else if (ascii_ieq_str(sub, "MOVE")) {
        do_file(srv, c, tag, p, true, true);
    } else {
        conn_replyf(c, "%s BAD unknown UID command\r\n", tag);
    }
    free(sub);
}

static void dispatch(ImapdServer *srv, Conn *c) {
    char *cmd = c->cmd;
    const char *p = cmd;
    char *tag = NULL, *word = NULL;
    size_t tl, wl;

    /* RFC 2177: while IDLE, the only valid client input is the untagged
       continuation "DONE" (no tag).  Anything else is rejected. */
    if (c->idle) {
        const char *q = cmd;
        while (*q == ' ') q++;
        if (ascii_ieq_str(q, "DONE")) {
            c->idle = false;
            conn_replyf(c, "%s OK IDLE completed\r\n", c->idle_tag);
        } else {
            conn_replyf(c, "%s BAD command not allowed during IDLE\r\n",
                        c->idle_tag);
        }
        goto out;
    }

    if (imapd_next_astring(&p, &tag, &tl) != 1) {
        conn_reply(c, "* BAD missing tag\r\n");
        goto out;
    }
    if (tl == 0 || tl > IMAPD_MAX_TAG) {
        conn_reply(c, "* BAD invalid tag\r\n");
        goto out;
    }
    if (imapd_next_astring(&p, &word, &wl) != 1) {
        conn_replyf(c, "%s BAD missing command\r\n", tag);
        goto out;
    }
    while (*p == ' ') p++;

    imapd_dbg("CMD user=%s tag=%s word=%s rest=%s",
              c->user ? c->user : "(preauth)", tag, word, p);

    if (ascii_ieq_str(word, "CAPABILITY")) {
        conn_replyf(c, "* CAPABILITY %s\r\n", cap_of(srv, c));
        conn_replyf(c, "%s OK CAPABILITY completed\r\n", tag);
    } else if (ascii_ieq_str(word, "NOOP")) {
        if (c->ist == IST_SELECTED) refresh_selected(srv, c);
        conn_replyf(c, "%s OK NOOP completed\r\n", tag);
    } else if (ascii_ieq_str(word, "LOGOUT")) {
        conn_reply(c, "* BYE imapd logging out\r\n");
        conn_replyf(c, "%s OK LOGOUT completed\r\n", tag);
        c->closed = true;
    } else if (ascii_ieq_str(word, "STARTTLS")) {
        /* RFC 2595: pre-auth only, never twice, and nothing may be
           pipelined after it (leftover bytes would leak into the TLS
           stream, since c->in is plaintext but the next reader is not). */
        if (c->ist != IST_NOT_AUTH || c->in_len != 0) {
            conn_replyf(c, "%s BAD STARTTLS not allowed now\r\n", tag);
        } else if (c->tls) {
            conn_replyf(c, "%s NO TLS is already active\r\n", tag);
        } else if (!imapd_tls_available(srv)) {
            conn_replyf(c, "%s NO STARTTLS not supported "
                           "(no certificate loaded)\r\n", tag);
        } else if (imapd_tls_start(srv, c) != 0) {
            conn_replyf(c, "%s NO STARTTLS out of memory\r\n", tag);
        } else {
            /* the OK reply drains in the clear (PENDING), then the poll
               loop runs the handshake and resets the session (TLS reset) */
            conn_replyf(c, "%s OK Begin TLS negotiation now\r\n", tag);
        }
    } else if (ascii_ieq_str(word, "ENABLE")) {
        /* RFC 5162: acknowledge the extensions we can enable (CONDSTORE).
           FairEmail sends ENABLE CONDSTORE after LOGIN; a bare BAD here can
           make it give up / drop the connection. */
        const char *q = p;
        bool ok = true, enabled_condstore = false;
        while (*q == ' ') q++;
        if (*q == '\0') ok = false;
        while (ok && *q) {
            char *cap = NULL;
            size_t cl;
            int r = imapd_next_astring(&q, &cap, &cl);
            if (r != 1 || cl == 0) { ok = false; free(cap); break; }
            if (ascii_ieq_str(cap, "CONDSTORE")) enabled_condstore = true;
            free(cap);
            while (*q == ' ') q++;
        }
        if (!ok) {
            conn_replyf(c, "%s BAD ENABLE requires at least one capability\r\n",
                        tag);
        } else {
            conn_replyf(c, "* ENABLED%s\r\n",
                        enabled_condstore ? " CONDSTORE" : "");
            conn_replyf(c, "%s OK ENABLE completed\r\n", tag);
        }
    } else if (ascii_ieq_str(word, "LOGIN")) {
        do_login(srv, c, tag, p);
    } else if (ascii_ieq_str(word, "AUTHENTICATE")) {
        do_authenticate(srv, c, tag, p);
    } else if (ascii_ieq_str(word, "SELECT")) {
        do_select(srv, c, tag, p, false);
    } else if (ascii_ieq_str(word, "EXAMINE")) {
        do_select(srv, c, tag, p, true);
    } else if (ascii_ieq_str(word, "CREATE")) {
        do_create(srv, c, tag, p);
    } else if (ascii_ieq_str(word, "DELETE")) {
        do_delete(srv, c, tag, p);
    } else if (ascii_ieq_str(word, "RENAME")) {
        do_rename(srv, c, tag, p);
    } else if (ascii_ieq_str(word, "SUBSCRIBE")) {
        do_subscribe(srv, c, tag, p, true);
    } else if (ascii_ieq_str(word, "UNSUBSCRIBE")) {
        do_subscribe(srv, c, tag, p, false);
    } else if (ascii_ieq_str(word, "LIST")) {
        do_list(srv, c, tag, p, false);
    } else if (ascii_ieq_str(word, "LSUB")) {
        do_list(srv, c, tag, p, true);
    } else if (ascii_ieq_str(word, "STATUS")) {
        do_status(srv, c, tag, p);
    } else if (ascii_ieq_str(word, "APPEND")) {
        do_append(srv, c, tag, p);
    } else if (ascii_ieq_str(word, "CLOSE")) {
        do_close(srv, c, tag);
    } else if (ascii_ieq_str(word, "CHECK")) {
        if (c->ist != IST_SELECTED)
            conn_replyf(c, "%s BAD CHECK not allowed now\r\n", tag);
        else {
            refresh_selected(srv, c);
            conn_replyf(c, "%s OK CHECK completed\r\n", tag);
        }
    } else if (ascii_ieq_str(word, "EXPUNGE")) {
        do_expunge(srv, c, tag, NULL, false);
    } else if (ascii_ieq_str(word, "SEARCH")) {
        do_search(srv, c, tag, p, false);
    } else if (ascii_ieq_str(word, "FETCH")) {
        do_fetch(srv, c, tag, p, false);
    } else if (ascii_ieq_str(word, "STORE")) {
        do_store(srv, c, tag, p, false);
    } else if (ascii_ieq_str(word, "COPY")) {
        do_file(srv, c, tag, p, false, false);
    } else if (ascii_ieq_str(word, "MOVE")) {
        do_file(srv, c, tag, p, false, true);
    } else if (ascii_ieq_str(word, "UID")) {
        do_uid(srv, c, tag, p);
    } else if (ascii_ieq_str(word, "IDLE")) {
        /* RFC 2177: only in SELECTED state.  Reply with a continuation, then
           refresh_selected (via the poll loop) drives unsolicited EXISTS /
           RECENT / EXPUNGE updates until the client sends DONE. */
        if (c->ist != IST_SELECTED) {
            conn_replyf(c, "%s BAD IDLE not allowed now\r\n", tag);
        } else {
            snprintf(c->idle_tag, sizeof c->idle_tag, "%s", tag);
            c->idle = true;
            conn_reply(c, "+ idling\r\n");
        }
    } else {
        conn_replyf(c, "%s BAD unknown command\r\n", tag);
    }

out:
    free(tag);
    free(word);
    free(c->cmd);
    c->cmd = NULL;
    c->cmd_len = 0;
    c->cmd_cap = 0;
}

/* ------------------------------------------------------------------ */
/* Entry points                                                        */
/* ------------------------------------------------------------------ */

void imapd_imap_greeting(ImapdServer *srv, Conn *c) {
    conn_replyf(c, "* OK [CAPABILITY %s] imapd ready\r\n", cap_of(srv, c));
}

/* Post-handshake reset: STARTTLS is only valid pre-auth, so this drops any
   half-assembled command and defensively closes a selected mailbox (the
   buffered c->in bytes are post-TLS and stay). */
void imapd_imap_tls_reset(ImapdServer *srv, Conn *c) {
    (void)srv;
    free(c->cmd);
    c->cmd = NULL;
    c->cmd_len = 0;
    c->cmd_cap = 0;
    c->mode = IC_LINE;
    c->lit_left = 0;
    c->cont_auth = false;
    c->auth_tag[0] = '\0';
    close_selected(c);
    c->ist = IST_NOT_AUTH;
    imapd_fetch_free(c);
}

void imapd_imap_readable(ImapdServer *srv, Conn *c, time_t now) {
    char tmp[IMAPD_RECV_CHUNK];

    if (c->tls) {   /* STARTTLS: poll loop drives the handshake; we drain */
        if (!imapd_tls_established(c)) return;
        for (;;) {
            /* Drain LOOP, not once: mbedtls buffers decrypted plaintext
               internally, so a single read per POLLIN can stall the
               session when several records arrived in one segment. */
            int n = imapd_tls_recv(c, tmp, sizeof tmp);
            if (n < 0) { c->closed = true; return; }
            if (n == 0) {
                /* mbedtls wants more TLS bytes; leave the connection open.
                   (Do NOT treat a pending FIN as EOF here: MSG_PEEK on the
                   raw socket can false-positive when mbedtls has buffered a
                   whole record but poll also reports POLLIN, causing a
                   graceful connection to be reset with an RST.) */
                return;
            }
            c->last_act = now;
            if (buf_append(&c->in, &c->in_len, &c->in_cap, tmp, (size_t)n)
                != 0) {
                conn_reply(c, "* BYE too much data\r\n");
                c->closed = true;
                return;
            }
            imap_process(srv, c, now);
            if (c->closed || c->fg) return;   /* a streaming FETCH owns it */
        }
    }

    {
        ssize_t n = recv(c->fd, tmp, sizeof tmp, 0);
        if (n < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
                return;
            c->closed = true;
            return;
        }
        if (n == 0) {
            c->closed = true;
            return;
        }
        c->last_act = now;
        if (buf_append(&c->in, &c->in_len, &c->in_cap, tmp, (size_t)n) != 0) {
            conn_reply(c, "* BYE too much data\r\n");
            c->closed = true;
            return;
        }
        imap_process(srv, c, now);
    }
}

/* RFC 2177 IDLE: periodically re-scan the selected mailbox.  Only emits
   unsolicited EXISTS/RECENT when the message set actually changed, so it is
   safe to call on every poll loop tick. */
void imapd_imap_idle_refresh(ImapdServer *srv, Conn *c) {
    if (!c->idle || c->ist != IST_SELECTED || c->fg) return;
    if (!c->mb_open) return;
    refresh_selected(srv, c);
}

