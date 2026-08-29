/* pop3d.c — RFC 1939 POP3 server for imapd (a companion listener).
 *
 * Serves each user's INBOX maildir over POP3 (RFC 1939 + CAPA per RFC 2449,
 * STLS per RFC 2595).  Single-threaded like the rest of imapd: the poll loop
 * (imapd.c) owns the sockets; this file is the per-connection state machine
 * for kind == CONN_POP3.
 *
 * Session states: AUTHORIZATION (PO_AUTH) -> TRANSACTION (PO_TRANS) on a
 * successful USER+PASS.  The INBOX is opened once with imapd_mbox_peek
 * (no new->cur move, so POP3 does not disturb IMAP's \Recent semantics);
 * DELE marks a message for deletion and QUIT expunges them (RFC 1939).
 *
 * Large RETR/TOP responses stream through a small dot-stuffing pump
 * (Pop3Gen) so a big message never has to fit in memory or the reply
 * buffer; the poll loop drives imapd_pop3_pump on POLLOUT.
 *
 * Cleartext USER/PASS follow RFC 2595 11.1 gating: refused on a non-loopback
 * bind until STLS completes when the daemon has a cert loaded.
 */
#include "imapd.h"
#include "mail.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>

/* ------------------------------------------------------------------ */
/* Small helpers (duplicated from imapd_imap.c / imapd_ingest.c per     */
/* house style)                                                        */
/* ------------------------------------------------------------------ */

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
        while (c->out_off < c->out_len) {
            int n = imapd_tls_send(c, c->out + c->out_off,
                                   c->out_len - c->out_off);
            if (n < 0) {
                c->closed = true;
                c->out_len = c->out_off = 0;
                return;
            }
            if (n == 0) return;
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
    if ((size_t)n >= sizeof buf) { conn_reply(c, "-ERR reply too long\r\n"); c->closed = true; return; }
    conn_reply(c, buf);
}

/* POP3 command words are at most 4 chars; compare a NUL-terminated word. */
static bool word_eq(const char *a, const char *b) {
    while (*a && *b) {
        char ca = *a++, cb = *b++;
        if (ca >= 'A' && ca <= 'Z') ca = (char)(ca + 32);
        if (cb >= 'A' && cb <= 'Z') cb = (char)(cb + 32);
        if (ca != cb) return false;
    }
    return *a == *b;
}

/* Parse a strictly-positive decimal integer (leading spaces skipped);
   returns 0 and sets *out, or -1 when absent/invalid/out of range. */
static int parse_ulong(const char *s, unsigned long *out) {
    unsigned long v = 0;
    if (!s) return -1;
    while (*s == ' ') s++;
    if (*s < '0' || *s > '9') return -1;
    while (*s >= '0' && *s <= '9') {
        v = v * 10 + (unsigned long)(*s - '0');
        if (v > 0x7fffffffUL) return -1;
        s++;
    }
    if (*s != '\0' && *s != ' ') return -1;
    *out = v;
    return 0;
}

/* Find the end of the RFC 5322 header block in buf[0..len): the byte after
   the first blank line (CRLFCRLF or LFLF).  Returns len when not found. */
static size_t hdr_end_of(const char *buf, size_t len) {
    size_t i;
    for (i = 0; i + 1 < len; i++) {
        if (buf[i] == '\n') {
            if (buf[i + 1] == '\n') return i + 2;
            if (buf[i + 1] == '\r' && i + 2 < len && buf[i + 2] == '\n')
                return i + 3;
        }
    }
    return len;
}

/* ------------------------------------------------------------------ */
/* Mailbox open + helpers                                              */
/* ------------------------------------------------------------------ */

/* Open the user's INBOX into c->mb and size the deleted-mark array.
   Returns 0 on success, -1 on failure (mbox closed, c->mb_open stays as-is). */
static int open_inbox(ImapdServer *srv, Conn *c) {
    if (imapd_mbox_peek(&srv->cfg, c->user, "INBOX", &c->mb) != 0) return -1;
    c->mb_open = true;
    if (c->mb.nmsgs > 0) {
        c->del = calloc(c->mb.nmsgs, sizeof(bool));
        if (!c->del) {
            imapd_mbox_close(&c->mb);
            c->mb_open = false;
            return -1;
        }
    }
    return 0;
}

/* Non-deleted octet total across the mailbox. */
static size_t mbox_octets(const Conn *c) {
    size_t total = 0, i;
    for (i = 0; i < c->mb.nmsgs; i++)
        if (!c->del[i]) total += c->mb.msgs[i].size;
    return total;
}

/* 1-based message number -> 0-based index, or -1 (out of range or deleted). */
static long msg_index(const Conn *c, unsigned long n) {
    if (n < 1 || n > c->mb.nmsgs) return -1;
    if (c->del[n - 1]) return -1;
    return (long)(n - 1);
}

/* ------------------------------------------------------------------ */
/* Streaming RETR/TOP generator                                        */
/* ------------------------------------------------------------------ */

enum { PG_HDR = 0, PG_BODY, PG_END, PG_DONE };

struct Pop3Gen {
    int    fd;       /* message file, -1 once fully consumed */
    size_t size;     /* bytes of the message to stream (file prefix) */
    size_t pos;      /* bytes already streamed */
    int    phase;    /* PG_HDR / PG_BODY / PG_END / PG_DONE */
    bool   bol;      /* next byte is at line start (dot-stuffing) */
};

void imapd_pop3_free(Conn *c) {
    Pop3Gen *g = c->pg;
    if (!g) return;
    if (g->fd >= 0) close(g->fd);
    free(g);
    c->pg = NULL;
}

/* Byte offset (from file start) of the message region TOP should send:
   the header block plus `n` body lines (RFC 1939).  n==0 -> headers only.
   Returns fsize when the body has fewer than n lines. */
static size_t top_cut(int fd, size_t hdr_end, size_t fsize, unsigned long n) {
    size_t off = hdr_end;
    unsigned long seen = 0;
    char buf[8192];
    if (n == 0) return hdr_end;
    while (off < fsize) {
        size_t want = fsize - off, i;
        ssize_t got;
        if (want > sizeof buf) want = sizeof buf;
        got = pread(fd, buf, want, (off_t)off);
        if (got <= 0) break;
        for (i = 0; i < (size_t)got; i++) {
            if (buf[i] == '\n') {
                seen++;
                if (seen == n) return off + i + 1;
            }
        }
        off += (size_t)got;
    }
    return fsize;
}

/* Start a streaming RETR (top < 0) or TOP n (top >= 0) of message at
   position idx.  Returns 0 on success (sets c->pg), -1 on any failure. */
static int start_retr(Conn *c, size_t idx, long top) {
    Imail *m = &c->mb.msgs[idx];
    int fd = open(m->path, O_RDONLY);
    Pop3Gen *g;
    size_t fsize = m->size;
    size_t send_end = fsize;
    if (fd < 0) return -1;
    if (top >= 0) {
        char buf[IMAPD_HDR_CAP];
        size_t got = 0, want = fsize < IMAPD_HDR_CAP ? fsize : IMAPD_HDR_CAP;
        size_t hdr_end;
        while (got < want) {
            ssize_t r = read(fd, buf + got, want - got);
            if (r < 0) {
                if (errno == EINTR) continue;
                close(fd);
                return -1;
            }
            if (r == 0) break;
            got += (size_t)r;
        }
        hdr_end = hdr_end_of(buf, got);
        send_end = top_cut(fd, hdr_end, fsize, (unsigned long)top);
    }
    g = calloc(1, sizeof *g);
    if (!g) { close(fd); return -1; }
    g->fd = fd;
    g->size = send_end;
    g->phase = PG_HDR;
    g->bol = true;
    c->pg = g;
    return 0;
}

/* Dot-stuff one raw chunk into a stuffed buffer, tracking line state. */
static size_t stuff(const char *raw, size_t n, bool *bol, char *out) {
    size_t o = 0, i;
    for (i = 0; i < n; i++) {
        char ch = raw[i];
        if (*bol && ch == '.') out[o++] = '.';
        out[o++] = ch;
        *bol = (ch == '\n');
    }
    return o;
}

void imapd_pop3_pump(ImapdServer *srv, Conn *c) {
    Pop3Gen *g = c->pg;
    (void)srv;
    if (!g) return;
    while (!c->closed && g->phase != PG_DONE) {
        if ((c->out_len - c->out_off) >= IMAPD_MAX_OUT / 2) {
            conn_flush(c);
            return;
        }
        if (g->phase == PG_HDR) {
            conn_reply(c, "+OK message follows\r\n");
            g->phase = PG_BODY;
            continue;
        }
        if (g->phase == PG_END) {
            if (!g->bol) conn_reply(c, "\r\n");
            conn_reply(c, ".\r\n");
            g->phase = PG_DONE;
            break;
        }
        /* PG_BODY: stream the next dot-stuffed chunk */
        {
            char raw[8192], stuffed[16384];
            ssize_t r;
            size_t want = g->size - g->pos;
            size_t n, o;
            if (want == 0) {           /* all message bytes consumed */
                g->phase = PG_END;
                continue;
            }
            if (want > sizeof raw) want = sizeof raw;
            r = pread(g->fd, raw, want, (off_t)g->pos);
            if (r <= 0) {              /* short read: end early, no error */
                g->phase = PG_END;
                continue;
            }
            n = (size_t)r;
            o = stuff(raw, n, &g->bol, stuffed);
            if (buf_append(&c->out, &c->out_len, &c->out_cap,
                           stuffed, o) != 0) {
                c->closed = true;
                return;
            }
            g->pos += n;
        }
    }
    if (!c->closed && g->phase == PG_DONE) {
        conn_flush(c);
        imapd_pop3_free(c);
    }
}

/* ------------------------------------------------------------------ */
/* Commands                                                            */
/* ------------------------------------------------------------------ */

static void pop3_err(Conn *c, const char *msg) {
    conn_replyf(c, "-ERR %s\r\n", msg);
}

/* RFC 2595 gating: cleartext USER/PASS allowed only when no TLS is
   configured, TLS is already up, or the POP3 bind is loopback. */
static bool cleartext_ok(const ImapdServer *srv, const Conn *c) {
    return !srv->tls_ready || imapd_tls_established(c) || srv->pop3_loopback;
}

/* Clear a marked-deleted state without touching the mailbox. */
static void pop3_reset_deleted(Conn *c) {
    if (c->del && c->mb.nmsgs > 0) memset(c->del, 0, c->mb.nmsgs);
    c->ndel = 0;
}

static void cmd_capa(ImapdServer *srv, Conn *c) {
    conn_replyf(c, "+OK Capability list follows\r\n");
    conn_reply(c, "USER\r\nUIDL\r\nTOP\r\nRESP-CODES\r\nPIPELINING\r\n");
    if (imapd_tls_available(srv) && !imapd_tls_established(c))
        conn_reply(c, "STLS\r\n");
    conn_replyf(c, "IMPLEMENTATION visage-pop3d\r\n");
    conn_reply(c, ".\r\n");
}

static void cmd_stls(ImapdServer *srv, Conn *c) {
    if (c->pst != PO_AUTH) {
        pop3_err(c, "STLS not valid in transaction state");
        return;
    }
    if (imapd_tls_established(c)) {
        pop3_err(c, "TLS already active");
        return;
    }
    if (c->in_len != 0) {
        pop3_err(c, "Pipelined data before STLS");
        return;
    }
    if (!imapd_tls_available(srv)) {
        pop3_err(c, "STLS not supported");
        return;
    }
    if (imapd_tls_start(srv, c) != 0) {
        pop3_err(c, "Could not start TLS");
        return;
    }
    /* the +OK drains in the clear (PENDING), then the poll loop runs the
       handshake and resets the session to PO_AUTH */
    conn_reply(c, "+OK Begin TLS negotiation\r\n");
}

static void cmd_user(ImapdServer *srv, Conn *c, const char *arg) {
    if (c->pst != PO_AUTH) {
        pop3_err(c, "USER not valid in transaction state");
        return;
    }
    if (!cleartext_ok(srv, c)) {
        pop3_err(c, "Cleartext login disabled; use STLS first");
        return;
    }
    if (!arg || !*arg || !imapd_user_ok(arg)) {
        pop3_err(c, "Invalid user");
        return;
    }
    free(c->pend_user);
    c->pend_user = strdup(arg);
    if (!c->pend_user) { pop3_err(c, "Out of memory"); return; }
    conn_reply(c, "+OK\r\n");
}

static void cmd_pass(ImapdServer *srv, Conn *c, const char *arg) {
    if (c->pst != PO_AUTH) {
        pop3_err(c, "PASS not valid in transaction state");
        return;
    }
    if (!cleartext_ok(srv, c)) {
        pop3_err(c, "Cleartext login disabled; use STLS first");
        free(c->pend_user);
        c->pend_user = NULL;
        return;
    }
    if (!c->pend_user || !arg || !*arg) {
        pop3_err(c, "Invalid PASS");
        free(c->pend_user);
        c->pend_user = NULL;
        return;
    }
    if (!imapd_auth_check(srv, c->pend_user, arg)) {
        /* RFC 1939: a failed PASS drops the pending USER; the client must
           re-issue USER before PASS again */
        pop3_err(c, "Invalid credentials");
        free(c->pend_user);
        c->pend_user = NULL;
        return;
    }
    free(c->user);
    c->user = strdup(c->pend_user);
    if (!c->user) { pop3_err(c, "Out of memory"); return; }
    free(c->pend_user);
    c->pend_user = NULL;
    if (open_inbox(srv, c) != 0) {
        free(c->user);
        c->user = NULL;
        pop3_err(c, "Cannot open mailbox");
        return;
    }
    c->pst = PO_TRANS;
    conn_reply(c, "+OK mailbox locked and ready\r\n");
}

static void cmd_stat(Conn *c) {
    size_t nmsg = c->mb.nmsgs - c->ndel;
    conn_replyf(c, "+OK %zu %zu\r\n", nmsg, mbox_octets(c));
}

static void cmd_list(Conn *c, const char *arg) {
    unsigned long n;
    size_t i;
    if (arg && *arg) {
        long idx;
        if (parse_ulong(arg, &n) != 0) { pop3_err(c, "Invalid message number"); return; }
        idx = msg_index(c, n);
        if (idx < 0) { pop3_err(c, "No such message"); return; }
        conn_replyf(c, "+OK %zu %zu\r\n", (size_t)n, c->mb.msgs[idx].size);
        return;
    }
    conn_replyf(c, "+OK %zu messages (%zu octets)\r\n",
                c->mb.nmsgs - c->ndel, mbox_octets(c));
    for (i = 0; i < c->mb.nmsgs; i++) {
        if (c->del[i]) continue;
        conn_replyf(c, "%zu %zu\r\n", i + 1, c->mb.msgs[i].size);
    }
    conn_reply(c, ".\r\n");
}

static void cmd_uidl(Conn *c, const char *arg) {
    unsigned long n;
    size_t i;
    if (arg && *arg) {
        long idx;
        if (parse_ulong(arg, &n) != 0) { pop3_err(c, "Invalid message number"); return; }
        idx = msg_index(c, n);
        if (idx < 0) { pop3_err(c, "No such message"); return; }
        conn_replyf(c, "+OK %zu %s\r\n", (size_t)n, c->mb.msgs[idx].base);
        return;
    }
    conn_replyf(c, "+OK %zu messages\r\n", c->mb.nmsgs - c->ndel);
    for (i = 0; i < c->mb.nmsgs; i++) {
        if (c->del[i]) continue;
        conn_replyf(c, "%zu %s\r\n", i + 1, c->mb.msgs[i].base);
    }
    conn_reply(c, ".\r\n");
}

static void cmd_retr(ImapdServer *srv, Conn *c, const char *arg, long top) {
    unsigned long n;
    long idx;
    if (!arg || !*arg) { pop3_err(c, "Missing message number"); return; }
    if (parse_ulong(arg, &n) != 0) { pop3_err(c, "Invalid message number"); return; }
    idx = msg_index(c, n);
    if (idx < 0) { pop3_err(c, "No such message"); return; }
    if (start_retr(c, (size_t)idx, top) != 0) {
        pop3_err(c, "Message unavailable");
        return;
    }
    /* downloading counts as read for cross-protocol \Seen consistency */
    {
        Imail *m = &c->mb.msgs[idx];
        if (!(m->flags & IMAIL_SEEN)) {
            m->flags |= IMAIL_SEEN;
            (void)imapd_mbox_store(&c->mb, m->uid, m->flags);
        }
    }
    imapd_pop3_pump(srv, c);
}

static void cmd_dele(Conn *c, const char *arg) {
    unsigned long n;
    if (!arg || !*arg) { pop3_err(c, "Missing message number"); return; }
    if (parse_ulong(arg, &n) != 0) { pop3_err(c, "Invalid message number"); return; }
    if (n < 1 || n > c->mb.nmsgs) { pop3_err(c, "No such message"); return; }
    if (c->del[n - 1]) { pop3_err(c, "Message already deleted"); return; }
    c->del[n - 1] = true;
    c->ndel++;
    conn_reply(c, "+OK message deleted\r\n");
}

static void cmd_top(ImapdServer *srv, Conn *c, const char *arg) {
    char *nums = NULL;
    const char *rest = arg;
    size_t restlen;
    unsigned long n, lines;
    long idx;
    /* "msg n": two unsigned args */
    if (!arg || !*arg) { pop3_err(c, "Missing arguments"); return; }
    while (*rest == ' ') rest++;
    for (restlen = 0; rest[restlen] && rest[restlen] != ' '; restlen++) ;
    nums = malloc(restlen + 1);
    if (!nums) { pop3_err(c, "Out of memory"); return; }
    memcpy(nums, rest, restlen);
    nums[restlen] = '\0';
    if (parse_ulong(nums, &n) != 0) {
        free(nums);
        pop3_err(c, "Invalid message number");
        return;
    }
    free(nums);
    idx = msg_index(c, n);
    if (idx < 0) { pop3_err(c, "No such message"); return; }
    {
        const char *l = rest + restlen;
        while (*l == ' ') l++;
        if (parse_ulong(l, &lines) != 0) { pop3_err(c, "Invalid line count"); return; }
    }
    if (start_retr(c, (size_t)idx, (long)lines) != 0) {
        pop3_err(c, "Message unavailable");
        return;
    }
    imapd_pop3_pump(srv, c);
}

static void pop3_quit(Conn *c) {
    if (c->mb_open) {
        size_t i;
        for (i = c->mb.nmsgs; i > 0; i--) {
            if (c->del && c->del[i - 1])
                (void)imapd_mbox_expunge(&c->mb, c->mb.msgs[i - 1].uid);
        }
        imapd_mbox_close(&c->mb);
        c->mb_open = false;
    }
    free(c->del);
    c->del = NULL;
    c->ndel = 0;
    conn_reply(c, "+OK bye\r\n");
    c->closed = true;
}

static void pop3_command(ImapdServer *srv, Conn *c, const char *line) {
    const char *p = line, *arg;
    size_t wlen;
    char word[8];
    while (*p == ' ') p++;
    arg = p;
    while (*arg && *arg != ' ') arg++;
    wlen = (size_t)(arg - p);
    if (wlen == 0 || wlen >= sizeof word) {
        pop3_err(c, "Command not recognized");
        return;
    }
    memcpy(word, p, wlen);
    word[wlen] = '\0';
    while (*arg == ' ') arg++;

    if (word_eq(word, "QUIT"))       { pop3_quit(c); return; }
    if (word_eq(word, "NOOP"))       { conn_reply(c, "+OK\r\n"); return; }
    if (word_eq(word, "RSET"))       { pop3_reset_deleted(c); conn_reply(c, "+OK\r\n"); return; }
    if (word_eq(word, "CAPA"))       { cmd_capa(srv, c); return; }
    if (word_eq(word, "STLS"))       { cmd_stls(srv, c); return; }
    if (word_eq(word, "USER"))       { cmd_user(srv, c, arg); return; }
    if (word_eq(word, "PASS"))       { cmd_pass(srv, c, arg); return; }
    if (c->pst != PO_TRANS) {
        pop3_err(c, "Authorization required");
        return;
    }
    if (word_eq(word, "STAT"))       { cmd_stat(c); return; }
    if (word_eq(word, "LIST"))       { cmd_list(c, *arg ? arg : NULL); return; }
    if (word_eq(word, "UIDL"))       { cmd_uidl(c, *arg ? arg : NULL); return; }
    if (word_eq(word, "RETR"))       { cmd_retr(srv, c, arg, -1); return; }
    if (word_eq(word, "DELE"))       { cmd_dele(c, arg); return; }
    if (word_eq(word, "TOP"))        { cmd_top(srv, c, arg); return; }
    pop3_err(c, "Command not recognized");
}

static void pop3_commands(ImapdServer *srv, Conn *c) {
    for (;;) {
        size_t i = 0, linelen, consumed;
        char *line;
        if (c->closed) return;
        if (c->pg) return;               /* a streaming RETR/TOP owns the conn */
        if (c->tls && !imapd_tls_established(c)) return;   /* handshaking */
        while (i < c->in_len && c->in[i] != '\n') i++;
        if (i == c->in_len) {
            if (c->in_len > IMAPD_MAX_LINE) {
                conn_reply(c, "-ERR line too long\r\n");
                c->closed = true;
            }
            return;
        }
        if (i > IMAPD_MAX_LINE) {
            conn_reply(c, "-ERR line too long\r\n");
            c->closed = true;
            return;
        }
        linelen = i;
        if (linelen > 0 && c->in[linelen - 1] == '\r') linelen--;
        line = malloc(linelen + 1);
        if (!line) {
            conn_reply(c, "-ERR out of memory\r\n");
            c->closed = true;
            return;
        }
        memcpy(line, c->in, linelen);
        line[linelen] = '\0';
        consumed = i + 1;
        memmove(c->in, c->in + consumed, c->in_len - consumed);
        c->in_len -= consumed;
        pop3_command(srv, c, line);
        free(line);
        if (c->closed || c->pg) return;
    }
}

/* ------------------------------------------------------------------ */
/* Entry points                                                        */
/* ------------------------------------------------------------------ */

void imapd_pop3_greeting(ImapdServer *srv, Conn *c) {
    char g[512];
    int gn = snprintf(g, sizeof g, "+OK %s POP3 server ready\r\n",
                      srv->cfg.hostname);
    if (gn < 0 || (size_t)gn >= sizeof g)
        conn_reply(c, "+OK POP3 server ready\r\n");
    else
        conn_reply(c, g);
}

/* Post-handshake reset (RFC 2595): STLS is only valid pre-auth, so the
   session restarts at PO_AUTH with any pending USER dropped and no mailbox
   held. */
void imapd_pop3_tls_reset(ImapdServer *srv, Conn *c) {
    (void)srv;
    imapd_pop3_free(c);
    free(c->pend_user);
    c->pend_user = NULL;
    free(c->del);
    c->del = NULL;
    c->ndel = 0;
    c->pst = PO_AUTH;
}

void imapd_pop3_readable(ImapdServer *srv, Conn *c, time_t now) {
    char tmp[IMAPD_RECV_CHUNK];

    if (c->tls) {   /* STARTTLS: poll loop drives the handshake; we drain */
        if (!imapd_tls_established(c)) return;
        for (;;) {
            int n = imapd_tls_recv(c, tmp, sizeof tmp);
            if (n < 0) { c->closed = true; return; }
            if (n == 0) return;
            c->last_act = now;
            if (buf_append(&c->in, &c->in_len, &c->in_cap, tmp, (size_t)n) != 0) {
                conn_reply(c, "-ERR too much data\r\n");
                c->closed = true;
                return;
            }
            pop3_commands(srv, c);
            if (c->closed || c->pg) return;   /* a streaming RETR/TOP owns it */
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
        if (n == 0) { c->closed = true; return; }
        c->last_act = now;
        if (buf_append(&c->in, &c->in_len, &c->in_cap, tmp, (size_t)n) != 0) {
            conn_reply(c, "-ERR too much data\r\n");
            c->closed = true;
            return;
        }
        pop3_commands(srv, c);
    }
}
