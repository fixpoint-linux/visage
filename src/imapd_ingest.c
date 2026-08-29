/* imapd_ingest.c — SMTP ingest listener for imapd.
 *
 * A minimal relay-RECEIVING SMTP server (the mirror image of smtp_in.c):
 * visage's smtp_out connects here (EHLO -> MAIL FROM -> RCPT TO* -> DATA ->
 * QUIT, one pipelining-free message per transaction) and imapd stores the
 * message into <root>/<rcpt-local-part>/Inbox.  No AUTH; STARTTLS (RFC 3207)
 * is offered when --cert/--key are configured (relay.tls = "starttls").
 *
 * The FSM, limits and reply codes mirror smtp_in.c exactly (220 greet ->
 * HELO/EHLO -> MAIL -> RCPT* -> DATA -> RSET/NOOP/QUIT), with one added
 * storage rule: a recipient is only accepted when its local-part is a valid
 * maildir user name (delivery creates the maildir on demand).  End-of-DATA
 * de-dot-stuffs, rejects control bytes, normalizes CRLF, prepends a
 * Return-Path header and delivers per recipient (250 / 451). */
#include "imapd.h"
#include "mail.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <poll.h>

/* ------------------------------------------------------------------ */
/* Constants                                                           */
/* ------------------------------------------------------------------ */

#define INGEST_MAX_LINE 1000

/* ------------------------------------------------------------------ */
/* Small helpers (duplicated from smtp_in.c per house style)           */
/* ------------------------------------------------------------------ */

/* ASCII case-insensitive compare over exactly n bytes (stops at NUL). */
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

static void conn_reset(Conn *c, int new_state) {
    size_t i;
    free(c->from);
    c->from = NULL;
    for (i = 0; i < c->nrcpts; i++) free(c->rcpts[i]);
    free(c->rcpts);
    c->rcpts = NULL;
    c->nrcpts = 0;
    c->rcpt_cap = 0;
    free(c->data);
    c->data = NULL;
    c->data_len = 0;
    c->data_cap = 0;
    c->st = new_state;
}

static int conn_add_rcpt(Conn *c, const char *rcpt) {
    char **na;
    char *dup;
    if (c->nrcpts == c->rcpt_cap) {
        size_t nc = c->rcpt_cap ? c->rcpt_cap * 2 : 4;
        na = realloc(c->rcpts, nc * sizeof *na);
        if (!na) return -1;
        c->rcpts = na;
        c->rcpt_cap = nc;
    }
    dup = strdup(rcpt);
    if (!dup) return -1;
    c->rcpts[c->nrcpts++] = dup;
    return 0;
}

/* Parse "KEY:<path>" out of a command tail (cf. smtp_in.c). */
static int parse_addr_arg(const char *rest, const char *key, char *path,
                          size_t pathsz, const char **params) {
    size_t klen = strlen(key);
    const char *p;
    const char *gt;
    size_t plen;

    if (ascii_strncasecmp(rest, key, klen) != 0) return -1;
    p = rest + klen;
    while (*p == ' ') p++;
    if (*p != ':') return -1;
    p++;
    while (*p == ' ') p++;
    if (*p != '<') return -1;
    p++;
    gt = strchr(p, '>');
    if (!gt) return -1;
    plen = (size_t)(gt - p);
    if (plen >= pathsz) return -1;
    memcpy(path, p, plen);
    path[plen] = '\0';
    *params = gt + 1;
    return 0;
}

/* True if every byte is printable ASCII (no control chars, no space). */
static bool path_clean(const char *p) {
    const unsigned char *q = (const unsigned char *)p;
    while (*q) {
        if (*q < 0x21 || *q > 0x7e) return false;
        if (*q == '"' || *q == '<' || *q == '>') return false;
        q++;
    }
    return true;
}

/* Scan raw (dot-stuffed) DATA bytes for the end-of-message terminator
   (verbatim from smtp_in.c data_scan). */
static int data_scan(const char *buf, size_t len, uint64_t max_total,
                     size_t *msg_end, size_t *term_len) {
    size_t i = 0;
    size_t line_start = 0;
    const uint64_t line_max = (uint64_t)INGEST_MAX_LINE + 1;

    while (i < len) {
        char ch = buf[i];
        if (ch == '\n') {
            size_t content_end = i;
            size_t clen;
            if (content_end > line_start && buf[content_end - 1] == '\r')
                content_end--;
            clen = content_end - line_start;
            if ((uint64_t)clen > line_max) return -1;
            if (clen == 1 && buf[line_start] == '.') {
                *msg_end = line_start;
                *term_len = i + 1 - line_start;
                return 1;
            }
            line_start = i + 1;
            i++;
            continue;
        }
        if (ch == '\r') {
            size_t content_end;
            size_t clen;
            if (i + 1 < len && buf[i + 1] == '\n') { i++; continue; }
            content_end = i;
            clen = content_end - line_start;
            if ((uint64_t)clen > line_max) return -1;
            if (clen == 1 && buf[line_start] == '.') {
                *msg_end = line_start;
                *term_len = i + 1 - line_start;
                return 1;
            }
            line_start = i + 1;
            i++;
            continue;
        }
        i++;
    }
    if ((uint64_t)len > max_total) return -1;
    if ((uint64_t)(len - line_start) > line_max) return -1;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Delivery (end of DATA)                                              */
/* ------------------------------------------------------------------ */

static void ingest_deliver(ImapdServer *srv, Conn *c) {
    char *msg = c->data;
    size_t msglen = c->data_len;
    char rp[INGEST_MAX_LINE + 4];
    size_t i;
    int failed = 0;

    if (mail_unstuff_dots(msg, &msglen) != 0) {
        conn_reply(c, "451 4.3.0 Temporary processing error\r\n");
        return;
    }
    /* Reject (never sanitize) NUL/control bytes, mirroring smtp_in.c. */
    if (mail_data_has_ctl(msg, msglen)) {
        conn_reply(c, "554 5.6.0 Message contains NUL or control bytes\r\n");
        c->closed = true;
        return;
    }
    if (msglen > (size_t)srv->cfg.max_msg) {
        conn_reply(c, "552 5.3.4 Message exceeds fixed limit\r\n");
        c->closed = true;
        return;
    }

    /* Normalize to CRLF (buffer must hold the worst case) and stamp the
       Return-Path so IMAP clients see the envelope sender. */
    {
        char *nb = realloc(msg, msglen * 2 + 2);
        if (!nb) {
            conn_reply(c, "451 4.3.0 Storage allocation failure\r\n");
            return;
        }
        msg = nb;
        msglen = (size_t)mail_normalize_crlf(msg, msglen);
    }
    snprintf(rp, sizeof rp, "<%s>",
             (c->from && c->from[0]) ? c->from : "");
    if (mail_header_set(&msg, &msglen, "Return-Path", rp) != 0) {
        conn_reply(c, "451 4.3.0 Temporary processing error\r\n");
        return;
    }

    /* Ownership moves to msg; conn_reset below must not free it. */
    c->data = NULL;
    c->data_len = 0;
    c->data_cap = 0;

    for (i = 0; i < c->nrcpts; i++) {
        const char *rcpt = c->rcpts[i];
        char *local = NULL, *domain = NULL;
        char dir[4096];
        if (mail_addr_parse(rcpt, &local, &domain) != 0) { failed = 1; continue; }
        if (imapd_mbox_dir(&srv->cfg, local, "INBOX", dir, sizeof dir) != 0 ||
            imapd_mbox_deliver(dir, msg, msglen, 0, NULL) != 0)
            failed = 1;
        mail_addr_free(local, domain);
    }
    free(msg);
    conn_reset(c, ST_HELO);

    /* A partial failure is at-least-once-safe (cf. smtp_in.c): the client
       resends and already-delivered maildirs get a duplicate. */
    conn_reply(c, failed ? "451 4.3.0 Temporary delivery failure\r\n"
                         : "250 2.0.0 OK: stored\r\n");
}

/* ------------------------------------------------------------------ */
/* Command handling                                                    */
/* ------------------------------------------------------------------ */

static void ingest_data(ImapdServer *srv, Conn *c, time_t now);

static void ingest_command(ImapdServer *srv, Conn *c, char *line) {
    char *p = line;
    char *sp;
    size_t vlen;
    char *rest;

    while (*p == ' ') p++;
    sp = strchr(p, ' ');
    vlen = sp ? (size_t)(sp - p) : strlen(p);
    rest = sp ? sp + 1 : p + strlen(p);
    while (*rest == ' ') rest++;

    if (vlen == 4 && ascii_strncasecmp(p, "EHLO", 4) == 0) {
        size_t cap;
        char *buf;
        if (!*rest) { conn_reply(c, "501 5.5.4 EHLO requires a domain\r\n"); return; }
        conn_reset(c, ST_HELO);
        cap = strlen(srv->cfg.hostname) + 96;
        buf = malloc(cap);
        if (!buf) { conn_reply(c, "250 OK\r\n"); return; }
        /* RFC 3207: STARTTLS is advertised only while in cleartext. */
        snprintf(buf, cap,
                 "250-%s\r\n250-8BITMIME\r\n250-SIZE %u%s\r\n250 OK\r\n",
                 srv->cfg.hostname, srv->cfg.max_msg,
                 (!c->tls && imapd_tls_available(srv))
                     ? "\r\n250-STARTTLS" : "");
        conn_reply(c, buf);
        free(buf);
    } else if (vlen == 4 && ascii_strncasecmp(p, "HELO", 4) == 0) {
        size_t cap;
        char *buf;
        if (!*rest) { conn_reply(c, "501 5.5.4 HELO requires a domain\r\n"); return; }
        conn_reset(c, ST_HELO);
        cap = strlen(srv->cfg.hostname) + 16;
        buf = malloc(cap);
        if (!buf) { conn_reply(c, "250 OK\r\n"); return; }
        snprintf(buf, cap, "250 %s\r\n", srv->cfg.hostname);
        conn_reply(c, buf);
        free(buf);
    } else if (vlen == 4 && ascii_strncasecmp(p, "MAIL", 4) == 0) {
        char path[INGEST_MAX_LINE];
        const char *params = NULL;
        if (c->st != ST_HELO) {
            conn_reply(c, "503 5.5.1 Error: send HELO/EHLO first\r\n");
            return;
        }
        if (parse_addr_arg(rest, "FROM", path, sizeof path, &params) != 0) {
            conn_reply(c, "501 5.5.4 Syntax: MAIL FROM:<address>\r\n");
            return;
        }
        if (!path_clean(path)) {
            conn_reply(c, "501 5.5.4 Invalid reverse-path\r\n");
            return;
        }
        free(c->from);
        c->from = strdup(path);
        if (!c->from) {
            conn_reply(c, "451 4.3.0 Storage allocation failure\r\n");
            return;
        }
        c->st = ST_MAIL;
        conn_reply(c, "250 2.1.0 OK\r\n");
    } else if (vlen == 4 && ascii_strncasecmp(p, "RCPT", 4) == 0) {
        char path[INGEST_MAX_LINE];
        const char *params = NULL;
        char *local = NULL, *domain = NULL;
        if (c->st != ST_MAIL) {
            conn_reply(c, "503 5.5.1 Error: need MAIL first\r\n");
            return;
        }
        if (c->nrcpts >= IMAPD_MAX_RCPTS) {
            conn_reply(c, "452 4.5.3 Too many recipients\r\n");
            return;
        }
        if (parse_addr_arg(rest, "TO", path, sizeof path, &params) != 0) {
            conn_reply(c, "501 5.5.4 Syntax: RCPT TO:<address>\r\n");
            return;
        }
        if (!path_clean(path) || path[0] == '\0') {
            conn_reply(c, "501 5.5.4 Invalid recipient address\r\n");
            return;
        }
        if (mail_addr_parse(path, &local, &domain) != 0) {
            conn_reply(c, "501 5.5.4 Invalid recipient address\r\n");
            return;
        }
        mail_addr_free(local, domain);
        /* The RCPT local-part names the maildir user directory. */
        {
            char *l2 = NULL, *d2 = NULL;
            int ok;
            (void)mail_addr_parse(path, &l2, &d2);
            ok = l2 && imapd_user_ok(l2);
            mail_addr_free(l2, d2);
            if (!ok) {
                conn_reply(c, "550 5.1.1 User unknown\r\n");
                return;
            }
        }
        if (conn_add_rcpt(c, path) != 0) {
            conn_reply(c, "451 4.3.0 Storage allocation failure\r\n");
            return;
        }
        conn_reply(c, "250 2.1.5 OK\r\n");
    } else if (vlen == 4 && ascii_strncasecmp(p, "DATA", 4) == 0) {
        if (c->st != ST_MAIL) {
            conn_reply(c, "503 5.5.1 Error: need RCPT first\r\n");
            return;
        }
        if (c->nrcpts == 0) {
            conn_reply(c, "503 5.5.1 Error: no valid recipients\r\n");
            return;
        }
        conn_reply(c, "354 End data with <CR><LF>.<CR><LF>\r\n");
        free(c->data);
        c->data = NULL;
        c->data_len = 0;
        c->data_cap = 0;
        c->st = ST_DATA;
    } else if (vlen == 4 && ascii_strncasecmp(p, "RSET", 4) == 0) {
        conn_reset(c, (c->st == ST_INIT) ? ST_INIT : ST_HELO);
        conn_reply(c, "250 2.0.0 OK\r\n");
    } else if (vlen == 4 && ascii_strncasecmp(p, "NOOP", 4) == 0) {
        conn_reply(c, "250 2.0.0 OK\r\n");
    } else if (vlen == 4 && ascii_strncasecmp(p, "QUIT", 4) == 0) {
        conn_reply(c, "221 2.0.0 Bye\r\n");
        c->closed = true;
    } else if (vlen == 4 && ascii_strncasecmp(p, "VRFY", 4) == 0) {
        conn_reply(c, "252 2.5.2 Cannot VRFY user\r\n");
    } else if (vlen == 8 && ascii_strncasecmp(p, "STARTTLS", 8) == 0) {
        /* RFC 3207: only after EHLO, never twice, no parameters, and no
           pipelined bytes (c->in is plaintext but the next reader is TLS). */
        if (c->tls || c->st != ST_HELO) {
            conn_reply(c, "503 5.5.1 Error: TLS already active or no EHLO\r\n");
        } else if (*rest) {
            conn_reply(c, "501 5.5.4 Syntax: STARTTLS\r\n");
        } else if (c->in_len != 0) {
            conn_reply(c, "500 5.5.2 Pipelined data before STARTTLS\r\n");
        } else if (!imapd_tls_available(srv)) {
            conn_reply(c, "502 5.5.1 Command not implemented\r\n");
        } else if (imapd_tls_start(srv, c) != 0) {
            conn_reply(c, "451 4.3.0 Storage allocation failure\r\n");
        } else {
            /* the 220 drains in the clear (PENDING), then the poll loop
               runs the handshake and resets the session to ST_INIT */
            conn_reply(c, "220 2.0.0 Ready to start TLS\r\n");
        }
    } else if (vlen == 4 && ascii_strncasecmp(p, "AUTH", 4) == 0) {
        conn_reply(c, "502 5.5.1 Command not implemented\r\n");
    } else {
        conn_reply(c, "500 5.5.2 Command not recognized\r\n");
    }
}

static void ingest_commands(ImapdServer *srv, Conn *c, time_t now) {
    (void)now;
    for (;;) {
        size_t i = 0;
        size_t linelen, consumed;
        if (c->closed) return;
        if (c->tls && !imapd_tls_established(c)) return;   /* handshaking */
        while (i < c->in_len && c->in[i] != '\n') i++;
        if (i == c->in_len) {
            if (c->in_len > INGEST_MAX_LINE) {
                conn_reply(c, "500 5.5.2 Line too long\r\n");
                c->closed = true;
            }
            return;
        }
        if (i > INGEST_MAX_LINE) {
            conn_reply(c, "500 5.5.2 Line too long\r\n");
            c->closed = true;
            return;
        }
        linelen = i;
        if (linelen > 0 && c->in[linelen - 1] == '\r') linelen--;
        /* Copy the line out and consume it BEFORE dispatch, so a handler
           sees c->in_len == 0 unless the client pipelined more bytes after
           it (STARTTLS relies on this; mirrors imap_process). */
        {
            char *line = malloc(linelen + 1);
            if (!line) {
                conn_reply(c, "451 4.3.0 Storage allocation failure\r\n");
                c->closed = true;
                return;
            }
            memcpy(line, c->in, linelen);
            line[linelen] = '\0';
            consumed = i + 1;
            memmove(c->in, c->in + consumed, c->in_len - consumed);
            c->in_len -= consumed;
            ingest_command(srv, c, line);
            free(line);
        }

        /* Once DATA starts, every remaining buffered byte is MESSAGE DATA. */
        if (c->st == ST_DATA && !c->closed) {
            if (c->in_len > 0) {
                if ((uint64_t)c->data_len + (uint64_t)c->in_len >
                        (uint64_t)srv->cfg.max_msg * 2 + 16) {
                    conn_reply(c, "552 5.3.4 Message exceeds fixed limit\r\n");
                    c->closed = true;
                    return;
                }
                if (buf_append(&c->data, &c->data_len, &c->data_cap,
                               c->in, c->in_len) != 0) {
                    conn_reply(c, "451 4.3.0 Storage allocation failure\r\n");
                    c->closed = true;
                    return;
                }
                c->in_len = 0;
            }
            return;
        }
    }
}

/* ------------------------------------------------------------------ */
/* DATA input                                                          */
/* ------------------------------------------------------------------ */

static void ingest_data(ImapdServer *srv, Conn *c, time_t now) {
    size_t msg_end = 0, term_len = 0;
    uint64_t raw_cap = (uint64_t)srv->cfg.max_msg * 2 + 16;
    int r = data_scan(c->data, c->data_len, raw_cap, &msg_end, &term_len);
    if (r < 0) {
        conn_reply(c, "552 5.3.4 Message exceeds fixed limits\r\n");
        c->closed = true;
        return;
    }
    if (r == 0) return;   /* need more data */

    {
        size_t leftover_start = msg_end + term_len;
        size_t leftover = c->data_len - leftover_start;
        if (leftover > 0) {
            if (buf_append(&c->in, &c->in_len, &c->in_cap,
                           c->data + leftover_start, leftover) != 0) {
                c->closed = true;
                free(c->data);
                c->data = NULL;
                c->data_len = c->data_cap = 0;
                return;
            }
        }
        c->data_len = msg_end;
    }

    ingest_deliver(srv, c);

    if (!c->closed && c->in_len > 0)
        ingest_commands(srv, c, now);
}

/* ------------------------------------------------------------------ */
/* Entry point                                                         */
/* ------------------------------------------------------------------ */

void imapd_ingest_greeting(ImapdServer *srv, Conn *c) {
    char g[512];
    int gn = snprintf(g, sizeof g, "220 %s ESMTP imapd\r\n",
                      srv->cfg.hostname);
    if (gn < 0 || (size_t)gn >= sizeof g)
        conn_reply(c, "220 localhost ESMTP imapd\r\n");
    else
        conn_reply(c, g);
}

/* Post-handshake reset (RFC 3207 4): the client must EHLO again, so the
   session restarts at ST_INIT with envelope state dropped. */
void imapd_ingest_tls_reset(ImapdServer *srv, Conn *c) {
    (void)srv;
    conn_reset(c, ST_INIT);
}

void imapd_ingest_readable(ImapdServer *srv, Conn *c, time_t now) {
    char tmp[IMAPD_RECV_CHUNK];

    if (c->tls) {   /* STARTTLS: poll loop drives the handshake; we drain */
        if (!imapd_tls_established(c)) return;
        for (;;) {
            /* Drain LOOP, not once: mbedtls buffers decrypted plaintext
               internally, so a single read per POLLIN can stall the
               session when several records arrived in one segment. */
            int n = imapd_tls_recv(c, tmp, sizeof tmp);
            if (n < 0) { c->closed = true; return; }
            if (n == 0) return;
            c->last_act = now;
            if (c->st == ST_DATA) {
                if ((uint64_t)c->data_len + (uint64_t)n >
                        (uint64_t)srv->cfg.max_msg * 2 + 16) {
                    conn_reply(c, "552 5.3.4 Message exceeds fixed limit\r\n");
                    c->closed = true;
                    return;
                }
                if (buf_append(&c->data, &c->data_len, &c->data_cap,
                               tmp, (size_t)n) != 0) {
                    conn_reply(c, "451 4.3.0 Storage allocation failure\r\n");
                    c->closed = true;
                    return;
                }
                ingest_data(srv, c, now);   /* may return to command mode */
            } else {
                if (buf_append(&c->in, &c->in_len, &c->in_cap, tmp, (size_t)n)
                    != 0) {
                    conn_reply(c, "500 5.5.2 Line too long\r\n");
                    c->closed = true;
                    return;
                }
                ingest_commands(srv, c, now);
            }
            if (c->closed) return;
            if (c->st == ST_DATA) return;   /* bulk DATA: next POLLIN */
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

        if (c->st == ST_DATA) {
            if ((uint64_t)c->data_len + (uint64_t)n >
                    (uint64_t)srv->cfg.max_msg * 2 + 16) {
                conn_reply(c, "552 5.3.4 Message exceeds fixed limit\r\n");
                c->closed = true;
                return;
            }
            if (buf_append(&c->data, &c->data_len, &c->data_cap,
                           tmp, (size_t)n) != 0) {
                conn_reply(c, "451 4.3.0 Storage allocation failure\r\n");
                c->closed = true;
                return;
            }
            ingest_data(srv, c, now);
        } else {
            if (buf_append(&c->in, &c->in_len, &c->in_cap, tmp, (size_t)n)
                != 0) {
                conn_reply(c, "500 5.5.2 Line too long\r\n");
                c->closed = true;
                return;
            }
            ingest_commands(srv, c, now);
        }
    }
}
