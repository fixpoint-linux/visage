/* outbox_submit.c — SMTP submission session state machine + direct delivery.
 *
 * Implements the per-connection SMTP dialogue for outbox (EHLO/HELO, STARTTLS,
 * AUTH PLAIN/LOGIN, MAIL/RCPT/DATA), the strict-DMARC envelope policy
 * (envelope MAIL FROM domain ∈ allowed set; header From: domain == envelope
 * domain), DKIM signing (selector "visage", per-From-domain key), and the
 * RFC 5321 direct-MX delivery loop.
 *
 * The poll loop (outbox_main.c) owns fds and TLS handshake driving; this file
 * owns command parsing, the DATA payload, and DKIM-sign + spool at DATA
 * completion.  The actual MX delivery is handed off to the worker queue in
 * outbox_deliver.c so the poll loop never blocks on outbound SMTP/DNS.
 */
#include "outbox.h"
#include "visage.h"
#include "mail.h"
#include "dkim.h"

#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <sys/stat.h>

/* ------------------------------------------------------------------ */
/* Small helpers (duplicated from smtp_in.c per house style)           */
/* ------------------------------------------------------------------ */

int outbox_buf_append(char **buf, size_t *len, size_t *cap,
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

/* ASCII case-insensitive compare over exactly n bytes. */
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

/* ASCII case-insensitive full-string equality. */
static bool ascii_ieq_str(const char *a, const char *b) {
    while (*a && *b) {
        char ca = *a++, cb = *b++;
        if (ca >= 'A' && ca <= 'Z') ca = (char)(ca + 32);
        if (cb >= 'A' && cb <= 'Z') cb = (char)(cb + 32);
        if (ca != cb) return false;
    }
    return *a == *b;
}

static void lowercase_into(const char *s, char *out, size_t outsz) {
    size_t i;
    for (i = 0; s[i] && i + 1 < outsz; i++) {
        char ch = s[i];
        out[i] = (ch >= 'A' && ch <= 'Z') ? (char)(ch + 32) : ch;
    }
    out[i] = '\0';
}

/* ------------------------------------------------------------------ */
/* Reply output                                                       */
/* ------------------------------------------------------------------ */

void outbox_conn_flush(OutboxConn *c) {
    if (c->tls && !smtp_in_tls_pending(c->tls)) {
        while (c->out_off < c->out_len) {
            int n = smtp_in_tls_send(c->tls, c->out + c->out_off,
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

void outbox_conn_reply(OutboxConn *c, const char *text) {
    if (c->out_len > OUTBOX_MAX_OUT) {
        c->closed = true;
        return;
    }
    if (outbox_buf_append(&c->out, &c->out_len, &c->out_cap, text,
                          strlen(text)) != 0) {
        c->closed = true;
        return;
    }
    outbox_conn_flush(c);
}

/* ------------------------------------------------------------------ */
/* Session lifecycle                                                  */
/* ------------------------------------------------------------------ */

void outbox_conn_reset_txn(OutboxConn *c, int state) {
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
    c->auth_pending = OB_AUTH_NONE;
    free(c->pending_user);
    c->pending_user = NULL;
    c->state = state;
}

void outbox_conn_destroy(OutboxConn *c) {
    size_t i;
    smtp_in_tls_conn_free(c->tls);   /* close_notify while the fd is still open */
    if (c->fd >= 0) close(c->fd);
    free(c->auth_user);
    free(c->pending_user);
    free(c->from);
    for (i = 0; i < c->nrcpts; i++) free(c->rcpts[i]);
    free(c->rcpts);
    free(c->in);
    free(c->data);
    free(c->out);
    free(c);
}

int outbox_conn_add_rcpt(OutboxConn *c, const char *rcpt) {
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

/* ------------------------------------------------------------------ */
/* Pure helpers (outbox.h)                                             */
/* ------------------------------------------------------------------ */

bool outbox_domain_allowed(const OutboxConfig *cfg, const char *domain) {
    size_t i;
    if (!cfg || !domain) return false;
    for (i = 0; i < cfg->ndomains; i++)
        if (cfg->domains[i] && ascii_ieq_str(cfg->domains[i], domain))
            return true;
    return false;
}

bool outbox_domain_internal(const OutboxConfig *cfg, const char *domain) {
    size_t i;
    const char *const *list;
    size_t n;
    if (!cfg || !domain) return false;
    /* Default: the served domains ARE the internal set (the operator may
       override with a dedicated --internal-domains list). */
    if (cfg->ninternal_domains > 0) {
        list = (const char *const *)cfg->internal_domains;
        n = cfg->ninternal_domains;
    } else {
        list = (const char *const *)cfg->domains;
        n = cfg->ndomains;
    }
    for (i = 0; i < n; i++)
        if (list[i] && ascii_ieq_str(list[i], domain))
            return true;
    return false;
}

const char *outbox_dkim_key(const OutboxConfig *cfg, const char *domain) {
    size_t i;
    if (!cfg || !domain) return NULL;
    for (i = 0; i < cfg->ndkim; i++)
        if (cfg->dkim[i].domain && ascii_ieq_str(cfg->dkim[i].domain, domain))
            return cfg->dkim[i].key;
    return NULL;
}

/* Parse an addr-spec ("local@domain" or "<local@domain>", whitespace
 * tolerated) and return the lowercased domain.  Returns 0, or -1. */
int outbox_addr_domain(const char *addr, char *out, size_t outsz) {
    char *local = NULL, *domain = NULL;
    if (!addr || mail_addr_parse(addr, &local, &domain) != 0)
        return -1;
    if (!domain || !domain[0]) {
        mail_addr_free(local, domain);
        return -1;
    }
    lowercase_into(domain, out, outsz);
    mail_addr_free(local, domain);
    return 0;
}

/* Extract the addr-spec from a From header VALUE ("Name <addr>" or "addr"). */
static int from_addr_extract(const char *hdr, char *addr, size_t addr_sz) {
    const char *lt = strchr(hdr, '<');
    if (lt) {
        const char *gt = strchr(lt, '>');
        size_t n;
        if (!gt) return -1;
        n = (size_t)(gt - lt - 1);
        if (n == 0 || n >= addr_sz) return -1;
        memcpy(addr, lt + 1, n);
        addr[n] = '\0';
        return 0;
    }
    while (*hdr == ' ' || *hdr == '\t') hdr++;
    {
        size_t n = strlen(hdr);
        while (n > 0 && (hdr[n - 1] == ' ' || hdr[n - 1] == '\t')) n--;
        if (n == 0 || n >= addr_sz) return -1;
        memcpy(addr, hdr, n);
        addr[n] = '\0';
    }
    return 0;
}

int outbox_from_header_domain(const char *msg, size_t len, char *out,
                              size_t outsz) {
    char hdr[4096];
    char addr[SMTP_MAX_LINE];
    if (mail_header_get(msg, len, "From", hdr, sizeof hdr) != 0)
        return -1;
    if (from_addr_extract(hdr, addr, sizeof addr) != 0)
        return -1;
    return outbox_addr_domain(addr, out, outsz);
}

/* ------------------------------------------------------------------ */
/* Delivery                                                            */
/* ------------------------------------------------------------------ */

/* Spooled mail must not be readable by other local users: create 0600. */
static int write_file(const char *path, const char *data, size_t len) {
    FILE *f;
    size_t w;
    int rc, fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return -1;
    f = fdopen(fd, "wb");
    if (!f) { close(fd); return -1; }
    w = fwrite(data, 1, len, f);
    rc = fclose(f);
    if (w != len || rc != 0) return -1;
    return 0;
}

static int mkdir_p(const char *path) {
    char *tmp;
    size_t plen, i;
    int rc = 0;
    if (!path || !path[0]) return -1;
    tmp = strdup(path);
    if (!tmp) return -1;
    plen = strlen(tmp);
    for (i = 1; i < plen; i++) {
        if (tmp[i] == '/') {
            tmp[i] = '\0';
            if (mkdir(tmp, 0700) != 0 && errno != EEXIST) { rc = -1; goto out; }
            tmp[i] = '/';
        }
    }
    if (mkdir(tmp, 0700) != 0 && errno != EEXIST) rc = -1;
out:
    free(tmp);
    return rc;
}

/* Best-effort spool of an accepted message (envelope + body per file) so an
 * accepted message is never lost to a delivery-time crash.  Non-fatal: a
 * spool failure is logged and delivery proceeds.  NOTE: v1 does NOT re-drive
 * these spool files after a crash — a durable queue + daemon re-drive loop is
 * the documented follow-up (see the note in outbox_main.c). */
static void spool_message(const OutboxServer *srv, const char *from,
                          OutboxConn *c, const char *msg, size_t msglen) {
    char path[4096];
    char env[4096];
    size_t w = 0, i, pathlen;
    static uint64_t seq;
    int n;

    if (!srv->cfg.spool || !srv->cfg.spool[0]) return;
    if (mkdir_p(srv->cfg.spool) != 0) {
        fprintf(stderr, "outbox: spool: cannot create %s\n", srv->cfg.spool);
        return;
    }
    n = snprintf(path, sizeof path, "%s/%ld-%llu.eml", srv->cfg.spool,
                 (long)time(NULL), (unsigned long long)seq);
    if (n < 0 || (size_t)n >= sizeof path) return;
    seq++;
    pathlen = (size_t)n;
    if (write_file(path, msg, msglen) != 0) {
        fprintf(stderr, "outbox: spool: write %s failed\n", path);
        return;
    }

    /* Envelope sidecar (<msg>.env): one "MAIL FROM:" / "RCPT TO:" line each. */
    n = snprintf(env, sizeof env, "MAIL FROM:<%s>\n", from ? from : "");
    if (n < 0 || (size_t)n >= sizeof env) return;
    w = (size_t)n;
    for (i = 0; i < c->nrcpts; i++) {
        int r = snprintf(env + w, sizeof env - w, "RCPT TO:<%s>\n", c->rcpts[i]);
        if (r < 0 || (size_t)r >= sizeof env - w) return;
        w += (size_t)r;
    }
    if (pathlen >= sizeof path) return;
    memcpy(path + pathlen - 4, ".env", 4);   /* ".eml" -> ".env" */
    path[pathlen] = '\0';
    (void)write_file(path, env, w);
}

/* ------------------------------------------------------------------ */
/* DATA completion                                                     */
/* ------------------------------------------------------------------ */

static void deliver_message(OutboxServer *srv, OutboxConn *c) {
    char *msg = c->data;
    size_t msglen = c->data_len;
    char envdom[256], fromdom[256];
    const char *key;
    char *signed_msg = NULL;
    size_t signed_len = 0;
    const char *out_msg;
    size_t out_len;

    if (mail_unstuff_dots(msg, &msglen) != 0) {
        outbox_conn_reply(c, "451 4.3.0 Temporary processing error\r\n");
        return;
    }
    /* Reject (never sanitize) NUL/control bytes; 8-bit bytes stay allowed. */
    if (mail_data_has_ctl(msg, msglen)) {
        outbox_conn_reply(c, "554 5.6.0 Message contains NUL or control bytes\r\n");
        c->closed = true;
        return;
    }
    if (msglen > (size_t)srv->max_msg) {
        outbox_conn_reply(c, "552 5.3.4 Message exceeds fixed limit\r\n");
        c->closed = true;
        return;
    }

    /* Strict DMARC aspf=s: header From: domain MUST equal the envelope MAIL
       FROM domain.  (The envelope domain was validated at MAIL time.) */
    if (outbox_addr_domain(c->from, envdom, sizeof envdom) != 0 ||
        outbox_from_header_domain(msg, msglen, fromdom, sizeof fromdom) != 0 ||
        !ascii_ieq_str(envdom, fromdom)) {
        outbox_conn_reply(c, "554 5.7.1 Sender address rejected "
                             "(From domain must equal envelope MAIL FROM)\r\n");
        return;
    }

    /* DKIM-sign as the From domain using that domain's key (selector
       "visage").  On failure (no key / sign error) deliver UNSIGNED — never
       fabricate a signature, never lose the message. */
    key = outbox_dkim_key(&srv->cfg, fromdom);
    if (key && dkim_sign(msg, msglen, fromdom, "visage", key,
                         &signed_msg, &signed_len) == 0) {
        out_msg = signed_msg;
        out_len = signed_len;
    } else {
        if (key)
            fprintf(stderr, "outbox: dkim: sign failed for %s; delivering "
                            "unsigned\n", fromdom);
        else
            fprintf(stderr, "outbox: dkim: no key for %s; delivering unsigned\n",
                    fromdom);
        out_msg = msg;
        out_len = msglen;
    }

    spool_message(srv, c->from, c, out_msg, out_len);

    /* Hand the signed message to the delivery worker.  The poll loop must
       NEVER block on outbound SMTP/DNS: a reply whose first leg targets the
       local ingress (visage) needs visage to connect BACK here (the reply_relay
       hop) to complete, so an inline delivery would wedge the daemon.  The
       spool audit copy is already on disk above, before we ack, so an accepted
       message is not lost to a crash. */
    {
        int qrc = outbox_delivery_enqueue(&srv->delivery, c->from, c->rcpts,
                                          c->nrcpts, out_msg, out_len);
        if (qrc == -2) {   /* delivery queue at its jobs/bytes cap */
            free(signed_msg);
            outbox_conn_reply(c,
                              "452 4.3.1 Delivery queue full, try later\r\n");
            return;
        }
        if (qrc != 0) {
            free(signed_msg);
            outbox_conn_reply(c, "451 4.3.0 Temporary delivery failure\r\n");
            return;
        }
    }
    free(signed_msg);

    outbox_conn_reply(c, "250 2.0.0 OK: queued\r\n");
}

/* ------------------------------------------------------------------ */
/* Command argument parsing                                            */
/* ------------------------------------------------------------------ */

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

/* ------------------------------------------------------------------ */
/* AUTH                                                                */
/* ------------------------------------------------------------------ */

static void finish_auth(OutboxServer *srv, OutboxConn *c, const char *user,
                        const char *pass, time_t now) {
    if (outbox_auth_blocked(srv, c->peer_ip, c->peer_ip_len, now)) {
        outbox_conn_reply(c, "454 4.7.0 Too many failed attempts\r\n");
        return;
    }
    if (outbox_auth_check(&srv->auth, user, pass)) {
        outbox_auth_clear(srv, c->peer_ip, c->peer_ip_len);
        c->authenticated = true;
        free(c->auth_user);
        c->auth_user = strdup(user);
        outbox_conn_reply(c, "235 2.7.0 Authentication successful\r\n");
    } else {
        outbox_auth_fail(srv, c->peer_ip, c->peer_ip_len, now);
        outbox_conn_reply(c, "535 5.7.8 Authentication credentials invalid\r\n");
    }
}

/* AUTH PLAIN: decode "\0authcid\0passwd" (authzid ignored) and check. */
static void auth_plain_check(OutboxServer *srv, OutboxConn *c, const char *b64,
                             time_t now) {
    unsigned char dec[512];
    size_t dlen, i, us, ulen, plen;
    char user[128], pass[512];

    if (outbox_b64_decode(b64, strlen(b64), dec, sizeof dec, &dlen) != 0) {
        outbox_auth_fail(srv, c->peer_ip, c->peer_ip_len, now);
        outbox_conn_reply(c, "501 5.5.4 Invalid base64\r\n");
        return;
    }
    /* Skip authzid up to the first NUL. */
    for (i = 0; i < dlen && dec[i] != 0; i++) {}
    if (i >= dlen) {
        outbox_auth_fail(srv, c->peer_ip, c->peer_ip_len, now);
        outbox_conn_reply(c, "501 5.5.4 Malformed AUTH PLAIN response\r\n");
        return;
    }
    i++;               /* past first NUL */
    us = i;
    while (i < dlen && dec[i] != 0) i++;
    if (i >= dlen) {
        outbox_auth_fail(srv, c->peer_ip, c->peer_ip_len, now);
        outbox_conn_reply(c, "501 5.5.4 Malformed AUTH PLAIN response\r\n");
        return;
    }
    ulen = i - us;
    i++;               /* past second NUL */
    plen = dlen - i;
    if (ulen == 0 || ulen >= sizeof user || plen >= sizeof pass) {
        outbox_auth_fail(srv, c->peer_ip, c->peer_ip_len, now);
        outbox_conn_reply(c, "501 5.5.4 Malformed AUTH PLAIN response\r\n");
        return;
    }
    memcpy(user, dec + us, ulen);
    user[ulen] = '\0';
    memcpy(pass, dec + i, plen);
    pass[plen] = '\0';
    finish_auth(srv, c, user, pass, now);
}

static void handle_auth_cont(OutboxServer *srv, OutboxConn *c, const char *line,
                             time_t now) {
    if (line[0] == '*' && line[1] == '\0') {
        c->auth_pending = OB_AUTH_NONE;
        free(c->pending_user);
        c->pending_user = NULL;
        outbox_conn_reply(c, "501 5.7.0 Authentication aborted\r\n");
        return;
    }
    switch (c->auth_pending) {
    case OB_AUTH_PLAIN:
        c->auth_pending = OB_AUTH_NONE;
        auth_plain_check(srv, c, line, now);
        break;
    case OB_AUTH_LOGIN_USER: {
        unsigned char u[256];
        size_t ulen;
        c->auth_pending = OB_AUTH_NONE;
        if (outbox_b64_decode(line, strlen(line), u, sizeof u, &ulen) != 0 ||
            ulen == 0 || ulen >= sizeof u) {
            free(c->pending_user);
            c->pending_user = NULL;
            outbox_auth_fail(srv, c->peer_ip, c->peer_ip_len, now);
            outbox_conn_reply(c, "501 5.5.4 Invalid base64\r\n");
            return;
        }
        u[ulen] = '\0';
        c->pending_user = strdup((char *)u);
        if (!c->pending_user) {
            outbox_conn_reply(c, "451 4.3.0 Storage allocation failure\r\n");
            return;
        }
        c->auth_pending = OB_AUTH_LOGIN_PASS;
        outbox_conn_reply(c, "334 UGFzc3dvcmQ6\r\n");   /* "Password:" */
        break;
    }
    case OB_AUTH_LOGIN_PASS: {
        unsigned char p[512];
        size_t plen;
        char *user = c->pending_user;
        c->auth_pending = OB_AUTH_NONE;
        c->pending_user = NULL;
        /* plen >= sizeof p: outbox_b64_decode can emit exactly sizeof p bytes
           and p[plen] = '\0' below would write one past the buffer. */
        if (!user ||
            outbox_b64_decode(line, strlen(line), p, sizeof p, &plen) != 0 ||
            plen == 0 || plen >= sizeof p) {
            free(user);
            outbox_auth_fail(srv, c->peer_ip, c->peer_ip_len, now);
            outbox_conn_reply(c, "501 5.5.4 Invalid base64\r\n");
            return;
        }
        p[plen] = '\0';
        finish_auth(srv, c, user, (char *)p, now);
        free(user);
        break;
    }
    default:
        c->auth_pending = OB_AUTH_NONE;
        outbox_conn_reply(c, "503 5.5.1 Bad sequence of commands\r\n");
        break;
    }
}

static void do_auth(OutboxServer *srv, OutboxConn *c, const char *rest,
                    time_t now) {
    const char *mech = rest;
    const char *sp;
    size_t mlen;
    const char *init = NULL;

    while (*mech == ' ') mech++;
    sp = strchr(mech, ' ');
    mlen = sp ? (size_t)(sp - mech) : strlen(mech);
    if (sp) {
        init = sp + 1;
        while (*init == ' ') init++;
        if (!*init) init = NULL;
    }

    if (mlen == 5 && ascii_strncasecmp(mech, "PLAIN", 5) == 0) {
        if (init) {
            auth_plain_check(srv, c, init, now);
        } else {
            c->auth_pending = OB_AUTH_PLAIN;
            outbox_conn_reply(c, "334 \r\n");
        }
    } else if (mlen == 5 && ascii_strncasecmp(mech, "LOGIN", 5) == 0) {
        if (init) {
            /* initial response = base64 username */
            unsigned char u[256];
            size_t ulen;
            c->auth_pending = OB_AUTH_NONE;
            if (outbox_b64_decode(init, strlen(init), u, sizeof u, &ulen) != 0 ||
                ulen == 0 || ulen >= sizeof u) {
                outbox_auth_fail(srv, c->peer_ip, c->peer_ip_len, now);
                outbox_conn_reply(c, "501 5.5.4 Invalid base64\r\n");
                return;
            }
            u[ulen] = '\0';
            free(c->pending_user);
            c->pending_user = strdup((char *)u);
            if (!c->pending_user) {
                outbox_conn_reply(c, "451 4.3.0 Storage allocation failure\r\n");
                return;
            }
            c->auth_pending = OB_AUTH_LOGIN_PASS;
            outbox_conn_reply(c, "334 UGFzc3dvcmQ6\r\n");
        } else {
            c->auth_pending = OB_AUTH_LOGIN_USER;
            outbox_conn_reply(c, "334 VXNlcm5hbWU6\r\n");   /* "Username:" */
        }
    } else {
        outbox_conn_reply(c, "504 5.5.4 Unrecognized authentication type\r\n");
    }
}

/* ------------------------------------------------------------------ */
/* Command handling                                                    */
/* ------------------------------------------------------------------ */

static bool channel_secure(const OutboxConn *c) {
    return smtp_in_tls_established(c->tls);
}

static bool require_secure(OutboxConn *c) {
    if (channel_secure(c)) return true;
    outbox_conn_reply(c, "530 5.7.0 Must issue a STARTTLS command first\r\n");
    return false;
}

static bool require_auth(OutboxConn *c) {
    if (!require_secure(c)) return false;
    if (c->authenticated) return true;
    outbox_conn_reply(c, "530 5.7.0 Authentication required\r\n");
    return false;
}

static void do_helo(OutboxServer *srv, OutboxConn *c, bool ehlo) {
    const char *hn = (srv->cfg.hostname && srv->cfg.hostname[0])
                         ? srv->cfg.hostname : "localhost";
    outbox_conn_reset_txn(c, OB_ST_HELO);
    if (ehlo) {
        bool secure = channel_secure(c);
        char buf[512];
        int n = snprintf(buf, sizeof buf,
                         "250-%s\r\n250-8BITMIME\r\n250-SIZE %u\r\n%s%s250 OK\r\n",
                         hn, srv->max_msg,
                         secure ? "250-AUTH PLAIN LOGIN\r\n" : "",
                         (!secure && smtp_in_tls_available()) ? "250-STARTTLS\r\n" : "");
        if (n < 0 || (size_t)n >= sizeof buf)
            outbox_conn_reply(c, "250 OK\r\n");
        else
            outbox_conn_reply(c, buf);
    } else {
        char buf[512];
        int n = snprintf(buf, sizeof buf, "250 %s\r\n", hn);
        if (n < 0 || (size_t)n >= sizeof buf)
            outbox_conn_reply(c, "250 localhost\r\n");
        else
            outbox_conn_reply(c, buf);
    }
}

static void do_mail(OutboxServer *srv, OutboxConn *c, const char *rest) {
    char path[SMTP_MAX_LINE];
    const char *params = NULL;
    char domain[256];

    if (c->state != OB_ST_HELO) {
        outbox_conn_reply(c, "503 5.5.1 Error: send EHLO first\r\n");
        return;
    }
    if (!require_auth(c)) return;
    if (parse_addr_arg(rest, "FROM", path, sizeof path, &params) != 0) {
        outbox_conn_reply(c, "501 5.5.4 Syntax: MAIL FROM:<address>\r\n");
        return;
    }
    (void)params;
    if (outbox_addr_domain(path, domain, sizeof domain) != 0 ||
        !outbox_domain_allowed(&srv->cfg, domain)) {
        outbox_conn_reply(c, "554 5.7.1 Sender address rejected "
                             "(domain not permitted)\r\n");
        return;
    }
    free(c->from);
    c->from = strdup(path);
    if (!c->from) {
        outbox_conn_reply(c, "451 4.3.0 Storage allocation failure\r\n");
        return;
    }
    c->state = OB_ST_MAIL;
    outbox_conn_reply(c, "250 2.1.0 OK\r\n");
}

static void do_rcpt(OutboxServer *srv, OutboxConn *c, const char *rest) {
    char path[SMTP_MAX_LINE];
    const char *params = NULL;
    char *local = NULL, *domain = NULL;

    (void)srv;
    if (c->state != OB_ST_MAIL) {
        outbox_conn_reply(c, "503 5.5.1 Error: need MAIL first\r\n");
        return;
    }
    if (!require_auth(c)) return;
    if (srv->max_rcpts != 0 && c->nrcpts >= (size_t)srv->max_rcpts) {
        outbox_conn_reply(c, "452 4.5.3 Too many recipients\r\n");
        return;
    }
    if (parse_addr_arg(rest, "TO", path, sizeof path, &params) != 0) {
        outbox_conn_reply(c, "501 5.5.4 Syntax: RCPT TO:<address>\r\n");
        return;
    }
    (void)params;
    if (path[0] == '\0') {
        outbox_conn_reply(c, "501 5.5.4 Empty recipient\r\n");
        return;
    }
    /* Accept any syntactically valid external address (this is authenticated
       outbound submission, not an open relay). */
    if (mail_addr_parse(path, &local, &domain) != 0) {
        outbox_conn_reply(c, "501 5.5.4 Invalid recipient address\r\n");
        return;
    }
    mail_addr_free(local, domain);
    if (outbox_conn_add_rcpt(c, path) != 0) {
        outbox_conn_reply(c, "451 4.3.0 Storage allocation failure\r\n");
        return;
    }
    outbox_conn_reply(c, "250 2.1.5 OK\r\n");
}

static void do_data(OutboxServer *srv, OutboxConn *c) {
    (void)srv;
    if (c->state != OB_ST_MAIL) {
        outbox_conn_reply(c, "503 5.5.1 Error: need RCPT first\r\n");
        return;
    }
    if (!require_auth(c)) return;
    if (c->nrcpts == 0) {
        outbox_conn_reply(c, "503 5.5.1 Error: no valid recipients\r\n");
        return;
    }
    outbox_conn_reply(c, "354 End data with <CR><LF>.<CR><LF>\r\n");
    free(c->data);
    c->data = NULL;
    c->data_len = 0;
    c->data_cap = 0;
    c->state = OB_ST_DATA;
}

static void handle_command(OutboxServer *srv, OutboxConn *c, char *line,
                           time_t now) {
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
        if (!*rest) { outbox_conn_reply(c, "501 5.5.4 EHLO requires a domain\r\n"); return; }
        do_helo(srv, c, true);
    } else if (vlen == 4 && ascii_strncasecmp(p, "HELO", 4) == 0) {
        if (!*rest) { outbox_conn_reply(c, "501 5.5.4 HELO requires a domain\r\n"); return; }
        do_helo(srv, c, false);
    } else if (vlen == 8 && ascii_strncasecmp(p, "STARTTLS", 8) == 0) {
        if (channel_secure(c) || c->tls) {
            outbox_conn_reply(c, "503 5.5.1 Error: TLS already active\r\n");
        } else if (c->state != OB_ST_HELO) {
            outbox_conn_reply(c, "503 5.5.1 Error: send EHLO first\r\n");
        } else if (*rest) {
            outbox_conn_reply(c, "501 5.5.4 Syntax: STARTTLS\r\n");
        } else if (c->in_len != 0) {
            outbox_conn_reply(c, "500 5.5.2 Pipelined data before STARTTLS\r\n");
        } else if (!smtp_in_tls_available()) {
            outbox_conn_reply(c, "502 5.5.1 Command not implemented\r\n");
        } else if (!(c->tls = smtp_in_tls_start(c->fd))) {
            outbox_conn_reply(c, "451 4.3.0 Storage allocation failure\r\n");
        } else {
            outbox_conn_reply(c, "220 2.0.0 Ready to start TLS\r\n");
        }
    } else if (vlen == 4 && ascii_strncasecmp(p, "AUTH", 4) == 0) {
        if (!require_secure(c)) return;
        if (outbox_auth_blocked(srv, c->peer_ip, c->peer_ip_len, now)) {
            outbox_conn_reply(c, "454 4.7.0 Too many failed attempts\r\n");
            return;
        }
        do_auth(srv, c, rest, now);
    } else if (vlen == 4 && ascii_strncasecmp(p, "MAIL", 4) == 0) {
        do_mail(srv, c, rest);
    } else if (vlen == 4 && ascii_strncasecmp(p, "RCPT", 4) == 0) {
        do_rcpt(srv, c, rest);
    } else if (vlen == 4 && ascii_strncasecmp(p, "DATA", 4) == 0) {
        do_data(srv, c);
    } else if (vlen == 4 && ascii_strncasecmp(p, "RSET", 4) == 0) {
        outbox_conn_reset_txn(c, (c->state == OB_ST_INIT) ? OB_ST_INIT : OB_ST_HELO);
        outbox_conn_reply(c, "250 2.0.0 OK\r\n");
    } else if (vlen == 4 && ascii_strncasecmp(p, "NOOP", 4) == 0) {
        outbox_conn_reply(c, "250 2.0.0 OK\r\n");
    } else if (vlen == 4 && ascii_strncasecmp(p, "QUIT", 4) == 0) {
        outbox_conn_reply(c, "221 2.0.0 Bye\r\n");
        c->closed = true;
    } else if (vlen == 4 && ascii_strncasecmp(p, "VRFY", 4) == 0) {
        outbox_conn_reply(c, "252 2.5.2 Cannot VRFY user\r\n");
    } else {
        outbox_conn_reply(c, "500 5.5.2 Command not recognized\r\n");
    }
}

/* ------------------------------------------------------------------ */
/* DATA input                                                         */
/* ------------------------------------------------------------------ */

static int data_scan(const char *buf, size_t len, uint32_t max_line,
                     uint64_t max_total, size_t *msg_end, size_t *term_len) {
    size_t i = 0;
    size_t line_start = 0;
    uint64_t line_max = (uint64_t)max_line + 1;

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

static void process_commands(OutboxServer *srv, OutboxConn *c, time_t now);

static void process_data(OutboxServer *srv, OutboxConn *c, time_t now) {
    size_t msg_end = 0, term_len = 0;
    int r = data_scan(c->data, c->data_len, srv->max_line, srv->raw_cap,
                      &msg_end, &term_len);
    if (r < 0) {
        outbox_conn_reply(c, "552 5.3.4 Message exceeds fixed limits\r\n");
        c->closed = true;
        return;
    }
    if (r == 0) return;   /* need more data */

    {
        size_t leftover_start = msg_end + term_len;
        size_t leftover = c->data_len - leftover_start;
        if (leftover > 0) {
            if (outbox_buf_append(&c->in, &c->in_len, &c->in_cap,
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

    deliver_message(srv, c);
    outbox_conn_reset_txn(c, OB_ST_HELO);

    if (!c->closed && c->in_len > 0)
        process_commands(srv, c, now);
}

static void process_commands(OutboxServer *srv, OutboxConn *c, time_t now) {
    for (;;) {
        size_t i = 0;
        size_t linelen, consumed;
        if (c->closed) return;
        while (i < c->in_len && c->in[i] != '\n') i++;
        if (i == c->in_len) {
            if (c->in_len > srv->max_line) {
                outbox_conn_reply(c, "500 5.5.2 Line too long\r\n");
                c->closed = true;
            }
            return;
        }
        if (i > (size_t)srv->max_line) {
            outbox_conn_reply(c, "500 5.5.2 Line too long\r\n");
            c->closed = true;
            return;
        }
        linelen = i;
        if (linelen > 0 && c->in[linelen - 1] == '\r') linelen--;
        {
            char *line = malloc(linelen + 1);
            if (!line) {
                outbox_conn_reply(c, "451 4.3.0 Storage allocation failure\r\n");
                c->closed = true;
                return;
            }
            memcpy(line, c->in, linelen);
            line[linelen] = '\0';
            consumed = i + 1;
            memmove(c->in, c->in + consumed, c->in_len - consumed);
            c->in_len -= consumed;
            if (c->auth_pending != OB_AUTH_NONE)
                handle_auth_cont(srv, c, line, now);
            else
                handle_command(srv, c, line, now);
            free(line);
        }

        /* Once DATA starts, remaining buffered bytes are MESSAGE DATA. */
        if (c->state == OB_ST_DATA && !c->closed) {
            if (c->in_len > 0) {
                if ((uint64_t)c->data_len + (uint64_t)c->in_len > srv->raw_cap) {
                    outbox_conn_reply(c, "552 5.3.4 Message exceeds fixed limit\r\n");
                    c->closed = true;
                    return;
                }
                if (outbox_buf_append(&c->data, &c->data_len, &c->data_cap,
                                      c->in, c->in_len) != 0) {
                    outbox_conn_reply(c, "451 4.3.0 Storage allocation failure\r\n");
                    c->closed = true;
                    return;
                }
                c->in_len = 0;
            }
            return;
        }
    }
}

static void conn_take_bytes(OutboxServer *srv, OutboxConn *c, char *tmp,
                            size_t n, time_t now) {
    if (c->state == OB_ST_DATA) {
        if ((uint64_t)c->data_len + (uint64_t)n > srv->raw_cap) {
            outbox_conn_reply(c, "552 5.3.4 Message exceeds fixed limit\r\n");
            c->closed = true;
            return;
        }
        if (outbox_buf_append(&c->data, &c->data_len, &c->data_cap, tmp, n) != 0) {
            outbox_conn_reply(c, "451 4.3.0 Storage allocation failure\r\n");
            c->closed = true;
            return;
        }
        process_data(srv, c, now);
    } else {
        if (outbox_buf_append(&c->in, &c->in_len, &c->in_cap, tmp, n) != 0) {
            outbox_conn_reply(c, "500 5.5.2 Line too long\r\n");
            c->closed = true;
            return;
        }
        process_commands(srv, c, now);
    }
}

void outbox_conn_readable(OutboxServer *srv, OutboxConn *c, time_t now) {
    char tmp[OUTBOX_RECV_CHUNK];

    if (c->tls) {
        if (!smtp_in_tls_established(c->tls)) return;
        for (;;) {
            int n = smtp_in_tls_recv(c->tls, tmp, sizeof tmp);
            if (n < 0) { c->closed = true; return; }
            if (n == 0) return;
            c->last_act = now;
            conn_take_bytes(srv, c, tmp, (size_t)n, now);
            if (c->closed) return;
            if (c->state == OB_ST_DATA) return;   /* bulk DATA: next POLLIN */
        }
    }

    {
        ssize_t n = recv(c->fd, tmp, sizeof tmp, 0);
        if (n < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) return;
            c->closed = true;
            return;
        }
        if (n == 0) {
            c->closed = true;
            return;
        }
        c->last_act = now;
        conn_take_bytes(srv, c, tmp, (size_t)n, now);
    }
}
