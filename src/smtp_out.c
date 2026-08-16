/* smtp_out.c — outbound SMTP relay client (slice S4, STARTTLS added S-B2).
 *
 * Full delivery dialogue against Config.relay:
 *   connect (bounded timeout) -> 220 greeting -> EHLO -> [STARTTLS] ->
 *   [AUTH PLAIN] -> MAIL FROM -> RCPT TO -> DATA -> dot-stuffed body ->
 *   CRLF.CRLF -> final reply -> QUIT -> close.
 *
 * STARTTLS comes in two modes:
 *   - relay.tls == "starttls" (opportunistic): after EHLO, if the relay
 *     advertises STARTTLS (any line of the full multi-line EHLO reply), we send
 *     "STARTTLS", expect 220, then run an mbedTLS 1.2 handshake over the SAME
 *     blocking fd (authmode VERIFY_NONE + SNI via relay.host; protects against
 *     passive snooping only), then re-EHLO over TLS (RFC 3207) and continue.
 *     If STARTTLS is NOT advertised (or the STARTTLS command is refused) we
 *     fall back to plaintext — EXCEPT the hard rule: when relay.tls ==
 *     "starttls" AND relay.auth.enabled, we REFUSE the fallback (SMTP_PERMFAIL,
 *     "refusing to send AUTH over plaintext") so AUTH PLAIN credentials are
 *     never sent in the clear.
 *   - relay.tls == "starttls-verify" (MANDATORY TLS + verification, fail
 *     closed): STARTTLS MUST be advertised (else PERMFAIL) and the STARTTLS
 *     command MUST be accepted (4xx refusal -> TEMPFAIL retry, 5xx/absent ->
 *     PERMFAIL).  The handshake runs with VERIFY_REQUIRED against the trusted
 *     CA chain (relay.tls_ca file, or the embedded Mozilla bundle when empty)
 *     plus mbedtls_ssl_set_hostname for the SAN/CN check.  A certificate
 *     verification failure (VERIFY_FAILED / BAD_CERTIFICATE / CA_CHAIN_REQUIRED
 *     / non-zero verify_result) is PERMANENT — we NEVER fall back to plaintext
 *     and NEVER retry a bad cert; any other TLS error (timeout/EOF/transport)
 *     is TEMPFAIL and the durable queue re-drives.  No AUTH-over-plaintext is
 *     possible in this mode (mandatory TLS subsumes the auth rule).
 * relay.tls == "none" is the unchanged plaintext path (byte-identical).
 *
 * Reply-code mapping: 2xx/3xx = ok, 4xx = tempfail, 5xx = permfail. Connect
 * failures and 4xx replies are retried up to Config.relay.retries additional
 * times with exponential backoff; 5xx is permanent and is never retried.
 *
 * Bounds: every server line is capped at SMTP_MAX_LINE bytes; each read/write
 * is bounded by Config.limits.cmd_timeout (the DATA payload uses data_timeout,
 * falling back to cmd_timeout); the connect uses a fixed
 * SMTP_CONNECT_TIMEOUT_MS; the TLS BIO callbacks are poll-bounded with those
 * same timeouts (blocking sockets, so recv/send never return EAGAIN).  No
 * unbounded buffers are used. */
#include "visage.h"
#include "smtp.h"
#include "mail.h"

#include <sys/socket.h>
#include <netdb.h>
#include <poll.h>
#include <fcntl.h>

#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/x509_crt.h"

/* Embedded Mozilla CA bundle (src/data/cacert_pem.c — GENERATED; regenerate
   via tools/gen_cacert.sh).  Referenced only on the 'starttls-verify' path as
   the default trust anchor when relay.tls_ca is empty. */
extern const char visage_cacert_pem[];
extern const size_t visage_cacert_pem_len;

#define SMTP_CONNECT_TIMEOUT_MS 10000  /* bounded connect timeout (10 s)   */
#define SMTP_DEFAULT_TIMEOUT    60     /* fallback when a *timeout == 0     */
#define SMTP_MAX_CRED_LEN       4096   /* sanity cap on AUTH PLAIN payload  */
#define SMTP_WRITE_CHUNK        65536  /* bound each blocking send()        */
#define SMTP_MAX_REPLY          16384  /* cap on a full multi-line EHLO reply */

static const char b64_tab[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* ------------------------------------------------------------------ */
/* Shared helpers (declared in smtp.h)                                */
/* ------------------------------------------------------------------ */

const char *smtp_status_str(int status) {
    switch (status) {
    case SMTP_OK:       return "ok";
    case SMTP_TEMPFAIL: return "tempfail";
    case SMTP_PERMFAIL: return "permfail";
    case SMTP_ERROR:    return "error";
    default:            return "unknown";
    }
}

int smtp_reply_code(const char *line, int *code) {
    if (!line || !code) return -1;
    if (line[0] < '0' || line[0] > '9') return -1;
    if (line[1] < '0' || line[1] > '9') return -1;
    if (line[2] < '0' || line[2] > '9') return -1;
    *code = (line[0] - '0') * 100 + (line[1] - '0') * 10 + (line[2] - '0');
    return 0;
}

int smtp_b64_encode(const void *in, size_t inlen, char *out, size_t outsz,
                    size_t *outlen) {
    if (outlen) *outlen = 0;
    if (!in || !out || !outlen) return -1;
    if (inlen > SIZE_MAX / 2) return -1;    /* guard the size arithmetic      */
    size_t req = ((inlen + 2) / 3) * 4 + 1; /* encoded length + NUL terminator */
    if (outsz < req) return -1;

    const unsigned char *p = (const unsigned char *)in;
    size_t i = 0, o = 0;
    while (i + 3 <= inlen) {
        uint32_t v = ((uint32_t)p[i] << 16) | ((uint32_t)p[i + 1] << 8) |
                     (uint32_t)p[i + 2];
        out[o++] = b64_tab[(v >> 18) & 0x3f];
        out[o++] = b64_tab[(v >> 12) & 0x3f];
        out[o++] = b64_tab[(v >> 6) & 0x3f];
        out[o++] = b64_tab[v & 0x3f];
        i += 3;
    }
    if (inlen - i == 1) {
        uint32_t v = (uint32_t)p[i] << 16;
        out[o++] = b64_tab[(v >> 18) & 0x3f];
        out[o++] = b64_tab[(v >> 12) & 0x3f];
        out[o++] = '=';
        out[o++] = '=';
    } else if (inlen - i == 2) {
        uint32_t v = ((uint32_t)p[i] << 16) | ((uint32_t)p[i + 1] << 8);
        out[o++] = b64_tab[(v >> 18) & 0x3f];
        out[o++] = b64_tab[(v >> 12) & 0x3f];
        out[o++] = b64_tab[(v >> 6) & 0x3f];
        out[o++] = '=';
    }
    out[o] = '\0';
    *outlen = o;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Small internal helpers                                             */
/* ------------------------------------------------------------------ */

static void set_status(char *out, size_t outsz, const char *msg) {
    if (!out || outsz == 0) return;
    snprintf(out, outsz, "%s", msg ? msg : "");
}

static bool has_crlf(const char *s) {
    if (!s) return false;
    return strchr(s, '\r') != NULL || strchr(s, '\n') != NULL;
}

/* Map a 3-digit SMTP reply code to its delivery class. */
static int smtp_class(int code) {
    if (code >= 200 && code < 400) return SMTP_OK;
    if (code >= 400 && code < 500) return SMTP_TEMPFAIL;
    if (code >= 500 && code < 600) return SMTP_PERMFAIL;
    return SMTP_ERROR;
}

/* Convert a timeout in seconds to poll() milliseconds (int32_t-bounded).
   0 seconds means "no timeout" (poll blocks indefinitely). */
static int timeout_ms(uint32_t seconds) {
    if (seconds == 0) return -1;
    uint64_t ms = (uint64_t)seconds * 1000u;
    if (ms > 2147483647) ms = 2147483647;
    return (int)ms;
}

/* Validate relay.tls ∈ {"none", "starttls", "starttls-verify"}.  Pure; unit-tested. */
int smtp_tls_valid(const char *tls) {
    if (!tls) return -1;
    if (strcmp(tls, "none") == 0) return 0;
    if (strcmp(tls, "starttls") == 0) return 0;
    if (strcmp(tls, "starttls-verify") == 0) return 0;
    return -1;
}

/* Does the multi-line SMTP reply advertise capability `cap`?  `reply` is the
   raw reply text (each line begins with a 3-digit code + ' ' or '-' and is
   '\n'- or '\r'-terminated).  Matching is a case-insensitive, whole-keyword
   comparison against the whitespace-delimited tokens in the text that follows
   the "ddd " / "ddd-" prefix of each line — so "STARTTLS" is found whether it
   appears on a continuation line or on the final line (some servers put it
   last).  Pure — no I/O. */
bool smtp_reply_has_cap(const char *reply, size_t len, const char *cap) {
    if (!reply || !cap) return false;
    size_t capn = strlen(cap);
    if (capn == 0) return false;

    size_t i = 0;
    while (i < len) {
        size_t line_start = i;
        while (i < len && reply[i] != '\n') i++;
        size_t line_end = i;                 /* at '\n' or len */
        if (i < len) i++;                    /* skip the '\n' */

        size_t llen = line_end - line_start;
        if (llen < 4) continue;
        const char *lp = reply + line_start;
        if (lp[0] < '0' || lp[0] > '9' || lp[1] < '0' || lp[1] > '9' ||
            lp[2] < '0' || lp[2] > '9') continue;
        if (lp[3] != ' ' && lp[3] != '-') continue;

        /* tokenize the text after "ddd " / "ddd-" */
        size_t p = line_start + 4;
        while (p < line_end) {
            while (p < line_end &&
                   (reply[p] == ' ' || reply[p] == '\t' || reply[p] == '\r'))
                p++;
            size_t tok = p;
            while (p < line_end &&
                   !(reply[p] == ' ' || reply[p] == '\t' || reply[p] == '\r'))
                p++;
            size_t tlen = p - tok;
            if (tlen != capn) continue;
            size_t k;
            for (k = 0; k < capn; k++) {
                int a = (reply[tok + k] >= 'A' && reply[tok + k] <= 'Z')
                            ? reply[tok + k] + ('a' - 'A') : reply[tok + k];
                int b = (cap[k] >= 'A' && cap[k] <= 'Z')
                            ? cap[k] + ('a' - 'A') : cap[k];
                if (a != b) break;
            }
            if (k == capn) return true;
        }
    }
    return false;
}

/* Copy the first reply line's text (after the "ddd " / "ddd-" prefix) into
   out for a human-readable status message. */
static void reply_first_text(const char *reply, size_t len, char *out,
                             size_t outsz) {
    if (!out || outsz == 0) return;
    out[0] = '\0';
    if (!reply || len < 4) return;
    size_t end = 0;
    while (end < len && reply[end] != '\n' && reply[end] != '\r') end++;
    size_t start = 4;
    size_t copylen = (end > start) ? (end - start) : 0;
    if (copylen > outsz - 1) copylen = outsz - 1;
    memcpy(out, reply + start, copylen);
    out[copylen] = '\0';
}

/* ------------------------------------------------------------------ */
/* TLS connection state                                               */
/* ------------------------------------------------------------------ */

/* A relay connection: the fd plus optional in-place TLS state.  tls is false
   until the STARTTLS handshake completes; the I/O primitives below dispatch on
   it (read/send vs mbedtls_ssl_read/mbedtls_ssl_write). */
typedef struct SmtpConn {
    int        fd;
    bool       tls;              /* handshake completed; speak TLS           */
    uint32_t   tmo;              /* current op timeout (s) for the BIO poll  */
    mbedtls_ssl_context ssl;     /* in-place storage (valid once setup'd)    */
} SmtpConn;

/* Process-wide mbedTLS state, seeded lazily and once (single-threaded daemon;
   smtp_out_send may be called repeatedly).  Two shared SSL configs are kept —
   both read-only after setup and every connection reuses the same settings:
     g_ssl_conf         CLIENT / VERIFY_NONE    / TLS1.2  (relay.tls "starttls")
     g_ssl_conf_verify  CLIENT / VERIFY_REQUIRED / TLS1.2 + CA chain
                        (relay.tls "starttls-verify"; CA chain installed
                         lazily+sticky by smtp_tls_verify_init). */
static mbedtls_entropy_context g_entropy;
static mbedtls_ctr_drbg_context g_drbg;
static mbedtls_ssl_config     g_ssl_conf;
static mbedtls_ssl_config     g_ssl_conf_verify;
static mbedtls_x509_crt       g_ca_chain;
static bool g_tls_ready = false;
static int  g_tls_status = 0;   /* 0 = ok, else the mbedTLS seed/setup error */
static bool g_verify_ready = false;
static int  g_verify_status = 0; /* 0 = ok, else the mbedTLS CA-parse error  */

/* Idempotent one-time mbedTLS init.  Returns 0, or the mbedTLS error. */
static int smtp_tls_global_init(void) {
    if (g_tls_ready) return g_tls_status;

    mbedtls_entropy_init(&g_entropy);
    mbedtls_ctr_drbg_init(&g_drbg);
    mbedtls_ssl_config_init(&g_ssl_conf);
    mbedtls_ssl_config_init(&g_ssl_conf_verify);
    mbedtls_x509_crt_init(&g_ca_chain);

    const char pers[] = "visage_smtp_out";
    int r = mbedtls_ctr_drbg_seed(&g_drbg, mbedtls_entropy_func, &g_entropy,
                                  (const unsigned char *)pers, sizeof pers - 1);
    if (r == 0)
        r = mbedtls_ssl_config_defaults(&g_ssl_conf, MBEDTLS_SSL_IS_CLIENT,
                                        MBEDTLS_SSL_TRANSPORT_STREAM,
                                        MBEDTLS_SSL_PRESET_DEFAULT);
    if (r == 0) {
        mbedtls_ssl_conf_rng(&g_ssl_conf, mbedtls_ctr_drbg_random, &g_drbg);
        mbedtls_ssl_conf_authmode(&g_ssl_conf, MBEDTLS_SSL_VERIFY_NONE);
        mbedtls_ssl_conf_min_tls_version(&g_ssl_conf,
                                         MBEDTLS_SSL_VERSION_TLS1_2);
        mbedtls_ssl_conf_max_tls_version(&g_ssl_conf,
                                         MBEDTLS_SSL_VERSION_TLS1_2);
    }
    if (r == 0)
        r = mbedtls_ssl_config_defaults(&g_ssl_conf_verify, MBEDTLS_SSL_IS_CLIENT,
                                        MBEDTLS_SSL_TRANSPORT_STREAM,
                                        MBEDTLS_SSL_PRESET_DEFAULT);
    if (r == 0) {
        mbedtls_ssl_conf_rng(&g_ssl_conf_verify, mbedtls_ctr_drbg_random,
                             &g_drbg);
        mbedtls_ssl_conf_authmode(&g_ssl_conf_verify,
                                  MBEDTLS_SSL_VERIFY_REQUIRED);
        mbedtls_ssl_conf_min_tls_version(&g_ssl_conf_verify,
                                         MBEDTLS_SSL_VERSION_TLS1_2);
        mbedtls_ssl_conf_max_tls_version(&g_ssl_conf_verify,
                                         MBEDTLS_SSL_VERSION_TLS1_2);
    }

    g_tls_status = r;
    g_tls_ready = true;   /* do not re-seed on every attempt */
    return r;
}

/* Lazily parse the trusted CA chain and install it into g_ssl_conf_verify.
   Sticky: attempted once, then the result is cached (a bad tls_ca file is not
   re-read on every connection).  `tls_ca` empty (or NULL) selects the embedded
   Mozilla bundle; otherwise it is a path to a PEM CA bundle.  Returns 0 on
   success, or a negative mbedTLS error.  mbedtls_x509_crt_parse(_file) returns
   the number of parsed certs (>= 0), and is permissive about a few skipped
   certs — only a negative return is fatal; a non-negative count is accepted
   even if some CAs were skipped. */
static int smtp_tls_verify_init(const char *tls_ca) {
    if (g_verify_ready) return g_verify_status;

    int r = smtp_tls_global_init();
    if (r != 0) {
        g_verify_status = r;
        g_verify_ready = true;
        return r;
    }

    if (tls_ca && *tls_ca)
        r = mbedtls_x509_crt_parse_file(&g_ca_chain, tls_ca);
    else
        /* mbedtls_x509_crt_parse's buflen must INCLUDE the terminating NUL
           (its PEM-vs-DER detection checks buf[buflen-1] == '\0'); the
           generated visage_cacert_pem_len excludes it, hence the +1. */
        r = mbedtls_x509_crt_parse(&g_ca_chain,
                                   (const unsigned char *)visage_cacert_pem,
                                   visage_cacert_pem_len + 1);

    if (r < 0) {
        g_verify_status = r;
        g_verify_ready = true;
        return r;
    }
    /* r >= 0: some number of certs parsed (a few may be skipped — acceptable). */

    mbedtls_ssl_conf_ca_chain(&g_ssl_conf_verify, &g_ca_chain, NULL);

    g_verify_status = 0;
    g_verify_ready = true;
    return 0;
}

/* mbedTLS BIO callbacks: blocking, poll-bounded (the production contract).
   ctx is the SmtpConn carrying the fd + the current operation timeout.  On
   poll timeout return MBEDTLS_ERR_SSL_TIMEOUT (from ssl.h; NOT the NET_* codes
   in net_sockets.h, which we do not compile).  recv()==0 is EOF -> return 0
   per the mbedTLS contract.  EINTR loops; the fd stays BLOCKING so recv/send
   never return EAGAIN. */
static int bio_recv(void *ctx, unsigned char *buf, size_t len) {
    SmtpConn *c = ctx;
    for (;;) {
        struct pollfd pfd;
        pfd.fd = c->fd;
        pfd.events = POLLIN;
        pfd.revents = 0;
        int pr = poll(&pfd, 1, timeout_ms(c->tmo));
        if (pr < 0) {
            if (errno == EINTR) continue;
            return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
        }
        if (pr == 0) return MBEDTLS_ERR_SSL_TIMEOUT;
        ssize_t r = recv(c->fd, buf, len, 0);
        if (r < 0) {
            if (errno == EINTR) continue;
            return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
        }
        if (r == 0) return 0;               /* EOF */
        return (int)r;
    }
}

static int bio_send(void *ctx, const unsigned char *buf, size_t len) {
    SmtpConn *c = ctx;
    size_t chunk = len;
    if (chunk > SMTP_WRITE_CHUNK) chunk = SMTP_WRITE_CHUNK;
    for (;;) {
        struct pollfd pfd;
        pfd.fd = c->fd;
        pfd.events = POLLOUT;
        pfd.revents = 0;
        int pr = poll(&pfd, 1, timeout_ms(c->tmo));
        if (pr < 0) {
            if (errno == EINTR) continue;
            return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
        }
        if (pr == 0) return MBEDTLS_ERR_SSL_TIMEOUT;
        ssize_t w = send(c->fd, buf, chunk, MSG_NOSIGNAL);
        if (w < 0) {
            if (errno == EINTR) continue;
            return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
        }
        if (w == 0) return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
        return (int)w;                      /* partial write is fine */
    }
}

/* Initialise a connection around an already-connected blocking fd. */
static void smtp_conn_init(SmtpConn *conn, int fd) {
    conn->fd = fd;
    conn->tls = false;
    conn->tmo = 0;
    mbedtls_ssl_init(&conn->ssl);
}

/* Close a connection: send TLS close_notify (best effort) on the success
   path, free any TLS state, then close the fd.  Safe on the plaintext path
   (tls == false) and on an init-only/partially-setup ssl context. */
static void smtp_conn_close(SmtpConn *conn, bool graceful) {
    if (!conn) return;
    if (conn->tls && graceful)
        (void)mbedtls_ssl_close_notify(&conn->ssl);
    mbedtls_ssl_free(&conn->ssl);
    if (conn->fd >= 0) close(conn->fd);
    conn->fd = -1;
}

/* ------------------------------------------------------------------ */
/* Bounded I/O primitives                                             */
/* ------------------------------------------------------------------ */

/* Read one byte with a bounded timeout.  Returns 1 (byte stored in *b), 0
   (EOF), -1 (timeout/error).  The TLS path dispatches to mbedtls_ssl_read,
   whose BIO callbacks enforce the timeout; the plaintext path polls + reads
   directly (byte-identical to the original smtp_read_line inner loop). */
static int conn_read_byte(SmtpConn *conn, uint32_t tmo, unsigned char *b) {
    if (conn->tls) {
        conn->tmo = tmo;
        int r = mbedtls_ssl_read(&conn->ssl, b, 1);
        if (r == 1) return 1;
        if (r == 0 || r == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) return 0;
        return -1;   /* MBEDTLS_ERR_SSL_TIMEOUT (propagated) or other error */
    }
    for (;;) {
        struct pollfd pfd;
        pfd.fd = conn->fd;
        pfd.events = POLLIN;
        pfd.revents = 0;
        int pr = poll(&pfd, 1, timeout_ms(tmo));
        if (pr < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (pr == 0) return -1;                /* timed out */
        ssize_t r = read(conn->fd, b, 1);
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (r == 0) return 0;                  /* EOF */
        return 1;
    }
}

/* Send up to len bytes (may be partial).  Returns bytes sent (>0) or -1 on
   timeout/error.  The plaintext path is byte-identical to the original
   smtp_write_all inner loop (poll POLLOUT, send up to SMTP_WRITE_CHUNK). */
static ssize_t conn_send(SmtpConn *conn, const char *buf, size_t len,
                         uint32_t tmo) {
    if (conn->tls) {
        conn->tmo = tmo;
        int w = mbedtls_ssl_write(&conn->ssl, (const unsigned char *)buf, len);
        if (w > 0) return (ssize_t)w;
        return -1;   /* MBEDTLS_ERR_SSL_TIMEOUT (propagated) or other error */
    }
    size_t chunk = len;
    if (chunk > SMTP_WRITE_CHUNK) chunk = SMTP_WRITE_CHUNK;
    for (;;) {
        struct pollfd pfd;
        pfd.fd = conn->fd;
        pfd.events = POLLOUT;
        pfd.revents = 0;
        int pr = poll(&pfd, 1, timeout_ms(tmo));
        if (pr < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (pr == 0) return -1;                /* timed out */
        ssize_t w = send(conn->fd, buf, chunk, MSG_NOSIGNAL);
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (w == 0) return -1;
        return w;
    }
}

/* Read one CRLF-terminated line (tolerating a bare LF) into buf[0..bufsz).
   Returns 0 and sets *outlen (including the terminator) on success; -1 on
   timeout, EOF, I/O error, or a line that would exceed bufsz bytes. */
static int smtp_read_line(SmtpConn *conn, uint32_t tmo, char *buf, size_t bufsz,
                          size_t *outlen) {
    size_t n = 0;
    for (;;) {
        if (n >= bufsz) return -1;                 /* line too long */
        unsigned char b;
        if (conn_read_byte(conn, tmo, &b) <= 0) return -1;
        buf[n++] = (char)b;
        if (n >= 2 && buf[n - 2] == '\r' && buf[n - 1] == '\n') {
            *outlen = n;
            return 0;
        }
        if (buf[n - 1] == '\n') {                  /* tolerate bare LF */
            *outlen = n;
            return 0;
        }
    }
}

/* Read one complete (possibly multi-line) SMTP reply. The first line's text
   (after "ddd " or "ddd-") is copied into text[0..textsz). Returns 0 and
   sets *code on success; -1 on any error or malformed reply. */
static int smtp_read_reply(SmtpConn *conn, uint32_t tmo, int *code, char *text,
                           size_t textsz) {
    if (code) *code = 0;
    if (text && textsz) text[0] = '\0';

    int first = -1;
    for (;;) {
        char line[SMTP_MAX_LINE];
        size_t n = 0;
        if (smtp_read_line(conn, tmo, line, sizeof line, &n) != 0)
            return -1;

        int lc = 0;
        if (n < 4 || smtp_reply_code(line, &lc) != 0)
            return -1;
        char sep = line[3];
        if (sep != ' ' && sep != '-')
            return -1;

        if (first < 0) {
            first = lc;
            size_t tlen = n;
            if (tlen >= 2 && line[tlen - 2] == '\r' && line[tlen - 1] == '\n')
                tlen -= 2;
            else if (tlen >= 1 && line[tlen - 1] == '\n')
                tlen -= 1;
            size_t start = 4;
            size_t copylen = (tlen > start) ? (tlen - start) : 0;
            if (text && textsz > 0) {
                if (copylen > textsz - 1) copylen = textsz - 1;
                memcpy(text, line + start, copylen);
                text[copylen] = '\0';
            }
        } else if (lc != first) {
            return -1;                             /* code changed mid-reply */
        }

        if (sep == ' ') {
            *code = first;
            return 0;
        }
    }
}

/* Read one complete (possibly multi-line) SMTP reply, capturing the raw text
   of EVERY line (CRLF-terminated, as received) into reply[0..replysz) so the
   full capability list is available (some servers put STARTTLS on a later
   line).  Returns 0 and sets *code and *replylen on success; -1 on error, a
   malformed reply, or a reply that would overflow replysz. */
static int smtp_read_reply_all(SmtpConn *conn, uint32_t tmo, int *code,
                               char *reply, size_t replysz, size_t *replylen) {
    if (code) *code = 0;
    if (replylen) *replylen = 0;
    if (reply && replysz) reply[0] = '\0';

    int first = -1;
    size_t total = 0;
    for (;;) {
        char line[SMTP_MAX_LINE];
        size_t n = 0;
        if (smtp_read_line(conn, tmo, line, sizeof line, &n) != 0)
            return -1;

        int lc = 0;
        if (n < 4 || smtp_reply_code(line, &lc) != 0)
            return -1;
        char sep = line[3];
        if (sep != ' ' && sep != '-')
            return -1;

        if (first < 0) first = lc;
        else if (lc != first) return -1;      /* code changed mid-reply */

        if (reply && replysz > 0) {
            if (total > replysz - 1 || n > replysz - 1 - total)
                return -1;                    /* overflow: fail closed */
            memcpy(reply + total, line, n);
            total += n;
        }
        if (sep == ' ') {
            *code = first;
            if (reply && replysz > 0) reply[total] = '\0';
            if (replylen) *replylen = total;
            return 0;
        }
    }
}

/* Write exactly len bytes, bounded by tmo seconds, handling partial writes
   and EINTR. Returns 0 on success, -1 on timeout/error. */
static int smtp_write_all(SmtpConn *conn, const char *buf, size_t len,
                          uint32_t tmo) {
    size_t off = 0;
    while (off < len) {
        ssize_t w = conn_send(conn, buf + off, len - off, tmo);
        if (w <= 0) return -1;
        off += (size_t)w;
    }
    return 0;
}

/* Send one command line (including its CRLF) and read the reply into *code.
   The first reply line's text is copied into status_out. Returns 0 on
   success, -1 on a write/read failure. */
static int smtp_exchange(SmtpConn *conn, uint32_t tmo, const char *cmd,
                         int *code, char *status_out, size_t status_sz) {
    if (smtp_write_all(conn, cmd, strlen(cmd), tmo) != 0) {
        set_status(status_out, status_sz, "write failed");
        return -1;
    }
    char text[SMTP_MAX_LINE];
    if (smtp_read_reply(conn, tmo, code, text, sizeof text) != 0) {
        set_status(status_out, status_sz, "read failed");
        return -1;
    }
    set_status(status_out, status_sz, text);
    return 0;
}

/* Build "<verb><addr>\r\n" into buf (bounded). Returns 0, or -1 if it would
   not fit. */
static int build_addr_cmd(char *buf, size_t bufsz, const char *verb,
                          const char *addr) {
    int n = snprintf(buf, bufsz, "%s<%s>\r\n", verb, addr);
    if (n < 0 || (size_t)n >= bufsz) return -1;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Connect                                                            */
/* ------------------------------------------------------------------ */

/* Blocking TCP connect to relay.host:port with a bounded timeout. Tries each
   address returned by getaddrinfo in turn. Returns the connected fd, or -1
   (with a message in status_out). */
static int smtp_connect(const Config *c, char *status_out, size_t status_sz) {
    char portstr[16];
    snprintf(portstr, sizeof portstr, "%u", c->relay.port);

    struct addrinfo hints;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo *res = NULL;
    int gai = getaddrinfo(c->relay.host, portstr, &hints, &res);
    if (gai != 0) {
        set_status(status_out, status_sz, gai_strerror(gai));
        return -1;
    }

    int fd = -1;
    for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
        int s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (s < 0) continue;

        int fl = fcntl(s, F_GETFL, 0);
        if (fl < 0 || fcntl(s, F_SETFL, fl | (int)O_NONBLOCK) < 0) {
            close(s);
            continue;
        }

        int rc = connect(s, ai->ai_addr, ai->ai_addrlen);
        if (rc < 0 && errno != EINPROGRESS) {
            close(s);
            continue;
        }

        struct pollfd pfd;
        pfd.fd = s;
        pfd.events = POLLOUT;
        pfd.revents = 0;
        if (poll(&pfd, 1, SMTP_CONNECT_TIMEOUT_MS) <= 0) {
            close(s);
            continue;
        }

        int soerr = 0;
        uint32_t slen = sizeof soerr;
        if (getsockopt(s, SOL_SOCKET, SO_ERROR, &soerr, &slen) < 0 ||
            soerr != 0) {
            close(s);
            continue;
        }

        if (fcntl(s, F_SETFL, fl) < 0) {           /* restore blocking mode */
            close(s);
            continue;
        }

        fd = s;
        break;
    }
    freeaddrinfo(res);

    if (fd < 0)
        set_status(status_out, status_sz, "connect failed");
    return fd;
}

/* ------------------------------------------------------------------ */
/* STARTTLS                                                            */
/* ------------------------------------------------------------------ */

/* Perform the TLS handshake over conn->fd.  conn->tls is false on entry; on
   success conn->tls is set and the caller may speak TLS.  On failure the fd
   stays plaintext (conn->tls left false) and the caller must abort the
   attempt.  When `verify` is true the handshake uses g_ssl_conf_verify
   (VERIFY_REQUIRED + the trusted CA chain installed by smtp_tls_verify_init,
   keyed on tls_ca); the hostname is still set for SNI, which under
   VERIFY_REQUIRED also enforces the SAN/CN match.  Returns 0 on success, or a
   negative mbedTLS error code (MBEDTLS_ERR_SSL_TIMEOUT on a poll timeout). */
static int smtp_tls_handshake(SmtpConn *conn, const char *host, bool verify,
                              const char *tls_ca, uint32_t tmo,
                              char *status_out, size_t status_sz) {
    int r = smtp_tls_global_init();
    if (r != 0) {
        set_status(status_out, status_sz, "tls init failed");
        return r;
    }

    if (verify) {
        r = smtp_tls_verify_init(tls_ca);
        if (r != 0) {
            set_status(status_out, status_sz, "tls verify init failed");
            return r;
        }
    }

    r = mbedtls_ssl_setup(&conn->ssl,
                          verify ? &g_ssl_conf_verify : &g_ssl_conf);
    if (r != 0) {
        set_status(status_out, status_sz, "tls setup failed");
        return r;
    }
    if (host && *host) {
        r = mbedtls_ssl_set_hostname(&conn->ssl, host);   /* SNI (+SAN/CN) */
        if (r != 0) {
            set_status(status_out, status_sz, "tls hostname failed");
            return r;
        }
    }

    conn->tmo = tmo;
    mbedtls_ssl_set_bio(&conn->ssl, conn, bio_send, bio_recv, NULL);

    r = mbedtls_ssl_handshake(&conn->ssl);
    if (r != 0) {
        char ebuf[128];
        mbedtls_strerror(r, ebuf, sizeof ebuf);
        set_status(status_out, status_sz, ebuf);
        return r;
    }
    conn->tls = true;
    return 0;
}

/* ------------------------------------------------------------------ */
/* AUTH PLAIN                                                         */
/* ------------------------------------------------------------------ */

/* Classify an AUTH PLAIN final reply code: 235 -> SMTP_OK, 4xx ->
   SMTP_TEMPFAIL, 5xx (incl 535/534 bad-credentials) -> SMTP_PERMFAIL, anything
   else (a 2xx/3xx that isn't 235, an unexpected second 334 challenge, or an
   out-of-range code) -> SMTP_ERROR.  Pure — no I/O; unit-tested. */
int smtp_auth_class(int code) {
    if (code == 235) return SMTP_OK;
    if (code >= 400 && code < 500) return SMTP_TEMPFAIL;
    if (code >= 500 && code < 600) return SMTP_PERMFAIL;
    return SMTP_ERROR;
}

/* Perform SMTP AUTH PLAIN (RFC 4954/4616): the SASL PLAIN response is
   base64("" NUL username NUL password) with an empty authzid.  Two forms are
   supported, in order:
     (a) single-line "AUTH PLAIN <b64>" -> 235 — the common path; most relays
         accept the RFC 4954 initial response.
     (b) two-step "AUTH PLAIN <b64>" -> 334 <challenge> -> "<b64>" -> 235/535 —
         some relays reject the one-line form and instead solicit the response
         with a 334.  Per RFC 4616 the client ignores the 334 challenge data
         and sends the fixed PLAIN response unchanged.
   Returns a status class (SMTP_OK on 235, SMTP_TEMPFAIL on 4xx, SMTP_PERMFAIL
   on 5xx, SMTP_ERROR otherwise).  The caller guarantees this is reached only
   when the transport is already cleared to carry credentials (TLS, or the
   explicit no-auth-no-TLS plaintext path). */
static int smtp_auth_plain(SmtpConn *conn, uint32_t tmo,
                           const ConfigRelayAuth *auth, char *status_out,
                           size_t status_sz) {
    const char *u = auth->username ? auth->username : "";
    const char *p = auth->password ? auth->password : "";
    size_t ulen = strlen(u);
    size_t plen = strlen(p);
    if (ulen > SMTP_MAX_CRED_LEN || plen > SMTP_MAX_CRED_LEN) {
        set_status(status_out, status_sz, "auth credentials too long");
        return SMTP_ERROR;
    }

    size_t plainlen = 1 + ulen + 1 + plen;   /* \0 + authcid + \0 + passwd */
    if (plainlen > SMTP_MAX_CRED_LEN) {
        set_status(status_out, status_sz, "auth credentials too long");
        return SMTP_ERROR;
    }

    char *plain = malloc(plainlen);
    if (!plain) {
        set_status(status_out, status_sz, "out of memory");
        return SMTP_ERROR;
    }
    char *w = plain;
    *w++ = '\0';                         /* empty authzid (RFC 4616-compliant) */
    memcpy(w, u, ulen); w += ulen;
    *w++ = '\0';
    memcpy(w, p, plen); w += plen;

    size_t b64cap = ((plainlen + 2) / 3) * 4;
    char *b64 = malloc(b64cap + 1);
    if (!b64) {
        free(plain);
        set_status(status_out, status_sz, "out of memory");
        return SMTP_ERROR;
    }
    size_t elen = 0;
    if (smtp_b64_encode(plain, plainlen, b64, b64cap + 1, &elen) != 0) {
        free(plain);
        free(b64);
        set_status(status_out, status_sz, "base64 encode failed");
        return SMTP_ERROR;
    }
    free(plain);

    /* (a) single-line form: "AUTH PLAIN " (11 bytes) + encoded + CRLF */
    size_t cmdlen = 11 + elen + 2;
    char *cmd = malloc(cmdlen + 1);
    if (!cmd) {
        free(b64);
        set_status(status_out, status_sz, "out of memory");
        return SMTP_ERROR;
    }
    memcpy(cmd, "AUTH PLAIN ", 11);
    memcpy(cmd + 11, b64, elen);
    memcpy(cmd + 11 + elen, "\r\n", 2);
    cmd[cmdlen] = '\0';

    int code = 0;
    int r = smtp_exchange(conn, tmo, cmd, &code, status_out, status_sz);
    free(cmd);
    if (r != 0) {
        free(b64);
        return SMTP_TEMPFAIL;
    }

    /* (b) two-step form: a 334 reply means the relay declined the initial
       response and wants the credential on its own line (RFC 4954 §4).  Some
       relays reject the one-line form outright and require this.  Send the
       base64 blob standalone and read the final reply; ignore any challenge
       data the 334 line carried (RFC 4616: the PLAIN response is fixed). */
    if (code == 334) {
        size_t resplen = elen + 2;
        char *resp = malloc(resplen + 1);
        if (!resp) {
            free(b64);
            set_status(status_out, status_sz, "out of memory");
            return SMTP_ERROR;
        }
        memcpy(resp, b64, elen);
        memcpy(resp + elen, "\r\n", 2);
        resp[resplen] = '\0';
        free(b64);

        r = smtp_exchange(conn, tmo, resp, &code, status_out, status_sz);
        free(resp);
        if (r != 0) return SMTP_TEMPFAIL;
        return smtp_auth_class(code);
    }

    free(b64);
    return smtp_auth_class(code);
}

/* ------------------------------------------------------------------ */
/* DATA payload                                                       */
/* ------------------------------------------------------------------ */

/* Dot-stuff the body and send it followed by the "CRLF . CRLF" terminator. */
static int smtp_send_data(SmtpConn *conn, uint32_t dtmo, const char *body,
                          size_t bodylen) {
    char *stuffed = NULL;
    size_t slen = 0;
    if (mail_stuff_dots(body, bodylen, &stuffed, &slen) != 0)
        return -1;
    int rc = smtp_write_all(conn, stuffed, slen, dtmo);
    if (rc == 0)
        rc = smtp_write_all(conn, "\r\n.\r\n", 5, dtmo);
    mail_free(stuffed);
    return rc;
}

/* ------------------------------------------------------------------ */
/* Dialogue                                                           */
/* ------------------------------------------------------------------ */

/* Exponential backoff cadence, shared by the outbound client's in-attempt
   retry loop and (S-A2) the durable-queue's across-attempt re-drive.  attempt
   is 1-based: 1s, 2s, 4s, 8s, 16s, ... doubling, then capped at 1h (3600s) so
   a multi-hour relay outage re-drives for ~3.7 days (max_attempts=100) rather
   than dropping after ~48 min.  Pure (no sleep). */
uint32_t smtp_backoff_sec(uint32_t attempt) {
    uint32_t exp = attempt - 1;
    if (exp >= 12) return 3600u;    /* cap at 1h (also guards the shift) */
    return 1u << exp;
}

static void smtp_backoff(uint32_t attempt) {
    sleep(smtp_backoff_sec(attempt));
}

static int smtp_dialogue(SmtpConn *conn, const Config *c, uint32_t tmo,
                         uint32_t dtmo, const char *body, size_t bodylen,
                         const char *mail_cmd, const char *rcpt_cmd,
                         char *status_out, size_t status_sz) {
    char text[SMTP_MAX_LINE];
    char caps[SMTP_MAX_REPLY];
    size_t caplen = 0;
    int code = 0;
    int cls;
    int starttls_cls = SMTP_ERROR;   /* STARTTLS-command refusal class (if any) */

    /* Derive the TLS mode from relay.tls (validated by the caller). */
    const char *tlsv = c->relay.tls;
    bool tls_opp    = (tlsv && strcmp(tlsv, "starttls") == 0);        /* opportunistic */
    bool tls_verify = (tlsv && strcmp(tlsv, "starttls-verify") == 0); /* mandatory TLS */
    bool want_tls = tls_opp || tls_verify;

    /* 1. greeting: expect 220 */
    if (smtp_read_reply(conn, tmo, &code, text, sizeof text) != 0) {
        set_status(status_out, status_sz, "no greeting");
        return SMTP_TEMPFAIL;
    }
    set_status(status_out, status_sz, text);
    if (code != 220)
        return (code >= 400) ? smtp_class(code) : SMTP_ERROR;

    /* 2. EHLO (capture the full multi-line capability list) */
    const char *helo = (c->hostname && *c->hostname) ? c->hostname : "localhost";
    char ehlo_cmd[SMTP_MAX_LINE];
    int n = snprintf(ehlo_cmd, sizeof ehlo_cmd, "EHLO %s\r\n", helo);
    if (n < 0 || (size_t)n >= sizeof ehlo_cmd) {
        set_status(status_out, status_sz, "EHLO name too long");
        return SMTP_ERROR;
    }
    if (smtp_write_all(conn, ehlo_cmd, strlen(ehlo_cmd), tmo) != 0) {
        set_status(status_out, status_sz, "write failed");
        return SMTP_TEMPFAIL;
    }
    if (smtp_read_reply_all(conn, tmo, &code, caps, sizeof caps, &caplen) != 0) {
        set_status(status_out, status_sz, "read failed");
        return SMTP_TEMPFAIL;
    }
    reply_first_text(caps, caplen, status_out, status_sz);
    if ((cls = smtp_class(code)) != SMTP_OK)
        return cls;

    /* 3. STARTTLS */
    bool did_tls = false;
    if (want_tls) {
        bool advertised = smtp_reply_has_cap(caps, caplen, "STARTTLS");
        if (tls_verify && !advertised) {
            /* Mandatory TLS: the relay must offer STARTTLS.  Absent -> it
               cannot satisfy the policy — permanent (never fall back to
               plaintext). */
            set_status(status_out, status_sz,
                       "relay does not advertise STARTTLS (starttls-verify)");
            return SMTP_PERMFAIL;
        }

        if (advertised) {
            /* advertised: attempt the upgrade */
            if (smtp_exchange(conn, tmo, "STARTTLS\r\n", &code, status_out,
                              status_sz) != 0)
                return SMTP_TEMPFAIL;
            if (code == 220) {
                int hr = smtp_tls_handshake(conn, c->relay.host, tls_verify,
                                            c->relay.tls_ca, tmo,
                                            status_out, status_sz);
                if (hr != 0) {
                    if (tls_verify) {
                        /* Mandatory TLS: classify the handshake failure.  A
                           certificate-verification failure is permanent — we
                           NEVER fall back to plaintext and NEVER retry a bad
                           cert; any other TLS error (timeout/EOF/transport) is
                           transient and the durable queue re-drives.  status_out
                           already carries the specific mbedTLS error.  The
                           verify_result != 0 arm is belt-and-suspenders: it
                           also catches a failed verify_init/setup (no session
                           yet -> 0xFFFFFFFF), which is a config/alloc error and
                           correctly fail-closed as PERMFAIL. */
                        if (hr == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED ||
                            hr == MBEDTLS_ERR_SSL_BAD_CERTIFICATE ||
                            hr == MBEDTLS_ERR_SSL_CA_CHAIN_REQUIRED ||
                            mbedtls_ssl_get_verify_result(&conn->ssl) != 0)
                            return SMTP_PERMFAIL;
                        return SMTP_TEMPFAIL;
                    }
                    /* opportunistic: transient — return TEMPFAIL so the durable
                       queue re-drives later (never falling through to AUTH). */
                    return SMTP_TEMPFAIL;
                }
                did_tls = true;
                /* re-EHLO over TLS (RFC 3207: server forgets EHLO state) */
                if (smtp_exchange(conn, tmo, ehlo_cmd, &code, status_out,
                                  status_sz) != 0)
                    return SMTP_TEMPFAIL;
                if ((cls = smtp_class(code)) != SMTP_OK)
                    return cls;
            } else {
                /* STARTTLS command refused.  RFC 3207: a 4xx (e.g. 454) is
                   temporary (the server may offer TLS later); a 5xx means the
                   upgrade is unavailable. */
                starttls_cls = smtp_class(code);
                if (tls_verify) {
                    /* Mandatory TLS: 4xx -> TEMPFAIL (retry), 5xx/absent ->
                       PERMFAIL. */
                    set_status(status_out, status_sz,
                               "STARTTLS refused (starttls-verify)");
                    return (starttls_cls == SMTP_TEMPFAIL) ? SMTP_TEMPFAIL
                                                           : SMTP_PERMFAIL;
                }
            }
        }

        if (!did_tls && tls_opp && c->relay.auth.enabled) {
            /* Opportunistic STARTTLS unavailable (not advertised, or command
               refused): hard rule — never send AUTH PLAIN credentials in the
               clear.  A 4xx refusal is transient (retry later); not-advertised
               or 5xx is permanent. */
            set_status(status_out, status_sz,
                       "refusing to send AUTH over plaintext");
            return (starttls_cls == SMTP_TEMPFAIL) ? SMTP_TEMPFAIL
                                                   : SMTP_PERMFAIL;
        }
        /* no auth and no TLS: opportunistic plaintext fallback */
    }

    /* 4. AUTH PLAIN (if enabled; over TLS iff we did STARTTLS) */
    if (c->relay.auth.enabled) {
        cls = smtp_auth_plain(conn, tmo, &c->relay.auth, status_out, status_sz);
        if (cls != SMTP_OK)
            return cls;
    }

    /* 5. MAIL FROM */
    if (smtp_exchange(conn, tmo, mail_cmd, &code, status_out, status_sz) != 0)
        return SMTP_TEMPFAIL;
    if ((cls = smtp_class(code)) != SMTP_OK)
        return cls;

    /* 6. RCPT TO */
    if (smtp_exchange(conn, tmo, rcpt_cmd, &code, status_out, status_sz) != 0)
        return SMTP_TEMPFAIL;
    if ((cls = smtp_class(code)) != SMTP_OK)
        return cls;

    /* 7. DATA: expect 354 */
    if (smtp_exchange(conn, tmo, "DATA\r\n", &code, status_out, status_sz) != 0)
        return SMTP_TEMPFAIL;
    if (code != 354)
        return (smtp_class(code) == SMTP_OK) ? SMTP_ERROR : smtp_class(code);

    /* 8. dot-stuffed body + terminator */
    if (smtp_send_data(conn, dtmo, body, bodylen) != 0) {
        set_status(status_out, status_sz, "data write failed");
        return SMTP_TEMPFAIL;
    }

    /* 9. final reply: 250/251 = accepted */
    if (smtp_read_reply(conn, tmo, &code, text, sizeof text) != 0) {
        set_status(status_out, status_sz, "no reply after DATA");
        return SMTP_TEMPFAIL;
    }
    set_status(status_out, status_sz, text);
    if (code != 250 && code != 251)
        return (smtp_class(code) == SMTP_OK) ? SMTP_ERROR : smtp_class(code);

    /* 10. QUIT (best-effort; do not block waiting for the 221) */
    (void)smtp_write_all(conn, "QUIT\r\n", 6, tmo);

    return SMTP_OK;
}

/* ------------------------------------------------------------------ */
/* Public entry point                                                 */
/* ------------------------------------------------------------------ */

int smtp_out_send(Store *s, const Config *c, const char *from, const char *to,
                  const char *body, size_t bodylen, char *status_out,
                  size_t status_sz) {
    (void)s;   /* reserved for delivery logging (later slices) */
    set_status(status_out, status_sz, "");

    if (!c || !from || !to || !body) {
        set_status(status_out, status_sz, "bad arguments");
        return SMTP_ERROR;
    }
    if (!c->relay.host || !*c->relay.host) {
        set_status(status_out, status_sz, "no relay host configured");
        return SMTP_ERROR;
    }
    if (smtp_tls_valid(c->relay.tls) != 0) {
        set_status(status_out, status_sz,
                   "invalid relay.tls (expected \"none\", \"starttls\", or \"starttls-verify\")");
        return SMTP_ERROR;
    }
    if (has_crlf(from) || has_crlf(to)) {
        set_status(status_out, status_sz, "invalid envelope address");
        return SMTP_ERROR;
    }
    if (!*from || !*to) {
        set_status(status_out, status_sz, "empty envelope address");
        return SMTP_ERROR;
    }

    uint32_t tmo = c->limits.cmd_timeout ? c->limits.cmd_timeout
                                         : SMTP_DEFAULT_TIMEOUT;
    uint32_t dtmo = c->limits.data_timeout ? c->limits.data_timeout : tmo;

    char mail_cmd[SMTP_MAX_LINE];
    char rcpt_cmd[SMTP_MAX_LINE];
    if (build_addr_cmd(mail_cmd, sizeof mail_cmd, "MAIL FROM:", from) != 0 ||
        build_addr_cmd(rcpt_cmd, sizeof rcpt_cmd, "RCPT TO:", to) != 0) {
        set_status(status_out, status_sz, "envelope address too long");
        return SMTP_ERROR;
    }

    uint32_t retries = c->relay.retries;
    for (uint32_t attempt = 0;; attempt++) {
        if (attempt > 0)
            smtp_backoff(attempt);

        int fd = smtp_connect(c, status_out, status_sz);
        if (fd < 0) {
            if (attempt >= retries)
                return SMTP_TEMPFAIL;
            continue;
        }

        SmtpConn conn;
        smtp_conn_init(&conn, fd);
        int rc = smtp_dialogue(&conn, c, tmo, dtmo, body, bodylen, mail_cmd,
                               rcpt_cmd, status_out, status_sz);
        smtp_conn_close(&conn, rc == SMTP_OK);

        if (rc == SMTP_OK || rc == SMTP_PERMFAIL || rc == SMTP_ERROR)
            return rc;
        /* SMTP_TEMPFAIL (4xx or transport): retry if attempts remain */
        if (attempt >= retries)
            return SMTP_TEMPFAIL;
    }
}
