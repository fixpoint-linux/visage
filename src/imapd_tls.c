/* imapd_tls.c — STARTTLS for imapd (mbedTLS 3.6, SERVER role).
 *
 * All mbedTLS code for imapd lives here; the rest of the daemon only sees
 * the opaque Conn.tls pointer and the imapd_tls_* entry points declared in
 * imapd.h (imap_check.c keeps compiling without any mbedtls header).
 * Mirrors the client-side idioms of smtp_out.c with three server-side and
 * three event-loop deltas:
 *
 *   server-side: config_defaults(MBEDTLS_SSL_IS_SERVER) +
 *                x509/pk cert+key load, pk_check_pair and conf_own_cert
 *                (setup copied from tests/tls_selfcheck.c).
 *
 *   event-loop:  imapd's fds are NON-BLOCKING (smtp_out handshakes on a
 *                blocking fd), so the BIOs map EAGAIN/EWOULDBLOCK to
 *                MBEDTLS_ERR_SSL_WANT_READ/WANT_WRITE and the poll loop in
 *                imapd.c drives the handshake via imapd_tls_handshake_step,
 *                polling whichever direction the last round asked for.
 *
 * Per-connection states:
 *   PENDING      the plaintext "OK Begin TLS" / "220" reply is still
 *                draining c->out; only POLLOUT is polled.  It MUST be fully
 *                out before the handshake starts, or our plaintext bytes
 *                would interleave after the client's ClientHello.
 *   HANDSHAKE    mbedtls_ssl_handshake is driven on POLLIN/POLLOUT.
 *   ESTABLISHED  plain I/O is replaced by imapd_tls_recv/imapd_tls_send.
 * A fatal handshake drops the connection without any reply (the wire is
 * mid-TLS; plaintext would be garbage to the peer).
 *
 * Cert/key load is fail-closed: --cert/--key (or IMAPD_CERT/IMAPD_KEY) that
 * fail to parse or don't match make imapd_tls_global_init report -1 so the
 * daemon exits; absent paths mean TLS is silently disabled (plaintext
 * loopback default preserved). */
#include "imapd.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sys/socket.h>

#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/pk.h>
#include <mbedtls/error.h>

/* Handshake phases (Conn.tls is non-NULL from STARTTLS acceptance on). */
enum { TLS_PENDING = 0, TLS_HANDSHAKE, TLS_ESTABLISHED };

struct ImapdTls {
    mbedtls_ssl_context ssl;
    int                 state;       /* TLS_* */
    bool                want_write;  /* last handshake round wants POLLOUT */
};

/* Process-wide state: one DRBG + one read-only server config, set up once
   by imapd_tls_global_init before the poll loop starts (single-threaded). */
static mbedtls_entropy_context g_entropy;
static mbedtls_ctr_drbg_context g_drbg;
static mbedtls_ssl_config g_conf;
static mbedtls_x509_crt g_crt;
static mbedtls_pk_context g_pk;

/* ------------------------------------------------------------------ */
/* Global init (fail-closed cert/key load)                             */
/* ------------------------------------------------------------------ */

int imapd_tls_global_init(ImapdServer *srv) {
    const char pers[] = "imapd_tls";
    int r;

    srv->tls_ready = false;
    if (!srv->cfg.cert && !srv->cfg.key) return 0;   /* TLS disabled */
    if (!srv->cfg.cert || !srv->cfg.key) {
        fprintf(stderr, "imapd: --cert and --key must be given together\n");
        return -1;
    }

    mbedtls_entropy_init(&g_entropy);
    mbedtls_ctr_drbg_init(&g_drbg);
    mbedtls_ssl_config_init(&g_conf);
    mbedtls_x509_crt_init(&g_crt);
    mbedtls_pk_init(&g_pk);

    r = mbedtls_ctr_drbg_seed(&g_drbg, mbedtls_entropy_func, &g_entropy,
                              (const unsigned char *)pers, sizeof pers - 1);
    if (r == 0) {
        /* mbedtls_x509_crt_parse_file returns the number of parsed certs
           (>= 0) on success; only a negative code is fatal (cf. smtp_out). */
        r = mbedtls_x509_crt_parse_file(&g_crt, srv->cfg.cert);
        if (r >= 0) r = 0;
    }
    if (r == 0)
        r = mbedtls_pk_parse_keyfile(&g_pk, srv->cfg.key, NULL,
                                     mbedtls_ctr_drbg_random, &g_drbg);
    if (r == 0)
        r = mbedtls_pk_check_pair(&g_crt.pk, &g_pk,
                                  mbedtls_ctr_drbg_random, &g_drbg);
    if (r == 0)
        r = mbedtls_ssl_config_defaults(&g_conf, MBEDTLS_SSL_IS_SERVER,
                                        MBEDTLS_SSL_TRANSPORT_STREAM,
                                        MBEDTLS_SSL_PRESET_DEFAULT);
    if (r == 0) {
        mbedtls_ssl_conf_rng(&g_conf, mbedtls_ctr_drbg_random, &g_drbg);
        mbedtls_ssl_conf_authmode(&g_conf, MBEDTLS_SSL_VERIFY_NONE);
        mbedtls_ssl_conf_min_tls_version(&g_conf,
                                         MBEDTLS_SSL_VERSION_TLS1_2);
        mbedtls_ssl_conf_max_tls_version(&g_conf,
                                         MBEDTLS_SSL_VERSION_TLS1_2);
        r = mbedtls_ssl_conf_own_cert(&g_conf, &g_crt, &g_pk);
    }
    if (r != 0) {
        char err[192];
        mbedtls_strerror(r, err, sizeof err);
        fprintf(stderr, "imapd: TLS setup failed: %s (cert %s, key %s)\n",
                err, srv->cfg.cert, srv->cfg.key);
        return -1;
    }

    srv->tls_ready = true;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Non-blocking BIOs (the smtp_out ones are blocking; this is the delta)*/
/* ------------------------------------------------------------------ */

static int bio_recv(void *ctx, unsigned char *buf, size_t len) {
    Conn *c = ctx;
    if (len == 0) return 0;
    for (;;) {
        ssize_t r = recv(c->fd, buf, len, 0);
        if (r < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                return MBEDTLS_ERR_SSL_WANT_READ;
            return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
        }
        return (int)r;   /* 0 = EOF, per the mbedTLS BIO contract */
    }
}

static int bio_send(void *ctx, const unsigned char *buf, size_t len) {
    Conn *c = ctx;
    ssize_t r = send(c->fd, buf, len, MSG_NOSIGNAL);
    if (r < 0) {
        if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
            return MBEDTLS_ERR_SSL_WANT_WRITE;
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }
    if (r == 0) return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    return (int)r;
}

/* ------------------------------------------------------------------ */
/* Per-connection lifecycle                                            */
/* ------------------------------------------------------------------ */

int imapd_tls_start(ImapdServer *srv, Conn *c) {
    ImapdTls *t;
    (void)srv;   /* the process-wide config is already set up */
    t = calloc(1, sizeof *t);
    if (!t) return -1;
    mbedtls_ssl_init(&t->ssl);
    if (mbedtls_ssl_setup(&t->ssl, &g_conf) != 0) {
        free(t);
        return -1;
    }
    mbedtls_ssl_set_bio(&t->ssl, c, bio_send, bio_recv, NULL);
    t->state = TLS_PENDING;
    t->want_write = false;
    c->tls = t;
    return 0;
}

int imapd_tls_handshake_step(Conn *c, time_t now) {
    ImapdTls *t = c->tls;
    int r;
    if (!t) return -1;
    if (t->state == TLS_PENDING)
        t->state = TLS_HANDSHAKE;   /* caller drained c->out first */
    if (t->state == TLS_ESTABLISHED) return 1;
    c->last_act = now;              /* handshake traffic counts as activity */
    r = (int)mbedtls_ssl_handshake(&t->ssl);
    if (r == 0) {
        t->state = TLS_ESTABLISHED;
        return 1;
    }
    if (r == MBEDTLS_ERR_SSL_WANT_READ) {
        t->want_write = false;
        return 0;
    }
    if (r == MBEDTLS_ERR_SSL_WANT_WRITE) {
        t->want_write = true;
        return 0;
    }
    return -1;   /* fatal: drop the conn, never reply in clear */
}

int imapd_tls_recv(Conn *c, char *buf, size_t len) {
    ImapdTls *t = c->tls;
    int r;
    if (!t || t->state != TLS_ESTABLISHED) return -1;
    r = (int)mbedtls_ssl_read(&t->ssl, (unsigned char *)buf, len);
    if (r > 0) return r;
    if (r == MBEDTLS_ERR_SSL_WANT_READ ||
        r == MBEDTLS_ERR_SSL_WANT_WRITE) return 0;
    /* 0 (EOF without alert), PEER_CLOSE_NOTIFY, or a fatal code: done. */
    return -1;
}

int imapd_tls_send(Conn *c, const char *buf, size_t len) {
    ImapdTls *t = c->tls;
    int r;
    if (!t || len == 0) return -1;
    r = (int)mbedtls_ssl_write(&t->ssl, (const unsigned char *)buf, len);
    if (r > 0) return r;
    if (r == MBEDTLS_ERR_SSL_WANT_WRITE) return 0;
    /* WANT_READ is renegotiation-only (compiled out); treat as fatal. */
    return -1;
}

void imapd_tls_conn_free(Conn *c) {
    ImapdTls *t = c->tls;
    if (!t) return;
    c->tls = NULL;
    if (t->state == TLS_ESTABLISHED)
        (void)mbedtls_ssl_close_notify(&t->ssl);   /* best effort */
    mbedtls_ssl_free(&t->ssl);
    free(t);
}

/* ------------------------------------------------------------------ */
/* Predicates (consume only; no mbedtls types leak out)                */
/* ------------------------------------------------------------------ */

bool imapd_tls_available(const ImapdServer *srv) {
    return srv->tls_ready;
}

bool imapd_tls_pending(const Conn *c) {
    const ImapdTls *t = c->tls;
    return t && t->state == TLS_PENDING;
}

bool imapd_tls_handshaking(const Conn *c) {
    const ImapdTls *t = c->tls;
    return t && t->state != TLS_ESTABLISHED;
}

bool imapd_tls_established(const Conn *c) {
    const ImapdTls *t = c->tls;
    return t && t->state == TLS_ESTABLISHED;
}

bool imapd_tls_wants_write(const Conn *c) {
    const ImapdTls *t = c->tls;
    return t && t->want_write;
}
