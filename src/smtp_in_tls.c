/* smtp_in_tls.c — STARTTLS for the inbound SMTP listener (RFC 3207; mbedTLS
 * 3.6, SERVER role).
 *
 * All mbedTLS code for smtp_in lives here; the rest of the daemon only sees
 * the opaque Conn.tls pointer and the smtp_in_tls_* entry points declared in
 * smtp.h (config_check.c keeps compiling without any mbedtls header).
 * Parallel to imapd_tls.c with one structural delta: this module is keyed on
 * the connection fd (cast through intptr_t) instead of the Conn struct, so
 * it shares nothing with smtp_in.c's Conn — the poll loop in smtp_in.c
 * drives the handshake exactly like imapd.c does.
 *
 * smtp_in's fds are NON-BLOCKING, so the BIOs map EAGAIN/EWOULDBLOCK to
 * MBEDTLS_ERR_SSL_WANT_READ/WANT_WRITE and the poll loop drives the
 * handshake via smtp_in_tls_handshake_step, polling whichever direction the
 * last round asked for.
 *
 * Per-connection states:
 *   PENDING      the plaintext "220 Ready" reply is still draining c->out;
 *                only POLLOUT is polled.  It MUST be fully out before the
 *                handshake starts, or our plaintext bytes would interleave
 *                after the client's ClientHello.
 *   HANDSHAKE    mbedtls_ssl_handshake is driven on POLLIN/POLLOUT.
 *   ESTABLISHED  plain I/O is replaced by smtp_in_tls_recv/smtp_in_tls_send.
 * A fatal handshake drops the connection without any reply (the wire is
 * mid-TLS; plaintext would be garbage to the peer).
 *
 * Cert/key load is fail-closed: a Config.tls cert/key that fail to parse or
 * don't match make smtp_in_tls_global_init report -1 so the daemon exits;
 * absent/empty paths mean TLS is silently disabled (plaintext loopback
 * default preserved). */
#include "smtp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>

#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/pk.h>
#include <mbedtls/error.h>

/* Handshake phases (Conn.tls is non-NULL from STARTTLS acceptance on). */
enum { TLS_PENDING = 0, TLS_HANDSHAKE, TLS_ESTABLISHED };

struct SmtpTls {
    mbedtls_ssl_context ssl;
    int                 state;       /* TLS_* */
    bool                want_write;  /* last handshake round wants POLLOUT */
};

/* Process-wide state: one DRBG + one read-only server config, set up once
   by smtp_in_tls_global_init before the poll loop starts (single-threaded). */
static mbedtls_entropy_context g_entropy;
static mbedtls_ctr_drbg_context g_drbg;
static mbedtls_ssl_config g_conf;
static mbedtls_x509_crt g_crt;
static mbedtls_pk_context g_pk;
static bool g_ready;

/* ------------------------------------------------------------------ */
/* Global init (fail-closed cert/key load)                             */
/* ------------------------------------------------------------------ */

int smtp_in_tls_global_init(const char *cert, const char *key) {
    const char pers[] = "smtp_in_tls";
    int r;

    g_ready = false;
    if (!cert && !key) return 0;             /* TLS disabled */
    if (cert && !cert[0] && key && !key[0]) return 0;   /* "" "" = disabled */
    if (!cert || !key || !cert[0] || !key[0]) {
        fprintf(stderr, "visage: tls.cert and tls.key must be given together\n");
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
        r = mbedtls_x509_crt_parse_file(&g_crt, cert);
        if (r >= 0) r = 0;
    }
    if (r == 0)
        r = mbedtls_pk_parse_keyfile(&g_pk, key, NULL,
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
        fprintf(stderr, "visage: TLS setup failed: %s (cert %s, key %s)\n",
                err, cert, key);
        return -1;
    }

    g_ready = true;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Non-blocking BIOs (keyed on the conn fd, not a Conn pointer)        */
/* ------------------------------------------------------------------ */

static int bio_recv(void *ctx, unsigned char *buf, size_t len) {
    int fd = (int)(intptr_t)ctx;
    if (len == 0) return 0;
    for (;;) {
        ssize_t r = recv(fd, buf, len, 0);
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
    int fd = (int)(intptr_t)ctx;
    ssize_t r = send(fd, buf, len, MSG_NOSIGNAL);
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

SmtpTls *smtp_in_tls_start(int fd) {
    SmtpTls *t;
    if (!g_ready || fd < 0) return NULL;
    t = calloc(1, sizeof *t);
    if (!t) return NULL;
    mbedtls_ssl_init(&t->ssl);
    if (mbedtls_ssl_setup(&t->ssl, &g_conf) != 0) {
        free(t);
        return NULL;
    }
    mbedtls_ssl_set_bio(&t->ssl, (void *)(intptr_t)fd, bio_send, bio_recv, NULL);
    t->state = TLS_PENDING;
    t->want_write = false;
    return t;
}

int smtp_in_tls_handshake_step(SmtpTls *t) {
    int r;
    if (!t) return -1;
    if (t->state == TLS_PENDING)
        t->state = TLS_HANDSHAKE;   /* caller drained c->out first */
    if (t->state == TLS_ESTABLISHED) return 1;
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

int smtp_in_tls_recv(SmtpTls *t, char *buf, size_t len) {
    int r;
    if (!t || t->state != TLS_ESTABLISHED) return -1;
    r = (int)mbedtls_ssl_read(&t->ssl, (unsigned char *)buf, len);
    if (r > 0) return r;
    if (r == MBEDTLS_ERR_SSL_WANT_READ ||
        r == MBEDTLS_ERR_SSL_WANT_WRITE) return 0;
    /* 0 (EOF without alert), PEER_CLOSE_NOTIFY, or a fatal code: done. */
    return -1;
}

int smtp_in_tls_send(SmtpTls *t, const char *buf, size_t len) {
    int r;
    if (!t || len == 0) return -1;
    r = (int)mbedtls_ssl_write(&t->ssl, (const unsigned char *)buf, len);
    if (r > 0) return r;
    if (r == MBEDTLS_ERR_SSL_WANT_WRITE) return 0;
    /* WANT_READ is renegotiation-only (compiled out); treat as fatal. */
    return -1;
}

void smtp_in_tls_conn_free(SmtpTls *t) {
    if (!t) return;
    if (t->state == TLS_ESTABLISHED)
        (void)mbedtls_ssl_close_notify(&t->ssl);   /* best effort */
    mbedtls_ssl_free(&t->ssl);
    free(t);
}

/* ------------------------------------------------------------------ */
/* Predicates (consume only; no mbedtls types leak out)                */
/* ------------------------------------------------------------------ */

bool smtp_in_tls_available(void) {
    return g_ready;
}

bool smtp_in_tls_pending(const SmtpTls *t) {
    return t && t->state == TLS_PENDING;
}

bool smtp_in_tls_handshaking(const SmtpTls *t) {
    return t && t->state != TLS_ESTABLISHED;
}

bool smtp_in_tls_established(const SmtpTls *t) {
    return t && t->state == TLS_ESTABLISHED;
}

bool smtp_in_tls_wants_write(const SmtpTls *t) {
    return t && t->want_write;
}
