/* verify_selfcheck.c — mbedTLS 3.6.7 VERIFY_REQUIRED + CA chain + hostname gate.
 *
 * In-sandbox regression gate for S-B4 'starttls-verify'. NO sockets: the
 * client and server are wired back-to-back through memory BIOs using the
 * NON-BLOCKING WANT_READ/WANT_WRITE contract (an empty read buffer is "no
 * data yet", NOT EOF), exactly like tests/tls_selfcheck.c.
 *
 * Unlike tls_selfcheck.c (which uses VERIFY_NONE to mirror 'starttls'), this
 * gate exercises the VERIFY_REQUIRED path: the client is configured with a
 * trusted CA chain via mbedtls_ssl_conf_ca_chain + mbedtls_ssl_set_hostname,
 * and asserts three cases:
 *   1. good CA (verify-ca.pem) + matching hostname  -> handshake succeeds
 *   2. hostname mismatch                            -> MBEDTLS_ERR_X509_CERT_VERIFY_FAILED
 *                                                       + MBEDTLS_X509_BADCERT_CN_MISMATCH
 *   3. wrong CA (verify-wrongca.pem)                -> MBEDTLS_ERR_X509_CERT_VERIFY_FAILED
 *                                                       + MBEDTLS_X509_BADCERT_NOT_TRUSTED
 *
 * Cert paths are relative to the repo root (run as `cd $ROOT &&
 * ./tests/verify_selfcheck.com`), matching tls_selfcheck.com's convention.
 * Prints "verify_selfcheck: OK" and returns 0 iff every assertion passes.
 */
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/version.h"
#include "mbedtls/error.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/pk.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- memory BIO channel ------------------------------------------------ */

typedef struct {
    unsigned char b[1 << 16];       /* 64 KiB full-duplex pipe                */
    size_t len;                     /* bytes currently buffered               */
    size_t off;                     /* read cursor                            */
} Chan;

typedef struct {
    Chan *out;                      /* where I write                          */
    Chan *in;                       /* where I read                           */
} BioCtx;

static int bio_send(void *v, const unsigned char *p, size_t n) {
    BioCtx *c = v;
    if (c->out->off == c->out->len) {
        c->out->off = c->out->len = 0;   /* peer drained us: reuse the pipe */
    }
    if (c->out->len + n > sizeof c->out->b) {
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;  /* would overflow the pipe   */
    }
    memcpy(c->out->b + c->out->len, p, n);
    c->out->len += n;
    return (int) n;
}

static int bio_recv(void *v, unsigned char *p, size_t n) {
    BioCtx *c = v;
    size_t k;
    if (c->in->off == c->in->len) {
        c->in->off = c->in->len = 0;     /* drained: reclaim buffered bytes  */
        return MBEDTLS_ERR_SSL_WANT_READ;         /* empty != EOF            */
    }
    k = c->in->len - c->in->off;
    if (k > n) {
        k = n;
    }
    memcpy(p, c->in->b + c->in->off, k);
    c->in->off += k;
    if (c->in->off == c->in->len) {
        c->in->off = c->in->len = 0;     /* drained: reclaim buffered bytes  */
    }
    return (int) k;
}

/* ---- reporting ---------------------------------------------------------- */

static void die(const char *what, int ret) {
    char buf[160];
    mbedtls_strerror(ret, buf, sizeof buf);
    fprintf(stderr, "verify_selfcheck: FAIL %s (-0x%04x: %s)\n", what, -ret, buf);
    exit(1);
}

/* Run one full client<->server handshake. The client uses VERIFY_REQUIRED with
 * `ca_cert` as its trusted CA chain and `hostname` as the SNI/hostname check
 * target; the server presents `srv_cert`/`srv_key`. Returns the CLIENT
 * handshake code (0 on success) and stores the client's verify_result in
 * *vrfy. When the client fails verification it returns a negative code but the
 * server is still driven to completion so its fatal alert can be read (the two
 * ends share the channel pair; neither must deadlock). */
static int run_handshake(const char *srv_cert, const char *srv_key, const char *ca_cert,
                         const char *hostname, uint32_t *vrfy) {
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context drbg;
    mbedtls_ssl_config srv_conf, cli_conf;
    mbedtls_ssl_context srv, cli;
    mbedtls_x509_crt srv_crt, ca_crt;
    mbedtls_pk_context srv_pk;
    Chan c2s, s2c;
    BioCtx bc, bs;
    int ret, cli_done = 0, srv_done = 0, cli_ret = 0;
    unsigned int guard = 0;

    /* 1. One DRBG, seeded from the platform entropy source (/dev/urandom). */
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&drbg);
    {
        const char *pers = "visage_verify_selfcheck";
        ret = mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &entropy,
                                    (const unsigned char *) pers, strlen(pers));
        if (ret != 0) {
            die("ctr_drbg_seed", ret);
        }
    }

    /* 2. Load the server cert + (unencrypted) key + the trusted CA chain. */
    mbedtls_x509_crt_init(&srv_crt);
    mbedtls_pk_init(&srv_pk);
    ret = mbedtls_x509_crt_parse_file(&srv_crt, srv_cert);
    if (ret != 0) {
        die("x509_crt_parse_file(cert)", ret);
    }
    ret = mbedtls_pk_parse_keyfile(&srv_pk, srv_key, NULL, mbedtls_ctr_drbg_random, &drbg);
    if (ret != 0) {
        die("pk_parse_keyfile(key)", ret);
    }
    mbedtls_x509_crt_init(&ca_crt);
    ret = mbedtls_x509_crt_parse_file(&ca_crt, ca_cert);
    if (ret != 0) {
        die("x509_crt_parse_file(ca)", ret);
    }

    /* 3. Server config: TLS 1.2, stream, VERIFY_NONE, own cert chain. */
    mbedtls_ssl_config_init(&srv_conf);
    ret = mbedtls_ssl_config_defaults(&srv_conf, MBEDTLS_SSL_IS_SERVER,
                                      MBEDTLS_SSL_TRANSPORT_STREAM,
                                      MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0) {
        die("config_defaults(server)", ret);
    }
    mbedtls_ssl_conf_rng(&srv_conf, mbedtls_ctr_drbg_random, &drbg);
    mbedtls_ssl_conf_authmode(&srv_conf, MBEDTLS_SSL_VERIFY_NONE);
    mbedtls_ssl_conf_min_tls_version(&srv_conf, MBEDTLS_SSL_VERSION_TLS1_2);
    mbedtls_ssl_conf_max_tls_version(&srv_conf, MBEDTLS_SSL_VERSION_TLS1_2);
    ret = mbedtls_ssl_conf_own_cert(&srv_conf, &srv_crt, &srv_pk);
    if (ret != 0) {
        die("conf_own_cert(server)", ret);
    }

    /* 4. Client config: TLS 1.2, stream, VERIFY_REQUIRED + CA chain + hostname. */
    mbedtls_ssl_config_init(&cli_conf);
    ret = mbedtls_ssl_config_defaults(&cli_conf, MBEDTLS_SSL_IS_CLIENT,
                                      MBEDTLS_SSL_TRANSPORT_STREAM,
                                      MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0) {
        die("config_defaults(client)", ret);
    }
    mbedtls_ssl_conf_rng(&cli_conf, mbedtls_ctr_drbg_random, &drbg);
    mbedtls_ssl_conf_authmode(&cli_conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_ca_chain(&cli_conf, &ca_crt, NULL);
    mbedtls_ssl_conf_min_tls_version(&cli_conf, MBEDTLS_SSL_VERSION_TLS1_2);
    mbedtls_ssl_conf_max_tls_version(&cli_conf, MBEDTLS_SSL_VERSION_TLS1_2);

    mbedtls_ssl_init(&srv);
    mbedtls_ssl_init(&cli);
    ret = mbedtls_ssl_setup(&srv, &srv_conf);
    if (ret != 0) {
        die("setup(server)", ret);
    }
    ret = mbedtls_ssl_setup(&cli, &cli_conf);
    if (ret != 0) {
        die("setup(client)", ret);
    }
    ret = mbedtls_ssl_set_hostname(&cli, hostname);   /* SNI + hostname check */
    if (ret != 0) {
        die("set_hostname(client)", ret);
    }

    /* 5. Wire the two ends back-to-back through the memory channels. */
    memset(&c2s, 0, sizeof c2s);
    memset(&s2c, 0, sizeof s2c);
    bc.out = &c2s;  bc.in = &s2c;      /* client writes c2s, reads s2c       */
    bs.out = &s2c;  bs.in = &c2s;      /* server writes s2c, reads c2s       */
    mbedtls_ssl_set_bio(&cli, &bc, bio_send, bio_recv, NULL);
    mbedtls_ssl_set_bio(&srv, &bs, bio_send, bio_recv, NULL);

    /* 6. Drive the handshake, alternating ends until both complete. A client
     * verification failure is captured (not fatal here) so the alert can reach
     * the server; the server is driven to its own completion either way. */
    while (!cli_done || !srv_done) {
        if (!cli_done) {
            ret = mbedtls_ssl_handshake(&cli);
            if (ret == 0) {
                cli_done = 1;
            } else if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
                       ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
                cli_ret = ret;      /* e.g. CERT_VERIFY_FAILED: record it     */
                cli_done = 1;
            }
        }
        if (!srv_done) {
            ret = mbedtls_ssl_handshake(&srv);
            if (ret == 0) {
                srv_done = 1;
            } else if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
                       ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
                srv_done = 1;       /* server saw the client's alert: done    */
            }
        }
        if (++guard > 100000) {
            fprintf(stderr, "verify_selfcheck: FAIL handshake (no progress)\n");
            exit(1);
        }
    }

    *vrfy = mbedtls_ssl_get_verify_result(&cli);

    /* teardown */
    mbedtls_ssl_free(&cli);
    mbedtls_ssl_free(&srv);
    mbedtls_ssl_config_free(&cli_conf);
    mbedtls_ssl_config_free(&srv_conf);
    mbedtls_x509_crt_free(&ca_crt);
    mbedtls_pk_free(&srv_pk);
    mbedtls_x509_crt_free(&srv_crt);
    mbedtls_ctr_drbg_free(&drbg);
    mbedtls_entropy_free(&entropy);

    return cli_ret;
}

int main(void) {
    uint32_t vrfy;
    int ret;

    /* 1. Good CA + matching hostname -> handshake succeeds, no verify flags. */
    ret = run_handshake("tests/verify-relay.pem", "tests/verify-relay.key",
                        "tests/verify-ca.pem", "localhost", &vrfy);
    if (ret != 0) {
        die("good-CA handshake", ret);
    }
    if (vrfy != 0) {
        fprintf(stderr, "verify_selfcheck: FAIL good-CA verify_result=0x%08lx\n",
                (unsigned long) vrfy);
        return 1;
    }
    printf("ok   good CA + matching hostname accepted\n");

    /* 2. Good CA but hostname mismatch -> VERIFY_FAILED + CN_MISMATCH. */
    ret = run_handshake("tests/verify-relay.pem", "tests/verify-relay.key",
                        "tests/verify-ca.pem", "wrong.example", &vrfy);
    if (ret != MBEDTLS_ERR_X509_CERT_VERIFY_FAILED) {
        die("hostname-mismatch handshake", ret);
    }
    if ((vrfy & MBEDTLS_X509_BADCERT_CN_MISMATCH) == 0) {
        fprintf(stderr, "verify_selfcheck: FAIL CN_MISMATCH flag absent (verify_result=0x%08lx)\n",
                (unsigned long) vrfy);
        return 1;
    }
    printf("ok   hostname mismatch rejected (CN_MISMATCH)\n");

    /* 3. Wrong CA (unrelated signer) -> VERIFY_FAILED + NOT_TRUSTED. */
    ret = run_handshake("tests/verify-relay.pem", "tests/verify-relay.key",
                        "tests/verify-wrongca.pem", "localhost", &vrfy);
    if (ret != MBEDTLS_ERR_X509_CERT_VERIFY_FAILED) {
        die("wrong-CA handshake", ret);
    }
    if ((vrfy & MBEDTLS_X509_BADCERT_NOT_TRUSTED) == 0) {
        fprintf(stderr, "verify_selfcheck: FAIL NOT_TRUSTED flag absent (verify_result=0x%08lx)\n",
                (unsigned long) vrfy);
        return 1;
    }
    printf("ok   wrong CA rejected (NOT_TRUSTED)\n");

    /* 4. Embedded Mozilla bundle parses in-memory (the smtp_out.c default
     *    trust-anchor path when relay.tls_ca == "").  Guards the
     *    mbedtls_x509_crt_parse buflen-must-include-the-NUL requirement:
     *    passing visage_cacert_pem_len (without +1) DER-misdetects the buffer
     *    and returns MBEDTLS_ERR_X509_INVALID_FORMAT. */
    {
        extern const char visage_cacert_pem[];
        extern const size_t visage_cacert_pem_len;
        mbedtls_x509_crt chain;
        int count = 0;
        mbedtls_x509_crt_init(&chain);
        ret = mbedtls_x509_crt_parse(&chain,
                                     (const unsigned char *) visage_cacert_pem,
                                     visage_cacert_pem_len + 1);
        for (const mbedtls_x509_crt *c = &chain; c; c = c->next) {
            if (c->raw.len > 0) {
                count++;
            }
        }
        mbedtls_x509_crt_free(&chain);
        if (ret < 0 || count < 100) {
            fprintf(stderr, "verify_selfcheck: FAIL embedded bundle parse "
                            "(ret=%d count=%d; expected ret>=0, >=100 certs)\n",
                    ret, count);
            return 1;
        }
        printf("ok   embedded Mozilla bundle parses (%d CA certs)\n", count);
    }

    printf("verify_selfcheck: OK\n");
    return 0;
}
