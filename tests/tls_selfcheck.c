/* tls_selfcheck.c — in-process mbedTLS 3.6.7 smoke test (slice S-B1).
 *
 * NO sockets: the client and server are wired back-to-back through memory
 * BIOs. This exercises everything a blocked live STARTTLS handshake would,
 * minus the socket syscalls: /dev/urandom entropy, CTR_DRBG, bignum
 * (__int128 ECDHE), AES-GCM, ECDHE-RSA, x509/PEM parse, and the TLS 1.2
 * record layer.
 *
 * The BIO callbacks use the NON-BLOCKING WANT_READ/WANT_WRITE contract (an
 * empty read buffer is "no data yet", NOT EOF). The production outbound
 * relay path (S-B2) uses the OTHER contract — blocking poll-bounded
 * callbacks returning MBEDTLS_ERR_SSL_TIMEOUT — the two are both valid per
 * mbedtls_ssl_set_bio() and must not be mixed.
 *
 * Asserts: version string == "Mbed TLS 3.6.7", TLS 1.2 handshake completes,
 * negotiated ciphersuite is an ECDHE-RSA AES-GCM one, peer cert CN ==
 * "localhost", a 64 KiB payload round-trips in both directions, and both
 * sides close with a clean close_notify. Prints "tls_selfcheck: OK" and
 * returns 0 iff every assertion passes.
 */
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/version.h"
#include "mbedtls/error.h"
#include "mbedtls/x509.h"
#include "mbedtls/x509_crt.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PAYLOAD_LEN   (64 * 1024)   /* round-trip size (exercises 4+ records) */
#define CHUNK_LEN     8192          /* cap per write so the 64KiB channel      */
                                    /* drains as it fills (no overflow)        */

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
    fprintf(stderr, "tls_selfcheck: FAIL %s (-0x%04x: %s)\n", what, -ret, buf);
    exit(1);
}

/* Drive one SSL op to completion, giving the other side a turn whenever the
 * op reports it would block. The sender/receiver share the channel pair
 * already wired via mbedtls_ssl_set_bio(); we just alternate the two ends
 * until `n` bytes have been written by `sender` and read back by `receiver`. */
static void pump_data(mbedtls_ssl_context *sender, mbedtls_ssl_context *receiver,
                      const unsigned char *send, unsigned char *recv, size_t n,
                      const char *what) {
    size_t sent = 0, got = 0;
    unsigned int guard = 0;
    while (sent < n || got < n) {
        int progressed = 0;
        if (sent < n) {
            size_t chunk = n - sent;
            int r;
            if (chunk > CHUNK_LEN) {
                chunk = CHUNK_LEN;
            }
            r = mbedtls_ssl_write(sender, send + sent, chunk);
            if (r > 0) {
                sent += (size_t) r;
                progressed = 1;
            } else if (r != MBEDTLS_ERR_SSL_WANT_READ &&
                       r != MBEDTLS_ERR_SSL_WANT_WRITE) {
                die(what, r);
            }
        }
        if (got < n) {
            int r = mbedtls_ssl_read(receiver, recv + got, n - got);
            if (r > 0) {
                got += (size_t) r;
                progressed = 1;
            } else if (r != MBEDTLS_ERR_SSL_WANT_READ &&
                       r != MBEDTLS_ERR_SSL_WANT_WRITE) {
                die(what, r);
            }
        }
        if (!progressed && ++guard > 100000) {
            fprintf(stderr, "tls_selfcheck: FAIL %s (no progress)\n", what);
            exit(1);
        }
    }
    if (memcmp(send, recv, n) != 0) {
        fprintf(stderr, "tls_selfcheck: FAIL %s (data corrupted)\n", what);
        exit(1);
    }
}

int main(void) {
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context drbg;
    mbedtls_ssl_config srv_conf, cli_conf;
    mbedtls_ssl_context srv, cli;
    mbedtls_x509_crt srv_cert;
    mbedtls_pk_context srv_key;
    Chan c2s, s2c;
    BioCtx bc, bs;
    const mbedtls_x509_crt *peer;
    const char *suite, *version;
    unsigned char send1[PAYLOAD_LEN], send2[PAYLOAD_LEN];
    unsigned char recv1[PAYLOAD_LEN], recv2[PAYLOAD_LEN];
    char dn[512];
    int ret, cli_done = 0, srv_done = 0, got_close;
    unsigned int guard = 0;
    size_t i;
    unsigned char byte;

    /* 1. Pin the vendored version. */
    if (strcmp(MBEDTLS_VERSION_STRING_FULL, "Mbed TLS 3.6.7") != 0) {
        fprintf(stderr, "tls_selfcheck: FAIL version string '%s'\n",
                MBEDTLS_VERSION_STRING_FULL);
        return 1;
    }

    /* 2. One DRBG, seeded from the platform entropy source (/dev/urandom). */
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&drbg);
    {
        const char *pers = "visage_tls_selfcheck";
        ret = mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &entropy,
                                    (const unsigned char *) pers, strlen(pers));
        if (ret != 0) {
            die("ctr_drbg_seed", ret);
        }
    }

    /* 3. Load the test server cert + (unencrypted) key. */
    mbedtls_x509_crt_init(&srv_cert);
    mbedtls_pk_init(&srv_key);
    ret = mbedtls_x509_crt_parse_file(&srv_cert,
                                      "tests/visage-test-cert.pem");
    if (ret != 0) {
        die("x509_crt_parse_file(cert)", ret);
    }
    ret = mbedtls_pk_parse_keyfile(&srv_key, "tests/visage-test-key.pem", NULL,
                                   mbedtls_ctr_drbg_random, &drbg);
    if (ret != 0) {
        die("pk_parse_keyfile(key)", ret);
    }

    /* 4. Server config: TLS 1.2, stream, VERIFY_NONE, own cert chain. */
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
    ret = mbedtls_ssl_conf_own_cert(&srv_conf, &srv_cert, &srv_key);
    if (ret != 0) {
        die("conf_own_cert(server)", ret);
    }

    /* 5. Client config: TLS 1.2, stream, VERIFY_NONE (matches 'starttls'). */
    mbedtls_ssl_config_init(&cli_conf);
    ret = mbedtls_ssl_config_defaults(&cli_conf, MBEDTLS_SSL_IS_CLIENT,
                                      MBEDTLS_SSL_TRANSPORT_STREAM,
                                      MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0) {
        die("config_defaults(client)", ret);
    }
    mbedtls_ssl_conf_rng(&cli_conf, mbedtls_ctr_drbg_random, &drbg);
    mbedtls_ssl_conf_authmode(&cli_conf, MBEDTLS_SSL_VERIFY_NONE);
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
    ret = mbedtls_ssl_set_hostname(&cli, "localhost");   /* exercise SNI    */
    if (ret != 0) {
        die("set_hostname(client)", ret);
    }

    /* 6. Wire the two ends back-to-back through the memory channels. */
    memset(&c2s, 0, sizeof c2s);
    memset(&s2c, 0, sizeof s2c);
    bc.out = &c2s;  bc.in = &s2c;      /* client writes c2s, reads s2c       */
    bs.out = &s2c;  bs.in = &c2s;      /* server writes s2c, reads c2s       */
    mbedtls_ssl_set_bio(&cli, &bc, bio_send, bio_recv, NULL);
    mbedtls_ssl_set_bio(&srv, &bs, bio_send, bio_recv, NULL);

    /* 7. Drive the handshake, alternating ends until both complete. */
    while (!cli_done || !srv_done) {
        if (!cli_done) {
            ret = mbedtls_ssl_handshake(&cli);
            if (ret == 0) {
                cli_done = 1;
            } else if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
                       ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
                die("handshake(client)", ret);
            }
        }
        if (!srv_done) {
            ret = mbedtls_ssl_handshake(&srv);
            if (ret == 0) {
                srv_done = 1;
            } else if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
                       ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
                die("handshake(server)", ret);
            }
        }
        if (++guard > 100000) {
            fprintf(stderr, "tls_selfcheck: FAIL handshake (no progress)\n");
            return 1;
        }
    }

    /* 8. Assert negotiated protocol version + ciphersuite. */
    if (mbedtls_ssl_get_version_number(&cli) != MBEDTLS_SSL_VERSION_TLS1_2) {
        fprintf(stderr, "tls_selfcheck: FAIL negotiated version != TLS1.2\n");
        return 1;
    }
    version = mbedtls_ssl_get_version(&cli);
    suite = mbedtls_ssl_get_ciphersuite(&cli);
    if (strcmp(version, "TLSv1.2") != 0) {
        fprintf(stderr, "tls_selfcheck: FAIL version string '%s'\n", version);
        return 1;
    }
    if (strstr(suite, "ECDHE-RSA") == NULL || strstr(suite, "GCM") == NULL) {
        fprintf(stderr, "tls_selfcheck: FAIL ciphersuite '%s'\n", suite);
        return 1;
    }
    printf("ok   version %s, ciphersuite %s\n", version, suite);

    /* 9. Assert the peer certificate CN (requires KEEP_PEER_CERTIFICATE). */
    peer = mbedtls_ssl_get_peer_cert(&cli);
    if (peer == NULL) {
        fprintf(stderr, "tls_selfcheck: FAIL peer certificate not retained\n");
        return 1;
    }
    if (mbedtls_x509_dn_gets(dn, sizeof dn, &peer->subject) < 0) {
        fprintf(stderr, "tls_selfcheck: FAIL dn_gets(subject)\n");
        return 1;
    }
    if (strstr(dn, "CN=localhost") == NULL) {
        fprintf(stderr, "tls_selfcheck: FAIL peer CN (subject '%s')\n", dn);
        return 1;
    }
    printf("ok   peer cert subject %s\n", dn);

    /* 10. 64 KiB round-trip, both directions. */
    for (i = 0; i < PAYLOAD_LEN; i++) {
        send1[i] = (unsigned char) (i * 7 + 1);
        send2[i] = (unsigned char) (i * 13 + 3);
    }
    pump_data(&cli, &srv, send1, recv1, PAYLOAD_LEN, "client->server 64KiB");
    printf("ok   client->server 64KiB round-trip\n");
    pump_data(&srv, &cli, send2, recv2, PAYLOAD_LEN, "server->client 64KiB");
    printf("ok   server->client 64KiB round-trip\n");

    /* 11. Clean close_notify both ways. */
    ret = mbedtls_ssl_close_notify(&cli);
    if (ret != 0) {
        die("close_notify(client)", ret);
    }
    got_close = mbedtls_ssl_read(&srv, &byte, 1);
    if (got_close != MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
        fprintf(stderr, "tls_selfcheck: FAIL server close_notify read (-0x%04x)\n",
                -got_close);
        return 1;
    }
    ret = mbedtls_ssl_close_notify(&srv);
    if (ret != 0) {
        die("close_notify(server)", ret);
    }
    got_close = mbedtls_ssl_read(&cli, &byte, 1);
    if (got_close != MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
        fprintf(stderr, "tls_selfcheck: FAIL client close_notify read (-0x%04x)\n",
                -got_close);
        return 1;
    }
    printf("ok   clean close_notify both directions\n");

    /* teardown */
    mbedtls_ssl_free(&cli);
    mbedtls_ssl_free(&srv);
    mbedtls_ssl_config_free(&cli_conf);
    mbedtls_ssl_config_free(&srv_conf);
    mbedtls_pk_free(&srv_key);
    mbedtls_x509_crt_free(&srv_cert);
    mbedtls_ctr_drbg_free(&drbg);
    mbedtls_entropy_free(&entropy);

    printf("tls_selfcheck: OK\n");
    return 0;
}
