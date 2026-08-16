/* relay_fake.c — recording SMTP server for the visage S8 e2e harness.
 *
 * No external dependencies; pure POSIX sockets.  Listens on 127.0.0.1:PORT and
 * serves inbound SMTP submissions serially (one connection at a time) as the
 * fake outbound relay that the visage daemon forwards to.  For every accepted
 * connection it records the full client dialogue verbatim to
 * OUTDIR/dialogue-<seq>.txt and the de-dot-stuffed message body to
 * OUTDIR/msg-<seq>.eml, then replies with the standard SMTP codes
 * (220/250/354/250/221).  The sequence number increments per connection.
 *
 * The loop keeps accepting connections until terminated (SIGTERM/SIGINT) so a
 * single run can record the forward message and the reply round-trip.
 *
 * Usage:  relay_fake PORT OUTDIR [--tls]
 *
 * With `--tls` the accepted socket's reads/writes are wrapped in an mbedTLS
 * 1.2 SERVER session (the same vendored library the daemon links) using the
 * test cert/key (tests/visage-test-cert.pem / visage-test-key.pem).  In TLS
 * mode the EHLO reply advertises STARTTLS and, once the client issues the
 * STARTTLS command, a handshake is performed and the recorded dialogue + body
 * are the DECRYPTED SMTP traffic.  The fake only ever records traffic it can
 * read: if the client fails to actually upgrade, the mbedTLS reads fail on the
 * plaintext bytes and nothing readable is recorded — so a non-empty, readable
 * msg-<seq>.eml + dialogue-<seq>.txt is itself proof TLS was used.
 *
 * Exit codes: 0 normal exit; 1 bind/setup/TLS-init failure; 2 usage error. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>

#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/pk.h"
#include "mbedtls/error.h"

#define IO_TIMEOUT_MS 15000  /* per read/write timeout                    */
#define MAX_LINE      4096   /* max one SMTP command line                 */
#define GROW_STEP     8192   /* body buffer growth step                   */

/* A relay connection: the fd plus optional in-place TLS state.  `tls` is false
   until the STARTTLS handshake completes; the I/O primitives below dispatch on
   it (read/send vs mbedtls_ssl_read/mbedtls_ssl_write). */
typedef struct {
    int  fd;
    bool tls;
    mbedtls_ssl_context ssl;   /* in-place storage (init'd in conn_new)   */
} Conn;

static int wait_fd(int fd, short events, int timeout_ms) {
    struct pollfd p;
    p.fd = fd;
    p.events = events;
    p.revents = 0;
    for (;;) {
        int r = poll(&p, 1, timeout_ms);
        if (r > 0) return 0;
        if (r == 0) return -1;              /* timed out */
        if (errno == EINTR) continue;
        return -1;
    }
}

/* --- TLS (server role, only active when --tls) -------------------------- */

/* Shared, lazily-initialised server TLS state.  The cert/key/ssl_config must
   outlive every connection (mbedtls_ssl_setup references the config, and
   conf_own_cert references the cert/key), so they are globals — the same
   pattern the daemon's outbound path uses.  Initialised once; a failure is
   sticky (later connections reuse the error). */
static mbedtls_x509_crt        g_cert;
static mbedtls_pk_context      g_key;
static mbedtls_entropy_context g_entropy;
static mbedtls_ctr_drbg_context g_drbg;
static mbedtls_ssl_config      g_ssl_conf;
static bool g_tls_ready = false;
static int  g_tls_status = 0;

#define TEST_CERT_PATH "tests/visage-test-cert.pem"
#define TEST_KEY_PATH  "tests/visage-test-key.pem"

static int tls_server_init(void) {
    if (g_tls_ready) return g_tls_status;
    int r = 0;
    mbedtls_x509_crt_init(&g_cert);
    mbedtls_pk_init(&g_key);
    mbedtls_entropy_init(&g_entropy);
    mbedtls_ctr_drbg_init(&g_drbg);
    mbedtls_ssl_config_init(&g_ssl_conf);

    r = mbedtls_x509_crt_parse_file(&g_cert, TEST_CERT_PATH);
    if (r) goto fail;
    {
        const char *pers = "relay_fake";
        r = mbedtls_ctr_drbg_seed(&g_drbg, mbedtls_entropy_func, &g_entropy,
                                  (const unsigned char *) pers, strlen(pers));
        if (r) goto fail;
    }
    r = mbedtls_pk_parse_keyfile(&g_key, TEST_KEY_PATH, NULL,
                                 mbedtls_ctr_drbg_random, &g_drbg);
    if (r) goto fail;
    r = mbedtls_ssl_config_defaults(&g_ssl_conf, MBEDTLS_SSL_IS_SERVER,
                                    MBEDTLS_SSL_TRANSPORT_STREAM,
                                    MBEDTLS_SSL_PRESET_DEFAULT);
    if (r) goto fail;
    mbedtls_ssl_conf_rng(&g_ssl_conf, mbedtls_ctr_drbg_random, &g_drbg);
    mbedtls_ssl_conf_authmode(&g_ssl_conf, MBEDTLS_SSL_VERIFY_NONE);
    mbedtls_ssl_conf_min_tls_version(&g_ssl_conf, MBEDTLS_SSL_VERSION_TLS1_2);
    mbedtls_ssl_conf_max_tls_version(&g_ssl_conf, MBEDTLS_SSL_VERSION_TLS1_2);
    r = mbedtls_ssl_conf_own_cert(&g_ssl_conf, &g_cert, &g_key);
    if (r) goto fail;
    g_tls_status = 0;
    g_tls_ready = true;
    return 0;
fail:
    g_tls_status = r;
    g_tls_ready = true;   /* do not re-init on subsequent connections */
    fprintf(stderr, "relay_fake: tls init failed -0x%04x\n", -r);
    return r;
}

/* Blocking poll-bounded BIO callbacks (the S-B2 production contract): wait
   for readability/writability then recv/send.  On poll timeout return
   MBEDTLS_ERR_SSL_TIMEOUT so mbedTLS propagates it out of read/write. */
static int bio_recv(void *v, unsigned char *buf, size_t len) {
    Conn *c = v;
    if (wait_fd(c->fd, POLLIN, IO_TIMEOUT_MS) != 0)
        return MBEDTLS_ERR_SSL_TIMEOUT;
    for (;;) {
        ssize_t n = recv(c->fd, buf, len, 0);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
        if (n == 0) return 0;            /* EOF per mbedTLS contract */
        return (int) n;
    }
}

static int bio_send(void *v, const unsigned char *buf, size_t len) {
    Conn *c = v;
    if (wait_fd(c->fd, POLLOUT, IO_TIMEOUT_MS) != 0)
        return MBEDTLS_ERR_SSL_TIMEOUT;
    for (;;) {
        ssize_t n = send(c->fd, buf, len, MSG_NOSIGNAL);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
        return (int) n;
    }
}

/* Perform the server TLS handshake over c->fd.  On success c->tls is set and
   all subsequent I/O on c is encrypted.  Returns 0 on success, -1 otherwise. */
static int tls_server_handshake(Conn *c) {
    if (tls_server_init() != 0) return -1;
    int r = mbedtls_ssl_setup(&c->ssl, &g_ssl_conf);
    if (r != 0) {
        fprintf(stderr, "relay_fake: ssl_setup failed -0x%04x\n", -r);
        return -1;
    }
    mbedtls_ssl_set_bio(&c->ssl, c, bio_send, bio_recv, NULL);
    r = mbedtls_ssl_handshake(&c->ssl);
    if (r != 0) {
        fprintf(stderr, "relay_fake: handshake failed -0x%04x\n", -r);
        return -1;
    }
    c->tls = true;
    return 0;
}

/* --- I/O dispatch (plaintext vs TLS) ------------------------------------ */

static Conn *conn_new(int fd) {
    Conn *c = calloc(1, sizeof *c);
    if (!c) return NULL;
    c->fd = fd;
    c->tls = false;
    mbedtls_ssl_init(&c->ssl);
    return c;
}

static void conn_free(Conn *c) {
    if (!c) return;
    if (c->tls) (void)mbedtls_ssl_close_notify(&c->ssl);
    mbedtls_ssl_free(&c->ssl);
    free(c);
}

static int send_all(int fd, const char *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        if (wait_fd(fd, POLLOUT, IO_TIMEOUT_MS) != 0) return -1;
        ssize_t n = send(fd, buf + off, len - off, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) return -1;
        off += (size_t)n;
    }
    return 0;
}

static int conn_send(Conn *c, const char *buf, size_t len) {
    if (!c->tls) return send_all(c->fd, buf, len);
    size_t off = 0;
    while (off < len) {
        int w = mbedtls_ssl_write(&c->ssl,
                                  (const unsigned char *) buf + off, len - off);
        if (w > 0) { off += (size_t) w; continue; }
        return -1;   /* blocking BIO: a poll timeout / error is terminal */
    }
    return 0;
}

static int reply(Conn *c, const char *line) {
    return conn_send(c, line, strlen(line));
}

/* Read one byte from the connection.  Returns 1 (one byte), 0 (EINTR, retry),
   or -1 (timeout / EOF / error).  Plaintext path is byte-identical to the
   original wait_fd(fd,POLLIN)+read(fd,1). */
static int conn_read_byte(Conn *c, char *b) {
    if (!c->tls) {
        if (wait_fd(c->fd, POLLIN, IO_TIMEOUT_MS) != 0) return -1;
        for (;;) {
            ssize_t r = read(c->fd, b, 1);
            if (r == 0) return -1;                  /* EOF */
            if (r < 0) {
                if (errno == EINTR) return 0;       /* retry */
                return -1;
            }
            return 1;
        }
    }
    for (;;) {
        int r = mbedtls_ssl_read(&c->ssl, (unsigned char *) b, 1);
        if (r > 0) return 1;
        return -1;   /* timeout / EOF / error (WANT_* cannot occur: blocking BIO) */
    }
}

/* Read one CRLF- (or bare-LF-) terminated line into a heap buffer.  On success
   returns 0 and sets *out to a malloc'd NUL-terminated string with the CRLF
   stripped; *len is the byte count excluding NUL.  Returns -1 on timeout/EOF. */
static int read_line(Conn *c, char **out, size_t *len) {
    size_t cap = 128, n = 0;
    char *buf = malloc(cap);
    if (!buf) return -1;
    for (;;) {
        if (n + 1 >= cap) {
            cap *= 2;
            char *nb = realloc(buf, cap);
            if (!nb) { free(buf); return -1; }
            buf = nb;
        }
        int rb = conn_read_byte(c, &buf[n]);
        if (rb < 0) { free(buf); return -1; }
        if (rb == 0) continue;                  /* EINTR */
        n++;
        if (buf[n - 1] == '\n') {
            buf[n] = '\0';
            /* strip trailing CR (if any) from the returned line */
            size_t outlen = n;
            if (outlen > 0 && buf[outlen - 1] == '\n') outlen--;
            if (outlen > 0 && buf[outlen - 1] == '\r') outlen--;
            buf[outlen] = '\0';
            *out = buf;
            *len = outlen;
            return 0;
        }
    }
}

static int append_bytes(char **buf, size_t *len, size_t *cap,
                        const char *data, size_t n) {
    if (*len + n + 1 > *cap) {
        size_t ncap = *cap ? *cap : GROW_STEP;
        while (*len + n + 1 > ncap) ncap *= 2;
        char *nb = realloc(*buf, ncap);
        if (!nb) return -1;
        *buf = nb;
        *cap = ncap;
    }
    memcpy(*buf + *len, data, n);
    *len += n;
    (*buf)[*len] = '\0';
    return 0;
}

/* Handle one fully-established client connection.  Records the dialogue to
   dialogue-<seq>.txt and the de-dotted body to msg-<seq>.eml. */
static void handle_conn(int fd, const char *outdir, unsigned seq, bool tls_mode) {
    char path[1024];
    int rn;
    FILE *dlog = NULL, *mfile = NULL;
    Conn *c = conn_new(fd);
    if (!c) return;

    /* Open the recording files for this connection. */
    rn = snprintf(path, sizeof path, "%s/dialogue-%u.txt", outdir, seq);
    if (rn > 0 && (size_t)rn < sizeof path) dlog = fopen(path, "w");
    rn = snprintf(path, sizeof path, "%s/msg-%u.eml", outdir, seq);
    if (rn > 0 && (size_t)rn < sizeof path) mfile = fopen(path, "w");

    if (dlog) fprintf(dlog, "C: <connect>\n");

    /* Greeting. */
    if (reply(c, "220 relay_fake ESMTP ready\r\n") != 0) {
        if (dlog) fprintf(dlog, "S: 220 relay_fake ESMTP ready\n");
        goto done;
    }
    if (dlog) fprintf(dlog, "S: 220 relay_fake ESMTP ready\n");

    for (;;) {
        char *line = NULL;
        size_t llen = 0;
        if (read_line(c, &line, &llen) != 0) break;
        if (dlog) { fwrite(line, 1, llen, dlog); fputc('\n', dlog); }

        if (strncmp(line, "QUIT", 4) == 0) {
            reply(c, "221 2.0.0 Bye\r\n");
            free(line);
            break;
        } else if (strncmp(line, "EHLO", 4) == 0 ||
                   strncmp(line, "HELO", 4) == 0) {
            if (tls_mode && !c->tls) {
                /* Advertise STARTTLS so a TLS-capable client upgrades. */
                if (reply(c, "250-relay_fake\r\n250-STARTTLS\r\n250 8BITMIME\r\n") != 0) {
                    free(line);
                    break;
                }
                if (dlog) fprintf(dlog,
                        "S: 250-relay_fake\nS: 250-STARTTLS\nS: 250 8BITMIME\n");
            } else {
                if (reply(c, "250 relay_fake\r\n") != 0) { free(line); break; }
                if (dlog && tls_mode) fprintf(dlog, "S: 250 relay_fake\n");
            }
            free(line);
        } else if (strncmp(line, "STARTTLS", 8) == 0 && tls_mode) {
            free(line);
            if (reply(c, "220 2.0.0 Ready to start TLS\r\n") != 0) break;
            if (dlog) fprintf(dlog, "S: 220 2.0.0 Ready to start TLS\n");
            if (tls_server_handshake(c) != 0) break;
            if (dlog) fprintf(dlog, "S: <TLS established>\n");
        } else if (strncmp(line, "MAIL", 4) == 0) {
            reply(c, "250 2.1.0 OK\r\n");
            free(line);
        } else if (strncmp(line, "RCPT", 4) == 0) {
            reply(c, "250 2.1.5 OK\r\n");
            free(line);
        } else if (strncmp(line, "DATA", 4) == 0) {
            free(line);
            if (reply(c, "354 End data with <CR><LF>.<CR><LF>\r\n") != 0)
                break;
            if (dlog) fprintf(dlog, "S: 354 End data\n");
            /* Read the message body until the CRLF.CRLF terminator. */
            char *body = NULL;
            size_t blen = 0, bcap = 0;
            bool term = false;
            for (;;) {
                char *bl = NULL;
                size_t bln = 0;
                if (read_line(c, &bl, &bln) != 0) { free(bl); break; }
                if (dlog) { fwrite(bl, 1, bln, dlog); fputc('\n', dlog); }
                if (bln == 1 && bl[0] == '.') {   /* terminator */
                    free(bl);
                    term = true;
                    break;
                }
                /* De-dot-stuff: strip one leading '.' from stuffed lines. */
                size_t start = 0;
                if (bln >= 2 && bl[0] == '.' && bl[1] == '.') start = 1;
                if (append_bytes(&body, &blen, &bcap, bl + start, bln - start) != 0 ||
                    append_bytes(&body, &blen, &bcap, "\n", 1) != 0) {
                    free(bl);
                    free(body);
                    break;
                }
                free(bl);
            }
            if (term && mfile && body) {
                fwrite(body, 1, blen, mfile);
            }
            free(body);
            reply(c, "250 2.0.0 OK queued\r\n");
            if (dlog) fprintf(dlog, "S: 250 2.0.0 OK queued\n");
        } else if (strncmp(line, "RSET", 4) == 0 ||
                   strncmp(line, "NOOP", 4) == 0) {
            reply(c, "250 2.0.0 OK\r\n");
            free(line);
        } else {
            /* Unknown / AUTH: refuse politely. */
            reply(c, "502 5.5.1 Command not implemented\r\n");
            free(line);
        }
    }

done:
    if (dlog) { fflush(dlog); fclose(dlog); }
    if (mfile) { fflush(mfile); fclose(mfile); }
    conn_free(c);
}

int main(int argc, char **argv) {
    bool tls = false;
    const char *port_arg = NULL, *outdir = NULL;
    int i;
    /* Usage: relay_fake PORT OUTDIR [--tls].  Tolerate the flag in any
       position so callers may write PORT OUTDIR --tls or --tls PORT OUTDIR. */
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--tls") == 0) {
            tls = true;
        } else if (!port_arg) {
            port_arg = argv[i];
        } else if (!outdir) {
            outdir = argv[i];
        } else {
            fprintf(stderr, "usage: relay_fake PORT OUTDIR [--tls]\n");
            return 2;
        }
    }
    if (!port_arg || !outdir) {
        fprintf(stderr, "usage: relay_fake PORT OUTDIR [--tls]\n");
        return 2;
    }
    long port = atol(port_arg);
    if (port <= 0 || port > 65535) {
        fprintf(stderr, "relay_fake: invalid port %s\n", port_arg);
        return 2;
    }
    if (tls && tls_server_init() != 0) {
        fprintf(stderr, "relay_fake: cannot initialize TLS "
                        "(is %s / %s present from the project root?)\n",
                TEST_CERT_PATH, TEST_KEY_PATH);
        return 1;
    }

    int ls = socket(AF_INET, SOCK_STREAM, 0);
    if (ls < 0) {
        fprintf(stderr, "relay_fake: socket: %s\n", strerror(errno));
        return 1;
    }
    int one = 1;
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)port);
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(ls, (struct sockaddr *)&sa, sizeof sa) != 0) {
        fprintf(stderr, "relay_fake: bind %s:%ld: %s\n",
                "127.0.0.1", port, strerror(errno));
        close(ls);
        return 1;
    }
    if (listen(ls, 8) != 0) {
        fprintf(stderr, "relay_fake: listen: %s\n", strerror(errno));
        close(ls);
        return 1;
    }

    fprintf(stderr, "relay_fake: listening on 127.0.0.1:%ld recording to %s%s\n",
            port, outdir, tls ? " (TLS)" : "");

    unsigned seq = 0;
    for (;;) {
        int cfd = accept(ls, NULL, NULL);
        if (cfd < 0) {
            if (errno == EINTR) continue;
            break;
        }
        seq++;
        handle_conn(cfd, outdir, seq, tls);
        close(cfd);
    }
    close(ls);
    return 0;
}
