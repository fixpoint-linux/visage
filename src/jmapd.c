/* jmapd.c — companion JMAP server: CLI, config, listener, poll loop.
 *
 * One poll()-based, single-threaded event loop (mirroring imapd.c; no fork, no
 * threads in the request path) with ONE listener.  Connections are imapd Conn
 * structs embedded in a JmapdConn, so the TLS layer (imapd_tls.c) and the
 * buffer discipline are the same code the IMAP daemon runs.
 *
 * TLS is HTTPS FROM THE FIRST BYTE: there is no STARTTLS upgrade and no
 * plaintext phase on a TLS listener — at accept the connection is put straight
 * into imapd_tls_start and the handshake is driven by the poll loop.  Without
 * --cert/--key the listener is plaintext HTTP, which is only allowed on a
 * loopback bind (the mail-hub client's loopback_dev mode); a non-loopback bind
 * without TLS is refused at startup, because that would put the Basic
 * credential on the wire in clear text.
 *
 * Configuration: CLI flags + JMAPD_* env only (no Dhall), same shape as imapd.
 * Credentials are imapd's <root>/imapd.passwd. */
#include "visage.h"
#include "jmapd.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <poll.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <time.h>

/* ------------------------------------------------------------------ */
/* Small helpers (duplicated per house style)                          */
/* ------------------------------------------------------------------ */

static void set_nonblock(int fd) {
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl < 0) return;
    (void)fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

/* Drain the pending response backlog.  Identical to imapd.c's conn_flush: the
   TLS branch sends through mbedTLS once the handshake is up, and a dead peer
   drops the backlog so the reaper can see out_off >= out_len. */
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
            c->out_len = c->out_off = 0;
            return;
        }
        if (n == 0) { c->closed = true; c->out_len = c->out_off = 0; return; }
        c->out_off += (size_t)n;
    }
    c->out_len = c->out_off = 0;
}

static int peer_ip_of(struct sockaddr_storage *sa, socklen_t salen,
                      unsigned char *peer_ip, uint8_t *peer_ip_len) {
    *peer_ip_len = 0;
    if (sa->ss_family == AF_INET && salen >= sizeof(struct sockaddr_in)) {
        struct sockaddr_in *a = (struct sockaddr_in *)sa;
        memcpy(peer_ip, &a->sin_addr, 4);
        *peer_ip_len = 4;
        return 0;
    }
    if (sa->ss_family == AF_INET6 && salen >= sizeof(struct sockaddr_in6)) {
        struct sockaddr_in6 *a = (struct sockaddr_in6 *)sa;
        memcpy(peer_ip, &a->sin6_addr, 16);
        *peer_ip_len = 16;
        return 0;
    }
    return -1;
}

static size_t count_peer_conns(const JmapdServer *srv,
                               const unsigned char *ip, uint8_t iplen) {
    size_t n = 0, i;
    if (iplen == 0) return 0;
    for (i = 0; i < srv->nconns; i++) {
        const Conn *c = &srv->conns[i]->c;
        if (c->peer_ip_len == iplen && memcmp(c->peer_ip, ip, iplen) == 0)
            n++;
    }
    return n;
}

/* ------------------------------------------------------------------ */
/* Graceful shutdown                                                   */
/* ------------------------------------------------------------------ */

/* SIGTERM/SIGINT: set g_stop; the handler is installed WITHOUT SA_RESTART so
   poll() returns EINTR and the loop notices on the next iteration.  Nothing is
   half-written on the wire: the loop exits between requests, and open
   connections are closed (a JMAP request is idempotent; a client retries). */
static volatile sig_atomic_t g_stop;

static void on_signal(int sig) {
    (void)sig;
    g_stop = 1;
}

static int install_signal_handlers(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;   /* no SA_RESTART: poll() returns EINTR promptly */
    if (sigaction(SIGTERM, &sa, NULL) != 0) return -1;
    if (sigaction(SIGINT, &sa, NULL) != 0) return -1;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Connection lifecycle                                                */
/* ------------------------------------------------------------------ */

static void conn_destroy(JmapdConn *jc) {
    Conn *c = &jc->c;
    jmapd_download_free(jc);   /* closes the message file, not the socket */
    jmapd_log(jc, "disconnect", c->user, NULL);
    imapd_tls_conn_free(c);   /* close_notify while the fd is still open */
    if (c->fd >= 0) close(c->fd);
    free(c->user);
    free(c->in);
    free(c->out);
    free(jc);
}

/* Advance one TLS handshake round.  A fatal round drops the connection WITHOUT
   queueing any reply: the wire is mid-TLS and plaintext would be garbage. */
static void tls_advance(JmapdServer *srv, JmapdConn *jc, time_t now) {
    int r = imapd_tls_handshake_step(&jc->c, now);
    if (r < 0) {
        jc->c.closed = true;
        jc->c.out_len = jc->c.out_off = 0;
        return;
    }
    if (r > 0) {
        /* TLS up: the client's first request often arrived in the same TCP
           segment as the final flight, so POLLIN may never fire for it. */
        jmapd_http_readable(srv, jc, now);
    }
}

static void server_accept(JmapdServer *srv, time_t now) {
    for (;;) {
        struct sockaddr_storage sa;
        socklen_t salen = sizeof sa;
        int fd = accept(srv->listen_fd, (struct sockaddr *)&sa, &salen);
        JmapdConn *jc;
        if (fd < 0) {
            if (errno == EINTR) continue;
            return;   /* EAGAIN/EWOULDBLOCK or a real error */
        }
        set_nonblock(fd);

        if (srv->nconns >= JMAPD_MAX_CONNS) { close(fd); continue; }
        {
            unsigned char ip[16];
            uint8_t iplen = 0;
            (void)peer_ip_of(&sa, salen, ip, &iplen);
            if (iplen != 0 &&
                count_peer_conns(srv, ip, iplen) >= JMAPD_MAX_CONNS_PER_IP) {
                close(fd);
                continue;
            }
        }

        jc = calloc(1, sizeof *jc);
        if (!jc) { close(fd); continue; }
        jc->c.fd = fd;
        jc->c.last_act = now;
        jc->c.id = ++srv->next_conn_id;
        (void)peer_ip_of(&sa, salen, jc->c.peer_ip, &jc->c.peer_ip_len);
        jmapd_log(jc, "connect", NULL, srv->tls_ready ? "tls=on" : "tls=off");

        if (srv->nconns == srv->conn_cap) {
            size_t nc = srv->conn_cap ? srv->conn_cap * 2 : 16;
            JmapdConn **na = realloc(srv->conns, nc * sizeof *na);
            if (!na) { conn_destroy(jc); continue; }
            srv->conns = na;
            srv->conn_cap = nc;
        }
        srv->conns[srv->nconns++] = jc;

        if (srv->tls_ready) {
            /* HTTPS from the first byte: no greeting, no plaintext phase. */
            if (imapd_tls_start(&srv->auth, &jc->c) != 0) {
                jc->c.closed = true;
                continue;
            }
            tls_advance(srv, jc, now);
        }
    }
}

/* ------------------------------------------------------------------ */
/* Poll loop                                                           */
/* ------------------------------------------------------------------ */

static int poll_timeout_ms(const JmapdServer *srv, time_t now) {
    int ms = -1;
    size_t i;
    if (srv->cfg.cmd_tmo == 0) return -1;
    for (i = 0; i < srv->nconns; i++) {
        const Conn *c = &srv->conns[i]->c;
        time_t elapsed, remain;
        int rms;
        elapsed = (now > c->last_act) ? (now - c->last_act) : 0;
        if (elapsed >= (time_t)srv->cfg.cmd_tmo) return 0;
        remain = (time_t)srv->cfg.cmd_tmo - elapsed;
        rms = (int)(remain * 1000);
        if (rms > 2147483647) rms = 2147483647;
        if (ms < 0 || rms < ms) ms = rms;
    }
    return ms;
}

static void server_poll(JmapdServer *srv) {
    struct pollfd *pfds = NULL;
    size_t pfds_cap = 0;

    while (!g_stop) {
        time_t now = time(NULL);
        size_t nfds, n_before, i;

        /* idle timeouts */
        for (i = 0; i < srv->nconns; i++) {
            JmapdConn *jc = srv->conns[i];
            Conn *c = &jc->c;
            if (srv->cfg.cmd_tmo == 0) continue;
            if (now > c->last_act &&
                (now - c->last_act) >= (time_t)srv->cfg.cmd_tmo) {
                /* Mid-TLS: a plaintext 408 would corrupt the stream. */
                c->closed = true;
                c->out_len = c->out_off = 0;
            }
        }

        nfds = 1 + srv->nconns;
        if (nfds > pfds_cap) {
            free(pfds);
            pfds = malloc(nfds * sizeof *pfds);
            if (!pfds) break;
            pfds_cap = nfds;
        }
        pfds[0].fd = srv->listen_fd;
        pfds[0].events = POLLIN;
        pfds[0].revents = 0;
        for (i = 0; i < srv->nconns; i++) {
            JmapdConn *jc = srv->conns[i];
            Conn *c = &jc->c;
            pfds[1 + i].fd = c->fd;
            if (!c->closed && imapd_tls_handshaking(c)) {
                pfds[1 + i].events = imapd_tls_pending(c) ? POLLOUT
                                     : (imapd_tls_wants_write(c) ? POLLOUT
                                                                 : POLLIN);
            } else if (c->closed) {
                pfds[1 + i].events = (c->out_off < c->out_len) ? POLLOUT : 0;
            } else if (jc->blob) {
                /* A streamed download owns the connection: pump on POLLOUT
                   and read nothing until the body is complete. */
                pfds[1 + i].events = POLLOUT;
            } else {
                /* backpressure: stop reading while the reply backlog is high */
                pfds[1 + i].events =
                    (c->out_len < JMAPD_MAX_OUT / 2) ? POLLIN : 0;
                if (c->out_off < c->out_len) pfds[1 + i].events |= POLLOUT;
            }
            pfds[1 + i].revents = 0;
        }

        {
            int tmo = poll_timeout_ms(srv, now);
            int pr = poll(pfds, nfds, tmo);
            if (pr < 0) {
                if (errno == EINTR) continue;
                break;
            }
        }

        n_before = srv->nconns;
        if (pfds[0].revents & POLLIN) server_accept(srv, now);

        for (i = 0; i < n_before; i++) {
            JmapdConn *jc = srv->conns[i];
            Conn *c = &jc->c;
            short rev = pfds[1 + i].revents;
            if (c->closed) {
                if (rev & POLLOUT) conn_flush(c);
                continue;
            }
            if (imapd_tls_pending(c)) {
                if (rev & POLLOUT) {
                    conn_flush(c);
                    if (!c->closed && c->out_off >= c->out_len)
                        tls_advance(srv, jc, now);
                }
                continue;
            }
            if (imapd_tls_handshaking(c)) {
                if (rev & (POLLIN | POLLOUT | POLLHUP | POLLERR))
                    tls_advance(srv, jc, now);
                continue;
            }
            if (rev & (POLLIN | POLLHUP | POLLERR))
                jmapd_http_readable(srv, jc, now);
            if (!c->closed && (rev & POLLOUT)) {
                conn_flush(c);
                if (!c->closed && jc->blob) jmapd_download_pump(jc);
            }
        }

        /* destroy closed connections whose output has drained */
        for (i = 0; i < srv->nconns; ) {
            JmapdConn *jc = srv->conns[i];
            if (jc->c.closed && jc->c.out_off >= jc->c.out_len) {
                conn_destroy(jc);
                srv->conns[i] = srv->conns[srv->nconns - 1];
                srv->nconns--;
            } else {
                i++;
            }
        }
    }
    free(pfds);
}

/* ------------------------------------------------------------------ */
/* Listener                                                            */
/* ------------------------------------------------------------------ */

static int make_listener(const char *addr, uint16_t port) {
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    struct addrinfo *ai;
    char portstr[16];
    int fd = -1;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    snprintf(portstr, sizeof portstr, "%u", (unsigned)port);
    if (getaddrinfo(addr, portstr, &hints, &res) != 0) return -1;
    for (ai = res; ai; ai = ai->ai_next) {
        int s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        int one = 1;
        if (s < 0) continue;
        (void)setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
        if (bind(s, ai->ai_addr, ai->ai_addrlen) < 0) { close(s); continue; }
        if (listen(s, JMAPD_LISTEN_BACKLOG) < 0) { close(s); continue; }
        fd = s;
        break;
    }
    freeaddrinfo(res);
    if (fd < 0) return -1;
    set_nonblock(fd);
    return fd;
}

/* ------------------------------------------------------------------ */
/* Configuration (flags + env)                                         */
/* ------------------------------------------------------------------ */

static const char *env_or(const char *name, const char *dflt) {
    const char *v = getenv(name);
    return (v && v[0]) ? v : dflt;
}

static unsigned long env_num(const char *name, unsigned long dflt) {
    const char *v = getenv(name);
    unsigned long n;
    char *end;
    if (!v || !v[0]) return dflt;
    n = strtoul(v, &end, 10);
    if (*end != '\0') return dflt;
    return n;
}

static void config_defaults(JmapdConfig *cfg) {
    memset(cfg, 0, sizeof *cfg);
    /* Same root as imapd on purpose: both daemons serve one maildir tree. */
    cfg->root = env_or("JMAPD_ROOT", IMAPD_DEFAULT_ROOT);
    cfg->addr = env_or("JMAPD_ADDR", "127.0.0.1");
    cfg->port = (uint16_t)env_num("JMAPD_PORT", JMAPD_DEFAULT_PORT);
    cfg->cert = env_or("JMAPD_CERT", NULL);
    cfg->key = env_or("JMAPD_KEY", NULL);
    cfg->hostname = env_or("JMAPD_HOSTNAME", JMAPD_DEFAULT_HOSTNAME);
    cfg->public_url = env_or("JMAPD_PUBLIC_URL", "");
    cfg->max_req = (uint32_t)env_num("JMAPD_MAX_REQ", JMAPD_DEFAULT_MAX_REQ);
    cfg->outbox_host = env_or("JMAPD_OUTBOX_HOST", JMAPD_DEFAULT_OUTBOX_HOST);
    cfg->outbox_port = (uint16_t)env_num("JMAPD_OUTBOX_PORT",
                                         JMAPD_DEFAULT_OUTBOX_PORT);
    cfg->outbox_user = env_or("JMAPD_OUTBOX_USER", "");
    cfg->outbox_pass = env_or("JMAPD_OUTBOX_PASS", "");
    cfg->outbox_tls = env_or("JMAPD_OUTBOX_TLS", "implicit");
    cfg->identity = env_or("JMAPD_IDENTITY", "");
    cfg->submit_wait = (uint32_t)env_num("JMAPD_SUBMIT_WAIT",
                                         JMAPD_SUBMIT_DEFAULT_WAIT);
    cfg->cmd_tmo = (uint32_t)env_num("JMAPD_TMO", JMAPD_DEFAULT_TMO);
}

static const char *find_arg(int argc, char **argv, const char *name) {
    int i;
    for (i = 1; i < argc - 1; i++)
        if (strcmp(argv[i], name) == 0) return argv[i + 1];
    return NULL;
}

static int parse_u16(const char *s, uint16_t *out) {
    unsigned long n;
    char *end;
    if (!s || !s[0]) return -1;
    n = strtoul(s, &end, 10);
    if (*end != '\0' || n == 0 || n > 65535) return -1;
    *out = (uint16_t)n;
    return 0;
}

static int config_from_args(JmapdConfig *cfg, int argc, char **argv) {
    const char *v;
    if ((v = find_arg(argc, argv, "--root"))) cfg->root = v;
    if ((v = find_arg(argc, argv, "--addr"))) cfg->addr = v;
    if ((v = find_arg(argc, argv, "--cert"))) cfg->cert = v;
    if ((v = find_arg(argc, argv, "--key"))) cfg->key = v;
    if ((v = find_arg(argc, argv, "--hostname"))) cfg->hostname = v;
    if ((v = find_arg(argc, argv, "--public-url"))) cfg->public_url = v;
    if ((v = find_arg(argc, argv, "--outbox-host"))) cfg->outbox_host = v;
    if ((v = find_arg(argc, argv, "--outbox-user"))) cfg->outbox_user = v;
    if ((v = find_arg(argc, argv, "--outbox-pass"))) cfg->outbox_pass = v;
    if ((v = find_arg(argc, argv, "--outbox-tls"))) cfg->outbox_tls = v;
    if ((v = find_arg(argc, argv, "--identity"))) cfg->identity = v;
    if ((v = find_arg(argc, argv, "--submit-wait"))) {
        unsigned long n;
        char *end;
        n = strtoul(v, &end, 10);
        if (*end != '\0' || n > 600000) return -1;
        cfg->submit_wait = (uint32_t)n;
    }
    if ((v = find_arg(argc, argv, "--port")) &&
        parse_u16(v, &cfg->port) != 0) return -1;
    if ((v = find_arg(argc, argv, "--outbox-port")) &&
        parse_u16(v, &cfg->outbox_port) != 0) return -1;
    if ((v = find_arg(argc, argv, "--max-request"))) {
        unsigned long n;
        char *end;
        n = strtoul(v, &end, 10);
        if (*end != '\0' || n == 0) return -1;
        cfg->max_req = (uint32_t)n;
    }
    if ((v = find_arg(argc, argv, "--timeout"))) {
        unsigned long n;
        char *end;
        n = strtoul(v, &end, 10);
        if (*end != '\0') return -1;
        cfg->cmd_tmo = (uint32_t)n;
    }
    return 0;
}

static void usage(FILE *f) {
    fprintf(f,
        "usage: jmapd [options]\n"
        "\n"
        "options:\n"
        "  --root DIR           maildir root (env JMAPD_ROOT, default %s;\n"
        "                       should be imapd's root)\n"
        "  --addr ADDR          bind address (JMAPD_ADDR, default 127.0.0.1)\n"
        "  --port N             bind port (JMAPD_PORT, default %u)\n"
        "  --hostname H         host used in advertised URLs (JMAPD_HOSTNAME)\n"
        "  --public-url URL     base URL advertised verbatim in the session\n"
        "                       document, e.g. https://jmap.example.ch when a\n"
        "                       TLS-terminating proxy sits in front\n"
        "                       (JMAPD_PUBLIC_URL; empty = derive from\n"
        "                       --cert/--hostname/--port)\n"
        "  --cert PATH          TLS certificate PEM (JMAPD_CERT): enables\n"
        "                       HTTPS from the first byte\n"
        "  --key PATH           TLS private key PEM (JMAPD_KEY)\n"
        "  --max-request BYTES  request cap (JMAPD_MAX_REQ, default %u)\n"
        "  --timeout SECONDS    idle timeout (JMAPD_TMO, default %u)\n"
        "  --outbox-host HOST   submission relay (JMAPD_OUTBOX_HOST, default %s)\n"
        "  --outbox-port N      submission relay port (JMAPD_OUTBOX_PORT, "
        "default %u)\n"
        "  --outbox-tls MODE    implicit (default) or none (JMAPD_OUTBOX_TLS);\n"
        "                       none is refused for a non-loopback relay\n"
        "  --outbox-user USER   submission AUTH PLAIN user (JMAPD_OUTBOX_USER)\n"
        "  --outbox-pass PASS   submission AUTH PLAIN password "
        "(JMAPD_OUTBOX_PASS)\n"
        "  --submit-wait MS     how long a submission waits for the relay's\n"
        "                       verdict before answering created "
        "(JMAPD_SUBMIT_WAIT, default %u)\n"
        "  --identity ADDRESS   this account's own address (JMAPD_IDENTITY,\n"
        "                       default <user>@<hostname>)\n"
        "  --help               show this help and exit\n"
        "  --version            print the version and exit\n",
        IMAPD_DEFAULT_ROOT, (unsigned)JMAPD_DEFAULT_PORT,
        JMAPD_DEFAULT_MAX_REQ, JMAPD_DEFAULT_TMO, JMAPD_DEFAULT_OUTBOX_HOST,
        (unsigned)JMAPD_DEFAULT_OUTBOX_PORT, JMAPD_SUBMIT_DEFAULT_WAIT);
}

int main(int argc, char **argv) {
    JmapdServer srv;
    JmapdConfig cfg;

    if (argc > 1 && (strcmp(argv[1], "--help") == 0 ||
                     strcmp(argv[1], "-h") == 0)) {
        usage(stdout);
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "--version") == 0) {
        printf("jmapd %s\n", VISAGE_VERSION);
        return 0;
    }

    config_defaults(&cfg);
    if (config_from_args(&cfg, argc, argv) != 0) {
        fprintf(stderr, "jmapd: bad option value\n");
        usage(stderr);
        return 2;
    }
    if (argc > 1 && argv[1][0] != '-') {
        fprintf(stderr, "jmapd: unknown command '%s'\n\n", argv[1]);
        usage(stderr);
        return 2;
    }
    if (cfg.max_req < 1024) {
        fprintf(stderr, "jmapd: --max-request must be at least 1024\n");
        return 2;
    }

    memset(&srv, 0, sizeof srv);
    srv.cfg = cfg;
    srv.loopback = jmapd_addr_loopback(cfg.addr);

    /* Refuse a configuration that would put the Basic credential on the wire
       in clear text: no TLS is allowed only on a loopback bind. */
    if (!cfg.cert && !cfg.key && !srv.loopback) {
        fprintf(stderr,
                "jmapd: refusing a non-loopback bind (%s) without --cert/"
                "--key: JMAP carries the password in an Authorization header\n",
                cfg.addr);
        return 1;
    }

    /* The advertised base URL override.  The session document is what a client
       follows, so an override that cannot be advertised is a startup refusal
       rather than a document with a wrong (or half-joined) URL in it. */
    if (cfg.public_url && cfg.public_url[0]) {
        char norm[JMAPD_PUBLIC_URL_MAX];
        int why = jmapd_public_url_check(cfg.public_url, cfg.addr, norm,
                                         sizeof norm);
        if (why != JMAPD_PUB_OK) {
            fprintf(stderr, "jmapd: refusing --public-url '%s': %s\n",
                    cfg.public_url, jmapd_public_url_reason(why));
            return why == JMAPD_PUB_ERR_PLAINTEXT ? 1 : 2;
        }
    }

    /* The submission relay's TLS mode.  "none" exists for the tests (a
       recording sink on loopback) and would hand the AUTH PLAIN credential to
       any host in the path, so it is refused unless the relay is on this
       machine — the same rule, and the same reason, as the plaintext bind
       above. */
    if (strcmp(cfg.outbox_tls, "none") != 0 &&
        strcmp(cfg.outbox_tls, "implicit") != 0 &&
        strcmp(cfg.outbox_tls, "starttls") != 0 &&
        strcmp(cfg.outbox_tls, "starttls-verify") != 0) {
        fprintf(stderr,
                "jmapd: --outbox-tls must be implicit, starttls, "
                "starttls-verify or none (got '%s')\n", cfg.outbox_tls);
        return 2;
    }
    if (strcmp(cfg.outbox_tls, "none") == 0 &&
        !jmapd_addr_loopback(cfg.outbox_host)) {
        fprintf(stderr,
                "jmapd: refusing --outbox-tls none for the non-loopback relay "
                "%s: the submission credential would cross the network in "
                "clear text\n", cfg.outbox_host);
        return 1;
    }
    if (cfg.outbox_pass && cfg.outbox_pass[0] && !(cfg.outbox_user &&
                                                   cfg.outbox_user[0])) {
        fprintf(stderr, "jmapd: --outbox-pass without --outbox-user\n");
        return 2;
    }

    /* The imapd helpers (maildir store, passwd table, lockout, TLS) take an
       ImapdConfig/ImapdServer; fill the fields they read. */
    memset(&srv.icfg, 0, sizeof srv.icfg);
    srv.icfg.root = cfg.root;
    srv.icfg.cert = cfg.cert;
    srv.icfg.key = cfg.key;
    srv.icfg.hostname = cfg.hostname;
    srv.icfg.max_msg = IMAPD_DEFAULT_MAX_MSG;
    srv.icfg.cmd_tmo = cfg.cmd_tmo;
    srv.icfg.data_tmo = cfg.cmd_tmo;
    srv.auth.cfg = srv.icfg;

    if (imapd_auth_load(&srv.icfg, &srv.auth) != 0) {
        fprintf(stderr, "jmapd: cannot load %s/%s\n", cfg.root,
                IMAPD_PASSWD_FILE);
        return 1;
    }
    if (srv.auth.ncreds == 0)
        fprintf(stderr,
                "jmapd: WARNING no users configured (%s/%s missing or empty); "
                "every request will get 401 until you run "
                "`imapd passwd USER PASS --root %s`\n",
                cfg.root, IMAPD_PASSWD_FILE, cfg.root);

    if (imapd_tls_global_init(&srv.auth) != 0) return 1;   /* fail-closed */
    srv.tls_ready = imapd_tls_available(&srv.auth);

    srv.listen_fd = make_listener(cfg.addr, cfg.port);
    if (srv.listen_fd < 0) {
        fprintf(stderr, "jmapd: cannot listen on %s:%u\n", cfg.addr,
                (unsigned)cfg.port);
        return 1;
    }
    if (install_signal_handlers() != 0) {
        fprintf(stderr, "jmapd: cannot install signal handlers\n");
        return 1;
    }
    /* The outbox worker.  Started before the listener so a submission can
       never arrive at a daemon with no way to send it. */
    if (jmapd_submit_init(&srv) != 0) {
        fprintf(stderr, "jmapd: cannot start the submission worker\n");
        return 1;
    }

    printf("jmapd %s: %s on %s:%u, root %s, max request %u, outbox %s:%u "
           "(tls %s), identity %s\n",
           VISAGE_VERSION, srv.tls_ready ? "https" : "http", cfg.addr,
           (unsigned)cfg.port, cfg.root, cfg.max_req, cfg.outbox_host,
           (unsigned)cfg.outbox_port, cfg.outbox_tls,
           (cfg.identity && cfg.identity[0]) ? cfg.identity : "<user>@<host>");
    fflush(stdout);

    server_poll(&srv);

    {
        size_t i;
        for (i = 0; i < srv.nconns; i++) conn_destroy(srv.conns[i]);
        free(srv.conns);
    }
    close(srv.listen_fd);
    jmapd_submit_stop(&srv);   /* drain what is queued, then join */
    return 0;
}
