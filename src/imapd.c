/* imapd.c — companion IMAP mailbox server: CLI, listeners, poll loop.
 *
 * One poll()-based, single-threaded event loop (mirroring smtp_in.c; no
 * fork/thread) with two listeners:
 *   pfds[0]  SMTP ingest (receives visage's smtp_out relays, default
 *            127.0.0.1:2526 = config.example.dhall's relay target)
 *   pfds[1]  IMAP4rev1 (default 127.0.0.1:143)
 * Connections are kind-tagged Conn structs shared with the per-protocol
 * state machines (imapd_ingest.c / imapd_imap.c).
 *
 * Configuration: CLI flags + env vars only (no Dhall) — keeps imapd free of
 * the dhall/datalog link deps.  Credentials live in $ROOT/imapd.passwd
 * ("user:pass" lines, 0600); `imapd passwd USER PASS` manages that file.
 * TLS: STARTTLS (RFC 2595 IMAP / RFC 3207 ingest) is enabled by --cert/--key
 * (imapd_tls.c, mbedTLS SERVER role over these non-blocking fds).  SECURITY:
 * without cert/key the daemon is plaintext (loopback default); on a
 * non-loopback IMAP bind WITH TLS configured, cleartext LOGIN/AUTHENTICATE
 * are refused per RFC 3501 11.1 until STARTTLS completes. */
#include "visage.h"
#include "imapd.h"
#include "mail.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <poll.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <time.h>

/* ------------------------------------------------------------------ */
/* Small helpers (duplicated from smtp_in.c per house style)           */
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

static void set_nonblock(int fd) {
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl < 0) return;
    (void)fcntl(fd, F_SETFL, fl | O_NONBLOCK);
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

/* Extract the peer address bytes (cf. smtp_in.c peer_ip_of). */
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

/* Count how many live connections share the peer's address (O(n), n<=512). */
static size_t count_peer_conns(const ImapdServer *srv, const unsigned char *ip,
                               uint8_t iplen) {
    size_t n = 0, i;
    if (iplen == 0) return 0;
    for (i = 0; i < srv->nconns; i++) {
        const Conn *c = srv->conns[i];
        if (c->peer_ip_len == iplen && memcmp(c->peer_ip, ip, iplen) == 0)
            n++;
    }
    return n;
}

/* ------------------------------------------------------------------ */
/* Connection lifecycle                                                */
/* ------------------------------------------------------------------ */

static void conn_destroy(Conn *c) {
    size_t i;
    imapd_tls_conn_free(c);   /* close_notify while the fd is still open */
    if (c->fd >= 0) close(c->fd);
    if (c->kind == CONN_INGEST) {
        free(c->from);
        for (i = 0; i < c->nrcpts; i++) free(c->rcpts[i]);
        free(c->rcpts);
        free(c->data);
    } else if (c->kind == CONN_POP3) {
        imapd_pop3_free(c);
        free(c->user);
        free(c->pend_user);
        free(c->del);
        if (c->mb_open) imapd_mbox_close(&c->mb);
    } else {
        free(c->user);
        if (c->mb_open) imapd_mbox_close(&c->mb);
        imapd_fetch_free(c);
        free(c->cmd);
    }
    free(c->in);
    free(c->out);
    free(c);
}

/* ------------------------------------------------------------------ */
/* Accept + event loop (mirror of smtp_in.c server_poll)               */
/* ------------------------------------------------------------------ */

static void server_accept(ImapdServer *srv, int lfd, int kind, time_t now);

static int poll_timeout_ms(const ImapdServer *srv, time_t now) {
    int ms = -1;
    size_t i;
    for (i = 0; i < srv->nconns; i++) {
        const Conn *c = srv->conns[i];
        uint32_t tmo;
        if (c->kind == CONN_INGEST && c->st == ST_DATA)
            tmo = srv->cfg.data_tmo;
        else if (c->kind == CONN_IMAP && c->idle)
            tmo = IMAPD_IDLE_TMO;
        else
            tmo = srv->cfg.cmd_tmo;
        time_t elapsed, remain;
        int rms;
        if (tmo == 0) continue;
        elapsed = (now > c->last_act) ? (now - c->last_act) : 0;
        if (elapsed >= (time_t)tmo) return 0;
        remain = (time_t)tmo - elapsed;
        rms = (int)(remain * 1000);
        if (rms > 2147483647) rms = 2147483647;
        if (ms < 0 || rms < ms) ms = rms;
    }
    /* A SELECTED IDLE connection wants prompt EXISTS updates: cap the wait so
       imapd_imap_idle_refresh runs on a fixed scan cadence, not the (much
       longer) command timeout. */
    if (ms < 0 || IMAPD_IDLE_SCAN_MS < ms) {
        for (i = 0; i < srv->nconns; i++)
            if (srv->conns[i]->kind == CONN_IMAP && srv->conns[i]->idle) {
                ms = IMAPD_IDLE_SCAN_MS;
                break;
            }
    }
    return ms;
}

/* Advance one STARTTLS handshake round (PENDING -> HANDSHAKE ->
   ESTABLISHED).  A fatal round drops the conn WITHOUT queueing any reply:
   the wire is mid-TLS and plaintext would be garbage to the peer. */
static void tls_advance(ImapdServer *srv, Conn *c, time_t now) {
    int r = imapd_tls_handshake_step(c, now);
    if (r < 0) {
        c->closed = true;
        c->out_len = c->out_off = 0;
        return;
    }
    if (r > 0) {
        /* TLS is up: restart the session clean, then drain immediately (the
           final flight and the first app bytes often land in one TCP
           segment, so POLLIN may never fire for them). */
        if (c->kind == CONN_INGEST) imapd_ingest_tls_reset(srv, c);
        else if (c->kind == CONN_POP3) imapd_pop3_tls_reset(srv, c);
        else imapd_imap_tls_reset(srv, c);
        if (c->kind == CONN_INGEST) imapd_ingest_readable(srv, c, now);
        else if (c->kind == CONN_POP3) imapd_pop3_readable(srv, c, now);
        else imapd_imap_readable(srv, c, now);
    }
}

static void server_poll(ImapdServer *srv) {
    struct pollfd *pfds = NULL;
    size_t pfds_cap = 0;

    for (;;) {
        time_t now = time(NULL);
        size_t nfds, n_before, i;

        /* idle timeouts */
        for (i = 0; i < srv->nconns; i++) {
            Conn *c = srv->conns[i];
            uint32_t tmo;
            const char *bye = (c->kind == CONN_INGEST)
                                  ? "421 4.4.2 Timeout - closing connection\r\n"
                                  : "* BYE timeout\r\n";
            if (c->kind == CONN_INGEST && c->st == ST_DATA)
                tmo = srv->cfg.data_tmo;
            else if (c->kind == CONN_IMAP && c->idle)
                tmo = IMAPD_IDLE_TMO;   /* RFC 2177: longer cap while idling */
            else
                tmo = srv->cfg.cmd_tmo;
            if (tmo != 0 && now > c->last_act &&
                (now - c->last_act) >= (time_t)tmo) {
                if (imapd_tls_handshaking(c)) {
                    /* mid-TLS: a plaintext bye would corrupt the stream */
                    c->closed = true;
                    c->out_len = c->out_off = 0;
                    continue;
                }
                if (c->kind == CONN_POP3) {
                    /* RFC 1939: no mandated timeout message; just drop */
                    c->closed = true;
                    continue;
                }
                (void)buf_append(&c->out, &c->out_len, &c->out_cap,
                                 bye, strlen(bye));
                conn_flush(c);
                c->closed = true;
            }
        }

        /* build pollfd array: [0] ingest listener, [1] imap listener,
           [2] pop3 listener, then conns */
        nfds = 3 + srv->nconns;
        if (nfds > pfds_cap) {
            free(pfds);
            pfds = malloc(nfds * sizeof *pfds);
            if (!pfds) break;
            pfds_cap = nfds;
        }
        pfds[0].fd = srv->listen_ingest;
        pfds[0].events = POLLIN;
        pfds[0].revents = 0;
        pfds[1].fd = srv->listen_imap;
        pfds[1].events = POLLIN;
        pfds[1].revents = 0;
        pfds[2].fd = srv->listen_pop3;
        pfds[2].events = POLLIN;
        pfds[2].revents = 0;
        for (i = 0; i < srv->nconns; i++) {
            Conn *c = srv->conns[i];
            pfds[3 + i].fd = c->fd;
            if (!c->closed && imapd_tls_handshaking(c)) {
                /* STARTTLS: PENDING drains the plaintext reply (POLLOUT);
                   the handshake polls whichever way mbedtls asked for last */
                pfds[3 + i].events = imapd_tls_pending(c) ? POLLOUT
                                     : (imapd_tls_wants_write(c) ? POLLOUT
                                                                 : POLLIN);
            } else if (c->closed) {
                pfds[3 + i].events = (c->out_off < c->out_len) ? POLLOUT : 0;
            } else if (c->kind == CONN_POP3 && c->pg) {
                pfds[3 + i].events = POLLOUT;   /* POP3 stream owns the conn */
            } else if (c->fg) {
                pfds[3 + i].events = POLLOUT;   /* fetch owns the conn */
            } else {
                /* backpressure: stop reading while the reply backlog is high */
                pfds[3 + i].events =
                    (c->out_len < IMAPD_MAX_OUT / 2) ? POLLIN : 0;
                if (c->out_off < c->out_len) pfds[3 + i].events |= POLLOUT;
            }
            pfds[3 + i].revents = 0;
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

        if (pfds[0].revents & POLLIN)
            server_accept(srv, srv->listen_ingest, CONN_INGEST, now);
        if (pfds[1].revents & POLLIN)
            server_accept(srv, srv->listen_imap, CONN_IMAP, now);
        if (pfds[2].revents & POLLIN)
            server_accept(srv, srv->listen_pop3, CONN_POP3, now);

        for (i = 0; i < n_before; i++) {
            Conn *c = srv->conns[i];
            short rev = pfds[3 + i].revents;
            if (c->closed) {
                if (rev & POLLOUT) conn_flush(c);
                continue;
            }
            if (c->kind == CONN_POP3 && c->pg) {
                if (rev & POLLOUT) imapd_pop3_pump(srv, c);
                continue;
            }
            if (c->fg) {
                if (rev & POLLOUT) {
                    imapd_fetch_pump(srv, c);
                    /* The pump buffers output into c->out and only flushes
                       when it reaches IMAPD_MAX_OUT/2; drain any remainder
                       here or a full-but-unflushed buffer leaves poll()
                       reporting POLLOUT forever and the loop spins at 100%
                       CPU without ever sending. */
                    conn_flush(c);
                }
                continue;
            }
            if (imapd_tls_pending(c)) {
                /* the queued plaintext OK/220 reply is still draining; the
                   handshake starts only once it is fully on the wire */
                if (rev & POLLOUT) {
                    conn_flush(c);
                    if (!c->closed && c->out_off >= c->out_len)
                        tls_advance(srv, c, now);
                }
                continue;
            }
            if (imapd_tls_handshaking(c)) {
                if (rev & (POLLIN | POLLOUT | POLLHUP | POLLERR))
                    tls_advance(srv, c, now);
                continue;
            }
            if (rev & (POLLIN | POLLHUP | POLLERR)) {
                if (c->kind == CONN_INGEST)
                    imapd_ingest_readable(srv, c, now);
                else if (c->kind == CONN_POP3)
                    imapd_pop3_readable(srv, c, now);
                else
                    imapd_imap_readable(srv, c, now);
            }
            if (c->kind == CONN_IMAP && c->idle && !c->closed && !c->fg)
                imapd_imap_idle_refresh(srv, c);
            if (!c->closed && (rev & POLLOUT)) conn_flush(c);
        }

        /* destroy closed connections whose output has drained */
        for (i = 0; i < srv->nconns; ) {
            Conn *c = srv->conns[i];
            if (c->closed && c->out_off >= c->out_len) {
                conn_destroy(c);
                srv->conns[i] = srv->conns[srv->nconns - 1];
                srv->nconns--;
            } else {
                i++;
            }
        }
    }
    free(pfds);
}

static void server_accept(ImapdServer *srv, int lfd, int kind, time_t now) {
    for (;;) {
        struct sockaddr_storage sa;
        socklen_t salen = sizeof sa;
        int fd = accept(lfd, (struct sockaddr *)&sa, &salen);
        Conn *c;
        const char *busy = (kind == CONN_INGEST)
            ? "421 4.7.0 Too many connections\r\n"
            : "* BYE too many connections\r\n";
        if (fd < 0) {
            if (errno == EINTR) continue;
            return;   /* EAGAIN/EWOULDBLOCK or error */
        }
        set_nonblock(fd);

        /* connection limits are enforced BEFORE any greeting; POP3 gets no
           message (RFC 1939 has no busy reply), just a silent close */
        if (srv->nconns >= IMAPD_MAX_CONNS) {
            if (kind != CONN_POP3)
                (void)send(fd, busy, strlen(busy), MSG_NOSIGNAL);
            close(fd);
            continue;
        }
        {
            unsigned char ip[16];
            uint8_t iplen = 0;
            (void)peer_ip_of(&sa, salen, ip, &iplen);
            if (iplen != 0 &&
                count_peer_conns(srv, ip, iplen) >= IMAPD_MAX_CONNS_PER_IP) {
                if (kind != CONN_POP3)
                    (void)send(fd, busy, strlen(busy), MSG_NOSIGNAL);
                close(fd);
                continue;
            }
        }

        c = calloc(1, sizeof *c);
        if (!c) { close(fd); continue; }
        c->fd = fd;
        c->kind = kind;
        c->st = ST_INIT;
        c->ist = IST_NOT_AUTH;
        c->pst = PO_AUTH;
        c->last_act = now;
        (void)peer_ip_of(&sa, salen, c->peer_ip, &c->peer_ip_len);

        if (srv->nconns == srv->conn_cap) {
            size_t nc = srv->conn_cap ? srv->conn_cap * 2 : 16;
            Conn **na = realloc(srv->conns, nc * sizeof *na);
            if (!na) { conn_destroy(c); continue; }
            srv->conns = na;
            srv->conn_cap = nc;
        }
        srv->conns[srv->nconns++] = c;

        if (kind == CONN_INGEST)
            imapd_ingest_greeting(srv, c);
        else if (kind == CONN_POP3)
            imapd_pop3_greeting(srv, c);
        else
            imapd_imap_greeting(srv, c);
    }
}

/* ------------------------------------------------------------------ */
/* Listeners                                                           */
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

    snprintf(portstr, sizeof portstr, "%u", port);
    if (getaddrinfo(addr, portstr, &hints, &res) != 0) return -1;

    for (ai = res; ai; ai = ai->ai_next) {
        int s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (s < 0) continue;
        {
            int one = 1;
            (void)setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
        }
        if (bind(s, ai->ai_addr, ai->ai_addrlen) < 0) { close(s); continue; }
        if (listen(s, IMAPD_LISTEN_BACKLOG) < 0) { close(s); continue; }
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

static void config_defaults(ImapdConfig *cfg) {
    memset(cfg, 0, sizeof *cfg);
    cfg->root = env_or("IMAPD_ROOT", IMAPD_DEFAULT_ROOT);
    cfg->ingest_addr = env_or("IMAPD_INGEST_ADDR", "127.0.0.1");
    cfg->ingest_port = (uint16_t)env_num("IMAPD_INGEST_PORT",
                                         IMAPD_DEFAULT_INGEST_PORT);
    cfg->imap_addr = env_or("IMAPD_IMAP_ADDR", "127.0.0.1");
    cfg->imap_port = (uint16_t)env_num("IMAPD_IMAP_PORT",
                                       IMAPD_DEFAULT_IMAP_PORT);
    cfg->pop3_addr = env_or("IMAPD_POP3_ADDR", "127.0.0.1");
    cfg->pop3_port = (uint16_t)env_num("IMAPD_POP3_PORT",
                                       IMAPD_DEFAULT_POP3_PORT);
    cfg->hostname = env_or("IMAPD_HOSTNAME", "localhost");
    cfg->max_msg = (uint32_t)env_num("IMAPD_MAX_MSG", IMAPD_DEFAULT_MAX_MSG);
    cfg->cmd_tmo = IMAPD_DEFAULT_CMD_TMO;
    cfg->data_tmo = IMAPD_DEFAULT_DATA_TMO;
    cfg->cert = env_or("IMAPD_CERT", NULL);
    cfg->key = env_or("IMAPD_KEY", NULL);
}

/* Find the value that follows argv[i] == name (cf. main.c find_arg). */
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

static int config_from_args(ImapdConfig *cfg, int argc, char **argv,
                            int arg_start) {
    const char *v;
    if ((v = find_arg(argc, argv, "--root"))) cfg->root = v;
    if ((v = find_arg(argc, argv, "--ingest-addr"))) cfg->ingest_addr = v;
    if ((v = find_arg(argc, argv, "--imap-addr"))) cfg->imap_addr = v;
    if ((v = find_arg(argc, argv, "--pop3-addr"))) cfg->pop3_addr = v;
    if ((v = find_arg(argc, argv, "--hostname"))) cfg->hostname = v;
    if ((v = find_arg(argc, argv, "--cert"))) cfg->cert = v;
    if ((v = find_arg(argc, argv, "--key"))) cfg->key = v;
    if ((v = find_arg(argc, argv, "--ingest-port")) &&
        parse_u16(v, &cfg->ingest_port) != 0) return -1;
    if ((v = find_arg(argc, argv, "--imap-port")) &&
        parse_u16(v, &cfg->imap_port) != 0) return -1;
    if ((v = find_arg(argc, argv, "--pop3-port")) &&
        parse_u16(v, &cfg->pop3_port) != 0) return -1;
    if ((v = find_arg(argc, argv, "--max-msg"))) {
        unsigned long n;
        char *end;
        n = strtoul(v, &end, 10);
        if (*end != '\0' || n == 0) return -1;
        cfg->max_msg = (uint32_t)n;
    }
    (void)arg_start;
    return 0;
}

/* ------------------------------------------------------------------ */
/* CLI                                                                 */
/* ------------------------------------------------------------------ */

static void usage(FILE *f) {
    fprintf(f,
        "usage: imapd [options]\n"
        "       imapd passwd USER PASSWORD [options]\n"
        "\n"
        "options:\n"
        "  --root DIR           maildir root (env IMAPD_ROOT, default %s)\n"
        "  --ingest-addr ADDR   SMTP ingest bind address (IMAPD_INGEST_ADDR,\n"
        "                       default 127.0.0.1)\n"
        "  --ingest-port N      SMTP ingest port (IMAPD_INGEST_PORT, default %u;\n"
        "                       set visage's relay.host/port to this)\n"
        "  --imap-addr ADDR     IMAP bind address (IMAPD_IMAP_ADDR)\n"
        "  --imap-port N        IMAP port (IMAPD_IMAP_PORT, default %u)\n"
        "  --pop3-addr ADDR     POP3 bind address (IMAPD_POP3_ADDR)\n"
        "  --pop3-port N        POP3 port (IMAPD_POP3_PORT, default %u)\n"
        "  --hostname H         greeted hostname (IMAPD_HOSTNAME)\n"
        "  --max-msg BYTES      max message size (IMAPD_MAX_MSG, default %u)\n"
        "  --cert PATH          TLS certificate PEM (IMAPD_CERT; with --key,\n"
        "                       enables STARTTLS on all listeners)\n"
        "  --key PATH           TLS private key PEM (IMAPD_KEY)\n"
        "  --help               show this help and exit\n"
        "  --version            print the version and exit\n",
        IMAPD_DEFAULT_ROOT, IMAPD_DEFAULT_INGEST_PORT,
        IMAPD_DEFAULT_IMAP_PORT, IMAPD_DEFAULT_POP3_PORT,
        IMAPD_DEFAULT_MAX_MSG);
}

static int cmd_passwd(ImapdConfig *cfg, int argc, char **argv) {
    const char *user, *pass;
    int idx = -1, i;
    for (i = 1; i < argc - 1; i++) {
        if (strcmp(argv[i], "passwd") == 0) { idx = i + 1; break; }
    }
    if (idx < 0 || idx + 1 >= argc ||
        argv[idx][0] == '-' || argv[idx + 1][0] == '-') {
        fprintf(stderr, "imapd: passwd requires USER and PASSWORD\n");
        return 2;
    }
    user = argv[idx];
    pass = argv[idx + 1];
    if (config_from_args(cfg, argc, argv, idx + 2) != 0) {
        fprintf(stderr, "imapd: bad option value\n");
        return 2;
    }
    if (imapd_auth_set(cfg, user, pass) != 0) {
        fprintf(stderr, "imapd: cannot write %s/%s\n", cfg->root,
                IMAPD_PASSWD_FILE);
        return 1;
    }
    printf("ok: %s (in %s/%s)\n", user, cfg->root, IMAPD_PASSWD_FILE);
    return 0;
}

int main(int argc, char **argv) {
    ImapdServer srv;
    ImapdConfig cfg;

    if (argc > 1 && (strcmp(argv[1], "--help") == 0 ||
                     strcmp(argv[1], "-h") == 0)) {
        usage(stdout);
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "--version") == 0) {
        printf("imapd %s\n", VISAGE_VERSION);
        return 0;
    }

    config_defaults(&cfg);

    if (argc > 1 && strcmp(argv[1], "passwd") == 0)
        return cmd_passwd(&cfg, argc, argv);

    if (config_from_args(&cfg, argc, argv, 2) != 0) {
        fprintf(stderr, "imapd: bad option value\n");
        usage(stderr);
        return 2;
    }
    if (argc > 1 && argv[1][0] != '-' && strcmp(argv[1], "passwd") != 0) {
        fprintf(stderr, "imapd: unknown command '%s'\n\n", argv[1]);
        usage(stderr);
        return 2;
    }

    memset(&srv, 0, sizeof srv);
    srv.cfg = cfg;

    if (imapd_auth_load(&srv.cfg, &srv) != 0) {
        fprintf(stderr, "imapd: cannot load %s/%s\n", cfg.root,
                IMAPD_PASSWD_FILE);
        return 1;
    }
    if (srv.ncreds == 0)
        fprintf(stderr,
                "imapd: WARNING no users configured (%s/%s missing or "
                "empty); IMAP AUTH will fail until you run "
                "`imapd passwd USER PASS`\n", cfg.root, IMAPD_PASSWD_FILE);

    srv.listen_ingest = make_listener(cfg.ingest_addr, cfg.ingest_port);
    if (srv.listen_ingest < 0) {
        fprintf(stderr, "imapd: cannot listen on %s:%u\n",
                cfg.ingest_addr, cfg.ingest_port);
        return 1;
    }
    srv.listen_imap = make_listener(cfg.imap_addr, cfg.imap_port);
    if (srv.listen_imap < 0) {
        fprintf(stderr, "imapd: cannot listen on %s:%u\n",
                cfg.imap_addr, cfg.imap_port);
        return 1;
    }
    srv.listen_pop3 = make_listener(cfg.pop3_addr, cfg.pop3_port);
    if (srv.listen_pop3 < 0) {
        fprintf(stderr, "imapd: cannot listen on %s:%u\n",
                cfg.pop3_addr, cfg.pop3_port);
        return 1;
    }

    /* STARTTLS: load cert/key (fail-closed => exit) and pin the RFC 3501
       11.1 / RFC 2595 gating binds (cleartext auth only on loopback when
       TLS is on). */
    srv.imap_loopback = imapd_addr_loopback(cfg.imap_addr);
    srv.pop3_loopback = imapd_addr_loopback(cfg.pop3_addr);
    if (imapd_tls_global_init(&srv) != 0) return 1;

    printf("imapd %s: smtp ingest on %s:%u, imap on %s:%u, pop3 on %s:%u, "
           "root %s, tls %s\n",
           VISAGE_VERSION,
           cfg.ingest_addr, cfg.ingest_port,
           cfg.imap_addr, cfg.imap_port,
           cfg.pop3_addr, cfg.pop3_port, cfg.root,
           srv.tls_ready ? "on (STARTTLS)" : "off");
    fflush(stdout);

    server_poll(&srv);

    close(srv.listen_ingest);
    close(srv.listen_imap);
    close(srv.listen_pop3);
    return 0;
}
