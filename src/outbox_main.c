/* outbox_main.c — CLI/env, listeners, and poll loop for the outbox daemon.
 *
 * Configuration is flags + env ONLY (the imapd precedent): no Dhall/datalog,
 * so outbox links the same lightweight set of objects imapd.com does.
 *
 * TLS is fail-closed: --cert/--key (or OUTBOX_CERT/OUTBOX_KEY) are REQUIRED
 * (both listeners are public by default, and AUTH must never run in the
 * clear).  The :465 listener is implicit-TLS (TLS on accept); the :587
 * listener is STARTTLS.  smtp_in_tls.c supplies the mbedTLS SERVER role over
 * these non-blocking fds, driven exactly like smtp_in.c drives it.
 *
 * FOLLOW-UP (out of scope for v1): delivery was INLINE and blocking at DATA
 * time — that wedged the single poll thread whenever a delivery was in flight
 * (notably the reverse-alias reply, whose first leg targets the local ingress
 * that then connects BACK here to finish).  Delivery is now handed to a single
 * worker thread via a lock-protected queue (outbox_deliver.c): the poll loop
 * only accepts/acks and never blocks on outbound SMTP/DNS.  v1 still does not
 * re-drive the spool files after a crash (a durable queue is the next slice);
 * see spool_message() in outbox_submit.c.
 */
#include "outbox.h"
#include "visage.h"
#include "auth_results.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <poll.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <time.h>
#include <dirent.h>
#include <signal.h>

/* ------------------------------------------------------------------ */
/* Small helpers                                                      */
/* ------------------------------------------------------------------ */

static void set_nonblock(int fd) {
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl < 0) return;
    (void)fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

/* ------------------------------------------------------------------ */
/* Graceful shutdown                                                  */
/* ------------------------------------------------------------------ */

/* SIGTERM/SIGINT: set g_stop and poke the poll loop through a self-pipe so it
 * exits promptly no matter which thread the signal was delivered to, then the
 * delivery worker is drained and joined (no accepted mail lost on a clean
 * stop). */
static volatile sig_atomic_t g_stop;
static int g_sigpipe[2] = {-1, -1};

static void on_signal(int sig) {
    (void)sig;
    g_stop = 1;
    if (g_sigpipe[1] >= 0) {
        char b = 'x';
        ssize_t ignored = write(g_sigpipe[1], &b, 1);
        (void)ignored;
    }
}

/* Best-effort: failure leaves the default signal disposition (immediate
 * termination), which is still safe — every accepted message is spooled to
 * disk before it is acknowledged. */
static int install_signal_handlers(void) {
    struct sigaction sa;
    if (pipe(g_sigpipe) != 0) return -1;
    set_nonblock(g_sigpipe[0]);
    set_nonblock(g_sigpipe[1]);
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;   /* no SA_RESTART: poll()/read() return EINTR promptly */
    if (sigaction(SIGTERM, &sa, NULL) != 0 ||
        sigaction(SIGINT, &sa, NULL) != 0) {
        close(g_sigpipe[0]);
        close(g_sigpipe[1]);
        g_sigpipe[0] = g_sigpipe[1] = -1;
        return -1;
    }
    return 0;
}

/* Extract the peer address bytes (AF_INET -> 4, AF_INET6 -> 16). */
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

static size_t count_peer_conns(const OutboxServer *srv, const unsigned char *ip,
                               uint8_t iplen) {
    size_t n = 0, i;
    if (iplen == 0) return 0;
    for (i = 0; i < srv->nconns; i++) {
        const OutboxConn *c = srv->conns[i];
        if (c->peer_ip_len == iplen && memcmp(c->peer_ip, ip, iplen) == 0)
            n++;
    }
    return n;
}

/* ------------------------------------------------------------------ */
/* Listeners                                                          */
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
        if (listen(s, OUTBOX_LISTEN_BACKLOG) < 0) { close(s); continue; }
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

/* Find the value that follows argv[i] == name. */
static const char *find_arg(int argc, char **argv, const char *name) {
    int i;
    for (i = 1; i < argc - 1; i++)
        if (strcmp(argv[i], name) == 0) return argv[i + 1];
    return NULL;
}

static int parse_port(const char *s, uint16_t *out, bool allow_zero) {
    unsigned long n;
    char *end;
    if (!s || !s[0]) return -1;
    n = strtoul(s, &end, 10);
    if (*end != '\0' || n > 65535) return -1;
    if (n == 0 && !allow_zero) return -1;
    *out = (uint16_t)n;
    return 0;
}

static int parse_u32(const char *s, uint32_t *out) {
    unsigned long n;
    char *end;
    if (!s || !s[0]) return -1;
    n = strtoul(s, &end, 10);
    if (*end != '\0' || n > UINT32_MAX) return -1;
    *out = (uint32_t)n;
    return 0;
}

static int parse_u64(const char *s, uint64_t *out) {
    unsigned long long n;
    char *end;
    if (!s || !s[0]) return -1;
    n = strtoull(s, &end, 10);
    if (*end != '\0') return -1;
    *out = (uint64_t)n;
    return 0;
}

/* Append a DOMAIN=KEYFILE entry to cfg->dkim.  Returns 0, or -1 on OOM. */
static int dkim_add(OutboxConfig *cfg, const char *domain, const char *key) {
    OutboxDkim *nd = realloc(cfg->dkim, (cfg->ndkim + 1) * sizeof *nd);
    if (!nd) return -1;
    cfg->dkim = nd;
    cfg->dkim[cfg->ndkim].domain = strdup(domain);
    cfg->dkim[cfg->ndkim].key = strdup(key);
    if (!cfg->dkim[cfg->ndkim].domain || !cfg->dkim[cfg->ndkim].key)
        return -1;
    cfg->ndkim++;
    return 0;
}

/* Split a comma list into *list / *n (append).  Returns 0, or -1 on OOM. */
static int domains_parse_into(char ***list, size_t *n, const char *liststr) {
    const char *p = liststr;
    while (p && *p) {
        const char *comma = strchr(p, ',');
        size_t len = comma ? (size_t)(comma - p) : strlen(p);
        char **nd;
        char *d;
        while (len > 0 && (p[len - 1] == ' ' || p[len - 1] == '\t')) len--;
        while (len > 0 && (*p == ' ' || *p == '\t')) { p++; len--; }
        if (len == 0) {
            p = comma ? comma + 1 : p + strlen(p);
            continue;
        }
        d = malloc(len + 1);
        if (!d) return -1;
        memcpy(d, p, len);
        d[len] = '\0';
        nd = realloc(*list, (*n + 1) * sizeof *nd);
        if (!nd) { free(d); return -1; }
        *list = nd;
        (*list)[(*n)++] = d;
        p = comma ? comma + 1 : p + strlen(p);
    }
    return 0;
}

/* Split a comma list into cfg->domains.  Returns 0, or -1 on OOM. */
static int domains_parse(OutboxConfig *cfg, const char *list) {
    return domains_parse_into(&cfg->domains, &cfg->ndomains, list);
}

/* Parse one "DOMAIN=KEYFILE" token. */
static int dkim_parse_one(OutboxConfig *cfg, const char *tok) {
    const char *eq = strchr(tok, '=');
    char *domain, *key;
    int rc;
    if (!eq || eq == tok || !eq[1]) return -1;
    domain = malloc((size_t)(eq - tok) + 1);
    if (!domain) return -1;
    memcpy(domain, tok, (size_t)(eq - tok));
    domain[eq - tok] = '\0';
    key = strdup(eq + 1);
    if (!key) { free(domain); return -1; }
    rc = dkim_add(cfg, domain, key);
    free(domain);
    free(key);
    return rc;
}

/* Scan <dir> for *.key files into DOMAIN=KEYFILE entries
 * (domain = basename minus the ".key" suffix). */
static int dkim_scan_dir(OutboxConfig *cfg, const char *dir) {
    DIR *d = opendir(dir);
    struct dirent *e;
    if (!d) return -1;
    while ((e = readdir(d)) != NULL) {
        size_t n = strlen(e->d_name);
        char *domain, *path;
        if (n <= 4 || strcmp(e->d_name + n - 4, ".key") != 0) continue;
        if (e->d_name[0] == '.') continue;
        domain = malloc(n - 4 + 1);
        if (!domain) { closedir(d); return -1; }
        memcpy(domain, e->d_name, n - 4);
        domain[n - 4] = '\0';
        if (strlen(dir) + 1 + n + 1 > 4096) {
            free(domain);
            continue;
        }
        path = malloc(strlen(dir) + 1 + n + 1);
        if (!path) { free(domain); closedir(d); return -1; }
        sprintf(path, "%s/%s", dir, e->d_name);
        if (dkim_add(cfg, domain, path) != 0) {
            free(domain);
            free(path);
            closedir(d);
            return -1;
        }
        free(domain);
        free(path);
    }
    closedir(d);
    return 0;
}

static void config_defaults(OutboxConfig *cfg) {
    memset(cfg, 0, sizeof *cfg);
    cfg->implicit_addr = strdup(env_or("OUTBOX_IMPLICIT_ADDR", "0.0.0.0"));
    cfg->implicit_port = (uint16_t)env_num("OUTBOX_IMPLICIT_PORT", 465);
    cfg->starttls_addr = strdup(env_or("OUTBOX_STARTTLS_ADDR", "0.0.0.0"));
    cfg->starttls_port = (uint16_t)env_num("OUTBOX_STARTTLS_PORT", 587);
    cfg->cert = strdup(env_or("OUTBOX_CERT", ""));
    cfg->key = strdup(env_or("OUTBOX_KEY", ""));
    cfg->passwd = strdup(env_or("OUTBOX_PASSWD", "./outbox.passwd"));
    cfg->hostname = strdup(env_or("OUTBOX_HOSTNAME", "localhost"));
    cfg->spool = strdup(env_or("OUTBOX_SPOOL", "./var/outbox-spool"));
    cfg->max_msg = (uint32_t)env_num("OUTBOX_MAX_MSG", OUTBOX_DEFAULT_MAX_MSG);
    cfg->max_line = (uint32_t)env_num("OUTBOX_MAX_LINE", SMTP_MAX_LINE);
    cfg->max_rcpts = (uint32_t)env_num("OUTBOX_MAX_RCPTS", OUTBOX_DEFAULT_MAX_RCPTS);
    cfg->cmd_tmo = (uint32_t)env_num("OUTBOX_CMD_TIMEOUT", OUTBOX_DEFAULT_CMD_TMO);
    cfg->data_tmo = (uint32_t)env_num("OUTBOX_DATA_TIMEOUT", OUTBOX_DEFAULT_DATA_TMO);
    cfg->max_attempts = (uint32_t)env_num("OUTBOX_MAX_ATTEMPTS", OUTBOX_DEFAULT_MAX_ATTEMPTS);
    cfg->deliver_port = (uint16_t)env_num("OUTBOX_DELIVER_PORT", OUTBOX_DEFAULT_DELIVER_PORT);
    cfg->dns_server = strdup(env_or("OUTBOX_DNS_SERVER", ""));
    cfg->queue_max_jobs = (uint32_t)env_num("OUTBOX_QUEUE_MAX_JOBS",
                                            OUTBOX_DEFAULT_QUEUE_MAX_JOBS);
    cfg->queue_max_bytes = env_num("OUTBOX_QUEUE_MAX_BYTES",
                                   OUTBOX_DEFAULT_QUEUE_MAX_BYTES);
    cfg->internal_relay_host = strdup(env_or("OUTBOX_INTERNAL_RELAY_HOST", ""));
    cfg->internal_relay_port = (uint16_t)env_num("OUTBOX_INTERNAL_RELAY_PORT",
                                                 OUTBOX_DEFAULT_INTERNAL_RELAY_PORT);
    cfg->internal_relay_tls = strdup(env_or("OUTBOX_INTERNAL_RELAY_TLS", "implicit"));
    cfg->internal_relay_user = strdup(env_or("OUTBOX_INTERNAL_RELAY_USER", ""));
    cfg->internal_relay_pass = strdup(env_or("OUTBOX_INTERNAL_RELAY_PASS", ""));
    {
        const char *idom = getenv("OUTBOX_INTERNAL_DOMAINS");
        if (idom && idom[0])
            (void)domains_parse_into(&cfg->internal_domains,
                                     &cfg->ninternal_domains, idom);
    }
    (void)domains_parse(cfg, env_or("OUTBOX_DOMAINS",
                                    "jaye.ch,blackarts.tech,jurassicpeak.com"));
    {
        const char *dkim_env = getenv("OUTBOX_DKIM");
        if (dkim_env && dkim_env[0]) {
            char *tmp = strdup(dkim_env);
            char *tok, *save = NULL;
            if (tmp) {
                for (tok = strtok_r(tmp, ",;", &save); tok;
                     tok = strtok_r(NULL, ",;", &save))
                    (void)dkim_parse_one(cfg, tok);
                free(tmp);
            }
        }
    }
    {
        const char *dkdir = getenv("OUTBOX_DKIM_DIR");
        if (dkdir && dkdir[0]) (void)dkim_scan_dir(cfg, dkdir);
    }
}

/* Apply CLI flags over the env defaults.  Returns 0, or -1 on a bad value. */
static int config_from_args(OutboxConfig *cfg, int argc, char **argv) {
    const char *v;
    int i;

    if ((v = find_arg(argc, argv, "--implicit-addr"))) { free(cfg->implicit_addr); cfg->implicit_addr = strdup(v); }
    if ((v = find_arg(argc, argv, "--starttls-addr"))) { free(cfg->starttls_addr); cfg->starttls_addr = strdup(v); }
    if ((v = find_arg(argc, argv, "--cert"))) { free(cfg->cert); cfg->cert = strdup(v); }
    if ((v = find_arg(argc, argv, "--key"))) { free(cfg->key); cfg->key = strdup(v); }
    if ((v = find_arg(argc, argv, "--passwd"))) { free(cfg->passwd); cfg->passwd = strdup(v); }
    if ((v = find_arg(argc, argv, "--hostname"))) { free(cfg->hostname); cfg->hostname = strdup(v); }
    if ((v = find_arg(argc, argv, "--spool"))) { free(cfg->spool); cfg->spool = strdup(v); }
    if ((v = find_arg(argc, argv, "--dns-server"))) { free(cfg->dns_server); cfg->dns_server = strdup(v); }
    if ((v = find_arg(argc, argv, "--domains"))) {
        size_t k;
        for (k = 0; k < cfg->ndomains; k++) free(cfg->domains[k]);
        free(cfg->domains);
        cfg->domains = NULL;
        cfg->ndomains = 0;
        if (domains_parse(cfg, v) != 0) return -1;
    }
    if ((v = find_arg(argc, argv, "--internal-domains"))) {
        size_t k;
        for (k = 0; k < cfg->ninternal_domains; k++)
            free(cfg->internal_domains[k]);
        free(cfg->internal_domains);
        cfg->internal_domains = NULL;
        cfg->ninternal_domains = 0;
        if (domains_parse_into(&cfg->internal_domains, &cfg->ninternal_domains,
                               v) != 0) return -1;
    }
    if ((v = find_arg(argc, argv, "--internal-relay-host"))) {
        free(cfg->internal_relay_host); cfg->internal_relay_host = strdup(v);
    }
    if ((v = find_arg(argc, argv, "--internal-relay-tls"))) {
        free(cfg->internal_relay_tls); cfg->internal_relay_tls = strdup(v);
    }
    if ((v = find_arg(argc, argv, "--internal-relay-user"))) {
        free(cfg->internal_relay_user); cfg->internal_relay_user = strdup(v);
    }
    if ((v = find_arg(argc, argv, "--internal-relay-pass"))) {
        free(cfg->internal_relay_pass); cfg->internal_relay_pass = strdup(v);
    }
    if ((v = find_arg(argc, argv, "--internal-relay-port")) &&
        parse_port(v, &cfg->internal_relay_port, false) != 0) return -1;
    if ((v = find_arg(argc, argv, "--implicit-port")) &&
        parse_port(v, &cfg->implicit_port, true) != 0) return -1;
    if ((v = find_arg(argc, argv, "--starttls-port")) &&
        parse_port(v, &cfg->starttls_port, true) != 0) return -1;
    if ((v = find_arg(argc, argv, "--deliver-port")) &&
        parse_port(v, &cfg->deliver_port, false) != 0) return -1;
    if ((v = find_arg(argc, argv, "--queue-max-jobs")) &&
        parse_u32(v, &cfg->queue_max_jobs) != 0) return -1;
    if ((v = find_arg(argc, argv, "--queue-max-bytes")) &&
        parse_u64(v, &cfg->queue_max_bytes) != 0) return -1;
    if ((v = find_arg(argc, argv, "--max-msg")) &&
        parse_u32(v, &cfg->max_msg) != 0) return -1;
    if ((v = find_arg(argc, argv, "--max-line")) &&
        parse_u32(v, &cfg->max_line) != 0) return -1;
    if ((v = find_arg(argc, argv, "--max-rcpts")) &&
        parse_u32(v, &cfg->max_rcpts) != 0) return -1;
    if ((v = find_arg(argc, argv, "--cmd-timeout")) &&
        parse_u32(v, &cfg->cmd_tmo) != 0) return -1;
    if ((v = find_arg(argc, argv, "--data-timeout")) &&
        parse_u32(v, &cfg->data_tmo) != 0) return -1;
    if ((v = find_arg(argc, argv, "--max-attempts")) &&
        parse_u32(v, &cfg->max_attempts) != 0) return -1;
    if ((v = find_arg(argc, argv, "--dkim-dir"))) {
        if (dkim_scan_dir(cfg, v) != 0) return -1;
    }
    /* Repeatable --dkim DOMAIN=KEYFILE */
    for (i = 1; i < argc - 1; i++) {
        if (strcmp(argv[i], "--dkim") == 0) {
            if (dkim_parse_one(cfg, argv[i + 1]) != 0) return -1;
        }
    }
    return 0;
}

void outbox_config_free(OutboxConfig *cfg) {
    size_t i;
    free(cfg->implicit_addr);
    free(cfg->starttls_addr);
    free(cfg->cert);
    free(cfg->key);
    free(cfg->passwd);
    free(cfg->hostname);
    free(cfg->spool);
    free(cfg->dns_server);
    free(cfg->internal_relay_host);
    free(cfg->internal_relay_tls);
    free(cfg->internal_relay_user);
    free(cfg->internal_relay_pass);
    for (i = 0; i < cfg->ndomains; i++) free(cfg->domains[i]);
    free(cfg->domains);
    for (i = 0; i < cfg->ninternal_domains; i++)
        free(cfg->internal_domains[i]);
    free(cfg->internal_domains);
    for (i = 0; i < cfg->ndkim; i++) {
        free(cfg->dkim[i].domain);
        free(cfg->dkim[i].key);
    }
    free(cfg->dkim);
}

/* ------------------------------------------------------------------ */
/* CLI                                                                 */
/* ------------------------------------------------------------------ */

static void usage(FILE *f) {
    fprintf(f,
        "usage: outbox [options]\n"
        "\n"
        "options (flags override env):\n"
        "  --implicit-addr ADDR  SMTPS listener bind (OUTBOX_IMPLICIT_ADDR,\n"
        "                        default 0.0.0.0)\n"
        "  --implicit-port N     SMTPS listener port (OUTBOX_IMPLICIT_PORT,\n"
        "                        default 465; 0 disables)\n"
        "  --starttls-addr ADDR  STARTTLS listener bind (OUTBOX_STARTTLS_ADDR,\n"
        "                        default 0.0.0.0)\n"
        "  --starttls-port N     STARTTLS listener port (OUTBOX_STARTTLS_PORT,\n"
        "                        default 587; 0 disables)\n"
        "  --cert PATH           TLS certificate PEM (OUTBOX_CERT; required)\n"
        "  --key PATH            TLS private key PEM (OUTBOX_KEY; required)\n"
        "  --passwd PATH         shared 'user:pass' credential file\n"
        "                        (OUTBOX_PASSWD, default ./outbox.passwd)\n"
        "  --domains LIST        comma-separated allowed From domains\n"
        "                        (OUTBOX_DOMAINS; default\n"
        "                        jaye.ch,blackarts.tech,jurassicpeak.com)\n"
        "  --dkim DOMAIN=KEYFILE DKIM signing key for DOMAIN (repeatable;\n"
        "                        OUTBOX_DKIM is a comma/semicolon list)\n"
        "  --dkim-dir DIR        scan DIR/*.key as <domain>.key (OUTBOX_DKIM_DIR)\n"
        "  --hostname H          EHLO + greeting hostname (OUTBOX_HOSTNAME)\n"
        "  --spool DIR           best-effort spool dir (OUTBOX_SPOOL)\n"
        "  --max-msg BYTES       max message size (OUTBOX_MAX_MSG)\n"
        "  --max-line BYTES      max command line (OUTBOX_MAX_LINE)\n"
        "  --max-rcpts N         max recipients (OUTBOX_MAX_RCPTS)\n"
        "  --cmd-timeout SEC     command idle timeout (OUTBOX_CMD_TIMEOUT)\n"
        "  --data-timeout SEC    DATA idle timeout (OUTBOX_DATA_TIMEOUT)\n"
        "  --max-attempts N      per-recipient MX delivery attempts\n"
        "                        (OUTBOX_MAX_ATTEMPTS)\n"
        "  --deliver-port N      direct-delivery port (OUTBOX_DELIVER_PORT,\n"
        "                        default 25; a test/dev knob)\n"
        "  --queue-max-jobs N    delivery-queue job cap (OUTBOX_QUEUE_MAX_JOBS,\n"
        "                        default 1024; 0 = default)\n"
        "  --queue-max-bytes N   delivery-queue message-byte cap\n"
        "                        (OUTBOX_QUEUE_MAX_BYTES, default 268435456;\n"
        "                        0 = default; full queue replies 452 at DATA)\n"
        "  --internal-relay-host HOST  internal-domain relay host (visage MX);\n"
        "                        empty disables internal routing\n"
        "                        (OUTBOX_INTERNAL_RELAY_HOST)\n"
        "  --internal-relay-port N     internal relay port\n"
        "                        (OUTBOX_INTERNAL_RELAY_PORT, default 2525)\n"
        "  --internal-relay-tls MODE   \"none\" | \"starttls\" | \"implicit\"\n"
        "                        (OUTBOX_INTERNAL_RELAY_TLS, default implicit)\n"
        "  --internal-relay-user USER  AUTH PLAIN username for the internal\n"
        "                        relay (OUTBOX_INTERNAL_RELAY_USER; empty = none)\n"
        "  --internal-relay-pass PASS  AUTH PLAIN password\n"
        "                        (OUTBOX_INTERNAL_RELAY_PASS)\n"
        "  --internal-domains LIST     comma list routed to the internal relay\n"
        "                        (OUTBOX_INTERNAL_DOMAINS; default = --domains)\n"
        "  --dns-server ADDR[:PORT]  DNS resolver override (OUTBOX_DNS_SERVER;\n"
        "                        default: first nameserver in /etc/resolv.conf)\n"
        "  --help                show this help and exit\n"
        "  --version             print the version and exit\n");
}

/* ------------------------------------------------------------------ */
/* Event loop                                                         */
/* ------------------------------------------------------------------ */

static uint32_t conn_timeout(const OutboxServer *srv, const OutboxConn *c) {
    return (c->state == OB_ST_DATA) ? srv->data_tmo : srv->cmd_tmo;
}

static void tls_advance(OutboxServer *srv, OutboxConn *c, time_t now) {
    int r;
    c->last_act = now;
    r = smtp_in_tls_handshake_step(c->tls);
    if (r < 0) {
        c->closed = true;
        c->out_len = c->out_off = 0;
        return;
    }
    if (r > 0) {
        /* TLS is up.  Implicit-TLS: this is the first contact -> 220 now.
           STARTTLS: session restart (RFC 3207: the client must EHLO again). */
        if (c->implicit_tls && !c->greeted) {
            char g[512];
            int gn = snprintf(g, sizeof g, "220 %s ESMTP outbox\r\n",
                              (srv->cfg.hostname && srv->cfg.hostname[0])
                                  ? srv->cfg.hostname : "localhost");
            c->greeted = true;
            c->state = OB_ST_INIT;
            outbox_conn_reply(c, (gn < 0 || (size_t)gn >= sizeof g)
                                     ? "220 localhost ESMTP outbox\r\n" : g);
            outbox_conn_readable(srv, c, now);
            return;
        }
        c->authenticated = false;
        free(c->auth_user);
        c->auth_user = NULL;
        outbox_conn_reset_txn(c, OB_ST_INIT);
        outbox_conn_readable(srv, c, now);
    }
}

static int poll_timeout_ms(const OutboxServer *srv, time_t now) {
    int ms = -1;
    size_t i;
    for (i = 0; i < srv->nconns; i++) {
        const OutboxConn *c = srv->conns[i];
        uint32_t tmo = conn_timeout(srv, c);
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
    return ms;
}

static void server_accept(OutboxServer *srv, int lfd, bool implicit_tls,
                          time_t now) {
    for (;;) {
        struct sockaddr_storage sa;
        socklen_t salen = sizeof sa;
        int fd = accept(lfd, (struct sockaddr *)&sa, &salen);
        OutboxConn *c;

        if (fd < 0) {
            if (errno == EINTR) continue;
            return;
        }
        set_nonblock(fd);

        if (srv->nconns >= OUTBOX_MAX_CONNS) {
            const char busy[] = "421 4.7.0 Too many connections\r\n";
            (void)send(fd, busy, sizeof busy - 1, MSG_NOSIGNAL);
            close(fd);
            continue;
        }
        {
            unsigned char ip[16];
            uint8_t iplen = 0;
            (void)peer_ip_of(&sa, salen, ip, &iplen);
            if (iplen != 0 &&
                count_peer_conns(srv, ip, iplen) >= OUTBOX_MAX_CONNS_PER_IP) {
                const char busy[] = "421 4.7.0 Too many connections\r\n";
                (void)send(fd, busy, sizeof busy - 1, MSG_NOSIGNAL);
                close(fd);
                continue;
            }
        }

        c = calloc(1, sizeof *c);
        if (!c) { close(fd); continue; }
        c->fd = fd;
        c->state = OB_ST_INIT;
        c->implicit_tls = implicit_tls;
        c->last_act = now;
        (void)peer_ip_of(&sa, salen, c->peer_ip, &c->peer_ip_len);

        if (implicit_tls) {
            /* SMTPS: TLS starts immediately (no plaintext PROXY support). */
            if (!(c->tls = smtp_in_tls_start(fd))) {
                close(fd);
                free(c);
                continue;
            }
        }

        if (srv->nconns == srv->conn_cap) {
            size_t nc = srv->conn_cap ? srv->conn_cap * 2 : 16;
            OutboxConn **na = realloc(srv->conns, nc * sizeof *na);
            if (!na) { outbox_conn_destroy(c); continue; }
            srv->conns = na;
            srv->conn_cap = nc;
        }
        srv->conns[srv->nconns++] = c;

        if (implicit_tls) continue;   /* 220 goes out once TLS is established */

        {
            char g[512];
            int gn = snprintf(g, sizeof g, "220 %s ESMTP outbox\r\n",
                              (srv->cfg.hostname && srv->cfg.hostname[0])
                                  ? srv->cfg.hostname : "localhost");
            outbox_conn_reply(c, (gn < 0 || (size_t)gn >= sizeof g)
                                     ? "220 localhost ESMTP outbox\r\n" : g);
            c->greeted = true;
        }
    }
}

static void server_poll(OutboxServer *srv) {
    struct pollfd *pfds = NULL;
    size_t pfds_cap = 0;

    for (;;) {
        time_t now = time(NULL);
        size_t nfds, n_before, i;

        /* idle timeout */
        for (i = 0; i < srv->nconns; i++) {
            OutboxConn *c = srv->conns[i];
            uint32_t tmo = conn_timeout(srv, c);
            if (tmo != 0 && now > c->last_act &&
                (now - c->last_act) >= (time_t)tmo) {
                if (smtp_in_tls_handshaking(c->tls)) {
                    c->closed = true;
                    c->out_len = c->out_off = 0;
                    continue;
                }
                outbox_conn_reply(c, "421 4.4.2 Timeout - closing connection\r\n");
                c->closed = true;
            }
        }

        nfds = 3 + srv->nconns;
        if (nfds > pfds_cap) {
            free(pfds);
            pfds = malloc(nfds * sizeof *pfds);
            if (!pfds) break;
            pfds_cap = nfds;
        }
        pfds[0].fd = srv->listen_starttls;
        pfds[0].events = POLLIN;
        pfds[0].revents = 0;
        pfds[1].fd = srv->listen_implicit;
        pfds[1].events = (srv->listen_implicit >= 0) ? POLLIN : 0;
        pfds[1].revents = 0;
        pfds[2].fd = g_sigpipe[0];
        pfds[2].events = POLLIN;
        pfds[2].revents = 0;
        for (i = 0; i < srv->nconns; i++) {
            OutboxConn *c = srv->conns[i];
            pfds[3 + i].fd = c->fd;
            if (!c->closed && smtp_in_tls_handshaking(c->tls)) {
                pfds[3 + i].events = smtp_in_tls_pending(c->tls)
                    ? POLLOUT
                    : (smtp_in_tls_wants_write(c->tls) ? POLLOUT : POLLIN);
            } else if (c->closed) {
                pfds[3 + i].events = (c->out_off < c->out_len) ? POLLOUT : 0;
            } else {
                pfds[3 + i].events =
                    (c->out_len < OUTBOX_MAX_OUT / 2) ? POLLIN : 0;
                if (c->out_off < c->out_len) pfds[3 + i].events |= POLLOUT;
            }
            pfds[3 + i].revents = 0;
        }

        {
            int tmo = poll_timeout_ms(srv, now);
            int pr = poll(pfds, nfds, tmo);
            if (pr < 0) {
                if (errno == EINTR) {
                    if (g_stop) break;
                    continue;
                }
                break;
            }
        }

        if (pfds[2].revents & POLLIN) {
            /* shutdown signal: drain the self-pipe and leave the loop */
            char tmp[64];
            while (read(g_sigpipe[0], tmp, sizeof tmp) > 0) {}
            break;
        }

        n_before = srv->nconns;

        if (pfds[0].revents & POLLIN)
            server_accept(srv, srv->listen_starttls, false, now);
        if (pfds[1].revents & POLLIN)
            server_accept(srv, srv->listen_implicit, true, now);

        for (i = 0; i < n_before; i++) {
            OutboxConn *c = srv->conns[i];
            short rev = pfds[3 + i].revents;
            if (c->closed) {
                if (rev & POLLOUT) outbox_conn_flush(c);
                continue;
            }
            if (smtp_in_tls_pending(c->tls)) {
                if (rev & POLLOUT) {
                    outbox_conn_flush(c);
                    if (!c->closed && c->out_off >= c->out_len)
                        tls_advance(srv, c, now);
                }
                continue;
            }
            if (smtp_in_tls_handshaking(c->tls)) {
                if (rev & (POLLIN | POLLOUT | POLLHUP | POLLERR))
                    tls_advance(srv, c, now);
                continue;
            }
            if (rev & (POLLIN | POLLHUP | POLLERR))
                outbox_conn_readable(srv, c, now);
            if (!c->closed && (rev & POLLOUT))
                outbox_conn_flush(c);
        }

        /* destroy closed connections whose output has drained */
        for (i = 0; i < srv->nconns; ) {
            OutboxConn *c = srv->conns[i];
            if (c->closed && c->out_off >= c->out_len) {
                outbox_conn_destroy(c);
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
/* Entry point                                                         */
/* ------------------------------------------------------------------ */

int outbox_main(int argc, char **argv) {
    OutboxServer srv;
    OutboxConfig cfg;

    if (argc > 1 && (strcmp(argv[1], "--help") == 0 ||
                     strcmp(argv[1], "-h") == 0)) {
        usage(stdout);
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "--version") == 0) {
        printf("outbox %s\n", VISAGE_VERSION);
        return 0;
    }

    config_defaults(&cfg);
    if (config_from_args(&cfg, argc, argv) != 0) {
        fprintf(stderr, "outbox: bad option value\n\n");
        usage(stderr);
        outbox_config_free(&cfg);
        return 2;
    }
    if (argc > 1 && argv[1][0] != '-') {
        fprintf(stderr, "outbox: unknown command '%s'\n\n", argv[1]);
        usage(stderr);
        outbox_config_free(&cfg);
        return 2;
    }

    /* TLS is mandatory for the submission security model (fail-closed). */
    if (!cfg.cert || !cfg.cert[0] || !cfg.key || !cfg.key[0]) {
        fprintf(stderr, "outbox: --cert and --key are required (AUTH must not "
                        "run in the clear)\n");
        outbox_config_free(&cfg);
        return 1;
    }

    /* Fail-closed: a configured internal relay requires a supported TLS mode. */
    if (cfg.internal_relay_host && cfg.internal_relay_host[0] &&
        smtp_tls_valid(cfg.internal_relay_tls) != 0) {
        fprintf(stderr, "outbox: --internal-relay-tls must be \"none\", "
                        "\"starttls\", or \"implicit\"\n");
        outbox_config_free(&cfg);
        return 1;
    }

    memset(&srv, 0, sizeof srv);
    srv.cfg = cfg;   /* move ownership of the parsed config into srv */

    if (outbox_auth_load(srv.cfg.passwd, &srv.auth) != 0) {
        fprintf(stderr, "outbox: cannot load %s\n", srv.cfg.passwd);
        outbox_config_free(&srv.cfg);
        return 1;
    }
    if (srv.auth.ncreds == 0)
        fprintf(stderr, "outbox: WARNING no users configured (%s missing or "
                        "empty); AUTH will fail until a user:pass line is "
                        "added\n", srv.cfg.passwd);

    /* Effective limits. */
    srv.max_line = srv.cfg.max_line ? srv.cfg.max_line : SMTP_MAX_LINE;
    srv.max_msg = srv.cfg.max_msg ? srv.cfg.max_msg : OUTBOX_DEFAULT_MAX_MSG;
    srv.max_rcpts = srv.cfg.max_rcpts;
    srv.cmd_tmo = srv.cfg.cmd_tmo ? srv.cfg.cmd_tmo : OUTBOX_DEFAULT_CMD_TMO;
    srv.data_tmo = srv.cfg.data_tmo ? srv.cfg.data_tmo : OUTBOX_DEFAULT_DATA_TMO;
    srv.raw_cap = (uint64_t)srv.max_msg * 2 + 16;

    /* One-shot delivery config for smtp_out_send_host (opportunistic STARTTLS,
       no relay auth, no internal retries — outbox drives the MX loop). */
    memset(&srv.deliver_cfg, 0, sizeof srv.deliver_cfg);
    srv.deliver_cfg.hostname = srv.cfg.hostname;
    srv.deliver_cfg.relay.tls = "starttls";
    srv.deliver_cfg.relay.auth.enabled = false;
    srv.deliver_cfg.relay.retries = 0;
    srv.deliver_cfg.limits.cmd_timeout = srv.cmd_tmo;
    srv.deliver_cfg.limits.data_timeout = srv.data_tmo;

    /* One-shot delivery config for internal-domain routing to the visage MX
       (TLS mode + optional AUTH from --internal-relay-*; retries == 0 so the
       worker's own attempt loop drives backoff).  Only reached when a recipient
       domain is internal AND internal_relay_host is configured. */
    memset(&srv.deliver_cfg_internal, 0, sizeof srv.deliver_cfg_internal);
    srv.deliver_cfg_internal.hostname = srv.cfg.hostname;
    srv.deliver_cfg_internal.relay.tls = srv.cfg.internal_relay_tls;
    srv.deliver_cfg_internal.relay.auth.enabled =
        srv.cfg.internal_relay_user && srv.cfg.internal_relay_user[0];
    srv.deliver_cfg_internal.relay.auth.username = srv.cfg.internal_relay_user;
    srv.deliver_cfg_internal.relay.auth.password = srv.cfg.internal_relay_pass;
    srv.deliver_cfg_internal.relay.retries = 0;
    srv.deliver_cfg_internal.limits.cmd_timeout = srv.cmd_tmo;
    srv.deliver_cfg_internal.limits.data_timeout = srv.data_tmo;

    /* TLS server config (fail-closed on a bad/unmatched cert/key). */
    if (smtp_in_tls_global_init(srv.cfg.cert, srv.cfg.key) != 0) {
        fprintf(stderr, "outbox: TLS setup failed\n");
        outbox_config_free(&srv.cfg);
        return 1;
    }
    srv.tls_ready = smtp_in_tls_available();

    /* Resolver override (empty = auto from /etc/resolv.conf). */
    if (srv.cfg.dns_server && srv.cfg.dns_server[0])
        auth_dns_set_resolver(srv.cfg.dns_server);

    srv.listen_starttls = -1;
    srv.listen_implicit = -1;
    if (srv.cfg.starttls_port != 0) {
        srv.listen_starttls =
            make_listener(srv.cfg.starttls_addr, srv.cfg.starttls_port);
        if (srv.listen_starttls < 0) {
            fprintf(stderr, "outbox: cannot listen on %s:%u\n",
                    srv.cfg.starttls_addr, srv.cfg.starttls_port);
            outbox_config_free(&srv.cfg);
            return 1;
        }
    }
    if (srv.cfg.implicit_port != 0) {
        srv.listen_implicit =
            make_listener(srv.cfg.implicit_addr, srv.cfg.implicit_port);
        if (srv.listen_implicit < 0) {
            fprintf(stderr, "outbox: cannot listen on %s:%u\n",
                    srv.cfg.implicit_addr, srv.cfg.implicit_port);
            outbox_config_free(&srv.cfg);
            return 1;
        }
    }

    /* Graceful-shutdown plumbing (best-effort: on failure SIGTERM falls back
       to the default immediate-termination disposition). */
    (void)install_signal_handlers();

    /* Start the delivery worker BEFORE the poll loop: the poll thread only
       enqueues at DATA completion; the worker performs every outbound
       SMTP/DNS so the accept loop can keep servicing connections (including
       visage's reply_relay callback) while deliveries are in flight. */
    outbox_delivery_queue_init(&srv.delivery);
    /* 0 => default (mirrors max_attempts' 0-means-default convention). */
    srv.delivery.max_jobs = srv.cfg.queue_max_jobs
                                ? srv.cfg.queue_max_jobs
                                : OUTBOX_DEFAULT_QUEUE_MAX_JOBS;
    srv.delivery.max_bytes = srv.cfg.queue_max_bytes
                                 ? srv.cfg.queue_max_bytes
                                 : OUTBOX_DEFAULT_QUEUE_MAX_BYTES;
    srv.delivery_started = false;
    if (pthread_create(&srv.delivery_thread, NULL, outbox_delivery_worker,
                       &srv) != 0) {
        fprintf(stderr, "outbox: cannot start delivery worker\n");
        outbox_delivery_queue_destroy(&srv.delivery);
        outbox_config_free(&srv.cfg);
        return 1;
    }
    srv.delivery_started = true;

    printf("outbox %s: starttls %s:%u, implicit-TLS %s:%u, hostname %s, "
           "domains %zu, dkim %zu, passwd %s\n",
           VISAGE_VERSION,
           srv.cfg.starttls_addr, srv.cfg.starttls_port,
           srv.cfg.implicit_addr, srv.cfg.implicit_port,
           srv.cfg.hostname, srv.cfg.ndomains, srv.cfg.ndkim, srv.cfg.passwd);
    fflush(stdout);

    server_poll(&srv);

    /* Clean stop: the loop has exited, so no new submissions are accepted.
       Close the queue and join the worker, which drains every already-queued
       (and in-flight) delivery — a bounded wait (SMTP cmd/data/connect
       timeouts) that preserves accepted mail. */
    outbox_delivery_shutdown(&srv.delivery);
    if (srv.delivery_started)
        pthread_join(srv.delivery_thread, NULL);
    outbox_delivery_queue_destroy(&srv.delivery);

    if (g_sigpipe[0] >= 0) close(g_sigpipe[0]);
    if (g_sigpipe[1] >= 0) close(g_sigpipe[1]);

    if (srv.listen_starttls >= 0) close(srv.listen_starttls);
    if (srv.listen_implicit >= 0) close(srv.listen_implicit);
    return 0;
}

int main(int argc, char **argv) {
    return outbox_main(argc, argv);
}
