/* main.c — visage CLI + daemon entry point (slice S7).
 *
 * Subcommands:
 *   visage daemon -c FILE          load config, open+seed the store, then run
 *                                  the combined SMTP + admin-HTTP event loop.
 *   visage config-check -c FILE    validate the config file and exit.
 *   visage add-alias -c FILE --alias A@D --dest X@Y
 *   visage rm-alias  -c FILE --alias A@D --dest X@Y
 *   visage log -c FILE [-n N]
 *     The CLI admin subcommands are HTTP clients to the running daemon's admin
 *     endpoint (POST/DELETE /alias, GET /log), using the bearer token from
 *     config.
 *   visage --help
 *   visage --version
 *
 * Exit codes: 0 success, 1 runtime error, 2 usage/config error. */
#include "visage.h"
#include "json.h"
#include "smtp.h"

#include <sys/socket.h>
#include <netdb.h>
#include <poll.h>

#define HTTP_CLIENT_MAX_RESP 65536

static void usage(FILE *f) {
    fprintf(f,
        "usage: visage <command> [options]\n"
        "\n"
        "commands:\n"
        "  daemon -c FILE          run the SMTP + admin HTTP daemon\n"
        "  config-check -c FILE    validate the config file and exit\n"
        "  add-alias -c FILE --alias A@D --dest X@Y\n"
        "                          add an alias via the running daemon\n"
        "  rm-alias -c FILE --alias A@D --dest X@Y\n"
        "                          remove an alias via the running daemon\n"
        "  log -c FILE [-n N]      print recent log entries via the daemon\n"
        "  --help                  show this help and exit\n"
        "  --version               print the version and exit\n");
}

/* Find the value that follows argv[i] == name.  Returns NULL if absent. */
static const char *find_arg(int argc, char **argv, int start, const char *name) {
    int i;
    for (i = start; i < argc - 1; i++)
        if (strcmp(argv[i], name) == 0) return argv[i + 1];
    return NULL;
}

/* ------------------------------------------------------------------ */
/* Admin HTTP client (for the CLI subcommands)                        */
/* ------------------------------------------------------------------ */

static int wait_fd(int fd, short events) {
    struct pollfd p;
    p.fd = fd;
    p.events = events;
    p.revents = 0;
    for (;;) {
        int pr = poll(&p, 1, 5000);
        if (pr > 0) return 0;
        if (pr == 0) return -1;
        if (errno == EINTR) continue;
        return -1;
    }
}

static int send_all(int fd, const char *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t n;
        if (wait_fd(fd, POLLOUT) != 0) return -1;
        n = send(fd, buf + off, len - off, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        off += (size_t)n;
    }
    return 0;
}

/* Send one admin request and read the full response into resp (NUL-terminated,
 * capped at resp_sz).  Returns 0 on success, -1 on any I/O error. */
static int admin_request(const Config *cfg, const char *method, const char *path,
                         const char *body, size_t bodylen,
                         char *resp, size_t resp_sz) {
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    struct addrinfo *ai;
    char portstr[16];
    char req[4096];
    int rn;
    int fd = -1;
    size_t n = 0;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    snprintf(portstr, sizeof portstr, "%u", cfg->http.port);
    if (getaddrinfo(cfg->http.address, portstr, &hints, &res) != 0) return -1;

    for (ai = res; ai; ai = ai->ai_next) {
        int s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (s < 0) continue;
        if (connect(s, ai->ai_addr, ai->ai_addrlen) == 0) { fd = s; break; }
        close(s);
    }
    freeaddrinfo(res);
    if (fd < 0) return -1;

    rn = snprintf(req, sizeof req,
        "%s %s HTTP/1.0\r\nHost: %s\r\nAuthorization: Bearer %s\r\n"
        "Content-Type: application/json\r\nContent-Length: %zu\r\n"
        "Connection: close\r\n\r\n",
        method, path, cfg->http.address, cfg->admin.token, bodylen);
    if (rn < 0 || (size_t)rn >= sizeof req) { close(fd); return -1; }
    if (send_all(fd, req, (size_t)rn) != 0) { close(fd); return -1; }
    if (body && bodylen && send_all(fd, body, bodylen) != 0) { close(fd); return -1; }

    while (n + 1 < resp_sz) {
        ssize_t r;
        if (wait_fd(fd, POLLIN) != 0) break;
        r = recv(fd, resp + n, resp_sz - 1 - n, 0);
        if (r < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (r == 0) break;
        n += (size_t)r;
    }
    resp[n] = '\0';
    close(fd);
    return 0;
}

/* Extract the HTTP status code from a response, or 0 if unparseable. */
static int resp_status(const char *resp) {
    const char *p = strchr(resp, ' ');
    int code = 0;
    if (!p) return 0;
    p++;
    while (*p >= '0' && *p <= '9') {
        code = code * 10 + (*p - '0');
        p++;
    }
    return code;
}

/* Pointer to the response body (after the blank line), or "" if none. */
static const char *resp_body(const char *resp) {
    const char *he = strstr(resp, "\r\n\r\n");
    return he ? he + 4 : "";
}

/* ------------------------------------------------------------------ */
/* Subcommand handlers                                                */
/* ------------------------------------------------------------------ */

static int cmd_daemon(const Config *cfg) {
    if (smtp_tls_valid(cfg->relay.tls) != 0) {
        fprintf(stderr, "visage: relay.tls must be \"none\" or \"starttls\" "
                        "(got '%s')\n", cfg->relay.tls ? cfg->relay.tls : "");
        return 1;
    }

    Store *s = store_open(cfg->storage.path);
    if (!s) {
        fprintf(stderr, "visage: cannot open store at '%s'\n", cfg->storage.path);
        return 1;
    }
    if (store_seed_aliases(s, cfg) != VISAGE_OK) {
        fprintf(stderr, "visage: failed to seed aliases\n");
        store_close(s);
        return 1;
    }

    printf("visage %s: smtp on %s:%u, admin http on %s:%u\n",
           VISAGE_VERSION,
           cfg->listen.address, cfg->listen.port,
           cfg->http.address, cfg->http.port);
    fflush(stdout);

    return http_serve(s, cfg);
}

static int cmd_config_check(const Config *cfg) {
    int ok = 1;
    if (!cfg->hostname || !cfg->hostname[0]) {
        fprintf(stderr, "visage: config-check: missing hostname\n");
        ok = 0;
    }
    if (cfg->ndomains == 0) {
        fprintf(stderr, "visage: config-check: no domains\n");
        ok = 0;
    }
    if (!cfg->listen.address || !cfg->listen.address[0] || cfg->listen.port == 0) {
        fprintf(stderr, "visage: config-check: invalid listen address/port\n");
        ok = 0;
    }
    if (!cfg->http.address || !cfg->http.address[0] || cfg->http.port == 0) {
        fprintf(stderr, "visage: config-check: invalid http address/port\n");
        ok = 0;
    }
    if (!cfg->admin.token || !cfg->admin.token[0]) {
        fprintf(stderr, "visage: config-check: missing admin token\n");
        ok = 0;
    }
    if (smtp_tls_valid(cfg->relay.tls) != 0) {
        fprintf(stderr,
                "visage: config-check: relay.tls must be \"none\" or "
                "\"starttls\"\n");
        ok = 0;
    }
    if (!ok) return 1;
    printf("config OK\n");
    return 0;
}

static int cmd_alias(const Config *cfg, const char *alias, const char *dest, int rm) {
    char body[1024];
    char resp[HTTP_CLIENT_MAX_RESP];
    char ea[512], ed[512];
    int bn, st;

    if (json_escape(alias, strlen(alias), ea, sizeof ea) != 0 ||
        json_escape(dest, strlen(dest), ed, sizeof ed) != 0) {
        fprintf(stderr, "visage: address too long\n");
        return 1;
    }
    bn = snprintf(body, sizeof body, "{\"alias\":\"%s\",\"destination\":\"%s\"}",
                  ea, ed);
    if (bn < 0 || (size_t)bn >= sizeof body) {
        fprintf(stderr, "visage: address too long\n");
        return 1;
    }

    if (admin_request(cfg, rm ? "DELETE" : "POST", "/alias",
                      body, (size_t)bn, resp, sizeof resp) != 0) {
        fprintf(stderr, "visage: cannot reach daemon at %s:%u\n",
                cfg->http.address, cfg->http.port);
        return 1;
    }
    st = resp_status(resp);
    if (st != 200) {
        fprintf(stderr, "visage: daemon returned HTTP %d: %s\n",
                st, resp_body(resp));
        return 1;
    }
    printf("ok\n");
    return 0;
}

static int cmd_log(const Config *cfg, long n) {
    char path[64];
    char resp[HTTP_CLIENT_MAX_RESP];
    int pn, st;

    if (n > 0)
        pn = snprintf(path, sizeof path, "/log?n=%ld", n);
    else
        pn = snprintf(path, sizeof path, "/log");
    if (pn < 0 || (size_t)pn >= sizeof path) {
        fprintf(stderr, "visage: bad -n value\n");
        return 2;
    }

    if (admin_request(cfg, "GET", path, NULL, 0, resp, sizeof resp) != 0) {
        fprintf(stderr, "visage: cannot reach daemon at %s:%u\n",
                cfg->http.address, cfg->http.port);
        return 1;
    }
    st = resp_status(resp);
    if (st != 200) {
        fprintf(stderr, "visage: daemon returned HTTP %d\n", st);
        return 1;
    }
    printf("%s\n", resp_body(resp));
    return 0;
}

/* ------------------------------------------------------------------ */
/* main                                                               */
/* ------------------------------------------------------------------ */

int main(int argc, char **argv) {
    const char *cmd;
    const char *cfgpath;
    const char *alias = NULL, *dest = NULL;
    long n = 0;
    Config cfg;
    char err[512];
    int rc;

    if (argc < 2) { usage(stderr); return 1; }
    cmd = argv[1];

    if (strcmp(cmd, "--help") == 0 || strcmp(cmd, "-h") == 0) {
        usage(stdout);
        return 0;
    }
    if (strcmp(cmd, "--version") == 0) {
        printf("visage %s\n", VISAGE_VERSION);
        return 0;
    }

    if (strcmp(cmd, "daemon") != 0 && strcmp(cmd, "config-check") != 0 &&
        strcmp(cmd, "add-alias") != 0 && strcmp(cmd, "rm-alias") != 0 &&
        strcmp(cmd, "log") != 0) {
        fprintf(stderr, "visage: unknown command '%s'\n\n", cmd);
        usage(stderr);
        return 2;
    }

    cfgpath = find_arg(argc, argv, 2, "-c");
    if (!cfgpath) cfgpath = find_arg(argc, argv, 2, "--config");
    if (!cfgpath) {
        fprintf(stderr, "visage: %s requires -c/--config PATH\n", cmd);
        return 2;
    }

    if (strcmp(cmd, "add-alias") == 0 || strcmp(cmd, "rm-alias") == 0) {
        alias = find_arg(argc, argv, 2, "--alias");
        dest = find_arg(argc, argv, 2, "--dest");
        if (!alias || !dest) {
            fprintf(stderr,
                "visage: %s requires --alias A@D and --dest X@Y\n", cmd);
            return 2;
        }
    }
    if (strcmp(cmd, "log") == 0) {
        const char *ns = find_arg(argc, argv, 2, "-n");
        if (ns) n = atol(ns);
    }

    if (config_load(cfgpath, &cfg, err, sizeof err) != 0) {
        fprintf(stderr, "visage: config error: %s\n", err[0] ? err : cfgpath);
        return 2;
    }

    if (strcmp(cmd, "daemon") == 0) {
        rc = cmd_daemon(&cfg);
    } else if (strcmp(cmd, "config-check") == 0) {
        rc = cmd_config_check(&cfg);
    } else if (strcmp(cmd, "add-alias") == 0 || strcmp(cmd, "rm-alias") == 0) {
        rc = cmd_alias(&cfg, alias, dest, strcmp(cmd, "rm-alias") == 0);
    } else {
        rc = cmd_log(&cfg, n);
    }

    config_free(&cfg);
    return rc;
}
