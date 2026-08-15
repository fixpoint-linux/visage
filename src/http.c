/* http.c — minimal admin HTTP endpoint (slice S7).
 *
 * A tiny HTTP/1.0-style server (no external HTTP library) that serves the
 * visage admin API over JSON.  It mirrors the poll()-based style of smtp_in.c:
 * the admin listener is registered with smtp_in_add_extra_fd() so it shares
 * one poll loop with SMTP (datalog is single-writer, so everything runs on one
 * thread).  Each accepted connection is served one request and closed
 * (HTTP/1.0 Connection: close), which keeps the protocol simple and correct.
 *
 * Routes (all require `Authorization: Bearer <Config.admin.token>` except
 * /health):
 *   GET    /health   -> {"ok":true}
 *   GET    /log?n=N  -> JSON array of the N most-recent log entries
 *   POST   /alias    -> {"alias":"a@d","destination":"x@y"}  (add)
 *   DELETE /alias    -> {"alias":"a@d","destination":"x@y"}  (remove)
 *
 * Bounds: the request (headers + body) is read into a fixed buffer capped at
 * HTTP_MAX_REQ bytes; Content-Length is honored and capped; every read/write
 * is bounded and the connection is closed after each request. */
#include "visage.h"
#include "json.h"

#include <sys/socket.h>
#include <netdb.h>
#include <poll.h>
#include <fcntl.h>

#define HTTP_MAX_REQ       65536
#define HTTP_LISTEN_BACKLOG 16
#define HTTP_READ_TIMEOUT_MS 5000
#define HTTP_WRITE_TIMEOUT_MS 5000

/* Upper bound on /log?n= to keep the response bounded. */
#define HTTP_MAX_LOG_N     1000

typedef struct {
    Store        *store;
    const Config *cfg;
} HttpServer;

/* ------------------------------------------------------------------ */
/* Small helpers                                                      */
/* ------------------------------------------------------------------ */

static void set_nonblock(int fd) {
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl < 0) return;
    (void)fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

/* ASCII case-insensitive compare over exactly n bytes. */
static int ci_eq(const char *a, const char *b, size_t n) {
    while (n-- > 0) {
        unsigned char ca = (unsigned char)*a++;
        unsigned char cb = (unsigned char)*b++;
        if (ca >= 'A' && ca <= 'Z') ca = (unsigned char)(ca + 32);
        if (cb >= 'A' && cb <= 'Z') cb = (unsigned char)(cb + 32);
        if (ca != cb) return 0;
    }
    return 1;
}

/* Index of the end-of-headers marker "\r\n\r\n" in buf[0..n), or SIZE_MAX. */
static size_t find_header_end(const char *buf, size_t n) {
    size_t i;
    for (i = 0; i + 3 < n; i++)
        if (buf[i] == '\r' && buf[i + 1] == '\n' &&
            buf[i + 2] == '\r' && buf[i + 3] == '\n')
            return i + 4;
    return SIZE_MAX;
}

/* Find a header "Name: value" in the header block buf[0..hlen).  Copies the
 * (trimmed) value into out.  Returns 0 on success, -1 if not found. */
static int header_value(const char *buf, size_t hlen, const char *name,
                        char *out, size_t outsz) {
    size_t nl = strlen(name);
    size_t i = 0;
    while (i < hlen) {
        size_t line_end = i;
        size_t linelen;
        while (line_end < hlen && buf[line_end] != '\r' && buf[line_end] != '\n')
            line_end++;
        linelen = line_end - i;
        if (linelen > nl && ci_eq(buf + i, name, nl) && buf[i + nl] == ':') {
            size_t v = i + nl + 1;
            size_t vlen;
            while (v < line_end && (buf[v] == ' ' || buf[v] == '\t')) v++;
            vlen = line_end - v;
            while (vlen > 0 && (buf[v + vlen - 1] == ' ' || buf[v + vlen - 1] == '\t'))
                vlen--;
            if (vlen + 1 > outsz) return -1;
            memcpy(out, buf + v, vlen);
            out[vlen] = '\0';
            return 0;
        }
        i = line_end + 1;
        while (i < hlen && (buf[i] == '\r' || buf[i] == '\n')) i++;
    }
    return -1;
}

/* ------------------------------------------------------------------ */
/* Socket I/O (bounded, with timeouts)                                */
/* ------------------------------------------------------------------ */

static int wait_fd(int fd, short events, int timeout_ms) {
    struct pollfd p;
    p.fd = fd;
    p.events = events;
    p.revents = 0;
    for (;;) {
        int pr = poll(&p, 1, timeout_ms);
        if (pr > 0) return 0;
        if (pr == 0) return -1;          /* timeout */
        if (errno == EINTR) continue;
        return -1;
    }
}

static int send_all(int fd, const char *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t n;
        if (wait_fd(fd, POLLOUT, HTTP_WRITE_TIMEOUT_MS) != 0) return -1;
        n = send(fd, buf + off, len - off, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        off += (size_t)n;
    }
    return 0;
}

/* Read one full HTTP request (headers + body per Content-Length) into buf.
 * Returns 0 on success with *len set; -1 on timeout/error/oversize. */
static int http_read_request(int fd, char *buf, size_t cap, size_t *len) {
    size_t n = 0;
    for (;;) {
        size_t he = find_header_end(buf, n);
        if (he != SIZE_MAX) {
            char cl[32];
            if (header_value(buf, he, "Content-Length", cl, sizeof cl) == 0) {
                char *endp;
                unsigned long v = strtoul(cl, &endp, 10);
                if (endp != cl) {
                    if (v > cap) return -1;               /* oversize body */
                    if (n - he >= (size_t)v) { *len = n; return 0; }
                } else {
                    *len = n;   /* malformed Content-Length: ignore body */
                    return 0;
                }
            } else {
                *len = n;       /* no Content-Length: no body expected */
                return 0;
            }
        }
        if (n >= cap) return -1;   /* request exceeds cap */
        if (wait_fd(fd, POLLIN, HTTP_READ_TIMEOUT_MS) != 0) return -1;
        {
            ssize_t r = recv(fd, buf + n, cap - n, 0);
            if (r < 0) {
                if (errno == EINTR) continue;
                return -1;
            }
            if (r == 0) return -1;   /* peer closed before a full request */
            n += (size_t)r;
        }
    }
}

/* Parse "METHOD SP target SP version" from the request line. */
static int parse_request_line(const char *req, size_t reqlen,
                              char *method, size_t msz,
                              char *target, size_t tsz) {
    size_t i = 0, j;
    while (i < reqlen && req[i] != ' ' && req[i] != '\r' && req[i] != '\n') i++;
    if (i == 0 || i >= msz) return -1;
    memcpy(method, req, i);
    method[i] = '\0';
    while (i < reqlen && req[i] == ' ') i++;
    j = i;
    while (i < reqlen && req[i] != ' ' && req[i] != '\r' && req[i] != '\n') i++;
    if (i == j || i - j >= tsz) return -1;
    memcpy(target, req + j, i - j);
    target[i - j] = '\0';
    return 0;
}

/* ------------------------------------------------------------------ */
/* Responses                                                          */
/* ------------------------------------------------------------------ */

static void send_response(int fd, int status, const char *reason,
                          const char *body, size_t bodylen) {
    char head[256];
    int hn = snprintf(head, sizeof head,
        "HTTP/1.0 %d %s\r\nContent-Type: application/json\r\n"
        "Content-Length: %zu\r\nConnection: close\r\n\r\n",
        status, reason, bodylen);
    if (hn < 0) return;
    if ((size_t)hn >= sizeof head) hn = (int)(sizeof head - 1);
    (void)send_all(fd, head, (size_t)hn);
    (void)send_all(fd, body, bodylen);
}

static void send_err(int fd, int status, const char *reason, const char *msg) {
    char body[1024];
    int bn = snprintf(body, sizeof body, "{\"error\":\"%s\"}", msg);
    if (bn < 0) return;
    if ((size_t)bn >= sizeof body) bn = (int)(sizeof body - 1);
    send_response(fd, status, reason, body, (size_t)bn);
}

/* ------------------------------------------------------------------ */
/* Auth                                                               */
/* ------------------------------------------------------------------ */

/* True if the Authorization header equals "Bearer <token>". */
static int auth_ok(const char *req, size_t reqlen, size_t header_end,
                   const char *token) {
    char auth[512];
    const char *p;
    (void)reqlen;
    if (!token || !token[0]) return 0;
    if (header_end == SIZE_MAX ||
        header_value(req, header_end, "Authorization", auth, sizeof auth) != 0)
        return 0;
    p = auth;
    while (*p == ' ' || *p == '\t') p++;
    if (strlen(p) < 7 || !ci_eq(p, "Bearer ", 7)) return 0;
    p += 7;
    while (*p == ' ' || *p == '\t') p++;
    return strcmp(p, token) == 0;
}

/* ------------------------------------------------------------------ */
/* Handlers                                                           */
/* ------------------------------------------------------------------ */

static void handle_log(HttpServer *srv, int fd, const char *target) {
    Store *s = srv->store;
    size_t n = 100;
    StoreLogEntry *entries = NULL;
    size_t nentries = 0, i;
    JsonBuilder b;
    char *body;
    size_t bodylen;
    const char *q = strchr(target, '?');

    if (q && strncmp(q, "?n=", 3) == 0) {
        const char *p = q + 3;
        unsigned long v = 0;
        while (*p >= '0' && *p <= '9') {
            if (v > (unsigned long)HTTP_MAX_LOG_N * 10) break;
            v = v * 10 + (unsigned long)(*p - '0');
            p++;
        }
        if (v > 0) n = (size_t)v;
    }
    if (n > HTTP_MAX_LOG_N) n = HTTP_MAX_LOG_N;

    if (store_log_recent(s, n, &entries, &nentries) != VISAGE_OK) {
        send_err(fd, 500, "Internal Server Error", "store error");
        return;
    }

    jsonb_init(&b);
    jsonb_begin_array(&b);
    for (i = 0; i < nentries; i++) {
        if (i) jsonb_comma(&b);
        jsonb_begin_object(&b);
        jsonb_key(&b, "msgid"); jsonb_u32(&b, entries[i].msgid); jsonb_comma(&b);
        jsonb_key(&b, "ts");    jsonb_u32(&b, entries[i].ts);    jsonb_comma(&b);
        jsonb_key(&b, "dir");   jsonb_u32(&b, entries[i].dir);   jsonb_comma(&b);
        jsonb_key(&b, "local"); jsonb_str(&b, entries[i].local ? entries[i].local : ""); jsonb_comma(&b);
        jsonb_key(&b, "remote"); jsonb_str(&b, entries[i].remote ? entries[i].remote : ""); jsonb_comma(&b);
        jsonb_key(&b, "status"); jsonb_str(&b, entries[i].status ? entries[i].status : "");
        jsonb_end_object(&b);
    }
    jsonb_end_array(&b);
    body = jsonb_detach(&b, &bodylen);
    store_log_entries_free(entries, nentries);
    if (!body) { send_err(fd, 500, "Internal Server Error", "out of memory"); return; }
    send_response(fd, 200, "OK", body, bodylen);
    free(body);
}

static void handle_alias(HttpServer *srv, int fd, const char *req,
                         size_t reqlen, size_t header_end, int rm) {
    char alias[512], dest[512];
    int rc;

    (void)reqlen;
    if (header_end == SIZE_MAX || header_end >= reqlen) {
        send_err(fd, 400, "Bad Request", "missing body");
        return;
    }
    if (json_obj_get_str(req + header_end, "alias", alias, sizeof alias) != 0 ||
        json_obj_get_str(req + header_end, "destination", dest, sizeof dest) != 0) {
        send_err(fd, 400, "Bad Request", "expected {\"alias\",\"destination\"}");
        return;
    }

    rc = rm ? store_alias_rm(srv->store, alias, dest)
            : store_alias_add(srv->store, alias, dest);
    if (rc != VISAGE_OK) {
        send_err(fd, 500, "Internal Server Error", "store error");
        return;
    }
    send_response(fd, 200, "OK", "{\"ok\":true}", 11);
}

static void handle_request(HttpServer *srv, int fd, const char *req, size_t reqlen) {
    char method[16], target[1024];
    size_t header_end = find_header_end(req, reqlen);

    if (parse_request_line(req, reqlen, method, sizeof method,
                           target, sizeof target) != 0) {
        send_err(fd, 400, "Bad Request", "malformed request");
        return;
    }
    if (header_end == SIZE_MAX) {
        send_err(fd, 400, "Bad Request", "malformed headers");
        return;
    }

    /* /health needs no auth. */
    if (strcmp(method, "GET") == 0 && strcmp(target, "/health") == 0) {
        send_response(fd, 200, "OK", "{\"ok\":true}", 11);
        return;
    }

    /* Everything else requires the bearer token. */
    if (!auth_ok(req, reqlen, header_end, srv->cfg->admin.token)) {
        send_err(fd, 401, "Unauthorized", "missing or invalid token");
        return;
    }

    if (strcmp(method, "GET") == 0 &&
        (strcmp(target, "/log") == 0 || strncmp(target, "/log?", 5) == 0)) {
        handle_log(srv, fd, target);
    } else if (strcmp(method, "POST") == 0 && strcmp(target, "/alias") == 0) {
        handle_alias(srv, fd, req, reqlen, header_end, 0);
    } else if (strcmp(method, "DELETE") == 0 && strcmp(target, "/alias") == 0) {
        handle_alias(srv, fd, req, reqlen, header_end, 1);
    } else if ((strcmp(method, "GET") == 0 ||
                strcmp(method, "POST") == 0 ||
                strcmp(method, "DELETE") == 0) &&
               (strcmp(target, "/alias") == 0 ||
                strcmp(target, "/log") == 0 || strncmp(target, "/log?", 5) == 0 ||
                strcmp(target, "/health") == 0)) {
        /* Known path, wrong method. */
        send_err(fd, 405, "Method Not Allowed", "method not allowed");
    } else {
        send_err(fd, 404, "Not Found", "unknown path");
    }
}

/* ------------------------------------------------------------------ */
/* Listener + extra-fd callback                                       */
/* ------------------------------------------------------------------ */

static int http_make_listener(const Config *cfg) {
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    struct addrinfo *ai;
    char portstr[16];
    int fd = -1;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    snprintf(portstr, sizeof portstr, "%u", cfg->http.port);
    if (getaddrinfo(cfg->http.address, portstr, &hints, &res) != 0) return -1;

    for (ai = res; ai; ai = ai->ai_next) {
        int s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (s < 0) continue;
        {
            int one = 1;
            (void)setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
        }
        if (bind(s, ai->ai_addr, ai->ai_addrlen) < 0) { close(s); continue; }
        if (listen(s, HTTP_LISTEN_BACKLOG) < 0) { close(s); continue; }
        fd = s;
        break;
    }
    freeaddrinfo(res);
    if (fd < 0) return -1;
    set_nonblock(fd);
    return fd;
}

/* Invoked by the SMTP poll loop when the admin listener is readable.  Accepts
 * and serves a bounded number of queued connections (one request each, then
 * close), returning control to the poll loop between batches so a flood of
 * admin connections cannot starve SMTP delivery.  Admin is low-traffic and
 * localhost-bound; serving one request synchronously per connection is
 * acceptable for the MVP. */
static void http_on_readable(int lfd, void *user) {
    HttpServer *srv = (HttpServer *)user;
    int served = 0;
    while (served < 4) {   /* bounded per poll wakeup */
        int cfd = accept(lfd, NULL, NULL);
        char buf[HTTP_MAX_REQ + 1];
        size_t reqlen = 0;

        if (cfd < 0) {
            if (errno == EINTR) continue;
            return;   /* EAGAIN/EWOULDBLOCK or error */
        }
        set_nonblock(cfd);
        if (http_read_request(cfd, buf, HTTP_MAX_REQ, &reqlen) == 0) {
            buf[reqlen] = '\0';   /* the request parser expects a NUL terminator */
            handle_request(srv, cfd, buf, reqlen);
        } else {
            send_err(cfd, 400, "Bad Request", "invalid request");
        }
        close(cfd);
        served++;
    }
}

/* ------------------------------------------------------------------ */
/* Entry point                                                        */
/* ------------------------------------------------------------------ */

/* Set up the admin listener, register it on the SMTP loop, then run the
 * combined SMTP+HTTP poll loop (smtp_in_main). */
int http_serve(Store *s, const Config *cfg) {
    HttpServer *srv;
    int lfd;

    if (!s || !cfg) return VISAGE_EPARAM;

    srv = calloc(1, sizeof *srv);
    if (!srv) return VISAGE_ENOMEM;
    srv->store = s;
    srv->cfg = cfg;

    lfd = http_make_listener(cfg);
    if (lfd < 0) { free(srv); return VISAGE_ERR; }

    if (smtp_in_add_extra_fd(lfd, http_on_readable, srv) != VISAGE_OK) {
        close(lfd);
        free(srv);
        return VISAGE_ERR;
    }

    return smtp_in_main(cfg, s);
}
