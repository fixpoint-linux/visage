/* http.c — minimal admin HTTP endpoint (slice S7, R4 non-blocking rewrite).
 *
 * A tiny HTTP/1.0-style server (no external HTTP library) that serves the
 * visage admin API over JSON.  It shares one poll loop with SMTP (datalog is
 * single-writer, so everything runs on one thread): the admin listener is
 * registered with smtp_in_add_extra_fd(), and each accepted connection is
 * registered as a per-connection HTTP fd via smtp_in_register_http_conn() so
 * its readable/writable events are multiplexed alongside SMTP connections.
 *
 * R4: every connection is served by a NON-BLOCKING state machine.  A
 * trickling admin client can no longer stall SMTP delivery — each event-loop
 * iteration does a bounded amount of admin work (one recv / a few sends) and
 * returns to poll(), which also services SMTP.  A connection is closed after
 * one request (HTTP/1.0 Connection: close).
 *
 * Routes (all require `Authorization: Bearer <Config.admin.token>` except
 * /health):
 *   GET    /health   -> {"ok":true}
 *   GET    /log?n=N  -> JSON array of the N most-recent log entries
 *   POST   /alias    -> {"alias":"a@d","destination":"x@y"}  (add)
 *   DELETE /alias    -> {"alias":"a@d","destination":"x@y"}  (remove)
 *
 * Bounds: the request is accumulated into a fixed per-connection buffer capped
 * at HTTP_MAX_REQ bytes (see http_parse.h); Content-Length is honored and
 * capped; every read/write is non-blocking and bounded. */
#include "visage.h"
#include "json.h"
#include "http_parse.h"

#include <sys/socket.h>
#include <netdb.h>
#include <poll.h>
#include <fcntl.h>

#define HTTP_LISTEN_BACKLOG 16
#define HTTP_READ_TIMEOUT_MS 5000   /* idle timeout for a registered conn (ms) */
#define HTTP_RECV_CHUNK      4096

/* Upper bound on /log?n= to keep the response bounded. */
#define HTTP_MAX_LOG_N 1000

/* Per-connection state-machine states. */
enum { HTTP_ST_RECV = 0, HTTP_ST_RESPOND };

typedef struct {
    Store        *store;
    const Config *cfg;
} HttpServer;

typedef struct HttpConn {
    int          fd;
    int          handle;              /* smtp_in_http slot handle, or -1 */
    HttpServer  *srv;

    /* Request accumulation (fixed, bounded, NUL-terminated). */
    char         recv[HTTP_MAX_REQ + 1];
    size_t       recv_len;
    size_t       header_end;          /* bytes through end of header block */
    size_t       body_len;            /* expected body bytes (0 = none) */

    int          state;               /* HTTP_ST_* */

    /* Response bytes pending to be flushed. */
    char        *resp;                /* owned */
    size_t       resp_len;
    size_t       resp_off;            /* bytes already sent */
} HttpConn;

/* ------------------------------------------------------------------ */
/* Forward declarations                                               */
/* ------------------------------------------------------------------ */

static void http_conn_free(HttpConn *c);
static void http_respond(HttpConn *c, int status, const char *reason,
                         const char *body, size_t bodylen);
static void http_respond_err(HttpConn *c, int status, const char *reason,
                             const char *msg);
static void http_try_flush(HttpConn *c);
static void http_process(HttpConn *c);
static void handle_request(HttpServer *srv, HttpConn *c);
static void http_conn_on_readable(int fd, void *user);
static void http_conn_on_writable(int fd, void *user);
static void http_conn_on_closed(int fd, void *user);

/* ------------------------------------------------------------------ */
/* Small helpers                                                      */
/* ------------------------------------------------------------------ */

static void set_nonblock(int fd) {
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl < 0) return;
    (void)fcntl(fd, F_SETFL, fl | O_NONBLOCK);
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
/* Auth                                                               */
/* ------------------------------------------------------------------ */

/* Constant-time equality of `supplied` against the configured `token`.
   The loop bound is the FIXED secret length, so runtime is independent of the
   supplied token's value; `supplied[i]` is only ever read while i < strlen(supplied)
   (never past its NUL), and a length mismatch is folded into d so both shorter and
   longer supplied tokens are rejected without any over-read.  No early exit. */
static int token_eq_ct(const char *supplied, const char *configured) {
    size_t ns = strlen(supplied);
    size_t nc = strlen(configured);
    size_t i;
    unsigned char d = (ns == nc) ? 0 : 1;
    for (i = 0; i < nc; i++) {
        unsigned char ac = (i < ns) ? (unsigned char)supplied[i] : 0u;
        d |= (unsigned char)(ac ^ (unsigned char)configured[i]);
    }
    return d == 0;
}

/* True if the Authorization header equals "Bearer <token>". */
static int auth_ok(const char *req, size_t reqlen, size_t header_end,
                   const char *token) {
    char auth[512];
    const char *p;
    (void)reqlen;
    if (!token || !token[0]) return 0;
    if (header_end == SIZE_MAX ||
        http_header_value(req, header_end, "Authorization", auth, sizeof auth) != 0)
        return 0;
    p = auth;
    while (*p == ' ' || *p == '\t') p++;
    if (strlen(p) < 7 || !http_ci_eq(p, "Bearer ", 7)) return 0;
    p += 7;
    while (*p == ' ' || *p == '\t') p++;
    return token_eq_ct(p, token);
}

/* ------------------------------------------------------------------ */
/* Connection lifecycle + response flushing                          */
/* ------------------------------------------------------------------ */

/* Release the smtp_in slot, close the fd, and free all per-connection state. */
static void http_conn_free(HttpConn *c) {
    if (!c) return;
    if (c->handle >= 0) smtp_in_http_close(c->handle);
    if (c->fd >= 0) close(c->fd);
    free(c->resp);
    free(c);
}

/* Build the full response (head + body) into c->resp and enter RESPOND. */
static int http_set_response(HttpConn *c, int status, const char *reason,
                             const char *body, size_t bodylen) {
    char head[256];
    int hn = snprintf(head, sizeof head,
        "HTTP/1.0 %d %s\r\nContent-Type: application/json\r\n"
        "Content-Length: %zu\r\nConnection: close\r\n\r\n",
        status, reason, bodylen);
    size_t headlen;
    char *nb;
    if (hn < 0) return -1;
    headlen = (size_t)hn < sizeof head ? (size_t)hn : sizeof head - 1;

    nb = malloc(headlen + bodylen);
    if (!nb) return -1;
    memcpy(nb, head, headlen);
    if (bodylen) memcpy(nb + headlen, body, bodylen);
    free(c->resp);
    c->resp = nb;
    c->resp_len = headlen + bodylen;
    c->resp_off = 0;
    c->state = HTTP_ST_RESPOND;
    return 0;
}

/* Queue a response, arm writable, and attempt an immediate non-blocking flush. */
static void http_respond(HttpConn *c, int status, const char *reason,
                         const char *body, size_t bodylen) {
    if (http_set_response(c, status, reason, body, bodylen) != 0) {
        http_conn_free(c);
        return;
    }
    smtp_in_http_set_events(c->handle, POLLOUT);
    http_try_flush(c);
}

/* Queue a JSON {"error": "..."} response. */
static void http_respond_err(HttpConn *c, int status, const char *reason,
                             const char *msg) {
    char body[1024];
    int bn = snprintf(body, sizeof body, "{\"error\":\"%s\"}", msg);
    if (bn < 0) { http_conn_free(c); return; }
    if ((size_t)bn >= sizeof body) bn = (int)(sizeof body - 1);
    http_respond(c, status, reason, body, (size_t)bn);
}

/* Flush as much of the pending response as the socket will accept (non-blocking).
   Frees the connection once the response has fully drained. */
static void http_try_flush(HttpConn *c) {
    while (c->resp_off < c->resp_len) {
        ssize_t n = send(c->fd, c->resp + c->resp_off, c->resp_len - c->resp_off,
                         MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) return;  /* wait POLLOUT */
            http_conn_free(c);
            return;
        }
        if (n == 0) { http_conn_free(c); return; }
        c->resp_off += (size_t)n;
    }
    /* Fully flushed: one request per connection. */
    http_conn_free(c);
}

/* ------------------------------------------------------------------ */
/* Handlers                                                           */
/* ------------------------------------------------------------------ */

static void handle_log(HttpServer *srv, HttpConn *c, const char *target) {
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
        http_respond_err(c, 500, "Internal Server Error", "store error");
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
    if (!body) { http_respond_err(c, 500, "Internal Server Error", "out of memory"); return; }
    http_respond(c, 200, "OK", body, bodylen);
    free(body);
}

static void handle_alias(HttpServer *srv, HttpConn *c, int rm) {
    char alias[512], dest[512];
    int rc;
    const char *body = c->recv + c->header_end;

    if (json_obj_get_str(body, "alias", alias, sizeof alias) != 0 ||
        json_obj_get_str(body, "destination", dest, sizeof dest) != 0) {
        http_respond_err(c, 400, "Bad Request", "expected {\"alias\",\"destination\"}");
        return;
    }

    if (config_alias_read_only(srv->cfg, alias)) {
        http_respond_err(c, 403, "Forbidden",
                         "alias is declared in config (read-only)");
        return;
    }

    rc = rm ? store_alias_rm(srv->store, alias, dest)
            : store_alias_add(srv->store, alias, dest);
    if (rc != VISAGE_OK) {
        http_respond_err(c, 500, "Internal Server Error", "store error");
        return;
    }
    http_respond(c, 200, "OK", "{\"ok\":true}", 11);
}

static void handle_request(HttpServer *srv, HttpConn *c) {
    char method[16], target[1024];
    const char *req = c->recv;
    size_t reqlen = c->recv_len;
    size_t header_end = c->header_end;

    if (parse_request_line(req, reqlen, method, sizeof method,
                           target, sizeof target) != 0) {
        http_respond_err(c, 400, "Bad Request", "malformed request");
        return;
    }
    if (header_end == SIZE_MAX || header_end > reqlen) {
        http_respond_err(c, 400, "Bad Request", "malformed headers");
        return;
    }

    /* /health needs no auth. */
    if (strcmp(method, "GET") == 0 && strcmp(target, "/health") == 0) {
        http_respond(c, 200, "OK", "{\"ok\":true}", 11);
        return;
    }

    /* Everything else requires the bearer token. */
    if (!auth_ok(req, reqlen, header_end, srv->cfg->admin.token)) {
        http_respond_err(c, 401, "Unauthorized", "missing or invalid token");
        return;
    }

    if (strcmp(method, "GET") == 0 &&
        (strcmp(target, "/log") == 0 || strncmp(target, "/log?", 5) == 0)) {
        handle_log(srv, c, target);
    } else if (strcmp(method, "POST") == 0 && strcmp(target, "/alias") == 0) {
        handle_alias(srv, c, 0);
    } else if (strcmp(method, "DELETE") == 0 && strcmp(target, "/alias") == 0) {
        handle_alias(srv, c, 1);
    } else if ((strcmp(method, "GET") == 0 ||
                strcmp(method, "POST") == 0 ||
                strcmp(method, "DELETE") == 0) &&
               (strcmp(target, "/alias") == 0 ||
                strcmp(target, "/log") == 0 || strncmp(target, "/log?", 5) == 0 ||
                strcmp(target, "/health") == 0)) {
        /* Known path, wrong method. */
        http_respond_err(c, 405, "Method Not Allowed", "method not allowed");
    } else {
        http_respond_err(c, 404, "Not Found", "unknown path");
    }
}

/* ------------------------------------------------------------------ */
/* Non-blocking state machine                                         */
/* ------------------------------------------------------------------ */

/* Advance the request state machine after newly-arrived bytes. */
static void http_process(HttpConn *c) {
    size_t header_end = SIZE_MAX, body_len = 0;
    int r = http_parse_probe(c->recv, c->recv_len, HTTP_MAX_REQ,
                             &header_end, &body_len);

    if (r == HTTP_PARSE_NEED_MORE) {
        if (c->recv_len >= HTTP_MAX_REQ)   /* buffer full, request incomplete */
            http_respond_err(c, 413, "Request Entity Too Large", "request too large");
        return;   /* wait for more data */
    }
    if (r == HTTP_PARSE_ERR) {
        http_respond_err(c, 413, "Request Entity Too Large", "request too large");
        return;
    }

    /* Full request buffered. */
    c->header_end = header_end;
    c->body_len = body_len;
    c->recv[c->recv_len] = '\0';
    handle_request(c->srv, c);
}

static void http_conn_on_readable(int fd, void *user) {
    HttpConn *c = (HttpConn *)user;
    char tmp[HTTP_RECV_CHUNK];
    size_t room, want;
    ssize_t n;

    (void)fd;
    if (c->state != HTTP_ST_RECV) return;

    if (c->recv_len >= HTTP_MAX_REQ) {
        http_respond_err(c, 413, "Request Entity Too Large", "request too large");
        return;
    }
    room = HTTP_MAX_REQ - c->recv_len;
    want = room < sizeof tmp ? room : sizeof tmp;
    n = recv(c->fd, tmp, want, 0);
    if (n < 0) {
        if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) return;
        http_conn_free(c);
        return;
    }
    if (n == 0) {   /* peer closed before a full request */
        http_conn_free(c);
        return;
    }

    memcpy(c->recv + c->recv_len, tmp, (size_t)n);
    c->recv_len += (size_t)n;
    c->recv[c->recv_len] = '\0';
    http_process(c);
}

static void http_conn_on_writable(int fd, void *user) {
    HttpConn *c = (HttpConn *)user;
    (void)fd;
    if (c->state == HTTP_ST_RESPOND) http_try_flush(c);
}

/* Invoked by the poll loop when this conn idled out (no activity within the
   registered idle timeout).  The slot is already released; just tear down. */
static void http_conn_on_closed(int fd, void *user) {
    HttpConn *c = (HttpConn *)user;
    (void)fd;
    http_conn_free(c);
}

/* ------------------------------------------------------------------ */
/* Listener + entry point                                             */
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
 * connections and registers each as a per-connection HTTP fd (non-blocking)
 * that the poll loop multiplexes alongside SMTP.  Accepting is O(1), so we
 * drain the backlog on each wakeup. */
static void http_accept(int lfd, void *user) {
    HttpServer *srv = (HttpServer *)user;
    for (;;) {
        int cfd = accept(lfd, NULL, NULL);
        HttpConn *c;
        int handle;

        if (cfd < 0) {
            if (errno == EINTR) continue;
            return;   /* EAGAIN/EWOULDBLOCK or error */
        }
        set_nonblock(cfd);

        c = calloc(1, sizeof *c);
        if (!c) { close(cfd); continue; }
        c->fd = cfd;
        c->handle = -1;
        c->srv = srv;
        c->state = HTTP_ST_RECV;

        handle = smtp_in_register_http_conn(cfd,
                                            http_conn_on_readable,
                                            http_conn_on_writable,
                                            http_conn_on_closed,
                                            HTTP_READ_TIMEOUT_MS / 1000,
                                            c);
        if (handle < 0) {
            /* Connection table full: reject with 503 (best-effort) and close. */
            static const char busy[] =
                "HTTP/1.0 503 Service Unavailable\r\n"
                "Content-Type: application/json\r\n"
                "Content-Length: 0\r\n"
                "Connection: close\r\n\r\n";
            (void)send(cfd, busy, sizeof busy - 1, MSG_NOSIGNAL);
            close(cfd);
            free(c);
            continue;
        }
        c->handle = handle;
    }
}

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

    if (smtp_in_add_extra_fd(lfd, http_accept, srv) != VISAGE_OK) {
        close(lfd);
        free(srv);
        return VISAGE_ERR;
    }

    return smtp_in_main(cfg, s);
}
