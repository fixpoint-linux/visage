/* admin.c — pure admin HTTP request -> response routing for visage.
 *
 * Factored out of http.c (which keeps only the non-blocking connection /
 * socket plumbing) so the whole admin API is a testable pure function:
 * admin_build_response() takes a fully-buffered request (headers + body) and
 * produces the complete HTTP response (head + body) with the correct
 * Content-Type — no sockets, no smtp_in, no poll loop.  http.c feeds it the
 * bytes a connection has accumulated and flushes whatever it returns.
 *
 * Auth model: /health and the embedded static UI shell (/ , /admin,
 * /app.js, /style.css) need no token (the shell contains no data, only client
 * code).  Every data route (/aliases, /status, /log, /alias, /replay)
 * requires `Authorization: Bearer <Config.admin.token>`.
 *
 * The embedded assets are generated into src/data/admin_ui.c by
 * tools/gen_admin_ui.sh from admin/{index.html,app.js,style.css}.
 */
#include "visage.h"
#include "json.h"
#include "http_parse.h"

#include <string.h>

/* Embedded admin UI assets (generated — see src/data/admin_ui.c). */
extern const char visage_admin_index_html[];
extern const size_t visage_admin_index_html_len;
extern const char visage_admin_app_js[];
extern const size_t visage_admin_app_js_len;
extern const char visage_admin_style_css[];
extern const size_t visage_admin_style_css_len;

/* ------------------------------------------------------------------ */
/* Response accumulator                                               */
/* ------------------------------------------------------------------ */

typedef struct {
    char  *buf;       /* full response (head + body), NUL-terminated */
    size_t len, cap;
    int    err;       /* sticky OOM flag */
} AdminResp;

static int ar_need(AdminResp *r, size_t extra) {
    size_t need = r->len + extra + 1;
    size_t nc;
    char *nb;
    if (need <= r->cap) return 0;
    nc = r->cap ? r->cap : 64;
    while (nc < need) nc *= 2;
    nb = realloc(r->buf, nc);
    if (!nb) { r->err = 1; return -1; }
    r->buf = nb;
    r->cap = nc;
    return 0;
}

static void ar_append(AdminResp *r, const char *s, size_t n) {
    if (r->err) return;
    if (ar_need(r, n) != 0) return;
    memcpy(r->buf + r->len, s, n);
    r->len += n;
    r->buf[r->len] = '\0';
}

/* Append the full head (status + Content-Type + Content-Length) and body. */
static void ar_respond(AdminResp *r, int status, const char *reason,
                       const char *ctype, const char *body, size_t bodylen) {
    char head[256];
    int hn;
    if (r->err) return;
    hn = snprintf(head, sizeof head,
        "HTTP/1.0 %d %s\r\nContent-Type: %s\r\nContent-Length: %zu\r\n"
        "Connection: close\r\n\r\n", status, reason, ctype, bodylen);
    if (hn < 0 || (size_t)hn >= sizeof head) { r->err = 1; return; }
    ar_append(r, head, (size_t)hn);
    ar_append(r, body, bodylen);
}

/* Append a JSON {"error":"..."} response.  msgs are fixed literals (no
 * user input), so no escaping is required. */
static void ar_err(AdminResp *r, int status, const char *reason,
                   const char *msg) {
    char body[1024];
    int bn = snprintf(body, sizeof body, "{\"error\":\"%s\"}", msg);
    if (bn < 0) { r->err = 1; return; }
    if ((size_t)bn >= sizeof body) bn = (int)(sizeof body - 1);
    ar_respond(r, status, reason, "application/json", body, (size_t)bn);
}

/* Transfer the built response to the caller.  On a sticky OOM frees and
 * returns VISAGE_ENOMEM. */
static int ar_finish(AdminResp *r, char **out, size_t *outlen) {
    if (r->err) {
        free(r->buf);
        r->buf = NULL;
        r->len = 0;
        *out = NULL;
        *outlen = 0;
        return VISAGE_ENOMEM;
    }
    *out = r->buf;
    *outlen = r->len;
    return VISAGE_OK;
}

/* ------------------------------------------------------------------ */
/* Request-line + auth (moved from http.c)                            */
/* ------------------------------------------------------------------ */

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
    /* auth[512] bounds the header value, so a "Bearer <token>" token longer
       than ~505 chars is truncated and can never authenticate.  config-check
       (main.c) enforces this ceiling via ADMIN_TOKEN_MAX_LEN (500). */
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
/* Static UI assets                                                   */
/* ------------------------------------------------------------------ */

/* Return the embedded asset matching `target`, or NULL.  Sets *ctype and
 * *len for the served bytes. */
static const char *static_asset(const char *target, const char **ctype,
                                size_t *len) {
    if (strcmp(target, "/") == 0 || strcmp(target, "/admin") == 0 ||
        strcmp(target, "/admin/") == 0 || strcmp(target, "/index.html") == 0) {
        *ctype = "text/html; charset=utf-8";
        *len = visage_admin_index_html_len;
        return visage_admin_index_html;
    }
    if (strcmp(target, "/app.js") == 0) {
        *ctype = "text/javascript; charset=utf-8";
        *len = visage_admin_app_js_len;
        return visage_admin_app_js;
    }
    if (strcmp(target, "/style.css") == 0) {
        *ctype = "text/css; charset=utf-8";
        *len = visage_admin_style_css_len;
        return visage_admin_style_css;
    }
    return NULL;
}

/* Serve a GET of a static asset.  Returns 0 if served, -1 if `target` is not
 * a static path (caller continues to auth + dispatch). */
static int serve_static(const char *method, const char *target, AdminResp *r) {
    const char *ctype, *body;
    size_t len;
    if (strcmp(method, "GET") != 0) return -1;
    body = static_asset(target, &ctype, &len);
    if (!body) return -1;
    ar_respond(r, 200, "OK", ctype, body, len);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Handlers                                                           */
/* ------------------------------------------------------------------ */

static void handle_log(Store *s, AdminResp *r, const char *target) {
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
            if (v > 1000ul * 10) break;
            v = v * 10 + (unsigned long)(*p - '0');
            p++;
        }
        if (v > 0) n = (size_t)v;
    }
    if (n > 1000) n = 1000;

    if (store_log_recent(s, n, &entries, &nentries) != VISAGE_OK) {
        ar_err(r, 500, "Internal Server Error", "store error");
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
    if (!body) { ar_err(r, 500, "Internal Server Error", "out of memory"); return; }
    ar_respond(r, 200, "OK", "application/json", body, bodylen);
    free(body);
}

static void handle_alias(const Config *cfg, Store *s, AdminResp *r, int rm,
                         const char *req, size_t header_end) {
    char alias[512], dest[512];
    int rc;
    const char *body = req + header_end;

    if (json_obj_get_str(body, "alias", alias, sizeof alias) != 0 ||
        json_obj_get_str(body, "destination", dest, sizeof dest) != 0) {
        ar_err(r, 400, "Bad Request", "expected {\"alias\",\"destination\"}");
        return;
    }

    if (config_alias_read_only(cfg, alias)) {
        ar_err(r, 403, "Forbidden", "alias is declared in config (read-only)");
        return;
    }

    rc = rm ? store_alias_rm(s, alias, dest)
            : store_alias_add(s, alias, dest);
    if (rc != VISAGE_OK) {
        ar_err(r, 500, "Internal Server Error", "store error");
        return;
    }
    ar_respond(r, 200, "OK", "application/json", "{\"ok\":true}", 11);
}

/* GET /aliases — every alias fact as a flat (alias, destination) list. */
static void handle_aliases(Store *s, AdminResp *r) {
    char **aliases = NULL, **dests = NULL;
    size_t n = 0, i;
    JsonBuilder b;
    char *body;
    size_t bodylen;

    if (store_alias_list_all(s, &aliases, &dests, &n) != VISAGE_OK) {
        ar_err(r, 500, "Internal Server Error", "store error");
        return;
    }

    jsonb_init(&b);
    jsonb_begin_object(&b);
    jsonb_key(&b, "aliases");
    jsonb_begin_array(&b);
    for (i = 0; i < n; i++) {
        if (i) jsonb_comma(&b);
        jsonb_begin_object(&b);
        jsonb_key(&b, "alias");       jsonb_str(&b, aliases[i]);       jsonb_comma(&b);
        jsonb_key(&b, "destination"); jsonb_str(&b, dests[i]);
        jsonb_end_object(&b);
    }
    jsonb_end_array(&b);
    jsonb_end_object(&b);
    body = jsonb_detach(&b, &bodylen);
    store_free_strvec(aliases, n);
    store_free_strvec(dests, n);
    if (!body) { ar_err(r, 500, "Internal Server Error", "out of memory"); return; }
    ar_respond(r, 200, "OK", "application/json", body, bodylen);
    free(body);
}

/* GET /status — dashboard JSON: hostname, domains, listeners, relay, and
 * queue counts by status. */
static void handle_status(const Config *cfg, Store *s, AdminResp *r) {
    static const char *qstatus[4] = {"queued", "delivering", "delivered", "permfail"};
    JsonBuilder b;
    char *body;
    size_t bodylen;
    long q[4];
    long ac;
    int i;

    ac = store_alias_count(s);
    if (ac < 0) { ar_err(r, 500, "Internal Server Error", "store error"); return; }
    for (i = 0; i < 4; i++) {
        q[i] = store_queue_count_by_status(s, qstatus[i]);
        if (q[i] < 0) { ar_err(r, 500, "Internal Server Error", "store error"); return; }
    }

    jsonb_init(&b);
    jsonb_begin_object(&b);
    jsonb_key(&b, "hostname");
    jsonb_str(&b, cfg->hostname ? cfg->hostname : "");
    jsonb_comma(&b);

    jsonb_key(&b, "domains");
    jsonb_begin_array(&b);
    for (i = 0; i < (int)cfg->ndomains; i++) {
        if (i) jsonb_comma(&b);
        jsonb_str(&b, cfg->domains[i] ? cfg->domains[i] : "");
    }
    jsonb_end_array(&b);
    jsonb_comma(&b);

    jsonb_key(&b, "listen");
    jsonb_begin_object(&b);
    jsonb_key(&b, "address"); jsonb_str(&b, cfg->listen.address ? cfg->listen.address : "");
    jsonb_comma(&b);
    jsonb_key(&b, "port");    jsonb_u32(&b, cfg->listen.port);
    jsonb_end_object(&b);
    jsonb_comma(&b);

    jsonb_key(&b, "http");
    jsonb_begin_object(&b);
    jsonb_key(&b, "address"); jsonb_str(&b, cfg->http.address ? cfg->http.address : "");
    jsonb_comma(&b);
    jsonb_key(&b, "port");    jsonb_u32(&b, cfg->http.port);
    jsonb_end_object(&b);
    jsonb_comma(&b);

    jsonb_key(&b, "relay");
    jsonb_begin_object(&b);
    jsonb_key(&b, "host"); jsonb_str(&b, cfg->relay.host ? cfg->relay.host : "");
    jsonb_comma(&b);
    jsonb_key(&b, "port"); jsonb_u32(&b, cfg->relay.port);
    jsonb_comma(&b);
    jsonb_key(&b, "tls");  jsonb_str(&b, cfg->relay.tls ? cfg->relay.tls : "");
    jsonb_end_object(&b);
    jsonb_comma(&b);

    jsonb_key(&b, "alias_count");
    jsonb_u32(&b, (uint32_t)ac);
    jsonb_comma(&b);

    jsonb_key(&b, "queue");
    jsonb_begin_object(&b);
    for (i = 0; i < 4; i++) {
        if (i) jsonb_comma(&b);
        jsonb_key(&b, qstatus[i]);
        jsonb_u32(&b, (uint32_t)q[i]);
    }
    jsonb_end_object(&b);

    jsonb_end_object(&b);
    body = jsonb_detach(&b, &bodylen);
    if (!body) { ar_err(r, 500, "Internal Server Error", "out of memory"); return; }
    ar_respond(r, 200, "OK", "application/json", body, bodylen);
    free(body);
}

/* POST /replay { "msgid": N } — re-queue every terminal (delivered/permfail)
   delivery for msgid whose durably-retained spool body <msgid>.<k>.out.eml
   still exists, flipping it back to "queued" (attempts reset, next_ts 0) so the
   queue re-drive redelivers it.  Responds {"ok":true,"replayed":K}. */
typedef struct {
    uint32_t msgid;
    uint32_t k;
} ReplayItem;

typedef struct {
    uint32_t     msgid;
    ReplayItem  *items;
    size_t       n, cap;
    int          oom;
} ReplayCollect;

static int replay_collect_cb(uint32_t k, const char *from, const char *to,
                             const char *status, void *user) {
    ReplayCollect *c = (ReplayCollect *)user;
    ReplayItem *it;
    (void)from;
    (void)to;
    /* Only terminal states are replayable: delivered or permfail.  A
       queued/delivering delivery is already active and must not be touched. */
    if (strcmp(status, "delivered") != 0 && strcmp(status, "permfail") != 0)
        return 0;
    if (c->n == c->cap) {
        size_t nc = c->cap ? c->cap * 2 : 4;
        ReplayItem *na = realloc(c->items, nc * sizeof *na);
        if (!na) { c->oom = 1; return 1; }
        c->items = na;
        c->cap = nc;
    }
    it = &c->items[c->n];
    it->msgid = c->msgid;
    it->k = k;
    c->n++;
    return 0;
}

static void handle_replay(const Config *cfg, Store *s, AdminResp *r,
                          const char *req, size_t header_end) {
    const char *body = req + header_end;
    uint32_t msgid;
    ReplayCollect rc;
    size_t i;
    int replayed = 0;
    char spoolpath[4096];
    char resp[128];
    int bn;

    if (json_obj_get_u32(body, "msgid", &msgid) != 0) {
        ar_err(r, 400, "Bad Request", "expected {\"msgid\":N}");
        return;
    }

    /* Collect the terminal rows (READ-ONLY walk), then mutate AFTER the walk:
       store_queue_set_status reallocs the dafsa states array. */
    memset(&rc, 0, sizeof rc);
    rc.msgid = msgid;
    if (store_queue_walk_msgid(s, msgid, replay_collect_cb, &rc)
            != VISAGE_OK || rc.oom) {
        free(rc.items);
        ar_err(r, 500, "Internal Server Error", "store error");
        return;
    }

    for (i = 0; i < rc.n; i++) {
        int n = snprintf(spoolpath, sizeof spoolpath, "%s/%u.%u.out.eml",
                         cfg->storage.spool, rc.items[i].msgid,
                         rc.items[i].k);
        if (n < 0 || (size_t)n >= sizeof spoolpath) continue;
        if (access(spoolpath, F_OK) != 0) continue;   /* no retained body */
        if (store_queue_set_status(s, rc.items[i].msgid,
                                   rc.items[i].k, "queued", 0, 0)
                == VISAGE_OK)
            replayed++;
    }
    free(rc.items);

    bn = snprintf(resp, sizeof resp, "{\"ok\":true,\"replayed\":%d}", replayed);
    if (bn < 0 || (size_t)bn >= sizeof resp) {
        ar_err(r, 500, "Internal Server Error", "out of memory");
        return;
    }
    ar_respond(r, 200, "OK", "application/json", resp, (size_t)bn);
}

/* ------------------------------------------------------------------ */
/* Entry point                                                        */
/* ------------------------------------------------------------------ */

/* Build the full HTTP response for a complete buffered request.  On success
 * returns VISAGE_OK and sets *out (malloc'd, caller frees) to the full
 * response bytes and *outlen to its length. */
int admin_build_response(const Config *cfg, Store *store,
                         const char *req, size_t reqlen, size_t header_end,
                         char **out, size_t *outlen) {
    char method[16], target[1024];
    AdminResp r;

    if (!cfg || !store || !req || !out || !outlen) return VISAGE_EPARAM;
    *out = NULL;
    *outlen = 0;
    memset(&r, 0, sizeof r);

    if (parse_request_line(req, reqlen, method, sizeof method,
                           target, sizeof target) != 0) {
        ar_err(&r, 400, "Bad Request", "malformed request");
        return ar_finish(&r, out, outlen);
    }
    if (header_end == SIZE_MAX || header_end > reqlen) {
        ar_err(&r, 400, "Bad Request", "malformed headers");
        return ar_finish(&r, out, outlen);
    }

    /* Public, no auth: health + the data-free static UI shell. */
    if (strcmp(method, "GET") == 0 && strcmp(target, "/health") == 0) {
        ar_respond(&r, 200, "OK", "application/json", "{\"ok\":true}", 11);
        return ar_finish(&r, out, outlen);
    }
    if (serve_static(method, target, &r) == 0)
        return ar_finish(&r, out, outlen);

    /* Everything else requires the bearer token. */
    if (!auth_ok(req, reqlen, header_end, cfg->admin.token)) {
        ar_err(&r, 401, "Unauthorized", "missing or invalid token");
        return ar_finish(&r, out, outlen);
    }

    if (strcmp(method, "GET") == 0 && strcmp(target, "/aliases") == 0) {
        handle_aliases(store, &r);
    } else if (strcmp(method, "GET") == 0 && strcmp(target, "/status") == 0) {
        handle_status(cfg, store, &r);
    } else if (strcmp(method, "GET") == 0 &&
               (strcmp(target, "/log") == 0 || strncmp(target, "/log?", 5) == 0)) {
        handle_log(store, &r, target);
    } else if (strcmp(method, "POST") == 0 && strcmp(target, "/alias") == 0) {
        handle_alias(cfg, store, &r, 0, req, header_end);
    } else if (strcmp(method, "DELETE") == 0 && strcmp(target, "/alias") == 0) {
        handle_alias(cfg, store, &r, 1, req, header_end);
    } else if (strcmp(method, "POST") == 0 && strcmp(target, "/replay") == 0) {
        handle_replay(cfg, store, &r, req, header_end);
    } else if ((strcmp(method, "GET") == 0 ||
                strcmp(method, "POST") == 0 ||
                strcmp(method, "DELETE") == 0) &&
               (strcmp(target, "/alias") == 0 ||
                strcmp(target, "/replay") == 0 ||
                strcmp(target, "/aliases") == 0 ||
                strcmp(target, "/status") == 0 ||
                strcmp(target, "/log") == 0 || strncmp(target, "/log?", 5) == 0 ||
                strcmp(target, "/health") == 0 ||
                strcmp(target, "/") == 0 || strcmp(target, "/admin") == 0 ||
                strcmp(target, "/admin/") == 0 || strcmp(target, "/index.html") == 0 ||
                strcmp(target, "/app.js") == 0 || strcmp(target, "/style.css") == 0)) {
        /* Known path, wrong method. */
        ar_err(&r, 405, "Method Not Allowed", "method not allowed");
    } else {
        ar_err(&r, 404, "Not Found", "unknown path");
    }
    return ar_finish(&r, out, outlen);
}
