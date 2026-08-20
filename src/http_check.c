/* http_check.c — in-sandbox unit checks for the incremental HTTP request
 * parser (src/http_parse.c).  No sockets: feeds requests in chunks and asserts
 * the parse verdicts (NEED_MORE -> DONE, header/body framing, oversize -> ERR,
 * malformed/absent Content-Length handling).  Returns 0 only if all pass. */
#include "visage.h"
#include "http_parse.h"

#include <stdio.h>
#include <string.h>

static int nchecks = 0;
static int nfails = 0;

static void check_ok(const char *what) {
    nchecks++;
    printf("ok   %s\n", what);
}

static void check_fail(const char *what, const char *detail) {
    nchecks++;
    nfails++;
    if (detail)
        printf("FAIL %s — %s\n", what, detail);
    else
        printf("FAIL %s\n", what);
}

#define EXPECT(cond, what) \
    do { if (cond) check_ok(what); else check_fail(what, NULL); } while (0)

/* Accumulator that simulates feeding a socket in arbitrary chunks. */
static char   acc[HTTP_MAX_REQ + 1];
static size_t acclen;

static int feed_raw(const char *chunk, size_t clen, size_t cap,
                    size_t *he, size_t *bl) {
    memcpy(acc + acclen, chunk, clen);
    acclen += clen;
    acc[acclen] = '\0';
    return http_parse_probe(acc, acclen, cap, he, bl);
}

static int feed(const char *chunk, size_t cap, size_t *he, size_t *bl) {
    return feed_raw(chunk, strlen(chunk), cap, he, bl);
}

static void feed_reset(void) { acclen = 0; }

/* ---- header-end / content-length framing ---- */

static void get_health_test(void) {
    size_t he = 0, bl = 0;
    feed_reset();

    EXPECT(feed("GET ", HTTP_MAX_REQ, &he, &bl) == HTTP_PARSE_NEED_MORE,
           "parse: GET /health header chunk 1 -> need more");
    EXPECT(feed("/health HTTP/1.0\r\nHost: x\r\n", HTTP_MAX_REQ, &he, &bl)
               == HTTP_PARSE_NEED_MORE,
           "parse: GET /health headers still incomplete -> need more");
    EXPECT(feed("\r\n", HTTP_MAX_REQ, &he, &bl) == HTTP_PARSE_DONE,
           "parse: GET /health complete on blank line -> done");
    EXPECT(he == acclen, "parse: GET /health header_end == total length");
    EXPECT(bl == 0, "parse: GET /health body_len == 0 (no Content-Length)");
}

static void post_alias_test(void) {
    static const char *body = "{\"alias\":\"x\",\"destination\":\"y\"}";
    size_t blen = strlen(body);
    char hdr[256];
    int hn = snprintf(hdr, sizeof hdr,
        "POST /alias HTTP/1.0\r\nAuthorization: Bearer t\r\n"
        "Content-Length: %zu\r\n\r\n", blen);
    size_t he = 0, bl = 0;
    size_t hdrlen = (size_t)hn;
    feed_reset();

    EXPECT(feed_raw(hdr, hdrlen, HTTP_MAX_REQ, &he, &bl) == HTTP_PARSE_NEED_MORE,
           "parse: POST headers-only -> need more (body pending)");
    EXPECT(he == hdrlen, "parse: POST header_end at end of header block");
    EXPECT(bl == blen, "parse: POST body_len == Content-Length");

    EXPECT(feed_raw(body, 5, HTTP_MAX_REQ, &he, &bl) == HTTP_PARSE_NEED_MORE,
           "parse: POST partial body -> need more");
    EXPECT(feed_raw(body + 5, blen - 5, HTTP_MAX_REQ, &he, &bl) == HTTP_PARSE_DONE,
           "parse: POST body complete -> done");
}

static void cl_case_insensitive_test(void) {
    size_t he = 0, bl = 0;
    feed_reset();
    EXPECT(feed("POST / HTTP/1.0\r\ncontent-length: 4\r\n\r\n", HTTP_MAX_REQ,
                &he, &bl) == HTTP_PARSE_NEED_MORE,
           "parse: lowercase content-length recognized -> need more");
    EXPECT(bl == 4, "parse: lowercase content-length body_len == 4");
    EXPECT(feed("abcd", HTTP_MAX_REQ, &he, &bl) == HTTP_PARSE_DONE,
           "parse: lowercase content-length body complete -> done");
}

/* ---- error / boundary cases ---- */

static void oversize_declared_test(void) {
    size_t he = 0, bl = 0;
    feed_reset();
    EXPECT(feed("POST / HTTP/1.0\r\nContent-Length: 99999999\r\n\r\n",
                HTTP_MAX_REQ, &he, &bl) == HTTP_PARSE_ERR,
           "parse: declared body > cap -> err");
}

static void oversize_buffer_test(void) {
    size_t he = 0, bl = 0;
    char big[100];
    memset(big, 'A', sizeof big);
    feed_reset();
    EXPECT(feed_raw(big, sizeof big, sizeof big, &he, &bl) == HTTP_PARSE_ERR,
           "parse: headers fill cap without terminator -> err");
}

static void body_short_of_cap_test(void) {
    size_t he = 0, bl = 0;
    /* The header below is 39 bytes and declares 62 body bytes, so a complete
     * request needs 39 + 62 = 101 bytes > cap(100).  Feeding exactly cap leaves
     * the body one byte short with the buffer full -> err. */
    enum { CAP = 100 };
    char buf[CAP];
    const char *hdr = "POST / HTTP/1.0\r\nContent-Length: 62\r\n\r\n";
    size_t hlen = strlen(hdr);
    memcpy(buf, hdr, hlen);
    memset(buf + hlen, 'B', CAP - hlen);
    feed_reset();
    EXPECT(feed_raw(buf, CAP, CAP, &he, &bl) == HTTP_PARSE_ERR,
           "parse: body cannot fit within cap -> err");
    EXPECT(bl == 62, "parse: body_short still reports declared body_len");
}

static void malformed_cl_test(void) {
    size_t he = 0, bl = 0;
    feed_reset();
    EXPECT(feed("POST / HTTP/1.0\r\nContent-Length: abc\r\n\r\n", HTTP_MAX_REQ,
                &he, &bl) == HTTP_PARSE_DONE,
           "parse: malformed Content-Length -> done (ignore body)");
    EXPECT(bl == 0, "parse: malformed Content-Length body_len == 0");
}

static void no_cl_test(void) {
    size_t he = 0, bl = 0;
    feed_reset();
    EXPECT(feed("POST / HTTP/1.0\r\nHost: x\r\n\r\n", HTTP_MAX_REQ, &he, &bl)
               == HTTP_PARSE_DONE,
           "parse: no Content-Length -> done");
    EXPECT(bl == 0, "parse: no Content-Length body_len == 0");
}

/* ---- header value extraction ---- */

static void header_value_test(void) {
    char out[64];
    const char *h = "Authorization: Bearer abc\r\nX-Foo:   spaced  \r\n\r\n";
    size_t he = http_find_header_end(h, strlen(h));
    EXPECT(he != SIZE_MAX, "hdr: header-end found");

    EXPECT(http_header_value(h, he, "Authorization", out, sizeof out) == 0 &&
           strcmp(out, "Bearer abc") == 0,
           "hdr: Authorization value extracted");
    EXPECT(http_header_value(h, he, "x-foo", out, sizeof out) == 0 &&
           strcmp(out, "spaced") == 0,
           "hdr: case-insensitive + trimmed value");
    EXPECT(http_header_value(h, he, "Missing", out, sizeof out) == -1,
           "hdr: absent header -> -1");
}

static void ci_eq_test(void) {
    EXPECT(http_ci_eq("Bearer", "bearer", 6) == 1, "ci_eq case-insensitive");
    EXPECT(http_ci_eq("Bearer", "BEARER", 6) == 1, "ci_eq uppercase");
    EXPECT(http_ci_eq("Bearer", "bearzr", 6) == 0, "ci_eq mismatch");
    EXPECT(http_ci_eq("a", "a", 0) == 1, "ci_eq zero length");
}

/* ---- admin route tests (src/admin.c, via admin_build_response) ---- */

static void expect_contains(const char *resp, const char *needle,
                            const char *what) {
    EXPECT(resp && strstr(resp, needle) != NULL, what);
}

/* Build a request + feed it through admin_build_response.  Returns the
 * admin_build_response status; on success *resp is a malloc'd full HTTP
 * response the caller frees. */
static int route(const Config *cfg, Store *store, const char *req,
                 char **resp, size_t *resplen) {
    size_t he = SIZE_MAX, bl = 0;
    if (http_parse_probe(req, strlen(req), HTTP_MAX_REQ, &he, &bl)
            != HTTP_PARSE_DONE)
        return -1;
    return admin_build_response(cfg, store, req, strlen(req), he, resp, resplen);
}

static void build_cfg(Config *cfg) {
    static char host[] = "mail.example.com";
    static char dom[]  = "example.com";
    static char *doms[] = { dom };
    static char tok[]  = "sekret-token";
    static char addr[] = "0.0.0.0";
    static char relay_host[] = "relay.example.com";
    static char tls[]  = "tls";
    static char spool[] = "/tmp/visage_http_spool";
    static char lock_alias[] = "locked@example.com";
    static char lock_dest[]  = "l@realmail.example";
    static char *lock_dests[] = { lock_dest };
    static ConfigAlias aliases[1] = { { lock_alias, lock_dests, 1 } };

    memset(cfg, 0, sizeof *cfg);
    cfg->hostname = host;
    cfg->domains = doms;
    cfg->ndomains = 1;
    cfg->listen.address = addr;
    cfg->listen.port = 25;
    cfg->http.address = addr;
    cfg->http.port = 8000;
    cfg->relay.host = relay_host;
    cfg->relay.port = 587;
    cfg->relay.tls = tls;
    cfg->storage.spool = spool;
    cfg->aliases = aliases;
    cfg->naliases = 1;
    cfg->admin.token = tok;
}

static void admin_routes_test(void) {
    char tpl[] = "/tmp/visage_http_XXXXXX";
    char *dir = mkdtemp(tpl);
    Config cfg;
    Store *s;
    char *resp = NULL;
    size_t resplen = 0;

    build_cfg(&cfg);
    EXPECT(dir != NULL, "admin: mkdtemp");
    s = store_open(dir);
    EXPECT(s != NULL, "admin: store_open");
    if (!s) return;

    EXPECT(store_alias_add(s, "alice@example.com", "a@realmail.example") == VISAGE_OK,
           "admin: seed alias a");
    EXPECT(store_alias_add(s, "alice@example.com", "b@realmail.example") == VISAGE_OK,
           "admin: seed alias b");

    /* static UI shell: no auth, correct Content-Type, real body. */
    EXPECT(route(&cfg, s, "GET / HTTP/1.0\r\nHost: x\r\n\r\n", &resp, &resplen) == VISAGE_OK,
           "admin: GET / builds");
    expect_contains(resp, "HTTP/1.0 200 OK", "admin: GET / -> 200");
    expect_contains(resp, "Content-Type: text/html; charset=utf-8", "admin: GET / -> text/html");
    expect_contains(resp, "visage admin", "admin: GET / body has the UI");
    free(resp); resp = NULL;

    EXPECT(route(&cfg, s, "GET /app.js HTTP/1.0\r\nHost: x\r\n\r\n", &resp, &resplen) == VISAGE_OK,
           "admin: GET /app.js builds");
    expect_contains(resp, "Content-Type: text/javascript; charset=utf-8", "admin: /app.js -> text/javascript");
    free(resp); resp = NULL;

    EXPECT(route(&cfg, s, "GET /style.css HTTP/1.0\r\nHost: x\r\n\r\n", &resp, &resplen) == VISAGE_OK,
           "admin: GET /style.css builds");
    expect_contains(resp, "Content-Type: text/css; charset=utf-8", "admin: /style.css -> text/css");
    free(resp); resp = NULL;

    /* /health stays public. */
    EXPECT(route(&cfg, s, "GET /health HTTP/1.0\r\nHost: x\r\n\r\n", &resp, &resplen) == VISAGE_OK,
           "admin: GET /health builds");
    expect_contains(resp, "HTTP/1.0 200 OK", "admin: /health -> 200 (no auth)");
    expect_contains(resp, "{\"ok\":true}", "admin: /health body");
    free(resp); resp = NULL;

    /* data routes 401 without a token. */
    EXPECT(route(&cfg, s, "GET /aliases HTTP/1.0\r\nHost: x\r\n\r\n", &resp, &resplen) == VISAGE_OK,
           "admin: /aliases no token builds");
    expect_contains(resp, "HTTP/1.0 401 Unauthorized", "admin: /aliases no token -> 401");
    free(resp); resp = NULL;

    EXPECT(route(&cfg, s, "GET /status HTTP/1.0\r\nHost: x\r\n\r\n", &resp, &resplen) == VISAGE_OK,
           "admin: /status no token builds");
    expect_contains(resp, "HTTP/1.0 401 Unauthorized", "admin: /status no token -> 401");
    free(resp); resp = NULL;

    /* wrong token also 401 (constant-time auth). */
    EXPECT(route(&cfg, s,
                 "GET /aliases HTTP/1.0\r\nAuthorization: Bearer wrong\r\nHost: x\r\n\r\n",
                 &resp, &resplen) == VISAGE_OK, "admin: /aliases wrong token");
    expect_contains(resp, "HTTP/1.0 401 Unauthorized", "admin: wrong token -> 401");
    free(resp); resp = NULL;

    /* /aliases with token -> 200 + flat JSON list. */
    EXPECT(route(&cfg, s,
                 "GET /aliases HTTP/1.0\r\nAuthorization: Bearer sekret-token\r\nHost: x\r\n\r\n",
                 &resp, &resplen) == VISAGE_OK, "admin: /aliases with token");
    expect_contains(resp, "HTTP/1.0 200 OK", "admin: /aliases with token -> 200");
    expect_contains(resp, "Content-Type: application/json", "admin: /aliases content-type");
    expect_contains(resp, "\"alias\":\"alice@example.com\"", "admin: /aliases lists alice");
    expect_contains(resp, "\"destination\":\"a@realmail.example\"", "admin: /aliases lists dest a");
    expect_contains(resp, "\"destination\":\"b@realmail.example\"", "admin: /aliases lists dest b");
    free(resp); resp = NULL;

    /* /status with token -> 200 + dashboard fields. */
    EXPECT(route(&cfg, s,
                 "GET /status HTTP/1.0\r\nAuthorization: Bearer sekret-token\r\nHost: x\r\n\r\n",
                 &resp, &resplen) == VISAGE_OK, "admin: /status with token");
    expect_contains(resp, "HTTP/1.0 200 OK", "admin: /status with token -> 200");
    expect_contains(resp, "\"hostname\":\"mail.example.com\"", "admin: /status hostname");
    expect_contains(resp, "\"alias_count\":2", "admin: /status alias_count == 2");
    expect_contains(resp, "\"queued\":0", "admin: /status queue queued == 0");
    free(resp); resp = NULL;

    /* POST /alias to a config-declared alias -> 403 read-only. */
    {
        const char *body = "{\"alias\":\"locked@example.com\",\"destination\":\"x@y.org\"}";
        char req[600];
        int n = snprintf(req, sizeof req,
                         "POST /alias HTTP/1.0\r\nAuthorization: Bearer sekret-token\r\n"
                         "Content-Length: %zu\r\n\r\n%s", strlen(body), body);
        EXPECT(n > 0 && route(&cfg, s, req, &resp, &resplen) == VISAGE_OK,
               "admin: POST read-only alias builds");
        expect_contains(resp, "HTTP/1.0 403 Forbidden", "admin: read-only alias -> 403");
        free(resp); resp = NULL;
    }

    /* unknown path with a valid token -> 404. */
    EXPECT(route(&cfg, s,
                 "GET /nope HTTP/1.0\r\nAuthorization: Bearer sekret-token\r\nHost: x\r\n\r\n",
                 &resp, &resplen) == VISAGE_OK, "admin: GET /nope");
    expect_contains(resp, "HTTP/1.0 404 Not Found", "admin: unknown path -> 404");
    free(resp); resp = NULL;

    store_close(s);
}

int main(void) {
    ci_eq_test();
    header_value_test();
    get_health_test();
    post_alias_test();
    cl_case_insensitive_test();
    oversize_declared_test();
    oversize_buffer_test();
    body_short_of_cap_test();
    malformed_cl_test();
    no_cl_test();
    admin_routes_test();

    printf("\n%d checks, %d failed\n", nchecks, nfails);
    return nfails ? 1 : 0;
}
