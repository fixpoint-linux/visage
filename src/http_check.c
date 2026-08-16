/* http_check.c — in-sandbox unit checks for the incremental HTTP request
 * parser (src/http_parse.c).  No sockets: feeds requests in chunks and asserts
 * the parse verdicts (NEED_MORE -> DONE, header/body framing, oversize -> ERR,
 * malformed/absent Content-Length handling).  Returns 0 only if all pass. */
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

    printf("\n%d checks, %d failed\n", nchecks, nfails);
    return nfails ? 1 : 0;
}
