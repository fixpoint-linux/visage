/* http_parse.c — pure HTTP/1.x request-parsing primitives (see http_parse.h).
 *
 * These mirror the pre-R4 blocking parser in http.c exactly, so the wire
 * semantics (header-end detection, Content-Length handling, oversize rules)
 * are unchanged.  The only difference is that they are pure over a buffer
 * rather than reading from a socket. */
#include "http_parse.h"

#include <stdlib.h>
#include <string.h>

/* ASCII case-insensitive compare over exactly n bytes. */
int http_ci_eq(const char *a, const char *b, size_t n) {
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
size_t http_find_header_end(const char *buf, size_t n) {
    size_t i;
    for (i = 0; i + 3 < n; i++)
        if (buf[i] == '\r' && buf[i + 1] == '\n' &&
            buf[i + 2] == '\r' && buf[i + 3] == '\n')
            return i + 4;
    return SIZE_MAX;
}

/* Find a header "Name: value" in the header block buf[0..hlen).  Copies the
 * (trimmed) value into out.  Returns 0 on success, -1 if not found. */
int http_header_value(const char *buf, size_t hlen, const char *name,
                      char *out, size_t outsz) {
    size_t nl = strlen(name);
    size_t i = 0;
    while (i < hlen) {
        size_t line_end = i;
        size_t linelen;
        while (line_end < hlen && buf[line_end] != '\r' && buf[line_end] != '\n')
            line_end++;
        linelen = line_end - i;
        if (linelen > nl && http_ci_eq(buf + i, name, nl) && buf[i + nl] == ':') {
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

int http_parse_probe(const char *buf, size_t len, size_t cap,
                     size_t *header_end, size_t *body_len) {
    size_t he = http_find_header_end(buf, len);

    if (he == SIZE_MAX) {
        /* No end-of-headers marker yet. */
        if (len >= cap) return HTTP_PARSE_ERR;   /* headers exceed cap */
        return HTTP_PARSE_NEED_MORE;
    }

    if (header_end) *header_end = he;
    if (body_len) *body_len = 0;

    {
        char cl[32];
        if (http_header_value(buf, he, "Content-Length", cl, sizeof cl) == 0) {
            char *endp;
            unsigned long v = strtoul(cl, &endp, 10);
            if (endp != cl) {
                if (v > cap) return HTTP_PARSE_ERR;   /* declared body too big */
                if (body_len) *body_len = (size_t)v;
                if (len - he >= (size_t)v) return HTTP_PARSE_DONE;
                if (len >= cap) return HTTP_PARSE_ERR; /* buffer full, body short */
                return HTTP_PARSE_NEED_MORE;
            }
            /* malformed Content-Length: ignore body */
        }
        /* no (or malformed) Content-Length: no body expected */
        return HTTP_PARSE_DONE;
    }
}
