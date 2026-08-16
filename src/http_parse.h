/* http_parse.h — pure HTTP/1.x request-parsing primitives for the admin API.
 *
 * Factored out of http.c so the incremental request parser can be unit-tested
 * in-sandbox (no sockets, no store).  These functions are pure over a byte
 * buffer; the HTTP state machine in http.c feeds them incrementally as bytes
 * arrive and uses the verdict to drive non-blocking readable/writable events. */
#ifndef VISAGE_HTTP_PARSE_H
#define VISAGE_HTTP_PARSE_H

#include <stddef.h>
#include <stdint.h>

/* Maximum total request bytes (headers + body) the admin server will buffer.
 * Mirrors the pre-R4 fixed-buffer bound; requests beyond this are rejected
 * with 413. */
#define HTTP_MAX_REQ 65536

/* Incremental parse verdicts. */
enum {
    HTTP_PARSE_NEED_MORE = 0,   /* more bytes needed (buffer still has room) */
    HTTP_PARSE_DONE      = 1,   /* a complete request (headers + body) is buffered */
    HTTP_PARSE_ERR       = -1   /* malformed, or exceeds HTTP_MAX_REQ */
};

/* ASCII case-insensitive compare over exactly n bytes (NUL is not special). */
int http_ci_eq(const char *a, const char *b, size_t n);

/* Offset of the end-of-headers marker "\r\n\r\n" in buf[0..n), or SIZE_MAX. */
size_t http_find_header_end(const char *buf, size_t n);

/* Extract the (trimmed) value of header `name` from the header block
   buf[0..hlen).  Copies the value NUL-terminated into out.  Returns 0 on
   success, -1 if the header is absent or out is too small. */
int http_header_value(const char *buf, size_t hlen, const char *name,
                      char *out, size_t outsz);

/* Probe the buffered request bytes buf[0..len) (len <= cap, cap <=
   HTTP_MAX_REQ).  On HTTP_PARSE_DONE sets *header_end (bytes through the end
   of the header block) and *body_len (expected body bytes per Content-Length;
   0 when there is no Content-Length or it is unparseable).  On
   HTTP_PARSE_NEED_MORE the request is still incomplete; on HTTP_PARSE_ERR it
   is malformed or exceeds cap. */
int http_parse_probe(const char *buf, size_t len, size_t cap,
                     size_t *header_end, size_t *body_len);

#endif /* VISAGE_HTTP_PARSE_H */
