/* jmapd_http.c — HTTP/1.1 request state machine + response writer for jmapd.
 *
 * Why not reuse src/http.c: the admin server has a fixed 64 KiB recv[] array,
 * parses one request and then closes (Connection: close), and its fds are
 * registered into smtp_in's poll loop.  jmapd needs (a) a configurable
 * multi-MiB request cap, (b) keep-alive — the mail-hub client issues several
 * POSTs per poll cycle and a TLS handshake each time is pure latency — and
 * (c) its own listener.  What IS reused is http_parse.c's pure primitives
 * (http_find_header_end / http_header_value / http_ci_eq); the 64 KiB cap and
 * the single-shot parse are caller policy, not parser facts.
 *
 * Request state per connection (JmapdConn):
 *   hdr_scanned   bytes already searched for "\r\n\r\n" — the scan resumes
 *                 from here, so a large body does not re-scan its headers on
 *                 every POLLIN (that would be quadratic in the body size).
 *   header_end    set once the header block is complete.
 *   body_len      Content-Length, known from the header-only parse.
 * Anything after the request (pipelined tail bytes) is a 400: this server
 * serves one request at a time, and accepting a tail would leak bytes from one
 * request into the next (http.c:237-241 takes the same line). */
#include "visage.h"
#include "jmapd.h"
#include "http_parse.h"

#include <sys/socket.h>
#include <ctype.h>

/* ------------------------------------------------------------------ */
/* Small buffer helper (duplicated per house style)                    */
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

/* ------------------------------------------------------------------ */
/* Status text + response writer                                       */
/* ------------------------------------------------------------------ */

const char *jmapd_http_status_text(int status) {
    switch (status) {
    case 200: return "OK";
    case 400: return "Bad Request";
    case 401: return "Unauthorized";
    case 404: return "Not Found";
    case 405: return "Method Not Allowed";
    case 411: return "Length Required";
    case 413: return "Content Too Large";
    case 431: return "Request Header Fields Too Large";
    case 500: return "Internal Server Error";
    case 501: return "Not Implemented";
    case 503: return "Service Unavailable";
    default:  return "Unknown";
    }
}

int jmapd_http_respond(Conn *c, int status, const char *ctype,
                       const char *body, size_t bodylen, bool keep_alive) {
    char head[512];
    int n;
    if (!body) bodylen = 0;
    if (bodylen > JMAPD_MAX_RESP) {
        /* Never emit an unbounded response: the caller's body is replaced by a
           small, honest error rather than being truncated mid-JSON.  The type
           is serverLimit, not serverFail: the request was legal and the answer
           would have been correct, it is the SIZE that is beyond this server,
           and a client can narrow it (fewer objects, a smaller limit). */
        char why[192];
        snprintf(why, sizeof why,
                 "response of %llu bytes exceeds this server's limit of %u "
                 "bytes; request fewer objects or a smaller limit",
                 (unsigned long long)bodylen, (unsigned)JMAPD_MAX_RESP);
        jmapd_log_conn(c, "response-over-limit", why);
        status = 500;
        ctype = "application/json; charset=utf-8";
        body = "{\"type\":\"serverLimit\",\"description\":\"response exceeds "
               "this server's limit; request fewer objects or a smaller "
               "limit\"}";
        bodylen = strlen(body);
    }
    n = snprintf(head, sizeof head,
                 "HTTP/1.1 %d %s\r\n"
                 "Content-Type: %s\r\n"
                 "Content-Length: %zu\r\n"
                 "Cache-Control: no-store\r\n"
                 "X-Content-Type-Options: nosniff\r\n"
                 "Connection: %s\r\n",
                 status, jmapd_http_status_text(status),
                 ctype ? ctype : "text/plain; charset=utf-8", bodylen,
                 keep_alive ? "keep-alive" : "close");
    if (n < 0 || (size_t)n >= sizeof head) return -1;
    if (status == 401) {
        size_t hl = strlen(head);
        int m = snprintf(head + hl, sizeof head - hl,
                         "WWW-Authenticate: Basic realm=\"jmapd\", "
                         "charset=\"UTF-8\"\r\n");
        if (m < 0 || (size_t)m >= sizeof head - hl) return -1;
        n += m;
    } else if (status == 405) {
        size_t hl = strlen(head);
        int m = snprintf(head + hl, sizeof head - hl, "Allow: GET, POST\r\n");
        if (m < 0 || (size_t)m >= sizeof head - hl) return -1;
        n += m;
    }
    {
        size_t hl = strlen(head);
        int m = snprintf(head + hl, sizeof head - hl, "\r\n");
        if (m < 0 || (size_t)m >= sizeof head - hl) return -1;
    }
    if (buf_append(&c->out, &c->out_len, &c->out_cap, head, strlen(head)) != 0)
        return -1;
    if (bodylen &&
        buf_append(&c->out, &c->out_len, &c->out_cap, body, bodylen) != 0)
        return -1;
    return 0;
}

/* Response head only: the body is streamed by the caller afterwards (the blob
   download).  Content-Length is exact, so the response is self-framing and the
   connection can stay alive. */
int jmapd_http_respond_head(Conn *c, int status, const char *ctype,
                            const char *disposition, size_t content_length,
                            bool keep_alive) {
    char head[1024];
    int n;
    n = snprintf(head, sizeof head,
                 "HTTP/1.1 %d %s\r\n"
                 "Content-Type: %s\r\n"
                 "Content-Length: %zu\r\n"
                 "Content-Disposition: %s\r\n"
                 "Cache-Control: no-store\r\n"
                 "X-Content-Type-Options: nosniff\r\n"
                 "Connection: %s\r\n"
                 "\r\n",
                 status, jmapd_http_status_text(status),
                 ctype ? ctype : "application/octet-stream",
                 content_length, disposition ? disposition : "attachment",
                 keep_alive ? "keep-alive" : "close");
    if (n < 0 || (size_t)n >= sizeof head) return -1;
    return buf_append(&c->out, &c->out_len, &c->out_cap, head, (size_t)n);
}

/* ------------------------------------------------------------------ */
/* Request parse (pure; unit-tested)                                   */
/* ------------------------------------------------------------------ */

/* Strict decimal parse: digits only, no sign, no space, no overflow. */
static int parse_content_length(const char *v, size_t *out) {
    size_t i, n = 0;
    if (!v[0]) return -1;
    for (i = 0; v[i]; i++) {
        if (v[i] < '0' || v[i] > '9') return -1;
        if (n > (SIZE_MAX - (size_t)(v[i] - '0')) / 10) return -1;
        n = n * 10 + (size_t)(v[i] - '0');
    }
    *out = n;
    return 0;
}

int jmapd_http_req_parse(const char *buf, size_t len, size_t cap,
                         JmapdHttpReq *req) {
    size_t he, hlen, i, sp1, sp2;
    char v[256];
    int m;

    if (!req) return 400;
    memset(req, 0, sizeof *req);

    he = http_find_header_end(buf, len);
    if (he == SIZE_MAX) {
        if (len >= cap || len >= JMAPD_MAX_HDR) return 431;
        return 0;                       /* headers still arriving */
    }
    if (he > JMAPD_MAX_HDR) return 431;
    hlen = he;
    req->header_end = he;

    /* ---- request line: METHOD SP TARGET SP HTTP/1.x CRLF ---- */
    sp1 = 0;
    while (sp1 < hlen && buf[sp1] != ' ') sp1++;
    if (sp1 == 0 || sp1 >= hlen) return 400;
    sp2 = sp1 + 1;
    while (sp2 < hlen && buf[sp2] != ' ') sp2++;
    if (sp2 >= hlen) return 400;
    req->method_raw = buf;
    req->method_len = sp1;
    if (sp1 == 3 && http_ci_eq(buf, "GET", 3)) req->method = JMAPD_M_GET;
    else if (sp1 == 4 && http_ci_eq(buf, "POST", 4)) req->method = JMAPD_M_POST;
    else req->method = JMAPD_M_OTHER;

    req->path = buf + sp1 + 1;
    req->path_len = sp2 - (sp1 + 1);
    /* Drop any query string: no route is parameterised by one (the download
       template's ?accept= is M2 and is matched by prefix). */
    for (i = 0; i < req->path_len; i++)
        if (req->path[i] == '?') { req->path_len = i; break; }

    if (hlen - sp2 - 1 < 8 || memcmp(buf + sp2 + 1, "HTTP/1.", 7) != 0)
        return 400;                     /* HTTP/0.9 or a bogus version */
    req->minor = buf[sp2 + 8] - '0';
    if (req->minor != 0 && req->minor != 1) return 400;

    /* ---- headers ---- */
    if (http_header_value(buf, hlen, "Transfer-Encoding", v, sizeof v) == 0) {
        /* No transfer coding is implemented: a chunked body cannot be framed,
           so refuse it rather than mis-parse the framing. */
        req->chunked = true;
        return 501;
    }
    if (http_header_value(buf, hlen, "Content-Length", v, sizeof v) == 0) {
        if (parse_content_length(v, &req->body_len) != 0) return 400;
        req->has_cl = true;
        if (req->body_len > cap) return 413;
    }
    if (req->method == JMAPD_M_POST && !req->has_cl) return 411;

    if (http_header_value(buf, hlen, "Authorization", v, sizeof v) == 0) {
        size_t l = strlen(v);
        if (l >= sizeof req->auth) return 431;
        memcpy(req->auth, v, l + 1);
        req->auth_len = l;
    }

    /* keep-alive: HTTP/1.1 defaults on, HTTP/1.0 defaults off */
    req->keep_alive = (req->minor == 1);
    if (http_header_value(buf, hlen, "Connection", v, sizeof v) == 0) {
        if (strlen(v) == 5 && http_ci_eq(v, "close", 5)) req->keep_alive = false;
        else if (strlen(v) == 10 && http_ci_eq(v, "keep-alive", 10))
            req->keep_alive = true;
    }

    /* ---- body ---- */
    m = (int)((len - he) >= req->body_len);
    if (m) return 1;
    if (len >= cap) return 413;         /* buffer full, body still short */
    return 0;
}

/* ------------------------------------------------------------------ */
/* Per-connection machine                                              */
/* ------------------------------------------------------------------ */

/* Routes that exist.  A path that is known but hit with the wrong method gets
   405; an unknown path gets 404; a route the milestone does not implement yet
   answers 501 (RFC-legal, and honest: the URL is advertised by the session
   document). */
enum { ROUTE_NONE = 0, ROUTE_SESSION, ROUTE_API, ROUTE_UPLOAD,
       ROUTE_DOWNLOAD, ROUTE_EVENT };

/* Exact match, or a prefix followed by '/': "/upload" and "/upload/x" match,
   "/uploadx" does not. */
static bool path_exact(const char *p, size_t n, const char *lit) {
    size_t l = strlen(lit);
    if (n == l) return memcmp(p, lit, l) == 0;
    return n > l && p[l] == '/' && memcmp(p, lit, l) == 0;
}

static int route_of(const char *p, size_t n) {
    if (path_exact(p, n, "/.well-known/jmap")) return ROUTE_SESSION;
    if (path_exact(p, n, "/jmap/session")) return ROUTE_SESSION;
    if (path_exact(p, n, "/api")) return ROUTE_API;
    if (path_exact(p, n, "/upload")) return ROUTE_UPLOAD;
    if (path_exact(p, n, "/download")) return ROUTE_DOWNLOAD;
    if (path_exact(p, n, "/event")) return ROUTE_EVENT;
    return ROUTE_NONE;
}

/* An HTTP-level refusal: a small JSON body, Connection: close, and the
   connection is marked dead.  The `type` mirrors RFC 8620 3.6.2 where one
   exists, so a JMAP client sees the same vocabulary at both levels. */
static void drop_status(Conn *c, int status) {
    const char *body;
    switch (status) {
    case 404: body = "{\"type\":\"notFound\"}"; break;
    case 405: body = "{\"type\":\"methodNotAllowed\"}"; break;
    case 411: body = "{\"type\":\"notRequest\"}"; break;
    case 413: body = "{\"type\":\"limit\"}"; break;
    case 431: body = "{\"type\":\"limit\"}"; break;
    case 501: body = "{\"type\":\"notImplemented\"}"; break;
    case 401: body = "{\"type\":\"unauthorized\"}"; break;
    case 400: body = "{\"type\":\"notRequest\"}"; break;
    default:  body = "{\"type\":\"serverFail\"}"; status = 500; break;
    }
    (void)jmapd_http_respond(c, status, "application/json; charset=utf-8",
                             body, strlen(body), false);
    c->closed = true;
}

/* Percent-decode one URL path segment.  A decoded NUL, or a value that does
   not fit, is rejected: the result names a blob and a part, and neither may
   carry a byte that could not have been produced by the encoder. */
static int pct_decode(const char *s, size_t n, char *out, size_t outsz) {
    size_t i = 0, o = 0;
    if (outsz == 0) return -1;
    while (i < n) {
        unsigned char ch = (unsigned char)s[i];
        if (ch == '%') {
            int hi, lo;
            if (i + 2 >= n) return -1;
            hi = s[i + 1] >= '0' && s[i + 1] <= '9' ? s[i + 1] - '0'
                 : (s[i + 1] | 0x20) >= 'a' && (s[i + 1] | 0x20) <= 'f'
                       ? (s[i + 1] | 0x20) - 'a' + 10
                       : -1;
            lo = s[i + 2] >= '0' && s[i + 2] <= '9' ? s[i + 2] - '0'
                 : (s[i + 2] | 0x20) >= 'a' && (s[i + 2] | 0x20) <= 'f'
                       ? (s[i + 2] | 0x20) - 'a' + 10
                       : -1;
            if (hi < 0 || lo < 0) return -1;
            ch = (unsigned char)((hi << 4) | lo);
            i += 3;
        } else {
            i++;
        }
        if (ch == '\0') return -1;
        if (o + 1 >= outsz) return -1;
        out[o++] = (char)ch;
    }
    out[o] = '\0';
    return 0;
}

/* Split /download/{accountId}/{blobId}/{name} into its three segments. */
static int download_segments(const JmapdHttpReq *req, char *acct, size_t acctsz,
                             char *blob, size_t blobsz, char *name,
                             size_t namesz) {
    const char *p = req->path;
    size_t n = req->path_len, i, start, seg = 0;
    char *dst[3];
    size_t dstsz[3];
    dst[0] = acct; dstsz[0] = acctsz;
    dst[1] = blob; dstsz[1] = blobsz;
    dst[2] = name; dstsz[2] = namesz;
    /* step past the "/download" prefix the router already matched */
    i = strlen("/download");
    if (n < i) return 404;
    while (i < n) {
        if (p[i] != '/') return 404;
        i++;
        start = i;
        while (i < n && p[i] != '/') i++;
        if (seg >= 3) return 404;
        if (i == start) return 404;                 /* empty segment */
        if (pct_decode(p + start, i - start, dst[seg], dstsz[seg]) != 0)
            return 404;
        seg++;
    }
    return seg == 3 ? 0 : 404;
}

/* GET /download/... — serve the DECODED bytes of one MIME part.  The id is
   parsed and the part resolved before the file is opened; the body is pumped
   from the file on POLLOUT, never buffered whole. */
static void dispatch_download(JmapdServer *srv, JmapdConn *c,
                              const JmapdHttpReq *req) {
    char acct[IMAPD_MAX_USER + 1], blob[JMAPD_BLOB_MAX], name[256];
    JmapdBlob *b = NULL;
    int st;

    if (jmapd_core_auth(srv, c, req) != 0) {
        drop_status(&c->c, 401);
        return;
    }
    /* A byte must never be served without the principal THIS request proved:
       reaching here with no user is a router bug, not a client error. */
    if (!c->c.user) {
        jmapd_log(c, "no-request-user", NULL, "route=download");
        drop_status(&c->c, 500);
        return;
    }
    st = download_segments(req, acct, sizeof acct, blob, sizeof blob, name,
                           sizeof name);
    if (st != 0) { drop_status(&c->c, st); return; }
    if (strcmp(acct, c->c.user) != 0) { drop_status(&c->c, 404); return; }
    st = jmapd_download_open(srv, c->c.user, blob, name, &b);
    if (st != 0) { drop_status(&c->c, st); return; }
    if (jmapd_http_respond_head(&c->c, 200, jmapd_download_ctype(b),
                               jmapd_download_disposition(b),
                               jmapd_download_length(b), req->keep_alive)
            != 0) {
        jmapd_download_free(c);
        drop_status(&c->c, 500);
        return;
    }
    c->blob = b;
    jmapd_download_pump(c);
}

static void dispatch(JmapdServer *srv, JmapdConn *c, const JmapdHttpReq *req,
                     const char *body, size_t bodylen) {
    int route = route_of(req->path, req->path_len);
    int status = 200;
    const char *ctype = "application/json; charset=utf-8";
    char *out = NULL;
    size_t outlen = 0;
    bool keep;

    if (route == ROUTE_NONE) { drop_status(&c->c, 404); return; }
    if (route == ROUTE_SESSION && req->method != JMAPD_M_GET) {
        drop_status(&c->c, 405);
        return;
    }
    if (route == ROUTE_API && req->method != JMAPD_M_POST) {
        drop_status(&c->c, 405);
        return;
    }
    if (route == ROUTE_DOWNLOAD) {
        if (req->method != JMAPD_M_GET) { drop_status(&c->c, 405); return; }
        dispatch_download(srv, c, req);
        return;
    }
    if (route == ROUTE_UPLOAD || route == ROUTE_EVENT) {
        /* v1 scope cut: no blob upload, no push (EventSource).  The session
           document advertises these URLs because the client requires all
           four; they answer 501 rather than pretending. */
        drop_status(&c->c, 501);
        return;
    }

    if (jmapd_core_handle(srv, c, req, body, bodylen, &status, &ctype, &out,
                          &outlen) != 0) {
        drop_status(&c->c, 500);
        return;
    }
    keep = req->keep_alive && status != 401;
    if (jmapd_http_respond(&c->c, status, ctype, out, outlen, keep) != 0) {
        free(out);
        c->c.closed = true;
        return;
    }
    free(out);
    if (!keep) c->c.closed = true;
}

void jmapd_http_readable(JmapdServer *srv, JmapdConn *c, time_t now) {
    char tmp[JMAPD_RECV_CHUNK];
    Conn *cc = &c->c;

    /* A download owns the connection until its body is fully queued: reading
       another request now would interleave it with the response body. */
    if (c->blob) return;

    /* ---- 1. read whatever the socket has ---- */
    if (cc->tls) {
        int n;
        if (!imapd_tls_established(cc)) return;
        /* Drain loop: mbedtls buffers decrypted plaintext internally. */
        for (;;) {
            n = imapd_tls_recv(cc, tmp, sizeof tmp);
            if (n < 0) { cc->closed = true; return; }
            if (n == 0) break;
            cc->last_act = now;
            if (buf_append(&cc->in, &cc->in_len, &cc->in_cap, tmp,
                           (size_t)n) != 0) {
                drop_status(cc, 413);
                return;
            }
        }
    } else {
        ssize_t n = recv(cc->fd, tmp, sizeof tmp, 0);
        if (n < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
                return;
            cc->closed = true;
            return;
        }
        if (n == 0) { cc->closed = true; return; }
        cc->last_act = now;
        if (buf_append(&cc->in, &cc->in_len, &cc->in_cap, tmp, (size_t)n) != 0) {
            drop_status(cc, 413);
            return;
        }
    }

    /* ---- 2. find the header block (incremental scan) ---- */
    if (!c->hdr_parsed) {
        size_t start, he;
        if (c->header_end == 0) {
            start = c->hdr_scanned > 3 ? c->hdr_scanned - 3 : 0;
            he = http_find_header_end(cc->in + start, cc->in_len - start);
            if (he == SIZE_MAX) {
                c->hdr_scanned = cc->in_len;
                if (cc->in_len >= JMAPD_MAX_HDR ||
                    cc->in_len >= srv->cfg.max_req) {
                    drop_status(cc, 431);
                }
                return;
            }
            c->header_end = start + he;
        }
        {
            JmapdHttpReq probe;
            int r = jmapd_http_req_parse(cc->in, c->header_end,
                                         srv->cfg.max_req, &probe);
            if (r > 1) { drop_status(cc, r); return; }
            c->body_len = probe.body_len;
            c->hdr_parsed = true;
        }
    }

    /* ---- 3. is the body complete? ---- */
    if (cc->in_len < c->header_end + c->body_len) {
        if (cc->in_len >= srv->cfg.max_req) { drop_status(cc, 413); return; }
        return;
    }

    /* ---- 4. dispatch exactly one request ---- */
    {
        JmapdHttpReq req;
        int r = jmapd_http_req_parse(cc->in, c->header_end + c->body_len,
                                     srv->cfg.max_req, &req);
        if (r != 1) { drop_status(cc, r > 1 ? r : 400); return; }
        /* Tail bytes (pipelining) are refused: one request in flight per
           connection, so nothing can leak into the next request. */
        if (cc->in_len != c->header_end + c->body_len) {
            drop_status(cc, 400);
            return;
        }
        c->nreq++;
        if (c->nreq >= JMAPD_MAX_REQS_PER_CONN) req.keep_alive = false;
        dispatch(srv, c, &req, cc->in + req.header_end, req.body_len);
    }

    /* ---- 5. reset the cursor for the next request ---- */
    cc->in_len = 0;
    if (cc->in) cc->in[0] = '\0';
    c->hdr_scanned = 0;
    c->header_end = 0;
    c->body_len = 0;
    c->hdr_parsed = false;
}
