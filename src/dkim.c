/* dkim.c — DKIM signing (RFC 6376) for outbound forward copies.
 *
 * a=rsa-sha256, c=relaxed/relaxed.  The canonicalization primitives
 * (relaxed_header / relaxed_body / collect / build_value / canon_dkim_hdr) and
 * the sign/verify cores (dkim_sign_core / dkim_verify_core) are transcribed
 * VERBATIM from the verified prototype tools/dkim_proto.c (which was
 * cross-checked against openssl + Python).  The public entry points add a
 * process-wide lazy entropy/ctr_drbg (mirroring smtp_out.c smtp_tls_global_init)
 * and a single-entry pk_context cache keyed by key_path (the daemon's signing
 * keys are fixed at startup).  On any key-load/sign failure the caller forwards
 * the message UNSIGNED; we log to stderr and return nonzero. */
#include "visage.h"
#include "dkim.h"

#include <stdint.h>
#include <stdbool.h>
#include <time.h>

#include "mbedtls/pk.h"
#include "mbedtls/md.h"
#include "mbedtls/base64.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

/* ------------------------------------------------------------------ */
/* Canonicalization primitives                                         */
/* ------------------------------------------------------------------ */

static bool is_wsp(char c) { return c == ' ' || c == '\t'; }
static char lower(char c) { return (c >= 'A' && c <= 'Z') ? (char)(c + 32) : c; }

/* ------------------------------------------------------------------ */
/* Buffer helpers                                                      */
/* ------------------------------------------------------------------ */

typedef struct { char *p; size_t len, cap; } Buf;

static int buf_init(Buf *b) {
    b->cap = 4096; b->p = malloc(b->cap);
    if (!b->p) return -1;
    b->len = 0; b->p[0] = '\0'; return 0;
}
static int buf_grow(Buf *b, size_t need) {
    size_t nc = b->cap ? b->cap : 4096;
    while (nc < need) { if (nc > (size_t)-1 / 2) return -1; nc *= 2; }
    char *np = realloc(b->p, nc); if (!np) return -1;
    b->p = np; b->cap = nc; return 0;
}
static int buf_put(Buf *b, const char *s, size_t n) {
    if (b->len + n + 1 > b->cap) if (buf_grow(b, b->len + n + 1) != 0) return -1;
    memcpy(b->p + b->len, s, n); b->len += n; b->p[b->len] = '\0'; return 0;
}
static int buf_putc(Buf *b, char c) { return buf_put(b, &c, 1); }
static void buf_free(Buf *b) { free(b->p); b->p = NULL; b->len = b->cap = 0; }

/* ------------------------------------------------------------------ */
/* Relaxed header canonicalization (RFC 6376 3.4.2)                    */
/* ------------------------------------------------------------------ */
/* Input: the raw bytes of one logical header "Name: value" (may be folded).
 * `colon` is the index of the ':' (0-based).  Output: canonicalized form
 * WITHOUT trailing CRLF:
 *   1. lowercase the field name;
 *   2. unfold CRLF+WSP -> single SP;
 *   3. collapse WSP runs -> single SP;
 *   4. delete trailing WSP of the value;
 *   5. delete WSP before and after the colon (keep the colon). */
static int relaxed_header(const char *hdr, size_t len, size_t colon, Buf *out) {
    size_t i;
    for (i = 0; i < colon; i++) if (buf_putc(out, lower(hdr[i])) != 0) return -1;
    if (buf_putc(out, ':') != 0) return -1;

    /* Value processing: delete leading WSP, then unfold + collapse. */
    Buf val; buf_init(&val);
    i = colon + 1;
    bool seen = false;      /* any non-WSP content emitted yet? */
    bool pending = false;   /* a WSP run pending a single SP */
    while (i < len) {
        char c = hdr[i];
        if (c == '\r' || c == '\n') {
            if (c == '\r' && i + 1 < len && hdr[i + 1] == '\n') i += 2; else i += 1;
            while (i < len && is_wsp(hdr[i])) i++;   /* skip fold WSP */
            if (seen) pending = true;               /* fold -> single SP */
            continue;
        }
        if (is_wsp(c)) {
            if (seen) pending = true;               /* collapse runs */
            i++;
            continue;
        }
        if (pending) { buf_putc(&val, ' '); pending = false; }
        buf_putc(&val, c);
        seen = true;
        i++;
    }
    while (val.len > 0 && is_wsp(val.p[val.len - 1])) val.len--;  /* trailing */
    val.p[val.len] = '\0';
    if (buf_put(out, val.p, val.len) != 0) { buf_free(&val); return -1; }
    buf_free(&val);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Body canonicalization + hash                                        */
/* ------------------------------------------------------------------ */

/* Relaxed body (3.4.4): strip trailing WSP per line, collapse WSP runs to
 * single SP, remove trailing empty lines; canonicalized body ends with a
 * single CRLF (empty body -> a single CRLF, 2 octets).  Body is CRLF. */
static int relaxed_body(const char *body, size_t len, char **out, size_t *outlen) {
    Buf o; buf_init(&o);
    size_t i = 0;
    while (i < len) {
        size_t ls = i;
        while (i < len && !(body[i] == '\r' && i + 1 < len && body[i + 1] == '\n')) i++;
        size_t le = i;
        Buf line; buf_init(&line);
        bool pending = false, seen = false;
        for (size_t j = ls; j < le; j++) {
            char c = body[j];
            if (is_wsp(c)) { if (seen) pending = true; continue; }
            if (pending) { buf_putc(&line, ' '); pending = false; }
            buf_putc(&line, c); seen = true;
        }
        buf_put(&o, line.p, line.len);
        buf_put(&o, "\r\n", 2);
        buf_free(&line);
        if (i < len) { if (body[i] == '\r' && i + 1 < len && body[i + 1] == '\n') i += 2; else i += 1; }
    }
    while (o.len >= 2 && o.p[o.len - 2] == '\r' && o.p[o.len - 1] == '\n') o.len -= 2;
    buf_put(&o, "\r\n", 2);
    o.p[o.len] = '\0';
    *out = o.p; *outlen = o.len; return 0;
}

/* ------------------------------------------------------------------ */
/* base64 via mbedtls                                                  */
/* ------------------------------------------------------------------ */

static int b64(const unsigned char *in, size_t inlen, char *out, size_t outsz, size_t *outlen) {
    size_t o = 0;
    if (mbedtls_base64_encode((unsigned char *)out, outsz, &o, in, inlen) != 0) return -1;
    *outlen = o; return 0;
}
static int b64d(const char *in, size_t inlen, unsigned char *out, size_t outsz, size_t *outlen) {
    size_t o = 0;
    if (mbedtls_base64_decode(out, outsz, &o, (const unsigned char *)in, inlen) != 0) return -1;
    *outlen = o; return 0;
}

/* ------------------------------------------------------------------ */
/* Header scanning                                                     */
/* ------------------------------------------------------------------ */

static const char *signable[] = {
    "from", "sender", "reply-to", "to", "cc", "date", "subject",
    "message-id", "mime-version", "content-type", "content-transfer-encoding",
    NULL
};
static bool is_signable(const char *name, size_t namelen) {
    for (int k = 0; signable[k]; k++)
        if (strlen(signable[k]) == namelen && strncasecmp(signable[k], name, namelen) == 0)
            return true;
    return false;
}
static size_t skip_line(const char *m, size_t len, size_t i) {
    while (i < len && m[i] != '\r' && m[i] != '\n') i++;
    if (i < len && m[i] == '\r') i++;
    if (i < len && m[i] == '\n') i++;
    return i;
}
static size_t header_end(const char *m, size_t len, size_t vstart) {
    size_t i = vstart;
    for (;;) {
        while (i < len && m[i] != '\r' && m[i] != '\n') i++;
        size_t j = i;
        if (j < len && m[j] == '\r') j++;
        if (j < len && m[j] == '\n') j++;
        if (j < len && (m[j] == ' ' || m[j] == '\t')) { i = j; continue; }
        return j;
    }
}
static int scan_header(const char *m, size_t len, size_t ls, size_t *namelen, size_t *colon, size_t *end) {
    size_t i = ls;
    while (i < len && m[i] != ':' && m[i] != '\r' && m[i] != '\n') i++;
    if (i >= len || m[i] != ':') { *end = skip_line(m, len, ls); return -1; }
    *namelen = i - ls; *colon = i; *end = header_end(m, len, i + 1); return 0;
}
static size_t find_blank(const char *m, size_t len) {
    size_t i = 0;
    while (i < len) {
        size_t ls = i;
        while (i < len && m[i] != '\r' && m[i] != '\n') i++;
        if (i == ls) return ls;
        if (i < len && m[i] == '\r') i++;
        if (i < len && m[i] == '\n') i++;
    }
    return len;
}

/* ------------------------------------------------------------------ */
/* Signable-header list                                                */
/* ------------------------------------------------------------------ */

typedef struct {
    char   **names;   /* lowercase names, h= order */
    size_t  *start, *colon, *end;
    size_t   n;
} HdrList;

static void hdrlist_free(HdrList *h) {
    for (size_t i = 0; i < h->n; i++) free(h->names[i]);
    free(h->names); free(h->start); free(h->colon); free(h->end);
    memset(h, 0, sizeof *h);
}

/* Collect the signable headers (in message order), skipping DKIM-Signature. */
static int collect(const char *msg, size_t len, HdrList *h) {
    size_t blank = find_blank(msg, len);
    size_t i = 0;
    while (i < blank) {
        size_t ls = i, nl = 0, colon = 0, end = 0;
        if (scan_header(msg, blank, ls, &nl, &colon, &end) != 0) { i = end; continue; }
        if (nl == 14 && strncasecmp(msg + ls, "dkim-signature", 14) == 0) { i = end; continue; }
        if (is_signable(msg + ls, nl)) {
            h->n++;
            h->names = realloc(h->names, h->n * sizeof(char *));
            h->start = realloc(h->start, h->n * sizeof(size_t));
            h->colon = realloc(h->colon, h->n * sizeof(size_t));
            h->end   = realloc(h->end,   h->n * sizeof(size_t));
            if (!h->names || !h->start || !h->colon || !h->end) return -1;
            h->names[h->n - 1] = malloc(nl + 1);
            for (size_t k = 0; k < nl; k++) h->names[h->n - 1][k] = lower(msg[ls + k]);
            h->names[h->n - 1][nl] = '\0';
            h->start[h->n - 1] = ls; h->colon[h->n - 1] = colon; h->end[h->n - 1] = end;
        }
        i = end;
    }
    return 0;
}

/* h= tag value: colon-separated lowercase names. */
static int htag(const HdrList *h, Buf *out) {
    for (size_t i = 0; i < h->n; i++) {
        if (i) buf_putc(out, ':');
        buf_put(out, h->names[i], strlen(h->names[i]));
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* DKIM-Signature construction                                         */
/* ------------------------------------------------------------------ */

#define DKIM_HDR_NAME "DKIM-Signature"
#define DKIM_HDR_NAME_LEN 14

/* Build the DKIM-Signature header VALUE (no "DKIM-Signature: " prefix, no
   CRLF).  bval may be empty (signing) or the base64 signature. */
static int build_value(char *out, size_t outsz, const char *d, const char *s,
                       uint32_t t, const char *bh, const char *h, const char *bval) {
    int n = snprintf(out, outsz,
                     "v=1; a=rsa-sha256; c=relaxed/relaxed; d=%s; s=%s; "
                     "t=%u; bh=%s; h=%s; b=%s", d, s, t, bh, h, bval);
    return (n < 0 || (size_t)n >= outsz) ? -1 : 0;
}

/* Canonicalize the DKIM-Signature header (relaxed, no trailing CRLF) given
   its tags (bval empty for the signing-input computation). */
static int canon_dkim_hdr(const char *d, const char *s, uint32_t t, const char *bh,
                          const char *h, const char *bval, Buf *out) {
    char val[2048];
    if (build_value(val, sizeof val, d, s, t, bh, h, bval) != 0) return -1;
    Buf full; buf_init(&full);
    buf_put(&full, DKIM_HDR_NAME, DKIM_HDR_NAME_LEN);
    buf_putc(&full, ':');
    buf_putc(&full, ' ');
    buf_put(&full, val, strlen(val));
    int rc = relaxed_header(full.p, full.len, DKIM_HDR_NAME_LEN, out);
    buf_free(&full);
    return rc;
}

/* ------------------------------------------------------------------ */
/* Sign (core — transcribed from tools/dkim_proto.c)                   */
/* ------------------------------------------------------------------ */

static int sha256(const unsigned char *in, size_t len, unsigned char out[32]) {
    return mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), in, len, out);
}

/* Sign msg -> DKIM-Signature header line (malloc, CRLF-terminated). */
static int dkim_sign_core(const char *msg, size_t len, mbedtls_pk_context *pk,
                          const char *d, const char *s, uint32_t t,
                          mbedtls_ctr_drbg_context *drbg,
                          char **sig_hdr, Buf *sig_input_out, unsigned char bodyhash_out[32]) {
    HdrList h; memset(&h, 0, sizeof h);
    if (collect(msg, len, &h) != 0) return -1;
    if (h.n == 0) { hdrlist_free(&h); return -1; }

    /* body hash */
    size_t blank = find_blank(msg, len);
    size_t bs = blank;
    if (bs < len) { if (msg[bs] == '\r') bs++; if (bs < len && msg[bs] == '\n') bs++; }
    char *cb = NULL; size_t cblen = 0;
    if (relaxed_body(msg + bs, len - bs, &cb, &cblen) != 0) { hdrlist_free(&h); return -1; }
    unsigned char bh[32];
    if (sha256((const unsigned char *)cb, cblen, bh) != 0) { free(cb); hdrlist_free(&h); return -1; }
    free(cb);
    memcpy(bodyhash_out, bh, 32);
    char bhb64[64]; size_t bhb64len = 0;
    if (b64(bh, 32, bhb64, sizeof bhb64, &bhb64len) != 0) { hdrlist_free(&h); return -1; }

    Buf htv; buf_init(&htv); htag(&h, &htv);

    /* signature input = canonicalized signed headers (each + CRLF)
                        + canonicalized DKIM-Signature (b empty, no CRLF) */
    Buf in; buf_init(&in);
    for (size_t i = 0; i < h.n; i++) {
        Buf ch; buf_init(&ch);
        relaxed_header(msg + h.start[i], h.end[i] - h.start[i], h.colon[i] - h.start[i], &ch);
        buf_put(&in, ch.p, ch.len);
        buf_put(&in, "\r\n", 2);
        buf_free(&ch);
    }
    {
        Buf cd; buf_init(&cd);
        canon_dkim_hdr(d, s, t, bhb64, htv.p, "", &cd);
        buf_put(&in, cd.p, cd.len);
        buf_free(&cd);
    }

    unsigned char sighash[32];
    if (sha256((const unsigned char *)in.p, in.len, sighash) != 0) { buf_free(&in); buf_free(&htv); hdrlist_free(&h); return -1; }

    unsigned char sig[512]; size_t siglen = 0;
    if (mbedtls_pk_sign(pk, MBEDTLS_MD_SHA256, sighash, 32, sig, sizeof sig,
                        &siglen, mbedtls_ctr_drbg_random, drbg) != 0) {
        buf_free(&in); buf_free(&htv); hdrlist_free(&h); return -1;
    }
    char b_b64[1024]; size_t b_b64len = 0;
    if (b64(sig, siglen, b_b64, sizeof b_b64, &b_b64len) != 0) { buf_free(&in); buf_free(&htv); hdrlist_free(&h); return -1; }

    char sigval[2048];
    if (build_value(sigval, sizeof sigval, d, s, t, bhb64, htv.p, b_b64) != 0) {
        buf_free(&in); buf_free(&htv); hdrlist_free(&h); return -1;
    }
    size_t hvlen = strlen(sigval);
    char *hdr = malloc(DKIM_HDR_NAME_LEN + 2 + hvlen + 3);
    if (!hdr) { buf_free(&in); buf_free(&htv); hdrlist_free(&h); return -1; }
    memcpy(hdr, DKIM_HDR_NAME, DKIM_HDR_NAME_LEN);
    hdr[DKIM_HDR_NAME_LEN] = ':';
    hdr[DKIM_HDR_NAME_LEN + 1] = ' ';
    memcpy(hdr + DKIM_HDR_NAME_LEN + 2, sigval, hvlen);
    hdr[DKIM_HDR_NAME_LEN + 2 + hvlen] = '\r';
    hdr[DKIM_HDR_NAME_LEN + 2 + hvlen + 1] = '\n';
    hdr[DKIM_HDR_NAME_LEN + 2 + hvlen + 2] = '\0';

    if (sig_input_out) *sig_input_out = in; else buf_free(&in);
    buf_free(&htv);
    hdrlist_free(&h);
    *sig_hdr = hdr;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Verify (external-verifier style; core from tools/dkim_proto.c)      */
/* ------------------------------------------------------------------ */

typedef struct {
    char  *d, *s, *bh;
    char **hnames; size_t nh;
    uint32_t t;
    unsigned char *sig; size_t siglen;
} Parsed;

static void parsed_free(Parsed *p) {
    free(p->d); free(p->s); free(p->bh);
    for (size_t i = 0; i < p->nh; i++) free(p->hnames[i]);
    free(p->hnames); free(p->sig);
    memset(p, 0, sizeof *p);
}

/* Extract a tag value (e.g. "d=") from the DKIM-Signature value. */
static char *tag_get(const char *val, size_t vlen, const char *tag) {
    size_t tl = strlen(tag);
    for (size_t i = 0; i + tl <= vlen; i++) {
        if (i > 0 && !(val[i - 1] == ';' || val[i - 1] == ' ' || val[i - 1] == '\t')) continue;
        if (strncmp(val + i, tag, tl) != 0) continue;
        size_t j = i + tl;
        size_t k = j;
        while (k < vlen && val[k] != ';') k++;
        char *out = malloc((k - j) + 1);
        memcpy(out, val + j, k - j);
        out[k - j] = '\0';
        return out;
    }
    return NULL;
}

static int parse_dkim(const char *msg, size_t len, Parsed *p) {
    size_t nl = 0, colon = 0, end = 0;
    if (scan_header(msg, len, 0, &nl, &colon, &end) != 0) return -1;
    if (nl != 14 || strncasecmp(msg, "dkim-signature", 14) != 0) return -1;
    size_t vstart = colon + 1;
    size_t vlen = end - vstart;
    while (vlen && (msg[vstart + vlen - 1] == '\r' || msg[vstart + vlen - 1] == '\n')) vlen--;
    const char *val = msg + vstart;

    p->d  = tag_get(val, vlen, "d=");
    p->s  = tag_get(val, vlen, "s=");
    p->bh = tag_get(val, vlen, "bh=");
    char *tt = tag_get(val, vlen, "t=");
    char *hh = tag_get(val, vlen, "h=");
    char *bb = tag_get(val, vlen, "b=");
    if (!p->d || !p->s || !p->bh || !tt || !hh || !bb) return -1;
    p->t = (uint32_t)strtoul(tt, NULL, 10);
    free(tt);
    size_t n = 1;
    for (const char *q = hh; *q; q++) if (*q == ':') n++;
    p->hnames = calloc(n, sizeof(char *));
    if (!p->hnames) { free(hh); free(bb); return -1; }
    p->nh = n;
    size_t idx = 0; const char *start = hh;
    for (const char *q = hh;; q++) {
        if (*q == ':' || *q == '\0') {
            size_t l = (size_t)(q - start);
            p->hnames[idx] = malloc(l + 1);
            memcpy(p->hnames[idx], start, l);
            p->hnames[idx][l] = '\0';
            idx++;
            if (*q == '\0') break;
            start = q + 1;
        }
    }
    free(hh);
    size_t bl = strlen(bb);
    while (bl && is_wsp(bb[bl - 1])) bl--;
    unsigned char *raw = malloc(512); size_t rawlen = 0;
    if (b64d(bb, bl, raw, 512, &rawlen) != 0) { free(bb); return -1; }
    free(bb);
    p->sig = raw; p->siglen = rawlen;
    return 0;
}

static int dkim_verify_core(const char *msg, size_t len, mbedtls_pk_context *pk,
                            Buf *sig_input_out) {
    Parsed p; memset(&p, 0, sizeof p);
    if (parse_dkim(msg, len, &p) != 0) return -1;

    Buf htv; buf_init(&htv);
    for (size_t i = 0; i < p.nh; i++) {
        if (i) buf_putc(&htv, ':');
        buf_put(&htv, p.hnames[i], strlen(p.hnames[i]));
    }

    Buf in; buf_init(&in);
    size_t blank = find_blank(msg, len);
    for (size_t i = 0; i < p.nh; i++) {
        size_t pos = 0; bool found = false;
        size_t hs = 0, hc = 0, he = 0;
        while (pos < blank) {
            size_t nl = 0, colon = 0, end = 0;
            if (scan_header(msg, blank, pos, &nl, &colon, &end) != 0) { pos = end; continue; }
            if (strlen(p.hnames[i]) == nl && strncasecmp(msg + pos, p.hnames[i], nl) == 0) {
                hs = pos; hc = colon; he = end; found = true; break;
            }
            pos = end;
        }
        if (!found) { buf_free(&in); buf_free(&htv); parsed_free(&p); return -1; }
        Buf ch; buf_init(&ch);
        relaxed_header(msg + hs, he - hs, hc - hs, &ch);
        buf_put(&in, ch.p, ch.len);
        buf_put(&in, "\r\n", 2);
        buf_free(&ch);
    }
    {
        Buf cd; buf_init(&cd);
        canon_dkim_hdr(p.d, p.s, p.t, p.bh, htv.p, "", &cd);
        buf_put(&in, cd.p, cd.len);
        buf_free(&cd);
    }

    unsigned char hh[32];
    sha256((const unsigned char *)in.p, in.len, hh);

    int v = mbedtls_pk_verify(pk, MBEDTLS_MD_SHA256, hh, 32, p.sig, p.siglen);

    if (sig_input_out) *sig_input_out = in; else buf_free(&in);
    buf_free(&htv);
    parsed_free(&p);
    return v;
}

/* ------------------------------------------------------------------ */
/* Process-wide lazy state + public entry points                      */
/* ------------------------------------------------------------------ */

static mbedtls_entropy_context g_entropy;
static mbedtls_ctr_drbg_context g_drbg;
static bool g_ready = false;
static int  g_ready_status = 0;

static char *g_pk_path = NULL;
static mbedtls_pk_context g_pk;
static bool g_pk_loaded = false;

/* Idempotent one-time entropy/ctr_drbg init (mirrors smtp_tls_global_init). */
static int dkim_global_init(void) {
    if (g_ready) return g_ready_status;
    mbedtls_entropy_init(&g_entropy);
    mbedtls_ctr_drbg_init(&g_drbg);
    const char pers[] = "visage_dkim";
    int r = mbedtls_ctr_drbg_seed(&g_drbg, mbedtls_entropy_func, &g_entropy,
                                  (const unsigned char *)pers, sizeof pers - 1);
    g_ready_status = r;
    g_ready = true;   /* do not re-seed on every call */
    return r;
}

/* Resolve (and cache) the parsed pk_context for key_path.  Single-entry cache:
 * the daemon's signing keys are fixed at startup; re-parsing happens only when
 * key_path changes.  Returns 0 and sets *out_pk, or a negative mbedTLS error. */
static int dkim_load_pk(const char *key_path, mbedtls_pk_context **out_pk) {
    int r = dkim_global_init();
    if (r != 0) return r;
    if (g_pk_loaded && g_pk_path && strcmp(g_pk_path, key_path) == 0) {
        *out_pk = &g_pk;
        return 0;
    }
    mbedtls_pk_free(&g_pk);
    mbedtls_pk_init(&g_pk);
    r = mbedtls_pk_parse_keyfile(&g_pk, key_path, NULL,
                                 mbedtls_ctr_drbg_random, &g_drbg);
    if (r != 0) {
        g_pk_loaded = false;
        free(g_pk_path); g_pk_path = NULL;
        return r;
    }
    if (mbedtls_pk_get_type(&g_pk) != MBEDTLS_PK_RSA) {
        mbedtls_pk_free(&g_pk);
        mbedtls_pk_init(&g_pk);
        g_pk_loaded = false;
        free(g_pk_path); g_pk_path = NULL;
        return -2;   /* not RSA */
    }
    free(g_pk_path);
    g_pk_path = strdup(key_path);
    g_pk_loaded = true;
    *out_pk = &g_pk;
    return 0;
}

int dkim_sign(const char *msg, size_t msglen, const char *domain,
              const char *selector, const char *key_path,
              char **out, size_t *outlen) {
    if (out) *out = NULL;
    if (outlen) *outlen = 0;
    if (!msg || !domain || !selector || !key_path || !out || !outlen) return -1;

    mbedtls_pk_context *pk = NULL;
    int r = dkim_load_pk(key_path, &pk);
    if (r != 0) {
        fprintf(stderr, "visage: dkim: key load failed (%s): -0x%04x\n",
                key_path, -r);
        return -1;
    }

    uint32_t t = (uint32_t)time(NULL);
    char *sig_hdr = NULL;
    Buf sig_input; memset(&sig_input, 0, sizeof sig_input);
    unsigned char bodyhash[32];
    r = dkim_sign_core(msg, msglen, pk, domain, selector, t, &g_drbg,
                       &sig_hdr, &sig_input, bodyhash);
    if (r != 0) {
        fprintf(stderr, "visage: dkim: sign failed for %s (selector %s)\n",
                domain, selector);
        return -1;
    }

    size_t shlen = strlen(sig_hdr);
    char *signed_msg = malloc(shlen + msglen + 1);
    if (!signed_msg) {
        free(sig_hdr);
        buf_free(&sig_input);
        fprintf(stderr, "visage: dkim: out of memory\n");
        return -1;
    }
    memcpy(signed_msg, sig_hdr, shlen);
    memcpy(signed_msg + shlen, msg, msglen);
    signed_msg[shlen + msglen] = '\0';
    free(sig_hdr);
    buf_free(&sig_input);
    *out = signed_msg;
    *outlen = shlen + msglen;
    return 0;
}

int dkim_verify(const char *msg, size_t len, const char *key_path) {
    if (!msg || !key_path) return -1;
    mbedtls_pk_context *pk = NULL;
    int r = dkim_load_pk(key_path, &pk);
    if (r != 0) return -1;
    return dkim_verify_core(msg, len, pk, NULL);
}

int dkim_relaxed_header(const char *hdr, size_t len, size_t colon,
                        char **out, size_t *outlen) {
    if (out) *out = NULL;
    if (outlen) *outlen = 0;
    if (!hdr || !out || !outlen) return -1;
    Buf b; memset(&b, 0, sizeof b);
    if (buf_init(&b) != 0) return -1;
    if (relaxed_header(hdr, len, colon, &b) != 0) { buf_free(&b); return -1; }
    size_t olen = b.len;
    char *s = malloc(olen + 1);
    if (!s) { buf_free(&b); return -1; }
    memcpy(s, b.p, olen);
    s[olen] = '\0';
    buf_free(&b);
    *out = s;
    *outlen = olen;
    return 0;
}

int dkim_relaxed_body_b64(const char *body, size_t len, char bh_b64[64]) {
    if (!bh_b64) return -1;
    char *cb = NULL; size_t cblen = 0;
    if (relaxed_body(body, len, &cb, &cblen) != 0) return -1;
    unsigned char h[32];
    if (sha256((const unsigned char *)cb, cblen, h) != 0) { free(cb); return -1; }
    free(cb);
    size_t olen = 0;
    if (b64(h, 32, bh_b64, 64, &olen) != 0) return -1;
    bh_b64[olen] = '\0';
    return 0;
}
