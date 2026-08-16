/* dkim_proto.c — scratch harness validating DKIM (RFC 6376) relaxed
 * canonicalization + rsa-sha256 against vendored mbedTLS under cosmocc.
 * Signs a fixed message, emits DKIM-Signature, re-verifies by RE-PARSING the
 * header (external-verifier style), and prints signature-input + body-hash
 * hex for independent cross-check (openssl / python). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
/* Sign                                                                */
/* ------------------------------------------------------------------ */

static int sha256(const unsigned char *in, size_t len, unsigned char out[32]) {
    return mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), in, len, out);
}

/* Sign msg -> DKIM-Signature header line (malloc, CRLF-terminated). */
static int dkim_sign(const char *msg, size_t len, mbedtls_pk_context *pk,
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
/* Verify (external-verifier style)                                    */
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

static int dkim_verify(const char *msg, size_t len, mbedtls_pk_context *pk,
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
/* main                                                                */
/* ------------------------------------------------------------------ */

static void hexdump(const unsigned char *p, size_t n) {
    for (size_t i = 0; i < n; i++) printf("%02x", p[i]);
    printf("\n");
}

int main(int argc, char **argv) {
    (void)argc;
    const char *keypath = argv[1];
    const char *d = "example.com";
    const char *s = "sel1";

    const char msg[] =
        "Received: by mx.example.com from client with SMTP\r\n"
        "Subject: Hello  World \r\n"
        "To:   bob@example.com\t\r\n"
        "Date: Fri, 11 Jul 2003 21:00:37 -0700\r\n"
        "Message-ID: <abc123@example.com>\r\n"
        "Return-Path: <jane@example.com>\r\n"
        "From: \"S via jane\" <reply+deadbeef@example.com>\r\n"
        "Sender: <jane@example.com>\r\n"
        "Reply-To: reply+deadbeef@example.com\r\n"
        "\r\n"
        "Hi.\r\n"
        "\r\n"
        "We lost the game.   Are you hungry yet?  \r\n"
        "\r\n"
        "Joe.\r\n";

    mbedtls_entropy_context ent; mbedtls_entropy_init(&ent);
    mbedtls_ctr_drbg_context drbg; mbedtls_ctr_drbg_init(&drbg);
    mbedtls_pk_context pk; mbedtls_pk_init(&pk);

    int r = mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &ent,
                                  (const unsigned char *)"dkim_proto", 10);
    if (r != 0) { fprintf(stderr, "drbg seed failed -0x%04x\n", -r); return 1; }
    r = mbedtls_pk_parse_keyfile(&pk, keypath, NULL, mbedtls_ctr_drbg_random, &drbg);
    if (r != 0) { fprintf(stderr, "parse keyfile failed -0x%04x\n", -r); return 1; }
    if (mbedtls_pk_get_type(&pk) != MBEDTLS_PK_RSA) { fprintf(stderr, "not RSA\n"); return 1; }

    char *sig_hdr = NULL;
    Buf sig_input; memset(&sig_input, 0, sizeof sig_input);
    unsigned char bodyhash[32];
    uint32_t t = (uint32_t)time(NULL);
    r = dkim_sign(msg, sizeof msg - 1, &pk, d, s, t, &drbg, &sig_hdr, &sig_input, bodyhash);
    if (r != 0) { fprintf(stderr, "sign failed %d\n", r); return 1; }

    printf("%s", sig_hdr);
    printf("BODYHASH_HEX "); hexdump(bodyhash, 32);
    printf("SIGINPUT_HEX "); hexdump((const unsigned char *)sig_input.p, sig_input.len);

    size_t shlen = strlen(sig_hdr);
    size_t mlen = sizeof msg - 1;
    char *signed_msg = malloc(shlen + mlen + 1);
    memcpy(signed_msg, sig_hdr, shlen);
    memcpy(signed_msg + shlen, msg, mlen);
    signed_msg[shlen + mlen] = '\0';

    Buf vinput; memset(&vinput, 0, sizeof vinput);
    int v = dkim_verify(signed_msg, shlen + mlen, &pk, &vinput);
    printf("SELFVERIFY %s\n", v == 0 ? "PASS" : "FAIL");
    printf("SIGINPUT2_HEX "); hexdump((const unsigned char *)vinput.p, vinput.len);
    printf("SIGINPUT_MATCH %s\n",
           (vinput.len == sig_input.len && memcmp(vinput.p, sig_input.p, vinput.len) == 0) ? "YES" : "NO");

    /* Dump sig-input and raw signature for an independent openssl check. */
    {
        FILE *f = fopen("/tmp/siginput.bin", "wb");
        if (f) { fwrite(sig_input.p, 1, sig_input.len, f); fclose(f); }
        /* extract b= from sig_hdr and base64-decode it */
        char *beq = strstr(sig_hdr, "b=");
        if (beq) {
            char *bv = beq + 2;
            size_t bvl = strlen(bv);
            while (bvl && (bv[bvl-1] == '\r' || bv[bvl-1] == '\n')) bvl--;
            unsigned char raw[512]; size_t rawlen = 0;
            if (b64d(bv, bvl, raw, 512, &rawlen) == 0) {
                f = fopen("/tmp/sig.raw", "wb");
                if (f) { fwrite(raw, 1, rawlen, f); fclose(f); }
            }
        }
    }

    free(sig_hdr); buf_free(&sig_input); buf_free(&vinput); free(signed_msg);
    mbedtls_pk_free(&pk); mbedtls_ctr_drbg_free(&drbg); mbedtls_entropy_free(&ent);
    return v == 0 ? 0 : 1;
}
