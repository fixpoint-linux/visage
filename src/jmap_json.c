/* jmap_json.c — bounded JSON parser (see jmap_json.h for the shape).
 *
 * Arena discipline: nodes come from fixed-size chunks and decoded strings from
 * variable-size blocks, both owned by the document, so a pointer handed out by
 * the parser stays valid until jmap_json_free.  Nothing is allocated in
 * proportion to anything but the input length: a 4 MiB request can cost at most
 * a few times 4 MiB, and every allocation failure is JMAP_JSON_E_NOMEM. */
#include "jmap_json.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#define NODE_CHUNK 64

typedef struct NodeChunk {
    struct NodeChunk *next;
    size_t            used;
    JmapJsonNode      v[NODE_CHUNK];
} NodeChunk;

typedef struct StrBlock {
    struct StrBlock *next;
    size_t           used, cap;
    char            *data;
} StrBlock;

struct JmapJsonDoc {
    NodeChunk    *nodes;
    StrBlock     *strs;
    JmapJsonNode *root;
};

typedef struct Parser {
    const char  *p, *end;
    JmapJsonDoc *doc;
    JmapJsonErr  err;
} Parser;

/* ------------------------------------------------------------------ */
/* Arenas                                                             */
/* ------------------------------------------------------------------ */

static JmapJsonNode *node_new(JmapJsonDoc *d) {
    NodeChunk *ch = d->nodes;
    if (!ch || ch->used == NODE_CHUNK) {
        ch = malloc(sizeof *ch);
        if (!ch) return NULL;
        ch->next = d->nodes;
        ch->used = 0;
        d->nodes = ch;
    }
    memset(&ch->v[ch->used], 0, sizeof ch->v[ch->used]);
    return &ch->v[ch->used++];
}

/* Carve n bytes out of the string arena (never NULL for n > 0 unless OOM). */
static char *str_take(JmapJsonDoc *d, size_t n) {
    StrBlock *b = d->strs;
    char *r;
    if (n == 0) n = 1;
    if (!b || b->cap - b->used < n) {
        size_t cap = n > 4096 ? n : 4096;
        b = malloc(sizeof *b);
        if (!b) return NULL;
        b->data = malloc(cap);
        if (!b->data) { free(b); return NULL; }
        b->cap = cap;
        b->used = 0;
        b->next = d->strs;
        d->strs = b;
    }
    r = b->data + b->used;
    b->used += n;
    return r;
}

/* ------------------------------------------------------------------ */
/* Lexical helpers                                                    */
/* ------------------------------------------------------------------ */

static void skip_ws(Parser *s) {
    while (s->p < s->end) {
        char c = *s->p;
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') s->p++;
        else break;
    }
}

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Four hex digits at s->p, consumed on success. */
static int hex4(Parser *s, unsigned *out) {
    unsigned v = 0;
    int i;
    if (s->end - s->p < 4) return -1;
    for (i = 0; i < 4; i++) {
        int h = hexval(s->p[i]);
        if (h < 0) return -1;
        v = (v << 4) | (unsigned)h;
    }
    s->p += 4;
    *out = v;
    return 0;
}

/* Encode one code point as UTF-8; returns the byte count (1..4). */
static int utf8_encode(unsigned cp, char *out) {
    if (cp < 0x80) { out[0] = (char)cp; return 1; }
    if (cp < 0x800) {
        out[0] = (char)(0xC0 | (cp >> 6));
        out[1] = (char)(0x80 | (cp & 0x3F));
        return 2;
    }
    if (cp < 0x10000) {
        out[0] = (char)(0xE0 | (cp >> 12));
        out[1] = (char)(0x80 | ((cp >> 6) & 0x3F));
        out[2] = (char)(0x80 | (cp & 0x3F));
        return 3;
    }
    out[0] = (char)(0xF0 | (cp >> 18));
    out[1] = (char)(0x80 | ((cp >> 12) & 0x3F));
    out[2] = (char)(0x80 | ((cp >> 6) & 0x3F));
    out[3] = (char)(0x80 | (cp & 0x3F));
    return 4;
}

/* Validate ONE UTF-8 sequence starting at p (< end).  On success sets *len and
   returns 0.  Rejects overlong forms, surrogates (0xED A0..BF) and anything
   above U+10FFFF — RFC 8259 requires the text to be valid UTF-8, and a lone
   surrogate encoded in raw bytes is exactly the kind of byte sequence that
   makes two JSON consumers disagree. */
static int utf8_valid(const char *p, const char *end, size_t *len) {
    unsigned char c0 = (unsigned char)p[0];
    size_t n, i;
    unsigned cp;
    if (c0 < 0x80) { *len = 1; return 0; }
    if (c0 >= 0xC2 && c0 <= 0xDF) { n = 2; cp = c0 & 0x1F; }
    else if (c0 >= 0xE0 && c0 <= 0xEF) { n = 3; cp = c0 & 0x0F; }
    else if (c0 >= 0xF0 && c0 <= 0xF4) { n = 4; cp = c0 & 0x07; }
    else return -1;
    if ((size_t)(end - p) < n) return -1;
    for (i = 1; i < n; i++) {
        unsigned char c = (unsigned char)p[i];
        if ((c & 0xC0) != 0x80) return -1;
        cp = (cp << 6) | (c & 0x3F);
    }
    if (n == 3 && (cp < 0x800 || (cp >= 0xD800 && cp <= 0xDFFF))) return -1;
    if (n == 4 && (cp < 0x10000 || cp > 0x10FFFF)) return -1;
    *len = n;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Values                                                             */
/* ------------------------------------------------------------------ */

static JmapJsonNode *p_value(Parser *s, int depth);

/* Parse one string literal (s->p at the opening quote) into the arena.
 *
 * Two bounded passes: first find the literal's end (skipping escaped bytes),
 * then decode into a reservation of exactly rawlen+1 bytes.  The decoded form
 * is never longer than the raw form, so that reservation always fits — and it
 * is the reason the arena cost is O(input) rather than O(input * strings).
 *
 * EVERY string is copied and NUL-terminated, including one with no escapes.
 * The alternative (point into the caller's buffer for escape-free strings)
 * makes the node a length-tagged slice, and a single consumer that treats it
 * as a C string then reads past the closing quote — which is exactly the
 * over-read that shipped once here.  One representation, no footgun; the copy
 * is bounded by the request cap. */
static int p_string(Parser *s, const char **out, size_t *outlen) {
    const char *p, *q;
    size_t rawlen, o = 0;
    char *buf;

    if (s->p >= s->end || *s->p != '"') { s->err = JMAP_JSON_E_SYNTAX; return -1; }
    p = s->p + 1;
    q = p;
    while (q < s->end) {
        if (*q == '\\') { q += 2; continue; }
        if (*q == '"') break;
        q++;
    }
    if (q >= s->end) { s->err = JMAP_JSON_E_STRING; return -1; }
    rawlen = (size_t)(q - p);
    buf = str_take(s->doc, rawlen + 1);
    if (!buf) { s->err = JMAP_JSON_E_NOMEM; return -1; }

    s->p = p;
    while (s->p < q) {
        unsigned char c = (unsigned char)*s->p;
        if (c < 0x20) { s->err = JMAP_JSON_E_STRING; return -1; }
        if (c == '\\') {
            s->p++;
            if (s->p >= q) { s->err = JMAP_JSON_E_STRING; return -1; }
            switch (*s->p) {
            case '"':  buf[o++] = '"';  s->p++; break;
            case '\\': buf[o++] = '\\'; s->p++; break;
            case '/':  buf[o++] = '/';  s->p++; break;
            case 'b':  buf[o++] = '\b'; s->p++; break;
            case 'f':  buf[o++] = '\f'; s->p++; break;
            case 'n':  buf[o++] = '\n'; s->p++; break;
            case 'r':  buf[o++] = '\r'; s->p++; break;
            case 't':  buf[o++] = '\t'; s->p++; break;
            case 'u': {
                unsigned cp;
                s->p++;
                if (hex4(s, &cp) != 0 || s->p > q) {
                    s->err = JMAP_JSON_E_STRING;
                    return -1;
                }
                if (cp >= 0xD800 && cp <= 0xDBFF) {
                    unsigned lo;
                    if (q - s->p < 6 || s->p[0] != '\\' || s->p[1] != 'u') {
                        s->err = JMAP_JSON_E_SURROGATE;
                        return -1;
                    }
                    s->p += 2;
                    if (hex4(s, &lo) != 0 || s->p > q ||
                        lo < 0xDC00 || lo > 0xDFFF) {
                        s->err = JMAP_JSON_E_SURROGATE;
                        return -1;
                    }
                    cp = 0x10000u + ((cp - 0xD800u) << 10) + (lo - 0xDC00u);
                } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
                    s->err = JMAP_JSON_E_SURROGATE;
                    return -1;
                } else if (cp == 0) {
                    /* A NUL inside a JMAP string is never legitimate and would
                       silently truncate every C consumer downstream, so it is
                       rejected here rather than carried as a length-tagged
                       time bomb. */
                    s->err = JMAP_JSON_E_STRING;
                    return -1;
                }
                o += (size_t)utf8_encode(cp, buf + o);
                break;
            }
            default:
                s->err = JMAP_JSON_E_STRING;
                return -1;
            }
            continue;
        }
        if (c < 0x80) { buf[o++] = (char)c; s->p++; continue; }
        {
            size_t n;
            if (utf8_valid(s->p, q, &n) != 0) {
                s->err = JMAP_JSON_E_UTF8;
                return -1;
            }
            memcpy(buf + o, s->p, n);
            o += n;
            s->p += n;
        }
    }
    buf[o] = '\0';
    s->p = q + 1;
    *out = buf;
    *outlen = o;
    return 0;
}

static bool is_digit(char c) { return c >= '0' && c <= '9'; }

static int p_number(Parser *s, JmapJsonNode *n) {
    const char *start = s->p;
    char tmp[64];
    size_t len;
    char *endp;

    if (s->p < s->end && *s->p == '-') s->p++;
    if (s->p >= s->end || !is_digit(*s->p)) { s->err = JMAP_JSON_E_NUMBER; return -1; }
    if (*s->p == '0') {
        s->p++;
        if (s->p < s->end && is_digit(*s->p)) { s->err = JMAP_JSON_E_NUMBER; return -1; }
    } else {
        while (s->p < s->end && is_digit(*s->p)) s->p++;
    }
    n->is_int = true;
    if (s->p < s->end && *s->p == '.') {
        n->is_int = false;
        s->p++;
        if (s->p >= s->end || !is_digit(*s->p)) { s->err = JMAP_JSON_E_NUMBER; return -1; }
        while (s->p < s->end && is_digit(*s->p)) s->p++;
    }
    if (s->p < s->end && (*s->p == 'e' || *s->p == 'E')) {
        n->is_int = false;
        s->p++;
        if (s->p < s->end && (*s->p == '+' || *s->p == '-')) s->p++;
        if (s->p >= s->end || !is_digit(*s->p)) { s->err = JMAP_JSON_E_NUMBER; return -1; }
        while (s->p < s->end && is_digit(*s->p)) s->p++;
    }
    len = (size_t)(s->p - start);
    if (len >= sizeof tmp) { s->err = JMAP_JSON_E_NUMBER; return -1; }
    memcpy(tmp, start, len);
    tmp[len] = '\0';
    n->num = strtod(tmp, &endp);
    if (endp != tmp + len) { s->err = JMAP_JSON_E_NUMBER; return -1; }
    if (n->is_int) {
        long long v;
        /* strtoll consumes every digit of an out-of-range literal and sets
           ERANGE, leaving endp at the end — so the end-pointer check alone
           would accept "99999999999999999999" and report LLONG_MAX as if it
           were the exact integer.  The literal either fits int64 or the node
           is honestly non-integral (a double), never a clamped value. */
        errno = 0;
        v = strtoll(tmp, &endp, 10);
        if (endp != tmp + len || errno == ERANGE) {
            n->is_int = false;          /* out of int64 range: keep as double */
        } else {
            n->inum = (int64_t)v;
        }
    }
    n->type = JMAP_JSON_NUM;
    return 0;
}

static int p_literal(Parser *s, const char *lit, JmapJsonType t, bool b,
                     JmapJsonNode *n) {
    size_t l = strlen(lit);
    if ((size_t)(s->end - s->p) < l || memcmp(s->p, lit, l) != 0) {
        s->err = JMAP_JSON_E_SYNTAX;
        return -1;
    }
    s->p += l;
    n->type = t;
    n->boolean = b;
    return 0;
}

static JmapJsonNode *p_value(Parser *s, int depth) {
    JmapJsonNode *n;

    if (depth > JMAP_JSON_MAX_DEPTH) { s->err = JMAP_JSON_E_DEPTH; return NULL; }
    if (s->p >= s->end) { s->err = JMAP_JSON_E_SYNTAX; return NULL; }
    n = node_new(s->doc);
    if (!n) { s->err = JMAP_JSON_E_NOMEM; return NULL; }

    switch (*s->p) {
    case '{': {
        JmapJsonNode **tail;
        n->type = JMAP_JSON_OBJ;
        s->p++;
        skip_ws(s);
        if (s->p < s->end && *s->p == '}') { s->p++; return n; }
        tail = &n->child;
        for (;;) {
            const char *k;
            size_t kl;
            JmapJsonNode *v;
            skip_ws(s);
            if (p_string(s, &k, &kl) != 0) return NULL;
            skip_ws(s);
            if (s->p >= s->end || *s->p != ':') { s->err = JMAP_JSON_E_SYNTAX; return NULL; }
            s->p++;
            skip_ws(s);
            v = p_value(s, depth + 1);
            if (!v) return NULL;
            v->key = k;
            v->keylen = kl;
            while (*tail) tail = &(*tail)->next;
            *tail = v;
            skip_ws(s);
            if (s->p < s->end && *s->p == ',') { s->p++; continue; }
            if (s->p < s->end && *s->p == '}') { s->p++; return n; }
            s->err = JMAP_JSON_E_SYNTAX;
            return NULL;
        }
    }
    case '[': {
        JmapJsonNode **tail;
        n->type = JMAP_JSON_ARR;
        s->p++;
        skip_ws(s);
        if (s->p < s->end && *s->p == ']') { s->p++; return n; }
        tail = &n->child;
        for (;;) {
            JmapJsonNode *v;
            skip_ws(s);
            v = p_value(s, depth + 1);
            if (!v) return NULL;
            *tail = v;
            tail = &v->next;
            skip_ws(s);
            if (s->p < s->end && *s->p == ',') { s->p++; continue; }
            if (s->p < s->end && *s->p == ']') { s->p++; return n; }
            s->err = JMAP_JSON_E_SYNTAX;
            return NULL;
        }
    }
    case '"':
        n->type = JMAP_JSON_STR;
        if (p_string(s, &n->str, &n->slen) != 0) return NULL;
        return n;
    case 't':
        if (p_literal(s, "true", JMAP_JSON_BOOL, true, n) != 0) return NULL;
        return n;
    case 'f':
        if (p_literal(s, "false", JMAP_JSON_BOOL, false, n) != 0) return NULL;
        return n;
    case 'n':
        if (p_literal(s, "null", JMAP_JSON_NULL, false, n) != 0) return NULL;
        return n;
    default:
        if (*s->p == '-' || is_digit(*s->p)) {
            if (p_number(s, n) != 0) return NULL;
            return n;
        }
        s->err = JMAP_JSON_E_SYNTAX;
        return NULL;
    }
}

/* ------------------------------------------------------------------ */
/* Public API                                                         */
/* ------------------------------------------------------------------ */

JmapJsonDoc *jmap_json_parse(const char *buf, size_t len, JmapJsonErr *err) {
    JmapJsonDoc *d;
    Parser s;
    if (err) *err = JMAP_JSON_OK;
    if (!buf) {
        if (err) *err = JMAP_JSON_E_SYNTAX;
        return NULL;
    }
    d = calloc(1, sizeof *d);
    if (!d) { if (err) *err = JMAP_JSON_E_NOMEM; return NULL; }
    s.p = buf;
    s.end = buf + len;
    s.doc = d;
    s.err = JMAP_JSON_OK;
    skip_ws(&s);
    d->root = p_value(&s, 1);
    if (!d->root) {
        if (err) *err = s.err == JMAP_JSON_OK ? JMAP_JSON_E_SYNTAX : s.err;
        jmap_json_free(d);
        return NULL;
    }
    skip_ws(&s);
    if (s.p != s.end) {
        if (err) *err = JMAP_JSON_E_TRAILING;
        jmap_json_free(d);
        return NULL;
    }
    return d;
}

const JmapJsonNode *jmap_json_root(const JmapJsonDoc *doc) {
    return doc ? doc->root : NULL;
}

void jmap_json_free(JmapJsonDoc *doc) {
    NodeChunk *nc;
    StrBlock *sb;
    if (!doc) return;
    nc = doc->nodes;
    while (nc) {
        NodeChunk *n = nc->next;
        free(nc);
        nc = n;
    }
    sb = doc->strs;
    while (sb) {
        StrBlock *n = sb->next;
        free(sb->data);
        free(sb);
        sb = n;
    }
    free(doc);
}

const JmapJsonNode *jmap_json_get(const JmapJsonNode *obj, const char *key) {
    const JmapJsonNode *c;
    size_t kl;
    if (!obj || obj->type != JMAP_JSON_OBJ || !key) return NULL;
    kl = strlen(key);
    for (c = obj->child; c; c = c->next)
        if (c->keylen == kl && memcmp(c->key, key, kl) == 0) return c;
    return NULL;
}

size_t jmap_json_count(const JmapJsonNode *n) {
    size_t k = 0;
    const JmapJsonNode *c;
    if (!n || (n->type != JMAP_JSON_ARR && n->type != JMAP_JSON_OBJ)) return 0;
    for (c = n->child; c; c = c->next) k++;
    return k;
}

const JmapJsonNode *jmap_json_at(const JmapJsonNode *arr, size_t i) {
    const JmapJsonNode *c;
    if (!arr || (arr->type != JMAP_JSON_ARR && arr->type != JMAP_JSON_OBJ)) return NULL;
    for (c = arr->child; c; c = c->next)
        if (i-- == 0) return c;
    return NULL;
}

int jmap_json_str(const JmapJsonNode *n, const char **s, size_t *slen) {
    if (!n || n->type != JMAP_JSON_STR) return -1;
    if (s) *s = n->str;
    if (slen) *slen = n->slen;
    return 0;
}

int jmap_json_u64(const JmapJsonNode *n, uint64_t *out) {
    if (!n || n->type != JMAP_JSON_NUM || !n->is_int || n->inum < 0) return -1;
    if (out) *out = (uint64_t)n->inum;
    return 0;
}

int jmap_json_bool(const JmapJsonNode *n, bool *out) {
    if (!n || n->type != JMAP_JSON_BOOL) return -1;
    if (out) *out = n->boolean;
    return 0;
}

const char *jmap_json_err_str(JmapJsonErr e) {
    switch (e) {
    case JMAP_JSON_OK:          return "ok";
    case JMAP_JSON_E_SYNTAX:    return "syntax";
    case JMAP_JSON_E_DEPTH:     return "depth";
    case JMAP_JSON_E_STRING:    return "string";
    case JMAP_JSON_E_SURROGATE: return "surrogate";
    case JMAP_JSON_E_UTF8:      return "utf8";
    case JMAP_JSON_E_NUMBER:    return "number";
    case JMAP_JSON_E_TRAILING:  return "trailing";
    case JMAP_JSON_E_NOMEM:     return "nomem";
    }
    return "unknown";
}
