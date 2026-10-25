/* json.c — minimal JSON helpers for the admin HTTP API (slice S7). */
#include "json.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* U+FFFD in UTF-8: what an unrepresentable byte becomes (see json.h). */
static const char utf8_replacement[3] = { '\xEF', '\xBF', '\xBD' };

static size_t utf8_replaced = 0;

void json_utf8_reset(void) { utf8_replaced = 0; }
size_t json_utf8_replacements(void) { return utf8_replaced; }

/* Length of the well-formed UTF-8 sequence at p (avail bytes available), or 0
   when p does not start one.  Overlong forms, surrogates and anything above
   U+10FFFF are rejected: each is as unrepresentable in JSON text as a raw
   0xAE, so each is replaced rather than copied. */
static size_t utf8_seq(const unsigned char *p, size_t avail) {
    unsigned char c0 = p[0];
    size_t n, i;
    unsigned cp;

    if (c0 < 0x80) return 1;
    if (c0 >= 0xC2 && c0 <= 0xDF) { n = 2; cp = c0 & 0x1F; }
    else if (c0 >= 0xE0 && c0 <= 0xEF) { n = 3; cp = c0 & 0x0F; }
    else if (c0 >= 0xF0 && c0 <= 0xF4) { n = 4; cp = c0 & 0x07; }
    else return 0;
    if (avail < n) return 0;
    for (i = 1; i < n; i++) {
        unsigned char c = p[i];
        if ((c & 0xC0) != 0x80) return 0;
        cp = (cp << 6) | (c & 0x3F);
    }
    if (n == 3 && (cp < 0x800 || (cp >= 0xD800 && cp <= 0xDFFF))) return 0;
    if (n == 4 && (cp < 0x10000 || cp > 0x10FFFF)) return 0;
    return n;
}

/* How many bytes ONE ill-formed subpart starting at p consumes, so it becomes
   ONE U+FFFD: the lead byte plus every continuation byte that follows it
   (bounded by the length its lead byte announces).  A body cut mid-character
   by maxBodyValueBytes is the case that makes this matter — it costs one
   replacement, not one per byte.  A sequence that is structurally complete but
   encodes an overlong form, a surrogate or a code point above U+10FFFF also
   collapses to a single replacement. */
static size_t utf8_bad_len(const unsigned char *p, size_t avail) {
    size_t n = utf8_seq(p, avail);
    size_t i;

    if (n) return n;                    /* not reachable: caller checks */
    if (p[0] < 0xC2 || p[0] > 0xF4) return 1;
    if (p[0] <= 0xDF) n = 2;
    else if (p[0] <= 0xEF) n = 3;
    else n = 4;
    for (i = 1; i < n && i < avail; i++)
        if ((p[i] & 0xC0) != 0x80) break;
    return i;
}

int json_escape(const char *s, size_t len, char *out, size_t outsz,
                size_t *replaced) {
    size_t i, o = 0, bad = 0;
    if (!s || !out) return -1;
    for (i = 0; i < len; i++) {
        unsigned char c = (unsigned char)s[i];
        switch (c) {
        case '"': case '\\': case '\b': case '\f':
        case '\n': case '\r': case '\t':
            if (o + 2 + 1 > outsz) return -1;
            out[o++] = '\\';
            out[o++] = (c == '"')  ? '"'  :
                       (c == '\\') ? '\\' :
                       (c == '\b') ? 'b'  :
                       (c == '\f') ? 'f'  :
                       (c == '\n') ? 'n'  :
                       (c == '\r') ? 'r'  : 't';
            break;
        default:
            if (c < 0x20) {
                int n;
                if (o + 6 + 1 > outsz) return -1;
                n = snprintf(out + o, 7, "\\u%04x", c);
                o += (size_t)n;
            } else if (c < 0x80) {
                if (o + 1 + 1 > outsz) return -1;
                out[o++] = (char)c;
            } else {
                size_t n = utf8_seq((const unsigned char *)s + i, len - i);
                if (n == 0) {
                    if (o + sizeof utf8_replacement + 1 > outsz) return -1;
                    memcpy(out + o, utf8_replacement, sizeof utf8_replacement);
                    o += sizeof utf8_replacement;
                    bad++;
                    i += utf8_bad_len((const unsigned char *)s + i, len - i) - 1;
                } else {
                    if (o + n + 1 > outsz) return -1;
                    memcpy(out + o, s + i, n);
                    o += n;
                    i += n - 1;
                }
            }
            break;
        }
    }
    out[o] = '\0';
    if (replaced) *replaced = bad;
    utf8_replaced += bad;
    return 0;
}

/* Grow the buffer so that len + extra + 1 (NUL) fits. */
static int jsonb_grow(JsonBuilder *b, size_t extra) {
    size_t nc;
    char *nb;
    if (b->err) return -1;
    if (b->len + extra + 1 > b->cap) {
        nc = b->cap ? b->cap : 64;
        while (nc < b->len + extra + 1) {
            if (nc > ((size_t)-1) / 2) { b->err = 1; return -1; }
            nc *= 2;
        }
        nb = realloc(b->buf, nc);
        if (!nb) { b->err = 1; return -1; }
        b->buf = nb;
        b->cap = nc;
    }
    return 0;
}

static int jsonb_raw(JsonBuilder *b, const char *s, size_t n) {
    if (jsonb_grow(b, n)) return -1;
    memcpy(b->buf + b->len, s, n);
    b->len += n;
    b->buf[b->len] = '\0';
    return 0;
}

void jsonb_init(JsonBuilder *b) {
    b->buf = NULL;
    b->len = 0;
    b->cap = 0;
    b->err = 0;
}

int jsonb_begin_object(JsonBuilder *b) { return jsonb_raw(b, "{", 1); }
int jsonb_end_object(JsonBuilder *b)   { return jsonb_raw(b, "}", 1); }
int jsonb_begin_array(JsonBuilder *b)  { return jsonb_raw(b, "[", 1); }
int jsonb_end_array(JsonBuilder *b)    { return jsonb_raw(b, "]", 1); }
int jsonb_comma(JsonBuilder *b)        { return jsonb_raw(b, ",", 1); }

int jsonb_key(JsonBuilder *b, const char *key) {
    size_t klen;
    char *esc;
    if (!key) { b->err = 1; return -1; }
    klen = strlen(key);
    esc = malloc(klen * 6 + 3);
    if (!esc) { b->err = 1; return -1; }
    if (json_escape(key, klen, esc, klen * 6 + 3, NULL) != 0 ||
        jsonb_raw(b, "\"", 1) != 0 ||
        jsonb_raw(b, esc, strlen(esc)) != 0 ||
        jsonb_raw(b, "\":", 2) != 0) {
        free(esc);
        b->err = 1;
        return -1;
    }
    free(esc);
    return 0;
}

int jsonb_str(JsonBuilder *b, const char *val) {
    size_t vlen = val ? strlen(val) : 0;
    char *esc = malloc(vlen * 6 + 3);
    if (!esc) { b->err = 1; return -1; }
    if (json_escape(val ? val : "", vlen, esc, vlen * 6 + 3, NULL) != 0 ||
        jsonb_raw(b, "\"", 1) != 0 ||
        jsonb_raw(b, esc, strlen(esc)) != 0 ||
        jsonb_raw(b, "\"", 1) != 0) {
        free(esc);
        b->err = 1;
        return -1;
    }
    free(esc);
    return 0;
}

int jsonb_u32(JsonBuilder *b, uint32_t v) {
    char tmp[16];
    int n = snprintf(tmp, sizeof tmp, "%u", v);
    if (n < 0 || (size_t)n >= sizeof tmp) { b->err = 1; return -1; }
    return jsonb_raw(b, tmp, (size_t)n);
}

int jsonb_bool(JsonBuilder *b, int v) {
    return jsonb_raw(b, v ? "true" : "false", v ? 4 : 5);
}

char *jsonb_detach(JsonBuilder *b, size_t *len_out) {
    char *r;
    if (b->err) {
        free(b->buf);
        b->buf = NULL;
        b->len = b->cap = 0;
        b->err = 0;
        if (len_out) *len_out = 0;
        return NULL;
    }
    if (!b->buf) {
        b->buf = malloc(1);
        if (!b->buf) { if (len_out) *len_out = 0; return NULL; }
        b->buf[0] = '\0';
        b->len = 0;
        b->cap = 1;
    }
    r = b->buf;
    if (len_out) *len_out = b->len;
    b->buf = NULL;
    b->len = b->cap = 0;
    b->err = 0;
    return r;
}

/* Decode a 4-hex-digit \uXXXX escape and append its UTF-8 to out[o..outsz). */
static int json_append_unicode(const char *h, char *out, size_t outsz, size_t *o) {
    unsigned cp = 0;
    int k;
    for (k = 0; k < 4; k++) {
        char c = h[k];
        cp <<= 4;
        if      (c >= '0' && c <= '9') cp |= (unsigned)(c - '0');
        else if (c >= 'a' && c <= 'f') cp |= (unsigned)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') cp |= (unsigned)(c - 'A' + 10);
        else return -1;
    }
    if (cp < 0x80) {
        if (*o + 1 + 1 > outsz) return -1;
        out[(*o)++] = (char)cp;
    } else if (cp < 0x800) {
        if (*o + 2 + 1 > outsz) return -1;
        out[(*o)++] = (char)(0xC0 | (cp >> 6));
        out[(*o)++] = (char)(0x80 | (cp & 0x3F));
    } else {
        if (*o + 3 + 1 > outsz) return -1;
        out[(*o)++] = (char)(0xE0 | (cp >> 12));
        out[(*o)++] = (char)(0x80 | ((cp >> 6) & 0x3F));
        out[(*o)++] = (char)(0x80 | (cp & 0x3F));
    }
    return 0;
}

int json_obj_get_str(const char *json, const char *key, char *out, size_t outsz) {
    const char *p;
    size_t klen;
    if (!json || !key || !out || outsz == 0) return -1;
    klen = strlen(key);
    p = json;
    while (p && *p) {
        const char *ks = strchr(p, '"');
        const char *ke;
        if (!ks) return -1;
        ks++;
        ke = strchr(ks, '"');
        if (!ke) return -1;
        if ((size_t)(ke - ks) == klen && memcmp(ks, key, klen) == 0) {
            const char *q = ke + 1;
            while (*q == ' ' || *q == '\t' || *q == '\n' || *q == '\r') q++;
            if (*q == ':') {
                q++;
                while (*q == ' ' || *q == '\t' || *q == '\n' || *q == '\r') q++;
                if (*q == '"') {
                    size_t o = 0;
                    q++;
                    while (*q && *q != '"') {
                        if (*q == '\\') {
                            q++;
                            if (!*q) return -1;
                            switch (*q) {
                            case '"': case '\\': case '/':
                                if (o + 1 + 1 > outsz) return -1;
                                out[o++] = *q;
                                q++;
                                break;
                            case 'b': if (o + 1 + 1 > outsz) return -1; out[o++] = '\b'; q++; break;
                            case 'f': if (o + 1 + 1 > outsz) return -1; out[o++] = '\f'; q++; break;
                            case 'n': if (o + 1 + 1 > outsz) return -1; out[o++] = '\n'; q++; break;
                            case 'r': if (o + 1 + 1 > outsz) return -1; out[o++] = '\r'; q++; break;
                            case 't': if (o + 1 + 1 > outsz) return -1; out[o++] = '\t'; q++; break;
                            case 'u':
                                if (q[1] && q[2] && q[3] && q[4]) {
                                    if (json_append_unicode(q + 1, out, outsz, &o) != 0) return -1;
                                    q += 5;
                                } else {
                                    return -1;
                                }
                                break;
                            default:
                                return -1;
                            }
                        } else {
                            if (o + 1 + 1 > outsz) return -1;
                            out[o++] = *q++;
                        }
                    }
                    if (*q != '"') return -1;
                    out[o] = '\0';
                    return 0;
                }
            }
            return -1;   /* key present but not a string / malformed */
        }
        p = ke + 1;
    }
    return -1;
}

/* Same shape as json_obj_get_str but for an unsigned 32-bit decimal number
   (no surrounding quotes).  Rejects negatives and uint32 overflow. */
int json_obj_get_u32(const char *json, const char *key, uint32_t *out) {
    const char *p;
    size_t klen;
    if (!json || !key || !out) return -1;
    klen = strlen(key);
    p = json;
    while (p && *p) {
        const char *ks = strchr(p, '"');
        const char *ke;
        if (!ks) return -1;
        ks++;
        ke = strchr(ks, '"');
        if (!ke) return -1;
        if ((size_t)(ke - ks) == klen && memcmp(ks, key, klen) == 0) {
            const char *q = ke + 1;
            uint32_t v = 0;
            while (*q == ' ' || *q == '\t' || *q == '\n' || *q == '\r') q++;
            if (*q != ':') return -1;
            q++;
            while (*q == ' ' || *q == '\t' || *q == '\n' || *q == '\r') q++;
            if (*q < '0' || *q > '9') return -1;   /* not a decimal number */
            while (*q >= '0' && *q <= '9') {
                uint32_t d = (uint32_t)(*q - '0');
                if (v > (UINT32_MAX - d) / 10) return -1;   /* overflow */
                v = v * 10 + d;
                q++;
            }
            *out = v;
            return 0;
        }
        p = ke + 1;
    }
    return -1;
}
