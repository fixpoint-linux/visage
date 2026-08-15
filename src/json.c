/* json.c — minimal JSON helpers for the admin HTTP API (slice S7). */
#include "json.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int json_escape(const char *s, size_t len, char *out, size_t outsz) {
    size_t i, o = 0;
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
            } else {
                if (o + 1 + 1 > outsz) return -1;
                out[o++] = (char)c;
            }
            break;
        }
    }
    out[o] = '\0';
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
    if (json_escape(key, klen, esc, klen * 6 + 3) != 0 ||
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
    if (json_escape(val ? val : "", vlen, esc, vlen * 6 + 3) != 0 ||
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
