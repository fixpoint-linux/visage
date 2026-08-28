/* mail.c — RFC5322 email primitives: strict address parsing, CRLF
   normalization, dot-stuffing/unstuffing, header manipulation, and the
   forward-sanitize pipeline. Pure string/memory handling: no sockets, no
   datalog. See mail.h for the full API contract.

   All line-oriented parsing accepts CRLF, bare LF, or bare CR line endings
   (the CRLF normalizer canonicalizes inbound data first). Header name
   matching is case-insensitive (ASCII only). */
#include "visage.h"
#include "mail.h"
#include <limits.h>

/* ------------------------------------------------------------------ */
/* Small char/string helpers                                          */
/* ------------------------------------------------------------------ */

/* RFC5322 atext: printable ASCII that is not a "special" and not '.'. */
static bool is_atext(unsigned char c) {
    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9'))
        return true;
    switch (c) {
    case '!': case '#': case '$': case '%': case '&': case '\'':
    case '*': case '+': case '-': case '/': case '=': case '?':
    case '^': case '_': case '`': case '{': case '|': case '}': case '~':
        return true;
    default:
        return false;
    }
}

/* dot-atom: 1*(atext) with '.' separators; no leading/trailing/doubled dot. */
static bool dot_atom_ok(const char *s, size_t len) {
    if (len == 0) return false;
    if (s[0] == '.' || s[len - 1] == '.') return false;
    bool prev_dot = false;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c == '.') {
            if (prev_dot) return false;
            prev_dot = true;
        } else {
            if (!is_atext(c)) return false;
            prev_dot = false;
        }
    }
    return true;
}

/* ASCII case-insensitive equality over exactly n bytes. */
static bool ascii_ieq(const char *a, const char *b, size_t n) {
    for (size_t i = 0; i < n; i++) {
        char ca = a[i];
        char cb = b[i];
        if (ca >= 'A' && ca <= 'Z') ca = (char)(ca + 32);
        if (cb >= 'A' && cb <= 'Z') cb = (char)(cb + 32);
        if (ca != cb) return false;
    }
    return true;
}

/* Advance past one physical line (CRLF, LF, or CR). */
static size_t skip_line(const char *msg, size_t len, size_t i) {
    while (i < len && msg[i] != '\r' && msg[i] != '\n') i++;
    if (i < len && msg[i] == '\r') i++;
    if (i < len && msg[i] == '\n') i++;
    return i;
}

/* Given the start of a header's value (just after ':'), return the index just
   past the last line of that logical header, following folded continuation
   lines (next line begins with SP/HT). */
static size_t header_end(const char *msg, size_t len, size_t vstart) {
    size_t i = vstart;
    for (;;) {
        while (i < len && msg[i] != '\r' && msg[i] != '\n') i++;
        size_t j = i;
        if (j < len && msg[j] == '\r') j++;
        if (j < len && msg[j] == '\n') j++;
        if (j < len && (msg[j] == ' ' || msg[j] == '\t')) { i = j; continue; }
        return j;
    }
}

/* Scan the header starting at msg[line_start] (which must not be a blank
   line). Returns true for a well-formed "field: value" header, setting
   *name_len to the field-name length and *end to the index just past the
   header (including folded lines). Returns false for a malformed line (no
   colon before EOL), setting *end past that line. */
static bool scan_header(const char *msg, size_t len, size_t line_start,
                        size_t *name_len, size_t *end) {
    size_t colon = line_start;
    while (colon < len && msg[colon] != ':' && msg[colon] != '\r' && msg[colon] != '\n')
        colon++;
    if (colon >= len || msg[colon] != ':') {
        *name_len = 0;
        *end = skip_line(msg, len, line_start);
        return false;
    }
    *name_len = colon - line_start;
    *end = header_end(msg, len, colon + 1);
    return true;
}

/* Does a C string contain a CR or LF (header-injection vector)? */
static bool contains_crlf(const char *s) {
    return s && (strchr(s, '\r') != NULL || strchr(s, '\n') != NULL);
}

/* ------------------------------------------------------------------ */
/* Address parsing                                                    */
/* ------------------------------------------------------------------ */

/* Printable ASCII (space through tilde).  Anything outside this — control
   chars, CR/LF, DEL, non-ASCII — is rejected so header/SMTP injection stays
   structurally impossible. */
static bool is_printable(unsigned char c) {
    return c >= 0x20 && c <= 0x7E;
}

/* Validate a domain: a dot-atom (the common case) or a domain-literal
   "[...]" (RFC 5321 address-literal).  Rejects empty, a second '@', CR/LF
   and control chars, and unbalanced brackets. */
static bool domain_ok(const char *s, size_t len) {
    if (len == 0) return false;
    if (s[0] == '[') {
        if (len < 3) return false;           /* "[]" too short / no closing ] */
        if (s[len - 1] != ']') return false; /* unbalanced '[' without ']' */
        for (size_t i = 1; i + 1 < len; i++) {
            unsigned char c = (unsigned char)s[i];
            if (c < 0x21 || c > 0x7E) return false;      /* space/ctl/CR/LF/non-ASCII */
            if (c == '[' || c == ']' || c == '@') return false;
        }
        return true;
    }
    if (memchr(s, '@', len)) return false;   /* double '@' */
    return dot_atom_ok(s, len);
}

/* Scan a quoted-string local part starting at start (which must be '"').
   Validates content per RFC 5322 qtext/quoted-pair and requires the closing
   quote to be immediately followed by the '@' separator.  On success stores
   the separator pointer in *at_out and returns true. */
static bool quoted_local_ok(const char *start, const char *end,
                            const char **at_out) {
    const char *p = start + 1;
    bool saw_content = false;
    for (;;) {
        unsigned char c;
        if (p >= end) return false;          /* unclosed quote */
        c = (unsigned char)*p;
        if (c == '\\') {
            /* quoted-pair: '\' + one printable char (rejects CR/LF + ctl) */
            if (p + 1 >= end) return false;
            if (!is_printable((unsigned char)p[1])) return false;
            saw_content = true;
            p += 2;
            continue;
        }
        if (c == '"') break;                 /* closing quote */
        if (!is_printable(c)) return false;  /* ctl / CR / LF / non-ASCII */
        saw_content = true;
        p++;
    }
    if (!saw_content) return false;          /* empty quoted local part */
    if (p + 1 >= end) return false;          /* nothing after the quote */
    if (p[1] != '@') return false;           /* '@' must follow the quote */
    *at_out = p + 1;
    return true;
}

int mail_addr_parse(const char *s, char **local, char **domain) {
    if (local) *local = NULL;
    if (domain) *domain = NULL;
    if (!s || !local || !domain) return -1;

    const char *p = s;
    while (*p == ' ' || *p == '\t') p++;
    size_t n = strlen(p);
    const char *end = p + n;
    while (end > p && (end[-1] == ' ' || end[-1] == '\t')) end--;
    if (end <= p) return -1; /* empty */

    const char *start = p;
    if (*start == '<') {
        if (end[-1] != '>') return -1; /* unbalanced */
        start++;
        end--;
        if (end <= start) return -1;   /* "<>" */
    }
    /* Reject stray '<'/'>' outside a quoted-string (valid only as the outer
       angle wrapper above, or inside a quoted-string local part). */
    for (const char *q = start; q < end;) {
        if (*q == '"') {
            q++;
            while (q < end && *q != '"') {
                if (*q == '\\' && q + 1 < end) q++;
                q++;
            }
            if (q < end) q++; /* past the closing quote */
        } else {
            if (*q == '<' || *q == '>') return -1;
            q++;
        }
    }

    const char *at;
    if (*start == '"') {
        if (!quoted_local_ok(start, end, &at)) return -1;
    } else {
        at = memchr(start, '@', (size_t)(end - start));
        if (!at) return -1;                                    /* missing @ */
        if (memchr(at + 1, '@', (size_t)(end - (at + 1)))) return -1; /* extra @ */
        if (!dot_atom_ok(start, (size_t)(at - start))) return -1;
    }

    size_t ll = (size_t)(at - start);
    size_t dl = (size_t)(end - (at + 1));
    if (!domain_ok(at + 1, dl)) return -1;

    char *l = malloc(ll + 1);
    if (!l) return -1;
    char *d = malloc(dl + 1);
    if (!d) { free(l); return -1; }
    memcpy(l, start, ll);
    l[ll] = '\0';
    memcpy(d, at + 1, dl);
    d[dl] = '\0';
    *local = l;
    *domain = d;
    return 0;
}

/* ------------------------------------------------------------------ */
/* CRLF normalization                                                 */
/* ------------------------------------------------------------------ */

static size_t crlf_newlen(const char *buf, size_t len) {
    size_t n = 0;
    for (size_t i = 0; i < len; i++) {
        if (buf[i] == '\r') {
            if (i + 1 < len && buf[i + 1] == '\n') { n += 2; i++; }
            else n += 2;
        } else if (buf[i] == '\n') {
            n += 2;
        } else {
            n += 1;
        }
    }
    return n;
}

/* Rewrite in place (back-to-front, so the write cursor never overtakes the
   read cursor). The lookbehind for a CRLF pair is read BEFORE this
   iteration's writes. */
static void crlf_rewrite(char *buf, size_t len, size_t newlen) {
    size_t w = newlen;
    size_t i = len;
    while (i > 0) {
        char c = buf[i - 1];
        if (c == '\n') {
            bool has_cr = (i >= 2 && buf[i - 2] == '\r');
            buf[--w] = '\n';
            buf[--w] = '\r';
            i -= has_cr ? 2 : 1;
        } else if (c == '\r') {
            buf[--w] = '\n';
            buf[--w] = '\r';
            i -= 1;
        } else {
            buf[--w] = c;
            i -= 1;
        }
    }
}

int mail_normalize_crlf(char *buf, size_t len) {
    if (!buf && len > 0) return -1;
    size_t newlen = crlf_newlen(buf, len);
    if (newlen > (size_t)INT_MAX) return -1;
    crlf_rewrite(buf, len, newlen);
    return (int)newlen;
}

/* ------------------------------------------------------------------ */
/* Dot-stuffing / unstuffing                                          */
/* ------------------------------------------------------------------ */

int mail_unstuff_dots(char *buf, size_t *len) {
    if (!buf || !len) return -1;
    size_t n = *len;
    size_t w = 0;
    bool at_line_start = true;
    for (size_t r = 0; r < n; r++) {
        char c = buf[r];
        if (at_line_start && c == '.') {
            at_line_start = false; /* drop the stuffed dot */
            continue;
        }
        buf[w++] = c;
        at_line_start = (c == '\n' || c == '\r');
    }
    *len = w;
    return 0;
}

int mail_data_has_ctl(const char *buf, size_t len) {
    size_t i;
    if (!buf) return 0;
    for (i = 0; i < len; i++) {
        unsigned char c = (unsigned char)buf[i];
        /* NUL, DEL, or a C0 control other than TAB/LF/CR is rejected.
           Bytes 0x80..0xFF (8BITMIME) are allowed. */
        if (c == 0x00 || c == 0x7F || (c < 0x20 && c != 0x09 && c != 0x0A && c != 0x0D))
            return 1;
    }
    return 0;
}

int mail_stuff_dots(const char *in, size_t inlen, char **out, size_t *outlen) {
    if (out) *out = NULL;
    if (outlen) *outlen = 0;
    if (!in || !out || !outlen) return -1;

    size_t extra = 0;
    bool at_line_start = true;
    for (size_t i = 0; i < inlen; i++) {
        char c = in[i];
        if (at_line_start && c == '.') extra++;
        at_line_start = (c == '\n' || c == '\r');
    }

    size_t total = inlen + extra;
    char *buf = malloc(total + 1);
    if (!buf) return -1;

    size_t w = 0;
    at_line_start = true;
    for (size_t i = 0; i < inlen; i++) {
        char c = in[i];
        if (at_line_start && c == '.') buf[w++] = '.';
        buf[w++] = c;
        at_line_start = (c == '\n' || c == '\r');
    }
    buf[w] = '\0';
    *out = buf;
    *outlen = w;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Header manipulation                                                */
/* ------------------------------------------------------------------ */

/* Unfold + trim the value of a header into out[0..outsz). */
static int extract_value(const char *msg, size_t vstart, size_t hend,
                         char *out, size_t outsz) {
    size_t o = 0;
    size_t i = vstart;
    while (i < hend && (msg[i] == ' ' || msg[i] == '\t')) i++; /* leading WSP */
    while (i < hend) {
        char c = msg[i];
        if (c == '\r' || c == '\n') {
            /* folded line: collapse CRLF + leading WSP to a single space */
            size_t j = i;
            if (j < hend && msg[j] == '\r') j++;
            if (j < hend && msg[j] == '\n') j++;
            while (j < hend && (msg[j] == ' ' || msg[j] == '\t')) j++;
            if (o < outsz - 1) out[o++] = ' ';
            i = j;
            continue;
        }
        if (o < outsz - 1) out[o++] = c;
        i++;
    }
    out[o] = '\0';
    while (o > 0 && (out[o - 1] == ' ' || out[o - 1] == '\t')) o--;
    out[o] = '\0';
    return 0;
}

int mail_header_get(const char *msg, size_t len, const char *name,
                    char *out, size_t outsz) {
    if (!msg || !name || !*name || !out || outsz == 0) return -1;
    size_t namelen = strlen(name);
    size_t i = 0;
    while (i < len) {
        if (msg[i] == '\r' || msg[i] == '\n') return -1; /* blank line: end of headers */
        size_t line_start = i;
        size_t name_len = 0, end = 0;
        if (!scan_header(msg, len, line_start, &name_len, &end)) { i = end; continue; }
        if (name_len == namelen && ascii_ieq(msg + line_start, name, namelen)) {
            return extract_value(msg, line_start + name_len + 1, end, out, outsz);
        }
        i = end;
    }
    return -1;
}

int mail_header_set(char **msg, size_t *len, const char *name, const char *value) {
    if (!msg || !*msg || !len || !name || !*name || !value) return -1;
    if (strchr(name, ':') || strchr(name, '\r') || strchr(name, '\n')) return -1;
    if (strchr(value, '\r') || strchr(value, '\n')) return -1;

    const char *m = *msg;
    size_t mlen = *len;
    size_t namelen = strlen(name);
    size_t vlen = strlen(value);

    size_t i = 0;
    bool found = false;
    size_t hs = 0, he = 0;
    size_t insert_pos = mlen;
    while (i < mlen) {
        if (m[i] == '\r' || m[i] == '\n') { insert_pos = i; break; } /* blank line */
        size_t line_start = i;
        size_t name_len = 0, end = 0;
        if (!scan_header(m, mlen, line_start, &name_len, &end)) { i = end; continue; }
        if (name_len == namelen && ascii_ieq(m + line_start, name, namelen) && !found) {
            found = true;
            hs = line_start;
            he = end;
        }
        i = end;
    }

    size_t new_header_len = namelen + 2 + vlen + 2; /* "name: value\r\n" */
    bool need_nl = false;
    size_t newlen;
    if (found) {
        newlen = mlen - (he - hs) + new_header_len;
    } else {
        need_nl = (insert_pos == mlen && mlen > 0 &&
                   m[mlen - 1] != '\n' && m[mlen - 1] != '\r');
        newlen = mlen + (need_nl ? 2 : 0) + new_header_len;
    }

    char *nb = malloc(newlen + 1);
    if (!nb) return -1;
    size_t w = 0;
    if (found) {
        memcpy(nb + w, m, hs);
        w += hs;
        memcpy(nb + w, name, namelen);
        w += namelen;
        nb[w++] = ':';
        nb[w++] = ' ';
        memcpy(nb + w, value, vlen);
        w += vlen;
        nb[w++] = '\r';
        nb[w++] = '\n';
        memcpy(nb + w, m + he, mlen - he);
        w += mlen - he;
    } else {
        memcpy(nb + w, m, insert_pos);
        w += insert_pos;
        if (need_nl) { nb[w++] = '\r'; nb[w++] = '\n'; }
        memcpy(nb + w, name, namelen);
        w += namelen;
        nb[w++] = ':';
        nb[w++] = ' ';
        memcpy(nb + w, value, vlen);
        w += vlen;
        nb[w++] = '\r';
        nb[w++] = '\n';
        memcpy(nb + w, m + insert_pos, mlen - insert_pos);
        w += mlen - insert_pos;
    }
    nb[w] = '\0';
    free(*msg);
    *msg = nb;
    *len = w;
    return 0;
}

int mail_header_remove(char **msg, size_t *len, const char *name) {
    if (!msg || !*msg || !len || !name || !*name) return -1;
    const char *m = *msg;
    size_t mlen = *len;
    size_t namelen = strlen(name);

    size_t removed = 0;
    size_t count = 0;
    size_t i = 0;
    while (i < mlen) {
        if (m[i] == '\r' || m[i] == '\n') break; /* blank line */
        size_t line_start = i;
        size_t name_len = 0, end = 0;
        if (!scan_header(m, mlen, line_start, &name_len, &end)) { i = end; continue; }
        if (name_len == namelen && ascii_ieq(m + line_start, name, namelen)) {
            removed += end - line_start;
            count++;
        }
        i = end;
    }
    if (count == 0) return 0;

    size_t newlen = mlen - removed;
    char *nb = malloc(newlen + 1);
    if (!nb) return -1;
    size_t w = 0;
    i = 0;
    while (i < mlen) {
        if (m[i] == '\r' || m[i] == '\n') {
            memcpy(nb + w, m + i, mlen - i);
            w += mlen - i;
            break;
        }
        size_t line_start = i;
        size_t name_len = 0, end = 0;
        if (!scan_header(m, mlen, line_start, &name_len, &end)) {
            memcpy(nb + w, m + line_start, end - line_start);
            w += end - line_start;
            i = end;
            continue;
        }
        bool match = (name_len == namelen && ascii_ieq(m + line_start, name, namelen));
        if (!match) {
            memcpy(nb + w, m + line_start, end - line_start);
            w += end - line_start;
        }
        i = end;
    }
    nb[w] = '\0';
    free(*msg);
    *msg = nb;
    *len = w;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Forward sanitize pipeline                                          */
/* ------------------------------------------------------------------ */

int mail_sanitize_for_forward(const char *in, size_t inlen,
                              const MailRewrite *rw, char **out, size_t *outlen) {
    if (out) *out = NULL;
    if (outlen) *outlen = 0;
    if (!in || !rw || !out || !outlen) return -1;
    if (contains_crlf(rw->received) || contains_crlf(rw->return_path) ||
        contains_crlf(rw->from) || contains_crlf(rw->sender) ||
        contains_crlf(rw->reply_to))
        return -1;
    if (inlen > (SIZE_MAX - 1) / 2) return -1;

    /* 1. Normalize CRLF into a fresh heap buffer (worst case 2*inlen). */
    char *cur = malloc(2 * inlen + 1);
    if (!cur) return -1;
    memcpy(cur, in, inlen);
    size_t curlen = crlf_newlen(cur, inlen);
    crlf_rewrite(cur, inlen, curlen);
    cur[curlen] = '\0';

    /* 2. Rewrite the envelope/identity headers: remove ALL occurrences first,
       then append the single trusted value. Removing first closes the
       duplicate-header injection hole — a message carrying two "From:" (or
       Reply-To/Sender/Return-Path) headers would otherwise forward with the
       attacker's extra copy intact. mail_header_remove() is a no-op when the
       header is absent (returns 0), so this is safe to call unconditionally. */
    if (rw->return_path) {
        if (mail_header_remove(&cur, &curlen, "Return-Path") != 0 ||
            mail_header_set(&cur, &curlen, "Return-Path", rw->return_path) != 0)
            goto fail;
    }
    if (rw->from) {
        if (mail_header_remove(&cur, &curlen, "From") != 0 ||
            mail_header_set(&cur, &curlen, "From", rw->from) != 0)
            goto fail;
    }
    if (rw->sender) {
        if (mail_header_remove(&cur, &curlen, "Sender") != 0 ||
            mail_header_set(&cur, &curlen, "Sender", rw->sender) != 0)
            goto fail;
    }
    if (rw->reply_to) {
        if (mail_header_remove(&cur, &curlen, "Reply-To") != 0 ||
            mail_header_set(&cur, &curlen, "Reply-To", rw->reply_to) != 0)
            goto fail;
    }

    /* Strip upstream DKIM-Signature headers: the message is modified (From/
       Received/etc.) so any signature added by the original sender no longer
       verifies and would surface as a failed DKIM at the receiver. Leave only
       the one visage re-signs with (its own domain). */
    if (mail_header_remove(&cur, &curlen, "DKIM-Signature") != 0)
        goto fail;

    /* 3. Prepend the Received: line. */
    if (rw->received) {
        size_t rv = strlen(rw->received);
        size_t tot = 10 + rv + 2 + curlen; /* "Received: " + value + "\r\n" + rest */
        char *nw = malloc(tot + 1);
        if (!nw) goto fail;
        memcpy(nw, "Received: ", 10);
        memcpy(nw + 10, rw->received, rv);
        nw[10 + rv] = '\r';
        nw[10 + rv + 1] = '\n';
        memcpy(nw + 10 + rv + 2, cur, curlen);
        nw[tot] = '\0';
        free(cur);
        cur = nw;
        curlen = tot;
    }

    *out = cur;
    *outlen = curlen;
    return 0;

fail:
    free(cur);
    return -1;
}

/* ------------------------------------------------------------------ */
/* Free helpers                                                       */
/* ------------------------------------------------------------------ */

void mail_free(void *p) {
    free(p);
}

void mail_addr_free(char *local, char *domain) {
    free(local);
    free(domain);
}
