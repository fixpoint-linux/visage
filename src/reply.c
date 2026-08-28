/* reply.c — reverse-alias reply routing (slice S6).
 *
 * Implements the reverse-alias token lifecycle: minting the 32-hex token,
 * building the reply+<token>@domain reverse alias, routing an inbound reply
 * back to its original sender via the store's revmap, building the forward
 * MailRewrite strings, and stripping the reverse alias from To/Cc on the
 * outbound reply.  See reply.h for the API contract. */
#include "visage.h"
#include "reply.h"
#include <fcntl.h>
#include <time.h>

static const char hexdig[] = "0123456789abcdef";

/* --- token generation -------------------------------------------------- */

/* Fill 16 random bytes from /dev/urandom.  Returns 1 on success, 0 on any
 * failure (open/read error or short read). */
static int urandom16(unsigned char *b) {
    int fd = open("/dev/urandom", O_RDONLY);
    size_t got = 0;

    if (fd < 0) return 0;
    while (got < 16) {
        ssize_t r = read(fd, b + got, 16 - got);
        if (r < 0) {
            if (errno == EINTR) continue;
            close(fd);
            return 0;
        }
        if (r == 0) {          /* unexpected EOF: treat as failure */
            close(fd);
            return 0;
        }
        got += (size_t)r;
    }
    close(fd);
    return 1;
}

int reply_token_gen(char *out, size_t outsz) {
    unsigned char b[16];
    int nonzero = 0;
    size_t i;

    if (!out || outsz < 33) return VISAGE_EPARAM;

    /* No weak fallback: a token derived from time+pid+stack addresses is
       predictable (all tokens minted in the same second are even IDENTICAL),
       and reply tokens are the only authentication of the reverse-alias
       reply path.  Fail closed - the caller (forward_one, smtp_in.c:799-806)
       already refuses acceptance with 451 when this errors. */
    if (!urandom16(b)) return VISAGE_ERR;

    for (i = 0; i < 16; i++) {
        if (b[i]) { nonzero = 1; break; }
    }
    if (!nonzero) b[0] = 0x01;   /* guarantee the hex output is never all '0' */

    for (i = 0; i < 16; i++) {
        out[i * 2]     = hexdig[b[i] >> 4];
        out[i * 2 + 1] = hexdig[b[i] & 0x0f];
    }
    out[32] = '\0';
    return VISAGE_OK;
}

/* --- reverse-alias construction ---------------------------------------- */

int reply_make_reverse(const Config *cfg, const char *token, const char *alias_addr,
                       char *out, size_t outsz) {
    const char *prefix, *sep, *at;
    size_t plen, slen, tlen, dlen, total;

    if (!cfg || !token || !token[0] || !alias_addr || !out) return VISAGE_EPARAM;
    prefix = cfg->reply.prefix ? cfg->reply.prefix : "";
    sep = cfg->reply.separator ? cfg->reply.separator : "";

    at = strchr(alias_addr, '@');
    if (!at || at == alias_addr || at[1] == '\0') return VISAGE_EPARAM;

    plen = strlen(prefix);
    slen = strlen(sep);
    tlen = strlen(token);
    dlen = strlen(at + 1);
    total = plen + slen + tlen + 1 + dlen;
    if (total + 1 > outsz) return VISAGE_ERR;

    memcpy(out, prefix, plen);
    memcpy(out + plen, sep, slen);
    memcpy(out + plen + slen, token, tlen);
    out[plen + slen + tlen] = '@';
    memcpy(out + plen + slen + tlen + 1, at + 1, dlen);
    out[total] = '\0';
    return VISAGE_OK;
}

/* --- inbound reply routing ---------------------------------------------- */

/* If rcpt is a reverse-alias address ("<prefix><sep><token>@<domain>"), copy
 * the token (heap) into *out and return 1.  Return 0 if rcpt does not match
 * the shape (*out = NULL); negative on allocation failure. */
static int reply_token_extract(const Config *cfg, const char *rcpt, char **out) {
    const char *prefix, *sep, *p, *at;
    size_t plen, slen, tlen;
    char *t;

    *out = NULL;
    if (!cfg || !rcpt) return 0;
    prefix = cfg->reply.prefix ? cfg->reply.prefix : "";
    sep = cfg->reply.separator ? cfg->reply.separator : "";
    plen = strlen(prefix);
    slen = strlen(sep);

    if (strncmp(rcpt, prefix, plen) != 0) return 0;
    p = rcpt + plen;
    if (strncmp(p, sep, slen) != 0) return 0;
    p += slen;

    at = strchr(p, '@');
    if (!at || at == p || at[1] == '\0') return 0;   /* no token or no domain */

    tlen = (size_t)(at - p);
    t = malloc(tlen + 1);
    if (!t) return VISAGE_ENOMEM;
    memcpy(t, p, tlen);
    t[tlen] = '\0';
    *out = t;
    return 1;
}

int reply_route_inbound(Store *s, const Config *cfg, const char *rcpt,
                        char **sender_out, char **alias_addr_out) {
    char *token = NULL;
    char *sender = NULL, *alias = NULL;
    int rc;

    if (!sender_out || !alias_addr_out) return VISAGE_EPARAM;
    *sender_out = NULL;
    *alias_addr_out = NULL;

    rc = reply_token_extract(cfg, rcpt, &token);
    if (rc <= 0) return rc;        /* 0 = not a reply; negative = error */

    rc = store_revmap_resolve(s, token, &sender, &alias);
    free(token);
    if (rc != VISAGE_OK) {
        free(sender);
        free(alias);
        return rc;
    }
    if (!sender || !alias) {       /* unknown token: not a reply */
        free(sender);
        free(alias);
        return 0;
    }

    *sender_out = sender;
    *alias_addr_out = alias;
    return 1;
}

/* --- forward rewrite strings -------------------------------------------- */

int reply_from_rewrite(char **out, const char *sender, const char *reverse) {
    size_t slen, rlen, total;
    char *buf, *w;

    if (!out) return VISAGE_EPARAM;
    *out = NULL;
    if (!sender || !reverse) return VISAGE_EPARAM;

    slen = strlen(sender);
    rlen = strlen(reverse);
    /* "\"sender\" <reverse>" — 5 literal bytes. */
    total = slen + rlen + 5;

    buf = malloc(total + 1);
    if (!buf) return VISAGE_ENOMEM;

    w = buf;
    *w++ = '"';
    memcpy(w, sender, slen); w += slen;
    *w++ = '"';
    *w++ = ' ';
    *w++ = '<';
    memcpy(w, reverse, rlen); w += rlen;
    *w++ = '>';
    *w = '\0';

    *out = buf;
    return VISAGE_OK;
}

int reply_rewrite_build(const char *sender, const char *alias_addr, const char *reverse,
                        MailRewrite *rw) {
    char *from = NULL;
    int rc;

    if (!rw) return VISAGE_EPARAM;
    memset(rw, 0, sizeof *rw);
    if (!sender || !alias_addr || !reverse) return VISAGE_EPARAM;

    rc = reply_from_rewrite(&from, sender, reverse);
    if (rc != VISAGE_OK) return rc;
    rw->from = from;

    rw->reply_to = strdup(reverse);
    rw->return_path = strdup(alias_addr);
    rw->sender = strdup(alias_addr);
    if (!rw->reply_to || !rw->return_path || !rw->sender) {
        reply_rewrite_free(rw);
        return VISAGE_ENOMEM;
    }
    return VISAGE_OK;
}

void reply_rewrite_free(MailRewrite *rw) {
    if (!rw) return;
    free((void *)rw->from);
    free((void *)rw->reply_to);
    free((void *)rw->return_path);
    free((void *)rw->sender);
    memset(rw, 0, sizeof *rw);
}

/* --- stripping the reverse alias from To/Cc ------------------------------ */

/* ASCII case-insensitive equality over exactly n bytes. */
static int ascii_ieq_len(const char *a, const char *b, size_t n) {
    size_t i;
    for (i = 0; i < n; i++) {
        char ca = a[i], cb = b[i];
        if (ca >= 'A' && ca <= 'Z') ca = (char)(ca + 32);
        if (cb >= 'A' && cb <= 'Z') cb = (char)(cb + 32);
        if (ca != cb) return 0;
    }
    return 1;
}

/* Does the mailbox s[start..end) have an addr-spec equal to target?  Handles
 * the angle form ("Bob" <target>) and the bare form (target).  Respects quoted
 * strings, comments, and angle brackets while scanning. */
static int mailbox_matches(const char *s, size_t start, size_t end,
                           const char *target) {
    size_t i;
    int q = 0, c = 0, a = 0;
    size_t ang_s = 0, ang_e = 0;
    int found_angle = 0;
    size_t tlen = strlen(target);

    for (i = start; i < end; i++) {
        char ch = s[i];
        if (q) {
            if (ch == '\\' && i + 1 < end) i++;
            else if (ch == '"') q = 0;
        } else if (c) {
            if (ch == ')') c = 0;
        } else if (a) {
            if (ch == '>') { ang_e = i; a = 0; found_angle = 1; }
        } else if (ch == '"') q = 1;
        else if (ch == '(') c = 1;
        else if (ch == '<') { a = 1; ang_s = i + 1; }
    }

    if (found_angle) {
        size_t s0 = ang_s, e0 = ang_e;
        while (s0 < e0 && (s[s0] == ' ' || s[s0] == '\t')) s0++;
        while (e0 > s0 && (s[e0 - 1] == ' ' || s[e0 - 1] == '\t')) e0--;
        if (e0 - s0 != tlen) return 0;
        return ascii_ieq_len(s + s0, target, tlen);
    }

    /* Bare form: the last whitespace-delimited token is the addr-spec. */
    {
        size_t e0 = end;
        while (e0 > start && (s[e0 - 1] == ' ' || s[e0 - 1] == '\t')) e0--;
        size_t s0 = e0;
        while (s0 > start && s[s0 - 1] != ' ' && s[s0 - 1] != '\t') s0--;
        if (e0 - s0 != tlen) return 0;
        return ascii_ieq_len(s + s0, target, tlen);
    }
}

/* --- group-aware address-list stripping ---------------------------------
 *
 * RFC 5322 address-list grammar (subset handled here):
 *     address-list = address *("," address)
 *     address      = mailbox / group
 *     group        = display-name ":" [group-list] ";"
 *     group-list   = mailbox-list   (comma-separated, may nest via obs-syntax)
 *
 * A group is a SINGLE top-level element: its internal commas are not list
 * separators.  The reverse alias is stripped from any mailbox inside a group
 * while the group name, ':', surviving members, and closing ';' are preserved;
 * if every member is stripped the whole group element is dropped.  Nesting is
 * supported to arbitrary depth (a group body is itself an address list and is
 * processed recursively). */

/* Growable output buffer.  Allocation failure is recorded in o->oom (sticky)
 * so the recursive pass can bail out and the caller reports ENOMEM once. */
typedef struct {
    char *p;
    size_t len;
    size_t cap;
    int oom;
} OutBuf;

static void ob_init(OutBuf *o) {
    o->p = NULL;
    o->len = 0;
    o->cap = 0;
    o->oom = 0;
}

static void ob_put(OutBuf *o, const char *s, size_t n) {
    size_t need, ncap;
    char *np;

    if (o->oom || n == 0) return;
    if (n > SIZE_MAX - o->len - 1) { o->oom = 1; return; }
    need = o->len + n + 1;
    if (need > o->cap) {
        ncap = o->cap ? o->cap : 64;
        while (ncap < need) ncap *= 2;
        np = realloc(o->p, ncap);
        if (!np) { o->oom = 1; return; }
        o->p = np;
        o->cap = ncap;
    }
    memcpy(o->p + o->len, s, n);
    o->len += n;
}

static void ob_put_str(OutBuf *o, const char *s) {
    ob_put(o, s, strlen(s));
}

/* Append the whitespace-trimmed element s[start..end) to o, with a ", "
 * separator if o already holds an element (byte-identical to the legacy
 * non-group join). */
static void ob_put_elem(OutBuf *o, const char *s, size_t start, size_t end) {
    size_t s0 = start, e0 = end;
    while (s0 < e0 && (s[s0] == ' ' || s[s0] == '\t')) s0++;
    while (e0 > s0 && (s[e0 - 1] == ' ' || s[e0 - 1] == '\t')) e0--;
    if (e0 <= s0) return;
    if (o->len > 0) ob_put_str(o, ", ");
    ob_put(o, s + s0, e0 - s0);
}

/* Scan one address-list element starting at s[start]: a mailbox (bare or
 * angle form) or an RFC 5322 group (display-name ":" group-list ";").  Tracks
 * quoted strings, comments, angle brackets, and domain literals so that a
 * ',', ':', or ';' inside any of those is never structural, and tracks group
 * nesting depth so nested groups pair each ':' with its own ';'.
 *
 * Outputs: *is_group = 1 with *colon = index of the group ':' iff this is a
 * group; for a closed group *semi = index of the matching ';', otherwise
 * SIZE_MAX (unclosed).  Returns the index just past the element: just past the
 * ';' for a closed group, at the top-level ',' for a mailbox, or `end`. */
static size_t scan_address(const char *s, size_t start, size_t end,
                           int *is_group, size_t *colon, size_t *semi) {
    size_t i = start;
    int q = 0, c = 0, a = 0, d = 0;
    int depth = 0;

    *is_group = 0;
    *colon = SIZE_MAX;
    *semi = SIZE_MAX;

    while (i < end) {
        char ch = s[i];
        if (q) {
            if (ch == '\\' && i + 1 < end) i += 2;
            else { if (ch == '"') q = 0; i++; }
            continue;
        }
        if (c) { if (ch == ')') c = 0; i++; continue; }
        if (a) { if (ch == '>') a = 0; i++; continue; }
        if (d) { if (ch == ']') d = 0; i++; continue; }

        if (ch == '"') { q = 1; i++; continue; }
        if (ch == '(') { c = 1; i++; continue; }
        if (ch == '<') { a = 1; i++; continue; }
        if (ch == '[') { d = 1; i++; continue; }

        if (ch == ':') {
            if (depth == 0) { *is_group = 1; *colon = i; }
            depth++;
            i++;
            continue;
        }
        if (ch == ';') {
            if (depth > 0) {
                depth--;
                if (depth == 0) { *semi = i; return i + 1; }
            }
            i++;   /* stray ';' outside any group: consume, stay bounded */
            continue;
        }
        if (ch == ',') {
            if (depth == 0) return i;   /* element ends at a top-level comma */
            i++;                        /* comma inside a group body */
            continue;
        }
        i++;
    }
    return i;   /* ran off the end (unclosed group leaves *semi = SIZE_MAX) */
}

/* Recursively strip mailboxes whose addr-spec equals `target` from the address
 * list s[start..end).  Surviving addresses (mailboxes and groups) are appended
 * to o joined with ", ".  *matched is set to 1 if any mailbox was stripped.
 * Group nesting is handled by recursion: a group body is itself an address
 * list, so nested groups are stripped to arbitrary depth. */
static void addr_list_process(const char *s, size_t start, size_t end,
                              const char *target, OutBuf *o, int *matched) {
    size_t i = start;

    while (i < end && !o->oom) {
        int is_group;
        size_t colon, semi, addr_end, elem_start;

        while (i < end && (s[i] == ',' || s[i] == ' ' || s[i] == '\t')) i++;
        if (i >= end) break;
        elem_start = i;

        addr_end = scan_address(s, elem_start, end, &is_group, &colon, &semi);

        if (is_group && semi != SIZE_MAX) {
            /* Closed group.  Require a non-empty display-name; otherwise it is
             * a stray ':' and we fall back to keeping the element verbatim. */
            size_t p = elem_start;
            while (p < colon && (s[p] == ' ' || s[p] == '\t')) p++;
            if (p < colon) {
                OutBuf body;
                int body_matched = 0;

                ob_init(&body);
                addr_list_process(s, colon + 1, semi, target, &body, &body_matched);
                if (body.oom) { o->oom = 1; free(body.p); return; }

                if (body.len == 0) {
                    if (body_matched) {
                        *matched = 1;   /* every internal mailbox stripped */
                    } else {
                        /* already-empty group ("Name:;"): preserve verbatim */
                        ob_put_elem(o, s, elem_start, addr_end);
                    }
                } else {
                    if (o->len > 0) ob_put_str(o, ", ");
                    ob_put(o, s + elem_start, (colon + 1) - elem_start);
                    ob_put_str(o, " ");
                    ob_put(o, body.p, body.len);
                    ob_put(o, s + semi, addr_end - semi);
                    *matched = *matched || body_matched;
                }
                free(body.p);
                i = addr_end;
                continue;
            }
        }

        if (is_group) {
            /* Unclosed group (no ';') or empty display-name: malformed —
             * keep the element verbatim, do not attempt to strip inside. */
            ob_put_elem(o, s, elem_start, addr_end);
            i = addr_end;
            continue;
        }

        /* Plain mailbox element. */
        if (mailbox_matches(s, elem_start, addr_end, target)) {
            *matched = 1;
        } else {
            ob_put_elem(o, s, elem_start, addr_end);
        }
        i = addr_end;
    }
}

/* Remove every mailbox whose addr-spec equals target from a comma-separated
 * address list (RFC 5322 group-aware).  Returns 1 (match found; *out = new
 * list, possibly "") with a heap buffer in *out, 0 (no match; *out = NULL), or
 * negative on error. */
static int addr_list_strip(const char *list, const char *target, char **out) {
    OutBuf o;
    int matched = 0;
    size_t n = strlen(list);

    ob_init(&o);
    addr_list_process(list, 0, n, target, &o, &matched);

    if (o.oom) {
        free(o.p);
        return VISAGE_ENOMEM;
    }
    if (!matched) {
        free(o.p);
        *out = NULL;
        return 0;
    }
    if (o.p == NULL) {          /* matched, but nothing survived: "" */
        o.p = malloc(1);
        if (!o.p) return VISAGE_ENOMEM;
        o.p[0] = '\0';
    } else {
        o.p[o.len] = '\0';
    }
    *out = o.p;
    return 1;
}

int reply_strip_reverse(char **msg, size_t *len, const char *reverse) {
    static const char *names[] = { "To", "Cc" };
    int k;

    if (!msg || !*msg || !len || !reverse || !*reverse) return VISAGE_EPARAM;

    for (k = 0; k < 2; k++) {
        char *val = malloc(*len + 1);
        char *stripped = NULL;
        int rc;

        if (!val) return VISAGE_ENOMEM;

        rc = mail_header_get(*msg, *len, names[k], val, *len + 1);
        if (rc == 0) {
            rc = addr_list_strip(val, reverse, &stripped);
            if (rc < 0) { free(val); return rc; }
            if (rc == 1) {
                if (stripped[0] == '\0') {
                    mail_header_remove(msg, len, names[k]);
                } else {
                    mail_header_set(msg, len, names[k], stripped);
                }
                free(stripped);
            }
        }
        free(val);
    }
    return VISAGE_OK;
}

void reply_free(void *p) {
    free(p);
}
