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

/* Fallback PRNG: xorshift64 seeded from time + pid + stack addresses.  Always
 * succeeds (never all-zero seed). */
static void prng16(unsigned char *b) {
    uint64_t s = (uint64_t)time(NULL);
    s ^= (uint64_t)(uintptr_t)getpid() << 32;
    s ^= (uint64_t)(uintptr_t)b;       /* stack address of the output buffer */
    s ^= (uint64_t)(uintptr_t)&s;      /* stack address of the seed itself */
    if (s == 0) s = 0x9E3779B97F4A7C15ull;

    for (int i = 0; i < 16; i += 8) {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        memcpy(b + i, &s, 8);
    }
}

int reply_token_gen(char *out, size_t outsz) {
    unsigned char b[16];
    int nonzero = 0;
    size_t i;

    if (!out || outsz < 33) return VISAGE_EPARAM;

    if (!urandom16(b)) prng16(b);

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

int reply_from_rewrite(char **out, const char *sender, const char *alias_addr,
                       const char *reverse) {
    size_t slen, alen, rlen, total;
    char *buf, *w;

    if (!out) return VISAGE_EPARAM;
    *out = NULL;
    if (!sender || !alias_addr || !reverse) return VISAGE_EPARAM;

    slen = strlen(sender);
    alen = strlen(alias_addr);
    rlen = strlen(reverse);
    /* "\"<sender> via <alias_addr>\" <reverse>" — 14 literal bytes. */
    total = slen + alen + rlen + 14;

    buf = malloc(total + 1);
    if (!buf) return VISAGE_ENOMEM;

    w = buf;
    *w++ = '"';
    *w++ = '<';
    memcpy(w, sender, slen); w += slen;
    *w++ = '>';
    memcpy(w, " via ", 5); w += 5;
    *w++ = '<';
    memcpy(w, alias_addr, alen); w += alen;
    *w++ = '>';
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

    rc = reply_from_rewrite(&from, sender, alias_addr, reverse);
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

/* Remove every mailbox whose addr-spec equals target from a comma-separated
 * address list.  Returns 1 (match found; *out = new list, possibly "") with a
 * heap buffer in *out, 0 (no match; *out = NULL), or negative on error. */
static int addr_list_strip(const char *list, const char *target, char **out) {
    size_t n = strlen(list);
    size_t cap = n + 1;
    char *buf = malloc(cap);
    size_t w = 0, i = 0;
    int matched = 0;
    int first = 1;

    if (!buf) return VISAGE_ENOMEM;

    while (i < n) {
        while (i < n && (list[i] == ',' || list[i] == ' ' || list[i] == '\t')) i++;
        if (i >= n) break;

        size_t start = i;
        int q = 0, c = 0, a = 0;
        size_t j = i;
        while (j < n) {
            char ch = list[j];
            if (q) {
                if (ch == '\\' && j + 1 < n) j += 2;
                else { if (ch == '"') q = 0; j++; }
            } else if (c) {
                if (ch == ')') c = 0;
                j++;
            } else if (a) {
                if (ch == '>') a = 0;
                j++;
            } else if (ch == '"') { q = 1; j++; }
            else if (ch == '(') { c = 1; j++; }
            else if (ch == '<') { a = 1; j++; }
            else if (ch == ',') break;
            else j++;
        }
        size_t end = j;

        if (mailbox_matches(list, start, end, target)) {
            matched = 1;
        } else {
            size_t s0 = start, e0 = end;
            while (s0 < e0 && (list[s0] == ' ' || list[s0] == '\t')) s0++;
            while (e0 > s0 && (list[e0 - 1] == ' ' || list[e0 - 1] == '\t')) e0--;
            if (e0 > s0) {
                if (!first) { buf[w++] = ','; buf[w++] = ' '; }
                memcpy(buf + w, list + s0, e0 - s0);
                w += e0 - s0;
                first = 0;
            }
        }
        i = end;
        if (i < n && list[i] == ',') i++;
    }

    buf[w] = '\0';
    if (!matched) { free(buf); *out = NULL; return 0; }
    *out = buf;
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
