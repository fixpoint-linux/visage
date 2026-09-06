/* auth_results.c — inbound message authentication (SPF/DKIM/DMARC).
 *
 * Implements:
 *   - a minimal blocking DNS TXT client (RFC 1035) over UDP, using the system
 *     resolver (first "nameserver" line of /etc/resolv.conf, default 127.0.0.53)
 *   - SPF evaluation (RFC 7208 subset: ip4/ip6/a/mx/include/all + ~all)
 *   - DKIM signature verification via a DNS-fetched public key
 *     (selector._domainkey.d; see dkim_verify_key in dkim.c)
 *   - DMARC evaluation (RFC 7489: _dmarc.<domain>, p= policy + alignment)
 *   - the RFC 8601 "Authentication-Results" header line
 *
 * All DNS work is blocking and happens in the single-threaded poll loop, which
 * is the same discipline smtp_out.c already uses (getaddrinfo at relay time).
 * DNS answers are memoized in a small (name,qtype) TTL cache and the resolver
 * endpoint / urandom source are resolved once per process (see the cache
 * block near dns_query_raw), so repeated lookups are cheap.
 */
#include "visage.h"
#include "auth_results.h"
#include "dkim.h"
#include "mail.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <strings.h>
#include <ctype.h>

#define AUTH_DNS_PORT    53
#define AUTH_DNS_TIMEOUT 4000   /* ms */
#define AUTH_DNS_BUFSZ   4096

/* ------------------------------------------------------------------ */
/* DNS TXT query (RFC 1035)                                            */
/* ------------------------------------------------------------------ */

/* Overridable resolver (set once by auth_dns_set_resolver before any query).
 * Empty = auto-detect from /etc/resolv.conf. */
static char g_resolver[128];

/* Resolver generation: bumped whenever the configured resolver changes so
 * cached DNS replies (see the cache near dns_query_raw) are never served
 * across a resolver switch (tests point this at per-suite fake servers). */
static unsigned g_dns_gen;

void auth_dns_set_resolver(const char *server) {
    if (server && server[0])
        snprintf(g_resolver, sizeof g_resolver, "%s", server);
    else
        g_resolver[0] = '\0';
    g_dns_gen++;
}

/* Find the first "nameserver" IP in /etc/resolv.conf into out (NUL-terminated).
 * Returns 0, or -1 to use the default. */
static int resolver_file_addr(char *out, size_t outsz) {
    FILE *f = fopen("/etc/resolv.conf", "r");
    char line[512];
    if (!f) return -1;
    while (fgets(line, sizeof line, f)) {
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (strncasecmp(p, "nameserver", 10) != 0) continue;
        p += 10;
        while (*p == ' ' || *p == '\t') p++;
        char *e = p;
        while (*e && *e != '\n' && *e != ' ' && *e != '\t') e++;
        size_t n = (size_t)(e - p);
        if (n == 0 || n >= outsz) continue;
        memcpy(out, p, n);
        out[n] = '\0';
        fclose(f);
        return 0;
    }
    fclose(f);
    return -1;
}

/* Cached resolver endpoint: the g_resolver override string is split and/or
 * /etc/resolv.conf is parsed ONCE, on first use — not per query (the parse
 * used to run for every lookup).  Recomputed only when auth_dns_set_resolver
 * installs a different value. */
static char     g_ns_addr[128];
static uint16_t g_ns_port;
static char     g_ns_from[sizeof g_resolver];
static bool     g_ns_cached;

/* Resolve the DNS server address + port for a query.  Honour the g_resolver
 * override ("addr[:port]" or "[v6]:port"); otherwise read /etc/resolv.conf
 * (port stays 53).  Never fails: falls back to 127.0.0.53:53. */
static void resolver_addrport(char *addr, size_t addr_sz, uint16_t *port) {
    if (!g_ns_cached || strcmp(g_resolver, g_ns_from) != 0) {
        char a[sizeof g_ns_addr];
        uint16_t p = AUTH_DNS_PORT;
        a[0] = '\0';

        if (g_resolver[0]) {
            const char *src = g_resolver;
            if (src[0] == '[') {   /* "[addr]:port" */
                const char *close = strchr(src, ']');
                if (close) {
                    size_t alen = (size_t)(close - src - 1);
                    if (alen > 0 && alen < sizeof a) {
                        memcpy(a, src + 1, alen);
                        a[alen] = '\0';
                    }
                    if (close[1] == ':') {
                        unsigned long pv = strtoul(close + 2, NULL, 10);
                        if (pv > 0 && pv <= 65535) p = (uint16_t)pv;
                    }
                }
            } else {
                const char *colon = strrchr(src, ':');
                if (colon) {       /* "addr:port" */
                    size_t alen = (size_t)(colon - src);
                    if (alen > 0 && alen < sizeof a) {
                        memcpy(a, src, alen);
                        a[alen] = '\0';
                    }
                    unsigned long pv = strtoul(colon + 1, NULL, 10);
                    if (pv > 0 && pv <= 65535) p = (uint16_t)pv;
                } else {
                    snprintf(a, sizeof a, "%s", src);
                }
            }
        }
        if (!a[0]) {
            if (resolver_file_addr(a, sizeof a) != 0 || !a[0])
                snprintf(a, sizeof a, "%s", "127.0.0.53");
        }
        memcpy(g_ns_addr, a, sizeof g_ns_addr);
        g_ns_port = p;
        snprintf(g_ns_from, sizeof g_ns_from, "%s", g_resolver);
        g_ns_cached = true;
    }
    snprintf(addr, addr_sz, "%s", g_ns_addr);
    *port = g_ns_port;
}

/* Encode `name` ("a.b") into a DNS label sequence.  Returns the byte count, or
 * -1 if the name is too long.  The terminating root label is included. */
static int dns_encode_name(const char *name, unsigned char *out, size_t outsz) {
    size_t w = 0;
    const char *p = name;
    while (*p) {
        const char *dot = strchr(p, '.');
        size_t label = dot ? (size_t)(dot - p) : strlen(p);
        if (label == 0 || label > 63) return -1;
        if (w + 1 + label > outsz) return -1;
        out[w++] = (unsigned char)label;
        memcpy(out + w, p, label);
        w += label;
        p += label;
        if (*p == '.') p++;
    }
    if (w + 1 > outsz) return -1;
    out[w++] = 0;
    return (int)w;
}

/* Skip a possibly-compressed name at `p` in `msg` (msglen); returns pointer
 * past the name, or NULL on error/loop. */
static const unsigned char *dns_skip_name(const unsigned char *msg, size_t msglen,
                                          const unsigned char *p) {
    int jumped = 0;
    const unsigned char *next = NULL;
    int hops = 0;
    for (;;) {
        if (p >= msg + msglen) return NULL;
        unsigned char len = *p;
        if (len == 0) { p++; return next ? next : p; }
        if ((len & 0xC0) == 0xC0) {
            if (p + 1 >= msg + msglen) return NULL;
            if (!jumped) next = p + 2;
            jumped = 1;
            p = msg + ((p[0] & 0x3F) << 8 | p[1]);
            if (++hops > 32) return NULL;
        } else if ((len & 0xC0) == 0) {
            p += 1 + len;
        } else {
            return NULL;
        }
    }
}

static void put16(unsigned char *b, uint16_t v) { b[0] = v >> 8; b[1] = v; }
static uint16_t get16(const unsigned char *b) { return (uint16_t)((b[0] << 8) | b[1]); }

/* 16 random bits from /dev/urandom for a DNS transaction ID (unpredictable
 * IDs make off-path response spoofing materially harder).  Returns 1 on
 * success, 0 on any failure (open/read error or short read) — callers fail the
 * query closed rather than fall back to a predictable ID.  The descriptor is
 * opened once per process and reused (each query used to re-open it); on a
 * read error it is closed so the next call re-opens it. */
static int urandom16(uint16_t *out) {
    static int fd = -1;
    unsigned char b[2];
    size_t got = 0;

    if (fd < 0)
        fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return 0;
    while (got < 2) {
        ssize_t r = read(fd, b + got, 2 - got);
        if (r < 0) {
            if (errno == EINTR) continue;
            close(fd);
            fd = -1;
            return 0;
        }
        if (r == 0) {          /* unexpected EOF: treat as failure */
            close(fd);
            fd = -1;
            return 0;
        }
        got += (size_t)r;
    }
    *out = (uint16_t)((b[0] << 8) | b[1]);
    return 1;
}

/* Validate the echoed question section of a DNS response (defined after
 * dns_read_name below). */
static int dns_check_question(const unsigned char *msg, size_t msglen,
                              const char *name, uint16_t qtype,
                              const unsigned char **pp);

/* Generic RFC 1035 query transport with the (name,qtype) reply cache in front
 * of it (defined with the delivery-DNS helpers below).  auth_dns_txt and
 * auth_dns_a route through it so every lookup in this file shares one code
 * path — and one cache. */
static int dns_query_raw(const char *name, uint16_t qtype,
                         unsigned char *r, size_t rsz);

/* Blocking DNS TXT query for `name`.  Populates out[0..*n) with heap strings.
 * Returns record count (>=0) or -1. */
int auth_dns_txt(const char *name, AuthTxt *out, size_t cap, size_t *n) {
    unsigned char r[AUTH_DNS_BUFSZ];
    const unsigned char *p;
    unsigned ancount;
    size_t i, found = 0;
    int msglen;

    *n = 0;
    if (!name || !name[0]) return -1;
    msglen = dns_query_raw(name, 16 /* TXT */, r, sizeof r);
    if (msglen < 0) return -1;
    if (dns_check_question(r, (size_t)msglen, name, 16, &p) != 0) return -1;
    ancount = get16(r + 6);
    if (ancount == 0) return 0;              /* NXDOMAIN/NODATA -> 0 records */

    for (i = 0; i < ancount && found < cap; i++) {
        p = dns_skip_name(r, (size_t)msglen, p); if (!p) return -1;
        if (p + 10 > r + (size_t)msglen) return -1;
        uint16_t rtype = get16(p);
        uint16_t rdlen = get16(p + 8);
        p += 10;
        if (p + rdlen > r + (size_t)msglen) return -1;
        if (rtype == 16) {   /* TXT */
            char *s = NULL;
            size_t sl = 0;
            if (auth_txt_parse_rdata(p, rdlen, &s, &sl) == 0) {
                out[found].s = s;
                out[found].len = sl;
                found++;
            }
        }
        p += rdlen;
    }
    *n = found;
    return (int)found;
}

/* Parse a TXT RDATA block (a run of <len><data> character-strings) into one
 * NUL-terminated heap string.  The second (copy) loop re-checks the segment
 * length exactly like the first (sizing) loop, so a truncated final
 * character-string can never make memcpy exceed the malloc'd buffer.  Returns
 * 0 and fills the `out` string and `out_len` on success, -1 on a
 * malformed/oversized block.  Test-facing: lets auth_check feed a truncated
 * RDATA without live DNS. */
int auth_txt_parse_rdata(const unsigned char *p, size_t rdlen,
                         char **out, size_t *out_len) {
    size_t tlen = 0, seg = 0, w = 0, sg = 0;
    char *s;

    if (!p || !out || !out_len) return -1;
    *out = NULL;
    *out_len = 0;

    while (seg < rdlen) {
        size_t slen = p[seg];
        if (seg + 1 + slen > rdlen) break;
        tlen += slen;
        seg += 1 + slen;
    }
    if (tlen + 1 > AUTH_TXT_MAX_LEN) return -1;

    s = malloc(tlen + 1);
    if (!s) return -1;
    while (sg < rdlen) {
        size_t slen = p[sg];
        if (sg + 1 + slen > rdlen) break;   /* malformed: stop at validated tlen */
        memcpy(s + w, p + sg + 1, slen);
        w += slen;
        sg += 1 + slen;
    }
    s[w] = '\0';
    *out = s;
    *out_len = w;
    return 0;
}

void auth_txt_free(AuthTxt *v, size_t n) {
    size_t i;
    for (i = 0; i < n; i++) free(v[i].s);
}

/* ------------------------------------------------------------------ */
/* Envelope-From domain                                               */
/* ------------------------------------------------------------------ */

char *auth_env_from_domain(const char *env_from) {
    char *local = NULL, *domain = NULL;
    if (!env_from || env_from[0] == '\0' ||
        (env_from[0] == '<' && env_from[1] == '>'))
        return strdup("");
    if (mail_addr_parse(env_from, &local, &domain) != 0)
        return strdup("");
    char *out = strdup(domain ? domain : "");
    mail_addr_free(local, domain);
    return out;
}

/* ------------------------------------------------------------------ */
/* SPF (RFC 7208 subset)                                               */
/* ------------------------------------------------------------------ */

/* Blocking DNS A query for `name`; fills out[0..*n).  Reuses the generic
 * transport with qtype A (1).  Returns record count (>=0) or -1. */
static int auth_dns_a(const char *name, AuthAddr *out, size_t cap, size_t *n) {
    unsigned char r[AUTH_DNS_BUFSZ];
    const unsigned char *p;
    unsigned ancount;
    size_t i, found = 0;
    int msglen;

    *n = 0;
    if (!name || !name[0]) return -1;
    msglen = dns_query_raw(name, 1 /* A */, r, sizeof r);
    if (msglen < 0) return -1;
    if (dns_check_question(r, (size_t)msglen, name, 1, &p) != 0) return -1;
    ancount = get16(r + 6);

    for (i = 0; i < ancount && found < cap; i++) {
        uint16_t rtype, rdlen;
        p = dns_skip_name(r, (size_t)msglen, p); if (!p) return -1;
        if (p + 10 > r + (size_t)msglen) return -1;
        rtype = get16(p);
        rdlen = get16(p + 8);
        p += 10;
        if (p + rdlen > r + (size_t)msglen) return -1;
        if (rtype == 1 && rdlen == 4) {
            memcpy(out[found].ip, p, 4);
            out[found].len = 4;
            found++;
        }
        p += rdlen;
    }
    *n = found;
    return (int)found;
}

/* Does `ip` (iplen) fall within the IPv4 `a.b.c.d/prefix`? */
static int spf_ip4_match(const unsigned char *ip, uint8_t iplen,
                         const char *cidr) {
    if (iplen != 4) return 0;
    struct in_addr a;
    unsigned prefix = 32;
    char buf[64], *slash;
    if (strlen(cidr) >= sizeof buf) return 0;
    strcpy(buf, cidr);
    slash = strchr(buf, '/');
    if (slash) { *slash = '\0'; prefix = (unsigned)atoi(slash + 1); if (prefix > 32) prefix = 32; }
    if (inet_pton(AF_INET, buf, &a) != 1) return 0;
    const unsigned char *m = (const unsigned char *)&a;
    if (prefix == 0) return 1;
    unsigned bits = prefix;
    for (int b = 0; b < 4 && bits > 0; b++) {
        unsigned char mm = bits >= 8 ? 0xff : (unsigned char)(0xff << (8 - bits));
        if ((ip[b] & mm) != (m[b] & mm)) return 0;
        bits = bits >= 8 ? bits - 8 : 0;
    }
    return 1;
}

static int spf_ip6_match(const unsigned char *ip, uint8_t iplen,
                         const char *cidr) {
    if (iplen != 16) return 0;
    struct in6_addr a;
    unsigned prefix = 128;
    char buf[64], *slash;
    if (strlen(cidr) >= sizeof buf) return 0;
    strcpy(buf, cidr);
    slash = strchr(buf, '/');
    if (slash) { *slash = '\0'; prefix = (unsigned)atoi(slash + 1); if (prefix > 128) prefix = 128; }
    if (inet_pton(AF_INET6, buf, &a) != 1) return 0;
    const unsigned char *m = a.s6_addr;
    unsigned bits = prefix;
    for (int b = 0; b < 16 && bits > 0; b++) {
        unsigned char mm = bits >= 8 ? 0xff : (unsigned char)(0xff << (8 - bits));
        if ((ip[b] & mm) != (m[b] & mm)) return 0;
        bits = bits >= 8 ? bits - 8 : 0;
    }
    return 1;
}

/* RFC 7208 §4.6.4: at most 10 DNS-requiring TERMS per SPF check — the limit
 * is on the total across a:/mx:/include:/redirect= (a non-recursive a:/mx:
 * counts too), not just the include/redirect recursion depth (which is all
 * the old depth counter capped, leaving ~140 a: mechanisms per record
 * unbounded).  The counter is threaded through the whole evaluation and
 * incremented for every such term whether or not the query happens; an
 * over-budget term simply does not match, so records within the budget
 * evaluate exactly as before. */
#define AUTH_SPF_MAX_LOOKUPS 10

static AuthSpf auth_spf_eval_depth(const char *domain,
                                   const unsigned char *ip, uint8_t iplen,
                                   int *lookups);

/* Evaluate one SPF mechanism list against ip.  `rec` is the v=spf1 record
 * (without "v=spf1"); `def_dom` is the envelope-from domain used by the plain
 * "a" / "mx" mechanisms (may be NULL).  `lookups` is the shared DNS-term
 * budget counter for the whole evaluation.  Returns the first matching
 * result. */
static AuthSpf auth_spf_eval_record_depth(const char *rec, const char *def_dom,
                                          const unsigned char *ip, uint8_t iplen,
                                          int *lookups) {
    const char *p = rec;
    while (*p) {
        while (*p == ' ') p++;
        if (!*p) break;
        const char *tok = p;
        while (*p && *p != ' ') p++;
        size_t tl = (size_t)(p - tok);

        /* qualifier (optional): + (pass) - (fail) ~ (softfail) ? (neutral) */
        AuthSpf q = AUTH_SPF_PASS;
        const char *mech = tok;
        if (tl > 0 && (*mech == '+' || *mech == '-' || *mech == '~' || *mech == '?')) {
            if (*mech == '-') q = AUTH_SPF_FAIL;
            else if (*mech == '~') q = AUTH_SPF_SOFTFAIL;
            else if (*mech == '?') q = AUTH_SPF_NEUTRAL;
            mech++; tl--;
        }
        if (tl >= 4 && strncasecmp(mech, "ip4:", 4) == 0) {
            char cidr[64];
            size_t cl = tl - 4;
            if (cl >= sizeof cidr) cl = sizeof cidr - 1;
            memcpy(cidr, mech + 4, cl);
            cidr[cl] = '\0';
            if (spf_ip4_match(ip, iplen, cidr)) return q;
        } else if (tl >= 4 && strncasecmp(mech, "ip6:", 4) == 0) {
            char cidr[64];
            size_t cl = tl - 4;
            if (cl >= sizeof cidr) cl = sizeof cidr - 1;
            memcpy(cidr, mech + 4, cl);
            cidr[cl] = '\0';
            if (spf_ip6_match(ip, iplen, cidr)) return q;
        } else if (tl == 3 && strncasecmp(mech, "all", 3) == 0) {
            return q;
        } else if (tl >= 1 && strncasecmp(mech, "a", 1) == 0) {
            /* a:<domain> or plain "a": match the (envelope-from) domain A records */
            char dom[512];
            const char *dd;
            size_t i, n = 0;
            AuthAddr addrs[AUTH_MAX_ADDRS];
            if (tl >= 2 && mech[1] == ':') {
                size_t dl = tl - 2;
                if (dl >= sizeof dom) dl = sizeof dom - 1;
                memcpy(dom, mech + 2, dl);
                dom[dl] = '\0';
                dd = dom;
            } else {
                dd = def_dom;
            }
            if (++*lookups <= AUTH_SPF_MAX_LOOKUPS &&
                dd && auth_dns_a(dd, addrs, AUTH_MAX_ADDRS, &n) >= 0) {
                for (i = 0; i < n; i++) {
                    if (addrs[i].len == iplen &&
                        memcmp(addrs[i].ip, ip, iplen) == 0)
                        return q;
                }
            }
        } else if (tl >= 2 && strncasecmp(mech, "mx", 2) == 0) {
            /* mx[:domain]: the mail-exchanger A records; for the minimal
               subset treat as neutral unless the domain's own A matches. */
            char dom[512];
            const char *dd;
            size_t i, n = 0;
            AuthAddr addrs[AUTH_MAX_ADDRS];
            if (tl >= 3 && mech[2] == ':') {
                size_t dl = tl - 3;
                if (dl >= sizeof dom) dl = sizeof dom - 1;
                memcpy(dom, mech + 3, dl);
                dom[dl] = '\0';
                dd = dom;
            } else {
                dd = def_dom;
            }
            if (++*lookups <= AUTH_SPF_MAX_LOOKUPS &&
                dd && auth_dns_a(dd, addrs, AUTH_MAX_ADDRS, &n) >= 0) {
                for (i = 0; i < n; i++)
                    if (addrs[i].len == iplen &&
                        memcmp(addrs[i].ip, ip, iplen) == 0)
                        return q;
            }
        } else if (tl >= 8 && strncasecmp(mech, "redirect=", 9) == 0) {
            char dom[512];
            size_t dl = tl - 9;
            if (dl >= sizeof dom) dl = sizeof dom - 1;
            memcpy(dom, mech + 9, dl);
            dom[dl] = '\0';
            /* redirect= must be the last mechanism; evaluate the target
               (respecting the RFC 7208 §4.6.4 lookup budget). */
            AuthSpf r = ++*lookups > AUTH_SPF_MAX_LOOKUPS
                            ? AUTH_SPF_NONE
                            : auth_spf_eval_depth(dom, ip, iplen, lookups);
            if (r == AUTH_SPF_PASS) return q;
            if (r == AUTH_SPF_FAIL) return AUTH_SPF_FAIL;
            if (r == AUTH_SPF_SOFTFAIL) return AUTH_SPF_SOFTFAIL;
        } else if (tl >= 7 && strncasecmp(mech, "include:", 8) == 0) {
            /* include:<domain> — evaluate the included domain's record.  RFC
               7208 §5.2: the include matches ONLY when the included record
               passes; on any other result (fail/softfail/neutral/none) it
               does not match and evaluation continues to the next mechanism.
               (Only `all` and `redirect=` carry fail/softfail forward.) */
            char dom[512];
            size_t dl = tl - 8;
            if (dl >= sizeof dom) dl = sizeof dom - 1;
            memcpy(dom, mech + 8, dl);
            dom[dl] = '\0';
            if (++*lookups <= AUTH_SPF_MAX_LOOKUPS &&
                auth_spf_eval_depth(dom, ip, iplen, lookups) == AUTH_SPF_PASS)
                return q;
        }
    }
    return AUTH_SPF_NEUTRAL;   /* record present but no mechanism matched */
}

/* Public, non-static wrapper for the auth_check harness (fresh budget). */
AuthSpf auth_spf_eval_record(const char *rec, const char *def_dom,
                             const unsigned char *ip, uint8_t iplen) {
    int lookups = 0;
    return auth_spf_eval_record_depth(rec, def_dom, ip, iplen, &lookups);
}

/* Fetch and evaluate `domain`'s SPF record.  The initial TXT fetch is not a
 * "term" (RFC 7208 §4.6.4 counts mechanisms/modifiers); an include's fetch is
 * covered by the include itself having consumed budget. */
static AuthSpf auth_spf_eval_depth(const char *domain,
                                   const unsigned char *ip, uint8_t iplen,
                                   int *lookups) {
    AuthTxt v[AUTH_TXT_MAX_RECORDS];
    size_t n = 0, i;
    if (!domain || !domain[0] || !ip) return AUTH_SPF_NONE;
    if (auth_dns_txt(domain, v, AUTH_TXT_MAX_RECORDS, &n) < 0) {
        auth_txt_free(v, n);
        return AUTH_SPF_NONE;
    }
    AuthSpf res = AUTH_SPF_NONE;
    for (i = 0; i < n; i++) {
        if (strncasecmp(v[i].s, "v=spf1", 6) == 0) {
            const char *rec = v[i].s + 6;
            while (*rec == ' ') rec++;
            res = auth_spf_eval_record_depth(rec, domain, ip, iplen, lookups);
            break;
        }
    }
    auth_txt_free(v, n);
    return res;
}

AuthSpf auth_spf_eval(const char *domain,
                      const unsigned char *ip, uint8_t iplen) {
    int lookups = 0;
    return auth_spf_eval_depth(domain, ip, iplen, &lookups);
}

/* ------------------------------------------------------------------ */
/* DKIM                                                                */
/* ------------------------------------------------------------------ */

AuthDkim auth_dkim_eval(const char *msg, size_t msglen, char **sig_domain) {
    char hdr[2048];
    char *d = NULL, *s = NULL;

    if (sig_domain) *sig_domain = NULL;
    if (!msg || !msglen) return AUTH_DKIM_NONE;
    if (mail_header_get(msg, msglen, "DKIM-Signature", hdr, sizeof hdr) != 0)
        return AUTH_DKIM_NONE;   /* no signature */

    /* extract d= and s= tokens (RFC 6376; unfolded by mail_header_get) */
    {
        const char *p = hdr;
        while (p && *p) {
            while (*p == ' ' || *p == '\t') p++;
            if (p[0] == 'd' && p[1] == '=') {
                const char *q = p + 2;
                while (*q == ' ' || *q == '\t') q++;
                const char *e = q;
                while (*e && *e != ';' && *e != ' ' && *e != '\t') e++;
                d = malloc((size_t)(e - q) + 1);
                if (d) { memcpy(d, q, (size_t)(e - q)); d[e - q] = '\0'; }
            } else if (p[0] == 's' && p[1] == '=') {
                const char *q = p + 2;
                while (*q == ' ' || *q == '\t') q++;
                const char *e = q;
                while (*e && *e != ';' && *e != ' ' && *e != '\t') e++;
                s = malloc((size_t)(e - q) + 1);
                if (s) { memcpy(s, q, (size_t)(e - q)); s[e - q] = '\0'; }
            }
            /* advance past this tag */
            const char *semi = strchr(p, ';');
            if (!semi) break;
            p = semi + 1;
        }
    }

    if (!d || !d[0] || !s || !s[0]) {
        free(d); free(s);
        return AUTH_DKIM_NONE;
    }

    /* Fetch the public key from DNS: s._domainkey.d -> TXT, take p= */
    {
        char qname[512];
        AuthTxt v[AUTH_TXT_MAX_RECORDS];
        size_t n = 0, i;
        snprintf(qname, sizeof qname, "%s._domainkey.%s", s, d);
        if (auth_dns_txt(qname, v, AUTH_TXT_MAX_RECORDS, &n) < 0) {
            auth_txt_free(v, n); free(d); free(s);
            return AUTH_DKIM_NONE;
        }
        char *pubkey = NULL;
        for (i = 0; i < n && !pubkey; i++) {
            /* record contains "p=<base64> ..." */
            char *pk = strstr(v[i].s, "p=");
            if (pk) {
                size_t pl = strlen(pk + 2);
                if (pl + 32 < 2048) {   /* p= value plus PEM wrappers */
                    char *key = malloc(pl + 96);
                    if (key) {
                        snprintf(key, pl + 96,
                                 "-----BEGIN PUBLIC KEY-----\n%.*s\n"
                                 "-----END PUBLIC KEY-----\n",
                                 (int)pl, pk + 2);
                        pubkey = key;
                    }
                }
            }
        }
        auth_txt_free(v, n);
        if (!pubkey) { free(d); free(s); return AUTH_DKIM_NONE; }

        int vr = dkim_verify_key(msg, msglen, pubkey);
        free(pubkey);
        if (vr != 0) {
            free(d); free(s);
            return AUTH_DKIM_FAIL;
        }
    }

    if (sig_domain) *sig_domain = d;
    else free(d);
    free(s);
    return AUTH_DKIM_PASS;
}

/* ------------------------------------------------------------------ */
/* DMARC (RFC 7489)                                                    */
/* ------------------------------------------------------------------ */

static const char *dmarc_policy(const char *from_domain, int *out_p) {
    AuthTxt v[AUTH_TXT_MAX_RECORDS];
    size_t n = 0, i;
    char qname[512];
    const char *pol = NULL;
    *out_p = 0;
    snprintf(qname, sizeof qname, "_dmarc.%s", from_domain);
    if (auth_dns_txt(qname, v, AUTH_TXT_MAX_RECORDS, &n) < 0) {
        auth_txt_free(v, n);
        return NULL;
    }
    for (i = 0; i < n; i++) {
        if (strncasecmp(v[i].s, "v=DMARC1", 8) == 0) {
            char *pp = strstr(v[i].s, "p=");
            if (pp && pp[2] != '\0') {
                char c = pp[2];
                *out_p = (c == 'q' || c == 'Q') ? 1 : (c == 'r' || c == 'R') ? 2 : 0;
                pol = "";
            }
            break;
        }
    }
    auth_txt_free(v, n);
    return pol;
}

/* Extract the domain of the RFC 5322 "From:" address from the raw message
 * headers (the domain DMARC policy + alignment are keyed on).  Returns a heap
 * copy of the domain, or NULL if the header is absent or unparseable.
 * Test-facing: pure, no DNS. */
char *auth_header_from_domain(const char *msg, size_t msglen) {
    char hdr[2048];
    const char *lt, *addr;
    size_t alen;
    char *tmp, *local = NULL, *domain = NULL;

    if (!msg || !msglen) return NULL;
    if (mail_header_get(msg, msglen, "From", hdr, sizeof hdr) != 0)
        return NULL;

    /* take the addr-spec: "<a@b>" or a bare "a@b" (optional display name) */
    lt = strchr(hdr, '<');
    if (lt) {
        const char *gt = strchr(lt, '>');
        if (!gt) return NULL;
        addr = lt + 1;
        alen = (size_t)(gt - addr);
    } else {
        addr = hdr;
        alen = strlen(hdr);
    }
    tmp = malloc(alen + 1);
    if (!tmp) return NULL;
    memcpy(tmp, addr, alen);
    tmp[alen] = '\0';
    if (mail_addr_parse(tmp, &local, &domain) != 0) {
        free(tmp);
        return NULL;
    }
    free(tmp);
    free(local);
    return domain;
}

/* DMARC identifier alignment (RFC 7489 §3.1, relaxed: the authenticated domain
 * is identical to, or a subdomain of, the From domain).  Test-facing. */
int auth_dmarc_domain_align(const char *auth_domain, const char *from_domain) {
    size_t fl, al, prefix;
    if (!auth_domain || !from_domain) return 0;
    fl = strlen(from_domain);
    al = strlen(auth_domain);
    if (al == fl) return strcasecmp(auth_domain, from_domain) == 0;
    if (al < fl) return 0;
    prefix = al - fl;   /* e.g. "sub.example.com" vs "example.com" -> 4 */
    return auth_domain[prefix - 1] == '.' &&
           strcasecmp(auth_domain + prefix, from_domain) == 0;
}

AuthDmarc auth_dmarc_eval(const char *env_from_domain, const char *header_from_domain,
                          AuthSpf spf, AuthDkim dkim, const char *dkim_sig_domain) {
    int pol;
    int spf_aligned, dkim_aligned;
    if (!header_from_domain || !header_from_domain[0]) return AUTH_DMARC_NONE;
    if (dmarc_policy(header_from_domain, &pol) == NULL) return AUTH_DMARC_NONE;
    if (pol == 0) return AUTH_DMARC_NONE;   /* p=none: record, no action */

    /* DMARC requires identifier alignment (RFC 7489 §3.1): SPF/DKIM only count
       toward a pass when the authenticated domain aligns with the From domain.
       SPF authenticates the envelope-from (MAIL FROM) domain; DKIM the d= tag. */
    spf_aligned = (spf == AUTH_SPF_PASS &&
                   auth_dmarc_domain_align(env_from_domain, header_from_domain));
    dkim_aligned = (dkim == AUTH_DKIM_PASS &&
                    auth_dmarc_domain_align(dkim_sig_domain, header_from_domain));
    if (spf_aligned || dkim_aligned)
        return AUTH_DMARC_PASS;
    if (spf == AUTH_SPF_FAIL && !dkim_aligned)
        return AUTH_DMARC_FAIL;
    return AUTH_DMARC_NONE;
}

/* ------------------------------------------------------------------ */
/* Authentication-Results (RFC 8601)                                   */
/* ------------------------------------------------------------------ */

static const char *spf_str(AuthSpf v) {
    switch (v) {
    case AUTH_SPF_PASS: return "pass";
    case AUTH_SPF_FAIL: return "fail";
    case AUTH_SPF_SOFTFAIL: return "softfail";
    case AUTH_SPF_NEUTRAL: return "neutral";
    default: return "none";
    }
}

static const char *dkim_str(AuthDkim v) {
    return v == AUTH_DKIM_PASS ? "pass" : v == AUTH_DKIM_FAIL ? "fail" : "none";
}

static const char *dmarc_str(AuthDmarc v) {
    return v == AUTH_DMARC_PASS ? "pass" : v == AUTH_DMARC_FAIL ? "fail" : "none";
}

/* Format the RFC 8601 "Authentication-Results" header line (CRLF-terminated,
 * heap, NUL-terminated) from already-computed results.  Test-facing: the DNS
 * lookups happen in the caller, so the exact on-wire shape is unit-testable
 * here.  `mailfromdom` is the envelope (MAIL FROM) domain, `fromdom` the
 * header From: domain, and `dkim_dom` the DKIM d= tag. */
char *auth_results_format(const char *hostname, AuthSpf spf, AuthDkim dkim,
                          AuthDmarc dmarc, const char *mailfromdom,
                          const char *fromdom, const char *dkim_dom) {
    size_t cap = 256;
    char *buf = malloc(cap);
    if (!buf) return NULL;
    bool have_d = (dkim == AUTH_DKIM_PASS && dkim_dom && dkim_dom[0]);
    const char *hfrom = fromdom && fromdom[0] ? fromdom
                                              : (mailfromdom ? mailfromdom : "");
    size_t n = (size_t)snprintf(buf, cap, "Authentication-Results: %s;\r\n"
                                "\tspf=%s smtp.mailfrom=%s;\r\n"
                                "\tdkim=%s%s%s;\r\n"
                                "\tdmarc=%s header.from=%s\r\n",
                                hostname && hostname[0] ? hostname : "localhost",
                                spf_str(spf), mailfromdom ? mailfromdom : "",
                                dkim_str(dkim),
                                have_d ? " header.d=" : "",
                                have_d ? dkim_dom : "",
                                dmarc_str(dmarc), hfrom);
    if (n >= cap) { free(buf); return NULL; }
    return buf;
}

char *auth_results_build(const char *hostname, const char *msg, size_t msglen,
                         const char *env_from_domain,
                         const unsigned char *ip, uint8_t iplen) {
    char *fromdom = NULL;
    char *hdrfrom = NULL;
    char *dkim_dom = NULL;
    AuthSpf spf;
    AuthDkim dkim;
    AuthDmarc dmarc;
    char *out = NULL;

    fromdom = auth_env_from_domain(env_from_domain);
    if (!fromdom) return NULL;
    if (fromdom[0] == '\0') { free(fromdom); return NULL; }  /* null sender: nothing to auth */

    hdrfrom = auth_header_from_domain(msg, msglen);
    spf = auth_spf_eval(fromdom, ip, iplen);
    dkim = auth_dkim_eval(msg, msglen, &dkim_dom);
    dmarc = auth_dmarc_eval(fromdom, hdrfrom, spf, dkim, dkim_dom);

    out = auth_results_format(hostname, spf, dkim, dmarc, fromdom, hdrfrom, dkim_dom);

    free(fromdom);
    free(hdrfrom);
    free(dkim_dom);
    return out;
}

/* ------------------------------------------------------------------ */
/* DNS reply cache                                                     */
/* ------------------------------------------------------------------ */

/* Small (name,qtype) cache of raw replies so repeated lookups within the
 * answer's TTL do not re-query — one inbound message repeats the same
 * TXT/A queries across SPF/DKIM/DMARC, and so do consecutive messages from
 * the same sender.  Round-robin eviction; entries belong to the resolver
 * generation they were fetched under and are ignored once
 * auth_dns_set_resolver changes it.  Hard failures (timeouts, malformed
 * replies) are never cached.  Single-threaded per process, like the rest of
 * this file (each process does its DNS from one thread). */
#define AUTH_DNS_CACHE_SLOTS   64
#define AUTH_DNS_CACHE_NEG_TTL 30     /* s: cache empty answers (NODATA/NXDOMAIN) briefly */
#define AUTH_DNS_CACHE_MAX_TTL 3600   /* s: staleness ceiling even for long-TTL answers */

typedef struct {
    char           name[256];
    uint16_t       qtype;
    unsigned       gen;       /* g_dns_gen the reply was fetched under */
    unsigned char *reply;     /* heap copy of the raw reply, header..end */
    size_t         len;
    time_t         expires;   /* unix seconds; 0 = free slot */
} DnsCacheEnt;

static DnsCacheEnt g_dns_cache[AUTH_DNS_CACHE_SLOTS];
static size_t      g_dns_cache_victim;

static uint32_t get32(const unsigned char *b) {
    return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) |
           ((uint32_t)b[2] << 8) | b[3];
}

/* Cache lifetime for a raw reply: the minimum TTL across its answer records
 * (an empty answer gets the short negative TTL).  Returns 0, or -1 when the
 * answer section is malformed (the reply is then not cached). */
static int dns_reply_ttl(const unsigned char *r, size_t msglen, uint32_t *out) {
    const unsigned char *p = r + 12;
    unsigned ancount, i;
    uint32_t ttl = 0;

    if (msglen < 12) return -1;
    p = dns_skip_name(r, msglen, p);
    if (!p) return -1;
    p += 4;   /* QTYPE + QCLASS */
    ancount = get16(r + 6);
    if (ancount == 0) { *out = AUTH_DNS_CACHE_NEG_TTL; return 0; }
    for (i = 0; i < ancount; i++) {
        uint32_t t;
        uint16_t rdlen;
        p = dns_skip_name(r, msglen, p);
        if (!p || p + 10 > r + msglen) return -1;
        t = get32(p + 4);       /* TTL, between CLASS and RDLENGTH */
        rdlen = get16(p + 8);
        p += 10;
        if (p + rdlen > r + msglen) return -1;
        if (i == 0 || t < ttl) ttl = t;
        p += rdlen;
    }
    if (ttl > AUTH_DNS_CACHE_MAX_TTL) ttl = AUTH_DNS_CACHE_MAX_TTL;
    *out = ttl;
    return 0;
}

/* Serve a fresh cached reply into `r`; returns 1 on hit, 0 on miss. */
static int dns_cache_get(const char *name, uint16_t qtype,
                         unsigned char *r, size_t rsz, int *outlen) {
    time_t now = time(NULL);
    size_t i;
    for (i = 0; i < AUTH_DNS_CACHE_SLOTS; i++) {
        DnsCacheEnt *e = &g_dns_cache[i];
        if (e->expires == 0 || e->gen != g_dns_gen) continue;
        if (e->qtype != qtype || strcasecmp(e->name, name) != 0) continue;
        if (now >= e->expires) {         /* expired: free the slot */
            free(e->reply); e->reply = NULL; e->expires = 0;
            continue;
        }
        if (e->len > rsz) continue;      /* cannot happen; guard anyway */
        memcpy(r, e->reply, e->len);
        *outlen = (int)e->len;
        return 1;
    }
    return 0;
}

static void dns_cache_put(const char *name, uint16_t qtype,
                          const unsigned char *reply, size_t len, time_t expires) {
    DnsCacheEnt *e = &g_dns_cache[g_dns_cache_victim++ % AUTH_DNS_CACHE_SLOTS];
    unsigned char *copy = malloc(len);
    if (!copy) return;                   /* cache is best-effort */
    free(e->reply);
    snprintf(e->name, sizeof e->name, "%s", name);
    e->qtype = qtype;
    e->gen = g_dns_gen;
    e->reply = copy;
    memcpy(copy, reply, len);
    e->len = len;
    e->expires = expires;
}

/* Generic RFC 1035 query (header + QNAME + QTYPE + QCLASS, RD set).  Returns
 * the raw reply length (>= 12), or -1 on a hard failure (resolver, socket,
 * timeout, mismatched id, short reply). */
static int dns_query_raw(const char *name, uint16_t qtype,
                         unsigned char *r, size_t rsz) {
    unsigned char q[AUTH_DNS_BUFSZ];
    char ns[128];
    uint16_t nsport;
    struct sockaddr_in sa;
    int fd, len, rc;
    uint16_t qid;
    int cached;

    if (!name || !name[0]) return -1;
    if (dns_cache_get(name, qtype, r, rsz, &cached)) return cached;
    if (!urandom16(&qid)) return -1;
    resolver_addrport(ns, sizeof ns, &nsport);
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port = htons(nsport);
    if (inet_pton(AF_INET, ns, &sa.sin_addr) != 1) { close(fd); return -1; }

    memset(q, 0, sizeof q);
    put16(q, qid);
    put16(q + 2, 0x0100);      /* RD */
    put16(q + 4, 1);           /* QDCOUNT */
    len = dns_encode_name(name, q + 12, sizeof q - 12);
    if (len < 0) { close(fd); return -1; }
    len += 12;
    if (len + 4 > (int)sizeof q) { close(fd); return -1; }
    put16(q + (size_t)len, qtype);
    put16(q + (size_t)len + 2, 1);   /* IN */
    len += 4;

    rc = sendto(fd, q, (size_t)len, 0, (struct sockaddr *)&sa, sizeof sa);
    if (rc < 0) { close(fd); return -1; }
    {
        struct pollfd pfd;
        pfd.fd = fd;
        pfd.events = POLLIN;
        if (poll(&pfd, 1, AUTH_DNS_TIMEOUT) <= 0) { close(fd); return -1; }
    }
    rc = (int)recv(fd, r, rsz, 0);
    close(fd);
    if (rc < 12 || get16(r) != qid) return -1;
    if (dns_check_question(r, (size_t)rc, name, qtype, NULL) != 0) return -1;

    {
        uint32_t ttl;
        if (dns_reply_ttl(r, (size_t)rc, &ttl) == 0)
            dns_cache_put(name, qtype, r, (size_t)rc, time(NULL) + (time_t)ttl);
    }
    return rc;
}

/* Decode a (possibly compressed) wire-format domain name into out
 * (NUL-terminated).  Returns 0, or -1 on a malformed name/loop/overflow. */
static int dns_read_name(const unsigned char *msg, size_t msglen,
                         const unsigned char *p, char *out, size_t outsz) {
    size_t w = 0;
    int hops = 0;
    if (outsz == 0) return -1;
    out[0] = '\0';
    for (;;) {
        unsigned char len;
        uint16_t off;
        if (p >= msg + msglen) return -1;
        len = *p;
        if (len == 0) break;
        if ((len & 0xC0) == 0xC0) {
            if (p + 1 >= msg + msglen) return -1;
            off = (uint16_t)(((len & 0x3F) << 8) | p[1]);
            p = msg + off;
            if (++hops > 32) return -1;
            continue;
        }
        if ((len & 0xC0) != 0) return -1;   /* 0x40/0x80 label types unsupported */
        if (len > 63) return -1;
        p++;
        if (p + len > msg + msglen) return -1;
        if (w > 0) {
            if (w + 1 >= outsz) return -1;
            out[w++] = '.';
        }
        if (w + len >= outsz) return -1;
        memcpy(out + w, p, len);
        w += len;
        p += len;
    }
    if (w == 0) return -1;
    out[w] = '\0';
    return 0;
}

/* Validate the echoed question section of a DNS response against the query we
 * sent: QDCOUNT must be 1, QNAME must equal `name` (case-insensitive), QTYPE
 * must equal `qtype`, and QCLASS must be IN (1).  On success sets *pp just past
 * the question (first answer) and returns 0; returns -1 on any mismatch. */
static int dns_check_question(const unsigned char *msg, size_t msglen,
                              const char *name, uint16_t qtype,
                              const unsigned char **pp) {
    char qname[256];
    const unsigned char *p;

    if (msglen < 12 || get16(msg + 4) != 1) return -1;   /* QDCOUNT must be 1 */
    p = msg + 12;
    if (dns_read_name(msg, msglen, p, qname, sizeof qname) != 0) return -1;
    if (strcasecmp(qname, name) != 0) return -1;
    p = dns_skip_name(msg, msglen, p);
    if (!p) return -1;
    if (p + 4 > msg + msglen) return -1;
    if (get16(p) != qtype) return -1;
    if (get16(p + 2) != 1) return -1;   /* QCLASS IN */
    if (pp) *pp = p + 4;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Delivery DNS (MX + A/AAAA)                                          */
/* ------------------------------------------------------------------ */

int auth_dns_mx(const char *name, AuthMx *out, size_t cap, size_t *n) {
    unsigned char r[AUTH_DNS_BUFSZ];
    const unsigned char *p;
    uint16_t ancount;
    size_t i, found = 0;
    int msglen;

    *n = 0;
    if (!name || !name[0] || !out || cap == 0) return -1;
    msglen = dns_query_raw(name, 15 /* MX */, r, sizeof r);
    if (msglen < 0) return -1;

    ancount = get16(r + 6);
    p = r + 12;
    p = dns_skip_name(r, (size_t)msglen, p);
    if (!p) return -1;
    p += 4;   /* QTYPE + QCLASS */

    for (i = 0; i < ancount && found < cap; i++) {
        uint16_t rtype, rdlen, pref;
        p = dns_skip_name(r, (size_t)msglen, p);
        if (!p) return -1;
        if (p + 10 > r + (size_t)msglen) return -1;
        rtype = get16(p);
        rdlen = get16(p + 8);
        p += 10;
        if (p + rdlen > r + (size_t)msglen) return -1;
        if (rtype == 15 && rdlen >= 3) {
            char host[256];
            pref = get16(p);
            if (dns_read_name(r, (size_t)msglen, p + 2, host, sizeof host) == 0) {
                char *h = strdup(host);
                if (h) {
                    out[found].host = h;
                    out[found].pref = pref;
                    found++;
                }
            }
        }
        p += rdlen;
    }

    /* Stable sort by ascending preference (RFC 5321 delivery order). */
    for (i = 0; i + 1 < found; i++) {
        size_t j;
        for (j = 0; j + 1 < found - i; j++) {
            if (out[j].pref > out[j + 1].pref) {
                AuthMx t = out[j];
                out[j] = out[j + 1];
                out[j + 1] = t;
            }
        }
    }
    *n = found;
    return (int)found;
}

void auth_mx_free(AuthMx *v, size_t n) {
    size_t i;
    for (i = 0; i < n; i++) free(v[i].host);
}

/* Blocking AAAA query; mirrors auth_dns_a.  Static: the public surface is
 * auth_dns_addr (A + AAAA merged). */
static int auth_dns_aaaa(const char *name, AuthAddr *out, size_t cap, size_t *n) {
    unsigned char r[AUTH_DNS_BUFSZ];
    const unsigned char *p;
    uint16_t ancount;
    size_t i, found = 0;
    int msglen;

    *n = 0;
    if (!name || !name[0]) return -1;
    msglen = dns_query_raw(name, 28 /* AAAA */, r, sizeof r);
    if (msglen < 0) return -1;

    ancount = get16(r + 6);
    p = r + 12;
    p = dns_skip_name(r, (size_t)msglen, p);
    if (!p) return -1;
    p += 4;

    for (i = 0; i < ancount && found < cap; i++) {
        uint16_t rtype, rdlen;
        p = dns_skip_name(r, (size_t)msglen, p);
        if (!p) return -1;
        if (p + 10 > r + (size_t)msglen) return -1;
        rtype = get16(p);
        rdlen = get16(p + 8);
        p += 10;
        if (p + rdlen > r + (size_t)msglen) return -1;
        if (rtype == 28 && rdlen == 16) {
            memcpy(out[found].ip, p, 16);
            out[found].len = 16;
            found++;
        }
        p += rdlen;
    }
    *n = found;
    return (int)found;
}

int auth_dns_addr(const char *name, AuthAddr *out, size_t cap, size_t *n) {
    size_t na = 0, nq = 0;
    int ra, rq;
    if (!out || cap == 0) return -1;
    ra = auth_dns_a(name, out, cap, &na);
    rq = auth_dns_aaaa(name, out + na, cap - na, &nq);
    if (ra < 0 && rq < 0) return -1;
    *n = na + nq;
    return (int)(na + nq);
}
