/* auth_results.h — inbound message authentication (SPF/DKIM/DMARC) and the
 * RFC 8601 "Authentication-Results" header FairEmail et al. render.
 *
 * visage is the MX receiver for its domains, but historically it only DKIM
 * *signed* outbound and never evaluated inbound auth, so delivered mail had no
 * Authentication-Results and clients showed SPF/DKIM/DMARC/TLS as unknown.
 *
 * These functions are called on the raw inbound message at DATA time (before
 * mail_sanitize_for_forward strips the original DKIM-Signature), and the
 * resulting header is prepended so it survives forwarding to the mailbox.
 *
 * All functions block (they do DNS TXT queries) — consistent with the existing
 * smtp_out relay path, which already blocks on getaddrinfo in the same thread.
 */
#ifndef VISAGE_AUTH_RESULTS_H
#define VISAGE_AUTH_RESULTS_H

#include <stddef.h>
#include <stdint.h>

/* Maximum number of TXT strings returned for one DNS TXT query, and the max
 * length of each.  DKIM "p=" keys and SPF records stay well within this. */
#define AUTH_TXT_MAX_RECORDS 16
#define AUTH_TXT_MAX_LEN     1024

/* One TXT answer string (the concatenation of the record's <len><data>
 * segments).  heap-allocated, NUL-terminated. */
typedef struct {
    char *s;
    size_t len;
} AuthTxt;

/* Do a blocking DNS TXT query for `name` (e.g. "v=spf1" domain, "_dmarc.d",
 * "selector._domainkey.d").  Fills `out` (0..*n records) with heap strings the
 * caller frees with auth_txt_free.  Returns number of records (>=0), or -1 on
 * a hard failure (no resolver, socket error, malformed reply). */
int auth_dns_txt(const char *name, AuthTxt *out, size_t cap, size_t *n);

/* Test-facing: parse one TXT RDATA block (a run of <len><data> character
 * strings) into a single NUL-terminated heap string.  Returns 0 and fills the
 * `out` string and `out_len` on success, -1 on a malformed/oversized block.
 * Caller frees *out. */
int auth_txt_parse_rdata(const unsigned char *p, size_t rdlen,
                         char **out, size_t *out_len);

void auth_txt_free(AuthTxt *v, size_t n);

/* SPF result values (RFC 7208 §2.6). */
typedef enum {
    AUTH_SPF_NONE = 0,    /* no SPF record / temp error */
    AUTH_SPF_NEUTRAL,     /* "~all"-less, no match */
    AUTH_SPF_PASS,
    AUTH_SPF_FAIL,
    AUTH_SPF_SOFTFAIL,
} AuthSpf;

/* Evaluate SPF for `domain` against peer address `ip`/`iplen`
 * (4-byte IPv4 or 16-byte IPv6).  DNS TXT query; blocking. */
AuthSpf auth_spf_eval(const char *domain,
                      const unsigned char *ip, uint8_t iplen);

/* Test-facing: evaluate one SPF mechanism list (the text after "v=spf1",
 * without any prefix) against an address.  `def_dom` is the envelope-from
 * domain for the plain "a"/"mx" mechanisms (may be NULL).  No DNS for
 * ip4/ip6/all; "a"/"mx"/"include"/"redirect=" do DNS. */
AuthSpf auth_spf_eval_record(const char *rec, const char *def_dom,
                             const unsigned char *ip, uint8_t iplen);

/* DKIM result values (RFC 8601 §2.5.3). */
typedef enum {
    AUTH_DKIM_NONE = 0,   /* no DKIM-Signature header present */
    AUTH_DKIM_PASS,
    AUTH_DKIM_FAIL,       /* signature present but did not verify */
} AuthDkim;

/* Verify the DKIM-Signature in `msg` (msglen bytes) using the public key
 * fetched from DNS (selector._domainkey.d).  On NONE/PASS sets *sig_domain to
 * the signature's d= value (heap, caller frees). */
AuthDkim auth_dkim_eval(const char *msg, size_t msglen,
                        char **sig_domain);

/* DMARC result values (RFC 7489 §6.4). */
typedef enum {
    AUTH_DMARC_NONE = 0,  /* no _dmarc TXT / no policy / temp error */
    AUTH_DMARC_PASS,
    AUTH_DMARC_FAIL,
} AuthDmarc;

/* Evaluate DMARC for the RFC 5322 From domain `header_from_domain` given an
 * SPF + DKIM result.  `env_from_domain` is the envelope (MAIL FROM) domain and
 * `dkim_sig_domain` the DKIM d= tag, both used for identifier alignment
 * (RFC 7489 §3.1).  DNS TXT query; blocking. */
AuthDmarc auth_dmarc_eval(const char *env_from_domain,
                          const char *header_from_domain,
                          AuthSpf spf, AuthDkim dkim,
                          const char *dkim_sig_domain);

/* Test-facing: extract the domain of the RFC 5322 "From:" address from the raw
 * message headers.  Returns a heap copy, or NULL if absent/unparseable. */
char *auth_header_from_domain(const char *msg, size_t msglen);

/* Test-facing: DMARC identifier alignment (RFC 7489 §3.1, relaxed).  Returns 1
 * when `auth_domain` is identical to, or a subdomain of, `from_domain`. */
int auth_dmarc_domain_align(const char *auth_domain, const char *from_domain);

/* Build the full "Authentication-Results: <host>; ...\r\n" header line for the
 * inbound message `msg` (raw, msglen bytes) sent from `env_from_domain` by peer
 * `ip`/`iplen`.  Performs the DNS lookups.  Returns a heap, NUL-terminated
 * header line (including trailing CRLF) or NULL on allocation failure.  The
 * caller prepends it to the message and frees it. */
char *auth_results_build(const char *hostname, const char *msg, size_t msglen,
                         const char *env_from_domain,
                         const unsigned char *ip, uint8_t iplen);

/* Format the RFC 8601 header line from already-computed results (no DNS).
 * Test-facing; see auth_results.c.  `mailfromdom` is the envelope (MAIL FROM)
 * domain, `fromdom` the header From: domain.  Returns heap, NUL-terminated
 * line or NULL. */
char *auth_results_format(const char *hostname, AuthSpf spf, AuthDkim dkim,
                          AuthDmarc dmarc, const char *mailfromdom,
                          const char *fromdom, const char *dkim_dom);

/* Parse the envelope-From address's domain ("MAIL FROM:" value).  Returns a
 * heap copy of the domain ("" for the null sender <>), or NULL on failure. */
char *auth_env_from_domain(const char *env_from);

/* ------------------------------------------------------------------ */
/* Delivery DNS (MX + A/AAAA), shared by the outbox direct-delivery     */
/* path (src/outbox_submit.c).  Same blocking RFC 1035 UDP transport    */
/* as auth_dns_txt, querying the same (overridable) resolver.           */
/* ------------------------------------------------------------------ */

#define AUTH_MAX_MX     16
#define AUTH_MAX_ADDRS  16

/* One MX answer: the exchange hostname (heap, NUL-terminated, trailing root
 * dot stripped) plus its preference value. */
typedef struct {
    char    *host;
    uint16_t pref;
} AuthMx;

/* One A/AAAA answer: 4-byte IPv4 or 16-byte IPv6 address bytes. */
typedef struct {
    unsigned char ip[16];
    uint8_t       len;   /* 4 or 16 */
} AuthAddr;

/* Override the DNS resolver used by every auth_dns_* query (default: the first
 * "nameserver" line of /etc/resolv.conf, falling back to 127.0.0.53).  `server`
 * is "addr" or "addr:port" (e.g. "127.0.0.53" or "127.0.0.1:5300"; an IPv6
 * literal may be bracketed as "[::1]:5300").  Call once at startup before any
 * query.  Not thread-safe (single-threaded daemon). */
void auth_dns_set_resolver(const char *server);

/* Blocking DNS MX query for `name`.  Fills out[0..*n) sorted by ascending
 * preference (RFC 5321 delivery order).  Returns the record count (>=0), or -1
 * on a hard failure (no resolver, socket error, malformed reply).  Free with
 * auth_mx_free. */
int auth_dns_mx(const char *name, AuthMx *out, size_t cap, size_t *n);
void auth_mx_free(AuthMx *v, size_t n);

/* Blocking A + AAAA query for `name`: appends A records first, then AAAA.
 * Fills out[0..*n).  Returns the address count (>=0; an empty/absent answer is
 * 0, not an error), or -1 on a hard failure. */
int auth_dns_addr(const char *name, AuthAddr *out, size_t cap, size_t *n);

#endif /* VISAGE_AUTH_RESULTS_H */
