/* outbox.h — standalone SMTP submission + direct-delivery daemon ("outbox").
 *
 * A poll()-based, single-threaded event loop (mirroring smtp_in.c / imapd.c)
 * with two listeners:
 *   - implicit-TLS (SMTPS, RFC 8314) :465 — TLS starts immediately on accept
 *   - STARTTLS (RFC 3207)            :587 — plaintext until STARTTLS
 *
 * Submission is authenticated against ONE shared credential store (a plaintext
 * "user:pass" file, 0600, one per line — the same format as imapd.passwd).
 * After AUTH PLAIN/LOGIN the single account may send From: any of the
 * configured allowed domains; the envelope MAIL FROM domain MUST be in that
 * set (else 554 5.7.1) and, at DATA time, the RFC5322 From: header domain MUST
 * equal the envelope MAIL FROM domain (strict DMARC aspf=s — else 554 5.7.1).
 * Each accepted message is DKIM-signed (selector "visage") with the From
 * domain's key and delivered DIRECTLY to each recipient's MX (RFC 5321
 * preference order; no-MX falls back to the domain A record, port 25).
 *
 * Config: CLI flags + env only (the imapd precedent — no Dhall/datalog).
 *
 * Bounds: every command line is capped at SMTP_MAX_LINE; the DATA payload at
 * max_msg (2x + 16 during dot-stuffed accumulation); recipient count at
 * max_rcpts; cmd/data reads are idle-timed.  No unbounded allocations on
 * attacker-controlled length. */
#ifndef VISAGE_OUTBOX_H
#define VISAGE_OUTBOX_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <pthread.h>

#include "config.h"   /* Config — the one-shot delivery config for smtp_out */
#include "smtp.h"     /* SmtpTls (opaque), SMTP_MAX_LINE, smtp_backoff_sec */

/* ------------------------------------------------------------------ */
/* Limits (mirroring smtp_in.c's bounded-buffer discipline)           */
/* ------------------------------------------------------------------ */

#define OUTBOX_MAX_CONNS          512
#define OUTBOX_MAX_CONNS_PER_IP   16
#define OUTBOX_MAX_OUT            (256u * 1024u)
#define OUTBOX_RECV_CHUNK         4096
#define OUTBOX_LISTEN_BACKLOG     128

#define OUTBOX_DEFAULT_MAX_MSG    (32u * 1024u * 1024u)
#define OUTBOX_DEFAULT_CMD_TMO    300
#define OUTBOX_DEFAULT_DATA_TMO   600
#define OUTBOX_DEFAULT_MAX_RCPTS  32
#define OUTBOX_DEFAULT_MAX_ATTEMPTS 5   /* per-recipient in-session MX attempts */
#define OUTBOX_DEFAULT_DELIVER_PORT 25
#define OUTBOX_DEFAULT_INTERNAL_RELAY_PORT 2525  /* visage MX implicit-TLS ingest */

/* Delivery-queue caps (enforced in outbox_delivery_enqueue): an authenticated
   submitter must not be able to enqueue unbounded ~max_msg jobs and OOM the
   daemon (queued mail is lost — v1 does not re-drive the spool). */
#define OUTBOX_DEFAULT_QUEUE_MAX_JOBS  1024
#define OUTBOX_DEFAULT_QUEUE_MAX_BYTES (256u * 1024u * 1024u)

/* Brute-force protection (mirrors imapd's per-IP failed-auth lockout). */
#define OUTBOX_AUTH_MAX_FAILS     5
#define OUTBOX_AUTH_WINDOW_SEC    60
#define OUTBOX_AUTH_LOCKOUT_SEC   300
#define OUTBOX_AUTH_MAX_TRACKED   64

/* ------------------------------------------------------------------ */
/* Configuration (flags + env, no Dhall on purpose)                    */
/* ------------------------------------------------------------------ */

/* One DKIM signing key: DOMAIN -> RSA private-key PEM path. */
typedef struct {
    char *domain;
    char *key;
} OutboxDkim;

typedef struct {
    char       *implicit_addr;   /* SMTPS listener bind address      */
    uint16_t    implicit_port;   /* 0 disables the listener          */
    char       *starttls_addr;   /* STARTTLS listener bind address   */
    uint16_t    starttls_port;   /* 0 disables the listener          */
    char       *cert;            /* TLS certificate PEM (required)   */
    char       *key;             /* TLS private key PEM (required)   */
    char       *passwd;          /* shared credential file path      */
    char      **domains;         /* allowed envelope-From domains    */
    size_t      ndomains;
    OutboxDkim *dkim;            /* DOMAIN=KEYFILE signing map       */
    size_t      ndkim;
    char       *hostname;        /* EHLO + greeting hostname         */
    char       *spool;           /* best-effort spool dir            */
    uint32_t    max_msg;
    uint32_t    max_line;
    uint32_t    max_rcpts;
    uint32_t    cmd_tmo;
    uint32_t    data_tmo;
    uint32_t    max_attempts;    /* per-recipient delivery attempts  */
    uint16_t    deliver_port;    /* delivery port (default 25; override for tests) */
    char       *dns_server;      /* DNS resolver override ("addr[:port]") */
    uint32_t    queue_max_jobs;  /* delivery-queue job cap (0 => default)  */
    uint64_t    queue_max_bytes; /* delivery-queue message-byte cap        */
    /* Internal-domain delivery routing: a recipient whose domain is in the
       internal set (below) is delivered to this relay — the visage MX — instead
       of the recipient domain's public MX.  Empty host => disabled (current
       direct-MX behavior). */
    char       *internal_relay_host;  /* internal relay host ("" => disabled)  */
    uint16_t    internal_relay_port;  /* internal relay port (default 2525)    */
    char       *internal_relay_tls;   /* "none" | "starttls" | "implicit"      */
    char       *internal_relay_user;  /* AUTH PLAIN username ("" => no auth)   */
    char       *internal_relay_pass;  /* AUTH PLAIN password                   */
    char      **internal_domains;     /* internal-routing set (NULL/empty =>   */
    size_t      ninternal_domains;    /*   default to the served `domains`)    */
} OutboxConfig;

/* ------------------------------------------------------------------ */
/* Credentials + lockout                                               */
/* ------------------------------------------------------------------ */

typedef struct {
    char *user;   /* owned */
    char *pass;   /* owned */
} OutboxCred;

typedef struct {
    OutboxCred *creds;
    size_t      ncreds;
} OutboxAuth;

typedef struct {
    unsigned char ip[16];
    uint8_t       len;
    uint32_t      count;
    time_t        first_fail;
    time_t        lock_until;
} OutboxFail;

/* ------------------------------------------------------------------ */
/* Session state                                                       */
/* ------------------------------------------------------------------ */

enum { OB_ST_INIT = 0, OB_ST_HELO, OB_ST_MAIL, OB_ST_DATA };

/* AUTH LOGIN challenge progression. */
enum { OB_AUTH_NONE = 0, OB_AUTH_PLAIN, OB_AUTH_LOGIN_USER, OB_AUTH_LOGIN_PASS };

typedef struct OutboxConn {
    int    fd;
    bool   closed;            /* close once the output buffer drains  */
    bool   implicit_tls;      /* accepted on the :465 SMTPS listener  */
    bool   greeted;           /* the 220 greeting has been sent       */
    bool   authenticated;     /* a successful AUTH completed          */
    char  *auth_user;         /* authenticated username (owned)       */
    char  *pending_user;      /* AUTH LOGIN username so far (owned)   */
    int    state;             /* OB_ST_*                              */
    int    auth_pending;      /* OB_AUTH_* continuation (AUTH PLAIN/LOGIN) */
    char  *from;              /* MAIL FROM path (owned; "" = null)    */
    char **rcpts;             /* accepted RCPT addresses (owned)      */
    size_t nrcpts, rcpt_cap;
    char  *in;                /* command input buffer (owned)         */
    size_t in_len, in_cap;
    char  *data;              /* DATA input buffer (dot-stuffed)      */
    size_t data_len, data_cap;
    size_t data_scan_pos;     /* resumable DATA scan: offset of the last
                                 confirmed line start (see data_scan) */
    char  *out;               /* reply output buffer (owned)          */
    size_t out_len, out_off, out_cap;
    time_t last_act;          /* idle-timeout clock                   */
    unsigned char peer_ip[16];
    uint8_t       peer_ip_len;
    SmtpTls *tls;             /* server TLS state (NULL = plaintext)  */
} OutboxConn;

/* One queued outbound message: the DKIM-signed bytes + its envelope, owned by
 * the delivery queue.  Built by the poll thread at DATA completion and drained
 * by the single delivery worker thread (outbox_deliver.c).  A TEMPFAILing job
 * is re-appended with a due-time instead of sleeping in the worker, so one
 * temp-failing recipient cannot hold the single worker (and its remaining
 * recipients) hostage. */
typedef struct OutboxDeliveryJob {
    char  *from;            /* envelope MAIL FROM (owned; "" = null)   */
    char **rcpts;           /* recipient addresses (owned)             */
    size_t nrcpts;
    char  *msg;             /* DKIM-signed message bytes (owned)       */
    size_t msglen;
    time_t due;             /* worker delivers only when now >= due    */
    uint32_t attempt;       /* current per-recipient attempt (1-based) */
    unsigned char *rcpt_done; /* per-recipient terminal mark (owned)   */
    struct OutboxDeliveryJob *next;
} OutboxDeliveryJob;

typedef struct {
    pthread_mutex_t lock;
    pthread_cond_t  cond;
    OutboxDeliveryJob *head;
    OutboxDeliveryJob *tail;
    bool shutdown;          /* producer closed: worker drains then exits */
    size_t njobs;           /* queued jobs (under lock)                  */
    size_t bytes;           /* summed msglen of queued jobs (under lock) */
    size_t max_jobs;        /* enqueue rejects past this (0 = unlimited) */
    size_t max_bytes;       /* enqueue rejects past this (0 = unlimited) */
} OutboxDeliveryQueue;

typedef struct OutboxServer {
    OutboxConfig cfg;
    OutboxAuth   auth;
    OutboxFail   fails[OUTBOX_AUTH_MAX_TRACKED];
    size_t       nfails;
    int          listen_starttls;   /* :587 */
    int          listen_implicit;   /* :465 */
    OutboxConn **conns;
    size_t       nconns, conn_cap;
    bool         tls_ready;
    Config       deliver_cfg;       /* one-shot config for smtp_out_send_host */
    Config       deliver_cfg_internal; /* one-shot config for the internal relay */
    uint32_t     max_line, max_msg, max_rcpts, cmd_tmo, data_tmo;
    uint64_t     raw_cap;
    OutboxDeliveryQueue delivery;   /* off-thread delivery queue (worker)  */
    pthread_t   delivery_thread;    /* the single delivery worker thread    */
    bool        delivery_started;   /* delivery_thread was created          */
} OutboxServer;

/* ------------------------------------------------------------------ */
/* Entry points                                                        */
/* ------------------------------------------------------------------ */

/* CLI/env + listeners + poll loop (outbox_main.c). */
int outbox_main(int argc, char **argv);

/* Release every heap allocation owned by cfg (outbox_main.c). */
void outbox_config_free(OutboxConfig *cfg);

/* Passwd-file load + constant-time credential check + lockout
   (outbox_auth.c).  Missing passwd file -> empty table, not an error. */
int  outbox_auth_load(const char *path, OutboxAuth *a);
bool outbox_auth_check(const OutboxAuth *a, const char *user, const char *pass);
void outbox_auth_fail(OutboxServer *srv, const unsigned char *ip, uint8_t len,
                      time_t now);
void outbox_auth_clear(OutboxServer *srv, const unsigned char *ip, uint8_t len);
bool outbox_auth_blocked(OutboxServer *srv, const unsigned char *ip,
                         uint8_t len, time_t now);

/* Strict base64 decode (AUTH PLAIN/LOGIN): rejects non-alphabet bytes,
   misplaced '=' padding, and output overflow.  Returns 0 and sets *outlen, or
   -1 (with *outlen 0). */
int outbox_b64_decode(const char *in, size_t inlen, unsigned char *out,
                      size_t outsz, size_t *outlen);

/* Feed readable bytes into the submission state machine (outbox_submit.c). */
void outbox_conn_readable(OutboxServer *srv, OutboxConn *c, time_t now);

/* Conn I/O + lifecycle helpers shared with the poll loop (outbox_submit.c). */
void outbox_conn_reply(OutboxConn *c, const char *text);   /* queue + flush */
void outbox_conn_flush(OutboxConn *c);
void outbox_conn_destroy(OutboxConn *c);
void outbox_conn_reset_txn(OutboxConn *c, int state);      /* clear transaction */
int  outbox_conn_add_rcpt(OutboxConn *c, const char *rcpt);
int  outbox_buf_append(char **buf, size_t *len, size_t *cap,
                       const char *src, size_t n);

/* ------------------------------------------------------------------ */
/* Pure helpers (unit-tested by outbox_check.c)                        */
/* ------------------------------------------------------------------ */

/* Case-insensitive membership of `domain` in cfg->domains. */
bool outbox_domain_allowed(const OutboxConfig *cfg, const char *domain);

/* Case-insensitive membership of `domain` in the internal-routing set:
   cfg->internal_domains when configured, else the served cfg->domains. */
bool outbox_domain_internal(const OutboxConfig *cfg, const char *domain);

/* Extract the RFC5322 From: header address's domain from `msg`/`len` into
 * out[0..outsz) (NUL-terminated, lowercased).  The From value may be a bare
 * addr-spec or "Display Name <addr-spec>".  Returns 0 on success, -1 if there
 * is no From header, no parseable address, or out is too small. */
int outbox_from_header_domain(const char *msg, size_t len, char *out,
                              size_t outsz);

/* Find the DKIM key file for `domain` (case-insensitive) in cfg->dkim.
 * Returns the key path, or NULL when the domain has no configured key. */
const char *outbox_dkim_key(const OutboxConfig *cfg, const char *domain);

/* Extract the lowercased domain of an addr-spec ("local@domain" or
 * "<local@domain>", whitespace tolerated).  Returns 0, or -1 on a parse
 * failure.  Shared by the submission state machine and the delivery worker. */
int outbox_addr_domain(const char *addr, char *out, size_t outsz);

/* ------------------------------------------------------------------ */
/* Off-thread delivery queue (outbox_deliver.c)                        */
/* ------------------------------------------------------------------ */

void outbox_delivery_queue_init(OutboxDeliveryQueue *q);
void outbox_delivery_queue_destroy(OutboxDeliveryQueue *q);
/* Copy the envelope + DKIM-signed message into a job and append it.  Returns
 * 0, -1 on OOM/shutdown (nothing enqueued), or -2 when the queue is at its
 * jobs/bytes cap (nothing enqueued; caller replies 4xx).  Never blocks
 * (bounded critical section). */
int  outbox_delivery_enqueue(OutboxDeliveryQueue *q, const char *from,
                             char *const *rcpts, size_t nrcpts,
                             const char *msg, size_t msglen);
/* Tell the worker to finish draining the queue and exit (call before join). */
void outbox_delivery_shutdown(OutboxDeliveryQueue *q);
/* Worker thread entry: arg is the OutboxServer *.  Drains jobs until
 * shutdown && empty, delivering each via the direct-MX path. */
void *outbox_delivery_worker(void *arg);

#endif /* VISAGE_OUTBOX_H */
