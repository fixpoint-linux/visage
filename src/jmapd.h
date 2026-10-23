/* jmapd.h — companion JMAP server (jmapd) for the visage mail stack.
 *
 * jmapd is to JMAP (RFC 8620 / 8621) what imapd is to IMAP: a single-process,
 * poll()-based daemon serving the SAME maildir root and the SAME
 * <root>/imapd.passwd as imapd, with the same bounded-buffer discipline and the
 * same "no Dhall, no datalog" link budget.  It is HTTPS from the first byte
 * (imapd_tls.c, mbedTLS SERVER role) when --cert/--key are configured, and
 * plaintext HTTP on a loopback bind when they are not (the mail-hub client's
 * loopback_dev mode).
 *
 * The daemon reuses imapd's building blocks rather than re-implementing them:
 *   Conn / ImapdServer        imapd.h      per-conn buffers + creds + lockout
 *   imapd_auth_*              imap_maildir.c  passwd table, constant-time
 *                                             compare, per-IP lockout
 *   imapd_mbox_*              imap_maildir.c  maildir scan/uidlist/counts
 *   imapd_tls_*               imapd_tls.c  server TLS over a non-blocking fd
 *   http_parse.c primitives   header-end / header-value / case-insensitive eq
 *   json.c                    JsonBuilder for every response body
 *
 * This header carries the limits, the config, the per-connection/server state,
 * and the pure helper declarations that src/jmap_check.c unit-tests without
 * sockets.  The wire details of each layer live in their own headers:
 * jmap_json.h (parser), and the .c files for HTTP, core, mail. */
#ifndef VISAGE_JMAPD_H
#define VISAGE_JMAPD_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>

#include "imapd.h"
#include "json.h"
#include "jmap_json.h"
#include "jmap_mime.h"

/* ------------------------------------------------------------------ */
/* Limits                                                             */
/* ------------------------------------------------------------------ */

#define JMAPD_MAX_CONNS           512
#define JMAPD_MAX_CONNS_PER_IP    16
/* Pending response backlog per connection; above half of this the poll loop
   stops reading (mirrors imapd.c's IMAPD_MAX_OUT/2 backpressure). */
#define JMAPD_MAX_OUT             (256u * 1024u)
#define JMAPD_RECV_CHUNK          4096
#define JMAPD_LISTEN_BACKLOG      128
/* Request cap (headers + body) and response cap.  A JMAP Email/set draft is
   routinely larger than http_parse.c's 64 KiB admin cap, so the request cap is
   configurable and defaults to 4 MiB; the response cap bounds one reply. */
#define JMAPD_DEFAULT_MAX_REQ     (4u * 1024u * 1024u)
#define JMAPD_MAX_RESP            (16u * 1024u * 1024u)
/* Keep-alive: bound the number of requests one connection may carry. */
#define JMAPD_MAX_REQS_PER_CONN   100
/* Request-shape caps advertised in the session document and enforced on the
   way in (RFC 8620 3.6.2 "limit"). */
#define JMAPD_MAX_CALLS           32
#define JMAPD_MAX_OBJECTS         256
#define JMAPD_MAX_CAPS            8
/* Header block cap: bounds the per-event header re-scan, so a 4 MiB body
   arriving in 4 KiB chunks cannot make the parser quadratic. */
#define JMAPD_MAX_HDR             (16u * 1024u)
/* Query bounds.  total is always exact; `ids` is capped (a client pages with
   position), and the `text` filter's raw-byte scan is charged against a
   per-request budget so one query cannot hold the poll loop for a minute. */
#define JMAPD_QUERY_DEFAULT_LIMIT 256
#define JMAPD_TEXT_SCAN_MAX       (128u * 1024u * 1024u)
/* Hard cap on one streamed blob (decoded bytes).  A message is already capped
   by IMAPD_DEFAULT_MAX_MSG; this bounds the SERVED part independently. */
#define JMAPD_MAX_BLOB_BYTES      (64u * 1024u * 1024u)
/* Thread ids are "t" + base64url(root Message-ID).  The key is capped so the
   encoded id always fits JMAPD_ID_MAX (4/3 * 360 + 1 + NUL < 512). */
#define JMAPD_THREAD_KEY_MAX      360
/* Email/set bounds: a create's built message may not exceed the server's
   max message size, and one call may not touch more objects than a get. */
#define JMAPD_MAX_SET             JMAPD_MAX_OBJECTS
/* Cap on the advertised base URL (--public-url).  The session document joins
   a suffix of at most ~52 bytes onto it, so this stays well inside the 512-byte
   base buffer jmapd_session_render uses. */
#define JMAPD_PUBLIC_URL_MAX      384
#define JMAPD_DEFAULT_TMO         300      /* idle timeout, seconds */
#define JMAPD_DEFAULT_PORT        8081     /* next to visage's admin :8080 */
#define JMAPD_DEFAULT_HOSTNAME    "localhost"
#define JMAPD_DEFAULT_OUTBOX_HOST "127.0.0.1"
#define JMAPD_DEFAULT_OUTBOX_PORT 465      /* outbox.com (M4 submission) */

/* The JMAP capabilities this daemon speaks.  `submission` is advertised
   because the mail-hub client sends it in `using` on EVERY request
   (jmap.zig default_using) and because EmailSubmission/set exists (M4). */
#define JMAPD_CAP_CORE  "urn:ietf:params:jmap:core"
#define JMAPD_CAP_MAIL  "urn:ietf:params:jmap:mail"
#define JMAPD_CAP_SUB   "urn:ietf:params:jmap:submission"

/* Submission bounds (M4).  One worker thread drains a bounded queue; the poll
   loop only appends to it, so a slow or hung relay can never wedge the
   daemon's event loop.  Recipients are capped per submission because the
   envelope is built in fixed buffers (RFC 8621 7.5's rcptTo list). */
#define JMAPD_SUBMIT_MAX_RCPT     16
#define JMAPD_SUBMIT_QUEUE_JOBS   8
#define JMAPD_SUBMIT_QUEUE_BYTES  (8u * 1024u * 1024u)
#define JMAPD_SUBMIT_DEFAULT_WAIT 5000   /* ms to wait for the outcome */
/* Submitted-email ledger: the ids this account has already handed to the
   outbox.  Bounded (oldest dropped), so a long-lived account cannot grow it
   without limit; it is what makes a second submission of the same Email a
   refusal instead of a duplicate send. */
#define JMAPD_LEDGER_MAX          4096
#define JMAPD_LEDGER_FILE         "jmapd-submitted"

/* ------------------------------------------------------------------ */
/* Configuration (CLI flags + JMAPD_* env, no Dhall on purpose)        */
/* ------------------------------------------------------------------ */

typedef struct JmapdConfig {
    const char *root;         /* maildir root (JMAPD_ROOT)            */
    const char *addr;         /* bind address (JMAPD_ADDR)            */
    uint16_t    port;         /* bind port (JMAPD_PORT)               */
    const char *cert;         /* TLS certificate PEM (JMAPD_CERT)     */
    const char *key;          /* TLS private key PEM (JMAPD_KEY)      */
    const char *hostname;     /* name used in advertised URLs         */
    const char *public_url;   /* advertised base URL override
                                 (JMAPD_PUBLIC_URL, "" = derive)      */
    uint32_t    max_req;      /* request cap in bytes (JMAPD_MAX_REQ) */
    const char *outbox_host;  /* submission relay (JMAPD_OUTBOX_HOST) */
    uint16_t    outbox_port;
    const char *outbox_user;  /* submission AUTH PLAIN user (may be "") */
    const char *outbox_pass;  /* submission AUTH PLAIN password        */
    const char *outbox_tls;   /* "implicit" (default) or "none"        */
    const char *identity;     /* own address (JMAPD_IDENTITY, "" = derive) */
    uint32_t    submit_wait;  /* ms to wait for a submission's outcome */
    uint32_t    cmd_tmo;      /* idle timeout, seconds                */
} JmapdConfig;

/* ------------------------------------------------------------------ */
/* HTTP/1.1 request (pure parse result; see jmapd_http.c)              */
/* ------------------------------------------------------------------ */

enum { JMAPD_M_GET = 0, JMAPD_M_POST, JMAPD_M_OTHER };

typedef struct JmapdHttpReq {
    int         method;        /* JMAPD_M_* */
    const char *method_raw;    /* points into the request buffer */
    size_t      method_len;
    const char *path;          /* request target, no query string */
    size_t      path_len;
    int         minor;         /* HTTP/1.minor (0 or 1) */
    size_t      header_end;    /* bytes through the blank line */
    size_t      body_len;      /* Content-Length (0 when absent) */
    char        auth[512];     /* Authorization value ("" when absent) */
    size_t      auth_len;
    bool        keep_alive;    /* may this connection serve another request */
    bool        chunked;       /* Transfer-Encoding: chunked -> 501 */
    bool        has_cl;        /* Content-Length present and valid */
} JmapdHttpReq;

/* Parse one buffered request.  Returns:
 *    1  a complete request (headers + body) is present in buf[0..len)
 *    0  more bytes are needed (the caller keeps buffering)
 *   >1  the HTTP status to answer with, then close (400/411/413/431/501)
 * A verdict of 1 with `body_len` bytes means buf[header_end..header_end+
 * body_len) is the body and nothing else follows in this request. */
int jmapd_http_req_parse(const char *buf, size_t len, size_t cap,
                         JmapdHttpReq *req);

/* Reason phrase for a status (never NULL). */
const char *jmapd_http_status_text(int status);

/* Append a complete response (status line + headers + body) to c->out.  The
   caller flushes.  Returns 0, or -1 on allocation failure. */
int jmapd_http_respond(Conn *c, int status, const char *ctype,
                       const char *body, size_t bodylen, bool keep_alive);

/* Response HEAD only, with an explicit Content-Length and an optional
   Content-Disposition, for a body the caller streams afterwards (the blob
   download).  The body bytes must be appended to c->out by the caller, and
   must total exactly content_length. */
int jmapd_http_respond_head(Conn *c, int status, const char *ctype,
                            const char *disposition, size_t content_length,
                            bool keep_alive);

/* ------------------------------------------------------------------ */
/* Server + connection state                                          */
/* ------------------------------------------------------------------ */

/* A jmapd connection is an imapd Conn (so imapd_tls.c and the buffer helpers
   apply unchanged) with the HTTP layer's per-connection cursor appended.
   Conn is the FIRST member: a JmapdConn* is also a valid Conn* (the TLS layer
   stores the Conn* it is handed), which is the whole point of the layout. */
typedef struct JmapdBlob JmapdBlob;   /* opaque: src/jmap_mail.c (download) */

typedef struct JmapdConn {
    Conn     c;              /* c.user is the user THIS request proved, not a
                                session: it is freed and re-resolved by
                                jmapd_core_auth on every request */
    JmapdBlob *blob;        /* active streamed download (NULL when idle) */
    size_t   hdr_scanned;   /* bytes already scanned for the header end */
    size_t   header_end;    /* 0 until the header block is complete */
    size_t   body_len;      /* Content-Length of the request being read */
    bool     hdr_parsed;    /* header_end/body_len are valid */
    uint32_t nreq;          /* requests served on this connection */
} JmapdConn;

typedef struct JmapdServer {
    ImapdConfig  icfg;      /* root/cert/key/hostname for the imapd helpers */
    JmapdConfig  cfg;
    ImapdServer  auth;      /* creds table + per-IP lockout (imapd_auth_*) */
    int          listen_fd;
    JmapdConn  **conns;
    size_t       nconns, conn_cap;
    uint32_t     next_conn_id;
    bool         tls_ready;
    bool         loopback;  /* bound to a loopback address */
    struct JmapdSubmit *submit;  /* the outbox worker (src/jmapd_submit.c) */
} JmapdServer;

/* ------------------------------------------------------------------ */
/* Pure helpers (unit-tested by src/jmap_check.c)                      */
/* ------------------------------------------------------------------ */

/* ---- id codec ---------------------------------------------------- */

/* Mailbox ids are "m" + base64url(maildir name); Email ids are "e" +
   base64url(maildir base name), with an optional ".base64url(mailbox)" suffix
   for the duplicate-base case (see the plan's DECISIONS 3).  Both decoders are
   strict: wrong prefix, a non-base64url byte, an empty or oversized payload,
   and any decoded '/' / '\\' / ".." / control byte are rejected BEFORE the
   value can reach a path.  Round-trip is exact for every name imapd accepts. */
#define JMAPD_ID_MAX 512

int jmapd_b64url_encode(const unsigned char *in, size_t inlen, char *out,
                        size_t outsz);
int jmapd_b64url_decode(const char *in, size_t inlen, unsigned char *out,
                        size_t outsz, size_t *outlen);

int jmapd_id_mailbox(const char *name, char *out, size_t outsz);
int jmapd_id_mailbox_parse(const char *id, char *name, size_t namesz);

int jmapd_id_email(const char *base, const char *mbox, char *out, size_t outsz);
/* mbox is "" when the id carries no duplicate-disambiguation suffix. */
int jmapd_id_email_parse(const char *id, char *base, size_t basesz,
                         char *mbox, size_t mboxsz);

/* ---- session document -------------------------------------------- */

/* Verdicts from the --public-url validators.  Everything but OK is a startup
   refusal: the session document is what a client follows, so a base URL that
   cannot be advertised must never be half-advertised. */
enum {
    JMAPD_PUB_OK = 0,
    JMAPD_PUB_ERR_SCHEME,     /* not http:// or https://              */
    JMAPD_PUB_ERR_HOST,       /* no host between the scheme and path  */
    JMAPD_PUB_ERR_USERINFO,   /* user[:pass]@host                     */
    JMAPD_PUB_ERR_QUERY,      /* '?' or '#'                           */
    JMAPD_PUB_ERR_CHAR,       /* not printable ASCII, or a space      */
    JMAPD_PUB_ERR_LONG,       /* does not fit JMAPD_PUBLIC_URL_MAX    */
    JMAPD_PUB_ERR_PLAINTEXT   /* http:// on a non-loopback bind       */
};

/* Normalize an advertised base URL: syntax only.  Accepts an optional path
   suffix (preserved, e.g. "https://host/jmap"), strips trailing '/', and
   writes the result to *out.  An empty/NULL url is not an error — it means
   "no override" and yields "".  Returns JMAPD_PUB_OK or a refusal reason. */
int jmapd_public_url_normalize(const char *url, char *out, size_t outsz);

/* Normalize AND apply the deployment policy for this listener: a plaintext
   http:// base URL is allowed only when the bind address is loopback, the same
   rule the plaintext listener itself is held to (the client would otherwise be
   told to send the password in clear across a network).  `bind_addr` is the
   configured --addr. */
int jmapd_public_url_check(const char *url, const char *bind_addr, char *out,
                           size_t outsz);

/* Human-readable reason for a validator verdict (never NULL). */
const char *jmapd_public_url_reason(int why);

/* Render the JMAP session resource (RFC 8620 2) for `account_id`.  Every
   advertised URL is absolute and shares one base: the --public-url override
   verbatim when set (behind a TLS-terminating reverse proxy the listener's own
   scheme/port are the wrong thing to advertise), else the scheme the listener
   actually speaks — https when TLS is configured, http otherwise — plus
   --hostname and --port.  Heap-allocates *out (NUL-terminated); *outlen
   excludes the NUL.  Returns 0, or -1 on OOM or an unadvertisable override. */
int jmapd_session_render(const JmapdConfig *cfg, const char *account_id,
                         char **out, size_t *outlen);

/* ---- auth -------------------------------------------------------- */

enum { JMAPD_AUTH_NONE = 0, JMAPD_AUTH_BASIC, JMAPD_AUTH_BEARER };

/* Parse an Authorization header value.  Basic yields user+pass; Bearer yields
   the token in pass and an empty user (the account is resolved by matching the
   token against the passwd table).  Returns 0, or -1 when the header is
   malformed, the base64 does not decode, or the fields do not fit. */
int jmapd_auth_parse(const char *v, size_t vlen, int *scheme, char *user,
                     size_t usersz, char *pass, size_t passsz);

/* ---- state strings ----------------------------------------------- */

/* JMAP state strings are opaque to clients: "<type><counter>", e.g. "e12".
   The counters are persisted per account in <root>/<user>/jmapd-state and are
   bumped by jmapd's own commits AND whenever a request observes that the
   maildir fingerprint moved (an imapd delivery, a flag change, a delete), so
   a client that holds an old state is never told nothing happened. */
int jmapd_state_fmt(char type, uint64_t n, char *out, size_t outsz);

/* Per-account counters + the maildir fingerprint they were last bumped for. */
typedef struct JmapdState {
    uint64_t email;
    uint64_t mailbox;
    uint64_t thread;
    uint64_t submission;
    uint64_t fp;         /* fingerprint as of the last bump */
    bool     have_fp;    /* false: nothing observed yet (adopt, do not bump) */
} JmapdState;

/* Bump masks for jmapd_state_bump. */
#define JMAPD_ST_EMAIL    1u
#define JMAPD_ST_MAILBOX  2u
#define JMAPD_ST_THREAD   4u

/* Load the persisted counters.  A missing or unreadable sidecar yields zeros
   with have_fp false (the next sync then adopts the maildir as-is rather than
   bumping on every daemon restart). */
void jmapd_state_load(JmapdServer *srv, const char *user, JmapdState *st);

/* Persist (tmp+rename, 0600).  Best-effort: a read-only root leaves the
   counters in memory for this request and the next request re-derives them. */
int jmapd_state_save(JmapdServer *srv, const char *user, const JmapdState *st);

/* A 64-bit digest of what a JMAP client can observe in the maildir: per
   mailbox the new//cur/ entry counts and the uidlist sidecar's (mtime, size).
   A flag rename or a delivery changes it; nothing else does.  Bounded work:
   one readdir + two stats per mailbox. */
uint64_t jmapd_state_fingerprint(JmapdServer *srv, const char *user);

/* Observe the maildir; bump email/mailbox/thread when the fingerprint moved
   since the last observation, and persist.  Cheap when nothing changed. */
void jmapd_state_sync(JmapdServer *srv, const char *user, JmapdState *st);

/* Bump after a jmapd commit and adopt the POST-write fingerprint, so the next
   sync does not bump a second time for our own change. */
void jmapd_state_bump(JmapdServer *srv, const char *user, JmapdState *st,
                      unsigned types);

/* Loopback bind-address classifier (same rule as imapd_addr_loopback; kept
   local so jmapd does not have to link imapd_imap.c for one predicate). */
bool jmapd_addr_loopback(const char *addr);

/* ---- submission envelope (RFC 8621 7.5) -------------------------- */

/* The SMTP envelope of one submission: the reverse-path plus the deduplicated
   forward-paths.  Pure: src/jmap_check.c renders envelopes from hand-written
   messages without a maildir or a socket. */
typedef struct JmapdEnvelope {
    char   mail_from[256];
    char   rcpt[JMAPD_SUBMIT_MAX_RCPT][256];
    size_t nrcpt;
    bool   overflow;    /* more distinct recipients than the cap: truncated */
} JmapdEnvelope;

/* Render the envelope from the message itself: mailFrom is the first address
   of Sender (else From), replaced by `identity` when it differs (RFC 8621 7.5
   requires the Identity's address when the message's own is not allowed);
   rcptTo is the deduplicated set of To/Cc/Bcc addr-specs.  Returns 0, or -1
   when the message has no usable recipient at all (nothing to send to) or the
   message cannot be read. */
int jmapd_envelope_render(const char *msg, size_t msglen, const char *identity,
                          JmapdEnvelope *out);

/* ------------------------------------------------------------------ */
/* Entry points per module                                            */
/* ------------------------------------------------------------------ */

/* jmapd.c */
void jmapd_log(const JmapdConn *c, const char *event, const char *user,
               const char *detail);

/* jmap_core.c response-builder helpers: json.c's builder has no literal/null
   emitter, and every JMAP object needs one (parentId, role, replyTo, ...). */
void jmapd_jb_lit(JsonBuilder *b, const char *lit);
void jmapd_jb_u64(JsonBuilder *b, uint64_t v);
void jmapd_jb_method_error(JsonBuilder *b, const char *type);

/* jmapd_http.c: buffer bytes into c and dispatch every complete request.
   Appends the response(s) to c->out; sets c->c.closed when the connection
   must go away. */
void jmapd_http_readable(JmapdServer *srv, JmapdConn *c, time_t now);

/* jmap_core.c: authenticate THIS request (Basic/Bearer + per-IP lockout).
   Returns 0 with c->c.user set to the user this request's own header proved,
   or -1 (the caller answers 401).  c->c.user is per REQUEST, never per
   connection: HTTP has no session, and a pooled upstream connection (Caddy)
   can carry a different client's next request.  Exported because the download
   route lives in jmapd_http.c and must not serve a byte before the credential
   is checked. */
int jmapd_core_auth(JmapdServer *srv, JmapdConn *c, const JmapdHttpReq *req);

/* jmap_core.c: route one request.  On success returns 0 and sets *status (200)
   plus the response body (heap, caller frees) and Content-Type via *ctype. */
int jmapd_core_handle(JmapdServer *srv, JmapdConn *c, const JmapdHttpReq *req,
                      const char *body, size_t bodylen, int *status,
                      const char **ctype, char **out, size_t *outlen);

/* ---- #resultOf back-references (RFC 8620 3.7) --------------------- */

/* One earlier call's rendered result, kept for the rest of the request so a
   later call can resolve {"#ids":{"resultOf":"q0","name":"Email/query",
   "path":"/ids"}}.  The client sends exactly that shape: Email/query then
   Email/get with the ids as a back-reference, in ONE request. */
typedef struct JmapdCallResult {
    char        *callid;   /* owned */
    char        *name;     /* owned: the method name */
    char        *json;     /* owned: the rendered result object */
    size_t       json_len;
    JmapJsonDoc *doc;      /* lazily parsed view of json, for resolution */
} JmapdCallResult;

/* Per-call context handed to a method.  `prev` holds the results of the calls
   BEFORE this one, which is all RFC 8620 3.7 allows a reference to name. */
typedef struct JmapdCtx {
    JmapdServer         *srv;
    const char          *user;
    const JmapdCallResult *prev;
    size_t               nprev;
    /* Set by jmapd_arg when a back-reference could not be resolved; the
       method must answer this method-level error instead of its result. */
    const char          *argerr;
} JmapdCtx;

/* Method handlers (jmap_core.c dispatch table).  Each writes the method's
   *result* object into `out` and returns 0, or -1 on allocation failure.  A
   method-level error is a result object of the form {"type":...}. */
typedef int (*JmapdMethodFn)(JmapdCtx *ctx, const JmapJsonNode *args,
                             JsonBuilder *out);

/* Look one argument up, following a "#name" back-reference.  Returns the
   argument node (which may live in an earlier result's document — it is valid
   for the rest of the request), NULL when the argument is absent, or NULL with
   ctx->argerr set to "invalidResultReference" when a reference could not be
   resolved.  Bound: path depth JMAPD_MAX_REF_DEPTH, path length
   JMAPD_MAX_REF_PATH, and only calls earlier in the SAME request. */
#define JMAPD_MAX_REF_DEPTH 8
#define JMAPD_MAX_REF_PATH  256
const JmapJsonNode *jmapd_arg(JmapdCtx *ctx, const JmapJsonNode *args,
                              const char *key);

/* jmap_mail.c */
int jmapd_method_mailbox_get(JmapdCtx *ctx, const JmapJsonNode *args,
                             JsonBuilder *out);
int jmapd_method_identity_get(JmapdCtx *ctx, const JmapJsonNode *args,
                              JsonBuilder *out);
int jmapd_method_email_get(JmapdCtx *ctx, const JmapJsonNode *args,
                           JsonBuilder *out);
int jmapd_method_thread_get(JmapdCtx *ctx, const JmapJsonNode *args,
                            JsonBuilder *out);

/* jmap_query.c */
int jmapd_method_email_query(JmapdCtx *ctx, const JmapJsonNode *args,
                             JsonBuilder *out);

/* Thread id of a message: "t" + base64url(root key), where the root key is the
   first Message-ID in References, else In-Reply-To, else the message's own
   Message-ID, else `fallback` (its uidlist Message-ID or maildir base).  One
   rule for Email/get, Email/set's created answer and Thread/get. */
void jmapd_thread_id_of(const char *msg, size_t msglen, const char *fallback,
                        char *out, size_t outsz);

/* One message as located on disk (jmap_mail.c).  `base` and `mbox` are the
   INPUT to jmapd_email_locate (mbox "" means "search every mailbox");
   everything else is filled in.  `id` is the id the caller asked for, so a
   duplicate-base "f" id round-trips unchanged. */
typedef struct JmapdEmail {
    char     base[IMAPD_MAX_MBOX + 1];   /* in: base name */
    char     mbox[IMAPD_MAX_MBOX + 1];   /* in: hint; out: where it was found */
    char     id[JMAPD_ID_MAX];           /* out: the JMAP id */
    char     path[4096];                 /* out */
    size_t   size;                       /* out: file bytes */
    time_t   internal_date;              /* out */
    uint8_t  flags;                      /* out */
    uint32_t uid;                        /* out */
    char     mid[512];                   /* out: Message-ID header value */
    bool     found;
} JmapdEmail;

/* Locate each entry across the account's mailboxes.  Returns 0 (each entry's
   `found` says whether it was located) or -1 on allocation failure. */
int jmapd_email_locate(JmapdServer *srv, const char *user, JmapdEmail *want,
                       size_t n);

/* Read one message file into a heap buffer, capped by the server's max message
   size (JmapdConfig/ImapdConfig max_msg).  Returns 0 with *out NUL-terminated
   and *outlen set, or -1. */
int jmapd_read_file(JmapdServer *srv, const char *path, size_t size,
                    char **out, size_t *outlen);

/* The account's Identity id ("i" + b64url(user)) and its own address.  The
   address is --identity/JMAPD_IDENTITY when configured, else user@hostname.
   Returns 0, or -1 when the buffer is too small. */
int jmapd_identity_id(const char *user, char *out, size_t outsz);
int jmapd_identity_email(JmapdServer *srv, const char *user, char *out,
                         size_t outsz);

/* RFC 3339 / RFC 8621 UTCDate: "YYYY-MM-DDTHH:MM:SSZ" (the mail-hub client's
   cache parser requires exactly this shape).  Writes "" when the time cannot
   be converted. */
void jmapd_iso8601_utc(time_t t, char *out, size_t outsz);

/* The maildir folder name of a JMAP role ("sent", "drafts", ...), or NULL for
   an unknown role.  The store's names ARE the roles (jmap_mail.c's ROLES), so
   this is the one place that mapping is spelled. */
const char *jmapd_role_mbox(const char *role);

/* Split an address-list header value into deduplicated addr-specs, bounded by
   `max` (returns the count).  Used for the submission envelope; the display
   names are dropped because an SMTP envelope has no place for them. */
size_t jmapd_addr_list(const char *value, char out[][256], size_t max);

/* The first addr-spec of an address-list header value ("" when none).
   Returns 0 when one was found, -1 otherwise. */
int jmapd_first_addr(const char *value, char *out, size_t outsz);

/* jmap_set.c — Email/set (RFC 8621 4.6): update (a JSON-Patch over keywords
   and mailboxIds), create (an RFC 5322 message built from the JMAP body) and
   destroy.  mailboxIds REPLACEMENT is a maildir MOVE, which keeps the Email
   id: imapd_mbox_file renames the file, and the base name — the identity —
   survives a rename, a move and a uidlist rebuild. */
int jmapd_method_email_set(JmapdCtx *ctx, const JmapJsonNode *args,
                           JsonBuilder *out);

/* The patch verdict for one Email update.  Pure: src/jmap_check.c drives the
   whole matrix without a maildir. */
typedef enum {
    JMAPD_PATCH_OK = 0,
    JMAPD_PATCH_E_PATH,    /* a property (or path) Email/set cannot patch */
    JMAPD_PATCH_E_TYPE,    /* a value of the wrong JSON type */
    JMAPD_PATCH_E_EMPTY,   /* mailboxIds would be empty (an Email must be in one) */
    JMAPD_PATCH_E_MULTI,   /* more than one mailbox: this store is one-per-message */
    JMAPD_PATCH_E_KEYWORD  /* a keyword this store cannot represent */
} JmapdPatchErr;

typedef struct JmapdEmailPatch {
    uint8_t flags;                    /* out: the IMAIL_* set after the patch */
    char    mbox[IMAPD_MAX_MBOX + 1]; /* out: the mailbox after the patch */
    bool    mbox_moved;               /* out: mbox differs from the current one */
    char    bad[256];                 /* out: the offending path, for the error */
} JmapdEmailPatch;

/* Apply one RFC 8620 5.3 patch object to an Email's mutable properties.
   Supported paths: "keywords", "keywords/<kw>", "mailboxIds",
   "mailboxIds/<mailboxId>", with ~0/~1 escapes in the segments.  A null (or
   false, for the boolean maps) value removes; anything else on an immutable
   property is JMAPD_PATCH_E_PATH.  Returns JMAPD_PATCH_OK or the first error. */
JmapdPatchErr jmapd_patch_apply(const JmapJsonNode *patch, const char *cur_mbox,
                                uint8_t cur_flags, JmapdEmailPatch *out);

/* Apply one patch to one located Email in the maildir — the WRITE half of
   Email/set's update, exported because RFC 8621 7.5's onSuccessUpdateEmail is
   an implicit Email/set call made from src/jmapd_submit.c.  Returns 0, or -1
   with *err_type set to an RFC 8621 SetError type and err_desc filled in.
   *changed is incremented when the maildir actually moved. */
int jmapd_email_update(JmapdServer *srv, const char *user,
                       const JmapdEmail *loc, const JmapJsonNode *patch,
                       const char **err_type, char *err_desc, size_t descsz,
                       unsigned *changed);

/* jmapd_submit.c — EmailSubmission/set (RFC 8621 7.5): render the envelope,
   hand the message to the single outbox worker, move the submitted Email to
   the Sent mailbox, then apply onSuccessUpdateEmail as an implicit Email/set. */
int jmapd_method_email_submission_set(JmapdCtx *ctx, const JmapJsonNode *args,
                                      JsonBuilder *out);

/* Start the outbox worker thread.  Returns 0, or -1 when the thread cannot be
   created (the caller then refuses to start: a daemon that advertises
   submission and cannot send is worse than one that does not start). */
int jmapd_submit_init(JmapdServer *srv);

/* Drain the queue and join the worker (called on the way out). */
void jmapd_submit_stop(JmapdServer *srv);

/* jmap_state.c — /changes answers the RFC-legal method error
   cannotCalculateChanges (RFC 8620 5.2): this store keeps no per-object change
   log, and claiming diffs it cannot compute is the one failure a client acts
   on.  The mail-hub client treats it as "full refresh" (plan DECISIONS 4). */
int jmapd_method_email_changes(JmapdCtx *ctx, const JmapJsonNode *args,
                               JsonBuilder *out);
int jmapd_method_mailbox_changes(JmapdCtx *ctx, const JmapJsonNode *args,
                                 JsonBuilder *out);
int jmapd_method_thread_changes(JmapdCtx *ctx, const JmapJsonNode *args,
                                JsonBuilder *out);
int jmapd_method_email_query_changes(JmapdCtx *ctx, const JmapJsonNode *args,
                                     JsonBuilder *out);

/* Create the role mailboxes a JMAP account needs (Inbox/.Sent/.Drafts/
   .Trash/.Junk/.Archive) when they are missing.  Idempotent; returns 0 even
   when one could not be created (Mailbox/get then simply reports fewer
   mailboxes), or -1 on allocation failure. */
int jmapd_account_prepare(JmapdServer *srv, const char *user);

/* ------------------------------------------------------------------ */
/* Blob download (RFC 8621 4.1.4: the DECODED bytes of one part)      */
/* ------------------------------------------------------------------ */

/* Resolve a blob id and open its message file.  Returns 0 with *out set, or
   the HTTP status to answer with (404 for an id that does not parse or a
   message that is gone, 413 for a part over JMAPD_MAX_BLOB_BYTES, 500 for an
   I/O failure).  Nothing is opened before the id has been parsed and its
   part resolved, so a malformed or hostile id cannot reach open(2). */
int jmapd_download_open(JmapdServer *srv, const char *user, const char *blob_id,
                        const char *name, JmapdBlob **out);

/* The Content-Type / Content-Disposition of an open blob. */
const char *jmapd_download_ctype(const JmapdBlob *b);
const char *jmapd_download_disposition(const JmapdBlob *b);
size_t jmapd_download_length(const JmapdBlob *b);

/* Append the next decoded chunk to the connection's output (POLLOUT pump,
   modelled on imapd_imap.c's FetchGen stream_lit: pread a chunk, decode it,
   append, repeat until the backlog reaches JMAPD_MAX_OUT/2).  Frees the blob
   and clears c->blob when the body is complete. */
void jmapd_download_pump(JmapdConn *c);
void jmapd_download_free(JmapdConn *c);

#endif /* VISAGE_JMAPD_H */
