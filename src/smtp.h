/* smtp.h — types shared by the inbound (smtp_in.c) and outbound (smtp_out.c)
   SMTP sides: the message envelope, reply-code parsing, the delivery status
   vocabulary, and a bounded base64 encoder used for AUTH PLAIN. */
#ifndef VISAGE_SMTP_H
#define VISAGE_SMTP_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "config.h"
#include "store.h"

/* Maximum length of one SMTP line (command or reply) including its CRLF.
   RFC 5321 §4.5.3.1.4 caps replies at 512 octets; we allow generous headroom
   while staying firmly bounded. */
#define SMTP_MAX_LINE 1000

/* A message envelope: the RFC5321 reverse-path (`from`) and forward-path
   (`to`) plus the raw (pre-dot-stuff) message bytes. All pointers are
   borrowed, not owned, by this struct. */
struct Envelope {
    const char *from;
    const char *to;
    const char *body;
    size_t      bodylen;
};

/* Delivery status vocabulary shared by in/out. Maps onto the SMTP reply
   class (2xx ok, 4xx tempfail, 5xx permfail) plus a transport-level error. */
enum {
    SMTP_OK       = 0,
    SMTP_TEMPFAIL = 1,
    SMTP_PERMFAIL = 2,
    SMTP_ERROR    = 3
};

/* Human-readable name for a status code (never NULL). */
const char *smtp_status_str(int status);

/* Exponential backoff cadence shared by the outbound client's in-attempt
 * retry loop and the durable-queue's across-attempt re-drive: attempt is
 * 1-based -> 1s, 2s, 4s, 8s, 16s, ... doubling, then capped at 1h (3600s).
 * Pure (no sleep). */
uint32_t smtp_backoff_sec(uint32_t attempt);

/* Parse the 3-digit code that begins an SMTP reply line. Returns 0 and stores
   the code in *code on success; -1 if the line is too short or does not begin
   with three ASCII digits. */
int smtp_reply_code(const char *line, int *code);

/* Base64-encode inlen bytes (which may contain NULs) into out, always
   NUL-terminated. Returns 0 and sets *outlen (excluding the NUL) on success;
   -1 if out is too small or an argument is NULL. */
int smtp_b64_encode(const void *in, size_t inlen, char *out, size_t outsz,
                    size_t *outlen);

/* ------------------------------------------------------------------ */
/* Inbound RCPT acceptance (smtp_in.c). Factored as pure functions so  */
/* the routing decision and SIZE parsing can be unit-tested without a  */
/* socket.                                                             */
/* ------------------------------------------------------------------ */

/* Accept/reject decision for one inbound RCPT TO:<rcpt>. */
typedef enum {
    RCPT_OK = 0,        /* accepted */
    RCPT_BAD_DOMAIN,    /* domain not in Config.domains -> 550 5.1.1 */
    RCPT_NOROUTE,       /* no exact alias / catch-all / reply-token -> 550 5.1.1 */
    RCPT_ERR            /* store/alloc failure -> 451 4.3.0 */
} RcptDecision;

/* Decide whether an inbound recipient is deliverable: its domain must be
 * served (Config.domains) AND it must resolve to a reply-token, an exact
 * alias, or the catch-all. Pure — touches only the store, no sockets. */
RcptDecision smtp_in_rcpt_ok(Store *s, const Config *cfg, const char *rcpt);

/* Parse the optional "SIZE=n" parameter out of a MAIL FROM argument tail
 * (space-separated key=value tokens). Returns 0 on success; sets *present and
 * *size when a SIZE token is found (leaving *size untouched when absent).
 * Returns -1 on a malformed or overflowing SIZE value. */
int smtp_in_parse_size(const char *params, uint64_t *size, bool *present);

/* ------------------------------------------------------------------ */
/* Inbound STARTTLS (smtp_in_tls.c; mbedTLS SERVER role over the       */
/* non-blocking conn fds).  The entry points live only in binaries     */
/* linked with src/smtp_in_tls.c + the vendored mbedTLS objects        */
/* (config_check.com stays mbedtls-free).                              */
/* ------------------------------------------------------------------ */

typedef struct SmtpTls SmtpTls;

/* Load cert/key into the process-wide server config.  Both NULL or both ""
   mean TLS disabled (returns 0); exactly one path, a parse failure, or a
   cert/key mismatch prints an error and returns -1 (fail-closed: the caller
   must exit before binding any listener). */
int  smtp_in_tls_global_init(const char *cert, const char *key);

/* Begin STARTTLS on fd: allocates the per-conn context in the PENDING state
   (the queued plaintext 220 reply drains first).  Returns NULL on allocation
   or setup failure (the plaintext conn is preserved). */
SmtpTls *smtp_in_tls_start(int fd);

/* Drive one handshake round.  Returns 1 established, 0 still negotiating
   (poll POLLIN or POLLOUT per smtp_in_tls_wants_write), -1 fatal (the wire is
   mid-TLS: the caller must drop the conn WITHOUT queueing any reply).
   PENDING -> HANDSHAKE advance requires the conn's out buffer to be drained. */
int  smtp_in_tls_handshake_step(SmtpTls *t);

/* Decrypted read: >0 n bytes, 0 no data right now (WANT_*), -1 fatal or the
   peer closed (caller drops the conn). */
int  smtp_in_tls_recv(SmtpTls *t, char *buf, size_t len);

/* Encrypted write: >0 n plaintext bytes accepted, 0 socket would block
   (retry on POLLOUT), -1 fatal. */
int  smtp_in_tls_send(SmtpTls *t, const char *buf, size_t len);

/* Best-effort close_notify + free (the fd is closed by the caller, and MUST
   still be open here so close_notify can flush). */
void smtp_in_tls_conn_free(SmtpTls *t);

bool smtp_in_tls_available(void);                  /* cert+key loaded       */
bool smtp_in_tls_pending(const SmtpTls *t);        /* plaintext reply draining */
bool smtp_in_tls_handshaking(const SmtpTls *t);    /* PENDING or HANDSHAKE  */
bool smtp_in_tls_established(const SmtpTls *t);    /* TLS active: speak TLS */
bool smtp_in_tls_wants_write(const SmtpTls *t);    /* handshake wants POLLOUT */

/* ------------------------------------------------------------------ */
/* Outbound relay STARTTLS helpers (smtp_out.c).                       */
/* ------------------------------------------------------------------ */

/* Validate relay.tls ∈ {"none", "starttls", "starttls-verify"}.  Returns 0 if
   valid, -1 if the value is missing or not a supported TLS mode.  Pure. */
int smtp_tls_valid(const char *tls);

/* Does the multi-line SMTP reply advertise capability `cap`?  `reply` is the
   raw reply text (each line begins with a 3-digit code + ' ' or '-' and is
   '\n'- or '\r'-terminated).  Match is a case-insensitive comparison against
   the whitespace-delimited keywords that follow the "ddd " / "ddd-" prefix of
   each line.  Pure — no I/O. */
bool smtp_reply_has_cap(const char *reply, size_t len, const char *cap);

/* Classify an AUTH PLAIN final reply code: 235 -> SMTP_OK, 4xx ->
   SMTP_TEMPFAIL, 5xx (incl 535/534) -> SMTP_PERMFAIL, anything else ->
   SMTP_ERROR.  Pure — no I/O. */
int smtp_auth_class(int code);

#endif /* VISAGE_SMTP_H */
