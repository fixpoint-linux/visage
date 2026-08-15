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

#endif /* VISAGE_SMTP_H */
