/* reply.h — reverse-alias reply routing (slice S6).
 *
 * SimpleLogin-style reverse aliases: when an inbound message is forwarded
 * through an alias, the forwarder mints a token and writes a "reverse alias"
 * (reply+<token>@domain) into the rewritten From/Reply-To.  When the alias
 * owner replies, the reply lands back at that reverse alias, and this module
 * maps the token back to the original sender so the reply can be delivered
 * outbound FROM the alias TO the original sender.
 *
 * Ownership: strings returned through a char** are heap-allocated and owned
 * by the caller (free with reply_free() or free()).  The token helpers write
 * into caller-provided buffers. */
#ifndef VISAGE_REPLY_H
#define VISAGE_REPLY_H

#include <stddef.h>
#include "config.h"
#include "store.h"
#include "mail.h"

/* Generate a 32-char lowercase hex token (16 random bytes) into out[0..outsz).
 * Requires outsz >= 33.  Reads /dev/urandom; on any failure falls back to a
 * PRNG seeded from time + pid + addresses.  The result is never all-zero.
 * Returns 0 (VISAGE_OK) on success, negative on error. */
int reply_token_gen(char *out, size_t outsz);

/* Build the reverse alias "<prefix><sep><token>@<domain>" into out[0..outsz),
 * where prefix/separator come from cfg->reply and domain is the domain part of
 * alias_addr (split at its first '@').  Requires room for the result plus NUL.
 * Returns 0 on success, negative on error. */
int reply_make_reverse(const Config *cfg, const char *token, const char *alias_addr,
                       char *out, size_t outsz);

/* Route an inbound recipient that looks like a reverse alias.  If rcpt parses
 * as "<prefix><sep><token>@<domain>", the token is looked up in the revmap;
 * on a hit *sender_out and *alias_addr_out are set to freshly-malloc'd strings
 * (the stored original sender and the alias address).  Returns:
 *     1   — matched: a reply, outputs set
 *     0   — not a reply (rcpt is not a reverse alias, or token unknown),
 *           outputs left NULL
 *   < 0  — error (bad args, alloc/store failure) */
int reply_route_inbound(Store *s, const Config *cfg, const char *rcpt,
                        char **sender_out, char **alias_addr_out);

/* Heap-build the forward "From:" display string
 *     "<sender> via <alias_addr>" <reverse>
 * into *out (NUL-terminated).  Returns 0 on success, negative on error. */
int reply_from_rewrite(char **out, const char *sender, const char *alias_addr,
                       const char *reverse);

/* Fill a MailRewrite for mail_sanitize_for_forward() given the original sender
 * S and alias address A (with reverse = the reverse alias):
 *     from        = "\"<S> via <A>\" <reverse>"
 *     reply_to    = reverse
 *     return_path = A
 *     sender      = A
 *     received    = NULL (left for the caller)
 * On success returns 0; release the heap strings with reply_rewrite_free(). */
int reply_rewrite_build(const char *sender, const char *alias_addr, const char *reverse,
                        MailRewrite *rw);

/* Free the strings allocated by reply_rewrite_build() (NULL-safe). */
void reply_rewrite_free(MailRewrite *rw);

/* Strip the reverse-alias address from the To: and Cc: headers of *msg (a heap
 * buffer of *len bytes; *msg and *len may be replaced).  A header left with no
 * remaining addresses is removed entirely.  Returns 0, or negative on error. */
int reply_strip_reverse(char **msg, size_t *len, const char *reverse);

/* Free helper (NULL-safe). */
void reply_free(void *p);

#endif /* VISAGE_REPLY_H */
