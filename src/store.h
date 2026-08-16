/* store.h — datalog-dafsa store wrapper for visage.
 *
 * Thin wrapper over the embedded datalog-dafsa engine (<dl.h>).  The store
 * owns a single-writer dl_db handle and exposes the fixed schema as typed C
 * calls.  The column types are load-bearing — see the int/sym discipline:
 *
 *   relation                       arity   column types
 *   domain(name)                     1     [sym]
 *   alias(domain, local, dest)       3     [sym, sym, sym]  one fact per dest
 *   revmap(token, sender,            4     [sym, sym, sym, raw-u32]
 *          alias_addr, created_ts)
 *   log(msgid, ts, dir,              6     [raw, raw, raw, sym, sym, sym]
 *       local, remote, status)
 *   queue(msgid, k, from, to,        7     [raw, raw, sym, sym, raw, raw, sym]
 *         attempts, next_ts, status)         (msgid,k) is the delivery key
 *   meta(key, val)                   2     [sym, raw-u32]   next_msgid counter
 *
 * Strings are interned sym_ids (1-based) via dl_intern_str and read back with
 * dl_intern_str_of.  Integers are raw u32.  A sym column and an int column
 * share the same u32 namespace but mean different things, so they must NEVER
 * be compared against each other; each column is homogeneous.  Message bodies
 * are spooled to disk by higher layers — they are never interned here.
 */
#ifndef VISAGE_STORE_H
#define VISAGE_STORE_H

#include <stddef.h>
#include <stdint.h>
#include "config.h"

/* Opaque store handle (owns a dl_db + the declared schema). */
typedef struct Store Store;

/* Open (or create) the database directory at `path` and declare the fixed
 * schema.  Auto-creates the directory (single level) and takes a single-writer
 * flock.  Returns NULL on failure (lock contention, I/O error, bad path). */
Store *store_open(const char *path);

/* Close and release the store.  Returns 0 on success. */
int store_close(Store *s);

/* Seed domains + aliases from config at boot.  Idempotent: re-adding an
 * existing domain or alias/dest fact is a no-op.  Returns 0 on success. */
int store_seed_aliases(Store *s, const Config *cfg);

/* Add one alias -> destination mapping (alias = "local@domain").  Idempotent.
 * Returns 0 on success. */
int store_alias_add(Store *s, const char *alias, const char *dest);

/* Remove one alias -> destination mapping.  Returns 0 on success, including
 * the case where the mapping was already absent. */
int store_alias_rm(Store *s, const char *alias, const char *dest);

/* Resolve alias -> destination list.  On success returns 0 and sets *dests to
 * a malloc'd array of malloc'd strings (free with store_free_strvec) and
 * *ndests to its length.  An alias with no destinations returns 0 with
 * *dests == NULL and *ndests == 0. */
int store_resolve(Store *s, const char *alias, char ***dests, size_t *ndests);

/* Record a reply-token reverse mapping (token -> sender, alias_addr).
 * created_ts is set to the current unix time (raw u32).  Returns 0 on success.
 */
int store_revmap_add(Store *s, const char *token, const char *sender,
                     const char *alias_addr);

/* Look up a reply token -> (sender, alias_addr).  On success returns 0 and sets
 * *sender / *alias_addr to malloc'd strings (caller frees with free()).  An
 * unknown token returns 0 with both out-params set to NULL. */
int store_revmap_resolve(Store *s, const char *token, char **sender,
                         char **alias_addr);

/* Allocate the next monotonic message id (1-based, persisted in meta).
 * Returns 0 on error. */
uint32_t store_next_msgid(Store *s);

/* Append one log fact.  msgid/ts/dir are raw u32; local/remote/status are
 * interned strings.  Returns 0 on success. */
int store_log_add(Store *s, uint32_t msgid, uint32_t ts, uint32_t dir,
                  const char *local, const char *remote, const char *status);

/* Number of log facts.  Returns -1 on error. */
long store_log_count(Store *s);

/* A single log entry (one log fact).  Strings are heap-allocated and owned by
 * the array returned from store_log_recent. */
typedef struct {
    uint32_t msgid;
    uint32_t ts;
    uint32_t dir;
    char    *local;
    char    *remote;
    char    *status;
} StoreLogEntry;

/* Return up to `max` most-recent log entries (by msgid, newest last).  On
 * success sets *out to a malloc'd array (free with store_log_entries_free) and
 * *nout to its length; *out may be NULL with *nout == 0 when there are no
 * entries.  Returns 0 on success. */
int store_log_recent(Store *s, size_t max, StoreLogEntry **out, size_t *nout);

/* Free an array returned by store_log_recent (NULL-safe). */
void store_log_entries_free(StoreLogEntry *e, size_t n);

/* --- Durable outbound delivery queue ---------------------------------- */

/* Add one delivery to the queue: status "queued", attempts 0, next_ts 0.
 * (msgid, k) identifies the delivery; k is the per-msgid destination ordinal
 * (0-based).  from/to are the envelope sender and recipient (interned).
 * Returns 0 on success. */
int store_queue_add(Store *s, uint32_t msgid, uint32_t k,
                    const char *from, const char *to);

/* Transition a delivery to a new status/attempts/next_ts via delete+add,
 * preserving from/to.  Returns 0 on success, VISAGE_ESTORE if no such
 * (msgid, k) delivery exists. */
int store_queue_set_status(Store *s, uint32_t msgid, uint32_t k,
                           const char *status, uint32_t attempts,
                           uint32_t next_ts);

/* Full-walk deliveries with status == "queued" and next_ts <= now, invoking
 * cb(msgid, k, from, to, attempts, user) per due tuple.  from/to are interned
 * string pointers valid only for the duration of the callback; cb returns
 * non-zero to stop the walk early.  Returns 0 on success. */
int store_queue_due(Store *s, uint32_t now,
                    int (*cb)(uint32_t msgid, uint32_t k, const char *from,
                              const char *to, uint32_t attempts, void *user),
                    void *user);

/* Number of deliveries currently in the given status.  Returns -1 on error. */
long store_queue_count_by_status(Store *s, const char *status);

/* Recover a delivery left in "delivering" by a crash mid-send: reset it to
 * "queued" with next_ts 0 so the startup re-drive retries it (at-least-once).
 * attempts is preserved.  Returns 0 on success. */
int store_queue_reset_delivering(Store *s);

/* Soonest next_ts among deliveries with status == "queued", or UINT32_MAX if
 * none are queued.  A next_ts of 0 means "due now".  Used by the poll loop to
 * compute the re-drive wakeup deadline.  Never returns a negative value. */
uint32_t store_queue_next_due(Store *s);

/* Free a string vector returned by store_resolve (n == *ndests).  Safe on a
 * NULL vector. */
void store_free_strvec(char **vec, size_t n);

#endif /* VISAGE_STORE_H */
