/* jmap_json.h — bounded JSON parser for jmapd (RFC 8259 subset JMAP needs).
 *
 * src/json.c is a *writer* plus a flat key-extraction reader: it cannot see
 * arrays, nesting or types, so it cannot read a JMAP request (methodCalls is an
 * array of arrays of mixed types).  This is a separate, bounded, recursive
 * parser producing a slice DOM:
 *
 *   - every node lives in a chunked node arena owned by the document, so
 *     sibling/child pointers survive growth (no realloc-invalidated pointers);
 *   - a string with no escapes POINTS INTO THE CALLER'S BUFFER (no copy); a
 *     string with escapes is decoded into the document's string arena.  The
 *     caller's buffer must therefore outlive the document;
 *   - nesting is capped at JMAP_JSON_MAX_DEPTH, strings are bounded by the
 *     document length, and every step is checked: a hostile body yields a typed
 *     error, never a crash and never an unbounded allocation.
 *
 * The whole-document cap is the request cap (JmapdConfig.max_req), enforced by
 * the HTTP layer before the parser runs. */
#ifndef VISAGE_JMAP_JSON_H
#define VISAGE_JMAP_JSON_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/* Nesting cap.  A JMAP request nests methodCalls -> args -> filter -> ... and
   nothing legitimate goes deeper than a handful of levels; 32 leaves room for
   Email/set patch objects without giving a 4 MiB body a 4-million-deep tree. */
#define JMAP_JSON_MAX_DEPTH 32

typedef enum {
    JMAP_JSON_NULL = 0,
    JMAP_JSON_BOOL,
    JMAP_JSON_NUM,
    JMAP_JSON_STR,
    JMAP_JSON_ARR,
    JMAP_JSON_OBJ
} JmapJsonType;

/* Typed parse errors: the caller must be able to tell a truncated body from a
   hostile one (both are 400s, but only one is worth a log line). */
typedef enum {
    JMAP_JSON_OK = 0,
    JMAP_JSON_E_SYNTAX,     /* not JSON */
    JMAP_JSON_E_DEPTH,      /* deeper than JMAP_JSON_MAX_DEPTH */
    JMAP_JSON_E_STRING,     /* unterminated string, bad escape, raw control */
    JMAP_JSON_E_SURROGATE,  /* lone / truncated \uD800-\uDFFF */
    JMAP_JSON_E_UTF8,       /* invalid UTF-8 byte sequence */
    JMAP_JSON_E_NUMBER,     /* malformed or over-long number */
    JMAP_JSON_E_TRAILING,   /* non-whitespace after the top-level value */
    JMAP_JSON_E_NOMEM
} JmapJsonErr;

/* One DOM node.  `child` is the first array element / object member and `next`
   its sibling, so a container's members form a singly linked list. */
typedef struct JmapJsonNode {
    JmapJsonType type;
    const char  *key;       /* object member name (NULL outside an object) */
    size_t       keylen;
    const char  *str;       /* JMAP_JSON_STR: decoded UTF-8 (not NUL-terminated) */
    size_t       slen;
    double       num;       /* JMAP_JSON_NUM */
    int64_t      inum;      /* JMAP_JSON_NUM when is_int */
    bool         is_int;    /* the literal had no '.' / exponent and fit int64 */
    bool         boolean;   /* JMAP_JSON_BOOL */
    struct JmapJsonNode *child;
    struct JmapJsonNode *next;
} JmapJsonNode;

typedef struct JmapJsonDoc JmapJsonDoc;

/* Parse exactly one JSON value spanning buf[0..len).  Trailing whitespace is
   allowed, any other trailing byte is JMAP_JSON_E_TRAILING.  Returns NULL on
   error with *err set (JMAP_JSON_E_NOMEM when *err is left untouched). */
JmapJsonDoc *jmap_json_parse(const char *buf, size_t len, JmapJsonErr *err);

const JmapJsonNode *jmap_json_root(const JmapJsonDoc *doc);
void jmap_json_free(JmapJsonDoc *doc);

/* Object member lookup: the first member named `key`, or NULL. */
const JmapJsonNode *jmap_json_get(const JmapJsonNode *obj, const char *key);

/* Member/element count of an object or array (0 for any other type). */
size_t jmap_json_count(const JmapJsonNode *n);

/* The i-th array element / object member, or NULL when out of range. */
const JmapJsonNode *jmap_json_at(const JmapJsonNode *arr, size_t i);

/* Scalar accessors.  Each returns 0 on success, -1 when n is NULL or has
   another type.  jmap_json_u64 rejects negatives and non-integers. */
int jmap_json_str(const JmapJsonNode *n, const char **s, size_t *slen);
int jmap_json_u64(const JmapJsonNode *n, uint64_t *out);
int jmap_json_bool(const JmapJsonNode *n, bool *out);

const char *jmap_json_err_str(JmapJsonErr e);

#endif /* VISAGE_JMAP_JSON_H */
