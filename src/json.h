/* json.h — minimal JSON helpers for the admin HTTP API (slice S7).
 *
 * No external library: a tiny object/array builder writing into a heap buffer
 * and a request-body parser that extracts the string value of a named key.
 * Just enough for the admin endpoints (`/health`, `/log`, `/alias`). */
#ifndef VISAGE_JSON_H
#define VISAGE_JSON_H

#include <stddef.h>
#include <stdint.h>

/* Escape `s` (len bytes, which may include NULs) as a JSON string body (no
 * surrounding quotes) into out[0..outsz).  Always NUL-terminates.  Returns 0
 * on success, -1 if out is too small or an argument is NULL. */
int json_escape(const char *s, size_t len, char *out, size_t outsz);

/* A tiny JSON object/array builder into a heap buffer.  Errors are sticky in
 * b->err; check jsonb_detach's return. */
typedef struct {
    char   *buf;
    size_t  len;
    size_t  cap;
    int     err;
} JsonBuilder;

void   jsonb_init(JsonBuilder *b);
int    jsonb_begin_object(JsonBuilder *b);
int    jsonb_end_object(JsonBuilder *b);
int    jsonb_begin_array(JsonBuilder *b);
int    jsonb_end_array(JsonBuilder *b);
int    jsonb_key(JsonBuilder *b, const char *key);
int    jsonb_str(JsonBuilder *b, const char *val);   /* escaped + quoted */
int    jsonb_u32(JsonBuilder *b, uint32_t v);
int    jsonb_bool(JsonBuilder *b, int v);
int    jsonb_comma(JsonBuilder *b);
/* Detach the NUL-terminated buffer (caller frees); sets *len_out.  Returns
 * NULL (and a zeroed builder) on error. */
char  *jsonb_detach(JsonBuilder *b, size_t *len_out);

/* Parse a top-level JSON object string and extract the string value of `key`
 * into out[0..outsz), unescaping JSON escapes.  Returns 0 on success, -1 if
 * the key is absent, the value is not a string, or the buffer is too small. */
int json_obj_get_str(const char *json, const char *key, char *out, size_t outsz);

/* Parse a top-level JSON object string and extract the unsigned 32-bit number
 * value of `key` into *out.  Returns 0 on success, -1 if the key is absent, the
 * value is not a non-negative decimal number, or the number overflows uint32. */
int json_obj_get_u32(const char *json, const char *key, uint32_t *out);

#endif /* VISAGE_JSON_H */
