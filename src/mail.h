/* mail.h — RFC5322 email primitives: strict address parsing, CRLF
   normalization, dot-stuffing/unstuffing, header manipulation, and the
   forward-sanitize pipeline. Pure string/memory handling — no sockets, no
   datalog.

   Lengths are byte counts. Every heap buffer returned through a char** is
   NUL-terminated, and the returned length EXCLUDES the NUL terminator. */
#ifndef VISAGE_MAIL_H
#define VISAGE_MAIL_H

#include <stddef.h>

/* Forward-rewrite parameters for mail_sanitize_for_forward(). Each field is
   a header VALUE (the text after "Name: "); a NULL field means "leave that
   header as found". No field may contain CR or LF — mail_sanitize_for_forward
   rejects such input so header injection stays structurally impossible. */
typedef struct {
    const char *received;     /* value for the prepended "Received:" line */
    const char *return_path;  /* "Return-Path:" value */
    const char *from;         /* "From:" value */
    const char *sender;       /* "Sender:" value */
    const char *reply_to;     /* "Reply-To:" value */
} MailRewrite;

/* Parse an RFC5321 addr-spec, accepting either the bare "local@domain" form or
   the "<local@domain>" path form (surrounding SP/HT whitespace is tolerated).
   The local part may be a dot-atom or a quoted-string ("a b", with \" and \\
   quoted-pair escapes, kept verbatim including the quotes); the domain may be
   a dot-atom or a domain-literal ([127.0.0.1], [IPv6:...], kept verbatim
   including the brackets). Rejects control chars (CR/LF), unbalanced '<'/'>'
   and stray '<'/'>' outside a quoted-string, a missing or extra '@', empty
   local or domain, leading/trailing/doubled dots in a dot-atom, and non-ASCII
   bytes. On success heap-allocates *local and *domain (NUL-terminated) and
   returns 0; on any invalid input returns -1 and leaves *local and *domain
   NULL. */
int mail_addr_parse(const char *s, char **local, char **domain);

/* Normalize line endings to CRLF in place: every bare LF or bare CR becomes
   CRLF; an existing CRLF is left unchanged. Returns the new length, or -1 on
   error. The buffer must have room for the expanded result (worst case
   2 * len bytes). */
int mail_normalize_crlf(char *buf, size_t len);

/* Remove one leading '.' from every dot-stuffed line (inbound DATA de-dot).
   Shrinks in place; *len is updated. Returns 0, or -1 on error. */
int mail_unstuff_dots(char *buf, size_t *len);

/* Nonzero if buf[0..len) contains a NUL byte, a C0 control char other than
   TAB(0x09)/LF(0x0A)/CR(0x0D), or DEL(0x7F).  Bytes 0x80..0xFF are ALLOWED
   (8BITMIME bodies).  Used on the dot-unstuffed message body to REJECT (never
   sanitize) NUL/control bytes before forwarding. */
int mail_data_has_ctl(const char *buf, size_t len);

/* Add one leading '.' to every line that begins with '.' (outbound DATA
   dot-stuff). Heap-allocates *out (NUL-terminated) and sets *outlen (excluding
   the NUL). Returns 0, or -1 on error (with *out left NULL). */
int mail_stuff_dots(const char *in, size_t inlen, char **out, size_t *outlen);

/* Case-insensitive lookup of the first header named `name`; unfolds folded
   continuation lines (leading SP/HT) into single spaces. Writes the
   NUL-terminated value into out[0..outsz). Returns 0 if found, -1 if absent
   or on error. */
int mail_header_get(const char *msg, size_t len, const char *name,
                    char *out, size_t outsz);

/* Replace the first header named `name` with "name: value", or append it to
   the end of the header block if absent. *msg is a heap buffer of *len bytes
   (it may be an empty string). On success the old buffer is freed and
   *msg and *len are updated to the new heap buffer. Rejects names containing
   ':' or CR/LF, and values containing CR/LF. Returns 0, or -1 on error (old
   buffer left untouched). */
int mail_header_set(char **msg, size_t *len, const char *name, const char *value);

/* Remove every header named `name` (case-insensitive) including its folded
   continuation lines. On success the old buffer is freed and *msg and *len
   are updated; if no match is found, *msg and *len are left unchanged.
   Returns 0, or -1 on error. */
int mail_header_remove(char **msg, size_t *len, const char *name);

/* Forward sanitize pipeline: normalize CRLF, rewrite Return-Path/From/Sender/
   Reply-To (per rw), and prepend a "Received:" line. Every other header and
   the body pass through (CRLF-normalized) verbatim. Heap-allocates *out
   (NUL-terminated) and sets *outlen. Returns 0, or -1 on error. */
int mail_sanitize_for_forward(const char *in, size_t inlen,
                              const MailRewrite *rw, char **out, size_t *outlen);

/* Free helpers (both NULL-safe). */
void mail_free(void *p);
void mail_addr_free(char *local, char *domain);

#endif /* VISAGE_MAIL_H */
