/* dkim.h — DKIM signing (RFC 6376) for outbound forward copies.
 *
 * Signs a sanitized outbound message with a=rsa-sha256, c=relaxed/relaxed and
 * prepends a "DKIM-Signature: ...\r\n" header.  The canonicalization and
 * signature-input construction are transcribed VERBATIM from the verified
 * prototype tools/dkim_proto.c.  The daemon keys off config_dkim_find(cfg,
 * domain); on any key-load/sign failure the caller forwards the message
 * UNSIGNED (availability over signature — no mail loss).
 *
 * Bytes in / bytes out are byte counts (the message need not be
 * NUL-terminated).  *out is heap-allocated and NUL-terminated; *outlen
 * excludes the NUL. */
#ifndef VISAGE_DKIM_H
#define VISAGE_DKIM_H

#include <stddef.h>

/* Sign `msg` (msglen bytes) as `domain` with `selector` using the PEM RSA
 * private key at `key_path`.  Prepends the DKIM-Signature header and sets
 * *out (heap, NUL-terminated) and *outlen (the combined length).  Returns 0 on
 * success, nonzero on any failure (*out left NULL). */
int dkim_sign(const char *msg, size_t msglen, const char *domain,
              const char *selector, const char *key_path,
              char **out, size_t *outlen);

/* Re-parse the leading DKIM-Signature header of `msg`, recompute the header
 * hash over its h= set, and verify b= against `key_path`.  Returns 0 on a
 * successful verification, nonzero on any parse/verify failure. */
int dkim_verify(const char *msg, size_t len, const char *key_path);

/* --- test-facing canonicalization (used by dkim_check) ------------------- */
/* Relaxed-canonicalize one logical header (hdr[0..len), `colon` = index of
 * ':') with NO trailing CRLF into *out (heap, NUL-terminated; *outlen excludes
 * the NUL).  Returns 0 on success, nonzero on error. */
int dkim_relaxed_header(const char *hdr, size_t len, size_t colon,
                        char **out, size_t *outlen);

/* Relaxed-canonicalize the body `body` (len bytes), SHA-256 it, and base64-encode
 * into bh_b64 (must hold >= 64 bytes; NUL-terminated).  Returns 0 on success,
 * nonzero on error. */
int dkim_relaxed_body_b64(const char *body, size_t len, char bh_b64[64]);

#endif /* VISAGE_DKIM_H */
