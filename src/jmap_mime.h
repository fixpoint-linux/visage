/* jmap_mime.h — MIME tree, CTE decoding and body assembly for jmapd.
 *
 * The structure itself comes from imapd's walker (imapd_mime_iterate in
 * imap_maildir.c, the same delimiter rule BODY[<section>] uses), so jmapd
 * never disagrees with IMAP about where a part begins.  What is added here is
 * what JMAP needs on top of the bytes:
 *
 *   - an INCREMENTAL content-transfer-encoding decoder (7bit/8bit/binary,
 *     base64, quoted-printable).  ONE decoder serves both the whole-part
 *     bodyValue path and the streamed blob download, so the two can never
 *     disagree about what a part decodes to.  It is checked against imapd's
 *     strict whole-buffer imapd_b64_decode in src/jmap_check.c;
 *   - the part tree (parent/depth/classification) Email/get renders as
 *     textBody, htmlBody, attachments and bodyStructure;
 *   - bodyValue assembly with maxBodyValueBytes/isTruncated/isEncodingProblem.
 *
 * CHARSET IS PASSTHROUGH.  There is no iconv here and no new dependency: the
 * declared charset is reported verbatim in every BodyPart object and the
 * decoded bytes are handed to the client unchanged.  A message in
 * ISO-8859-1 therefore reaches the client as ISO-8859-1 bytes labelled
 * "iso-8859-1"; a UTF-8 client renders it as mojibake unless it transcodes.
 * That is a named, deliberate limitation of v1 (the alternative is an iconv
 * dependency and a per-part transcode failure mode), not an accident.
 */
#ifndef VISAGE_JMAP_MIME_H
#define VISAGE_JMAP_MIME_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include "imapd.h"

/* ------------------------------------------------------------------ */
/* Content-Transfer-Encoding                                           */
/* ------------------------------------------------------------------ */

enum {
    JMAPD_CTE_7BIT = 0,   /* 7bit, 8bit, binary and anything unknown: raw */
    JMAPD_CTE_BASE64,
    JMAPD_CTE_QP
};

/* Map a Content-Transfer-Encoding value (as ImailPart.cte reports it) to a
   decoder kind, or -1 when the token is not one this server can decode.  The
   caller of -1 passes the bytes through unchanged AND reports
   isEncodingProblem, which is the RFC-legal way to say "I cannot decode
   this" rather than handing the client encoded bytes as if they were text. */
int jmapd_cte_kind(const char *cte);

/* Incremental decoder state.  A partial base64 quad or a trailing '=' hex
   pair carries over between feed() calls, so a part can be decoded in
   arbitrarily sized chunks (that is what the download pump relies on). */
typedef struct JmapdDec {
    int      kind;
    unsigned acc;      /* base64 bit accumulator */
    int      bits;     /* bits currently held in acc */
    int      qp;       /* 0 plain, 1 after '=', 2 after '=X', 3 after '=\r' */
    int      qphi;     /* first hex digit of a '=XX' sequence */
    char     qpch;     /* the first hex digit verbatim (re-emitted on error) */
    int      pad;      /* base64: padding seen, encoded data ends */
    bool     bad;      /* malformed input was skipped (isEncodingProblem) */
    bool     eof;      /* finish() already ran */
} JmapdDec;

void jmapd_dec_init(JmapdDec *d, int kind);

/* Decode up to *inlen bytes of in[] into out[0..outsz), setting *inlen to the
   number actually consumed and returning the number of decoded bytes written
   (never more than consumed: every decoder here shrinks).  The caller loops
   while *inlen is short of the input; a full output buffer stops the call
   early rather than overrunning.  Malformed input is skipped and flagged in
   d->bad rather than failing the whole part. */
size_t jmapd_dec_feed(JmapdDec *d, const char *in, size_t *inlen,
                      unsigned char *out, size_t outsz);

/* Flush the final partial sequence (a base64 quad holding 2 or 3 bytes).
   Returns the bytes written. */
size_t jmapd_dec_finish(JmapdDec *d, unsigned char *out, size_t outsz);

/* Decode a whole in-memory body.  Heap-allocates *out (NUL-terminated, so a
   text value is usable as a C string) and sets *outlen (excluding the NUL).
   NUL bytes in the DECODED data are dropped: every consumer downstream
   (jsonb_str, log lines, the client's UTF-8 decoder) treats the value as a C
   string, and a JSON string that the writer truncates at a NUL while
   Content-Length counts the rest is a corrupt response.  Returns 0, or -1 on
   allocation failure. */
int jmapd_decode_all(int kind, const char *in, size_t inlen, char **out,
                     size_t *outlen, bool *bad);

/* ------------------------------------------------------------------ */
/* Part tree                                                           */
/* ------------------------------------------------------------------ */

/* A message with more parts than this is truncated (documented, never a
   crash): the walk stops and the remaining parts are simply absent. */
#define JMAPD_MAX_PARTS 128

typedef struct JmapdPart {
    ImailPart info;      /* id, type/subtype, charset, cte, disp, filename,
                            [start,end), hdr_end, depth, multipart */
    int       parent;    /* index of the enclosing part, -1 for the root */
    int       cte_kind;  /* JMAPD_CTE_* */
    int       body_kind; /* 0 not a body part, 1 text/plain, 2 text/html */
    bool      attachment;/* leaf that is not a selected body part */
} JmapdPart;

typedef struct JmapdTree {
    JmapdPart parts[JMAPD_MAX_PARTS];
    int       nparts;
} JmapdTree;

/* Build the tree from a complete message.  Returns 0 (possibly with zero
   parts for an empty message), or -1 on allocation failure. */
int jmapd_tree_build(const char *msg, size_t len, JmapdTree *t);

/* Index of the part with this partId ("" is the whole message), or -1. */
int jmapd_tree_find(const JmapdTree *t, const char *id);

/* Classify the leaves: textBody (text/plain) / htmlBody (text/html) get
   body_kind 1/2 unless they carry a filename or Content-Disposition:
   attachment; every other leaf is an attachment.  Called by
   jmapd_tree_build; exported because the classification is what
   hasAttachment and the attachments list both rest on. */
void jmapd_tree_classify(JmapdTree *t);

/* ------------------------------------------------------------------ */
/* bodyValues                                                          */
/* ------------------------------------------------------------------ */

/* Hard cap on one decoded bodyValue.  A client may ask for less (and gets
   isTruncated when the part is longer); it cannot ask for more, because the
   response cap (JMAPD_MAX_RESP) bounds one reply and a per-value cap is what
   keeps one huge part from eating it. */
#define JMAPD_MAX_BODY_VALUE (4u * 1024u * 1024u)

typedef struct JmapdBodyValue {
    char  *value;      /* decoded, NUL-terminated (NULs in the data dropped) */
    size_t len;
    bool   truncated;  /* more bytes exist than maxbytes allowed */
    bool   problem;    /* unknown CTE or malformed encoded input */
} JmapdBodyValue;

/* Decode part `idx` of the tree for a bodyValue.  maxbytes == 0 means "use
   the hard cap".  Frees any previous *bv.  Returns 0, or -1 on allocation
   failure. */
int jmapd_body_value(const char *msg, const JmapdTree *t, int idx,
                     size_t maxbytes, JmapdBodyValue *bv);

void jmapd_body_value_free(JmapdBodyValue *bv);

/* Decoded octet count of one part body (RFC 8621's BodyPart.size is the size
   AFTER decoding).  Decodes and discards: bounded, no buffer. */
size_t jmapd_decoded_size(const char *in, size_t inlen, int kind, bool *bad);

/* First line of the first text/plain body part, decoded, single line,
   at most 255 bytes.  Writes "" when there is none.  Returns 0. */
int jmapd_preview(const char *msg, const JmapdTree *t, char *out, size_t outsz);

/* ------------------------------------------------------------------ */
/* RFC 2047 encoded-words (display fields only)                        */
/* ------------------------------------------------------------------ */

/* Decode the encoded-words of one header VALUE: "=?charset?B?...?=" and
   "=?charset?Q?...?=", case-insensitive in the encoding letter, with the
   whitespace between ADJACENT encoded words dropped (RFC 2047 6.2) and
   anything that is not a well-formed encoded word passed through verbatim.

   CHARSET IS PASSTHROUGH, exactly as it is for body parts: the transfer
   encoding is undone and the resulting bytes are emitted unchanged, so a
   utf-8 word arrives as utf-8 and an iso-8859-1 word as 8-bit latin-1.  There
   is no iconv and no new dependency; a client that renders non-utf-8 display
   names correctly is doing the transcoding.

   Decoding never EXPANDS the value (a Q pair is 3 bytes for 1, base64 is 4
   for 3, and the "=?c?X?"/"?=" framing is dropped), so a buffer the size of
   the input can never truncate.  Returns 0, or -1 on a NULL/short argument. */
int jmapd_rfc2047_decode(const char *in, char *out, size_t outsz);

/* ------------------------------------------------------------------ */
/* File-based part resolution (blob download)                          */
/* ------------------------------------------------------------------ */

/* One part resolved against the message FILE, without reading the message
   into memory: a 30 MiB attachment must not be buffered to find the part that
   holds it.  The parse is the walker's own (imapd_mime_ct_parse /
   imapd_mime_param), and src/jmap_check.c asserts the two agree over a
   fixture corpus — a download that served a different part than Email/get
   described would be silent-wrong otherwise. */
typedef struct JmapdPartRef {
    size_t start, end, hdr_end;   /* byte offsets in the file */
    char   cte[32];
    char   type[48], subtype[48], charset[48];
    char   filename[128];
} JmapdPartRef;

/* Resolve part_id ("" = the whole message) against an open message file of
   filesize bytes.  Returns 0, or -1 when the path does not resolve. */
int jmapd_file_part(int fd, uint64_t filesize, const char *part_id,
                    JmapdPartRef *out);

/* ------------------------------------------------------------------ */
/* Blob ids                                                            */
/* ------------------------------------------------------------------ */

/* A blob id names one part of one email: "g" + b64url(emailId) + "." +
   b64url(partId).  Both halves are decoded with the strict base64url decoder
   and the email id is re-parsed by the email codec, so a traversal attempt
   cannot be expressed and nothing reaches open(2) before it is rejected. */
#define JMAPD_BLOB_MAX 1024

int jmapd_id_blob(const char *email_id, const char *part_id, char *out,
                  size_t outsz);
int jmapd_id_blob_parse(const char *blob, char *email_id, size_t emailsz,
                        char *part_id, size_t partsz);

#endif /* VISAGE_JMAP_MIME_H */
