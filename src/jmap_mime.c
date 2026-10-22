/* jmap_mime.c — MIME tree, CTE decoding and body assembly for jmapd.
 *
 * See jmap_mime.h for the contract.  Two properties this file exists to keep:
 *
 *   (1) ONE decoder.  The whole-part bodyValue path and the streamed blob
 *       download run the same incremental JmapdDec, so "the text the client
 *       reads" and "the bytes the client downloads" cannot diverge.  A second
 *       whole-buffer decoder (imapd_b64_decode) is used only by the unit
 *       checks, as the oracle this one is measured against.
 *   (2) Bounded work from message data.  A part body is decoded through a
 *       fixed chunk buffer, a bodyValue stops at maxBodyValueBytes, and the
 *       tree stops at JMAPD_MAX_PARTS.  Nothing here allocates from a header
 *       value's length.
 *
 * CHARSET IS PASSTHROUGH — no iconv, no transcoding (see the header).
 */
#include "visage.h"
#include "jmap_mime.h"
#include "jmapd.h"
#include "mail.h"

#include <errno.h>
#include <fcntl.h>
#include <strings.h>
#include <unistd.h>

/* ------------------------------------------------------------------ */
/* Content-Transfer-Encoding                                           */
/* ------------------------------------------------------------------ */

int jmapd_cte_kind(const char *cte) {
    if (!cte || !cte[0]) return JMAPD_CTE_7BIT;
    if (!strcasecmp(cte, "7bit") || !strcasecmp(cte, "8bit") ||
        !strcasecmp(cte, "binary"))
        return JMAPD_CTE_7BIT;
    if (!strcasecmp(cte, "base64")) return JMAPD_CTE_BASE64;
    if (!strcasecmp(cte, "quoted-printable")) return JMAPD_CTE_QP;
    return -1;
}

void jmapd_dec_init(JmapdDec *d, int kind) {
    memset(d, 0, sizeof *d);
    d->kind = kind;
}

/* base64 alphabet: the standard one, plus the URL-safe pair some senders
   emit.  Whitespace is ignored (a wrapped base64 body is legal and common). */
static int b64v(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+' || c == '-') return 62;
    if (c == '/' || c == '_') return 63;
    return -1;
}

static int qphex(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static bool b64_ws(char c) {
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

size_t jmapd_dec_feed(JmapdDec *d, const char *in, size_t *inlen,
                      unsigned char *out, size_t outsz) {
    size_t i = 0, o = 0;
    size_t n = *inlen;
    if (!d || !in || !inlen) return 0;
    *inlen = 0;
    if (outsz == 0) return 0;

    if (d->kind == JMAPD_CTE_BASE64) {
        for (; i < n; i++) {
            int v;
            char c = in[i];
            if (b64_ws(c)) continue;
            if (c == '=') { d->pad = 1; continue; }  /* padding: data ends */
            if (d->pad) { d->bad = true; continue; } /* data after padding */
            v = b64v(c);
            if (v < 0) { d->bad = true; continue; }
            d->acc = (d->acc << 6) | (unsigned)v;
            d->bits += 6;
            if (d->bits >= 8) {
                if (o >= outsz) break;
                d->bits -= 8;
                out[o++] = (unsigned char)((d->acc >> d->bits) & 0xFFu);
            }
        }
        *inlen = i;
        return o;
    }

    if (d->kind == JMAPD_CTE_QP) {
        for (; i < n; i++) {
            char c = in[i];
            switch (d->qp) {
            case 0:
                if (c == '=') { d->qp = 1; continue; }
                if (o >= outsz) goto full;
                out[o++] = (unsigned char)c;
                continue;
            case 1:   /* just saw '=' */
                if (c == '\r') { d->qp = 3; continue; }
                if (c == '\n') { d->qp = 0; continue; }   /* soft break */
                {
                    int h = qphex(c);
                    if (h < 0) {
                        if (o + 2 > outsz) goto full;
                        out[o++] = '=';
                        out[o++] = (unsigned char)c;
                        d->qp = 0;
                        d->bad = true;
                        continue;
                    }
                    d->qphi = h;
                    d->qpch = c;
                    d->qp = 2;
                    continue;
                }
            case 2: {   /* '=X' pending */
                int h = qphex(c);
                if (h < 0) {
                    if (o + 3 > outsz) goto full;
                    out[o++] = '=';
                    out[o++] = (unsigned char)d->qpch;
                    out[o++] = (unsigned char)c;
                    d->qp = 0;
                    d->bad = true;
                    continue;
                }
                if (o >= outsz) goto full;
                out[o++] = (unsigned char)((d->qphi << 4) | h);
                d->qp = 0;
                continue;
            }
            default:    /* 3: '=' CR seen, expect LF */
                if (c == '\n') { d->qp = 0; continue; }
                if (o + 3 > outsz) goto full;
                out[o++] = '=';
                out[o++] = '\r';
                out[o++] = (unsigned char)c;
                d->qp = 0;
                d->bad = true;
                continue;
            }
        }
        *inlen = i;
        return o;
    }

    /* 7bit / 8bit / binary: bytes pass through unchanged. */
    for (; i < n && o < outsz; i++) out[o++] = (unsigned char)in[i];
    *inlen = i;
    return o;

full:
    *inlen = i;
    return o;
}

size_t jmapd_dec_finish(JmapdDec *d, unsigned char *out, size_t outsz) {
    size_t o = 0;
    if (!d || d->eof) return 0;
    d->eof = true;
    if (d->kind == JMAPD_CTE_BASE64) {
        /* 6 leftover bits cannot form a byte: the final quad was short, which
           is malformed rather than merely unpadded. */
        if (d->bits == 6) d->bad = true;
        d->bits = 0;
        d->acc = 0;
        return 0;
    }
    if (d->kind == JMAPD_CTE_QP) {
        if (d->qp == 1 && outsz >= 1) { out[o++] = '='; d->bad = true; }
        else if (d->qp == 2 && outsz >= 3) {
            out[o++] = '=';
            out[o++] = (unsigned char)d->qpch;
            d->bad = true;
        } else if (d->qp == 3 && outsz >= 2) {
            out[o++] = '=';
            out[o++] = '\r';
            d->bad = true;
        }
        d->qp = 0;
    }
    return o;
}

/* ------------------------------------------------------------------ */
/* Whole-buffer decode                                                 */
/* ------------------------------------------------------------------ */

int jmapd_decode_all(int kind, const char *in, size_t inlen, char **out,
                     size_t *outlen, bool *bad) {
    JmapdDec d;
    char *buf;
    size_t o = 0, i = 0;
    if (!out || !outlen) return -1;
    *out = NULL;
    *outlen = 0;
    if (bad) *bad = false;
    if (!in) inlen = 0;
    buf = malloc(inlen + 1);
    if (!buf) return -1;
    jmapd_dec_init(&d, kind);
    while (i < inlen) {
        size_t n = inlen - i;
        size_t w = jmapd_dec_feed(&d, in + i, &n, (unsigned char *)buf + o,
                                  inlen + 1 - o);
        i += n;
        o += w;
        if (n == 0 && w == 0) break;   /* defensive: no progress possible */
    }
    o += jmapd_dec_finish(&d, (unsigned char *)buf + o, inlen + 1 - o);
    /* Drop NULs: every consumer downstream treats the value as a C string
       (see jmap_mime.h). */
    {
        size_t r = 0, w = 0;
        for (r = 0; r < o; r++)
            if (buf[r] != '\0') buf[w++] = buf[r];
        o = w;
    }
    buf[o] = '\0';
    *out = buf;
    *outlen = o;
    if (bad) *bad = d.bad;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Part tree                                                           */
/* ------------------------------------------------------------------ */

typedef struct TreeBuild {
    JmapdTree *t;
} TreeBuild;

static int tree_push(void *ctx, const ImailPart *p) {
    TreeBuild *tb = ctx;
    JmapdTree *t = tb->t;
    JmapdPart *q;
    int idx;
    if (t->nparts >= JMAPD_MAX_PARTS) return 1;   /* stop the walk */
    idx = t->nparts++;
    q = &t->parts[idx];
    memset(q, 0, sizeof *q);
    q->info = *p;
    q->parent = -1;
    if (p->depth > 0) {
        int k;
        for (k = idx - 1; k >= 0; k--)
            if (t->parts[k].info.depth == p->depth - 1) { q->parent = k; break; }
    }
    {
        int ck = jmapd_cte_kind(p->cte);
        q->cte_kind = (ck < 0) ? JMAPD_CTE_7BIT : ck;
    }
    return 0;
}

int jmapd_tree_build(const char *msg, size_t len, JmapdTree *t) {
    TreeBuild tb;
    if (!t) return -1;
    t->nparts = 0;
    tb.t = t;
    if (imapd_mime_iterate(msg ? msg : "", msg ? len : 0, tree_push, &tb) != 0)
        return -1;
    jmapd_tree_classify(t);
    return 0;
}

int jmapd_tree_find(const JmapdTree *t, const char *id) {
    int i;
    if (!t || !id) return -1;
    for (i = 0; i < t->nparts; i++)
        if (strcmp(t->parts[i].info.id, id) == 0) return i;
    return -1;
}

/* A part is a displayable body part when it is a leaf of type text/plain or
   text/html that is not itself an attachment (a filename or an explicit
   Content-Disposition: attachment marks a part as an attachment). */
void jmapd_tree_classify(JmapdTree *t) {
    int i;
    if (!t) return;
    for (i = 0; i < t->nparts; i++) {
        JmapdPart *p = &t->parts[i];
        bool leaf = !p->info.multipart;
        bool named = p->info.filename[0] != '\0' ||
                     strcmp(p->info.disp, "attachment") == 0;
        p->body_kind = 0;
        p->attachment = false;
        if (!leaf) continue;
        if (!named && strcmp(p->info.type, "text") == 0) {
            if (strcmp(p->info.subtype, "plain") == 0) p->body_kind = 1;
            else if (strcmp(p->info.subtype, "html") == 0) p->body_kind = 2;
        }
        if (p->body_kind == 0) p->attachment = true;
    }
}

/* ------------------------------------------------------------------ */
/* bodyValues                                                          */
/* ------------------------------------------------------------------ */

void jmapd_body_value_free(JmapdBodyValue *bv) {
    if (!bv) return;
    free(bv->value);
    bv->value = NULL;
    bv->len = 0;
    bv->truncated = false;
    bv->problem = false;
}

int jmapd_body_value(const char *msg, const JmapdTree *t, int idx,
                     size_t maxbytes, JmapdBodyValue *bv) {
    const JmapdPart *p;
    const char *body;
    size_t bodylen, o = 0, i = 0, cap;
    char *buf;
    JmapdDec d;
    bool problem = false;
    int kind;

    if (!bv) return -1;
    jmapd_body_value_free(bv);
    if (!msg || !t || idx < 0 || idx >= t->nparts) return -1;
    p = &t->parts[idx];
    if (p->info.hdr_end > p->info.end) return -1;
    body = msg + p->info.hdr_end;
    bodylen = p->info.end - p->info.hdr_end;

    kind = jmapd_cte_kind(p->info.cte);
    if (kind < 0) {
        kind = JMAPD_CTE_7BIT;
        problem = true;
    }
    cap = maxbytes ? maxbytes : JMAPD_MAX_BODY_VALUE;
    if (cap > JMAPD_MAX_BODY_VALUE) cap = JMAPD_MAX_BODY_VALUE;
    buf = malloc(cap + 1);
    if (!buf) return -1;
    jmapd_dec_init(&d, kind);
    while (i < bodylen) {
        size_t n = bodylen - i;
        size_t w;
        if (o >= cap) break;
        w = jmapd_dec_feed(&d, body + i, &n, (unsigned char *)buf + o, cap - o);
        i += n;
        o += w;
        if (n == 0 && w == 0) break;
    }
    if (o >= cap) {
        /* Probe for more decoded bytes so isTruncated is exact rather than a
           guess from the encoded length (base64/qp shrink). */
        unsigned char scratch[256];
        while (i < bodylen) {
            size_t n = bodylen - i;
            size_t w = jmapd_dec_feed(&d, body + i, &n, scratch,
                                      sizeof scratch);
            i += n;
            if (w > 0) { bv->truncated = true; break; }
            if (n == 0 && w == 0) break;
        }
    }
    {
        size_t r, w = 0;
        for (r = 0; r < o; r++)
            if (buf[r] != '\0') buf[w++] = buf[r];
        o = w;
    }
    buf[o] = '\0';
    bv->value = buf;
    bv->len = o;
    bv->problem = problem || d.bad;
    return 0;
}

size_t jmapd_decoded_size(const char *in, size_t inlen, int kind, bool *bad) {
    unsigned char out[4096];
    JmapdDec d;
    size_t total = 0, i = 0;
    if (bad) *bad = false;
    if (!in) return 0;
    jmapd_dec_init(&d, kind);
    while (i < inlen) {
        size_t n = inlen - i;
        size_t w = jmapd_dec_feed(&d, in + i, &n, out, sizeof out);
        i += n;
        total += w;
        if (n == 0 && w == 0) break;
    }
    total += jmapd_dec_finish(&d, out, sizeof out);
    if (bad) *bad = d.bad;
    return total;
}

/* ------------------------------------------------------------------ */
/* Preview                                                             */
/* ------------------------------------------------------------------ */

/* Decode at most this much of a part to find its first line.  A preview is
   one line; reading further would make a 30 MiB text part cost 30 MiB. */
#define PREVIEW_DECODE_MAX (64u * 1024u)

int jmapd_preview(const char *msg, const JmapdTree *t, char *out, size_t outsz) {
    int i;
    if (!out || outsz == 0) return -1;
    out[0] = '\0';
    if (!msg || !t) return 0;
    for (i = 0; i < t->nparts; i++) {
        const JmapdPart *p = &t->parts[i];
        char *buf = NULL;
        size_t bodylen, o = 0, r;
        bool bad = false;
        int kind;
        if (p->body_kind != 1) continue;
        bodylen = p->info.end > p->info.hdr_end
                      ? p->info.end - p->info.hdr_end
                      : 0;
        if (bodylen > PREVIEW_DECODE_MAX) bodylen = PREVIEW_DECODE_MAX;
        kind = jmapd_cte_kind(p->info.cte);
        if (kind < 0) kind = JMAPD_CTE_7BIT;
        /* Only a bounded prefix is decoded (see PREVIEW_DECODE_MAX): a
           preview is one line, not a reason to materialise a 30 MiB body. */
        if (jmapd_decode_all(kind, msg + p->info.hdr_end, bodylen, &buf, &o,
                             &bad) != 0)
            return -1;
        (void)bad;
        /* first non-empty line, tabs collapsed to one space */
        {
            size_t s = 0, e, w = 0;
            while (s < o && (buf[s] == '\r' || buf[s] == '\n' ||
                             buf[s] == ' ' || buf[s] == '\t'))
                s++;
            e = s;
            while (e < o && buf[e] != '\r' && buf[e] != '\n') e++;
            for (r = s; r < e && w + 1 < outsz; r++) {
                unsigned char c = (unsigned char)buf[r];
                if (c == '\t' || (c < 0x20 && c != 0) || c == 0x7f) {
                    if (w > 0 && out[w - 1] != ' ') out[w++] = ' ';
                    continue;
                }
                out[w++] = (char)c;
            }
            while (w > 0 && out[w - 1] == ' ') w--;
            out[w] = '\0';
        }
        free(buf);
        if (out[0] != '\0') return 0;
        /* An empty first text part: keep looking at the next one. */
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Blob ids                                                            */
/* ------------------------------------------------------------------ */

int jmapd_id_blob(const char *email_id, const char *part_id, char *out,
                  size_t outsz) {
    char a[JMAPD_ID_MAX * 2], b[JMAPD_ID_MAX * 2];
    int n;
    if (!email_id || !email_id[0] || !part_id || !out) return -1;
    if (jmapd_b64url_encode((const unsigned char *)email_id, strlen(email_id),
                            a, sizeof a) != 0)
        return -1;
    if (jmapd_b64url_encode((const unsigned char *)part_id, strlen(part_id), b,
                            sizeof b) != 0)
        return -1;
    n = snprintf(out, outsz, "g%s.%s", a, b);
    if (n < 0 || (size_t)n >= outsz) return -1;
    return 0;
}

/* A partId is "" (the whole message) or dotted 1-based decimal numbers, at
   most IMAPD_MAX_PART_DEPTH deep — exactly what imapd_mime_iterate emits.
   Anything else (a path separator, "..", a letter, a leading zero) is not a
   part id this server produced. */
static bool part_id_ok(const char *s) {
    int ncomp = 0;
    const char *p = s;
    if (!s[0]) return true;
    for (;;) {
        unsigned v = 0;
        int digits = 0;
        if (*p < '0' || *p > '9') return false;
        if (*p == '0') return false;              /* no leading zero */
        while (*p >= '0' && *p <= '9') {
            v = v * 10 + (unsigned)(*p - '0');
            if (v > 999999) return false;
            p++;
            digits++;
        }
        if (!digits) return false;
        if (++ncomp > IMAPD_MAX_PART_DEPTH) return false;
        if (*p == '\0') return true;
        if (*p != '.') return false;
        p++;
    }
}

int jmapd_id_blob_parse(const char *blob, char *email_id, size_t emailsz,
                        char *part_id, size_t partsz) {
    const char *dot;
    size_t n = 0;
    if (!blob || blob[0] != 'g' || !email_id || !part_id) return -1;
    dot = strchr(blob + 1, '.');
    if (!dot) return -1;
    if (jmapd_b64url_decode(blob + 1, (size_t)(dot - (blob + 1)),
                            (unsigned char *)email_id, emailsz - 1, &n) != 0)
        return -1;
    email_id[n] = '\0';
    if (n == 0) return -1;
    /* Re-parse the email id: it is the only thing that decides which file is
       opened, so it must be a valid id before anything else happens. */
    {
        char base[IMAPD_MAX_MBOX + 1], mbox[IMAPD_MAX_MBOX + 1];
        if (jmapd_id_email_parse(email_id, base, sizeof base, mbox,
                                 sizeof mbox) != 0)
            return -1;
    }
    if (jmapd_b64url_decode(dot + 1, strlen(dot + 1), (unsigned char *)part_id,
                            partsz - 1, &n) != 0)
        return -1;
    part_id[n] = '\0';
    return part_id_ok(part_id) ? 0 : -1;
}

/* ------------------------------------------------------------------ */
/* File-based part resolution (blob download)                          */
/* ------------------------------------------------------------------ */

#define MIME_FILE_CHUNK (64u * 1024u)

/* Offset just past the blank line that ends the header block starting at
   `from` (the same rule as mime_hdr_end, applied to a file).  A header block
   larger than IMAPD_HDR_CAP is treated as ending at the cap: the walker caps
   its own header scan the same way, and a 256 KiB header is not a message
   this server renders. */
static uint64_t file_hdr_end(int fd, uint64_t from, uint64_t limit) {
    char buf[MIME_FILE_CHUNK + 4];
    uint64_t stop = from + IMAPD_HDR_CAP;
    uint64_t pos = from;
    if (stop > limit) stop = limit;
    while (pos < stop) {
        size_t want = (size_t)((stop - pos) < MIME_FILE_CHUNK
                                   ? (stop - pos)
                                   : MIME_FILE_CHUNK);
        ssize_t r = pread(fd, buf, want, (off_t)pos);
        size_t i;
        if (r < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (r == 0) break;
        for (i = 0; i + 1 < (size_t)r; i++) {
            if (buf[i] == '\n' && buf[i + 1] == '\n')
                return pos + i + 2;
            if (i + 3 < (size_t)r && buf[i] == '\r' && buf[i + 1] == '\n' &&
                buf[i + 2] == '\r' && buf[i + 3] == '\n')
                return pos + i + 4;
        }
        /* overlap 3 bytes so a delimiter straddling the chunk boundary is
           still seen exactly once */
        if ((size_t)r < 4) break;
        pos += (uint64_t)r - 3;
    }
    return stop;
}

/* Read [from,to) of the file into a heap buffer (bounded by the caller's
   span; used for header blocks only). */
static int file_read_span(int fd, uint64_t from, uint64_t to, char **out,
                          size_t *outlen) {
    size_t n, got = 0;
    char *buf;
    *out = NULL;
    *outlen = 0;
    if (to < from) return -1;
    n = (size_t)(to - from);
    if (n > IMAPD_HDR_CAP) n = IMAPD_HDR_CAP;
    buf = malloc(n + 1);
    if (!buf) return -1;
    while (got < n) {
        ssize_t r = pread(fd, buf + got, n - got, (off_t)(from + got));
        if (r < 0) {
            if (errno == EINTR) continue;
            free(buf);
            return -1;
        }
        if (r == 0) break;
        got += (size_t)r;
    }
    buf[got] = '\0';
    *out = buf;
    *outlen = got;
    return 0;
}

/* First occurrence of the delimiter "--boundary" at or after `from`, or
   limit when there is none (the walker's rule: a delimiter is recognised
   anywhere in the body, not only at a line start). */
static uint64_t file_next_delim(int fd, uint64_t from, uint64_t limit,
                                const char *delim) {
    char buf[MIME_FILE_CHUNK + 1024];
    size_t dlen = strlen(delim);
    uint64_t pos = from;
    if (dlen == 0 || dlen > 512) return limit;
    while (pos < limit) {
        size_t want = (size_t)((limit - pos) < MIME_FILE_CHUNK
                                   ? (limit - pos)
                                   : MIME_FILE_CHUNK);
        ssize_t r = pread(fd, buf, want, (off_t)pos);
        char *hit;
        if (r < 0) {
            if (errno == EINTR) continue;
            return limit;
        }
        if (r == 0) return limit;
        hit = memmem(buf, (size_t)r, delim, dlen);
        if (hit) return pos + (uint64_t)(hit - buf);
        if ((size_t)r <= dlen) return limit;   /* last chunk, no more */
        pos += (uint64_t)r - (uint64_t)(dlen - 1);
    }
    return limit;
}

/* Fill cte/type/charset/filename from a part's header block. */
static void ref_from_hdr(const char *hdr, size_t hl, JmapdPartRef *ref) {
    char ct[1024], val[512], type[64], sub[64], boundary[512];
    ref->type[0] = '\0';
    ref->subtype[0] = '\0';
    ref->charset[0] = '\0';
    ref->filename[0] = '\0';
    strcpy(ref->cte, "7bit");
    if (mail_header_get(hdr, hl, "Content-Type", ct, sizeof ct) != 0)
        strcpy(ct, "text/plain");
    imapd_mime_ct_parse(ct, type, sizeof type, sub, sizeof sub, boundary,
                        sizeof boundary);
    snprintf(ref->type, sizeof ref->type, "%.*s", (int)sizeof ref->type - 1,
             type);
    snprintf(ref->subtype, sizeof ref->subtype, "%.*s",
             (int)sizeof ref->subtype - 1, sub);
    {
        size_t i;
        for (i = 0; ref->type[i]; i++)
            if (ref->type[i] >= 'A' && ref->type[i] <= 'Z')
                ref->type[i] = (char)(ref->type[i] - 'A' + 'a');
        for (i = 0; ref->subtype[i]; i++)
            if (ref->subtype[i] >= 'A' && ref->subtype[i] <= 'Z')
                ref->subtype[i] = (char)(ref->subtype[i] - 'A' + 'a');
    }
    if (imapd_mime_param(ct, "charset", val, sizeof val) == 0)
        snprintf(ref->charset, sizeof ref->charset, "%.*s",
                 (int)sizeof ref->charset - 1, val);
    if (mail_header_get(hdr, hl, "Content-Transfer-Encoding", val,
                        sizeof val) == 0) {
        size_t n;
        char *sp = val;
        while (*sp == ' ' || *sp == '\t') sp++;
        n = strcspn(sp, " \t;");
        sp[n] = '\0';
        snprintf(ref->cte, sizeof ref->cte, "%.*s", (int)sizeof ref->cte - 1,
                 sp);
    }
    if (mail_header_get(hdr, hl, "Content-Disposition", val, sizeof val) == 0 &&
        imapd_mime_param(val, "filename", ref->filename,
                         sizeof ref->filename) == 0)
        return;
    if (imapd_mime_param(ct, "name", ref->filename, sizeof ref->filename) != 0)
        ref->filename[0] = '\0';
}

int jmapd_file_part(int fd, uint64_t filesize, const char *part_id,
                    JmapdPartRef *out) {
    uint64_t cs = 0, ce = filesize, he;
    char *hdr = NULL;
    size_t hl = 0;
    int k = 0;

    if (fd < 0 || !part_id || !out) return -1;
    he = file_hdr_end(fd, cs, ce);
    /* Walk one level per dotted component. */
    while (part_id[k] != '\0') {
        /* parse this container's Content-Type */
        char ct[1024], type[64], sub[64], boundary[512], delim[600];
        uint64_t pos, d;
        int want = 0, idx = 0, found = 0;

        free(hdr);
        hdr = NULL;
        if (file_read_span(fd, cs, he, &hdr, &hl) != 0) return -1;
        if (mail_header_get(hdr, hl, "Content-Type", ct, sizeof ct) != 0) {
            free(hdr);
            return -1;               /* not multipart: cannot descend */
        }
        imapd_mime_ct_parse(ct, type, sizeof type, sub, sizeof sub, boundary,
                            sizeof boundary);
        if (strcasecmp(type, "multipart") != 0 || !boundary[0]) {
            free(hdr);
            return -1;
        }
        while (part_id[k] >= '0' && part_id[k] <= '9') {
            want = want * 10 + (part_id[k] - '0');
            k++;
            if (want > 999999) { free(hdr); return -1; }
        }
        if (want <= 0) { free(hdr); return -1; }
        snprintf(delim, sizeof delim, "--%s", boundary);
        pos = he;
        while (pos < ce) {
            uint64_t ps, e, q;
            d = file_next_delim(fd, pos, ce, delim);
            if (d == ce) break;
            q = d + strlen(delim);
            if (q + 1 < ce) {
                char tail[2];
                if (pread(fd, tail, 2, (off_t)q) == 2 && tail[0] == '-' &&
                    tail[1] == '-')
                    break;             /* closing delimiter */
            }
            ps = q;
            {
                char crlf[2];
                ssize_t r = pread(fd, crlf, 2, (off_t)ps);
                if (r == 2 && crlf[0] == '\r' && crlf[1] == '\n') ps += 2;
                else if (r >= 1 && (crlf[0] == '\n' || crlf[0] == '\r')) ps += 1;
            }
            e = file_next_delim(fd, ps, ce, delim);
            while (e > ps) {
                char c;
                if (pread(fd, &c, 1, (off_t)(e - 1)) != 1) break;
                if (c != '\n' && c != '\r') break;
                e--;
            }
            if (e > ps) {
                idx++;
                if (idx == want) {
                    cs = ps;
                    ce = e;
                    found = 1;
                    break;
                }
            }
            pos = e;
        }
        if (!found) { free(hdr); return -1; }
        he = file_hdr_end(fd, cs, ce);
        if (part_id[k] == '.') { k++; continue; }
        if (part_id[k] != '\0') { free(hdr); return -1; }
        break;
    }
    free(hdr);
    hdr = NULL;
    hl = 0;
    if (file_read_span(fd, cs, he, &hdr, &hl) != 0) return -1;
    out->start = (size_t)cs;
    out->end = (size_t)ce;
    out->hdr_end = (size_t)he;
    ref_from_hdr(hdr, hl, out);
    free(hdr);
    return 0;
}

/* ------------------------------------------------------------------ */
/* RFC 2047 encoded-words (display fields only)                        */
/* ------------------------------------------------------------------ */

/* One encoded word is "=?charset?ENC?text?=".  The whole word is bounded so a
   hostile header cannot make the scan quadratic: 1024 bytes covers any
   legitimate charset+payload (RFC 2047 2 caps an encoded word at 75 bytes plus
   the charset), and anything longer is passed through verbatim. */
#define EW_MAX 1024

static int ew_hex(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static bool ew_space(int c) { return c == ' ' || c == '\t'; }

/* Try to decode one encoded word starting at p (which points at "=?").  On
   success writes the decoded bytes into out[0..outsz), sets *used to the
   number of INPUT bytes consumed and *wrote to the number of output bytes, and
   returns 0.  Any malformed shape returns -1 and the caller emits '='. */
static int ew_decode(const char *p, size_t avail, unsigned char *out,
                     size_t outsz, size_t *used, size_t *wrote) {
    size_t cs, ce, enc, txt, end, o = 0;
    int enc_ch;

    *used = 0;
    *wrote = 0;
    if (avail < 7 || p[0] != '=' || p[1] != '?') return -1;
    if (avail > EW_MAX) avail = EW_MAX;

    /* charset?ENC? — charset is an arbitrary token, kept as passthrough */
    for (cs = 2; cs < avail && p[cs] != '?'; cs++)
        if (p[cs] == ' ' || p[cs] == '\t') return -1;
    if (cs == 2 || cs >= avail) return -1;
    ce = cs + 1;
    if (ce >= avail || p[ce + 1] != '?') return -1;
    enc_ch = p[ce];
    enc = ce + 2;
    if (enc_ch != 'B' && enc_ch != 'b' && enc_ch != 'Q' && enc_ch != 'q')
        return -1;

    /* text?= — the payload ends at the first "?=" (RFC 2047 2: no '?' is
       allowed inside the encoded-text of a B encoding, and Q encodes it) */
    for (txt = enc; txt + 1 < avail; txt++)
        if (p[txt] == '?' && p[txt + 1] == '=') break;
    if (txt + 1 >= avail) return -1;
    end = txt + 2;

    if (enc_ch == 'B' || enc_ch == 'b') {
        unsigned char raw[EW_MAX];
        size_t rawlen = 0;
        if (imapd_b64_decode(p + enc, txt - enc, raw, sizeof raw, &rawlen) != 0)
            return -1;
        if (rawlen > outsz) return -1;
        memcpy(out, raw, rawlen);
        o = rawlen;
    } else {
        size_t k = enc;
        while (k < txt) {
            if (p[k] == '_') {
                if (o + 1 > outsz) return -1;
                out[o++] = ' ';
                k++;
            } else if (p[k] == '=') {
                int hi, lo;
                if (k + 2 >= txt) return -1;
                hi = ew_hex((unsigned char)p[k + 1]);
                lo = ew_hex((unsigned char)p[k + 2]);
                if (hi < 0 || lo < 0) return -1;
                if (o + 1 > outsz) return -1;
                out[o++] = (unsigned char)((hi << 4) | lo);
                k += 3;
            } else {
                if (o + 1 > outsz) return -1;
                out[o++] = (unsigned char)p[k++];
            }
        }
    }
    *used = end;
    *wrote = o;
    return 0;
}

int jmapd_rfc2047_decode(const char *in, char *out, size_t outsz) {
    size_t i = 0, o = 0;

    if (!in || !out || outsz == 0) return -1;
    while (in[i]) {
        if (in[i] == '=' && in[i + 1] == '?') {
            unsigned char dec[EW_MAX];
            size_t used = 0, wrote = 0;
            if (ew_decode(in + i, strlen(in + i), dec, sizeof dec, &used,
                          &wrote) == 0) {
                if (o + wrote + 1 > outsz) return -1;
                memcpy(out + o, dec, wrote);
                o += wrote;
                i += used;
                /* Adjacent encoded words: the linear white space between them
                   is not part of the text (RFC 2047 6.2), so it is dropped
                   only when another encoded word follows. */
                {
                    size_t j = i;
                    while (in[j] && ew_space((unsigned char)in[j])) j++;
                    if (in[j] == '=' && in[j + 1] == '?') {
                        unsigned char d2[EW_MAX];
                        size_t u2 = 0, w2 = 0;
                        if (ew_decode(in + j, strlen(in + j), d2, sizeof d2, &u2,
                                      &w2) == 0)
                            i = j;   /* skip the separator whitespace */
                    }
                }
                continue;
            }
            /* Not a well-formed encoded word: emit it verbatim. */
        }
        if (o + 2 > outsz) return -1;
        out[o++] = in[i++];
    }
    out[o] = '\0';
    return 0;
}
