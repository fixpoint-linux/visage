/* imap_maildir.c — maildir store + pure helpers for imapd.
 *
 * Layout (maildir++): <root>/<user>/Inbox/{tmp,new,cur} is INBOX and
 * <root>/<user>/.<Folder>/{tmp,new,cur} are the other folders.  Message
 * flags live in the standard ":2,DFRST" filename info suffix; UIDs live in
 * a per-mailbox sidecar file "imapd-uidlist" ("uidvalidity uidnext" header
 * line then "uid base" lines) so a message keeps its UID across flag
 * renames and daemon restarts.  Single-writer: the daemon owns the tree.
 *
 * Pure helpers (flag suffix codec, seq-sets, base64, wildcards, validation)
 * are exported via imapd.h and unit-tested by imap_check.c. */
#include "imapd.h"
#include "mail.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <time.h>
#include <dirent.h>

/* ------------------------------------------------------------------ */
/* Small file helpers (duplicated per house style; cf. smtp_in.c)      */
/* ------------------------------------------------------------------ */

static int mkdir_p(const char *path) {
    char *tmp;
    size_t plen, i;
    int rc = 0;
    if (!path || !path[0]) return -1;
    tmp = strdup(path);
    if (!tmp) return -1;
    plen = strlen(tmp);
    for (i = 1; i < plen; i++) {
        if (tmp[i] == '/') {
            tmp[i] = '\0';
            if (mkdir(tmp, 0755) != 0 && errno != EEXIST) { rc = -1; goto out; }
            tmp[i] = '/';
        }
    }
    if (mkdir(tmp, 0755) != 0 && errno != EEXIST) rc = -1;
out:
    free(tmp);
    return rc;
}

static int write_file(const char *path, const char *data, size_t len) {
    /* 0600: mail bodies must not be world-readable on the host. */
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    size_t w;
    int rc;
    FILE *f;
    if (fd < 0) return -1;
    f = fdopen(fd, "wb");
    if (!f) { close(fd); return -1; }
    w = fwrite(data, 1, len, f);
    rc = fclose(f);
    if (w != len || rc != 0) return -1;
    return 0;
}

static int read_file(const char *path, char **out, size_t *outlen) {
    struct stat st;
    int fd;
    char *buf;
    size_t off = 0;

    if (!path || !out || !outlen) return -1;
    *out = NULL;
    *outlen = 0;

    fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    if (fstat(fd, &st) != 0 || st.st_size < 0) { close(fd); return -1; }
    buf = malloc((size_t)st.st_size + 1);
    if (!buf) { close(fd); return -1; }
    while (off < (size_t)st.st_size) {
        ssize_t r = read(fd, buf + off, (size_t)st.st_size - off);
        if (r < 0) {
            if (errno == EINTR) continue;
            free(buf);
            close(fd);
            return -1;
        }
        if (r == 0) break;   /* file shrank: return what was read */
        off += (size_t)r;
    }
    close(fd);
    buf[off] = '\0';
    *out = buf;
    *outlen = off;
    return 0;
}

/* Extract the Message-ID header value from a message buffer (malloc'd, or
   NULL if absent).  Feeds the fast SEARCH Message-ID index so searches don't
   have to read every message file. */
static char *imapd_msgid_of_buf(const char *msg, size_t len) {
    char buf[1024];
    if (!msg || len == 0) return NULL;
    if (mail_header_get(msg, len, "Message-ID", buf, sizeof buf) != 0 ||
        buf[0] == '\0')
        return NULL;
    return strdup(buf);
}

/* Recursively remove a directory tree (bounded: directories only, and the
   walk never follows symlinks).  Returns 0, or -1 on error. */
static int rmrf(const char *path) {
    DIR *d = opendir(path);
    struct dirent *e;
    char sub[4096];
    int rc = 0;
    if (!d) return -1;
    while ((e = readdir(d)) != NULL) {
        struct stat st;
        if (e->d_name[0] == '.') continue;
        if (snprintf(sub, sizeof sub, "%s/%s", path, e->d_name)
                >= (int)sizeof sub)
            { rc = -1; continue; }
        if (lstat(sub, &st) != 0) { rc = -1; continue; }
        if (S_ISDIR(st.st_mode)) {
            if (rmrf(sub) != 0) rc = -1;
        } else if (S_ISREG(st.st_mode)) {
            if (unlink(sub) != 0) rc = -1;
        } else {
            rc = -1;   /* symlink/other: not ours */
        }
    }
    closedir(d);
    if (rmdir(path) != 0) rc = -1;
    return rc;
}

/* ASCII case-insensitive full-string equality. */
static bool ascii_ieq_str(const char *a, const char *b) {
    while (*a && *b) {
        char ca = *a++, cb = *b++;
        if (ca >= 'A' && ca <= 'Z') ca = (char)(ca + 32);
        if (cb >= 'A' && cb <= 'Z') cb = (char)(cb + 32);
        if (ca != cb) return false;
    }
    return *a == *b;
}

/* ------------------------------------------------------------------ */
/* Header cache (S2)                                                   */
/* ------------------------------------------------------------------ */

/* Byte offset just past the header block (incl. the blank separator line).
   The bounded header read moved here from imapd_imap.c so the maildir layer
   owns header extraction. */
static size_t mail_hdr_end(const char *msg, size_t len) {
    size_t i;
    for (i = 0; i + 4 <= len; i++)
        if (msg[i] == '\r' && msg[i+1] == '\n' && msg[i+2] == '\r' &&
            msg[i+3] == '\n')
            return i + 4;
    for (i = 0; i + 2 <= len; i++)
        if (msg[i] == '\n' && msg[i+1] == '\n')
            return i + 2;
    return len;
}

int imapd_read_hdr(const char *path, char **out, size_t *outlen) {
    int fd;
    char *buf;
    size_t got = 0;
    if (!path || !out || !outlen) return -1;
    *out = NULL;
    *outlen = 0;
    buf = malloc(IMAPD_HDR_CAP + 1);
    if (!buf) return -1;
    fd = open(path, O_RDONLY);
    if (fd < 0) { free(buf); return -1; }
    while (got < IMAPD_HDR_CAP) {
        char chunk[8192];
        size_t need = sizeof chunk;
        ssize_t r;
        if (IMAPD_HDR_CAP - got < need) need = IMAPD_HDR_CAP - got;
        r = read(fd, chunk, need);
        if (r < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (r == 0) break;
        memcpy(buf + got, chunk, (size_t)r);
        got += (size_t)r;
        if (mail_hdr_end(buf, got) < got) break;   /* header block complete */
    }
    close(fd);
    got = mail_hdr_end(buf, got);
    buf[got] = '\0';
    *out = buf;
    *outlen = got;
    return 0;
}

/* The six indexed fields, in packing order. */
static const char *const MAIL_HDR_FIELDS[IH_NFIELDS] = {
    "From", "To", "Cc", "Bcc", "Subject", "Date"
};

/* Cached values are truncated at this many bytes so a pathological header
   cannot blow up the per-conn view or the per-mailbox sidecar (they feed
   SEARCH substrings and SORT keys, not display data). */
#define MAIL_HDR_FLD_MAX IMAPD_MAX_LINE

/* Append one field value to the packed block being built and record its
   offset.  Returns 0, or -1 on allocation failure (the block is freed). */
static int mail_hdr_pack(char **hdr, size_t *off, size_t *cap,
                         size_t fields_off[IH_NFIELDS], int fld,
                         const char *s) {
    char *nb;
    size_t sl = strlen(s), need = *off + sl + 1;
    if (need > *cap) {
        size_t nc = *cap ? *cap : 256;
        while (nc < need) nc *= 2;
        nb = realloc(*hdr, nc);
        if (!nb) return -1;
        *hdr = nb;
        *cap = nc;
    }
    memcpy(*hdr + *off, s, sl + 1);
    fields_off[fld] = *off;
    *off += sl + 1;
    return 0;
}

/* Build the packed block (From\0To\0Cc\0Bcc\0Subj\0Date\0, "" when absent)
   from a header block.  Returns 0 with blk_out/blen_out/fields_out set
   (blk owned by caller), or -1 on allocation failure. */
static int mail_hdr_build(const char *hdrblk, size_t hl,
                          char **blk_out, size_t *blen_out,
                          size_t fields_off[IH_NFIELDS]) {
    char *blk = NULL;
    char tmp[MAIL_HDR_FLD_MAX + 1];
    size_t off = 0, cap = 0;
    int i;
    *blk_out = NULL;
    *blen_out = 0;
    for (i = 0; i < IH_NFIELDS; i++) {
        if (mail_header_get(hdrblk, hl, MAIL_HDR_FIELDS[i], tmp,
                            sizeof tmp) != 0 || tmp[0] == '\0') {
            tmp[0] = '\0';
        }
        if (mail_hdr_pack(&blk, &off, &cap, fields_off, i, tmp) != 0) {
            free(blk);
            return -1;
        }
    }
    *blk_out = blk;
    *blen_out = off;
    return 0;
}

/* Install a packed block into m (takes ownership of blk). */
static void mail_hdr_install(Imail *m, char *blk, size_t blen,
                             const size_t fields_off[IH_NFIELDS]) {
    size_t i;
    if (m->hdr) free(m->hdr);
    m->hdr = blk;
    m->hdr_len = blen;
    for (i = 0; i < IH_NFIELDS; i++)
        m->fields_off[i] = fields_off[i];
    m->hdr_loaded = true;
}

/* Extract + install in one step (the lazy ensure path).  Returns 0/-1. */
static int mail_hdr_extract(Imail *m, const char *hdrblk, size_t hl) {
    char *blk = NULL;
    size_t blen = 0;
    size_t fields_off[IH_NFIELDS];
    if (mail_hdr_build(hdrblk, hl, &blk, &blen, fields_off) != 0) return -1;
    mail_hdr_install(m, blk, blen, fields_off);
    return 0;
}

/* Map a header name to its IH_* index (-1 when not an indexed field). */
int imapd_mail_hdr_fld(const char *name) {
    int i;
    if (!name) return -1;
    for (i = 0; i < IH_NFIELDS; i++)
        if (ascii_ieq_str(name, MAIL_HDR_FIELDS[i])) return i;
    return -1;
}

const char *imapd_mail_hdr_field(const Imail *m, int fld) {
    if (!m || !m->hdr || fld < 0 || fld >= IH_NFIELDS) return NULL;
    return m->hdr + m->fields_off[fld];
}

/* Per-message allowance charged against the caller's pump budget so even a
   fully warm-cache pass stays non-blocking on huge mailboxes (mirrors
   IMAPD_SEARCH_MSGCOST in imapd_imap.c; keep the two in sync). */
#define MAIL_HDR_MSGCOST 512u

int imapd_mail_ensure_hdrs(Mbox *mb, Imail *m, size_t *budget) {
    struct stat st;
    char *hdrblk = NULL;
    size_t hl = 0;
    int rc;

    if (m->hdr_valid) return 1;
    /* The stat guard is cheap correctness work, not budget work: always done,
       even when the budget is exhausted (it decides nothing by itself). */
    if (stat(m->path, &st) != 0 || !S_ISREG(st.st_mode)) return -1;
    if (m->hdr_loaded && m->hdr_fsize == (size_t)st.st_size &&
        m->hdr_mtime == (time_t)st.st_mtime &&
        m->hdr_ctime == (int64_t)st.st_ctime) {
        /* cached (sidecar or earlier extraction) and still fresh */
        if (budget) {
            if (*budget < MAIL_HDR_MSGCOST) return 0;
            *budget -= MAIL_HDR_MSGCOST;
        }
        m->hdr_valid = true;
        return 1;
    }
    /* Budget gate BEFORE the read (a read never starts that cannot be paid
       for; the next pump slice retries this message). */
    if (budget && *budget < MAIL_HDR_MSGCOST) return 0;
    if (imapd_read_hdr(m->path, &hdrblk, &hl) != 0) return -1;
    if (budget) {
        /* Never let the budget wrap: hl is bounded only by IMAPD_HDR_CAP, so
           a header block larger than the remaining budget would underflow
           size_t and hand the pump loop a huge "budget" — collapsing the
           whole remaining mailbox into ONE unbounded slice.  Clamp to 0:
           the slice ends right after this message. */
        size_t cost = MAIL_HDR_MSGCOST + hl;
        if (*budget < cost) *budget = 0;
        else *budget -= cost;
    }
    rc = mail_hdr_extract(m, hdrblk, hl);
    free(hdrblk);
    if (rc != 0) return -1;
    m->hdr_fsize = (size_t)st.st_size;
    m->hdr_mtime = (time_t)st.st_mtime;
    m->hdr_ctime = (int64_t)st.st_ctime;
    m->hdr_valid = true;
    /* persist at close (the sidecar rewrite includes every loaded block) */
    if (mb) mb->hdrs_dirty = true;
    return 1;
}

/* --- per-mailbox sidecar "imapd-hdrs" --- */

static int hdrs_path(const Mbox *mb, char *out, size_t outsz) {
    int n = snprintf(out, outsz, "%s/%s", mb->dir, IMAPD_HDRS_FILE);
    if (n < 0 || (size_t)n >= outsz) return -1;
    return 0;
}

/* Byte-append helper for building a row/escape buffer (grows geometrically,
   keeps a trailing NUL).  Returns 0, or -1 on allocation failure. */
static int hdrs_buf_append(char **buf, size_t *len, size_t *cap,
                           const char *src, size_t n) {
    char *nb;
    size_t need, nc;
    if (n == 0) return 0;
    need = *len + n;
    if (need + 1 > *cap) {
        nc = *cap ? *cap : 128;
        while (nc < need + 1) nc *= 2;
        nb = realloc(*buf, nc);
        if (!nb) return -1;
        *buf = nb;
        *cap = nc;
    }
    memcpy(*buf + *len, src, n);
    *len = need;
    (*buf)[*len] = '\0';
    return 0;
}

/* Append the escape sequence for byte c (TAB/NEWLINE/CR/BACKSLASH become
   \t \n \r \\, everything else is copied verbatim).  Returns 0/-1. */
static int hdrs_escape_char(char **out, size_t *outlen, size_t *outcap,
                            char c) {
    const char *rep;
    char one[2] = { c, '\0' };
    switch (c) {
    case '\t': rep = "\\t"; break;
    case '\n': rep = "\\n"; break;
    case '\r': rep = "\\r"; break;
    case '\\': rep = "\\\\"; break;
    default:   rep = one; break;
    }
    return hdrs_buf_append(out, outlen, outcap, rep, strlen(rep));
}

/* One sidecar row for m (cache must be loaded): "uid\tfrom\tto\tcc\tbcc\t
   subj\tdate\t<size>\t<mtime>" (no trailing newline), TAB-escaped.  Returns
   a malloc'd NUL-terminated string, or NULL on error. */
static char *mail_hdrs_row(const Imail *m) {
    char *row = NULL;
    size_t len = 0, cap = 0;
    char uidbuf[48];
    int i;
    snprintf(uidbuf, sizeof uidbuf, "%u", m->uid);
    if (hdrs_buf_append(&row, &len, &cap, uidbuf, strlen(uidbuf)) != 0)
        return NULL;
    for (i = 0; i < IH_NFIELDS; i++) {
        const char *v = imapd_mail_hdr_field(m, i);
        const char *q;
        if (!v) { free(row); return NULL; }
        /* raw TAB as the field separator (only VALUES are escaped) */
        if (hdrs_buf_append(&row, &len, &cap, "\t", 1) != 0) {
            free(row);
            return NULL;
        }
        for (q = v; *q; q++)
            if (hdrs_escape_char(&row, &len, &cap, *q) != 0) {
                free(row);
                return NULL;
            }
    }
    snprintf(uidbuf, sizeof uidbuf, "\t%zu\t%lld\t%lld",
             m->hdr_fsize, (long long)m->hdr_mtime, (long long)m->hdr_ctime);
    if (hdrs_buf_append(&row, &len, &cap, uidbuf, strlen(uidbuf)) != 0) {
        free(row);
        return NULL;
    }
    return row;
}

/* In-place unescape of one field (inverse of hdrs_escape_char). */
static void hdrs_unescape(char *s) {
    char *w = s;
    const char *r = s;
    while (*r) {
        if (*r == '\\' && r[1]) {
            r++;
            switch (*r) {
            case 't': *w++ = '\t'; break;
            case 'n': *w++ = '\n'; break;
            case 'r': *w++ = '\r'; break;
            case '\\': *w++ = '\\'; break;
            default:  *w++ = *r; break;
            }
            r++;
        } else {
            *w++ = *r++;
        }
    }
    *w = '\0';
}

/* One parsed sidecar row (uid + the six cached values + the stat guard
   captured at extraction). */
typedef struct HdrRow {
    char    *f[IH_NFIELDS];   /* owned, unescaped values ("" when absent) */
    uint32_t uid;
    size_t   fsize;           /* st_size guard captured at extraction */
    int64_t  mtime;           /* st_mtime guard captured at extraction */
    int64_t  ctime;           /* st_ctime guard captured at extraction */
} HdrRow;

static void hdrrow_free(HdrRow *r) {
    int i;
    for (i = 0; i < IH_NFIELDS; i++) free(r->f[i]);
    memset(r, 0, sizeof *r);
}

static void hdrrows_free(HdrRow *v, size_t n) {
    size_t i;
    for (i = 0; i < n; i++) hdrrow_free(&v[i]);
    free(v);
}

/* Parse the sidecar into a by-uid vector (duplicate uid: FIRST row wins).
   Missing file -> an empty (valid) vector.  Stops at the first malformed
   line, keeping prior rows (mirrors uidlist_load); the file is rewritten at
   close anyway.  Returns 0, or -1 on allocation failure. */
static int mail_hdrs_load(const Mbox *mb, uint32_t *uidvalidity,
                          HdrRow **rows_out, size_t *nrows_out) {
    char path[4200];
    char *buf = NULL, *p;
    size_t buflen = 0;
    HdrRow *v = NULL;
    size_t n = 0, cap = 0;
    uint32_t uv = 0;
    *uidvalidity = 0;
    *rows_out = NULL;
    *nrows_out = 0;
    if (hdrs_path(mb, path, sizeof path) != 0) return -1;
    if (read_file(path, &buf, &buflen) != 0) return 0;   /* missing: empty */
    p = buf;
    {
        /* header line: "<uidvalidity>" */
        unsigned long long a = 0;
        char *nl = strchr(p, '\n');
        if (nl) {
            if (sscanf(p, "%llu", &a) == 1 && a <= UINT32_MAX) uv = (uint32_t)a;
            p = nl + 1;
        } else {
            p = buf + buflen;   /* malformed header: no rows */
        }
    }
    while (*p) {
        char *nl = strchr(p, '\n');
        size_t ll = nl ? (size_t)(nl - p) : strlen(p);
        char *line, *tab, *uid_end;
        uint32_t uid;
        int i;
        if (ll == 0) { if (nl) { p = nl + 1; continue; } break; }
        line = malloc(ll + 1);
        if (!line) break;
        memcpy(line, p, ll);
        line[ll] = '\0';
        uid_end = NULL;
        uid = 0;
        /* uid field (digits), then exactly IH_NFIELDS TAB-separated fields */
        tab = strchr(line, '\t');
        if (!tab) { free(line); break; }
        uid_end = tab;
        {
            char *q = line;
            if (*q == '\0') { free(line); break; }
            for (; *q; q++) {
                if (*q < '0' || *q > '9') break;
                if (uid > (UINT32_MAX - (uint32_t)(*q - '0')) / 10u) {
                    uid = UINT32_MAX + 1u;   /* overflow marker */
                    break;
                }
                uid = uid * 10u + (uint32_t)(*q - '0');
            }
            if (q != uid_end || uid == 0) { free(line); break; }
        }
        {
            /* split the remaining IH_NFIELDS+2 fields on TAB: six values,
               then the size and mtime guard columns */
            char *q = uid_end + 1;
            bool ok = true;
            int ncols = IH_NFIELDS + 3;
            char *cols[12];
            for (i = 0; i < ncols; i++) {
                char *t = strchr(q, '\t');
                if (i == ncols - 1) {
                    if (t) { ok = false; break; }   /* extra column */
                    cols[i] = q;
                } else {
                    if (!t) { ok = false; break; }
                    *t = '\0';
                    cols[i] = q;
                    q = t + 1;
                }
            }
            if (!ok) { free(line); break; }
            if (n == cap) {
                size_t nc = cap ? cap * 2 : 32;
                HdrRow *nv = realloc(v, nc * sizeof *nv);
                if (!nv) { free(line); break; }
                v = nv;
                cap = nc;
            }
            for (i = 0; i < IH_NFIELDS; i++) {
                hdrs_unescape(cols[i]);
                v[n].f[i] = strdup(cols[i]);
                if (!v[n].f[i]) {
                    int j;
                    for (j = 0; j < i; j++) free(v[n].f[j]);
                    ok = false;
                    break;
                }
            }
            if (ok) {
                unsigned long long sz = 0;
                long long mt = 0, ct = 0;
                if (sscanf(cols[IH_NFIELDS], "%llu", &sz) == 1)
                    v[n].fsize = (size_t)sz;
                else ok = false;
                if (ok && sscanf(cols[IH_NFIELDS + 1], "%lld", &mt) == 1)
                    v[n].mtime = (int64_t)mt;
                else ok = false;
                if (ok && sscanf(cols[IH_NFIELDS + 2], "%lld", &ct) == 1)
                    v[n].ctime = ct;
                else ok = false;
            }
            if (!ok) { free(line); break; }
            v[n].uid = uid;
            n++;
        }
        free(line);
        if (!nl) break;
        p = nl + 1;
    }
    free(buf);
    *uidvalidity = uv;
    *rows_out = v;
    *nrows_out = n;
    return 0;
}

/* Save the per-mailbox header cache: header line "<uidvalidity>", then one
   TAB-escaped row per LOADED message cache (uids absent from the view are
   dropped, mirroring the uidlist prune).  Written via tmp+rename so the new
   file appears atomically.  Returns 0, or -1. */
static int mail_hdrs_save(Mbox *mb) {
    char path[4200], tmp[4200 + 16];
    FILE *f;
    size_t i;
    int rc = -1;
    if (hdrs_path(mb, path, sizeof path) != 0) return -1;
    snprintf(tmp, sizeof tmp, "%s.tmp", path);
    f = fopen(tmp, "wb");
    if (!f) return -1;
    if (fprintf(f, "%u\n", mb->uidvalidity) < 0) goto out;
    for (i = 0; i < mb->nmsgs; i++) {
        Imail *m = &mb->msgs[i];
        char *row;
        if (!m->hdr_loaded) continue;   /* never needed: not our row to write */
        /* Write the loaded block AS-IS.  Calling ensure_hdrs here would
           stat() EVERY hydrated row inline on the poll loop at close
           (15-30s on an NFS-scale FS for a 31.5k mailbox -> a LOGOUT
           freeze).  Rows hydrated from the sidecar but never touched are
           unchanged from what the sidecar already holds, so the rewrite
           is a no-op for them; rows the pump extracted/validated are
           already hdr_valid.  The (size,mtime,ctime) guard is re-checked
           by ensure_hdrs at USE time, so persisting a stale row cannot
           serve a stale value. */
        row = mail_hdrs_row(m);
        if (!row) goto out;
        if (fwrite(row, 1, strlen(row), f) != strlen(row) ||
            fputc('\n', f) == EOF) {
            free(row);
            goto out;
        }
        free(row);
    }
    if (fflush(f) != 0 || fclose(f) != 0) { f = NULL; goto out; }
    f = NULL;
    if (rename(tmp, path) != 0) goto out;
    rc = 0;
out:
    if (f) (void)fclose(f);
    if (rc != 0) (void)unlink(tmp);
    return rc;
}

/* Hydrate m's header cache from a sidecar row: pack the six values into
   ONE malloc'd block, install it, and adopt the row's stat guard.  The
   freshness of the guard is checked by imapd_mail_ensure_hdrs at use time.
   Returns 0, or -1 on allocation failure (m->hdr stays NULL). */
static int mail_hdrs_hydrate(Imail *m, const HdrRow *r) {
    char *blk = NULL;
    size_t off = 0, cap = 0;
    size_t fields_off[IH_NFIELDS];
    int i;
    for (i = 0; i < IH_NFIELDS; i++)
        if (mail_hdr_pack(&blk, &off, &cap, fields_off, i, r->f[i]) != 0) {
            free(blk);
            return -1;
        }
    if (m->hdr) free(m->hdr);
    m->hdr = blk;
    m->hdr_len = off;
    memcpy(m->fields_off, fields_off, sizeof fields_off);
    m->hdr_fsize = r->fsize;
    m->hdr_mtime = (time_t)r->mtime;
    m->hdr_ctime = r->ctime;
    m->hdr_loaded = true;
    return 0;
}


/* ------------------------------------------------------------------ */
/* Maildir flag suffix codec                                           */
/* ------------------------------------------------------------------ */

int imapd_flags_parse(const char *info, uint8_t *flags, char *unk,
                      size_t unksz) {
    size_t un = 0;
    if (!info || !flags || !unk || unksz == 0) return -1;
    *flags = 0;
    unk[0] = '\0';
    if (info[0] == '\0') return 0;          /* bare ":2," */
    if (info[0] != '2' || info[1] != ',') return -1;
    info += 2;
    for (; *info; info++) {
        switch (*info) {
        case 'D': *flags |= IMAIL_DRAFT;    break;
        case 'F': *flags |= IMAIL_FLAGGED;  break;
        case 'R': *flags |= IMAIL_ANSWERED; break;
        case 'S': *flags |= IMAIL_SEEN;     break;
        case 'T': *flags |= IMAIL_TRASHED;  break;
        default:
            if (un + 1 >= unksz) return -1; /* too many unknown letters */
            unk[un++] = *info;
            unk[un] = '\0';
            break;
        }
    }
    return 0;
}

int imapd_flags_encode(uint8_t flags, const char *unk, char *out,
                       size_t outsz) {
    size_t n = 0;
    if (!out || outsz < 3) return -1;
    out[n++] = '2';
    out[n++] = ',';
    if (flags & IMAIL_DRAFT)    out[n++] = 'D';
    if (flags & IMAIL_FLAGGED)  out[n++] = 'F';
    if (flags & IMAIL_ANSWERED) out[n++] = 'R';
    if (flags & IMAIL_SEEN)     out[n++] = 'S';
    if (flags & IMAIL_TRASHED)  out[n++] = 'T';
    if (unk) {
        for (; *unk; unk++) {
            if (n + 1 >= outsz) return -1;
            out[n++] = *unk;
        }
    }
    out[n] = '\0';
    return 0;
}

/* ------------------------------------------------------------------ */
/* Seq-sets                                                            */
/* ------------------------------------------------------------------ */

/* Parse one set token [start,end) (both inclusive, 1-based).  Returns the
   number of bytes consumed, or 0 on a malformed token. */
static size_t seqset_tok(const char *s, uint32_t star,
                         uint32_t *lo, uint32_t *hi) {
    uint64_t a = 0, b = 0;
    size_t n = 0;
    bool has_b = false, star_a = false, star_b = false;
    for (;;) {
        if (s[n] == '*') { star_a = true; n++; }
        else if (s[n] >= '1' && s[n] <= '9') {
            a = 0;
            do {
                a = a * 10 + (uint64_t)(s[n] - '0');
                if (a > UINT32_MAX) return 0;
                n++;
            } while (s[n] >= '0' && s[n] <= '9');
        } else return 0;
        if (s[n] == ':') {
            n++;
            if (s[n] == '*') { star_b = true; n++; }
            else if (s[n] >= '1' && s[n] <= '9') {
                b = 0;
                do {
                    b = b * 10 + (uint64_t)(s[n] - '0');
                    if (b > UINT32_MAX) return 0;
                    n++;
                } while (s[n] >= '0' && s[n] <= '9');
            } else return 0;   /* trailing ':' */
            has_b = true;
        }
        break;
    }
    *lo = star_a ? star : (uint32_t)a;
    *hi = (has_b && star_b) ? star : (has_b ? (uint32_t)b : *lo);
    if (*lo > *hi) { uint32_t t = *lo; *lo = *hi; *hi = t; }  /* "*:10" */
    return n;
}

int imapd_seqset_valid(const char *set) {
    uint32_t lo, hi;
    size_t n;
    if (!set || !set[0]) return 0;
    n = seqset_tok(set, 1, &lo, &hi);
    if (n == 0) return 0;
    set += n;
    while (*set == ',') {
        set++;
        n = seqset_tok(set, 1, &lo, &hi);
        if (n == 0) return 0;
        set += n;
    }
    return *set == '\0' ? 1 : 0;
}

bool imapd_seqset_has(const char *set, uint32_t n, uint32_t star) {
    uint32_t lo, hi;
    size_t k;
    if (!set || star == 0) return false;
    for (;;) {
        if (*set == '\0') return false;
        k = seqset_tok(set, star, &lo, &hi);
        if (k == 0) return false;   /* invalid set matches nothing */
        if (n >= lo && n <= hi) return true;
        if (set[k] == '\0') return false;
        set += k + 1;               /* skip ',' */
    }
}

/* ------------------------------------------------------------------ */
/* base64 decode (AUTH PLAIN)                                          */
/* ------------------------------------------------------------------ */

static int b64_val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

int imapd_b64_decode(const char *in, size_t inlen, unsigned char *out,
                     size_t outsz, size_t *outlen) {
    size_t i = 0, o = 0;
    if (!in || !out || !outlen) return -1;
    *outlen = 0;
    if (inlen % 4 != 0) return -1;
    while (i < inlen) {
        int v[4];
        unsigned acc;
        size_t pad = 0, keep;
        size_t j;
        for (j = 0; j < 4; j++) {
            char c = in[i + j];
            if (c == '=') {
                /* '=' only in the final quad, only as the last 1-2 bytes */
                if (i + 4 != inlen || j < 2) return -1;
                pad++;
                v[j] = 0;
            } else {
                if (pad > 0) return -1;   /* data after padding */
                v[j] = b64_val(c);
                if (v[j] < 0) return -1;
            }
        }
        acc = (unsigned)(((unsigned)v[0] << 18) | ((unsigned)v[1] << 12) |
                         ((unsigned)v[2] << 6)  | (unsigned)v[3]);
        keep = 3 - pad;
        if (o + keep > outsz) return -1;
        out[o++] = (unsigned char)(acc >> 16);
        if (keep > 1) out[o++] = (unsigned char)(acc >> 8);
        if (keep > 2) out[o++] = (unsigned char)acc;
        i += 4;
    }
    *outlen = o;
    return 0;
}

/* ------------------------------------------------------------------ */
/* LIST wildcards + name validation                                    */
/* ------------------------------------------------------------------ */

bool imapd_wildmat(const char *pat, const char *str) {
    while (*pat) {
        if (*pat == '*') {
            pat++;
            if (!*pat) return true;
            for (; *str; str++)
                if (imapd_wildmat(pat, str)) return true;
            return false;
        }
        if (*pat == '%') {
            pat++;
            if (!*pat) return strchr(str, '.') == NULL;
            for (; *str && *str != '.'; str++)
                if (imapd_wildmat(pat, str)) return true;
            return false;
        }
        {
            char a = *pat, b = *str;
            if (a >= 'A' && a <= 'Z') a = (char)(a + 32);
            if (b >= 'A' && b <= 'Z') b = (char)(b + 32);
            if (a != b) return false;
        }
        pat++;
        if (*str == '\0') return false;
        str++;
    }
    return *str == '\0';
}

bool imapd_user_ok(const char *u) {
    size_t n = 0;
    if (!u || !u[0]) return false;
    if (u[0] == '.') return false;               /* ".", "..", hidden */
    for (; u[n]; n++) {
        char c = u[n];
        bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                  (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-';
        if (!ok) return false;
    }
    return n <= IMAPD_MAX_USER;
}

int imapd_mbox_name_ok(const char *name) {
    size_t n = 0;
    if (!name || !name[0]) return -1;
    if (name[0] == '.') return -1;               /* hidden + "." + ".." */
    for (; name[n]; n++) {
        unsigned char c = (unsigned char)name[n];
        if (c < 0x20 || c == 0x7f) return -1;    /* no control bytes */
        if (c == '/') return -1;                 /* path traversal */
    }
    if (n > IMAPD_MAX_MBOX) return -1;
    if (name[n - 1] == '.') return -1;
    if (strstr(name, "..")) return -1;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Mailbox paths                                                       */
/* ------------------------------------------------------------------ */

int imapd_mbox_dir(const ImapdConfig *cfg, const char *user, const char *name,
                   char *out, size_t outsz) {
    if (!cfg || !cfg->root || !imapd_user_ok(user)) return -1;
    if (ascii_ieq_str(name, "INBOX")) {
        if (snprintf(out, outsz, "%s/%s/Inbox", cfg->root, user)
                >= (int)outsz) return -1;
        return 0;
    }
    if (imapd_mbox_name_ok(name) != 0) return -1;
    if (snprintf(out, outsz, "%s/%s/.%s", cfg->root, user, name)
            >= (int)outsz) return -1;
    return 0;
}

int imapd_mbox_create(const char *dir) {
    char sub[4096 + 8];
    if (snprintf(sub, sizeof sub, "%s/tmp", dir) >= (int)sizeof sub) return -1;
    if (mkdir_p(sub) != 0) return -1;
    if (snprintf(sub, sizeof sub, "%s/new", dir) >= (int)sizeof sub) return -1;
    if (mkdir_p(sub) != 0) return -1;
    if (snprintf(sub, sizeof sub, "%s/cur", dir) >= (int)sizeof sub) return -1;
    if (mkdir_p(sub) != 0) return -1;
    return 0;
}

int imapd_mbox_delete(const char *dir) {
    return rmrf(dir);
}

/* Generate a maildir-unique base filename:
   "<sec>.M<usec>P<pid>R<counter>.imapd".  The counter disambiguates files
   created within the same microsecond. */
static void unique_name(char *buf, size_t bufsz) {
    static unsigned long counter = 0;
    struct timespec ts;
    counter++;
    clock_gettime(CLOCK_REALTIME, &ts);
    snprintf(buf, bufsz, "%lld.M%ldP%luR%lu.imapd",
             (long long)ts.tv_sec, ts.tv_nsec / 1000,
             (unsigned long)getpid(), counter);
}

/* Build "<dir>/<sub>/<base>" plus the ":<info>" suffix when nonempty. */
static int msg_path(const char *dir, const char *sub, const char *base,
                    const char *info, char *out, size_t outsz) {
    int n;
    if (info && info[0])
        n = snprintf(out, outsz, "%s/%s/%s:%s", dir, sub, base, info);
    else
        n = snprintf(out, outsz, "%s/%s/%s", dir, sub, base);
    if (n < 0 || (size_t)n >= outsz) return -1;
    return 0;
}

/* Shared body of the deliver entry points.  Writes <dir>/tmp/<uniq> then
   renames into new/ (no flags) or cur/ (with the ":2," info suffix), and
   copies the maildir base name into base_out when given (so a caller can
   register a UID for the file).  Returns 0, or -1. */
static int deliver_file(const char *dir, const char *msg, size_t len,
                        uint8_t flags, const char *unk,
                        char *base_out, size_t base_sz) {
    char tmp[4096 + 8], dst[4096 + 64], uniq[128], info[32];
    bool has_flags = (flags != 0) || (unk && unk[0]);
    if (mail_data_has_ctl(msg, len)) return -1;
    if (imapd_mbox_create(dir) != 0) return -1;
    unique_name(uniq, sizeof uniq);
    if (msg_path(dir, "tmp", uniq, NULL, tmp, sizeof tmp) != 0) return -1;
    if (write_file(tmp, msg, len) != 0) return -1;
    info[0] = '\0';
    if (has_flags) {
        if (imapd_flags_encode(flags, unk, info, sizeof info) != 0) {
            (void)unlink(tmp);
            return -1;
        }
        if (msg_path(dir, "cur", uniq, info, dst, sizeof dst) != 0) {
            (void)unlink(tmp);
            return -1;
        }
    } else {
        if (msg_path(dir, "new", uniq, NULL, dst, sizeof dst) != 0) {
            (void)unlink(tmp);
            return -1;
        }
    }
    if (rename(tmp, dst) != 0) {
        (void)unlink(tmp);
        return -1;
    }
    if (base_out && base_sz) {
        size_t bl = strlen(uniq);
        if (bl + 1 > base_sz) return -1;
        memcpy(base_out, uniq, bl + 1);
    }
    return 0;
}

int imapd_mbox_deliver(const char *dir, const char *msg, size_t len,
                       uint8_t flags, const char *unk) {
    return deliver_file(dir, msg, len, flags, unk, NULL, 0);
}

/* ------------------------------------------------------------------ */
/* uidlist sidecar                                                     */
/* ------------------------------------------------------------------ */

/* (UidEnt is defined in imapd.h.) */
static void uidlist_free(UidEnt *v, size_t n) {
    size_t i;
    for (i = 0; i < n; i++) { free(v[i].base); free(v[i].mid); }
    free(v);
}

/* Open-addressed hash from base name -> index into a UidEnt array.  Used to
   make maildir scans O(n) instead of O(n^2) on large mailboxes. */
typedef struct BaseHash {
    char    **key;    /* owned base strings (NULL = empty slot) */
    uint32_t *val;    /* map array index */
    size_t    cap;    /* power of two */
} BaseHash;

static uint32_t bh_hash(const char *s) {
    uint32_t h = 2166136261u;
    while (*s) { h ^= (unsigned char)*s++; h *= 16777619u; }
    return h;
}

static void bh_free(BaseHash *h) {
    size_t i;
    if (!h->key) return;
    for (i = 0; i < h->cap; i++) free(h->key[i]);
    free(h->key);
    free(h->val);
    h->key = NULL;
    h->val = NULL;
    h->cap = 0;
}

static int bh_init(BaseHash *h, size_t n) {
    size_t cap = 16;
    memset(h, 0, sizeof *h);
    while (cap < n * 2) cap <<= 1;
    h->key = calloc(cap, sizeof *h->key);
    h->val = calloc(cap, sizeof *h->val);
    if (!h->key || !h->val) { bh_free(h); return -1; }
    h->cap = cap;
    return 0;
}

static int bh_put(BaseHash *h, const char *base, uint32_t val) {
    size_t i = bh_hash(base) & (h->cap - 1);
    while (h->key[i]) {
        if (strcmp(h->key[i], base) == 0) { h->val[i] = val; return 0; }
        i = (i + 1) & (h->cap - 1);
    }
    h->key[i] = strdup(base);
    if (!h->key[i]) return -1;   /* OOM: leave slot empty; caller must bail */
    h->val[i] = val;
    return 0;
}

static bool bh_get(const BaseHash *h, const char *base, uint32_t *val) {
    size_t i = bh_hash(base) & (h->cap - 1);
    while (h->key[i]) {
        if (strcmp(h->key[i], base) == 0) { *val = h->val[i]; return true; }
        i = (i + 1) & (h->cap - 1);
    }
    return false;
}

static int uidlist_path(const Mbox *mb, char *out, size_t outsz) {
    int n = snprintf(out, outsz, "%s/%s", mb->dir, IMAPD_UIDLIST_FILE);
    if (n < 0 || (size_t)n >= outsz) return -1;
    return 0;
}

/* Load "<uidvalidity> <uidnext>" + "uid base" lines.  Missing file yields
   an empty table (uidvalidity/uidnext come from the v/un defaults). */
static UidEnt *uidlist_load(const Mbox *mb, uint32_t *uidvalidity,
                            uint32_t *uidnext, size_t *n_out) {
    char path[4200];
    char *buf = NULL;
    size_t buflen = 0;
    UidEnt *v = NULL;
    size_t n = 0, cap = 0;
    char *p, *nl;
    if (uidlist_path(mb, path, sizeof path) != 0) return NULL;
    *n_out = 0;
    if (read_file(path, &buf, &buflen) != 0) return NULL;
    p = buf;
    /* header line */
    {
        unsigned long long a = 0, b = 0;
        if (sscanf(p, "%llu %llu", &a, &b) == 2) {
            *uidvalidity = (a > UINT32_MAX) ? 0 : (uint32_t)a;
            *uidnext = (b > UINT32_MAX) ? 1 : (uint32_t)b;
        }
        nl = strchr(p, '\n');
        if (!nl) { free(buf); return NULL; }
        p = nl + 1;
    }
    while (*p) {
        unsigned long long uid = 0;
        size_t bl;
        char *base;
        char *mid = NULL;
        uint64_t modseq = 1;
        char *rest;
        if (sscanf(p, "%llu", &uid) != 1) break;
        nl = strchr(p, '\n');
        if (!nl) nl = p + strlen(p);
        p += strspn(p, "0123456789");
        if (*p != ' ') break;   /* malformed line: keep what we have */
        p++;
        /* base: up to the next space or end of line */
        bl = (size_t)(nl - p);
        rest = memchr(p, ' ', bl);
        if (rest) bl = (size_t)(rest - p);
        if (bl == 0) break;
        base = malloc(bl + 1);
        if (!base) break;
        memcpy(base, p, bl);
        base[bl] = '\0';
        /* Optional " <modseq>" (CONDSTORE; older uidlists lack it) and then
           an optional " <message-id>".  Message-IDs never contain spaces. */
        if (rest) {
            char *q = rest + 1;
            unsigned long long ms = 0;
            if (sscanf(q, "%llu", &ms) == 1) {
                modseq = ms;
                q += strspn(q, "0123456789");
                if (*q == ' ' && q + 1 < nl) {
                    size_t mlen = (size_t)(nl - (q + 1));
                    mid = malloc(mlen + 1);
                    if (mid) { memcpy(mid, q + 1, mlen); mid[mlen] = '\0'; }
                }
            }
        }
        if (n == cap) {
            size_t nc = cap ? cap * 2 : 16;
            UidEnt *nv = realloc(v, nc * sizeof *nv);
            if (!nv) { free(base); free(mid); break; }
            v = nv;
            cap = nc;
        }
        v[n].base = base;
        v[n].mid = mid;
        v[n].uid = (uid == 0 || uid > UINT32_MAX) ? 0 : (uint32_t)uid;
        v[n].modseq = modseq;
        if (v[n].uid == 0) { free(base); free(mid); break; }
        n++;
        if (!*nl) break;
        p = nl + 1;
    }
    free(buf);
    *n_out = n;
    return v;
}

static int uidlist_save(const Mbox *mb, uint32_t uidvalidity,
                        uint32_t uidnext, const UidEnt *v, size_t n) {
    char path[4200];
    FILE *f;
    size_t i;
    if (uidlist_path(mb, path, sizeof path) != 0) return -1;
    f = fopen(path, "wb");
    if (!f) return -1;
    if (fprintf(f, "%u %u\n", uidvalidity, uidnext) < 0) goto fail;
    for (i = 0; i < n; i++) {
        if (v[i].mid && v[i].mid[0]) {
            if (fprintf(f, "%u %s %llu %s\n", v[i].uid, v[i].base,
                        (unsigned long long)v[i].modseq, v[i].mid) < 0)
                goto fail;
        } else {
            if (fprintf(f, "%u %s %llu\n", v[i].uid, v[i].base,
                        (unsigned long long)v[i].modseq) < 0)
                goto fail;
        }
    }
    if (fclose(f) != 0) return -1;
    return 0;
fail:
    (void)fclose(f);
    return -1;
}

/* ------------------------------------------------------------------ */
/* Scan (open/peek)                                                    */
/* ------------------------------------------------------------------ */

void imapd_mbox_close(Mbox *mb) {
    size_t i;
    if (!mb) return;
    /* Persist the header cache BEFORE freeing the view: the save walks the
       per-message blocks.  Dirty = this session extracted anything the
       sidecar does not hold (new files at scan, or lazy extraction). */
    if (mb->hdrs_dirty)
        (void)mail_hdrs_save(mb);
    mb->hdrs_dirty = false;
    for (i = 0; i < mb->nmsgs; i++) {
        free(mb->msgs[i].base);
        free(mb->msgs[i].path);
        free(mb->msgs[i].mid);
        free(mb->msgs[i].hdr);
    }
    free(mb->msgs);
    mb->msgs = NULL;
    mb->nmsgs = mb->cap = 0;
    /* Flush any STORE/EXPUNGE-driven uidlist changes made this session. */
    if (mb->uidlist_dirty && mb->uidmap)
        (void)uidlist_save(mb, mb->uidvalidity, mb->uidnext,
                           mb->uidmap, mb->nuidmap);
    uidlist_free(mb->uidmap, mb->nuidmap);
    mb->uidmap = NULL;
    mb->nuidmap = mb->uidmap_cap = 0;
    mb->uidlist_dirty = false;
}

/* Append one scanned file to the view (takes ownership of base/path; dups
   mid).  The header cache starts unhydrated; mbox_scan installs sidecar
   rows after the sort (it needs the final uid order). */
static int scan_add(Mbox *mb, uint32_t uid, uint8_t flags, const char *unk,
                    bool recent, const struct stat *st, uint64_t modseq,
                    char *base, char *path, const char *mid) {
    Imail *m;
    if (mb->nmsgs == mb->cap) {
        size_t nc = mb->cap ? mb->cap * 2 : 16;
        Imail *nv = realloc(mb->msgs, nc * sizeof *nv);
        if (!nv) return -1;
        mb->msgs = nv;
        mb->cap = nc;
    }
    m = &mb->msgs[mb->nmsgs++];
    m->uid = uid;
    m->flags = flags;
    m->modseq = modseq;
    if (modseq > mb->highestmodseq) mb->highestmodseq = modseq;
    snprintf(m->unk, sizeof m->unk, "%s", unk ? unk : "");
    m->recent = recent;
    m->internal_date = st->st_mtime;
    m->size = (size_t)st->st_size;
    m->base = base;
    m->path = path;
    m->mid = (mid && mid[0]) ? strdup(mid) : NULL;
    m->hdr = NULL;
    m->hdr_len = 0;
    memset(m->fields_off, 0, sizeof m->fields_off);
    m->hdr_fsize = 0;
    m->hdr_mtime = 0;
    m->hdr_loaded = false;
    m->hdr_valid = false;
    return 0;
}

static int imail_uid_cmp(const void *pa, const void *pb) {
    const Imail *a = pa, *b = pb;
    if (a->uid < b->uid) return -1;
    return a->uid == b->uid ? 0 : 1;
}

/* Scan one of new//cur/; assigns UIDs from the uidlist map or uidnext.
   New files get their Message-ID AND cached header fields extracted here
   (the single natural mutation point: uid assignment happens at scan time,
   not at ingest), and *hdrs_dirty_out is set so the close-time save persists
   them. */
static int scan_subdir(Mbox *mb, const char *sub, bool is_new,
                       UidEnt **map, size_t *nmap, size_t *map_cap,
                       uint32_t *uidnext, bool *changed,
                       const BaseHash *bh, bool *hdrs_dirty_out) {
    char sub_dir[4096 + 8];
    DIR *d;
    struct dirent *e;
    char *new_hdrblk = NULL;
    size_t new_hdrblk_len = 0;
    if (snprintf(sub_dir, sizeof sub_dir, "%s/%s", mb->dir, sub)
            >= (int)sizeof sub_dir) return -1;
    d = opendir(sub_dir);
    if (!d) return -1;   /* missing tmp/new/cur: caller creates first */
    while ((e = readdir(d)) != NULL) {
        char path[4096 + 64], info[32];
        const char *colon, *inf;
        struct stat st;
        uint32_t uid = 0;
        uint64_t modseq = 1;
        uint8_t flags = 0;
        size_t bl;
        char *base, *fpath;
        const char *mid = NULL;
        if (e->d_name[0] == '.') continue;
        colon = strchr(e->d_name, ':');
        if (colon) {
            bl = (size_t)(colon - e->d_name);
            inf = colon + 1;
        } else {
            bl = strlen(e->d_name);
            inf = NULL;
        }
        info[0] = '\0';
        if (inf && imapd_flags_parse(inf, &flags, info, sizeof info) != 0)
            continue;   /* not a maildir message name we manage */
        if (snprintf(path, sizeof path, "%s/%s", sub_dir, e->d_name)
                >= (int)sizeof path) continue;
        if (stat(path, &st) != 0 || !S_ISREG(st.st_mode)) continue;
        {
            /* Look the base up in the uidlist (O(1) via hash). */
            char tmp[4096 + 64];
            uint32_t idx;
            if (bl < sizeof tmp) {
                memcpy(tmp, e->d_name, bl);
                tmp[bl] = '\0';
                if (bh && bh_get(bh, tmp, &idx)) {
                    uid = (*map)[idx].uid;
                    modseq = (*map)[idx].modseq;
                    mid = (*map)[idx].mid;
                }
            }
        }
        if (uid == 0) {
            char *hdrblk = NULL;
            size_t hl = 0;
            uid = (*uidnext)++;
            modseq = (*uidnext);   /* new message: modseq >= any prior */
            *changed = true;
            /* record the assignment so the next save persists it */
            if (*nmap == *map_cap) {
                size_t nc = *map_cap ? *map_cap * 2 : 16;
                UidEnt *nv = realloc(*map, nc * sizeof **map);
                if (!nv) continue;
                *map = nv;
                *map_cap = nc;
            }
            (*map)[*nmap].base = malloc(bl + 1);
            if ((*map)[*nmap].base) {
                memcpy((*map)[*nmap].base, e->d_name, bl);
                (*map)[*nmap].base[bl] = '\0';
                (*map)[*nmap].uid = uid;
                (*map)[*nmap].modseq = modseq;
                /* extract the Message-ID AND the cached header fields now
                   (ONE bounded header read for both) so they persist in the
                   sidecars and future searches never re-read the file */
                if (imapd_read_hdr(path, &hdrblk, &hl) == 0) {
                    (*map)[*nmap].mid =
                        imapd_msgid_of_buf(hdrblk, hl);
                    if (!(*map)[*nmap].mid && hl >= IMAPD_HDR_CAP) {
                        /* Degenerate: >256KB of headers with no blank-line
                           end, so the capped block hid the Message-ID —
                           fall back to a full read (scan-time only, once
                           per new message). */
                        char *full = NULL;
                        size_t fl = 0;
                        if (read_file(path, &full, &fl) == 0) {
                            (*map)[*nmap].mid = imapd_msgid_of_buf(full, fl);
                            free(full);
                        }
                    }
                    /* hand the block to the view entry scan_add appends
                       below; the stat guard is the one just taken */
                    new_hdrblk = hdrblk;   /* borrowed until after scan_add */
                    new_hdrblk_len = hl;
                } else {
                    (*map)[*nmap].mid = NULL;
                }
                mid = (*map)[*nmap].mid;
                (*nmap)++;
                *hdrs_dirty_out = true;
            }
        }
        base = malloc(bl + 1);
        fpath = malloc(strlen(path) + 1);
        if (!base || !fpath) { free(base); free(fpath); free(new_hdrblk); continue; }
        memcpy(base, e->d_name, bl);
        base[bl] = '\0';
        strcpy(fpath, path);
        if (scan_add(mb, uid, flags, info, is_new, &st, modseq, base, fpath,
                     mid) != 0) {
            free(base);
            free(fpath);
            free(new_hdrblk);
        } else if (new_hdrblk) {
            /* install the scan-time extraction into the just-appended view
               entry: it is valid for the file exactly as scanned */
            Imail *m = &mb->msgs[mb->nmsgs - 1];
            if (mail_hdr_extract(m, new_hdrblk, new_hdrblk_len) == 0) {
                m->hdr_fsize = (size_t)st.st_size;
                m->hdr_mtime = st.st_mtime;
                m->hdr_valid = true;
            }
        }
        if (new_hdrblk) { free(new_hdrblk); new_hdrblk = NULL; }
    }
    closedir(d);
    return 0;
}

static int mbox_scan(Mbox *mb, const ImapdConfig *cfg, const char *user,
                     const char *name, bool move_new) {
    UidEnt *map = NULL;
    size_t nmap = 0, map_cap = 0, i;
    uint32_t uidvalidity = (uint32_t)time(NULL);
    uint32_t uidnext = 1;
    bool changed = false;
    bool map_owned = false;
    bool hdrs_dirty = false;
    HdrRow *hrows = NULL;
    size_t nhrows = 0;
    uint32_t huv = 0;
    int rc = -1;

    memset(mb, 0, sizeof *mb);
    if (imapd_mbox_dir(cfg, user, name, mb->dir, sizeof mb->dir) != 0)
        return -1;
    if (imapd_mbox_create(mb->dir) != 0) return -1;

    map = uidlist_load(mb, &uidvalidity, &uidnext, &nmap);
    if (uidnext == 0) uidnext = 1;
    map_owned = (map != NULL);
    map_cap = nmap;

    /* Index the uidlist by base so the two scan_subdir passes are O(n). */
    {
        BaseHash bht;
        if (bh_init(&bht, nmap) != 0) goto out;
        for (i = 0; i < nmap; i++)
            if (bh_put(&bht, map[i].base, (uint32_t)i) != 0) {
                bh_free(&bht);
                goto out;
            }
        if (scan_subdir(mb, "new", true, &map, &nmap, &map_cap, &uidnext,
                        &changed, &bht, &hdrs_dirty) != 0) {
            bh_free(&bht);
            goto out;
        }
        if (scan_subdir(mb, "cur", false, &map, &nmap, &map_cap, &uidnext,
                        &changed, &bht, &hdrs_dirty) != 0) {
            bh_free(&bht);
            goto out;
        }
        bh_free(&bht);
    }

    if (mb->nmsgs > 1)
        qsort(mb->msgs, mb->nmsgs, sizeof *mb->msgs, imail_uid_cmp);

    /* Hydrate the header cache from the sidecar (rows whose uid is absent
       from the view, or whose uidvalidity differs, are simply not offered).
       scan_add already installed blocks for brand-new files; those were
       extracted from the file itself, so a sidecar row can only be older. */
    if (mail_hdrs_load(mb, &huv, &hrows, &nhrows) == 0 && huv != 0 &&
        huv == uidvalidity) {
        size_t ri = 0, mi = 0;   /* both walk uid-ascending order */
        while (ri < nhrows && mi < mb->nmsgs) {
            Imail *m = &mb->msgs[mi];
            if (m->hdr_loaded) { mi++; continue; }
            if (hrows[ri].uid < m->uid) { ri++; continue; }
            if (hrows[ri].uid > m->uid) { mi++; continue; }
            if (mail_hdrs_hydrate(m, &hrows[ri]) != 0) { rc = -1; goto out; }
            ri++;
            mi++;
        }
    }
    hdrrows_free(hrows, nhrows);
    hrows = NULL;
    nhrows = 0;
    mb->hdrs_dirty = hdrs_dirty;

    /* Prune uidlist entries whose file vanished (O(n) via a base hash). */
    {
        BaseHash seen;
        if (bh_init(&seen, mb->nmsgs) == 0) {
            int ok = 0;
            for (i = 0; i < mb->nmsgs; i++)
                if (bh_put(&seen, mb->msgs[i].base, mb->msgs[i].uid) != 0) {
                    ok = -1;
                    break;
                }
            if (ok != 0) { bh_free(&seen); goto out; }
            for (i = 0; i < nmap; ) {
                uint32_t sv;
                if (bh_get(&seen, map[i].base, &sv) &&
                    sv == map[i].uid) {
                    i++;
                } else {
                    free(map[i].base);
                    free(map[i].mid);
                    map[i] = map[nmap - 1];
                    nmap--;
                    changed = true;
                }
            }
            bh_free(&seen);
        }
    }

    /* SELECT semantics: new/ files move to cur/ (still \Recent here). */
    if (move_new) {
        for (i = 0; i < mb->nmsgs; i++) {
            char dst[4096 + 64], info[32];
            Imail *m = &mb->msgs[i];
            if (!m->recent) continue;
            if (imapd_flags_encode(m->flags, m->unk, info, sizeof info) != 0)
                continue;
            if (msg_path(mb->dir, "cur", m->base, info, dst, sizeof dst) != 0)
                continue;
            if (rename(m->path, dst) == 0) {
                free(m->path);
                m->path = strdup(dst);
            }
        }
    }

    mb->uidvalidity = uidvalidity;
    mb->uidnext = uidnext;
    /* Keep the uidlist in memory for this session (saved on close) so that
       STORE can bump one modseq without rewriting the whole sidecar.  If the
       scan changed it, persist immediately so a crash mid-session loses
       nothing. */
    if (map) {
        mb->uidmap = map;
        mb->nuidmap = nmap;
        mb->uidmap_cap = map_cap;
        map_owned = false;   /* ownership transferred to the Mbox */
        if (changed) {
            if (uidlist_save(mb, uidvalidity, uidnext, map, nmap) != 0)
                goto out;
        }
    }
    rc = 0;
out:
    hdrrows_free(hrows, nhrows);
    if (rc != 0) {
        if (map_owned) uidlist_free(map, nmap);
        imapd_mbox_close(mb);
    }
    return rc;
}

int imapd_mbox_open(const ImapdConfig *cfg, const char *user,
                    const char *name, Mbox *mb) {
    return mbox_scan(mb, cfg, user, name, true);
}

int imapd_mbox_peek(const ImapdConfig *cfg, const char *user,
                    const char *name, Mbox *mb) {
    return mbox_scan(mb, cfg, user, name, false);
}

/* Cheap "did anything land in new/ ?" probe.  Unlike a full mbox scan (which
   stats every message and is O(n^2) on a large mailbox via scan_subdir's
   linear uidlist lookup), this just checks whether the new/ subdir has any
   files.  Used to gate refresh_selected so an IDLE/NOOP tick does not re-scan
   a 30k-message mailbox every second. */
bool imapd_mbox_has_new(const ImapdConfig *cfg, const char *user,
                        const char *name) {
    char sub_dir[4096 + 8];
    DIR *d;
    struct dirent *e;
    bool any = false;
    if (imapd_mbox_dir(cfg, user, name, sub_dir, sizeof sub_dir) != 0)
        return false;
    if (snprintf(sub_dir + strlen(sub_dir), sizeof sub_dir - strlen(sub_dir),
                 "/new") >= (int)(sizeof sub_dir - strlen(sub_dir)))
        return false;
    d = opendir(sub_dir);
    if (!d) return false;
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.') continue;
        any = true;
        break;
    }
    closedir(d);
    return any;
}

Imail *imapd_mbox_find(Mbox *mb, uint32_t uid) {
    size_t i;
    if (!mb) return NULL;
    for (i = 0; i < mb->nmsgs; i++)
        if (mb->msgs[i].uid == uid) return &mb->msgs[i];
    return NULL;
}

int imapd_mbox_store(Mbox *mb, uint32_t uid, uint8_t flags) {
    char dst[4096 + 64], info[32];
    size_t i;
    Imail *m = imapd_mbox_find(mb, uid);
    if (!m) return -1;
    if (imapd_flags_encode(flags, m->unk, info, sizeof info) != 0) return -1;
    if (msg_path(mb->dir, "cur", m->base, info, dst, sizeof dst) != 0)
        return -1;
    if (rename(m->path, dst) != 0) return -1;
    free(m->path);
    m->path = strdup(dst);
    if (!m->path) return -1;
    m->flags = flags;
    /* CONDSTORE: a flag change bumps this message's modseq.  Use the
       mailbox's next uid as a monotonic counter (uidnext grows on every
       delivery and is persisted); guarantee strictly-greater-than. */
    if (++mb->highestmodseq == 0) mb->highestmodseq = 1;
    m->modseq = mb->highestmodseq;
    /* Update the in-memory uidlist entry (persisted on close). */
    for (i = 0; i < mb->nuidmap; i++) {
        if (mb->uidmap[i].uid == uid) {
            mb->uidmap[i].modseq = m->modseq;
            mb->uidlist_dirty = true;
            return 0;
        }
    }
    /* uid absent from the map (shouldn't happen): append it. */
    if (mb->nuidmap == mb->uidmap_cap) {
        size_t nc = mb->uidmap_cap ? mb->uidmap_cap * 2 : 16;
        UidEnt *nv = realloc(mb->uidmap, nc * sizeof *nv);
        if (!nv) return -1;
        mb->uidmap = nv;
        mb->uidmap_cap = nc;
    }
    mb->uidmap[mb->nuidmap].base = strdup(m->base);
    if (!mb->uidmap[mb->nuidmap].base) return -1;
    mb->uidmap[mb->nuidmap].mid = m->mid ? strdup(m->mid) : NULL;
    mb->uidmap[mb->nuidmap].uid = uid;
    mb->uidmap[mb->nuidmap].modseq = m->modseq;
    mb->nuidmap++;
    mb->uidlist_dirty = true;
    return 0;
}

/* Remove one uid from the uidlist file (best-effort prune; the next open
   would prune anyway). */
static void uidmap_remove(Mbox *mb, uint32_t uid) {
    size_t i;
    for (i = 0; i < mb->nuidmap; i++) {
        if (mb->uidmap[i].uid != uid) continue;
        free(mb->uidmap[i].base);
        free(mb->uidmap[i].mid);
        mb->uidmap[i] = mb->uidmap[mb->nuidmap - 1];
        mb->nuidmap--;
        mb->uidlist_dirty = true;
        return;
    }
}

int imapd_mbox_expunge(Mbox *mb, uint32_t uid) {
    size_t i;
    for (i = 0; i < mb->nmsgs; i++) {
        if (mb->msgs[i].uid != uid) continue;
        (void)unlink(mb->msgs[i].path);
        free(mb->msgs[i].base);
        free(mb->msgs[i].path);
        free(mb->msgs[i].mid);
        free(mb->msgs[i].hdr);
        memmove(&mb->msgs[i], &mb->msgs[i + 1],
                (mb->nmsgs - i - 1) * sizeof *mb->msgs);
        mb->nmsgs--;
        uidmap_remove(mb, uid);
        return 0;
    }
    return -1;
}

/* Register the message file just placed into dest_name's cur/ by assigning it
   a fresh UID from the destination's uidlist sidecar.  This is O(1) in the
   destination size: it only loads/appends/saves the uidlist file, never a full
   rescan.  That matters because MOVE/COPY run once per message — rescanning a
   large destination (e.g. a 30k-message Archive) per message blocked the poll
   loop for seconds, so a queued client move timed out, its EXPUNGE removed the
   Inbox copy, and the archive copy was never registered: lost mail. */
static int mbox_register(const ImapdConfig *cfg, const char *user,
                         const char *dest_name, const char *base,
                         const char *mid,
                         uint32_t *uv_out, uint32_t *uid_out) {
    Mbox d;
    uint32_t uidvalidity, uidnext, uid;
    uint64_t modseq;
    size_t n, i;
    UidEnt *v;
    memset(&d, 0, sizeof d);
    if (imapd_mbox_dir(cfg, user, dest_name, d.dir, sizeof d.dir) != 0)
        return -1;
    if (imapd_mbox_create(d.dir) != 0) return -1;
    uidvalidity = (uint32_t)time(NULL);
    uidnext = 1;
    v = uidlist_load(&d, &uidvalidity, &uidnext, &n);
    if (uidnext == 0) uidnext = 1;
    /* idempotent: re-moving an already-archived base must not duplicate */
    for (i = 0; i < n; i++) {
        if (strcmp(v[i].base, base) == 0) {
            if (uv_out) *uv_out = uidvalidity;
            if (uid_out) *uid_out = v[i].uid;
            uidlist_free(v, n);
            return 0;
        }
    }
    uid = uidnext++;
    if (uid == 0) uid = 1;            /* UINT32_MAX rollover guard */
    modseq = uidnext;                  /* mirror scan_subdir: > any prior */
    {
        UidEnt *nv = realloc(v, (n + 1) * sizeof *v);
        if (!nv) { uidlist_free(v, n); return -1; }
        v = nv;
    }
    v[n].base = strdup(base);
    if (!v[n].base) { uidlist_free(v, n); return -1; }
    v[n].mid = (mid && mid[0]) ? strdup(mid) : NULL;
    v[n].uid = uid;
    v[n].modseq = modseq;
    n++;
    if (uidlist_save(&d, uidvalidity, uidnext, v, n) != 0) {
        free(v[n - 1].base);
        free(v[n - 1].mid);
        uidlist_free(v, n - 1);
        return -1;
    }
    if (uv_out) *uv_out = uidvalidity;
    if (uid_out) *uid_out = uid;
    uidlist_free(v, n);
    return 0;
}

/* Deliver msg into mailbox `name` and register a fresh UID for the new file
   in its uidlist sidecar (an O(1) append, no rescan) so the caller can report
   APPENDUID (RFC 4315).  On success returns 0 and sets *uv_out and *uid_out; a
   message that was delivered but whose UID could not be registered returns 0
   with *uid_out = 0 (the next scan assigns it then).  Returns -1 only when
   the delivery itself failed.

   The caller must NOT have the same mailbox open in this session: closing
   that view later would re-save its (older) in-memory uidmap over the entry
   registered here.  imapd_append closes/reopens the selected view around
   this call for exactly that reason. */
int imapd_mbox_deliver_uid(const ImapdConfig *cfg, const char *user,
                           const char *name, const char *msg, size_t len,
                           uint8_t flags, const char *unk,
                           uint32_t *uv_out, uint32_t *uid_out) {
    char dir[4096], base[128];
    char *mid;
    uint32_t uv = 0, uid = 0;
    if (uv_out) *uv_out = 0;
    if (uid_out) *uid_out = 0;
    if (!cfg || !user || !name || !msg) return -1;
    if (imapd_mbox_dir(cfg, user, name, dir, sizeof dir) != 0) return -1;
    if (deliver_file(dir, msg, len, flags, unk, base, sizeof base) != 0)
        return -1;
    /* The message is durably delivered now; a registration failure below
       must not turn the APPEND into an error. */
    mid = imapd_msgid_of_buf(msg, len);
    if (mbox_register(cfg, user, name, base, mid, &uv, &uid) == 0) {
        if (uv_out) *uv_out = uv;
        if (uid_out) *uid_out = uid;
    }
    free(mid);
    return 0;
}

/* Move (move=true) or copy (move=false) the message with uid out of mb into
   the mailbox named dest_name (a new mailbox is created if needed).  The
   destination gets a fresh UID via an O(1) uidlist append (no rescan); on MOVE
   the source view (mb) is compacted and its uidlist entry dropped, mirroring
   expunge.  When non-NULL, *uv_out and *uid_out receive the destination's
   UIDVALIDITY and the UID the message was registered under (for UIDPLUS
   COPYUID).  Returns 0. */
int imapd_mbox_file(const ImapdConfig *cfg, const char *user, Mbox *mb,
                    uint32_t uid, const char *dest_name, bool move,
                    uint32_t *uv_out, uint32_t *uid_out) {
    char destdir[4096], dst[4096 + 64], info[32];
    Imail *m = imapd_mbox_find(mb, uid);
    if (!m) return -1;
    if (imapd_mbox_dir(cfg, user, dest_name, destdir, sizeof destdir) != 0)
        return -1;
    if (imapd_mbox_create(destdir) != 0) return -1;
    if (imapd_flags_encode(m->flags, m->unk, info, sizeof info) != 0)
        return -1;
    if (msg_path(destdir, "cur", m->base, info, dst, sizeof dst) != 0)
        return -1;
    if (move) {
        if (rename(m->path, dst) != 0) return -1;
    } else {
        int fd, wfd;
        char buf[16384];
        ssize_t r;
        fd = open(m->path, O_RDONLY);
        if (fd < 0) return -1;
        wfd = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (wfd < 0) { close(fd); return -1; }
        while ((r = read(fd, buf, sizeof buf)) > 0) {
            if (write(wfd, buf, (size_t)r) != r) {
                close(fd); close(wfd); (void)unlink(dst);
                return -1;
            }
        }
        close(fd);
        if (close(wfd) != 0 || r < 0) { (void)unlink(dst); return -1; }
    }
    /* register the new file with a fresh UID in the destination (O(1),
       no full-destination rescan) */
    if (mbox_register(cfg, user, dest_name, m->base, m->mid,
                      uv_out, uid_out) != 0)
        return -1;
    if (move) {
        /* drop the source view entry (uid found again: the view is live) */
        uidmap_remove(mb, uid);
        for (size_t i = 0; i < mb->nmsgs; i++) {
            if (mb->msgs[i].uid != uid) continue;
            free(mb->msgs[i].base);
            free(mb->msgs[i].path);
            free(mb->msgs[i].mid);
            free(mb->msgs[i].hdr);
            memmove(&mb->msgs[i], &mb->msgs[i + 1],
                    (mb->nmsgs - i - 1) * sizeof *mb->msgs);
            mb->nmsgs--;
            break;
        }
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* LIST + subscriptions                                                */
/* ------------------------------------------------------------------ */

int imapd_mbox_list(const ImapdConfig *cfg, const char *user,
                    const char *pattern, char ***out, size_t *nout) {
    char userdir[4096 + IMAPD_MAX_USER];
    DIR *d;
    struct dirent *e;
    char **v = NULL;
    size_t n = 0, cap = 0;
    *out = NULL;
    *nout = 0;
    if (!imapd_user_ok(user)) return -1;
    if (snprintf(userdir, sizeof userdir, "%s/%s", cfg->root, user)
            >= (int)sizeof userdir) return -1;
    d = opendir(userdir);
    if (!d) return 0;   /* no folders yet */
    while ((e = readdir(d)) != NULL) {
        struct stat st;
        char path[4096 + IMAPD_MAX_MBOX];
        char *dup;
        if (e->d_name[0] != '.' || e->d_name[1] == '\0') continue;
        if (imapd_mbox_name_ok(e->d_name + 1) != 0) continue;
        if (snprintf(path, sizeof path, "%s/%s", userdir, e->d_name)
                >= (int)sizeof path) continue;
        if (stat(path, &st) != 0 || !S_ISDIR(st.st_mode)) continue;
        if (!imapd_wildmat(pattern, e->d_name + 1)) continue;
        if (n == cap) {
            size_t nc = cap ? cap * 2 : 8;
            char **nv = realloc(v, nc * sizeof *nv);
            if (!nv) goto fail;
            v = nv;
            cap = nc;
        }
        dup = strdup(e->d_name + 1);
        if (!dup) goto fail;
        v[n++] = dup;
    }
    closedir(d);
    *out = v;
    *nout = n;
    return 0;
fail:
    closedir(d);
    for (; n > 0; n--) free(v[n - 1]);
    free(v);
    return -1;
}

int imapd_sub_write(const char *path, const char *name, bool add) {
    char *buf = NULL;
    size_t buflen = 0;
    size_t rlen;
    const char *p;
    char *nb;
    size_t nl;
    if (imapd_sub_has(path, name) == add) return 0;   /* already in state */
    read_file(path, &buf, &buflen);                   /* ok when missing */
    rlen = strlen(name);
    /* Remove the line when unsubscribing. */
    if (!add && buf) {
        char *w = buf;
        p = buf;
        while (*p) {
            size_t ll = strcspn(p, "\n");
            if (ll == rlen && memcmp(p, name, rlen) == 0) {
                p += ll;
                if (*p == '\n') p++;
                continue;
            }
            memmove(w, p, ll);
            w += ll;
            p += ll;
            if (*p == '\n') { *w++ = '\n'; p++; }
        }
        *w = '\0';
        nl = (size_t)(w - buf);
        if (write_file(path, buf, nl) != 0) { free(buf); return -1; }
        free(buf);
        return 0;
    }
    /* Append when subscribing. */
    nl = buflen + rlen + 1;
    nb = realloc(buf, nl + 1);
    if (!nb) { free(buf); return -1; }
    if (buflen > 0 && nb[buflen - 1] != '\n') nb[buflen++] = '\n';
    memcpy(nb + buflen, name, rlen);
    nb[buflen + rlen] = '\n';
    if (write_file(path, nb, buflen + rlen + 1) != 0) { free(nb); return -1; }
    free(nb);
    return 0;
}

bool imapd_sub_has(const char *path, const char *name) {
    char *buf = NULL;
    size_t buflen = 0;
    const char *p;
    size_t rlen = strlen(name);
    bool found = false;
    if (read_file(path, &buf, &buflen) != 0) return false;
    p = buf;
    while (*p) {
        size_t ll = strcspn(p, "\n");
        if (ll == rlen && memcmp(p, name, rlen) == 0) { found = true; break; }
        p += ll;
        if (*p == '\n') p++;
    }
    free(buf);
    return found;
}

/* ------------------------------------------------------------------ */
/* Credentials                                                         */
/* ------------------------------------------------------------------ */

static void auth_free(ImapdServer *srv) {
    size_t i;
    for (i = 0; i < srv->ncreds; i++) {
        free(srv->creds[i].user);
        free(srv->creds[i].pass);
    }
    free(srv->creds);
    srv->creds = NULL;
    srv->ncreds = 0;
}

int imapd_auth_load(const ImapdConfig *cfg, ImapdServer *srv) {
    char path[4096];
    char *buf = NULL;
    size_t buflen = 0;
    const char *p;
    int n;
    auth_free(srv);
    n = snprintf(path, sizeof path, "%s/%s", cfg->root, IMAPD_PASSWD_FILE);
    if (n < 0 || (size_t)n >= sizeof path) return -1;
    if (read_file(path, &buf, &buflen) != 0) return 0;   /* none yet */
    p = buf;
    while (*p) {
        size_t ll = strcspn(p, "\n");
        char *line = malloc(ll + 1);
        char *colon;
        char *user = NULL, *pass = NULL;
        if (!line) { free(buf); return -1; }
        memcpy(line, p, ll);
        line[ll] = '\0';
        p += ll;
        if (*p == '\n') p++;
        if (line[0] == '#' || line[0] == '\0') { free(line); continue; }
        colon = strchr(line, ':');
        if (!colon) { free(line); continue; }
        *colon = '\0';
        user = line;
        pass = colon + 1;
        if (imapd_user_ok(user) && pass[0]) {
            ImapdCred *nv = realloc(srv->creds,
                                    (srv->ncreds + 1) * sizeof *nv);
            if (!nv) { free(line); free(buf); return -1; }
            srv->creds = nv;
            srv->creds[srv->ncreds].user = strdup(user);
            srv->creds[srv->ncreds].pass = strdup(pass);
            if (!srv->creds[srv->ncreds].user ||
                !srv->creds[srv->ncreds].pass) {
                free(srv->creds[srv->ncreds].user);
                free(srv->creds[srv->ncreds].pass);
                free(line);
                free(buf);
                return -1;
            }
            srv->ncreds++;
        }
        free(line);
    }
    free(buf);
    return 0;
}

/* Constant-time byte comparison over the LONGER of the two lengths.  Lengths
 * are folded in too, so the only observable difference is a single uniform
 * loop over max(alen, blen) bytes.  (Port of outbox_auth.c's ct_equal.) */
static bool ct_equal(const unsigned char *a, size_t alen,
                     const unsigned char *b, size_t blen) {
    volatile unsigned char diff = 0;
    size_t n = alen > blen ? alen : blen;
    size_t i;
    for (i = 0; i < n; i++) {
        unsigned char ca = (i < alen) ? a[i] : 0;
        unsigned char cb = (i < blen) ? b[i] : 0;
        diff = (unsigned char)(diff | (ca ^ cb));
    }
    return diff == 0;
}

bool imapd_auth_check(const ImapdServer *srv, const char *user,
                      const char *pass) {
    /* Dummy candidate so an unknown user still runs a full constant-time
       compare (hides user existence; mirrors outbox_auth_check). */
    static const char dummy_pass[] = "visage-dummy-imapd-password";
    const char *cand = dummy_pass;
    size_t clen = sizeof dummy_pass - 1;
    size_t i;

    if (!srv || !user || !pass) return false;
    for (i = 0; i < srv->ncreds; i++) {
        if (strcmp(srv->creds[i].user, user) == 0) {
            cand = srv->creds[i].pass;
            clen = strlen(srv->creds[i].pass);
            break;
        }
    }
    return ct_equal((const unsigned char *)pass, strlen(pass),
                    (const unsigned char *)cand, clen);
}

/* ---- brute-force protection (per-IP failed-auth lockout) ---- */

static ImapdFail *auth_fail_find(ImapdServer *srv, const unsigned char *ip,
                                 uint8_t len) {
    size_t i;
    for (i = 0; i < srv->nfails; i++)
        if (srv->fails[i].len == len &&
            memcmp(srv->fails[i].ip, ip, len) == 0)
            return &srv->fails[i];
    return NULL;
}

/* Record a failed auth for this peer.  When the threshold is crossed within
   the window, the IP is locked out. */
void imapd_auth_fail(ImapdServer *srv, const unsigned char *ip, uint8_t len,
                     time_t now) {
    ImapdFail *f;
    if (!srv || !ip || !len) return;
    f = auth_fail_find(srv, ip, len);
    if (!f) {
        if (srv->nfails >= IMAPD_AUTH_MAX_TRACKED) {
            /* Table full: evict the oldest expired entry (or, if none,
               the longest-idle one) so a new attacker isn't silently
               un-tracked while old state lingers. */
            size_t j, ev = 0;
            for (j = 1; j < srv->nfails; j++)
                if (srv->fails[j].first_fail < srv->fails[ev].first_fail)
                    ev = j;
            f = &srv->fails[ev];
            memset(f, 0, sizeof *f);
        } else {
            f = &srv->fails[srv->nfails++];
        }
        memcpy(f->ip, ip, len);
        f->len = len;
        f->count = 0;
        f->first_fail = 0;
        f->lock_until = 0;
    }
    if (now - f->first_fail > IMAPD_AUTH_WINDOW_SEC) {
        f->first_fail = now;   /* reset the window */
        f->count = 0;
    }
    f->count++;
    if (f->count >= IMAPD_AUTH_MAX_FAILS)
        f->lock_until = now + IMAPD_AUTH_LOCKOUT_SEC;
}

/* Clear any lockout/tally for this peer after a successful auth. */
void imapd_auth_clear(ImapdServer *srv, const unsigned char *ip, uint8_t len) {
    ImapdFail *f;
    if (!srv || !ip || !len) return;
    f = auth_fail_find(srv, ip, len);
    if (!f) return;
    f->count = 0;
    f->first_fail = 0;
    f->lock_until = 0;
}

/* True if this peer is currently locked out of auth. */
bool imapd_auth_blocked(ImapdServer *srv, const unsigned char *ip,
                        uint8_t len, time_t now) {
    ImapdFail *f;
    if (!srv || !ip || !len) return false;
    f = auth_fail_find(srv, ip, len);
    if (!f) return false;
    if (f->lock_until && now < f->lock_until) return true;
    if (f->lock_until) f->lock_until = 0;   /* lockout expired */
    return false;
}

int imapd_auth_set(const ImapdConfig *cfg, const char *user,
                   const char *pass) {
    char path[4096];
    char *buf = NULL;
    size_t buflen = 0;
    char *out = NULL;
    size_t outlen = 0, w = 0;
    int n;
    const char *p;
    if (!imapd_user_ok(user)) return -1;
    if (!pass || !pass[0]) return -1;
    n = snprintf(path, sizeof path, "%s/%s", cfg->root, IMAPD_PASSWD_FILE);
    if (n < 0 || (size_t)n >= sizeof path) return -1;
    if (mkdir_p(cfg->root) != 0) return -1;
    read_file(path, &buf, &buflen);   /* ok when missing */
    /* Rebuild without any existing line for this user. */
    outlen = buflen + strlen(user) + strlen(pass) + 2;
    out = malloc(outlen + 1);
    if (!out) { free(buf); return -1; }
    p = buf;
    while (buf && *p) {
        size_t ll = strcspn(p, "\n");
        if (ll > strlen(user) && memcmp(p, user, strlen(user)) == 0 &&
            p[strlen(user)] == ':') {
            p += ll;
            if (*p == '\n') p++;
            continue;
        }
        if (ll == 0) { p++; continue; }
        memcpy(out + w, p, ll);
        w += ll;
        if (p[ll] == '\n') { out[w++] = '\n'; p += ll + 1; }
        else p += ll;
    }
    if (w > 0 && out[w - 1] != '\n') out[w++] = '\n';
    memcpy(out + w, user, strlen(user));
    w += strlen(user);
    out[w++] = ':';
    memcpy(out + w, pass, strlen(pass));
    w += strlen(pass);
    out[w++] = '\n';
    if (write_file(path, out, w) != 0 || chmod(path, 0600) != 0) {
        free(out);
        free(buf);
        return -1;
    }
    free(out);
    free(buf);
    return 0;
}

/* ------------------------------------------------------------------ */

/* ------------------------------------------------------------------ */
/* BODYSTRUCTURE (RFC 3501)                                           */
/* ------------------------------------------------------------------ */

static int mb_append(char **b, size_t *l, size_t *c, const void *s, size_t n) {
    size_t need, nc;
    char *nb;
    if (n == 0) return 0;
    need = *l + n;
    if (need + 1 > *c) {
        nc = *c ? *c : 256;
        while (nc < need + 1) nc *= 2;
        nb = realloc(*b, nc);
        if (!nb) return -1;
        *b = nb;
        *c = nc;
    }
    memcpy(*b + *l, s, n);
    *l = need;
    (*b)[*l] = '\0';
    return 0;
}

static int bs_nstr(char **b, size_t *l, size_t *c, const char *s, size_t n) {
    size_t i;
    if (n == 0) return mb_append(b, l, c, "NIL", 3);
    if (mb_append(b, l, c, "\"", 1) != 0) return -1;
    for (i = 0; i < n; i++) {
        char ch = s[i];
        if (ch == '"' || ch == '\\')
            if (mb_append(b, l, c, "\\", 1) != 0) return -1;
        if (mb_append(b, l, c, &ch, 1) != 0) return -1;
    }
    return mb_append(b, l, c, "\"", 1);
}

static int bs_hdr(const char *hdr, size_t hdrlen, const char *name,
                  char *out, size_t outsz) {
    return mail_header_get(hdr, hdrlen, name, out, outsz) == 0 ? 0 : -1;
}

/* Parse a Content-Type value into type/subtype/boundary (no output). */
static void bs_ct_parse(const char *val, char *type, size_t tsz, char *sub,
                        size_t ssz, char *boundary, size_t bsz) {
    char tmp[1024];
    const char *p, *slash, *semi;
    size_t nl;
    strncpy(tmp, val, sizeof tmp - 1);
    tmp[sizeof tmp - 1] = '\0';
    if (type) type[0] = '\0';
    if (sub) sub[0] = '\0';
    if (boundary) boundary[0] = '\0';
    p = tmp;
    slash = strchr(p, '/');
    semi = strchr(p, ';');
    if (type) {
        const char *e = slash ? slash : (semi ? semi : p + strlen(p));
        nl = (size_t)(e - p);
        if (nl >= tsz) nl = tsz - 1;
        memcpy(type, p, nl); type[nl] = '\0';
    }
    if (sub && slash) {
        p = slash + 1;
        const char *e = semi ? semi : p + strlen(p);
        nl = (size_t)(e - p);
        if (nl >= ssz) nl = ssz - 1;
        memcpy(sub, p, nl); sub[nl] = '\0';
    }
    p = tmp;
    while (boundary && (p = strchr(p, ';')) != NULL) {
        char name[64];
        const char *eq, *vs, *ve;
        size_t nl2, vlen;
        p++;
        while (*p == ' ' || *p == '\t') p++;
        if (!*p) break;
        eq = strchr(p, '=');
        if (!eq) break;
        nl2 = (size_t)(eq - p);
        while (nl2 && (p[nl2 - 1] == ' ' || p[nl2 - 1] == '\t')) nl2--;
        if (nl2 == 0) break;
        if (nl2 >= sizeof name) nl2 = sizeof name - 1;
        memcpy(name, p, nl2); name[nl2] = '\0';
        vs = eq + 1;
        while (*vs == ' ' || *vs == '\t') vs++;
        if (*vs == '"') {
            vs++;
            ve = strchr(vs, '"');
            if (!ve) ve = vs + strlen(vs);
        } else {
            ve = vs;
            while (*ve && *ve != ';' && *ve != ' ' && *ve != '\t') ve++;
        }
        vlen = (size_t)(ve - vs);
        if (ascii_ieq_str(name, "boundary") && vlen < bsz) {
            memcpy(boundary, vs, vlen); boundary[vlen] = '\0';
        }
        p = eq;
    }
}

/* Emit `( "name" "value" ... )` params for a Content-Type value (NIL when
   none); skip the boundary param when skip_b. */
static int bs_ct_params(char **b, size_t *l, size_t *c, const char *val,
                        bool skip_b) {
    char tmp[1024];
    const char *p;
    bool started = false;
    strncpy(tmp, val, sizeof tmp - 1);
    tmp[sizeof tmp - 1] = '\0';
    p = tmp;
    while ((p = strchr(p, ';')) != NULL) {
        char name[64], vbuf[512];
        const char *eq, *vs, *ve;
        size_t nl, vlen;
        p++;
        while (*p == ' ' || *p == '\t') p++;
        if (!*p) break;
        eq = strchr(p, '=');
        if (!eq) break;
        nl = (size_t)(eq - p);
        while (nl && (p[nl - 1] == ' ' || p[nl - 1] == '\t')) nl--;
        if (nl == 0) break;
        if (nl >= sizeof name) nl = sizeof name - 1;
        memcpy(name, p, nl); name[nl] = '\0';
        vs = eq + 1;
        while (*vs == ' ' || *vs == '\t') vs++;
        if (*vs == '"') {
            vs++;
            ve = strchr(vs, '"');
            if (!ve) ve = vs + strlen(vs);
        } else {
            ve = vs;
            while (*ve && *ve != ';' && *ve != ' ' && *ve != '\t') ve++;
        }
        vlen = (size_t)(ve - vs);
        if (vlen >= sizeof vbuf) vlen = sizeof vbuf - 1;
        memcpy(vbuf, vs, vlen); vbuf[vlen] = '\0';
        if (!(skip_b && ascii_ieq_str(name, "boundary"))) {
            if (!started) {
                if (mb_append(b, l, c, "(", 1) != 0) return -1;
                started = true;
            } else if (mb_append(b, l, c, " ", 1) != 0) return -1;
            if (bs_nstr(b, l, c, name, strlen(name)) != 0) return -1;
            if (mb_append(b, l, c, " ", 1) != 0) return -1;
            if (bs_nstr(b, l, c, vbuf, vlen) != 0) return -1;
        }
        p = eq;
    }
    if (started) return mb_append(b, l, c, ")", 1);
    return mb_append(b, l, c, "NIL", 3);
}

/* Content-Disposition -> ("inline"|"attachment" (params)) or NIL. */
static int bs_disposition(char **b, size_t *l, size_t *c, const char *hdr,
                          size_t hdrlen) {
    char v[256], disp[64], pv[512];
    const char *semi, *p;
    size_t dl;
    if (bs_hdr(hdr, hdrlen, "Content-Disposition", v, sizeof v) != 0)
        return mb_append(b, l, c, "NIL", 3);
    semi = strchr(v, ';');
    p = v;
    dl = semi ? (size_t)(semi - v) : strlen(v);
    while (dl && (p[dl - 1] == ' ' || p[dl - 1] == '\t')) dl--;
    if (dl >= sizeof disp) dl = sizeof disp - 1;
    memcpy(disp, p, dl); disp[dl] = '\0';
    if (mb_append(b, l, c, "(\"", 2) != 0) return -1;
    if (mb_append(b, l, c, disp, dl) != 0) return -1;
    if (mb_append(b, l, c, "\" ", 2) != 0) return -1;
    if (semi) {
        strncpy(pv, semi, sizeof pv - 1); pv[sizeof pv - 1] = '\0';
        if (bs_ct_params(b, l, c, pv, false) != 0) return -1;
    } else if (mb_append(b, l, c, "NIL", 3) != 0) return -1;
    return mb_append(b, l, c, ")", 1);
}

static int bs_encoding(char **b, size_t *l, size_t *c, const char *hdr,
                       size_t hdrlen) {
    char v[64];
    char *sp;
    if (bs_hdr(hdr, hdrlen, "Content-Transfer-Encoding", v, sizeof v) != 0)
        strcpy(v, "7BIT");
    sp = strchr(v, ' ');
    if (sp) *sp = '\0';
    return bs_nstr(b, l, c, v, strlen(v));
}

static int bs_part(char **b, size_t *l, size_t *c, const char *msg, size_t msglen,
                   size_t start, size_t end);

/* Multipart body [bs,be): split on boundary, recurse into each part, emit
   `( part1 part2 ... "subtype" (params) NIL NIL NIL )`. */
static int bs_multipart(char **b, size_t *l, size_t *c, const char *msg,
                        size_t msglen, size_t bs, size_t be, const char *boundary,
                        const char *subtype, const char *ctval) {
    char delim[1024];
    size_t dlen, pos;
    int npart = 0;
    size_t blen = strlen(boundary);
    snprintf(delim, sizeof delim, "--%s", boundary);
    dlen = strlen(delim);
    if (mb_append(b, l, c, "(", 1) != 0) return -1;
    pos = bs;
    while (pos + dlen <= be) {
        size_t i, d = be;
        for (i = pos; i + dlen <= be; i++)
            if (msg[i] == '-' && msg[i + 1] == '-' &&
                memcmp(msg + i + 2, boundary, blen) == 0) { d = i; break; }
        if (d == be) break;
        if (d + dlen + 2 <= be && msg[d + dlen] == '-' && msg[d + dlen + 1] == '-')
            break;                       /* closing delimiter */
        pos = d + dlen;                  /* part starts after delimiter line */
        if (pos + 1 < be && msg[pos] == '\r' && msg[pos + 1] == '\n') pos += 2;
        else if (pos < be && (msg[pos] == '\n' || msg[pos] == '\r')) pos++;
        {
            size_t j, e = be;
            for (j = pos; j + dlen <= be; j++)
                if (msg[j] == '-' && msg[j + 1] == '-' &&
                    memcmp(msg + j + 2, boundary, blen) == 0) { e = j; break; }
            while (e > pos && (msg[e - 1] == '\n' || msg[e - 1] == '\r')) e--;
            if (e > pos) {
                if (npart && mb_append(b, l, c, " ", 1) != 0) return -1;
                if (bs_part(b, l, c, msg, msglen, pos, e) != 0) return -1;
                npart++;
            }
            pos = e;
        }
    }
    if (mb_append(b, l, c, " \"", 2) != 0) return -1;
    if (mb_append(b, l, c, subtype, strlen(subtype)) != 0) return -1;
    if (mb_append(b, l, c, "\" ", 2) != 0) return -1;
    if (bs_ct_params(b, l, c, ctval, true) != 0) return -1;
    if (mb_append(b, l, c, " NIL NIL NIL)", 13) != 0) return -1;
    return 0;
}

/* One part occupying [start,end) of msg. */
static int bs_part(char **b, size_t *l, size_t *c, const char *msg, size_t msglen,
                   size_t start, size_t end) {
    size_t hdr_end, i;
    char ct[1024], type[64], sub[64], boundary[512];
    hdr_end = end;
    for (i = start; i + 4 <= end; i++)
        if (msg[i] == '\r' && msg[i + 1] == '\n' && msg[i + 2] == '\r' &&
            msg[i + 3] == '\n') { hdr_end = i + 4; break; }
    if (hdr_end == end)
        for (i = start; i + 2 <= end; i++)
            if (msg[i] == '\n' && msg[i + 1] == '\n') { hdr_end = i + 2; break; }
    if (bs_hdr(msg + start, hdr_end - start, "Content-Type", ct, sizeof ct) != 0)
        strcpy(ct, "text/plain");
    bs_ct_parse(ct, type, sizeof type, sub, sizeof sub, boundary, sizeof boundary);
    if (ascii_ieq_str(type, "multipart")) {
        /* bs_multipart emits the whole structure: ((parts) "subtype" ...). */
        return bs_multipart(b, l, c, msg, msglen, hdr_end, end, boundary, sub, ct);
    }
    /* single part: ("type" "subtype" (params) id desc enc octets
       md5 disposition language location) */
    if (mb_append(b, l, c, "\"", 1) != 0) return -1;
    if (mb_append(b, l, c, type, strlen(type)) != 0) return -1;
    if (mb_append(b, l, c, "\" \"", 3) != 0) return -1;
    if (mb_append(b, l, c, sub, strlen(sub)) != 0) return -1;
    if (mb_append(b, l, c, "\" ", 2) != 0) return -1;
    if (bs_ct_params(b, l, c, ct, false) != 0) return -1;
    if (mb_append(b, l, c, " NIL NIL ", 9) != 0) return -1;   /* id, description */
    if (bs_encoding(b, l, c, msg + start, hdr_end - start) != 0) return -1;
    if (mb_append(b, l, c, " ", 1) != 0) return -1;
    {
        char sz[32];
        snprintf(sz, sizeof sz, "%zu", end > hdr_end ? end - hdr_end : 0);
        if (mb_append(b, l, c, sz, strlen(sz)) != 0) return -1;
    }
    if (mb_append(b, l, c, " NIL ", 5) != 0) return -1;        /* md5 */
    if (bs_disposition(b, l, c, msg + start, hdr_end - start) != 0) return -1;
    return mb_append(b, l, c, " NIL NIL", 8);                  /* lang, loc */
}

int imapd_bodystructure(const char *msg, size_t len, char **out, size_t *outlen) {
    char *b = NULL;
    size_t bl = 0, bc = 0;
    if (!msg || !out || !outlen) return -1;
    *out = NULL;
    *outlen = 0;
    if (bs_part(&b, &bl, &bc, msg, len, 0, len) != 0) {
        free(b);
        return -1;
    }
    *out = b;
    *outlen = bl;
    return 0;
}

/* ------------------------------------------------------------------ */
/* MIME part resolution (BODY[<section>] fetch)                       */
/* ------------------------------------------------------------------ */

static size_t mime_hdr_end(const char *msg, size_t len) {
    size_t i;
    for (i = 0; i + 4 <= len; i++)
        if (msg[i] == '\r' && msg[i + 1] == '\n' && msg[i + 2] == '\r' &&
            msg[i + 3] == '\n') return i + 4;
    for (i = 0; i + 2 <= len; i++)
        if (msg[i] == '\n' && msg[i + 1] == '\n') return i + 2;
    return len;
}

/* Return the 1-based k-th part's byte range [ps,pe) within a multipart body
   [bs,be) delimited by `boundary`. */
static int mime_kth_part(const char *msg, size_t bs, size_t be,
                         const char *boundary, int k, size_t *ps, size_t *pe) {
    char delim[1024];
    size_t dlen, blen = strlen(boundary), pos;
    int idx = 0;
    snprintf(delim, sizeof delim, "--%s", boundary);
    dlen = strlen(delim);
    pos = bs;
    while (pos + dlen <= be) {
        size_t i, d = be;
        for (i = pos; i + dlen <= be; i++)
            if (msg[i] == '-' && msg[i + 1] == '-' &&
                memcmp(msg + i + 2, boundary, blen) == 0) { d = i; break; }
        if (d == be) break;
        if (d + dlen + 2 <= be && msg[d + dlen] == '-' && msg[d + dlen + 1] == '-')
            break;                       /* closing delimiter */
        pos = d + dlen;
        if (pos + 1 < be && msg[pos] == '\r' && msg[pos + 1] == '\n') pos += 2;
        else if (pos < be && (msg[pos] == '\n' || msg[pos] == '\r')) pos++;
        {
            size_t j, e = be;
            for (j = pos; j + dlen <= be; j++)
                if (msg[j] == '-' && msg[j + 1] == '-' &&
                    memcmp(msg + j + 2, boundary, blen) == 0) { e = j; break; }
            while (e > pos && (msg[e - 1] == '\n' || msg[e - 1] == '\r')) e--;
            idx++;
            if (idx == k) { *ps = pos; *pe = e; return 0; }
            pos = e;
        }
    }
    return -1;
}

/* Resolve a MIME part path (1-based numbers) against a full message. Fills
   the part's byte range [start,end) and its header/body boundary hdr_end. */
int imapd_mime_part(const char *msg, size_t len, const int *path, int npath,
                    size_t *start, size_t *end, size_t *hdr_end) {
    size_t cs = 0, ce = len, he;
    int i;
    he = mime_hdr_end(msg, len);
    if (npath <= 0) { *start = 0; *end = len; *hdr_end = he; return 0; }
    for (i = 0; i < npath; i++) {
        char ct[1024], type[64], sub[64], boundary[512];
        if (bs_hdr(msg + cs, he - cs, "Content-Type", ct, sizeof ct) != 0)
            return -1;
        bs_ct_parse(ct, type, sizeof type, sub, sizeof sub, boundary,
                    sizeof boundary);
        if (!ascii_ieq_str(type, "multipart") || !boundary[0]) return -1;
        if (mime_kth_part(msg, he, ce, boundary, path[i], &cs, &ce) != 0)
            return -1;
        he = mime_hdr_end(msg + cs, ce - cs) + cs;
    }
    *start = cs;
    *end = ce;
    *hdr_end = he;
    return 0;
}
