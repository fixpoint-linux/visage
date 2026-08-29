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
    FILE *f = fopen(path, "wb");
    size_t w;
    int rc;
    if (!f) return -1;
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

int imapd_mbox_deliver(const char *dir, const char *msg, size_t len,
                       uint8_t flags, const char *unk) {
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
    return 0;
}

/* ------------------------------------------------------------------ */
/* uidlist sidecar                                                     */
/* ------------------------------------------------------------------ */

typedef struct UidEnt {
    char    *base;
    uint32_t uid;
} UidEnt;

static void uidlist_free(UidEnt *v, size_t n) {
    size_t i;
    for (i = 0; i < n; i++) free(v[i].base);
    free(v);
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
        if (sscanf(p, "%llu", &uid) != 1) break;
        nl = strchr(p, '\n');
        if (!nl) nl = p + strlen(p);
        p += strspn(p, "0123456789");
        if (*p != ' ') break;   /* malformed line: keep what we have */
        p++;
        bl = (size_t)(nl - p);
        if (bl == 0 || memchr(p, ' ', bl)) break;
        base = malloc(bl + 1);
        if (!base) break;
        memcpy(base, p, bl);
        base[bl] = '\0';
        if (n == cap) {
            size_t nc = cap ? cap * 2 : 16;
            UidEnt *nv = realloc(v, nc * sizeof *nv);
            if (!nv) { free(base); break; }
            v = nv;
            cap = nc;
        }
        v[n].base = base;
        v[n].uid = (uid == 0 || uid > UINT32_MAX) ? 0 : (uint32_t)uid;
        if (v[n].uid == 0) { free(base); break; }
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
    for (i = 0; i < n; i++)
        if (fprintf(f, "%u %s\n", v[i].uid, v[i].base) < 0) goto fail;
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
    for (i = 0; i < mb->nmsgs; i++) {
        free(mb->msgs[i].base);
        free(mb->msgs[i].path);
    }
    free(mb->msgs);
    mb->msgs = NULL;
    mb->nmsgs = mb->cap = 0;
}

/* Append one scanned file to the view (takes ownership of base/path). */
static int scan_add(Mbox *mb, uint32_t uid, uint8_t flags, const char *unk,
                    bool recent, const struct stat *st, char *base,
                    char *path) {
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
    snprintf(m->unk, sizeof m->unk, "%s", unk ? unk : "");
    m->recent = recent;
    m->internal_date = st->st_mtime;
    m->size = (size_t)st->st_size;
    m->base = base;
    m->path = path;
    return 0;
}

static int imail_uid_cmp(const void *pa, const void *pb) {
    const Imail *a = pa, *b = pb;
    if (a->uid < b->uid) return -1;
    return a->uid == b->uid ? 0 : 1;
}

/* Scan one of new//cur/; assigns UIDs from the uidlist map or uidnext. */
static int scan_subdir(Mbox *mb, const char *sub, bool is_new,
                       UidEnt **map, size_t *nmap,
                       uint32_t *uidnext, bool *changed) {
    char sub_dir[4096 + 8];
    DIR *d;
    struct dirent *e;
    if (snprintf(sub_dir, sizeof sub_dir, "%s/%s", mb->dir, sub)
            >= (int)sizeof sub_dir) return -1;
    d = opendir(sub_dir);
    if (!d) return -1;   /* missing tmp/new/cur: caller creates first */
    while ((e = readdir(d)) != NULL) {
        char path[4096 + 64], info[32];
        const char *colon, *inf;
        struct stat st;
        uint32_t uid = 0;
        uint8_t flags = 0;
        size_t i, bl;
        char *base, *fpath;
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
        for (i = 0; i < *nmap; i++) {
            if (strlen((*map)[i].base) == bl &&
                memcmp((*map)[i].base, e->d_name, bl) == 0) {
                uid = (*map)[i].uid;
                break;
            }
        }
        if (uid == 0) {
            UidEnt *nv;
            uid = (*uidnext)++;
            *changed = true;
            /* record the assignment so the next save persists it */
            nv = realloc(*map, (*nmap + 1) * sizeof **map);
            if (nv) {
                *map = nv;
                (*map)[*nmap].base = malloc(bl + 1);
                if ((*map)[*nmap].base) {
                    memcpy((*map)[*nmap].base, e->d_name, bl);
                    (*map)[*nmap].base[bl] = '\0';
                    (*map)[*nmap].uid = uid;
                    (*nmap)++;
                }
            }
        }
        base = malloc(bl + 1);
        fpath = malloc(strlen(path) + 1);
        if (!base || !fpath) { free(base); free(fpath); continue; }
        memcpy(base, e->d_name, bl);
        base[bl] = '\0';
        strcpy(fpath, path);
        if (scan_add(mb, uid, flags, info, is_new, &st, base, fpath) != 0) {
            free(base);
            free(fpath);
        }
    }
    closedir(d);
    return 0;
}

static int mbox_scan(Mbox *mb, const ImapdConfig *cfg, const char *user,
                     const char *name, bool move_new) {
    UidEnt *map = NULL;
    size_t nmap = 0, i, j;
    uint32_t uidvalidity = (uint32_t)time(NULL);
    uint32_t uidnext = 1;
    bool changed = false;
    int rc = -1;

    memset(mb, 0, sizeof *mb);
    if (imapd_mbox_dir(cfg, user, name, mb->dir, sizeof mb->dir) != 0)
        return -1;
    if (imapd_mbox_create(mb->dir) != 0) return -1;

    map = uidlist_load(mb, &uidvalidity, &uidnext, &nmap);
    if (uidnext == 0) uidnext = 1;

    if (scan_subdir(mb, "new", true, &map, &nmap, &uidnext, &changed) != 0)
        goto out;
    if (scan_subdir(mb, "cur", false, &map, &nmap, &uidnext, &changed) != 0)
        goto out;

    if (mb->nmsgs > 1)
        qsort(mb->msgs, mb->nmsgs, sizeof *mb->msgs, imail_uid_cmp);

    /* Prune uidlist entries whose file vanished. */
    for (i = 0; i < nmap; ) {
        bool found = false;
        for (j = 0; j < mb->nmsgs; j++) {
            if (mb->msgs[j].uid == map[i].uid &&
                strlen(mb->msgs[j].base) == strlen(map[i].base) &&
                memcmp(mb->msgs[j].base, map[i].base,
                       strlen(map[i].base)) == 0) {
                found = true;
                break;
            }
        }
        if (!found) {
            free(map[i].base);
            map[i] = map[nmap - 1];
            nmap--;
            changed = true;
        } else {
            i++;
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
    if (changed && uidlist_save(mb, uidvalidity, uidnext, map, nmap) != 0)
        goto out;
    rc = 0;
out:
    uidlist_free(map, nmap);
    if (rc != 0) imapd_mbox_close(mb);
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

Imail *imapd_mbox_find(Mbox *mb, uint32_t uid) {
    size_t i;
    if (!mb) return NULL;
    for (i = 0; i < mb->nmsgs; i++)
        if (mb->msgs[i].uid == uid) return &mb->msgs[i];
    return NULL;
}

int imapd_mbox_store(Mbox *mb, uint32_t uid, uint8_t flags) {
    char dst[4096 + 64], info[32];
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
    return 0;
}

/* Remove one uid from the uidlist file (best-effort prune; the next open
   would prune anyway). */
static void uidlist_drop_uid(Mbox *mb, uint32_t uid) {
    char path[4200];
    char *buf = NULL;
    size_t buflen = 0;
    UidEnt *map = NULL;
    size_t nmap = 0, i;
    uint32_t uv = mb->uidvalidity, un = mb->uidnext;
    if (uidlist_path(mb, path, sizeof path) != 0) return;
    if (read_file(path, &buf, &buflen) != 0) return;
    free(buf);
    map = uidlist_load(mb, &uv, &un, &nmap);
    for (i = 0; i < nmap; ) {
        if (map[i].uid == uid) {
            free(map[i].base);
            map[i] = map[nmap - 1];
            nmap--;
        } else {
            i++;
        }
    }
    (void)uidlist_save(mb, uv, un, map, nmap);
    uidlist_free(map, nmap);
}

int imapd_mbox_expunge(Mbox *mb, uint32_t uid) {
    size_t i;
    for (i = 0; i < mb->nmsgs; i++) {
        if (mb->msgs[i].uid != uid) continue;
        (void)unlink(mb->msgs[i].path);
        free(mb->msgs[i].base);
        free(mb->msgs[i].path);
        memmove(&mb->msgs[i], &mb->msgs[i + 1],
                (mb->nmsgs - i - 1) * sizeof *mb->msgs);
        mb->nmsgs--;
        uidlist_drop_uid(mb, uid);
        return 0;
    }
    return -1;
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

bool imapd_auth_check(const ImapdServer *srv, const char *user,
                      const char *pass) {
    size_t i;
    if (!srv || !user || !pass) return false;
    for (i = 0; i < srv->ncreds; i++)
        if (strcmp(srv->creds[i].user, user) == 0 &&
            strcmp(srv->creds[i].pass, pass) == 0)
            return true;
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
