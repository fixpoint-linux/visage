/* outbox_auth.c — shared-credential store for outbox.
 *
 * Loads a plaintext "user:pass" file (one credential per line, identical to
 * imapd's passwd file; '#' and blank lines skipped) and answers AUTH
 * PLAIN/LOGIN checks.  The password comparison is constant-time so the
 * response time does not leak which byte differs; when the username is unknown
 * the check still runs against a fixed dummy password so user-existence is not
 * revealed through timing either (usernames are not secret, but keeping the
 * compare uniform is cheap and strictly safer).
 *
 * Also provides a strict base64 decoder (the RFC 4648 subset SMTP AUTH uses)
 * and the per-IP brute-force lockout mirroring imapd's auth_fail/auth_clear/
 * auth_blocked. */
#include "outbox.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

/* ------------------------------------------------------------------ */
/* Strict base64 decode                                                */
/* ------------------------------------------------------------------ */

static int b64_val(unsigned char c) {
    if (c >= 'A' && c <= 'Z') return (int)(c - 'A');
    if (c >= 'a' && c <= 'z') return (int)(c - 'a') + 26;
    if (c >= '0' && c <= '9') return (int)(c - '0') + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

int outbox_b64_decode(const char *in, size_t inlen, unsigned char *out,
                      size_t outsz, size_t *outlen) {
    size_t i = 0, w = 0;
    uint32_t acc = 0;
    int nbits = 0;
    int pad = 0;

    if (outlen) *outlen = 0;
    if (!in || !out) return -1;

    for (i = 0; i < inlen; i++) {
        unsigned char c = (unsigned char)in[i];
        int v;
        if (c == '=') {
            pad++;
            continue;
        }
        if (pad > 0) return -1;          /* data after padding */
        v = b64_val(c);
        if (v < 0) return -1;            /* non-alphabet byte */
        acc = (acc << 6) | (uint32_t)v;
        nbits += 6;
        if (nbits >= 8) {
            nbits -= 8;
            if (w >= outsz) return -1;
            out[w++] = (unsigned char)((acc >> nbits) & 0xff);
        }
    }
    /* Padding must only ever be 1 or 2 '=' at the very end, and the leftover
       bits must be zero (canonical). */
    if (pad > 2) return -1;
    if (nbits >= 8 || (nbits > 0 && (acc & ((1u << nbits) - 1)) != 0))
        return -1;
    if (outlen) *outlen = w;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Passwd-file load + constant-time check                              */
/* ------------------------------------------------------------------ */

static int read_file(const char *path, char **out, size_t *outlen) {
    struct stat st;
    int fd;
    char *buf;
    size_t off = 0;

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
        if (r == 0) break;
        off += (size_t)r;
    }
    close(fd);
    buf[off] = '\0';
    *out = buf;
    *outlen = off;
    return 0;
}

/* Validate a username token for the passwd file: 1..128 chars of
 * [A-Za-z0-9._-].  Mirrors imapd_user_ok's maildir-safe alphabet. */
static bool user_ok(const char *u) {
    size_t n = 0;
    if (!u || !u[0]) return false;
    for (; u[n]; n++) {
        char c = u[n];
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
              (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-'))
            return false;
    }
    return n <= 128;
}

int outbox_auth_load(const char *path, OutboxAuth *a) {
    char *buf = NULL;
    size_t buflen = 0;
    const char *p;
    size_t i;

    for (i = 0; i < a->ncreds; i++) {
        free(a->creds[i].user);
        free(a->creds[i].pass);
    }
    free(a->creds);
    a->creds = NULL;
    a->ncreds = 0;

    if (read_file(path, &buf, &buflen) != 0) return 0;   /* none yet */
    p = buf;
    while (*p) {
        size_t ll = strcspn(p, "\n");
        char *line = malloc(ll + 1);
        char *colon;
        if (!line) { free(buf); return -1; }
        memcpy(line, p, ll);
        line[ll] = '\0';
        p += ll;
        if (*p == '\n') p++;
        if (line[0] == '#' || line[0] == '\0') { free(line); continue; }
        colon = strchr(line, ':');
        if (!colon) { free(line); continue; }
        *colon = '\0';
        if (user_ok(line) && colon[1]) {
            OutboxCred *nv = realloc(a->creds, (a->ncreds + 1) * sizeof *nv);
            if (!nv) { free(line); free(buf); return -1; }
            a->creds = nv;
            a->creds[a->ncreds].user = strdup(line);
            a->creds[a->ncreds].pass = strdup(colon + 1);
            if (!a->creds[a->ncreds].user || !a->creds[a->ncreds].pass) {
                free(a->creds[a->ncreds].user);
                free(a->creds[a->ncreds].pass);
                free(line);
                free(buf);
                return -1;
            }
            a->ncreds++;
        }
        free(line);
    }
    free(buf);
    return 0;
}

/* Constant-time byte comparison over the LONGER of the two lengths.  Lengths
 * are folded in too, so the only observable difference is a single uniform
 * loop over max(alen, blen) bytes. */
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

bool outbox_auth_check(const OutboxAuth *a, const char *user, const char *pass) {
    /* Dummy candidate so an unknown user still runs a full constant-time
       compare (hides user existence). */
    static const char dummy_pass[] = "visage-dummy-outbox-password";
    const char *cand = dummy_pass;
    size_t clen = sizeof dummy_pass - 1;
    size_t plen, i;

    if (!a || !user || !pass) return false;
    for (i = 0; i < a->ncreds; i++) {
        if (strcmp(a->creds[i].user, user) == 0) {
            cand = a->creds[i].pass;
            clen = strlen(a->creds[i].pass);
            break;
        }
    }
    plen = strlen(pass);
    return ct_equal((const unsigned char *)pass, plen,
                    (const unsigned char *)cand, clen);
}

/* ------------------------------------------------------------------ */
/* Per-IP brute-force lockout (mirrors imapd)                          */
/* ------------------------------------------------------------------ */

static OutboxFail *fail_find(OutboxServer *srv, const unsigned char *ip,
                             uint8_t len) {
    size_t i;
    for (i = 0; i < srv->nfails; i++)
        if (srv->fails[i].len == len && memcmp(srv->fails[i].ip, ip, len) == 0)
            return &srv->fails[i];
    return NULL;
}

void outbox_auth_fail(OutboxServer *srv, const unsigned char *ip, uint8_t len,
                      time_t now) {
    OutboxFail *f;
    if (!srv || !ip || !len) return;
    f = fail_find(srv, ip, len);
    if (!f) {
        if (srv->nfails >= OUTBOX_AUTH_MAX_TRACKED) {
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
    if (now - f->first_fail > OUTBOX_AUTH_WINDOW_SEC) {
        f->first_fail = now;
        f->count = 0;
    }
    f->count++;
    if (f->count >= OUTBOX_AUTH_MAX_FAILS)
        f->lock_until = now + OUTBOX_AUTH_LOCKOUT_SEC;
}

void outbox_auth_clear(OutboxServer *srv, const unsigned char *ip, uint8_t len) {
    OutboxFail *f;
    if (!srv || !ip || !len) return;
    f = fail_find(srv, ip, len);
    if (!f) return;
    f->count = 0;
    f->first_fail = 0;
    f->lock_until = 0;
}

bool outbox_auth_blocked(OutboxServer *srv, const unsigned char *ip,
                         uint8_t len, time_t now) {
    OutboxFail *f;
    if (!srv || !ip || !len) return false;
    f = fail_find(srv, ip, len);
    if (!f) return false;
    if (f->lock_until && now < f->lock_until) return true;
    if (f->lock_until) f->lock_until = 0;
    return false;
}
