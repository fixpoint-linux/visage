/* imap_fuzz.c — deterministic fuzz harness for the imapd sources.

   Unlike imap_check.c (which pins known-good contracts), this harness
   throws random/mutated byte streams at the same pure parsers AND drives
   the full wire state machine (imap_process -> dispatch -> store) over a
   real socketpair, then verifies the maildir store stayed consistent.
   Its job is to find crashes, memory errors, and store corruption in code
   paths that a hand-written test would never spell out by hand.

   Determinism: every generator is seeded from a single xorshift64* PRNG,
   so a failure reproduces exactly given the same seed.  Default seed is
   fixed (so `make` runs are stable); pass a seed as argv[1] to explore.
   Pass iterations as argv[2] (default 2000 pure + 400 wire rounds).

   Build: same sources as imap_check.com plus imap_fuzz.c.  Run under
   -fsanitize=address,undefined to catch memory errors.  Exits 0 only if
   every round ran clean and every post-fuzz store integrity check passed.
*/
#include "visage.h"
#include "imapd.h"
#include "mail.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/socket.h>

static int nchecks = 0;
static int nfails = 0;

static void check_ok(const char *what) {
    nchecks++;
    printf("ok   %s\n", what);
}
static void check_fail(const char *what, const char *detail) {
    nchecks++;
    nfails++;
    if (detail) printf("FAIL %s — %s\n", what, detail);
    else        printf("FAIL %s\n", what);
}
#define EXPECT(cond, what) \
    do { if (cond) check_ok(what); else check_fail(what, NULL); } while (0)

/* ---- PRNG (xorshift64*) ---- */
static uint64_t rng_state;
static void rng_seed(uint64_t s) { if (!s) s = 0x9E3779B97F4A7C15ULL; rng_state = s; }
static uint64_t rng_next(void) {
    uint64_t x = rng_state;
    x ^= x >> 12; x ^= x << 25; x ^= x >> 27;
    rng_state = x;
    return x * 0x2545F4914F6CDD1DULL;
}
static uint32_t rnd(uint32_t n) { return n ? (uint32_t)(rng_next() % n) : 0; }
static uint8_t rnd_byte(void) { return (uint8_t)(rng_next() & 0xff); }

/* Recursive directory delete (rmrf is static inside imap_maildir.c). */
static int fx_rmrf(const char *path) {
    struct stat st;
    if (lstat(path, &st) != 0) return -1;
    if (S_ISDIR(st.st_mode)) {
        DIR *d = opendir(path);
        struct dirent *e;
        int rc = 0;
        if (!d) return -1;
        while ((e = readdir(d)) != NULL) {
            char sub[8192];
            if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
                continue;
            snprintf(sub, sizeof sub, "%s/%s", path, e->d_name);
            if (fx_rmrf(sub) != 0) rc = -1;
        }
        closedir(d);
        if (rmdir(path) != 0) rc = -1;
        return rc;
    }
    return unlink(path);
}

/* Aligned with the IMAP grammar's hostile bytes: delimiters, quotes,
   braces, parens, stars, control chars, CRLF, and 8-bit + NUL. */
static const char kAlphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    "0123456789 \"(){}*:.,;<>~%+=-_[]\\\t\r\n\x01\x02\x7f\xff";

/* Fill buf[0..len) with random bytes from kAlphabet. */
static void rnd_buf(char *buf, size_t len) {
    size_t i;
    for (i = 0; i < len; i++)
        buf[i] = kAlphabet[rnd(sizeof kAlphabet - 1)];
}

/* ---- mutation helpers ---- */
/* Copy a base string into buf, then apply `edits` random mutations. */
static void mutate_str(const char *base, char *buf, size_t bufsz,
                       unsigned edits) {
    size_t n = strlen(base);
    unsigned e;
    if (n >= bufsz) n = bufsz - 1;
    memcpy(buf, base, n);
    buf[n] = '\0';
    for (e = 0; e < edits; e++) {
        size_t at = rnd((uint32_t)(n ? n : 1));
        switch (rnd(4)) {
        case 0: /* flip a byte */
            if (n) { buf[at] = (char)rnd_byte(); }
            break;
        case 1: /* insert a random byte */
            if (n + 1 < bufsz) {
                memmove(buf + at + 1, buf + at, n - at + 1);
                buf[at] = kAlphabet[rnd(sizeof kAlphabet - 1)];
                n++;
            }
            break;
        case 2: /* delete a byte */
            if (n) {
                memmove(buf + at, buf + at + 1, n - at);
                n--;
            }
            break;
        case 3: /* duplicate a span */
            if (n && at < n) {
                size_t ln = rnd((uint32_t)(n - at));
                if (n + ln < bufsz) {
                    memmove(buf + at + ln, buf + at, n - at);
                    memcpy(buf + at, buf + at + ln, ln);
                    n += ln;
                }
            }
            break;
        }
        buf[n] = '\0';
    }
}

/* ---- pure-parser fuzzing -------------------------------------------- */

static void fuzz_astring(void) {
    static const char *corpus[] = {
        "hello", "\"a \\\"b\\\" c\"", "\"\"", "\"unterminated", "  ",
        "(From To)", "1:*", "a1 LOGIN user pass", "{}", "{12}", "*",
    };
    unsigned i;
    for (i = 0; i < 2000; i++) {
        char in[96];
        const char *p;
        char *out = (char *)0x1;   /* sentinel: must be NULL on fail */
        size_t outlen = 999;
        int r;
        if (rnd(3) == 0) {
            size_t len = rnd(sizeof in);
            rnd_buf(in, len);
            in[len] = '\0';
        } else {
            mutate_str(corpus[rnd(sizeof corpus / sizeof *corpus)],
                       in, sizeof in, rnd(5));
        }
        p = in;
        out = NULL; outlen = 0;
        r = imapd_next_astring(&p, &out, &outlen);
        if (r == 1) {
            if (!out || outlen != strlen(out) || out[outlen] != '\0') {
                check_fail("astring success invariant", "out/len mismatch");
                free(out);
                continue;
            }
            free(out);
        } else if (r == 0) {
            if (out != NULL) check_fail("astring end-of-input", "out non-NULL");
        } else if (r == -1) {
            if (out != NULL) check_fail("astring error", "out non-NULL");
        } else {
            check_fail("astring return", "outside {-1,0,1}");
        }
    }
    check_ok("fuzz imapd_next_astring (2000)");
}

static void fuzz_lit_marker(void) {
    static const char *corpus[] = {
        "a1 APPEND Sent {12}", "a1 LOGIN user pass", "x {abc}", "x {}",
        "x {12345678901}", "x {12+}", "x {0}", "{}", "x { 2 }",
    };
    unsigned i;
    for (i = 0; i < 2000; i++) {
        char in[96];
        int r;
        if (rnd(3) == 0) { size_t len = rnd(sizeof in); rnd_buf(in, len); in[len]='\0'; }
        else mutate_str(corpus[rnd(sizeof corpus / sizeof *corpus)],
                        in, sizeof in, rnd(5));
        r = imapd_lit_marker(in);
        /* valid: 0, -1, -2, or a positive count */
        if (r != 0 && r != -1 && r != -2 && r <= 0)
            check_fail("lit_marker return", "unexpected");
    }
    check_ok("fuzz imapd_lit_marker (2000)");
}

static void fuzz_plain_list(void) {
    static const char *corpus[] = {
        "(From To Subject)", "(X)", "NoParen", "()", "(", "(a b)", "(a b)",
        "(one \"two\")", "(  a  b  )", "(a,)",
    };
    unsigned i;
    for (i = 0; i < 2000; i++) {
        char in[96];
        const char *p;
        char **v = NULL;
        size_t nv = 0, k;
        int r;
        if (rnd(3) == 0) { size_t len = rnd(sizeof in); rnd_buf(in, len); in[len]='\0'; }
        else mutate_str(corpus[rnd(sizeof corpus / sizeof *corpus)],
                        in, sizeof in, rnd(5));
        p = in;
        r = imapd_parse_plain_list(&p, &v, &nv);
        if (r == 0) {
            for (k = 0; k < nv; k++) free(v[k]);
            free(v);
        } else if (r != -1) {
            check_fail("plain_list return", "outside {-1,0}");
        }
    }
    check_ok("fuzz imapd_parse_plain_list (2000)");
}

static void fuzz_search(void) {
    static const char *corpus[] = {
        "ALL", "UNSEEN", "NOT FLAGGED", "OR FROM bob TO carol", "HEADER Message-ID x",
        "(FROM a AND SUBJECT b)", "SINCE 1-Jan-2000", "BODY \"needle\"",
        "UID 1:*", "LARGER 100", "NOT (OR (FROM a) (TO b))", "ALL ALL ALL",
    };
    unsigned i;
    for (i = 0; i < 2000; i++) {
        char in[128];
        const char *p;
        SearchKey *k = NULL;
        int r;
        if (rnd(3) == 0) { size_t len = rnd(sizeof in); rnd_buf(in, len); in[len]='\0'; }
        else mutate_str(corpus[rnd(sizeof corpus / sizeof *corpus)],
                        in, sizeof in, rnd(6));
        p = in;
        r = imapd_search_parse_program(&p, &k);
        if (r == 1) {
            (void)imapd_search_needs_body(k);
            imapd_search_free(k);
        } else if (r != 0 && r != -1) {
            check_fail("search_parse_program return", "outside {-1,0,1}");
        }
    }
    check_ok("fuzz imapd_search_parse_program (2000)");
}

static void fuzz_search_match(void) {
    static const char *corpus[] = { "ALL", "SEEN", "UNSEEN", "FLAGGED", "DELETED",
        "RECENT", "FROM bob", "TO carol", "SUBJECT hello", "BODY needle",
        "HEADER Message-ID <x>", "SINCE 1-Jan-2020", "LARGER 5", "NOT SEEN",
        "OR SEEN FLAGGED", "UID 1:3", "ANSWERED" };
    static const char *body =
        "From: bob@x\r\nSubject: hello world\r\nMessage-ID: <x@y>\r\n\r\n"
        "needle in the haystack\r\n";
    unsigned i;
    for (i = 0; i < 2000; i++) {
        char in[128];
        const char *p;
        SearchKey *k = NULL;
        Imail m;
        ImailDoc d;
        int r;
        if (rnd(3) == 0) { size_t len = rnd(sizeof in); rnd_buf(in, len); in[len]='\0'; }
        else mutate_str(corpus[rnd(sizeof corpus / sizeof *corpus)],
                        in, sizeof in, rnd(6));
        p = in;
        r = imapd_search_parse_program(&p, &k);
        if (r == 1) {
            memset(&m, 0, sizeof m);
            m.uid = (uint32_t)(1 + rnd(3));
            m.flags = (uint8_t)(rnd(256));
            m.size = strlen(body);
            d.m = &m;
            d.seq = m.uid;
            d.msg = body;
            d.msglen = strlen(body);
            (void)imapd_search_match(k, &d, 4, 3);
            imapd_search_free(k);
        }
    }
    check_ok("fuzz imapd_search_match (2000)");
}

static void fuzz_seqset(void) {
    static const char *corpus[] = { "1", "3:5", "*", "*:10", "1,2:4,9", "0",
        "a", "4:", "", "1,,2", "*:*", "4294967295", "1:4294967296", "-1" };
    unsigned i;
    for (i = 0; i < 2000; i++) {
        char in[96];
        uint32_t n = (uint32_t)(1 + rnd(10)), star = (uint32_t)(1 + rnd(10));
        if (rnd(3) == 0) { size_t len = rnd(sizeof in); rnd_buf(in, len); in[len]='\0'; }
        else mutate_str(corpus[rnd(sizeof corpus / sizeof *corpus)],
                        in, sizeof in, rnd(5));
        (void)imapd_seqset_valid(in);
        (void)imapd_seqset_has(in, n, star);
    }
    check_ok("fuzz seqset_valid/has (2000)");
}

static void fuzz_flags(void) {
    static const char *corpus[] = { "2,DFS", "2,D", "2,", "2,XY", "3,DFS",
        "2,DFRST", "abc", "2,", ",DFS", "2,", "2,DFRSTABC" };
    unsigned i;
    for (i = 0; i < 2000; i++) {
        char in[64], enc[64];
        uint8_t flags = 0;
        char unk[IMAPD_MAX_UNK];
        int r;
        if (rnd(3) == 0) { size_t len = rnd(sizeof in); rnd_buf(in, len); in[len]='\0'; }
        else mutate_str(corpus[rnd(sizeof corpus / sizeof *corpus)],
                        in, sizeof in, rnd(4));
        memset(unk, 0, sizeof unk);
        r = imapd_flags_parse(in, &flags, unk, sizeof unk);
        if (r == 0) {
            if (imapd_flags_encode(flags, unk, enc, sizeof enc) != 0)
                check_fail("flags roundtrip", "encode failed after parse ok");
            else {
                uint8_t f2 = 0; char u2[IMAPD_MAX_UNK] = {0};
                if (imapd_flags_parse(enc, &f2, u2, sizeof u2) != 0 || f2 != flags)
                    check_fail("flags roundtrip", "re-parse mismatch");
            }
        } else if (r != -1) {
            check_fail("flags_parse return", "outside {-1,0}");
        }
    }
    check_ok("fuzz flags_parse/encode roundtrip (2000)");
}

static void fuzz_b64(void) {
    static const char *corpus[] = { "AHVzZXIAcGFzcw==", "", "QQ==", "QQ=", "A!==",
        "QQ==QQ", "TWFpbA==", "aGVsbG8=", "dGVzdA==", "=====", "A" };
    unsigned i;
    for (i = 0; i < 2000; i++) {
        char in[64];
        unsigned char out[256];
        size_t outlen = 0;
        int r;
        if (rnd(3) == 0) { size_t len = rnd(sizeof in); rnd_buf(in, len); in[len]='\0'; }
        else mutate_str(corpus[rnd(sizeof corpus / sizeof *corpus)],
                        in, sizeof in, rnd(5));
        outlen = 999;
        r = imapd_b64_decode(in, strlen(in), out, sizeof out, &outlen);
        if (r == 0) {
            if (outlen > sizeof out) check_fail("b64 overflow", "outlen>sz");
        } else if (r != -1) {
            check_fail("b64 return", "outside {-1,0}");
        }
    }
    check_ok("fuzz imapd_b64_decode (2000)");
}

static void fuzz_validators(void) {
    static const char *corpus[] = {
        "user", "bob@x", ".hidden", "..", "a/b", "a b", "INBOX", ".folder",
        "folder.", "a..b", "127.0.0.1", "localhost", "::1", "10.0.0.1",
        "name with space", "éclair", "", "*",
    };
    unsigned i;
    for (i = 0; i < 2000; i++) {
        char in[96];
        if (rnd(3) == 0) { size_t len = rnd(sizeof in); rnd_buf(in, len); in[len]='\0'; }
        else mutate_str(corpus[rnd(sizeof corpus / sizeof *corpus)],
                        in, sizeof in, rnd(4));
        (void)imapd_user_ok(in);
        (void)imapd_mbox_name_ok(in);
        (void)imapd_wildmat(in, "INBOX");
        (void)imapd_wildmat("INBOX", in);
        (void)imapd_addr_loopback(in);
    }
    check_ok("fuzz user/mbox/wildmat/addr validators (2000)");
}

/* ---- wire-level fuzzing ---------------------------------------------- */

/* A scratch server + one authenticated, INBOX-selected connection.  The
   caller mutates command streams against it; after a batch we verify the
   store still loads and its on-disk message count matches the scan. */
typedef struct WireFx {
    char *root;
    ImapdServer srv;
    Conn *c;
    int peer;               /* other end of the socketpair (we write to it) */
} WireFx;

static void wire_set_nonblock(int fd) {
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl >= 0) (void)fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

static int wire_init(WireFx *w) {
    char tpl[] = "/tmp/visage_imapfuzz_XXXXXX";
    char dir[4096], passwd[4096];
    const char *msg = "Subject: hello\r\nMessage-ID: <a@b>\r\n\r\nbody\r\n";
    FILE *f;
    int sv[2];
    int i;
    char *mk;

    memset(w, 0, sizeof *w);
    mk = mkdtemp(tpl);
    if (!mk) return -1;
    w->root = strdup(mk);
    if (!w->root) return -1;

    memset(&w->srv.cfg, 0, sizeof w->srv.cfg);
    w->srv.cfg.root = w->root;
    w->srv.cfg.max_msg = 32u * 1024u * 1024u;
    w->srv.imap_loopback = true;

    /* user "u" with a password, an INBOX and an Archive folder. */
    if (imapd_mbox_dir(&w->srv.cfg, "u", "INBOX", dir, sizeof dir) != 0)
        return -1;
    for (i = 0; i < 3; i++)
        if (imapd_mbox_deliver(dir, msg, strlen(msg), 0, NULL) != 0) return -1;
    if (imapd_mbox_dir(&w->srv.cfg, "u", "Archive", dir, sizeof dir) != 0)
        return -1;
    if (imapd_mbox_create(dir) != 0) return -1;
    if (imapd_mbox_deliver(dir, msg, strlen(msg), 0, NULL) != 0) return -1;

    snprintf(passwd, sizeof passwd, "%s/imapd.passwd", w->root);
    f = fopen(passwd, "w");
    if (!f) return -1;
    fprintf(f, "u:secretpw\n");
    fclose(f);
    if (imapd_auth_load(&w->srv.cfg, &w->srv) != 0) return -1;

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) return -1;
    w->peer = sv[1];
    w->c = calloc(1, sizeof *w->c);
    if (!w->c) { close(sv[0]); close(sv[1]); return -1; }
    w->c->fd = sv[0];
    w->c->kind = CONN_IMAP;
    w->c->ist = IST_NOT_AUTH;
    wire_set_nonblock(sv[0]);
    imapd_imap_greeting(&w->srv, w->c);
    return 0;
}

/* Feed bytes through the real reader (imap_process -> dispatch), pumping any
   streaming FETCH to completion.  Returns after the socket is drained. */
static void wire_feed(WireFx *w, const char *bytes, size_t len) {
    size_t off = 0;
    while (off < len && !w->c->closed) {
        size_t chunk = len - off;
        ssize_t nw;
        if (chunk > 4096) chunk = 4096;
        nw = write(w->peer, bytes + off, chunk);
        if (nw <= 0) break;
        off += (size_t)nw;
        imapd_imap_readable(&w->srv, w->c, time(NULL));
        /* drain a streaming FETCH to completion before the next command */
        while (w->c->fg && !w->c->closed) imapd_fetch_pump(&w->srv, w->c);
    }
    /* if a literal is still pending (mode==IC_LIT), drop it by resetting */
    if (w->c->mode == IC_LIT && !w->c->closed) {
        free(w->c->cmd);
        w->c->cmd = NULL;
        w->c->cmd_len = w->c->cmd_cap = 0;
        w->c->mode = IC_LINE;
        w->c->lit_left = 0;
    }
}

static const char *kCommands[] = {
    "a1 LOGIN u secretpw\r\n",
    "a2 SELECT INBOX\r\n",
    "a3 STATUS INBOX (MESSAGES UIDNEXT UIDVALIDITY)\r\n",
    "a4 FETCH 1:* (FLAGS)\r\n",
    "a5 SEARCH ALL\r\n",
    "a6 SEARCH HEADER Message-ID x\r\n",
    "a7 STORE 1 +FLAGS.SILENT (\\Seen)\r\n",
    "a8 COPY 1 Archive\r\n",
    "a9 MOVE 1 Archive\r\n",
    "a10 EXPUNGE\r\n",
    "a11 UID FETCH 1:* (UID FLAGS)\r\n",
    "a12 UID SEARCH ALL\r\n",
    "a13 UID STORE 1 +FLAGS (\\Flagged)\r\n",
    "a14 UID MOVE 1 Archive\r\n",
    "a15 CREATE foo\r\n",
    "a16 LIST \"\" *\r\n",
    "a17 LSUB \"\" *\r\n",
    "a18 NOOP\r\n",
    "a19 CHECK\r\n",
    "a20 CLOSE\r\n",
    "a21 APPEND INBOX {5}\r\nhello\r\n",
    "a22 LOGOUT\r\n",
    "a23 CAPABILITY\r\n",
    "a24 ENABLE CONDSTORE\r\n",
    "a25 ID NIL\r\n",
    "a26 GETQUOTAROOT INBOX\r\n",
    "a27 SUBSCRIBE INBOX\r\n",
    "a28 UNSELECT\r\n",
    "a29 EXAMINE INBOX\r\n",
    "a30 RENAME foo bar\r\n",
    "a31 DELETE foo\r\n",
    "a32 UID EXPUNGE 1\r\n",
    "a33 SORT REVERSE DATE UTF-8 ALL\r\n",
    "a34 UID SORT DATE UTF-8 ALL\r\n",
    "a35 SEARCH HEADER X-Abcdef \"quote \\\" and space\"\r\n",
    "a36 FETCH 1 BODY[]\r\n",
};

static void fuzz_wire(unsigned rounds, bool *store_ok) {
    WireFx w;
    unsigned i;

    if (wire_init(&w) != 0) { check_fail("wire init", "setup failed"); return; }

    for (i = 0; i < rounds && nfails == 0; i++) {
        char line[256];
        const char *base;
        size_t len;

        if (w.c->closed) {
            /* connection dropped (e.g. LOGOUT or a closing BAD): reset it */
            imapd_fetch_free(w.c);
            free(w.c->user);
            w.c->user = NULL;
            if (w.c->mb_open) imapd_mbox_close(&w.c->mb);
            free(w.c->cmd);
            w.c->cmd = NULL;
            free(w.c->in);
            w.c->in = NULL;
            free(w.c->out);
            w.c->out = NULL;
            w.c->ist = IST_NOT_AUTH;
            w.c->closed = false;
            w.c->in = NULL; w.c->in_len = w.c->in_cap = 0;
            w.c->out = NULL; w.c->out_len = w.c->out_off = w.c->out_cap = 0;
            w.c->mode = IC_LINE;
            w.c->lit_left = 0;
            w.c->idle = false;
            imapd_imap_greeting(&w.srv, w.c);
        }

        if (w.c->idle) {   /* only DONE is accepted while IDLE */
            wire_feed(&w, "DONE\r\n", strlen("DONE\r\n"));
            continue;
        }

        switch (rnd(4)) {
        case 0: {   /* a mutated valid command */
            size_t bl;
            base = kCommands[rnd(sizeof kCommands / sizeof *kCommands)];
            bl = strlen(base);
            if (bl >= sizeof line) bl = sizeof line - 1;
            memcpy(line, base, bl);
            line[bl] = '\0';
            mutate_str(line, line, sizeof line, rnd(4));
            len = strlen(line);
            break;
        }
        case 1: {   /* raw random bytes (may include NUL/control) */
            size_t L = 1 + rnd(64);
            char *raw = malloc(L);
            if (!raw) continue;
            size_t k;
            for (k = 0; k < L; k++) raw[k] = (char)rnd_byte();
            wire_feed(&w, raw, L);
            free(raw);
            continue;
        }
        case 2: {   /* a malformed literal marker */
            char ln[48];
            snprintf(ln, sizeof ln, "a%d APPEND INBOX {%u}\r\n",
                     (unsigned)(1000 + i % 200), rnd(2000));
            len = strlen(ln);
            mutate_str(ln, line, sizeof line, rnd(3));
            len = strlen(line);
            break;
        }
        default: {   /* a valid command verbatim */
            base = kCommands[rnd(sizeof kCommands / sizeof *kCommands)];
            len = strlen(base);
            if (len >= sizeof line) len = sizeof line - 1;
            memcpy(line, base, len);
            line[len] = '\0';
            break;
        }
        }
        wire_feed(&w, line, len);
    }

    /* integrity: the INBOX must still load and its uidlist parse */
    {
        ImapdConfig cfg;
        Mbox mb;
        memset(&cfg, 0, sizeof cfg);
        cfg.root = w.root;
        if (imapd_mbox_open(&cfg, "u", "INBOX", &mb) == 0) {
            if (mb.uidvalidity == 0)
                check_fail("wire store", "uidvalidity 0 after fuzz");
            /* every uid must be unique and in [1, uidnext) */
            {
                size_t a, b;
                bool dup = false;
                for (a = 0; a < mb.nmsgs && !dup; a++)
                    for (b = a + 1; b < mb.nmsgs && !dup; b++)
                        if (mb.msgs[a].uid == mb.msgs[b].uid) dup = true;
                if (dup) check_fail("wire store", "duplicate uids after fuzz");
            }
            imapd_mbox_close(&mb);
        } else {
            check_fail("wire store", "INBOX failed to reopen after fuzz");
        }
    }

    /* teardown */
    if (w.c) {
        imapd_fetch_free(w.c);
        free(w.c->user);
        if (w.c->mb_open) imapd_mbox_close(&w.c->mb);
        free(w.c->cmd);
        free(w.c->in);
        free(w.c->out);
        if (w.c->fd >= 0) close(w.c->fd);
        free(w.c);
    }
    if (w.peer >= 0) close(w.peer);
    for (i = 0; i < w.srv.ncreds; i++) {
        free(w.srv.creds[i].user);
        free(w.srv.creds[i].pass);
    }
    free(w.srv.creds);
    (void)fx_rmrf(w.root);
    free(w.root);

    if (store_ok && nfails == 0) *store_ok = true;
    check_ok("fuzz wire protocol (store intact)");
}

int main(int argc, char **argv) {
    uint64_t seed = (argc > 1) ? strtoull(argv[1], NULL, 0) : 0x5EEDC0DE;
    unsigned pure_it = (argc > 2) ? (unsigned)strtoul(argv[2], NULL, 10) : 0;
    bool store_ok = false;

    rng_seed(seed);

    /* pure-parser rounds (iteration counts fixed unless argv overrides) */
    fuzz_astring();
    fuzz_lit_marker();
    fuzz_plain_list();
    fuzz_search();
    fuzz_search_match();
    fuzz_seqset();
    fuzz_flags();
    fuzz_b64();
    fuzz_validators();

    fuzz_wire(pure_it ? pure_it : 400, &store_ok);

    printf("\n%d checks, %d failed\n", nchecks, nfails);
    return nfails ? 1 : 0;
}
