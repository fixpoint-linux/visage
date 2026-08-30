/* imap_check.c — standalone checks for the imapd sources.
   No live sockets or threads: tests the pure helpers (flag suffix codec,
   seq-sets, base64 decode, SEARCH parse/match, tokenizer) plus the maildir
   store (deliver, uidlist assign/persist/prune, flag renames) inside an
   mkdtemp scratch root.  Returns 0 only if all checks pass.  The protocol
   state machines are exercised end-to-end by the daemon against real
   clients; this harness pins the store and parsing contracts. */
#include "visage.h"
#include "imapd.h"
#include "mail.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>

static int nchecks = 0;
static int nfails = 0;

static void check_ok(const char *what) {
    nchecks++;
    printf("ok   %s\n", what);
}

static void check_fail(const char *what, const char *detail) {
    nchecks++;
    nfails++;
    if (detail)
        printf("FAIL %s — %s\n", what, detail);
    else
        printf("FAIL %s\n", what);
}

#define EXPECT(cond, what) \
    do { if (cond) check_ok(what); else check_fail(what, NULL); } while (0)

static char *mk_tmpdir(void) {
    char tpl[] = "/tmp/visage_imapd_XXXXXX";
    return mkdtemp(tpl) ? strdup(tpl) : NULL;
}

/* ---- (1) maildir flag suffix codec ---- */

static void flags_test(void) {
    uint8_t f = 0;
    char unk[IMAPD_MAX_UNK];
    char out[32];

    EXPECT(imapd_flags_parse("2,DFRST", &f, unk, sizeof unk) == 0 &&
               f == (IMAIL_DRAFT | IMAIL_FLAGGED | IMAIL_ANSWERED |
                     IMAIL_SEEN | IMAIL_TRASHED) && unk[0] == '\0',
           "flags parse full DFRST");
    EXPECT(imapd_flags_encode(f, "", out, sizeof out) == 0 &&
           strcmp(out, "2,DFRST") == 0,
           "flags encode round-trip DFRST");

    EXPECT(imapd_flags_parse("2,", &f, unk, sizeof unk) == 0 && f == 0,
           "flags parse empty suffix");
    EXPECT(imapd_flags_encode(0, "", out, sizeof out) == 0 &&
           strcmp(out, "2,") == 0, "flags encode empty");

    EXPECT(imapd_flags_parse("2,SX", &f, unk, sizeof unk) == 0 &&
               f == IMAIL_SEEN && strcmp(unk, "X") == 0,
           "flags parse keeps unknown letter");
    EXPECT(imapd_flags_encode(f, unk, out, sizeof out) == 0 &&
           strcmp(out, "2,SX") == 0,
           "flags encode preserves unknown letter");

    EXPECT(imapd_flags_parse("x,DS", &f, unk, sizeof unk) == -1,
           "flags parse rejects bad version");
    EXPECT(imapd_flags_parse("2", &f, unk, sizeof unk) == -1,
           "flags parse rejects missing comma");
    EXPECT(imapd_flags_parse("2,SD", &f, unk, sizeof unk) == 0 &&
               f == (IMAIL_SEEN | IMAIL_DRAFT),
           "flags parse accepts non-canonical order");
}

/* ---- (2) uidlist assign / persist / prune ---- */

static void uidlist_test(const char *root) {
    ImapdConfig cfg;
    Mbox mb;
    char dir[4096];
    char msg[] = "Subject: u\r\n\r\nbody\r\n";
    uint32_t uv0;
    Imail *m;

    memset(&cfg, 0, sizeof cfg);
    cfg.root = root;
    cfg.hostname = "test";

    EXPECT(imapd_mbox_dir(&cfg, "bob", "INBOX", dir, sizeof dir) == 0,
           "mbox_dir INBOX");

    EXPECT(imapd_mbox_deliver(dir, msg, strlen(msg), 0, NULL) == 0 &&
           imapd_mbox_deliver(dir, msg, strlen(msg), 0, NULL) == 0 &&
           imapd_mbox_deliver(dir, msg, strlen(msg), 0, NULL) == 0,
           "deliver three messages");

    EXPECT(imapd_mbox_open(&cfg, "bob", "INBOX", &mb) == 0, "open scans");
    EXPECT(mb.uidvalidity > 0 && mb.uidnext == 4 && mb.nmsgs == 3,
           "uidlist assigns uids 1..3");
    EXPECT(mb.msgs[0].uid == 1 && mb.msgs[1].uid == 2 && mb.msgs[2].uid == 3,
           "view sorted by uid");
    EXPECT(mb.msgs[0].recent && mb.msgs[1].recent && mb.msgs[2].recent,
           "new/ arrivals are Recent");
    uv0 = mb.uidvalidity;
    imapd_mbox_close(&mb);

    EXPECT(imapd_mbox_deliver(dir, msg, strlen(msg), 0, NULL) == 0,
           "deliver a fourth message");
    EXPECT(imapd_mbox_peek(&cfg, "bob", "INBOX", &mb) == 0, "reopen");
    EXPECT(mb.uidnext == 5 && mb.msgs[3].uid == 4 && mb.nmsgs == 4,
           "uid stable across reopen, new msg gets uidnext");
    EXPECT(mb.uidvalidity == uv0, "uidvalidity stable");
    EXPECT(!mb.msgs[0].recent && mb.msgs[3].recent,
           "peek keeps new/ files (recent only for those)");
    imapd_mbox_close(&mb);

    /* remove uid 2's file -> pruned on next open */
    {
        char path[4200];
        EXPECT(imapd_mbox_peek(&cfg, "bob", "INBOX", &mb) == 0, "reopen 2");
        snprintf(path, sizeof path, "%s", mb.msgs[1].path);
        imapd_mbox_close(&mb);
        EXPECT(unlink(path) == 0, "unlink uid 2 file");
    }
    EXPECT(imapd_mbox_open(&cfg, "bob", "INBOX", &mb) == 0, "reopen 3");
    EXPECT(mb.nmsgs == 3 && mb.msgs[0].uid == 1 && mb.msgs[1].uid == 3,
           "vanished file pruned, other uids stable");
    EXPECT(mb.uidnext == 5, "uidnext never reuses after open");
    m = imapd_mbox_find(&mb, 3);
    EXPECT(m != NULL, "find by uid");
    imapd_mbox_close(&mb);
}

/* ---- (3) seq-set parser ---- */

static void seqset_test(void) {
    EXPECT(imapd_seqset_valid("1") == 1, "seqset valid 1");
    EXPECT(imapd_seqset_valid("3:5") == 1, "seqset valid 3:5");
    EXPECT(imapd_seqset_valid("*") == 1, "seqset valid *");
    EXPECT(imapd_seqset_valid("*:10") == 1, "seqset valid *:10");
    EXPECT(imapd_seqset_valid("1,2:4,9") == 1, "seqset valid list");
    EXPECT(imapd_seqset_valid("0") == 0, "seqset rejects 0");
    EXPECT(imapd_seqset_valid("a") == 0, "seqset rejects letters");
    EXPECT(imapd_seqset_valid("4:") == 0, "seqset rejects trailing colon");
    EXPECT(imapd_seqset_valid("") == 0, "seqset rejects empty");
    EXPECT(imapd_seqset_valid("1,,2") == 0, "seqset rejects empty element");

    EXPECT(imapd_seqset_has("1", 1, 10), "has 1 -> 1");
    EXPECT(!imapd_seqset_has("1", 2, 10), "has 1 !-> 2");
    EXPECT(imapd_seqset_has("3:5", 4, 10), "has 3:5 -> 4");
    EXPECT(!imapd_seqset_has("3:5", 6, 10), "has 3:5 !-> 6");
    EXPECT(imapd_seqset_has("*", 10, 10), "has * -> star");
    /* RFC 3501: a reversed range "*:10" with star=7 spans 7..10; with
       star=10 it is just {10} */
    EXPECT(imapd_seqset_has("*:10", 8, 7), "has *:10 -> 8 (reversed, star 7)");
    EXPECT(imapd_seqset_has("*:10", 10, 10), "has *:10 -> star");
    EXPECT(!imapd_seqset_has("*:10", 7, 10), "has *:10 !-> 7 when star=10");
    EXPECT(imapd_seqset_has("1,2:4,9", 3, 10), "has list -> 3");
    EXPECT(imapd_seqset_has("1,2:4,9", 9, 10), "has list -> 9");
    EXPECT(!imapd_seqset_has("1,2:4,9", 5, 10), "has list !-> 5");
}

/* ---- (4) tokenizer: astrings, literal markers, paren lists ---- */

static void tokenizer_test(void) {
    const char *p;
    char *s = NULL;
    size_t n = 0;

    p = "hello world";
    EXPECT(imapd_next_astring(&p, &s, &n) == 1 && strcmp(s, "hello") == 0,
           "astring atom");
    free(s);
    p += 1;
    EXPECT(imapd_next_astring(&p, &s, &n) == 1 && strcmp(s, "world") == 0 &&
           *p == '\0', "astring atom to end");
    free(s);

    p = "\"a \\\"b\\\" c\"";
    EXPECT(imapd_next_astring(&p, &s, &n) == 1 && strcmp(s, "a \"b\" c") == 0,
           "astring quoted with escapes");
    free(s);

    p = "\"\"";
    EXPECT(imapd_next_astring(&p, &s, &n) == 1 && n == 0 && s != NULL && s[0] == '\0',
           "astring empty quoted yields non-NULL empty string");
    free(s);

    p = "\"unterminated";
    EXPECT(imapd_next_astring(&p, &s, &n) == -1, "astring unterminated");

    p = "   ";
    EXPECT(imapd_next_astring(&p, &s, &n) == 0, "astring end of input");

    EXPECT(imapd_lit_marker("a1 APPEND Sent {12}") == 12,
           "literal marker {12}");
    EXPECT(imapd_lit_marker("a1 LOGIN user pass") == 0,
           "no literal marker");
    EXPECT(imapd_lit_marker("x {abc}") == -1, "malformed marker");
    EXPECT(imapd_lit_marker("x {}") == -1, "empty marker");
    EXPECT(imapd_lit_marker("x {12345678901}") == -1, "overflow marker");

    {
        char **v = NULL;
        size_t nv = 0, i;
        p = "(From To Subject)";
        EXPECT(imapd_parse_plain_list(&p, &v, &nv) == 0 && nv == 3 &&
                   strcmp(v[0], "From") == 0 && strcmp(v[2], "Subject") == 0,
               "plain paren list");
        for (i = 0; i < nv; i++) free(v[i]);
        free(v);
        p = "(X)";
        EXPECT(imapd_parse_plain_list(&p, &v, &nv) == 0 && nv == 1,
               "single-item list");
        for (i = 0; i < nv; i++) free(v[i]);
        free(v);
        p = "NoParen";
        EXPECT(imapd_parse_plain_list(&p, &v, &nv) == -1,
               "list rejects missing paren");
    }
}

/* ---- (5) base64 decode (AUTH PLAIN) ---- */

static void b64_test(void) {
    unsigned char out[512];
    size_t n = 0;

    /* RFC 4954 vector: "\0user\0pass" */
    EXPECT(imapd_b64_decode("AHVzZXIAcGFzcw==", 16, out, sizeof out, &n) == 0 &&
               n == 10 &&
               out[0] == 0 && memcmp(out + 1, "user", 4) == 0 &&
               out[5] == 0 && memcmp(out + 6, "pass", 4) == 0,
           "b64 AUTH PLAIN vector");

    EXPECT(imapd_b64_decode("", 0, out, sizeof out, &n) == 0 && n == 0,
           "b64 empty");
    EXPECT(imapd_b64_decode("QQ==", 4, out, sizeof out, &n) == 0 &&
               n == 1 && out[0] == 'A', "b64 QQ==");
    EXPECT(imapd_b64_decode("QQ=", 3, out, sizeof out, &n) == -1,
           "b64 bad length");
    EXPECT(imapd_b64_decode("A!==" , 4, out, sizeof out, &n) == -1,
           "b64 invalid char");
    EXPECT(imapd_b64_decode("QQ==QQ", 6, out, sizeof out, &n) == -1,
           "b64 padding misplacement");
    EXPECT(imapd_b64_decode("QQ==", 4, out, 0, &n) == -1,
           "b64 too-small output");
}

/* ---- (6) SEARCH parse + match over synthetic views ---- */

static void search_test(void) {
    Imail m[4];
    SearchKey *k = NULL;
    const char *p;
    size_t i;

    memset(m, 0, sizeof m);
    /* 1: seen, from bob, subject hello, body needle */
    m[0].uid = 1; m[0].flags = IMAIL_SEEN; m[0].size = 10;
    /* 2: unseen, flagged, from carol */
    m[1].uid = 2; m[1].flags = IMAIL_FLAGGED;
    /* 3: unseen, deleted, recent */
    m[2].uid = 3; m[2].flags = IMAIL_TRASHED; m[2].recent = true;
    /* 4: answered draft from bob */
    m[3].uid = 4; m[3].flags = IMAIL_ANSWERED | IMAIL_DRAFT;

    {
        static const char *const bodies[4] = {
            "From: bob@x\r\nSubject: hello\r\n\r\nneedle here\r\n",
            "From: carol@x\r\nSubject: other\r\n\r\nnothing\r\n",
            "From: dan@x\r\nSubject: hi\r\n\r\nNEEDLE caps\r\n",
            "From: bob@x\r\nSubject: draft\r\n\r\nno match\r\n",
        };
        ImailDoc d;
        uint32_t uidnext = 5;

#define MATCH(idx, key) ( \
        d.m = &m[idx], d.seq = (idx) + 1, d.msg = bodies[idx], \
        d.msglen = strlen(bodies[idx]), \
        imapd_search_match(key, &d, uidnext, 4))

        p = "ALL";
        EXPECT(imapd_search_parse_program(&p, &k) == 1,
               "search parse ALL");
        EXPECT(MATCH(0, k) && MATCH(1, k) && MATCH(2, k) && MATCH(3, k),
               "search ALL matches everything");
        imapd_search_free(k);

        p = "UNSEEN";
        EXPECT(imapd_search_parse_program(&p, &k) == 1, "search parse UNSEEN");
        EXPECT(!MATCH(0, k) && MATCH(1, k) && MATCH(2, k), "search UNSEEN");
        imapd_search_free(k);

        p = "SEEN";
        EXPECT(imapd_search_parse_program(&p, &k) == 1, "search parse SEEN");
        EXPECT(MATCH(0, k) && !MATCH(1, k), "search SEEN");
        imapd_search_free(k);

        p = "NEW";
        EXPECT(imapd_search_parse_program(&p, &k) == 1, "search parse NEW");
        EXPECT(MATCH(2, k) && !MATCH(0, k), "search NEW (recent+unseen)");
        imapd_search_free(k);

        p = "OLD";
        EXPECT(imapd_search_parse_program(&p, &k) == 1, "search parse OLD");
        EXPECT(MATCH(0, k) && !MATCH(2, k), "search OLD");
        imapd_search_free(k);

        p = "DELETED FLAGGED";
        EXPECT(imapd_search_parse_program(&p, &k) == 1, "search parse AND");
        EXPECT(!MATCH(2, k), "search DELETED+FLAGGED excludes 3");
        m[2].flags |= IMAIL_FLAGGED;
        EXPECT(MATCH(2, k), "search DELETED+FLAGGED includes 3 after set");
        m[2].flags &= (uint8_t)~IMAIL_FLAGGED;
        imapd_search_free(k);

        p = "NOT SEEN";
        EXPECT(imapd_search_parse_program(&p, &k) == 1, "search parse NOT");
        EXPECT(MATCH(1, k) && !MATCH(0, k), "search NOT SEEN");
        imapd_search_free(k);

        p = "OR SEEN FLAGGED";
        EXPECT(imapd_search_parse_program(&p, &k) == 1, "search parse OR");
        EXPECT(MATCH(0, k) && MATCH(1, k) && !MATCH(3, k), "search OR");
        imapd_search_free(k);

        p = "FROM bob";
        EXPECT(imapd_search_parse_program(&p, &k) == 1, "search parse FROM");
        EXPECT(MATCH(0, k) && MATCH(3, k) && !MATCH(1, k), "search FROM ci");
        imapd_search_free(k);

        p = "TO bob";
        EXPECT(imapd_search_parse_program(&p, &k) == 1, "search parse TO");
        EXPECT(!MATCH(0, k), "search TO no match");
        imapd_search_free(k);

        p = "SUBJECT hello";
        EXPECT(imapd_search_parse_program(&p, &k) == 1,
               "search parse SUBJECT");
        EXPECT(MATCH(0, k) && !MATCH(1, k), "search SUBJECT");
        imapd_search_free(k);

        p = "HEADER X-Tag zzz";
        EXPECT(imapd_search_parse_program(&p, &k) == 1,
               "search parse HEADER");
        EXPECT(!MATCH(0, k), "search HEADER missing -> false");
        imapd_search_free(k);

        p = "BODY needle";
        EXPECT(imapd_search_parse_program(&p, &k) == 1, "search parse BODY");
        EXPECT(MATCH(0, k), "search BODY");
        EXPECT(MATCH(2, k), "search BODY case-insensitive");
        EXPECT(!MATCH(1, k), "search BODY miss");
        imapd_search_free(k);

        p = "TEXT needle";
        EXPECT(imapd_search_parse_program(&p, &k) == 1, "search parse TEXT");
        EXPECT(MATCH(0, k) && MATCH(2, k), "search TEXT spans header+body");
        imapd_search_free(k);

        p = "UID 1,3";
        EXPECT(imapd_search_parse_program(&p, &k) == 1, "search parse UID");
        EXPECT(MATCH(0, k) && MATCH(2, k) && !MATCH(1, k), "search UID set");
        imapd_search_free(k);

        p = "UID 4:*";
        EXPECT(imapd_search_parse_program(&p, &k) == 1, "search parse UID *");
        EXPECT(MATCH(3, k), "search UID 4:* with uidnext 5");
        imapd_search_free(k);

        p = "1:2";
        EXPECT(imapd_search_parse_program(&p, &k) == 1, "search parse seqset");
        EXPECT(MATCH(0, k) && MATCH(1, k) && !MATCH(2, k), "search seq");
        imapd_search_free(k);

        p = "(SEEN FLAGGED)";
        EXPECT(imapd_search_parse_program(&p, &k) == 1, "search parse group");
        EXPECT(!MATCH(0, k), "search group");
        imapd_search_free(k);

        p = "BOGUS";
        EXPECT(imapd_search_parse_program(&p, &k) == -1,
               "search rejects unknown key");
        imapd_search_free(k);

        p = "FROM";
        EXPECT(imapd_search_parse_program(&p, &k) == -1,
               "search rejects missing arg");
        imapd_search_free(k);

#undef MATCH
    }
    for (i = 0; i < 4; i++) {
        /* silence set-but-unused warnings for the metadata-only fields */
        (void)m[i].internal_date;
    }
}

/* ---- (7) maildir delivery ---- */

static void deliver_test(const char *root) {
    ImapdConfig cfg;
    char dir[4096], path[8192];
    char msg[] = "Subject: d\r\n\r\nhello\r\n";
    char bad[] = "Subject: bad\r\n\r\n\x01ctl\r\n";
    char back[256];
    FILE *f;
    size_t got;
    DIR *d;
    struct dirent *e;
    int nfiles = 0;

    memset(&cfg, 0, sizeof cfg);
    cfg.root = root;

    EXPECT(imapd_mbox_dir(&cfg, "carol", "INBOX", dir, sizeof dir) == 0,
           "deliver: mbox dir");
    EXPECT(imapd_mbox_deliver(dir, msg, strlen(msg), 0, NULL) == 0,
           "deliver ok");
    EXPECT(imapd_mbox_deliver(dir, bad, strlen(bad), 0, NULL) == -1,
           "deliver rejects control bytes");
    EXPECT(imapd_mbox_deliver(dir, "a\0b", 3, 0, NULL) == -1,
           "deliver rejects NUL bytes");

    EXPECT(imapd_mbox_deliver(dir, msg, strlen(msg), 0, NULL) == 0,
           "second deliver ok (unique names)");

    {
        char newdir[8192];
        snprintf(newdir, sizeof newdir, "%s/new", dir);
        d = opendir(newdir);
    }
    if (!d) { check_fail("deliver: opendir new/", NULL); return; }
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.') continue;
        nfiles++;
        snprintf(path, sizeof path, "%s/new/%s", dir, e->d_name);
    }
    closedir(d);
    EXPECT(nfiles == 2, "two unique files in new/");

    f = fopen(path, "rb");
    if (!f) { check_fail("deliver: read back", NULL); return; }
    got = fread(back, 1, sizeof back, f);
    fclose(f);
    EXPECT(got == strlen(msg) && memcmp(back, msg, got) == 0,
           "delivered content byte-identical");

    /* user name validation guards path traversal */
    EXPECT(!imapd_user_ok("../etc"), "user_ok rejects traversal");
    EXPECT(!imapd_user_ok(""), "user_ok rejects empty");
    EXPECT(!imapd_user_ok("a/b"), "user_ok rejects slash");
    EXPECT(imapd_user_ok("alice.example-co_1"), "user_ok accepts valid");
    EXPECT(imapd_mbox_name_ok("Lists.News") == 0, "mbox_name_ok accepts dots");
    EXPECT(imapd_mbox_name_ok("../x") == -1, "mbox_name_ok rejects slash");
    EXPECT(imapd_mbox_name_ok(".hidden") == -1, "mbox_name_ok rejects leading dot");
    EXPECT(imapd_mbox_name_ok("a..b") == -1, "mbox_name_ok rejects ..");
}

/* ---- (8) flag rename keeps base + uid ---- */

static void flags_store_test(const char *root) {
    ImapdConfig cfg;
    Mbox mb;
    char dir[4096];
    char msg[] = "Subject: s\r\n\r\nx\r\n";
    char base0[256];
    Imail *m;

    memset(&cfg, 0, sizeof cfg);
    cfg.root = root;

    EXPECT(imapd_mbox_dir(&cfg, "dave", "INBOX", dir, sizeof dir) == 0,
           "store: mbox dir");
    EXPECT(imapd_mbox_deliver(dir, msg, strlen(msg), 0, NULL) == 0,
           "store: deliver");
    EXPECT(imapd_mbox_open(&cfg, "dave", "INBOX", &mb) == 0, "store: open");
    EXPECT(mb.nmsgs == 1, "store: one message");

    m = &mb.msgs[0];
    snprintf(base0, sizeof base0, "%s", m->base);
    EXPECT(imapd_mbox_store(&mb, m->uid, IMAIL_SEEN) == 0, "store set \\Seen");
    m = imapd_mbox_find(&mb, mb.msgs[0].uid);
    EXPECT(m != NULL && (m->flags & IMAIL_SEEN), "store: view updated");
    EXPECT(strcmp(m->base, base0) == 0, "store: base name kept");
    EXPECT(strstr(m->path, ":2,S") != NULL, "store: :2,S suffix in cur/");

    EXPECT(imapd_mbox_store(&mb, m->uid,
                            IMAIL_SEEN | IMAIL_FLAGGED | IMAIL_ANSWERED) == 0,
           "store multi flags");
    m = imapd_mbox_find(&mb, mb.msgs[0].uid);
    EXPECT(strstr(m->path, ":2,FRS") != NULL, "store: canonical DFRST order");

    EXPECT(imapd_mbox_store(&mb, m->uid, 0) == 0, "store clear flags");
    m = imapd_mbox_find(&mb, mb.msgs[0].uid);
    EXPECT(m->flags == 0 && strcmp(m->base, base0) == 0,
           "store: flags cleared, base kept");

    /* reopen: flags persisted, uid stable */
    imapd_mbox_close(&mb);
    EXPECT(imapd_mbox_open(&cfg, "dave", "INBOX", &mb) == 0, "store: reopen");
    EXPECT(mb.nmsgs == 1 && mb.msgs[0].uid == 1 && mb.msgs[0].flags == 0,
           "store: persisted across reopen");

    EXPECT(imapd_mbox_expunge(&mb, 1) == 0 && mb.nmsgs == 0,
           "expunge removes from view");
    imapd_mbox_close(&mb);
    EXPECT(imapd_mbox_open(&cfg, "dave", "INBOX", &mb) == 0, "expunge: reopen");
    EXPECT(mb.nmsgs == 0 && mb.uidnext == 2, "expunge persisted");
    imapd_mbox_close(&mb);
}

/* ---- credentials ---- */

static void auth_test(const char *root) {
    ImapdConfig cfg;
    ImapdServer srv;

    memset(&cfg, 0, sizeof cfg);
    cfg.root = root;
    memset(&srv, 0, sizeof srv);
    srv.cfg = cfg;

    EXPECT(imapd_auth_set(&cfg, "alice", "secret") == 0, "auth_set");
    EXPECT(imapd_auth_load(&cfg, &srv) == 0 && srv.ncreds == 1,
           "auth_load one user");
    EXPECT(imapd_auth_check(&srv, "alice", "secret"), "auth_check ok");
    EXPECT(!imapd_auth_check(&srv, "alice", "wrong"), "auth_check bad pass");
    EXPECT(!imapd_auth_check(&srv, "bob", "secret"), "auth_check bad user");

    EXPECT(imapd_auth_set(&cfg, "alice", "newpass") == 0, "auth_set replace");
    EXPECT(imapd_auth_set(&cfg, "bob", "pw2") == 0, "auth_set add");
    imapd_auth_load(&cfg, &srv);
    EXPECT(srv.ncreds == 2 && !imapd_auth_check(&srv, "alice", "secret") &&
               imapd_auth_check(&srv, "alice", "newpass") &&
               imapd_auth_check(&srv, "bob", "pw2"),
           "auth replace + add");
    {
        char p[4200];
        struct stat st;
        snprintf(p, sizeof p, "%s/%s", root, IMAPD_PASSWD_FILE);
        EXPECT(stat(p, &st) == 0 && (st.st_mode & 0777) == 0600,
               "passwd file is 0600");
    }
}

static void bf_test(void) {
    ImapdServer srv;
    unsigned char ip[4] = { 10, 0, 0, 1 };
    time_t t = 1000;
    memset(&srv, 0, sizeof srv);
    /* 5 failures lock out */
    imapd_auth_fail(&srv, ip, 4, t++);
    imapd_auth_fail(&srv, ip, 4, t++);
    imapd_auth_fail(&srv, ip, 4, t++);
    imapd_auth_fail(&srv, ip, 4, t++);
    EXPECT(!imapd_auth_blocked(&srv, ip, 4, t), "not blocked before threshold");
    imapd_auth_fail(&srv, ip, 4, t++);
    EXPECT(imapd_auth_blocked(&srv, ip, 4, t), "blocked after 5 failures");
    /* lock_until was set at the 5th fail (t=1004) => expires at 1304 */
    EXPECT(imapd_auth_blocked(&srv, ip, 4, 1303), "blocked inside lockout window");
    EXPECT(!imapd_auth_blocked(&srv, ip, 4, 1305), "unblocked after lockout expires");
    /* success clears the tally */
    imapd_auth_fail(&srv, ip, 4, t + 100);
    imapd_auth_fail(&srv, ip, 4, t + 101);
    imapd_auth_clear(&srv, ip, 4);
    EXPECT(!imapd_auth_blocked(&srv, ip, 4, t + 200), "clear resets tally");
    /* distinct IPs are tracked independently */
    {
        unsigned char ip2[4] = { 10, 0, 0, 2 };
        EXPECT(!imapd_auth_blocked(&srv, ip2, 4, t + 200),
               "unrelated IP unaffected");
    }
}

/* ---- LIST wildcards ---- */

static void wildmat_test(void) {
    EXPECT(imapd_wildmat("*", "Lists"), "wildmat * all");
    EXPECT(imapd_wildmat("*", "Lists.News"), "wildmat * crosses dots");
    EXPECT(imapd_wildmat("%", "Lists"), "wildmat % one level");
    EXPECT(!imapd_wildmat("%", "Lists.News"), "wildmat % stops at dot");
    EXPECT(imapd_wildmat("Lists.%", "Lists.News"), "wildmat prefix %");
    EXPECT(imapd_wildmat("in*", "INBOX-x"), "wildmat case-insensitive");
    EXPECT(!imapd_wildmat("Lis", "Lists"), "wildmat exact end");
}

/* ---- STARTTLS capability string + loopback classifier ---- */

static void tls_test(void) {
    EXPECT(strcmp(imapd_capability(true, true, true),
                  "IMAP4rev1 AUTH=PLAIN IDLE UIDPLUS CONDSTORE NAMESPACE ID SORT") == 0,
           "capability: TLS established drops STARTTLS");
    EXPECT(strcmp(imapd_capability(false, true, true),
                  "IMAP4rev1 STARTTLS AUTH=PLAIN IDLE UIDPLUS CONDSTORE NAMESPACE ID SORT") == 0,
           "capability: TLS available on loopback bind");
    EXPECT(strcmp(imapd_capability(false, true, false),
                  "IMAP4rev1 STARTTLS LOGINDISABLED IDLE UIDPLUS CONDSTORE NAMESPACE ID SORT") == 0,
           "capability: TLS available off-loopback => LOGINDISABLED");
    EXPECT(strcmp(imapd_capability(false, false, false),
                  "IMAP4rev1 AUTH=PLAIN IDLE UIDPLUS CONDSTORE NAMESPACE ID SORT") == 0,
           "capability: no cert = legacy plaintext default");

    EXPECT(imapd_addr_loopback("127.0.0.1"), "loopback 127.0.0.1");
    EXPECT(imapd_addr_loopback("127.9.9.9"), "loopback 127.9.9.9");
    EXPECT(imapd_addr_loopback("::1"), "loopback ::1");
    EXPECT(imapd_addr_loopback("localhost"), "loopback localhost");
    EXPECT(!imapd_addr_loopback("0.0.0.0"), "non-loopback 0.0.0.0");
    EXPECT(!imapd_addr_loopback("192.168.1.5"), "non-loopback 192.168.1.5");
}

static void bodystructure_test(void) {
    /* single-part text/plain with a charset param */
    {
        const char *m = "Content-Type: text/plain; charset=utf-8\r\n"
                        "Content-Transfer-Encoding: 7bit\r\n"
                        "\r\nhello";
        char *out = NULL; size_t len = 0;
        int r = imapd_bodystructure(m, strlen(m), &out, &len);
        EXPECT(r == 0 && out && strcmp(out,
              "\"text\" \"plain\" (\"charset\" \"utf-8\") NIL NIL \"7bit\" 5 NIL NIL NIL NIL") == 0,
              "bodystructure single text");
        free(out);
    }
    /* multipart/alternative with an HTML part */
    {
        const char *m =
            "Content-Type: multipart/alternative; boundary=X\r\n"
            "\r\n"
            "--X\r\n"
            "Content-Type: text/plain\r\n"
            "\r\n"
            "plain\r\n"
            "--X\r\n"
            "Content-Type: text/html\r\n"
            "\r\n"
            "<b>hi</b>\r\n"
            "--X--\r\n";
        char *out = NULL; size_t len = 0;
        int r = imapd_bodystructure(m, strlen(m), &out, &len);
        EXPECT(r == 0 && out, "bodystructure multipart parses");
        if (out)
            EXPECT(strstr(out, "\"alternative\" NIL NIL NIL") != NULL &&
                   strstr(out, "\"text\" \"plain\" NIL NIL NIL \"7BIT\" 5") != NULL &&
                   strstr(out, "\"text\" \"html\" NIL NIL NIL \"7BIT\" 9") != NULL,
                   "bodystructure multipart parts present");
        free(out);
    }
    /* attachment with disposition */
    {
        const char *m =
            "Content-Type: multipart/mixed; boundary=Y\r\n"
            "\r\n"
            "--Y\r\n"
            "Content-Type: text/plain\r\n"
            "\r\n"
            "body\r\n"
            "--Y\r\n"
            "Content-Type: application/pdf; name=\"doc.pdf\"\r\n"
            "Content-Disposition: attachment; filename=\"doc.pdf\"\r\n"
            "Content-Transfer-Encoding: base64\r\n"
            "\r\n"
            "JVBERg==\r\n"
            "--Y--\r\n";
        char *out = NULL; size_t len = 0;
        int r = imapd_bodystructure(m, strlen(m), &out, &len);
        EXPECT(r == 0 && out, "bodystructure attachment parses");
        if (out)
            EXPECT(strstr(out, "(\"attachment\" (\"filename\" \"doc.pdf\"))") != NULL,
                   "bodystructure attachment disposition present");
        free(out);
    }
}

static void mime_part_test(void) {
    const char *m =
        "Content-Type: multipart/mixed; boundary=Z\r\n"
        "\r\n"
        "--Z\r\nContent-Type: text/plain\r\n"
        "\r\n"
        "body\r\n"
        "--Z\r\nContent-Type: application/pdf\r\n"
        "\r\n"
        "%PDF\r\n"
        "--Z--\r\n";
    int path[2];
    size_t s, e, he;
    path[0] = 1;
    EXPECT(imapd_mime_part(m, strlen(m), path, 1, &s, &e, &he) == 0 &&
               e - he == 4 && strncmp(m + he, "body", 4) == 0,
           "mime_part part 1 body");
    path[0] = 2;
    EXPECT(imapd_mime_part(m, strlen(m), path, 1, &s, &e, &he) == 0 &&
               e - he == 4 && strncmp(m + he, "%PDF", 4) == 0,
           "mime_part part 2 body");
    path[0] = 3;
    EXPECT(imapd_mime_part(m, strlen(m), path, 1, &s, &e, &he) != 0,
           "mime_part part 3 does not exist");
    /* nested: multipart/alternative inside multipart/mixed */
    const char *m2 =
        "Content-Type: multipart/mixed; boundary=A\r\n"
        "\r\n"
        "--A\r\nContent-Type: multipart/alternative; boundary=B\r\n"
        "\r\n"
        "--B\r\nContent-Type: text/plain\r\n"
        "\r\n"
        "plain\r\n"
        "--B\r\nContent-Type: text/html\r\n"
        "\r\n"
        "<b>h</b>\r\n"
        "--B--\r\n"
        "--A--\r\n";
    int p2[2] = { 1, 2 };
    EXPECT(imapd_mime_part(m2, strlen(m2), p2, 2, &s, &e, &he) == 0 &&
               e - he == 8 && strncmp(m2 + he, "<b>h</b>", 8) == 0,
           "mime_part nested part 1.2");
}

int main(void) {
    char *root = mk_tmpdir();

    flags_test();
    seqset_test();
    tokenizer_test();
    search_test();
    b64_test();
    bf_test();
    wildmat_test();
    tls_test();
    bodystructure_test();
    mime_part_test();

    if (root) {
        ImapdConfig cfg;
        char **names = NULL;
        size_t nnames = 0;

        memset(&cfg, 0, sizeof cfg);
        cfg.root = root;

        uidlist_test(root);
        deliver_test(root);
        flags_store_test(root);
        auth_test(root);

        /* folder listing over the scratch root (carol has only INBOX; give
           her one folder, and reuse dave's user for a second) */
        {
            char dir[4096];
            if (imapd_mbox_dir(&cfg, "carol", "Lists", dir, sizeof dir) == 0)
                imapd_mbox_create(dir);
        }
        EXPECT(imapd_mbox_list(&cfg, "carol", "*", &names, &nnames) == 0 &&
                   nnames == 1 && strcmp(names[0], "Lists") == 0,
               "mbox_list finds folder");
        EXPECT(imapd_wildmat("Lists", names[0]), "list name matches pattern");
        while (nnames > 0) free(names[--nnames]);
        free(names);

        EXPECT(imapd_mbox_list(&cfg, "nobody", "*", &names, &nnames) == 0 &&
                   nnames == 0,
               "mbox_list empty for unknown user");

        free(root);
    } else {
        check_fail("mkdtemp scratch root", "mkdtemp failed");
    }

    printf("\n%d checks, %d failed\n", nchecks, nfails);
    return nfails ? 1 : 0;
}
