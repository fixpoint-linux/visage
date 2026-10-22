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
#include <pthread.h>

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

#define SC_MAX 64

typedef struct Sidecar {
    uint32_t uv, uidnext;
    size_t   n;
    uint32_t uid[SC_MAX];
    char     base[SC_MAX][160];
} Sidecar;

/* Parse "<dir>/imapd-uidlist": header then one (uid, base) per row.  A
   missing file is an empty sidecar.  Returns -1 on a malformed file. */
static int sidecar_load(const char *dir, Sidecar *sc) {
    char path[4200], line[512];
    FILE *f;
    memset(sc, 0, sizeof *sc);
    if (snprintf(path, sizeof path, "%s/%s", dir, IMAPD_UIDLIST_FILE)
            >= (int)sizeof path)
        return -1;
    f = fopen(path, "r");
    if (!f) return 0;
    if (!fgets(line, sizeof line, f)) { fclose(f); return -1; }
    if (sscanf(line, "%u %u", &sc->uv, &sc->uidnext) != 2) {
        fclose(f);
        return -1;
    }
    while (sc->n < SC_MAX && fgets(line, sizeof line, f)) {
        unsigned uid = 0;
        char base[160];
        if (sscanf(line, "%u %159s", &uid, base) != 2) { fclose(f); return -1; }
        sc->uid[sc->n] = uid;
        snprintf(sc->base[sc->n], sizeof sc->base[sc->n], "%s", base);
        sc->n++;
    }
    fclose(f);
    return 0;
}

static int sidecar_find(const Sidecar *sc, const char *base) {
    size_t i;
    for (i = 0; i < sc->n; i++)
        if (strcmp(sc->base[i], base) == 0) return (int)i;
    return -1;
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
        char pruned[256];
        Sidecar sc;
        EXPECT(imapd_mbox_peek(&cfg, "bob", "INBOX", &mb) == 0, "reopen 2");
        snprintf(path, sizeof path, "%s", mb.msgs[1].path);
        snprintf(pruned, sizeof pruned, "%s", mb.msgs[1].base);
        imapd_mbox_close(&mb);
        EXPECT(unlink(path) == 0, "unlink uid 2 file");
        EXPECT(imapd_mbox_open(&cfg, "bob", "INBOX", &mb) == 0, "reopen 3");
        EXPECT(mb.nmsgs == 3 && mb.msgs[0].uid == 1 && mb.msgs[1].uid == 3,
               "vanished file pruned, other uids stable");
        EXPECT(mb.uidnext == 5, "uidnext never reuses after open");
        /* The prune must reach the SIDECAR, not just the view: the scan's
           immediate save merges with the file it just loaded, so without the
           prune's tombstone the merge would put the row straight back and the
           mailbox would carry an orphan forever.  Read the file back. */
        EXPECT(sidecar_load(dir, &sc) == 0 && sc.n == 3 &&
                   sidecar_find(&sc, pruned) < 0,
               "the scan-time prune removes the row from the sidecar file");
        m = imapd_mbox_find(&mb, 3);
        EXPECT(m != NULL, "find by uid");
        imapd_mbox_close(&mb);
    }
}

/* ---- (2b) uidlist sidecar: the multi-daemon merge ----
   imapd and jmapd share one maildir root and each keeps its own uidlist
   snapshot, so imapd_uidlist_save must merge with the on-disk file instead
   overwriting it.  These checks drive the real save path (open -> mutate ->
   close) and read the sidecar back the way a reader would. */

static size_t slurp(const char *path, char *buf, size_t bufsz) {
    FILE *f = fopen(path, "rb");
    size_t n;
    if (!f) return 0;
    n = fread(buf, 1, bufsz - 1, f);
    fclose(f);
    buf[n] = '\0';
    return n;
}

static int write_text(const char *path, const char *text) {
    FILE *f = fopen(path, "w");
    if (!f) return -1;
    if (fputs(text, f) < 0) { fclose(f); return -1; }
    return fclose(f);
}

static void uidlist_merge_test(const char *root) {
    ImapdConfig cfg;
    Mbox a, b;
    char dir[4200], path[4400];
    char msg[] = "Subject: m\r\n\r\nbody\r\n";
    char *b1 = NULL, *b2 = NULL, *b3 = NULL;
    Sidecar sc;

    memset(&cfg, 0, sizeof cfg);
    cfg.root = root;
    cfg.hostname = "test";
    if (imapd_mbox_dir(&cfg, "merge", "INBOX", dir, sizeof dir) != 0) {
        check_fail("merge: mbox_dir", NULL);
        return;
    }
    snprintf(path, sizeof path, "%s/%s", dir, IMAPD_UIDLIST_FILE);

    /* --- (i) interleaved writers: A's snapshot is stale when it saves --- */
    EXPECT(imapd_mbox_deliver(dir, msg, strlen(msg), 0, NULL) == 0 &&
           imapd_mbox_deliver(dir, msg, strlen(msg), 0, NULL) == 0,
           "merge: deliver two messages");
    EXPECT(imapd_mbox_open(&cfg, "merge", "INBOX", &a) == 0,
           "merge: A opens");
    EXPECT(a.nmsgs == 2 && a.uidnext == 3, "merge: A snapshot holds 2 rows");
    b1 = a.nmsgs > 0 ? strdup(a.msgs[0].base) : NULL;
    b2 = a.nmsgs > 1 ? strdup(a.msgs[1].base) : NULL;

    /* a third message lands while A holds its snapshot; B registers it */
    EXPECT(imapd_mbox_deliver(dir, msg, strlen(msg), 0, NULL) == 0,
           "merge: deliver a third message");
    EXPECT(imapd_mbox_peek(&cfg, "merge", "INBOX", &b) == 0,
           "merge: B opens over A's stale snapshot");
    EXPECT(b.nmsgs == 3 && b.uidnext == 4, "merge: B snapshot holds 3 rows");
    b3 = b.nmsgs > 2 ? strdup(b.msgs[2].base) : NULL;

    /* A now saves its stale snapshot (a flag change makes it dirty) */
    EXPECT(imapd_mbox_store(&a, 1, IMAIL_SEEN) == 0, "merge: A stores a flag");
    imapd_mbox_close(&a);

    EXPECT(sidecar_load(dir, &sc) == 0 && sc.n == 3,
           "merge: the stale save keeps both snapshots' rows");
    EXPECT(b1 && b2 && b3 && sidecar_find(&sc, b1) >= 0 &&
               sidecar_find(&sc, b2) >= 0 && sidecar_find(&sc, b3) >= 0,
           "merge: every base still has a row after the stale save");
    EXPECT(sc.uidnext == 4, "merge: the stale uidnext did not rewind");
    EXPECT(sc.uv == a.uidvalidity, "merge: same generation keeps uidvalidity");
    EXPECT(sc.uid[0] != sc.uid[1] && sc.uid[1] != sc.uid[2] &&
               sc.uid[0] != sc.uid[2],
           "merge: merged uids are unique");
    imapd_mbox_close(&b);
    EXPECT(imapd_mbox_peek(&cfg, "merge", "INBOX", &b) == 0 && b.nmsgs == 3 &&
               b.uidnext == 4 && b.msgs[0].uid == 1 && b.msgs[1].uid == 2 &&
               b.msgs[2].uid == 3,
           "merge: uids stable across the merge");
    imapd_mbox_close(&b);

    /* --- (ii) a deliberately deleted row is not resurrected --- */
    {
        Mbox p;
        char *pb2 = NULL;
        EXPECT(imapd_mbox_dir(&cfg, "merge", "Prune", dir, sizeof dir) == 0,
               "merge: prune mbox_dir");
        EXPECT(imapd_mbox_deliver(dir, msg, strlen(msg), 0, NULL) == 0 &&
               imapd_mbox_deliver(dir, msg, strlen(msg), 0, NULL) == 0,
               "merge: prune delivers two messages");
        EXPECT(imapd_mbox_open(&cfg, "merge", "Prune", &p) == 0 && p.nmsgs == 2,
               "merge: prune opens with 2 rows");
        pb2 = p.nmsgs > 1 ? strdup(p.msgs[1].base) : NULL;
        EXPECT(pb2 != NULL, "merge: prune captured the doomed base");
        EXPECT(imapd_mbox_expunge(&p, 2) == 0, "merge: prune expunges uid 2");
        imapd_mbox_close(&p);   /* the disk file still holds the row */
        EXPECT(sidecar_load(dir, &sc) == 0 && sc.n == 1 && pb2 &&
                   sidecar_find(&sc, pb2) < 0,
               "merge: an expunged row is not resurrected by the merge");
        free(pb2);
    }

    /* --- (iii) a failed temp write leaves the old sidecar intact --- */
    {
        Mbox q;
        char tmp_path[4464], before[4096], after[4096];
        size_t bl, al;
        EXPECT(imapd_mbox_dir(&cfg, "merge", "Atomic", dir, sizeof dir) == 0,
               "merge: atomic mbox_dir");
        EXPECT(imapd_mbox_deliver(dir, msg, strlen(msg), 0, NULL) == 0,
               "merge: atomic delivers one message");
        EXPECT(imapd_mbox_open(&cfg, "merge", "Atomic", &q) == 0,
               "merge: atomic opens");
        imapd_mbox_close(&q);   /* the scan save wrote the sidecar */
        snprintf(path, sizeof path, "%s/%s", dir, IMAPD_UIDLIST_FILE);
        bl = slurp(path, before, sizeof before);
        EXPECT(bl > 0, "merge: atomic read the sidecar");
        /* Block the exact temp path imapd_uidlist_save uses (pid + thread id:
           this check runs in the same thread the save will), so it fails. */
        snprintf(tmp_path, sizeof tmp_path, "%s.tmp.%ld.%lx", path,
                 (long)getpid(), (unsigned long)pthread_self());
        EXPECT(mkdir(tmp_path, 0755) == 0, "merge: block the temp path");
        EXPECT(imapd_mbox_open(&cfg, "merge", "Atomic", &q) == 0 &&
                   imapd_mbox_store(&q, 1, IMAIL_FLAGGED) == 0,
               "merge: atomic opens and stores");
        imapd_mbox_close(&q);   /* the save must fail, atomically */
        al = slurp(path, after, sizeof after);
        EXPECT(al == bl && memcmp(before, after, bl) == 0,
               "merge: a failed save leaves the old sidecar byte-identical");
        EXPECT(rmdir(tmp_path) == 0, "merge: unblock the temp path");
        EXPECT(imapd_mbox_open(&cfg, "merge", "Atomic", &q) == 0 &&
                   q.nmsgs == 1 && q.msgs[0].uid == 1,
               "merge: the surviving sidecar still loads its rows");
        imapd_mbox_close(&q);
    }

    /* --- (iv) uidvalidity generations: the larger one wins, the loser's
       rows are dropped --- */
    {
        Mbox g;
        char *gb = NULL;
        char text[512];
        uint32_t guv;
        /* disk generation newer */
        EXPECT(imapd_mbox_dir(&cfg, "merge", "GenDisk", dir, sizeof dir) == 0,
               "merge: gen mbox_dir (disk newer)");
        EXPECT(imapd_mbox_deliver(dir, msg, strlen(msg), 0, NULL) == 0,
               "merge: gen delivers (disk newer)");
        EXPECT(imapd_mbox_open(&cfg, "merge", "GenDisk", &g) == 0,
               "merge: gen opens (disk newer)");
        guv = g.uidvalidity;
        gb = g.nmsgs > 0 ? strdup(g.msgs[0].base) : NULL;
        snprintf(path, sizeof path, "%s/%s", dir, IMAPD_UIDLIST_FILE);
        snprintf(text, sizeof text, "%u 7\n6 handrow 6\n", guv + 1000);
        EXPECT(write_text(path, text) == 0, "merge: hand-write a newer sidecar");
        EXPECT(imapd_mbox_store(&g, 1, IMAIL_SEEN) == 0,
               "merge: gen stores (disk newer)");
        imapd_mbox_close(&g);
        EXPECT(sidecar_load(dir, &sc) == 0 && sc.uv == guv + 1000,
               "merge: the larger (disk) uidvalidity wins");
        EXPECT(sc.n == 1 && sidecar_find(&sc, "handrow") >= 0 && gb &&
                   sidecar_find(&sc, gb) < 0,
               "merge: the older generation's rows are dropped");
        EXPECT(sc.uidnext == 7, "merge: disk-generation uidnext kept");
        free(gb);
        gb = NULL;

        /* memory generation newer (the crash-truncate re-mint case) */
        EXPECT(imapd_mbox_dir(&cfg, "merge", "GenMem", dir, sizeof dir) == 0,
               "merge: gen mbox_dir (memory newer)");
        EXPECT(imapd_mbox_deliver(dir, msg, strlen(msg), 0, NULL) == 0,
               "merge: gen delivers (memory newer)");
        EXPECT(imapd_mbox_open(&cfg, "merge", "GenMem", &g) == 0,
               "merge: gen opens (memory newer)");
        guv = g.uidvalidity;
        gb = g.nmsgs > 0 ? strdup(g.msgs[0].base) : NULL;
        snprintf(path, sizeof path, "%s/%s", dir, IMAPD_UIDLIST_FILE);
        snprintf(text, sizeof text, "%u 2\n1 stale 2\n", guv - 1000);
        EXPECT(write_text(path, text) == 0, "merge: hand-write an older sidecar");
        EXPECT(imapd_mbox_store(&g, 1, IMAIL_SEEN) == 0,
               "merge: gen stores (memory newer)");
        imapd_mbox_close(&g);
        EXPECT(sidecar_load(dir, &sc) == 0 && sc.uv == guv,
               "merge: the larger (memory) uidvalidity wins");
        EXPECT(sc.n == 1 && gb && sidecar_find(&sc, gb) >= 0 &&
                   sidecar_find(&sc, "stale") < 0,
               "merge: the dead generation's rows are dropped");
        free(gb);
    }

    /* --- (v) the uid a save REPORTS is the one the file holds ---
       mbox_register hands that uid to APPENDUID/COPYUID, so it must report
       what the merge persisted, not what the caller assigned: the re-minted
       uid when another daemon claimed the caller's uid for a different base,
       and 0 (no APPENDUID) when the caller's row lost a uidvalidity-generation
       race and is not in the file at all.  Driven through the save's probe
       because the production window (the file changing between
       mbox_register's load and its locked save) cannot be staged
       deterministically. */
    {
        Mbox d;
        UidEnt one;
        char nb[] = "newbase";
        uint32_t puid;
        int at;

        memset(&d, 0, sizeof d);
        EXPECT(imapd_mbox_dir(&cfg, "merge", "Report", dir, sizeof dir) == 0,
               "merge: report mbox_dir");
        EXPECT(imapd_mbox_create(dir) == 0, "merge: report mbox_create");
        snprintf(d.dir, sizeof d.dir, "%.*s", (int)sizeof d.dir - 1, dir);
        snprintf(path, sizeof path, "%s/%s", dir, IMAPD_UIDLIST_FILE);

        /* (v-a) the uid the caller picked is already held by another base */
        EXPECT(write_text(path, "500 5\n3 other 2\n") == 0,
               "merge: hand-write a sidecar claiming uid 3");
        memset(&one, 0, sizeof one);
        one.base = nb;
        one.uid = 3;
        one.modseq = 4;
        puid = 0;
        EXPECT(imapd_uidlist_save(&d, 500, 5, &one, 1, nb, &puid) == 0 &&
                   puid != 0 && puid != 3,
               "merge: a re-minted row reports the new uid, not the claimed 3");
        at = sidecar_load(dir, &sc) == 0 ? sidecar_find(&sc, nb) : -1;
        EXPECT(at >= 0 && sc.n == 2 && sc.uid[at] == puid,
               "merge: the reported uid is the uid in the file");

        /* (v-b) the disk is from a NEWER generation: the caller's rows are
           dropped, so nothing is persisted for the base and the report is 0 */
        EXPECT(write_text(path, "9000 5\n3 other 2\n") == 0,
               "merge: hand-write a newer-generation sidecar");
        memset(&one, 0, sizeof one);
        one.base = nb;
        one.uid = 4;
        one.modseq = 5;
        puid = 7;
        EXPECT(imapd_uidlist_save(&d, 500, 5, &one, 1, nb, &puid) == 0 &&
                   puid == 0,
               "merge: a row dropped by the generation race reports uid 0");
        EXPECT(sidecar_load(dir, &sc) == 0 && sc.uv == 9000 &&
                   sidecar_find(&sc, nb) < 0,
               "merge: the dropped row really is absent from the file");
    }

    free(b1);
    free(b2);
    free(b3);
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

/* ---- (4x) delivery target: recipient local part -> mailbox ---- */

/* The SMTP ingest is what files a delivered message, and visage's config is
   what writes the recipient ("catch_all", alias destinations).  The folder
   half of "user+Folder" is therefore ours, and it must not be able to name a
   path: imapd_mbox_dir() turns any name into "<root>/<user>/.<name>". */
static void delivery_target_test(void) {
    char u[64], f[64];

    EXPECT(imapd_delivery_target("null", u, sizeof u, f, sizeof f) == 0 &&
               strcmp(u, "null") == 0 && strcmp(f, "INBOX") == 0,
           "delivery target: plain user -> INBOX");

    EXPECT(imapd_delivery_target("null+Spam", u, sizeof u, f, sizeof f) == 0 &&
               strcmp(u, "null") == 0 && strcmp(f, "Spam") == 0,
           "delivery target: user+folder");

    EXPECT(imapd_delivery_target("marshall.jaye+Archive", u, sizeof u,
                                 f, sizeof f) == 0 &&
               strcmp(u, "marshall.jaye") == 0 && strcmp(f, "Archive") == 0,
           "delivery target: dotted user+folder");

    EXPECT(imapd_delivery_target("null+", u, sizeof u, f, sizeof f) == -1,
           "delivery target: empty folder rejected");
    EXPECT(imapd_delivery_target("+Spam", u, sizeof u, f, sizeof f) == -1,
           "delivery target: empty user rejected");
    EXPECT(imapd_delivery_target("nu/ll+Spam", u, sizeof u, f, sizeof f) == -1,
           "delivery target: slash in user rejected");
    EXPECT(imapd_delivery_target("null+a/b", u, sizeof u, f, sizeof f) == -1,
           "delivery target: slash in folder rejected");
    EXPECT(imapd_delivery_target("null+..x", u, sizeof u, f, sizeof f) == -1,
           "delivery target: dot-dot in folder rejected");
    EXPECT(imapd_delivery_target("null+.hidden", u, sizeof u, f, sizeof f) == -1,
           "delivery target: leading dot in folder rejected");
    EXPECT(imapd_delivery_target("null+Spam.", u, sizeof u, f, sizeof f) == -1,
           "delivery target: trailing dot in folder rejected");
    EXPECT(imapd_delivery_target(".hidden", u, sizeof u, f, sizeof f) == -1,
           "delivery target: leading dot in user rejected");
    EXPECT(imapd_delivery_target("", u, sizeof u, f, sizeof f) == -1,
           "delivery target: empty local part rejected");

    /* the two halves must both fit; a truncated user is a wrong mailbox.
       "null" needs 5 bytes (4 + NUL), so a 4-byte buffer must be refused. */
    EXPECT(imapd_delivery_target("null+Spam", u, 4, f, sizeof f) == -1,
           "delivery target: undersized user buffer rejected");
    EXPECT(imapd_delivery_target("null+Spam", u, sizeof u, f, 3) == -1,
           "delivery target: undersized folder buffer rejected");
}

/* ---- (5a) SASL PLAIN field split (AUTHENTICATE PLAIN) ---- */

/* The decode above is only half the path: the decoded bytes must be split
   into authzid/authcid/passwd, and those pointers are what get compared
   against the credential.  Without this, no client could ever authenticate
   with AUTHENTICATE PLAIN while every unit test still passed. */
static void sasl_plain_test(void) {
    unsigned char buf[64];
    const char *z = NULL, *u = NULL, *p = NULL;
    size_t n;

    /* "" NUL "user" NUL "pass" - the form every client sends */
    n = 1 + 4 + 1 + 4;
    memcpy(buf, "\0user\0pass", n);
    buf[n] = '\0';
    EXPECT(imapd_sasl_plain_split(buf, n, &z, &u, &p) == 0 &&
               strcmp(z, "") == 0 && strcmp(u, "user") == 0 &&
               strcmp(p, "pass") == 0,
           "sasl plain split: empty authzid");

    /* non-empty authzid equal to the authcid (allowed: not a proxy login) */
    n = 4 + 1 + 4 + 1 + 4;
    memcpy(buf, "user\0user\0pass", n);
    buf[n] = '\0';
    EXPECT(imapd_sasl_plain_split(buf, n, &z, &u, &p) == 0 &&
               strcmp(z, "user") == 0 && strcmp(u, "user") == 0 &&
               strcmp(p, "pass") == 0,
           "sasl plain split: authzid present");

    /* NUL is the separator in this grammar (RFC 4616), so a password cannot
       itself contain one - it would be a second field, not a longer
       password.  Asserted as a boundary: empty authzid and authcid. */
    n = 1 + 0 + 1 + 4;
    memcpy(buf, "\0\0pass", n);
    buf[n] = '\0';
    EXPECT(imapd_sasl_plain_split(buf, n, &z, &u, &p) == 0 &&
               strcmp(z, "") == 0 && strcmp(u, "") == 0 &&
               strcmp(p, "pass") == 0,
           "sasl plain split: empty authzid and authcid");

    /* missing passwd field */
    n = 1 + 4;
    memcpy(buf, "\0user", n);
    buf[n] = '\0';
    EXPECT(imapd_sasl_plain_split(buf, n, &z, &u, &p) == -1,
           "sasl plain split: no passwd");

    /* bare authzid, no separators at all */
    n = 4;
    memcpy(buf, "user", n);
    buf[n] = '\0';
    EXPECT(imapd_sasl_plain_split(buf, n, &z, &u, &p) == -1,
           "sasl plain split: authzid only");

    /* empty passwd is a valid split, not malformed */
    n = 1 + 4 + 1;
    memcpy(buf, "\0user\0", n);
    buf[n] = '\0';
    EXPECT(imapd_sasl_plain_split(buf, n, &z, &u, &p) == 0 &&
               strcmp(u, "user") == 0 && strcmp(p, "") == 0,
           "sasl plain split: empty passwd");
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

        /* regression: a 3-key implicit-AND program must keep ALL keys in the
           chain (a previous version overwrote tail->b and dropped the middle
           key).  m[0] is seen+from-bob+subject-hello; m[1] is unseen so it
           must not match even though it is also from bob. */
        p = "SEEN FROM bob SUBJECT hello";
        EXPECT(imapd_search_parse_program(&p, &k) == 1,
               "search parse 3-key AND");
        EXPECT(MATCH(0, k) && !MATCH(1, k) && !MATCH(3, k),
               "search 3-key AND keeps all keys");
        imapd_search_free(k);

        /* CC/BCC/LARGER/SMALLER/KEYWORD/UNKEYWORD/MODSEQ: the keys FairEmail's
           search dialog emits (recipient terms are enabled by default, and a
           size filter adds LARGER).  Their absence made the whole SEARCH
           program invalid, which the client reports as an unsupported search. */
        {
            static const char *const cb[2] = {
                "From: a@x\r\nTo: me@x\r\nCc: carol@x\r\n\r\nbody\r\n",
                "From: a@x\r\nTo: me@x\r\nBcc: dave@x\r\n\r\nbody\r\n",
            };
            ImailDoc dd;

            dd.seq = 1;
            p = "CC carol";
            EXPECT(imapd_search_parse_program(&p, &k) == 1, "search parse CC");
            dd.m = &m[0]; dd.msg = cb[0]; dd.msglen = strlen(cb[0]);
            EXPECT(imapd_search_match(k, &dd, uidnext, 4), "search CC match");
            dd.msg = cb[1]; dd.msglen = strlen(cb[1]);
            EXPECT(!imapd_search_match(k, &dd, uidnext, 4), "search CC miss");
            imapd_search_free(k);

            p = "BCC dave";
            EXPECT(imapd_search_parse_program(&p, &k) == 1, "search parse BCC");
            EXPECT(imapd_search_match(k, &dd, uidnext, 4), "search BCC match");
            imapd_search_free(k);

            /* the shape FairEmail sends: OR over sender+recipients */
            p = "OR FROM a@x CC carol";
            EXPECT(imapd_search_parse_program(&p, &k) == 1,
                   "search parse OR FROM CC");
            EXPECT(imapd_search_match(k, &dd, uidnext, 4), "search OR FROM CC");
            imapd_search_free(k);
        }

        p = "LARGER 5";
        EXPECT(imapd_search_parse_program(&p, &k) == 1, "search parse LARGER");
        EXPECT(MATCH(0, k) && !MATCH(1, k), "search LARGER");
        imapd_search_free(k);

        p = "SMALLER 5";
        EXPECT(imapd_search_parse_program(&p, &k) == 1, "search parse SMALLER");
        EXPECT(!MATCH(0, k) && MATCH(1, k), "search SMALLER");
        imapd_search_free(k);

        p = "LARGER ten";
        EXPECT(imapd_search_parse_program(&p, &k) == -1,
               "search rejects non-numeric LARGER");
        imapd_search_free(k);

        m[0].flags = IMAIL_SEEN | IMAIL_FLAGGED;
        m[0].unk[0] = 'P';
        m[0].unk[1] = '\0';
        p = "KEYWORD \\Seen";
        EXPECT(imapd_search_parse_program(&p, &k) == 1, "search parse KEYWORD");
        EXPECT(MATCH(0, k) && !MATCH(1, k), "search KEYWORD system flag");
        imapd_search_free(k);

        p = "KEYWORD P";
        EXPECT(imapd_search_parse_program(&p, &k) == 1,
               "search parse KEYWORD letter");
        EXPECT(MATCH(0, k) && !MATCH(1, k), "search KEYWORD unknown letter");
        imapd_search_free(k);

        p = "UNKEYWORD P";
        EXPECT(imapd_search_parse_program(&p, &k) == 1,
               "search parse UNKEYWORD");
        EXPECT(!MATCH(0, k) && MATCH(1, k), "search UNKEYWORD");
        imapd_search_free(k);

        m[0].modseq = 100;
        m[1].modseq = 7;
        p = "MODSEQ 50";
        EXPECT(imapd_search_parse_program(&p, &k) == 1, "search parse MODSEQ");
        EXPECT(MATCH(0, k) && !MATCH(1, k), "search MODSEQ >= value");
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

/* ---- (7b) APPEND uid registration (RFC 4315 APPENDUID) ---- */

static void appenduid_test(const char *root) {
    ImapdConfig cfg;
    Mbox mb;
    char msg[] = "Message-ID: <a1@test>\r\nSubject: a\r\n\r\nbody\r\n";
    char msg2[] = "Message-ID: <a2@test>\r\nSubject: b\r\n\r\nbody\r\n";
    uint32_t uv1 = 0, uid1 = 0, uv2 = 0, uid2 = 0, uv3 = 0, uid3 = 0;

    memset(&cfg, 0, sizeof cfg);
    cfg.root = root;
    cfg.hostname = "test";

    EXPECT(imapd_mbox_deliver_uid(&cfg, "erin", "Sent", msg, strlen(msg),
                                  0, NULL, &uv1, &uid1) == 0 &&
               uid1 == 1 && uv1 > 0,
           "APPEND registers the first uid");
    EXPECT(imapd_mbox_deliver_uid(&cfg, "erin", "Sent", msg2, strlen(msg2),
                                  0, NULL, &uv2, &uid2) == 0 &&
               uid2 == 2 && uv2 == uv1,
           "APPEND registers uidnext, uidvalidity stable");

    /* APPENDUID must name the uid the SIDECAR holds, not a locally assigned
       one the locked merge could have re-minted or dropped: read the file
       back and match the row of the message the scan says carries uid1. */
    {
        char dir[4096], base[256];
        Sidecar sc;
        int at;
        EXPECT(imapd_mbox_dir(&cfg, "erin", "Sent", dir, sizeof dir) == 0,
               "APPEND mbox_dir");
        EXPECT(imapd_mbox_peek(&cfg, "erin", "Sent", &mb) == 0 &&
                   mb.nmsgs == 2 && mb.msgs[0].uid == uid1,
               "APPEND reopens the mailbox");
        snprintf(base, sizeof base, "%s",
                 mb.nmsgs > 0 ? mb.msgs[0].base : "");
        imapd_mbox_close(&mb);
        at = sidecar_load(dir, &sc) == 0 ? sidecar_find(&sc, base) : -1;
        EXPECT(at >= 0 && sc.uid[at] == uid1,
               "APPEND reports the uid the sidecar actually holds");
    }

    /* The scan must adopt the registered uids, not hand out fresh ones:
       that is exactly what a UIDPLUS client relies on. */
    EXPECT(imapd_mbox_peek(&cfg, "erin", "Sent", &mb) == 0 &&
               mb.nmsgs == 2 && mb.uidnext == 3 &&
               mb.msgs[0].uid == 1 && mb.msgs[1].uid == 2 &&
               mb.uidvalidity == uv1,
           "registered uids survive the maildir scan");
    imapd_mbox_close(&mb);

    /* a flagged APPEND (file goes to cur/) is registered the same way */
    EXPECT(imapd_mbox_deliver_uid(&cfg, "erin", "Sent", msg, strlen(msg),
                                  IMAIL_SEEN, NULL, &uv3, &uid3) == 0 &&
               uid3 == 3 && uv3 == uv1,
           "flagged APPEND registers the uid too");

    /* a rejected delivery must not consume a uid */
    {
        char bad[] = "Subject: x\r\n\r\n\x01" "bad\r\n";
        uint32_t uvb = 1, uidb = 1;
        EXPECT(imapd_mbox_deliver_uid(&cfg, "erin", "Sent", bad, strlen(bad),
                                      0, NULL, &uvb, &uidb) == -1 &&
                   uidb == 0,
               "APPEND rejects control bytes and reports no uid");
    }
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

/* ---- (9) move/copy (imapd_mbox_file) ---- */

static void move_copy_test(const char *root) {
    ImapdConfig cfg;
    Mbox in, arc;
    char dir[4096];
    char msg[] = "Subject: move\r\n\r\nbody\r\n";
    uint32_t u1, u2, u3;
    int i, seen;

    memset(&cfg, 0, sizeof cfg);
    cfg.root = root;

    EXPECT(imapd_mbox_dir(&cfg, "erin", "INBOX", dir, sizeof dir) == 0,
           "move: inbox dir");
    EXPECT(imapd_mbox_deliver(dir, msg, strlen(msg), 0, NULL) == 0,
           "move: deliver 1");
    EXPECT(imapd_mbox_deliver(dir, msg, strlen(msg), 0, NULL) == 0,
           "move: deliver 2");
    EXPECT(imapd_mbox_deliver(dir, msg, strlen(msg), IMAIL_SEEN, NULL) == 0,
           "move: deliver 3 (\\Seen)");

    memset(&in, 0, sizeof in);
    EXPECT(imapd_mbox_open(&cfg, "erin", "INBOX", &in) == 0, "move: open inbox");
    EXPECT(in.nmsgs == 3, "move: 3 in inbox");
    u1 = in.msgs[0].uid;
    u2 = in.msgs[1].uid;
    u3 = in.msgs[2].uid;

    /* COPY msg1 to a brand-new Archive: source keeps it, dest gets uid 1 */
    EXPECT(imapd_mbox_file(&cfg, "erin", &in, u1, "Archive", false, NULL, NULL) == 0,
           "copy: file ok");
    EXPECT(in.nmsgs == 3, "copy: source unchanged");
    memset(&arc, 0, sizeof arc);
    EXPECT(imapd_mbox_open(&cfg, "erin", "Archive", &arc) == 0,
           "copy: open archive");
    EXPECT(arc.nmsgs == 1, "copy: one in archive");
    EXPECT(arc.msgs[0].uid == 1, "copy: fresh uid 1 in new mailbox");
    imapd_mbox_close(&arc);

    /* Re-copying the same message must not duplicate the destination entry */
    EXPECT(imapd_mbox_file(&cfg, "erin", &in, u1, "Archive", false, NULL, NULL) == 0,
           "copy: re-copy ok");
    memset(&arc, 0, sizeof arc);
    imapd_mbox_open(&cfg, "erin", "Archive", &arc);
    EXPECT(arc.nmsgs == 1, "copy: re-copy not duplicated");
    imapd_mbox_close(&arc);

    /* MOVE msg2: gone from source, appears in dest with next fresh uid */
    EXPECT(imapd_mbox_file(&cfg, "erin", &in, u2, "Archive", true, NULL, NULL) == 0,
           "move: file ok");
    EXPECT(in.nmsgs == 2, "move: source shrunk");
    EXPECT(imapd_mbox_find(&in, u2) == NULL, "move: gone from source view");
    memset(&arc, 0, sizeof arc);
    imapd_mbox_open(&cfg, "erin", "Archive", &arc);
    EXPECT(arc.nmsgs == 2, "move: two in archive");
    EXPECT(arc.msgs[0].uid != arc.msgs[1].uid &&
               arc.msgs[0].uid == 1 && arc.msgs[1].uid == 2,
           "move: distinct fresh uids, no collision");
    imapd_mbox_close(&arc);

    /* MOVE the \\Seen message: flag must survive into the destination */
    EXPECT(imapd_mbox_file(&cfg, "erin", &in, u3, "Archive", true, NULL, NULL) == 0,
           "move: seen msg ok");
    imapd_mbox_close(&in);
    memset(&arc, 0, sizeof arc);
    imapd_mbox_open(&cfg, "erin", "Archive", &arc);
    EXPECT(arc.nmsgs == 3, "move: all three in archive");
    seen = 0;
    for (i = 0; i < (int)arc.nmsgs; i++)
        if (arc.msgs[i].flags & IMAIL_SEEN) seen++;
    EXPECT(seen == 1, "move: \\Seen flag preserved");
    imapd_mbox_close(&arc);

    /* persistence: only msg1 (copied) remains in Inbox */
    memset(&in, 0, sizeof in);
    imapd_mbox_open(&cfg, "erin", "INBOX", &in);
    EXPECT(in.nmsgs == 1, "move: inbox persists (only copied msg left)");
    imapd_mbox_close(&in);
}

/* ---- (10) Message-ID index (fast SEARCH HEADER Message-ID) ---- */

static void mid_index_test(const char *root) {
    ImapdConfig cfg;
    Mbox mb;
    char dir[4096];
    char msg[] = "Subject: m\r\nMessage-ID: <abc@test.com>\r\nFrom: a\r\n\r\nbody\r\n";
    char noid[] = "Subject: n\r\nFrom: a\r\n\r\nbody\r\n";

    memset(&cfg, 0, sizeof cfg);
    cfg.root = root;
    imapd_mbox_dir(&cfg, "frank", "INBOX", dir, sizeof dir);

    EXPECT(imapd_mbox_deliver(dir, noid, strlen(noid), 0, NULL) == 0,
           "mid: deliver no-id");
    EXPECT(imapd_mbox_deliver(dir, msg, strlen(msg), 0, NULL) == 0,
           "mid: deliver with-id");

    memset(&mb, 0, sizeof mb);
    imapd_mbox_open(&cfg, "frank", "INBOX", &mb);
    EXPECT(mb.nmsgs == 2, "mid: two messages");
    {
        int withmid = 0, withoutmid = 0, i;
        for (i = 0; i < (int)mb.nmsgs; i++) {
            if (mb.msgs[i].mid && strcmp(mb.msgs[i].mid, "<abc@test.com>") == 0)
                withmid++;
            else if (!mb.msgs[i].mid || !mb.msgs[i].mid[0])
                withoutmid++;
        }
        EXPECT(withmid == 1 && withoutmid == 1,
               "mid: extracted only for the message that has one");
    }
    imapd_mbox_close(&mb);

    /* the mid must persist in the uidlist across reopen */
    memset(&mb, 0, sizeof mb);
    imapd_mbox_open(&cfg, "frank", "INBOX", &mb);
    EXPECT(mb.nmsgs == 2 &&
               ((mb.msgs[0].mid && strcmp(mb.msgs[0].mid, "<abc@test.com>") == 0) ||
                (mb.msgs[1].mid && strcmp(mb.msgs[1].mid, "<abc@test.com>") == 0)),
           "mid: persisted across reopen");
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
    sasl_plain_test();
    delivery_target_test();
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
        uidlist_merge_test(root);
        deliver_test(root);
        appenduid_test(root);
        flags_store_test(root);
        move_copy_test(root);
        mid_index_test(root);
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
