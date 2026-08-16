/* mail_check.c — standalone checks for src/mail.c. Every check prints a
   per-line ok/FAIL; the process exits 0 only if all checks pass. */
#include "visage.h"
#include "mail.h"
#include <stdio.h>
#include <string.h>

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

/* Heap dup (avoids strdup availability concerns). */
static char *xdup(const char *s) {
    size_t n = strlen(s);
    char *p = malloc(n + 1);
    if (!p) return NULL;
    memcpy(p, s, n + 1);
    return p;
}

/* ---- address parsing ---- */
static void addr_ok(const char *s, const char *want_l, const char *want_d,
                    const char *what) {
    char *l = NULL, *d = NULL;
    int rc = mail_addr_parse(s, &l, &d);
    char buf[256];
    if (rc == 0 && l && d && strcmp(l, want_l) == 0 && strcmp(d, want_d) == 0)
        check_ok(what);
    else {
        snprintf(buf, sizeof buf, "rc=%d l=%s d=%s", rc, l ? l : "<null>",
                 d ? d : "<null>");
        check_fail(what, buf);
    }
    mail_addr_free(l, d);
}

static void addr_bad(const char *s, const char *what) {
    char *l = NULL, *d = NULL;
    int rc = mail_addr_parse(s, &l, &d);
    char buf[256];
    if (rc != 0 && l == NULL && d == NULL)
        check_ok(what);
    else {
        snprintf(buf, sizeof buf, "rc=%d (want -1) l=%p d=%p", rc,
                 (void *)l, (void *)d);
        check_fail(what, buf);
    }
}

/* ---- CRLF normalization ---- */
static void crlf_test(const char *in, const char *want, const char *what) {
    size_t len = strlen(in);
    size_t cap = 2 * len + 1;
    char *buf = malloc(cap);
    char detail[256];
    memcpy(buf, in, len);
    buf[len] = '\0';
    int rc = mail_normalize_crlf(buf, len);
    size_t wl = strlen(want);
    if (rc == (int)wl && memcmp(buf, want, wl) == 0)
        check_ok(what);
    else {
        snprintf(detail, sizeof detail, "rc=%d want_len=%zu", rc, wl);
        check_fail(what, detail);
    }
    free(buf);
}

/* ---- dot-stuffing ---- */
static void stuff_exact(const char *in, const char *want, const char *what) {
    size_t il = strlen(in);
    char *out = NULL;
    size_t ol = 0;
    int rc = mail_stuff_dots(in, il, &out, &ol);
    size_t wl = strlen(want);
    char detail[256];
    if (rc == 0 && ol == wl && memcmp(out, want, wl) == 0 && out[ol] == '\0')
        check_ok(what);
    else {
        snprintf(detail, sizeof detail, "rc=%d ol=%zu wl=%zu", rc, ol, wl);
        check_fail(what, detail);
    }
    mail_free(out);
}

static void unstuff_exact(const char *in, const char *want, const char *what) {
    size_t il = strlen(in);
    char *buf = xdup(in);
    size_t n = il;
    int rc = mail_unstuff_dots(buf, &n);
    size_t wl = strlen(want);
    char detail[256];
    if (rc == 0 && n == wl && memcmp(buf, want, wl) == 0)
        check_ok(what);
    else {
        snprintf(detail, sizeof detail, "rc=%d n=%zu wl=%zu", rc, n, wl);
        check_fail(what, detail);
    }
    mail_free(buf);
}

static void stuff_roundtrip(const char *orig, const char *what) {
    size_t ol = strlen(orig);
    char *stuffed = NULL, *tmp = NULL;
    size_t sl = 0;
    int rc1 = mail_stuff_dots(orig, ol, &stuffed, &sl);
    int rc2 = -1;
    char detail[256];
    if (rc1 == 0) {
        tmp = malloc(sl + 1);
        memcpy(tmp, stuffed, sl);
        tmp[sl] = '\0';
        rc2 = mail_unstuff_dots(tmp, &sl);
    }
    if (rc1 == 0 && rc2 == 0 && tmp && sl == ol && memcmp(tmp, orig, ol) == 0)
        check_ok(what);
    else {
        snprintf(detail, sizeof detail, "rc1=%d rc2=%d sl=%zu ol=%zu", rc1, rc2,
                 sl, ol);
        check_fail(what, detail);
    }
    mail_free(stuffed);
    mail_free(tmp);
}

/* ---- header get/set/remove ---- */
static void header_tests(void) {
    const char msg[] =
        "From: alice@example.com\r\n"
        "Subject: Hello\r\n"
        "\tWorld\r\n"
        " Folded-again\r\n"
        "To: bob@example.com\r\n"
        "Cc: carol@example.com\r\n"
        "\r\n"
        "Body starts here\r\n"
        "X-OnlyBody: hidden\r\n";
    size_t mlen = sizeof(msg) - 1;
    char out[256];

    EXPECT(mail_header_get(msg, mlen, "from", out, sizeof out) == 0 &&
               strcmp(out, "alice@example.com") == 0,
           "header_get From");
    EXPECT(mail_header_get(msg, mlen, "SUBJECT", out, sizeof out) == 0 &&
               strcmp(out, "Hello World Folded-again") == 0,
           "header_get unfolds folded Subject");
    EXPECT(mail_header_get(msg, mlen, "to", out, sizeof out) == 0 &&
               strcmp(out, "bob@example.com") == 0,
           "header_get To");
    EXPECT(mail_header_get(msg, mlen, "CC", out, sizeof out) == 0 &&
               strcmp(out, "carol@example.com") == 0,
           "header_get Cc case-insensitive");
    EXPECT(mail_header_get(msg, mlen, "X-OnlyBody", out, sizeof out) == -1,
           "header_get does not search body");
    EXPECT(mail_header_get(msg, mlen, "X-Missing", out, sizeof out) == -1,
           "header_get missing returns -1");
}

static void set_check(const char *in, const char *name, const char *value,
                      const char *want, const char *what) {
    char *m = xdup(in);
    size_t mlen = strlen(m);
    int rc = mail_header_set(&m, &mlen, name, value);
    size_t wl = strlen(want);
    char detail[256];
    if (rc == 0 && mlen == wl && memcmp(m, want, wl) == 0 && m[mlen] == '\0')
        check_ok(what);
    else {
        snprintf(detail, sizeof detail, "rc=%d mlen=%zu wl=%zu", rc, mlen, wl);
        check_fail(what, detail);
    }
    mail_free(m);
}

static void remove_check(const char *in, const char *name, const char *want,
                         const char *what) {
    char *m = xdup(in);
    size_t mlen = strlen(m);
    int rc = mail_header_remove(&m, &mlen, name);
    size_t wl = strlen(want);
    char detail[256];
    if (rc == 0 && mlen == wl && memcmp(m, want, wl) == 0 && m[mlen] == '\0')
        check_ok(what);
    else {
        snprintf(detail, sizeof detail, "rc=%d mlen=%zu wl=%zu", rc, mlen, wl);
        check_fail(what, detail);
    }
    mail_free(m);
}

/* ---- sanitize ---- */
static void sanitize_tests(void) {
    const char in[] =
        "From: attacker@evil.example\n"
        "Subject: Test\n"
        "To: victim@example.com\n"
        "X-Keep: yes\n"
        "\n"
        "Hello body\n"
        ".dot line\n";

    const char want[] =
        "Received: by mail.visage.test from client with SMTP\r\n"
        "Subject: Test\r\n"
        "To: victim@example.com\r\n"
        "X-Keep: yes\r\n"
        "Return-Path: <alias@example.com>\r\n"
        "From: \"S via alias\" <reply+deadbeef@example.com>\r\n"
        "Sender: <alias@example.com>\r\n"
        "Reply-To: reply+deadbeef@example.com\r\n"
        "\r\n"
        "Hello body\r\n"
        ".dot line\r\n";

    MailRewrite rw = {
        .received    = "by mail.visage.test from client with SMTP",
        .return_path = "<alias@example.com>",
        .from        = "\"S via alias\" <reply+deadbeef@example.com>",
        .sender      = "<alias@example.com>",
        .reply_to    = "reply+deadbeef@example.com",
    };

    char *out = NULL;
    size_t outlen = 0;
    int rc = mail_sanitize_for_forward(in, sizeof(in) - 1, &rw, &out, &outlen);
    size_t wl = sizeof(want) - 1;
    char detail[256];
    if (rc == 0 && outlen == wl && memcmp(out, want, wl) == 0 && out[wl] == '\0')
        check_ok("sanitize adds Received + rewrites From/Sender/Reply-To + keeps body");
    else {
        snprintf(detail, sizeof detail, "rc=%d outlen=%zu wl=%zu", rc, outlen, wl);
        check_fail("sanitize adds Received + rewrites From/Sender/Reply-To + keeps body",
                   detail);
    }
    mail_free(out);

    /* CRLF injection in a rewrite field must be rejected. */
    const char msgin[] = "From: a@b\r\n\r\nbody\r\n";
    MailRewrite bad = { .reply_to = "x@y\r\nBcc: evil@example.com" };
    out = NULL;
    outlen = 0;
    rc = mail_sanitize_for_forward(msgin, strlen(msgin), &bad, &out, &outlen);
    EXPECT(rc != 0 && out == NULL && outlen == 0,
           "sanitize rejects CRLF injection in Reply-To");

    bad.reply_to = NULL;
    bad.received = "x\r\nInjected: yes";
    out = NULL;
    outlen = 0;
    rc = mail_sanitize_for_forward(msgin, strlen(msgin), &bad, &out, &outlen);
    EXPECT(rc != 0 && out == NULL && outlen == 0,
           "sanitize rejects CRLF injection in Received");
}

/* ---- header_set input validation ---- */
static void validation_tests(void) {
    char *m = xdup("Subject: hi\r\n\r\nb\r\n");
    size_t mlen = strlen(m);
    EXPECT(mail_header_set(&m, &mlen, "From", "a@b\r\nX: y") != 0,
           "header_set rejects CRLF in value");
    EXPECT(mail_header_set(&m, &mlen, "From: evil", "a@b") != 0,
           "header_set rejects ':' in name");
    mail_free(m);
}

int main(void) {
    /* address parsing: valid */
    addr_ok("alice@example.com", "alice", "example.com", "addr bare");
    addr_ok("<alice@example.com>", "alice", "example.com", "addr angle-bracket");
    addr_ok("  bob@sub.example.org  ", "bob", "sub.example.org", "addr trims ws");
    addr_ok("user+tag@example.com", "user+tag", "example.com", "addr plus-tag");
    addr_ok("a.b.c@d.e.f", "a.b.c", "d.e.f", "addr dotted");
    addr_ok("\"alice\"@example.com", "\"alice\"", "example.com", "addr quoted local");
    addr_ok("\"a b\"@example.com", "\"a b\"", "example.com", "addr quoted local with space");
    addr_ok("\"john..doe\"@x.com", "\"john..doe\"", "x.com", "addr quoted local with doubled dots");
    addr_ok("\"a@b\"@example.com", "\"a@b\"", "example.com", "addr inner @ inside quotes");
    addr_ok("\"a>b\"@x.com", "\"a>b\"", "x.com", "addr angle brackets inside quotes");
    addr_ok("\"a\\\"b\"@example.com", "\"a\\\"b\"", "example.com", "addr escaped quote in local");
    addr_ok("\"a\\\\b\"@x.com", "\"a\\\\b\"", "x.com", "addr escaped backslash in local");
    addr_ok("alice@[127.0.0.1]", "alice", "[127.0.0.1]", "addr IPv4 address-literal");
    addr_ok("alice@[IPv6:2001:db8::1]", "alice", "[IPv6:2001:db8::1]", "addr IPv6 address-literal");
    addr_ok("\"a b\"@[127.0.0.1]", "\"a b\"", "[127.0.0.1]", "addr quoted local + address-literal");

    /* address parsing: invalid */
    addr_bad(NULL, "addr NULL rejected");
    addr_bad("", "addr empty rejected");
    addr_bad("no-at-sign", "addr missing @ rejected");
    addr_bad("@example.com", "addr empty local rejected");
    addr_bad("alice@", "addr empty domain rejected");
    addr_bad("alice@example.com extra", "addr space in domain rejected");
    addr_bad("alice example@x.com", "addr space in local rejected");
    addr_bad("<alice@example.com", "addr unbalanced < rejected");
    addr_bad("alice@example.com>", "addr stray > rejected");
    addr_bad("alice@@example.com", "addr double @ rejected");
    addr_bad(".alice@example.com", "addr leading dot rejected");
    addr_bad("alice.@example.com", "addr trailing dot rejected");
    addr_bad("alice..b@example.com", "addr doubled dot rejected");
    addr_bad("alice@example..com", "addr doubled dot domain rejected");
    addr_bad("alice@example.com\n", "addr control char rejected");
    addr_bad("\"unclosed@example.com", "addr unclosed quote rejected");
    addr_bad("\"\"@x.com", "addr empty quoted local rejected");
    addr_bad("alice@[127.0.0.1", "addr unbalanced domain literal rejected");
    addr_bad("alice@[]", "addr empty domain literal rejected");
    addr_bad("\"a\r\nb\"@x", "addr CRLF inside quotes rejected");
    addr_bad("<>", "addr empty angle-brackets rejected");

    /* CRLF normalization */
    crlf_test("a\nb", "a\r\nb", "crlf bare LF");
    crlf_test("a\rb", "a\r\nb", "crlf bare CR");
    crlf_test("a\r\nb", "a\r\nb", "crlf existing CRLF unchanged");
    crlf_test("a\nb\rc\r\nd", "a\r\nb\r\nc\r\nd", "crlf mixed");
    crlf_test("\n", "\r\n", "crlf lone LF");
    crlf_test("plain", "plain", "crlf no newline");

    /* dot-stuff / unstuff */
    stuff_exact(".a\n..b\n", "..a\n...b\n", "stuff leading dots");
    unstuff_exact("..a\r\n...b\r\n", ".a\r\n..b\r\n", "unstuff leading dots");
    stuff_roundtrip("hello\r\n.world\r\n..two\r\nend",
                    "stuff/unstuff round-trip");

    /* headers */
    header_tests();
    set_check("From: old@example.com\r\nSubject: hi\r\n\r\nbody\r\n",
              "From", "new@example.com",
              "From: new@example.com\r\nSubject: hi\r\n\r\nbody\r\n",
              "header_set replaces in place");
    set_check("Subject: hi\r\n\r\nbody\r\n", "X-Custom", "yes",
              "Subject: hi\r\nX-Custom: yes\r\n\r\nbody\r\n",
              "header_set appends");
    remove_check("From: a@b\r\nX-Junk: one\r\n two\r\nSubject: s\r\n\r\nbody\r\n",
                 "x-junk",
                 "From: a@b\r\nSubject: s\r\n\r\nbody\r\n",
                 "header_remove removes folded continuation");
    remove_check("X-A: 1\r\nX-A: 2\r\nSubject: s\r\n\r\nb\r\n", "X-A",
                 "Subject: s\r\n\r\nb\r\n",
                 "header_remove removes all occurrences");

    /* sanitize + validation */
    sanitize_tests();
    validation_tests();

    printf("\n%d checks, %d failed\n", nchecks, nfails);
    return nfails ? 1 : 0;
}
