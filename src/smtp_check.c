/* smtp_check.c — standalone checks for src/smtp_out.c + src/smtp.h.
   No live sockets: tests the base64 helper (known vectors), the status-string
   mapping, reply-code parsing, and Envelope construction. Returns 0 only if
   all checks pass. The full SMTP dialogue is exercised by the S8 e2e harness
   against a fake server. */
#include "visage.h"
#include "smtp.h"
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

/* ---- base64 ---- */
static void b64_test(const char *in, size_t inlen, const char *want,
                     const char *what) {
    char out[256];
    size_t outlen = 0;
    int rc = smtp_b64_encode(in, inlen, out, sizeof out, &outlen);
    size_t wl = strlen(want);
    char detail[256];
    if (rc == 0 && outlen == wl && memcmp(out, want, wl) == 0 &&
        out[wl] == '\0')
        check_ok(what);
    else {
        snprintf(detail, sizeof detail, "rc=%d outlen=%zu want=%s", rc,
                 outlen, want);
        check_fail(what, detail);
    }
}

/* AUTH PLAIN vector with embedded NUL bytes (the base64 OUTPUT is plain text,
   so a normal string comparison is fine). */
static void b64_nul_test(const char *what) {
    /* RFC 4954 example: "\0user\0pass" -> "AHVzZXIAcGFzcw==" */
    static const unsigned char in[] = { 0, 'u', 's', 'e', 'r', 0, 'p', 'a',
                                        's', 's' };
    const char *want = "AHVzZXIAcGFzcw==";
    char out[64];
    size_t outlen = 0;
    int rc = smtp_b64_encode(in, sizeof in, out, sizeof out, &outlen);
    size_t wl = strlen(want);
    char detail[256];
    if (rc == 0 && outlen == wl && memcmp(out, want, wl) == 0 &&
        out[wl] == '\0')
        check_ok(what);
    else {
        snprintf(detail, sizeof detail, "rc=%d outlen=%zu", rc, outlen);
        check_fail(what, detail);
    }
}

static void b64_toosmall(const char *what) {
    char out[4];               /* "foo" needs 5 bytes (4 + NUL) */
    size_t outlen = 12345;     /* must be reset to 0 on failure */
    int rc = smtp_b64_encode("foo", 3, out, sizeof out, &outlen);
    EXPECT(rc == -1 && outlen == 0, what);
}

/* ---- Envelope construction dry-run (no sockets) ---- */
static void envelope_test(void) {
    const char body[] = "Subject: test\r\n\r\n.first\r\n..second\r\nend\r\n";
    struct Envelope e = {
        .from    = "alice@example.com",
        .to      = "bob@example.com",
        .body    = body,
        .bodylen = sizeof body - 1,
    };

    EXPECT(e.from != NULL && e.to != NULL && e.body != NULL &&
               e.bodylen == strlen(body),
           "Envelope construction");

    /* Dry-run the same dot-stuffing smtp_out applies to the body. */
    char *stuffed = NULL;
    size_t slen = 0;
    int rc = mail_stuff_dots(e.body, e.bodylen, &stuffed, &slen);
    const char *want = "Subject: test\r\n\r\n..first\r\n...second\r\nend\r\n";
    size_t wl = strlen(want);
    char detail[256];
    if (rc == 0 && slen == wl && memcmp(stuffed, want, wl) == 0)
        check_ok("Envelope dry-run dot-stuff");
    else {
        snprintf(detail, sizeof detail, "rc=%d slen=%zu wl=%zu", rc, slen, wl);
        check_fail("Envelope dry-run dot-stuff", detail);
    }
    mail_free(stuffed);
}

/* ---- smtp_in pure decision logic (no sockets) ---- */

static void size_parse_test(void) {
    uint64_t sz = 0;
    bool present = false;

    EXPECT(smtp_in_parse_size("SIZE=1000", &sz, &present) == 0 &&
               present && sz == 1000,
           "smtp_in size parse SIZE=1000");
    present = false;
    EXPECT(smtp_in_parse_size(" BODY=8BITMIME SIZE=2048", &sz, &present) == 0 &&
               present && sz == 2048,
           "smtp_in size parse SIZE among params");
    present = true;
    EXPECT(smtp_in_parse_size("BODY=8BITMIME", &sz, &present) == 0 && !present,
           "smtp_in size parse absent -> present false");
    EXPECT(smtp_in_parse_size("SIZE=", &sz, &present) == -1,
           "smtp_in size parse rejects empty value");
    EXPECT(smtp_in_parse_size("SIZE=abc", &sz, &present) == -1,
           "smtp_in size parse rejects non-numeric");
    EXPECT(smtp_in_parse_size("SIZE=99999999999999999999", &sz, &present) == -1,
           "smtp_in size parse rejects overflow");
}

static void rcpt_decision_test(void) {
    char tpl[] = "/tmp/visage_smtp_XXXXXX";
    char *dir = mkdtemp(tpl);
    char *dom[1];
    Config cfg;
    Store *s;

    if (!dir) { check_fail("rcpt decision (mkdtemp)", "mkdtemp failed"); return; }

    memset(&cfg, 0, sizeof cfg);
    dom[0] = "example.com";
    cfg.domains = dom;
    cfg.ndomains = 1;
    cfg.reply.prefix = "reply";
    cfg.reply.separator = "+";
    cfg.catch_all = "";

    s = store_open(dir);
    if (!s) { check_fail("rcpt decision (store_open)", "store_open failed"); return; }

    (void)store_alias_add(s, "jane@example.com", "jane@realmail.example");

    EXPECT(smtp_in_rcpt_ok(s, &cfg, "jane@example.com") == RCPT_OK,
           "rcpt: exact alias accepted");
    EXPECT(smtp_in_rcpt_ok(s, &cfg, "nobody@example.com") == RCPT_NOROUTE,
           "rcpt: unknown local rejected (no route)");
    EXPECT(smtp_in_rcpt_ok(s, &cfg, "jane@other.org") == RCPT_BAD_DOMAIN,
           "rcpt: foreign domain rejected");
    EXPECT(smtp_in_rcpt_ok(s, &cfg, "not-an-address") == RCPT_NOROUTE,
           "rcpt: malformed address rejected");
    EXPECT(smtp_in_rcpt_ok(s, &cfg, "JANE@EXAMPLE.COM") == RCPT_OK,
           "rcpt: alias match is case-insensitive");
    EXPECT(smtp_in_rcpt_ok(s, &cfg, "jane@EXAMPLE.COM") == RCPT_OK,
           "rcpt: domain gate is case-insensitive (resolves to alias)");

    (void)store_revmap_add(s, "deadbeefdeadbeefdeadbeefdeadbeef",
                           "orig@foo.org", "jane@example.com");
    EXPECT(smtp_in_rcpt_ok(s, &cfg,
          "reply+deadbeefdeadbeefdeadbeefdeadbeef@example.com") == RCPT_OK,
           "rcpt: valid reply token accepted");
    EXPECT(smtp_in_rcpt_ok(s, &cfg,
          "reply+ffffffffffffffffffffffffffffffff@example.com") == RCPT_NOROUTE,
           "rcpt: unknown reply token rejected");

    cfg.catch_all = "catch@realmail.example";
    EXPECT(smtp_in_rcpt_ok(s, &cfg, "anything@example.com") == RCPT_OK,
           "rcpt: catch-all accepted");
    cfg.catch_all = "";
    EXPECT(smtp_in_rcpt_ok(s, &cfg, "anything@example.com") == RCPT_NOROUTE,
           "rcpt: catch-all disabled rejects");

    (void)store_close(s);
}

/* ---- outbound STARTTLS pure helpers (S-B2) ---- */

static void tls_valid_test(void) {
    EXPECT(smtp_tls_valid("none") == 0, "tls_valid accepts none");
    EXPECT(smtp_tls_valid("starttls") == 0, "tls_valid accepts starttls");
    EXPECT(smtp_tls_valid("starttls-verify") == 0,
           "tls_valid accepts starttls-verify");
    EXPECT(smtp_tls_valid("tls") == -1, "tls_valid rejects tls");
    EXPECT(smtp_tls_valid("") == -1, "tls_valid rejects empty");
    EXPECT(smtp_tls_valid(NULL) == -1, "tls_valid rejects NULL");
}

static void cap_test(void) {
    /* STARTTLS on the final "250 " line */
    const char *r1 = "250-localhost\r\n250-8BITMIME\r\n250 STARTTLS\r\n";
    EXPECT(smtp_reply_has_cap(r1, strlen(r1), "STARTTLS"),
           "cap: STARTTLS on final 250 line");

    /* STARTTLS on a "250-" continuation line */
    const char *r2 =
        "250-localhost\r\n250-STARTTLS\r\n250-8BITMIME\r\n250 OK\r\n";
    EXPECT(smtp_reply_has_cap(r2, strlen(r2), "STARTTLS"),
           "cap: STARTTLS on a 250- continuation line");

    /* match is case-insensitive */
    const char *r3 = "250-localhost\r\n250 starttls\r\n";
    EXPECT(smtp_reply_has_cap(r3, strlen(r3), "STARTTLS"),
           "cap: STARTTLS match is case-insensitive");

    /* not advertised -> false */
    const char *r4 = "250-localhost\r\n250-8BITMIME\r\n250 SIZE 100000\r\n";
    EXPECT(!smtp_reply_has_cap(r4, strlen(r4), "STARTTLS"),
           "cap: STARTTLS absent -> false");

    /* no prefix false-positive on a longer keyword */
    const char *r5 = "250-STARTTLSFOO\r\n";
    EXPECT(!smtp_reply_has_cap(r5, strlen(r5), "STARTTLS"),
           "cap: no prefix match on STARTTLSFOO");

    EXPECT(!smtp_reply_has_cap("", 0, "STARTTLS"), "cap: empty reply -> false");
    EXPECT(!smtp_reply_has_cap(NULL, 0, "STARTTLS"), "cap: NULL reply -> false");
    EXPECT(!smtp_reply_has_cap("250 OK\r\n", 7, ""), "cap: empty cap -> false");
    EXPECT(!smtp_reply_has_cap("250 OK\r\n", 7, NULL), "cap: NULL cap -> false");
}

/* ---- outbound AUTH PLAIN classification (R3) ---- */

/* smtp_auth_class maps a final AUTH reply code to its delivery class.  The
   334 routing decision itself lives in smtp_auth_plain (needs a live SmtpConn),
   so this pins the classification that both the single-line and two-step paths
   converge on. */
static void auth_class_test(void) {
    EXPECT(smtp_auth_class(235) == SMTP_OK, "auth_class 235 -> OK");
    EXPECT(smtp_auth_class(535) == SMTP_PERMFAIL, "auth_class 535 -> PERMFAIL");
    EXPECT(smtp_auth_class(534) == SMTP_PERMFAIL, "auth_class 534 -> PERMFAIL");
    EXPECT(smtp_auth_class(450) == SMTP_TEMPFAIL, "auth_class 450 -> TEMPFAIL");
    EXPECT(smtp_auth_class(454) == SMTP_TEMPFAIL, "auth_class 454 -> TEMPFAIL");
    EXPECT(smtp_auth_class(334) == SMTP_ERROR,
           "auth_class unexpected 334 -> ERROR");
    EXPECT(smtp_auth_class(250) == SMTP_ERROR, "auth_class 250 -> ERROR");
    EXPECT(smtp_auth_class(301) == SMTP_ERROR, "auth_class 301 -> ERROR");
    EXPECT(smtp_auth_class(100) == SMTP_ERROR, "auth_class 100 -> ERROR");
    EXPECT(smtp_auth_class(600) == SMTP_ERROR, "auth_class 600 -> ERROR");
}

static void alias_read_only_test(void) {
    /* Build a Config with two config-declared aliases; config_alias_read_only
       must flag exact and case-insensitive matches and reject non-matches. */
    ConfigAlias aliases[2];
    char *d0[] = {"dest0@example.com"};
    char *d1[] = {"dest1@example.com"};
    aliases[0].alias = "info@example.com";
    aliases[0].destinations = d0;
    aliases[0].ndestinations = 1;
    aliases[1].alias = "Sales@Example.COM";
    aliases[1].destinations = d1;
    aliases[1].ndestinations = 1;

    Config cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.aliases = aliases;
    cfg.naliases = 2;

    EXPECT(config_alias_read_only(&cfg, "info@example.com") != 0,
           "alias_read_only exact match");
    EXPECT(config_alias_read_only(&cfg, "sales@example.com") != 0,
           "alias_read_only case-insensitive match");
    EXPECT(config_alias_read_only(&cfg, "nope@example.com") == 0,
           "alias_read_only non-match");
    EXPECT(config_alias_read_only(&cfg, NULL) == 0,
           "alias_read_only NULL alias");
    EXPECT(config_alias_read_only(NULL, "info@example.com") == 0,
           "alias_read_only NULL cfg");
}

int main(void) {
    /* base64 known vectors (RFC 4648) */
    b64_test("", 0, "", "base64 empty");
    b64_test("f", 1, "Zg==", "base64 f");
    b64_test("fo", 2, "Zm8=", "base64 fo");
    b64_test("foo", 3, "Zm9v", "base64 foo");
    b64_test("foob", 4, "Zm9vYg==", "base64 foob");
    b64_test("fooba", 5, "Zm9vYmE=", "base64 fooba");
    b64_test("foobar", 6, "Zm9vYmFy", "base64 foobar");
    b64_nul_test("base64 AUTH PLAIN vector (embedded NUL)");
    b64_toosmall("base64 rejects too-small output");

    /* status-string mapping */
    EXPECT(strcmp(smtp_status_str(SMTP_OK), "ok") == 0, "status_str ok");
    EXPECT(strcmp(smtp_status_str(SMTP_TEMPFAIL), "tempfail") == 0,
           "status_str tempfail");
    EXPECT(strcmp(smtp_status_str(SMTP_PERMFAIL), "permfail") == 0,
           "status_str permfail");
    EXPECT(strcmp(smtp_status_str(SMTP_ERROR), "error") == 0,
           "status_str error");
    EXPECT(strcmp(smtp_status_str(999), "unknown") == 0, "status_str unknown");
    EXPECT(smtp_status_str(-1) != NULL, "status_str never NULL");
    EXPECT(SMTP_OK == 0 && SMTP_TEMPFAIL == 1 && SMTP_PERMFAIL == 2 &&
               SMTP_ERROR == 3,
           "status enum values");

    /* backoff cadence (shared by smtp_out in-attempt retry + durable-queue
       across-attempt re-drive) */
    EXPECT(smtp_backoff_sec(1) == 1, "backoff_sec 1 -> 1s");
    EXPECT(smtp_backoff_sec(2) == 2, "backoff_sec 2 -> 2s");
    EXPECT(smtp_backoff_sec(3) == 4, "backoff_sec 3 -> 4s");
    EXPECT(smtp_backoff_sec(4) == 8, "backoff_sec 4 -> 8s");
    EXPECT(smtp_backoff_sec(5) == 16, "backoff_sec 5 -> 16s");
    EXPECT(smtp_backoff_sec(6) == 32, "backoff_sec 6 -> 32s");
    EXPECT(smtp_backoff_sec(12) == 2048, "backoff_sec 12 -> 2048s");
    EXPECT(smtp_backoff_sec(13) == 3600, "backoff_sec 13 -> capped 3600s");
    EXPECT(smtp_backoff_sec(100) == 3600, "backoff_sec 100 -> capped 3600s");

    /* reply-code parsing */
    {
        int code = 0;
        EXPECT(smtp_reply_code("250 OK", &code) == 0 && code == 250,
               "reply_code 250");
        EXPECT(smtp_reply_code("354 go ahead", &code) == 0 && code == 354,
               "reply_code 354");
        EXPECT(smtp_reply_code("550", &code) == 0 && code == 550,
               "reply_code 550");
        EXPECT(smtp_reply_code(" 250", &code) == -1,
               "reply_code rejects leading space");
        EXPECT(smtp_reply_code("25x", &code) == -1,
               "reply_code rejects non-digit");
        EXPECT(smtp_reply_code("", &code) == -1, "reply_code rejects empty");
        EXPECT(smtp_reply_code(NULL, &code) == -1, "reply_code rejects NULL");
    }

    /* Envelope construction dry-run */
    envelope_test();

    /* smtp_in pure decision logic (no sockets) */
    size_parse_test();
    rcpt_decision_test();

    /* outbound STARTTLS pure helpers (S-B2) */
    tls_valid_test();
    cap_test();

    /* outbound AUTH PLAIN classification (R3) */
    auth_class_test();

    /* config-declared aliases are read-only (admin lock) */
    alias_read_only_test();

    printf("\n%d checks, %d failed\n", nchecks, nfails);
    return nfails ? 1 : 0;
}
