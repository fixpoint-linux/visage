/* outbox_check.c — standalone checks for outbox's pure helpers (no sockets):
 * strict base64 decode, passwd-file load + constant-time credential check,
 * allowed-domain policy, and From-header domain extraction.  The full
 * submission dialogue (530/554/235/250 policy, STARTTLS, DKIM + MX delivery)
 * is exercised by the integration harness in tests/outbox_submit.sh against a
 * loopback fake-MX + fake-DNS.  Returns 0 only if all checks pass. */
#include "outbox.h"
#include "visage.h"
#include "smtp.h"
#include "mail.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
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

/* ---- base64 decode (strict) ---- */
static void b64_roundtrip(const char *what) {
    /* RFC 4954 AUTH PLAIN vector: "\0user\0pass" -> "AHVzZXIAcGFzcw==" */
    static const unsigned char plain[] = { 0, 'u', 's', 'e', 'r', 0, 'p', 'a',
                                           's', 's' };
    char b64[64];
    size_t elen = 0;
    unsigned char back[64];
    size_t blen = 0;
    if (smtp_b64_encode(plain, sizeof plain, b64, sizeof b64, &elen) != 0) {
        check_fail(what, "encode failed");
        return;
    }
    if (strcmp(b64, "AHVzZXIAcGFzcw==") != 0) {
        check_fail(what, "unexpected b64");
        return;
    }
    if (outbox_b64_decode(b64, elen, back, sizeof back, &blen) != 0 ||
        blen != sizeof plain || memcmp(back, plain, sizeof plain) != 0) {
        check_fail(what, "decode roundtrip mismatch");
        return;
    }
    check_ok(what);
}

static void b64_reject(const char *what) {
    unsigned char out[64];
    size_t outlen = 0;
    /* single char: not a full byte and non-zero leftover bits */
    EXPECT(outbox_b64_decode("a", 1, out, sizeof out, &outlen) == -1 &&
               outlen == 0, what);
    /* data after padding */
    EXPECT(outbox_b64_decode("AB=C", 4, out, sizeof out, &outlen) == -1,
           what);
    /* too much padding */
    EXPECT(outbox_b64_decode("====", 4, out, sizeof out, &outlen) == -1,
           what);
    /* non-alphabet byte */
    EXPECT(outbox_b64_decode("AB*D", 4, out, sizeof out, &outlen) == -1,
           what);
}

/* ---- passwd load + constant-time check ---- */
static void auth_passwd_test(void) {
    OutboxAuth a;
    char path[512];
    FILE *f;
    const char *dir = "/tmp";
    memset(&a, 0, sizeof a);

    snprintf(path, sizeof path, "%s/outbox_check_%d.passwd", dir, (int)getpid());
    f = fopen(path, "w");
    if (!f) { check_fail("auth passwd write", "fopen"); return; }
    fprintf(f, "# comment\n\nnull:secret\nalice:pw2\n");
    fclose(f);

    EXPECT(outbox_auth_load(path, &a) == 0 && a.ncreds == 2,
           "auth passwd load");
    EXPECT(outbox_auth_check(&a, "null", "secret"), "auth correct user+pass");
    EXPECT(!outbox_auth_check(&a, "null", "wrong"), "auth wrong pass");
    EXPECT(!outbox_auth_check(&a, "bob", "secret"), "auth unknown user");
    EXPECT(!outbox_auth_check(&a, "alice", "secret"), "auth alice wrong pass");
    EXPECT(outbox_auth_check(&a, "alice", "pw2"), "auth alice correct");

    unlink(path);
    {
        size_t i;
        for (i = 0; i < a.ncreds; i++) {
            free(a.creds[i].user);
            free(a.creds[i].pass);
        }
        free(a.creds);
    }
}

/* ---- allowed-domain policy ---- */
static void domain_policy_test(void) {
    OutboxConfig cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.domains = malloc(3 * sizeof *cfg.domains);
    cfg.domains[0] = strdup("jaye.ch");
    cfg.domains[1] = strdup("blackarts.tech");
    cfg.domains[2] = strdup("jurassicpeak.com");
    cfg.ndomains = 3;

    EXPECT(outbox_domain_allowed(&cfg, "jaye.ch"), "allowed jaye.ch");
    EXPECT(outbox_domain_allowed(&cfg, "JAYE.CH"), "allowed case-insensitive");
    EXPECT(outbox_domain_allowed(&cfg, "jurassicpeak.com"), "allowed jurassicpeak.com");
    EXPECT(!outbox_domain_allowed(&cfg, "evil.com"), "reject evil.com");
    EXPECT(!outbox_domain_allowed(&cfg, ""), "reject empty domain");

    free(cfg.domains[0]);
    free(cfg.domains[1]);
    free(cfg.domains[2]);
    free(cfg.domains);
}

/* ---- internal-routing domain set (defaults to served domains) ---- */
static void internal_domain_test(void) {
    OutboxConfig cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.domains = malloc(2 * sizeof *cfg.domains);
    cfg.domains[0] = strdup("jaye.ch");
    cfg.domains[1] = strdup("blackarts.tech");
    cfg.ndomains = 2;

    /* No dedicated internal set -> the served domains are internal. */
    EXPECT(outbox_domain_internal(&cfg, "jaye.ch"),
           "internal: served domain is internal by default");
    EXPECT(outbox_domain_internal(&cfg, "BLACKARTS.TECH"),
           "internal: default set is case-insensitive");
    EXPECT(!outbox_domain_internal(&cfg, "deliver.test"),
           "internal: external domain not internal by default");

    /* A dedicated set overrides the default. */
    cfg.internal_domains = malloc(1 * sizeof *cfg.internal_domains);
    cfg.internal_domains[0] = strdup("jurassicpeak.com");
    cfg.ninternal_domains = 1;
    EXPECT(outbox_domain_internal(&cfg, "jurassicpeak.com"),
           "internal: dedicated set matches");
    EXPECT(!outbox_domain_internal(&cfg, "jaye.ch"),
           "internal: dedicated set excludes a served domain");

    free(cfg.internal_domains[0]);
    free(cfg.internal_domains);
    free(cfg.domains[0]);
    free(cfg.domains[1]);
    free(cfg.domains);
}

/* ---- From-header domain extraction (strict aspf=s envelope alignment) ---- */
static void from_domain_case(const char *hdr, const char *want, const char *what) {
    char body[512];
    char out[256];
    int n = snprintf(body, sizeof body, "%s\r\nSubject: x\r\n\r\nbody\r\n", hdr);
    if (n < 0 || (size_t)n >= sizeof body) {
        check_fail(what, "build");
        return;
    }
    if (outbox_from_header_domain(body, (size_t)n, out, sizeof out) != 0) {
        if (want == NULL) { check_ok(what); return; }
        check_fail(what, "extract failed");
        return;
    }
    if (want && strcmp(out, want) == 0) check_ok(what);
    else if (!want) check_fail(what, "expected failure");
    else check_fail(what, out);
}

static void from_domain_test(void) {
    from_domain_case("From: Me <me@jaye.ch>", "jaye.ch", "From display-name");
    from_domain_case("From: me@jaye.ch", "jaye.ch", "From bare addr");
    from_domain_case("From: \"Doe, John\" <john@JAYE.ch>", "jaye.ch",
                     "From quoted display-name + case");
    from_domain_case("From: <me@blackarts.tech>", "blackarts.tech",
                     "From angle-only");
    from_domain_case("From: me@evil.com", "evil.com", "From evil.com (mismatch test)");
    from_domain_case("Subject: no from here", NULL, "From absent");
    from_domain_case("From: malformed-no-at", NULL, "From malformed");
}

int main(void) {
    b64_roundtrip("b64 decode roundtrip (AUTH PLAIN vector)");
    b64_reject("b64 decode rejects malformed");
    auth_passwd_test();
    domain_policy_test();
    internal_domain_test();
    from_domain_test();

    printf("%d checks, %d failures\n", nchecks, nfails);
    return nfails == 0 ? 0 : 1;
}
