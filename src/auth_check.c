/* auth_check.c — standalone checks for src/auth_results.c (SPF/DKIM/DMARC
 * evaluation) plus the dkim_verify_key DNS-key path.  No live sockets/DNS:
 * tests the pure logic (envelope domain extraction, SPF mechanism evaluation,
 * DKIM verify against a PEM public key).  Returns 0 only if all pass.
 */
#include "visage.h"
#include "auth_results.h"
#include "dkim.h"
#include "mail.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
    if (detail) printf("FAIL %s — %s\n", what, detail);
    else        printf("FAIL %s\n", what);
}
#define EXPECT(cond, what) \
    do { if (cond) check_ok(what); else check_fail(what, NULL); } while (0)

static const unsigned char IP4_A[] = { 192, 0, 2, 1 };   /* 192.0.2.1 */
static const unsigned char IP4_B[] = { 198, 51, 100, 7 }; /* 198.51.100.7 */

static void env_domain_test(void) {
    char *d;
    d = auth_env_from_domain("bob@example.com");
    EXPECT(d && strcmp(d, "example.com") == 0, "env domain basic");
    free(d);

    d = auth_env_from_domain("<sue@x.org>");
    EXPECT(d && strcmp(d, "x.org") == 0, "env domain angled");
    free(d);

    d = auth_env_from_domain("<>");
    EXPECT(d && strcmp(d, "") == 0, "null sender -> empty");
    free(d);

    d = auth_env_from_domain("alice@sub.example.com");
    EXPECT(d && strcmp(d, "sub.example.com") == 0, "env domain subdomain");
    free(d);
}

static void spf_test(void) {
    /* ip4 exact + -all */
    EXPECT(auth_spf_eval_record("ip4:192.0.2.1 -all", NULL, IP4_A, 4) == AUTH_SPF_PASS,
           "spf ip4 match pass");
    EXPECT(auth_spf_eval_record("ip4:192.0.2.1 -all", NULL, IP4_B, 4) == AUTH_SPF_FAIL,
           "spf ip4 non-match fail (-all)");
    /* ip4 cidr */
    EXPECT(auth_spf_eval_record("ip4:192.0.2.0/24 ~all", NULL, IP4_A, 4) == AUTH_SPF_PASS,
           "spf ip4 cidr pass");
    EXPECT(auth_spf_eval_record("ip4:198.51.100.0/24 ~all", NULL, IP4_A, 4) == AUTH_SPF_SOFTFAIL,
           "spf ip4 cidr miss softfail (~all)");
    /* explicit +qualifier */
    EXPECT(auth_spf_eval_record("+ip4:192.0.2.1 ?all", NULL, IP4_A, 4) == AUTH_SPF_PASS,
           "spf explicit + qualifier");
    /* all-only with - qualifier */
    EXPECT(auth_spf_eval_record("-all", NULL, IP4_A, 4) == AUTH_SPF_FAIL,
           "spf -all only fail");
    EXPECT(auth_spf_eval_record("~all", NULL, IP4_A, 4) == AUTH_SPF_SOFTFAIL,
           "spf ~all only softfail");
    /* no record match and no all */
    EXPECT(auth_spf_eval_record("ip4:198.51.100.7", NULL, IP4_A, 4) == AUTH_SPF_NEUTRAL,
           "spf no match no all -> neutral");
    /* first-match-wins: ip4 before all */
    EXPECT(auth_spf_eval_record("ip4:198.51.100.7 ip4:192.0.2.1 -all", NULL, IP4_A, 4) == AUTH_SPF_PASS,
           "spf first match wins");
}

static void txt_rdata_test(void) {
    char *s = NULL;
    size_t sl = 0;

    /* Two valid character-strings. */
    static const unsigned char ok[] = { 0x05, 'h', 'e', 'l', 'l', 'o',
                                        0x01, 'x' };
    EXPECT(auth_txt_parse_rdata(ok, sizeof ok, &s, &sl) == 0 &&
           s && sl == 6 && memcmp(s, "hellox", 6) == 0,
           "txt rdata two valid segments");
    free(s); s = NULL;

    /* Truncated FINAL character-string: a valid first segment ("hello")
       followed by a length byte claiming 3 bytes with only 1 present.  The
       copy loop must stop at the validated length (regression: it used to
       memcpy past the malloc'd buffer). */
    static const unsigned char trunc[] = { 0x05, 'h', 'e', 'l', 'l', 'o',
                                           0x03, 'x' };
    EXPECT(auth_txt_parse_rdata(trunc, sizeof trunc, &s, &sl) == 0 &&
           s && sl == 5 && memcmp(s, "hello", 5) == 0,
           "txt rdata truncated final segment stops at validated length");
    free(s); s = NULL;

    /* Wholly truncated first segment (length byte claims 200, 0 data bytes). */
    static const unsigned char first[] = { 0xC8 };
    EXPECT(auth_txt_parse_rdata(first, sizeof first, &s, &sl) == 0 &&
           s && sl == 0 && s[0] == '\0',
           "txt rdata truncated first segment -> empty string");
    free(s);
}

static void dmarc_align_test(void) {
    EXPECT(auth_dmarc_domain_align("example.com", "example.com"),
           "align exact match");
    EXPECT(auth_dmarc_domain_align("sub.example.com", "example.com"),
           "align relaxed subdomain");
    EXPECT(!auth_dmarc_domain_align("example.com", "sub.example.com"),
           "align no: auth is parent of from");
    EXPECT(!auth_dmarc_domain_align("other.com", "example.com"),
           "align no: different domain");
    EXPECT(!auth_dmarc_domain_align("notexample.com", "example.com"),
           "align no: suffix but not subdomain");
    EXPECT(!auth_dmarc_domain_align(NULL, "example.com"),
           "align no: null auth domain");
}

static void header_from_test(void) {
    char *d;
    const char *msg1 = "From: alice@example.com\r\nSubject: t\r\n\r\nbody\r\n";
    d = auth_header_from_domain(msg1, strlen(msg1));
    EXPECT(d && strcmp(d, "example.com") == 0, "from domain bare addr");
    free(d);

    const char *msg2 = "From: \"Alice Smith\" <alice@sub.example.com>\r\n\r\n";
    d = auth_header_from_domain(msg2, strlen(msg2));
    EXPECT(d && strcmp(d, "sub.example.com") == 0, "from domain display name");
    free(d);

    const char *msg3 = "Subject: no from\r\n\r\nbody\r\n";
    d = auth_header_from_domain(msg3, strlen(msg3));
    EXPECT(d == NULL, "from domain absent");
    free(d);
}

static void header_format_test(void) {
    char *h;
    /* full pass: header.d must carry the DKIM signature domain (regression:
       it was dropped, emitting a malformed "header.d=" with no value that
       FairEmail et al. render as unknown) */
    h = auth_results_format("mx.visage.test", AUTH_SPF_PASS, AUTH_DKIM_PASS,
                            AUTH_DMARC_PASS, "example.com", "example.com",
                            "example.com");
    EXPECT(h && strstr(h, "spf=pass smtp.mailfrom=example.com"),
           "hdr spf pass line");
    EXPECT(h && strstr(h, "dkim=pass header.d=example.com"),
           "hdr dkim carries header.d domain");
    EXPECT(h && strstr(h, "dmarc=pass header.from=example.com"),
           "hdr dmarc line");
    EXPECT(h && strstr(h, "Authentication-Results: mx.visage.test;"),
           "hdr hostname");
    free(h);

    /* header.from must reflect the From: domain, NOT the envelope domain */
    h = auth_results_format("h", AUTH_SPF_PASS, AUTH_DKIM_NONE,
                            AUTH_DMARC_NONE, "env.example", "from.example",
                            NULL);
    EXPECT(h && strstr(h, "smtp.mailfrom=env.example"),
           "hdr smtp.mailfrom is envelope domain");
    EXPECT(h && strstr(h, "header.from=from.example"),
           "hdr header.from is From domain");
    free(h);

    /* dkim none (no signature): no header.d= fragment at all */
    h = auth_results_format("h", AUTH_SPF_PASS, AUTH_DKIM_NONE,
                            AUTH_DMARC_NONE, "x.org", "x.org", NULL);
    EXPECT(h && strstr(h, "dkim=none;") && !strstr(h, "header.d"),
           "hdr dkim none omits header.d");
    free(h);
}

static void dkim_key_verify_test(void) {
    const char *msg = "From: a@b\r\nSubject: t\r\n\r\nhello\r\n";
    const char *keyfile = "tests/dkim-test-key.pem";
    char *signed_msg = NULL;
    size_t signed_len = 0;

    if (dkim_sign(msg, strlen(msg), "example.com", "sel1", keyfile,
                  &signed_msg, &signed_len) != 0) {
        check_fail("dkim key verify", "dkim_sign failed");
        return;
    }
    EXPECT(signed_len > 20 &&
               strncasecmp(signed_msg, "DKIM-Signature:", 15) == 0,
           "dkim signed message has header");

    /* round-trip via file path */
    EXPECT(dkim_verify(signed_msg, signed_len, keyfile) == 0,
           "dkim_verify (file) round-trip");

    /* dkim_verify_key with a malformed PEM must fail gracefully */
    EXPECT(dkim_verify_key(signed_msg, signed_len, "not a pem") != 0,
           "dkim_verify_key rejects malformed pem");

    /* Derive the public key and verify with dkim_verify_key */
    {
        char pub[64] = "/tmp/auth_check_pub_XXXXXX";
        int pfd = mkstemp(pub);
        if (pfd >= 0) {
            char cmd[256];
            close(pfd);
            snprintf(cmd, sizeof cmd,
                     "openssl pkey -in %s -pubout -out %s 2>/dev/null",
                     keyfile, pub);
            if (system(cmd) == 0) {
                FILE *pf = fopen(pub, "r");
                if (pf) {
                    /* read whole public PEM into a heap buffer */
                    fseek(pf, 0, SEEK_END);
                    long sz = ftell(pf);
                    fseek(pf, 0, SEEK_SET);
                    if (sz > 0 && sz < 8192) {
                        char *pem = malloc((size_t)sz + 1);
                        if (pem) {
                            size_t got = fread(pem, 1, (size_t)sz, pf);
                            pem[got] = '\0';
                            if (strstr(pem, "BEGIN PUBLIC KEY"))
                                EXPECT(dkim_verify_key(signed_msg, signed_len,
                                                       pem) == 0,
                                       "dkim_verify_key with public pem");
                            else
                                check_fail("dkim key verify",
                                           "no public key in derived pem");
                            free(pem);
                        }
                    }
                    fclose(pf);
                }
                remove(pub);
            }
        }
    }

    free(signed_msg);
}

int main(void) {
    env_domain_test();
    spf_test();
    txt_rdata_test();
    dmarc_align_test();
    header_from_test();
    header_format_test();
    dkim_key_verify_test();

    printf("\n%d checks, %d failed\n", nchecks, nfails);
    return nfails ? 1 : 0;
}
