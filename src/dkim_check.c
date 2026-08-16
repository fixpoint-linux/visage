/* dkim_check.c — DKIM golden-value selfcheck (R9).
 *
 * Asserts RFC 6376 relaxed canonicalization against INDEPENDENT golden values
 * (a transcription bug cannot pass self-consistently): the relaxed header
 * forms, the relaxed body-hash (bh), the empty-body hash, and a full
 * sign->verify round-trip against tests/dkim-test-key.pem with a well-formed
 * DKIM-Signature (v=1, a=rsa-sha256, d=, s=, bh=, h=, b=).  Returns 0 on
 * success, nonzero on any failure. */
#include "visage.h"
#include "dkim.h"
#include <stdio.h>
#include <string.h>

static int failures = 0;

static void check(int cond, const char *msg) {
    if (cond) {
        printf("PASS  %s\n", msg);
    } else {
        printf("FAIL  %s\n", msg);
        failures++;
    }
}

int main(void) {
    /* relaxed header golden forms (no trailing CRLF) */
    {
        const char *h = "Subject: Hello  World \r\n";
        char *out = NULL; size_t outlen = 0;
        if (dkim_relaxed_header(h, strlen(h), 7, &out, &outlen) != 0) {
            printf("FAIL  relaxed_header Subject returned error\n"); failures++;
        } else {
            check(outlen == strlen("subject:Hello World") &&
                  strcmp(out, "subject:Hello World") == 0,
                  "relaxed header 'Subject: Hello  World \\r\\n' -> 'subject:Hello World'");
            free(out);
        }
    }
    {
        const char *h = "To:   bob@example.com\t";
        char *out = NULL; size_t outlen = 0;
        if (dkim_relaxed_header(h, strlen(h), 2, &out, &outlen) != 0) {
            printf("FAIL  relaxed_header To returned error\n"); failures++;
        } else {
            check(outlen == strlen("to:bob@example.com") &&
                  strcmp(out, "to:bob@example.com") == 0,
                  "relaxed header 'To:   bob@example.com\\t' -> 'to:bob@example.com'");
            free(out);
        }
    }

    /* relaxed body hash golden */
    {
        char bh[64];
        const char *body =
            "Hi.\r\n"
            "\r\n"
            "We lost the game.   Are you hungry yet?  \r\n"
            "\r\n"
            "Joe.\r\n";
        if (dkim_relaxed_body_b64(body, strlen(body), bh) != 0) {
            printf("FAIL  relaxed_body_b64 returned error\n"); failures++;
        } else {
            check(strcmp(bh, "2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=") == 0,
                  "relaxed body bh golden = 2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=");
        }
    }
    /* empty-body hash golden (RFC 6376: empty body -> single CRLF) */
    {
        char bh[64];
        if (dkim_relaxed_body_b64("", 0, bh) != 0) {
            printf("FAIL  empty-body b64 returned error\n"); failures++;
        } else {
            check(strcmp(bh, "frcCV1k9oG9oKj3dpUqdJg1PxRT2RSN/XKdLCPjaYaY=") == 0,
                  "empty-body bh golden = frcCV1k9oG9oKj3dpUqdJg1PxRT2RSN/XKdLCPjaYaY=");
        }
    }

    /* full sign->verify round-trip + header well-formedness */
    {
        const char msg[] =
            "Subject: Hello  World \r\n"
            "To:   bob@example.com\t\r\n"
            "Date: Fri, 11 Jul 2003 21:00:37 -0700\r\n"
            "Message-ID: <abc123@example.com>\r\n"
            "From: jane@example.com\r\n"
            "\r\n"
            "Hi.\r\n";
        char *signed_msg = NULL; size_t signed_len = 0;
        int r = dkim_sign(msg, sizeof msg - 1, "example.com", "sel1",
                          "tests/dkim-test-key.pem", &signed_msg, &signed_len);
        if (r != 0) {
            printf("FAIL  dkim_sign round-trip failed (%d)\n", r); failures++;
        } else {
            check(strncmp(signed_msg, "DKIM-Signature: ", 16) == 0,
                  "signed output begins with 'DKIM-Signature: '");
            {
                const int well =
                    strstr(signed_msg, "v=1") != NULL &&
                    strstr(signed_msg, "a=rsa-sha256") != NULL &&
                    strstr(signed_msg, "d=example.com") != NULL &&
                    strstr(signed_msg, "s=sel1") != NULL &&
                    strstr(signed_msg, "bh=") != NULL &&
                    strstr(signed_msg, "h=") != NULL &&
                    strstr(signed_msg, "b=") != NULL;
                check(well, "DKIM-Signature well-formed (v=1,a=rsa-sha256,d=,s=,bh=,h=,b=)");
            }
            if (dkim_verify(signed_msg, signed_len, "tests/dkim-test-key.pem") == 0) {
                printf("PASS  sign->verify round-trip (tests/dkim-test-key.pem)\n");
            } else {
                printf("FAIL  sign->verify round-trip\n"); failures++;
            }
            free(signed_msg);
        }
    }

    if (failures) {
        printf("dkim_check: %d failure(s)\n", failures);
        return 1;
    }
    printf("dkim_check: all checks passed\n");
    return 0;
}
