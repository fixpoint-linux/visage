/* reply_check.c — standalone checks for the reverse-alias reply routing layer
 * (slice S6).  Exercises token generation, reverse-alias construction, inbound
 * reply routing through a fresh tmp store, the forward From-rewrite strings,
 * and To/Cc reverse-alias stripping.  Prints a PASS/FAIL line per check and
 * returns 0 iff every check passes. */
#include "visage.h"
#include "reply.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures;

static void check(int cond, const char *what) {
    if (cond) {
        printf("PASS: %s\n", what);
    } else {
        printf("FAIL: %s\n", what);
        failures++;
    }
}

/* 32 lowercase hex digits. */
static int is_hex32(const char *s) {
    size_t i;
    if (!s || strlen(s) != 32) return 0;
    for (i = 0; i < 32; i++) {
        char c = s[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return 0;
    }
    return 1;
}

int main(void) {
    char tpl[] = "/tmp/visage_reply_XXXXXX";
    char *dir = mkdtemp(tpl);
    Store *s;
    Config cfg;
    char tok1[64], tok2[64];
    char rev[256], want[256];
    char rcpt[256];
    char *sender, *alias_addr;
    char *from;

    if (!dir) {
        fprintf(stderr, "reply_check: mkdtemp failed\n");
        return 1;
    }
    printf("reply_check: db dir = %s\n", dir);

    memset(&cfg, 0, sizeof cfg);
    cfg.reply.prefix = "reply";
    cfg.reply.separator = "+";

    /* --- token generation --- */
    check(reply_token_gen(tok1, sizeof tok1) == VISAGE_OK, "token_gen returns OK");
    check(is_hex32(tok1), "token_gen produces 32 hex chars");
    check(reply_token_gen(tok2, sizeof tok2) == VISAGE_OK, "token_gen second call OK");
    check(strcmp(tok1, tok2) != 0, "token_gen two calls differ");
    check(strcmp(tok1, "00000000000000000000000000000000") != 0,
          "token_gen never all-zero");
    check(reply_token_gen(tok1, 32) != VISAGE_OK, "token_gen rejects too-small buffer");

    /* --- reverse-alias construction --- */
    check(reply_make_reverse(&cfg, tok1, "jane@example.com", rev, sizeof rev) == VISAGE_OK,
          "make_reverse returns OK");
    snprintf(want, sizeof want, "reply+%s@example.com", tok1);
    check(strcmp(rev, want) == 0, "make_reverse builds reply+<tok>@domain");

    /* --- inbound reply routing --- */
    s = store_open(dir);
    check(s != NULL, "store_open creates schema");
    if (!s) return 1;

    check(store_revmap_add(s, tok1, "orig@foo.org", "jane@example.com") == VISAGE_OK,
          "revmap_add for route test");

    sender = NULL;
    alias_addr = NULL;
    snprintf(rcpt, sizeof rcpt, "reply+%s@example.com", tok1);
    check(reply_route_inbound(s, &cfg, rcpt, &sender, &alias_addr) == 1,
          "route_inbound matching rcpt returns 1");
    check(sender != NULL && strcmp(sender, "orig@foo.org") == 0,
          "route_inbound returns stored sender");
    check(alias_addr != NULL && strcmp(alias_addr, "jane@example.com") == 0,
          "route_inbound returns stored alias_addr");
    free(sender);
    free(alias_addr);

    /* non-reply recipient falls through (rc == 0, outputs NULL). */
    sender = NULL;
    alias_addr = NULL;
    check(reply_route_inbound(s, &cfg, "jane@example.com", &sender, &alias_addr) == 0,
          "route_inbound non-reply rcpt returns 0");
    check(sender == NULL && alias_addr == NULL,
          "route_inbound non-reply leaves outputs NULL");
    free(sender);
    free(alias_addr);

    /* unknown token falls through. */
    sender = NULL;
    alias_addr = NULL;
    check(reply_route_inbound(s, &cfg,
          "reply+ffffffffffffffffffffffffffffffff@example.com",
          &sender, &alias_addr) == 0,
          "route_inbound unknown token returns 0");
    check(sender == NULL && alias_addr == NULL,
          "route_inbound unknown token leaves outputs NULL");
    free(sender);
    free(alias_addr);

    /* --- forward From rewrite --- */
    from = NULL;
    check(reply_from_rewrite(&from, "orig@foo.org",
                             "reply+deadbeef@example.com") == VISAGE_OK,
          "from_rewrite returns OK");
    check(from != NULL && strcmp(from,
          "\"orig@foo.org\" <reply+deadbeef@example.com>") == 0,
          "from_rewrite builds <sender> display form");
    reply_free(from);

    /* --- full MailRewrite build --- */
    {
        MailRewrite rw;
        check(reply_rewrite_build("orig@foo.org", "jane@example.com",
                                  "reply+deadbeef@example.com", &rw) == VISAGE_OK,
              "rewrite_build returns OK");
        check(rw.from != NULL && strcmp(rw.from,
              "\"orig@foo.org\" <reply+deadbeef@example.com>") == 0,
              "rewrite_build from value");
        check(rw.reply_to != NULL && strcmp(rw.reply_to, "reply+deadbeef@example.com") == 0,
              "rewrite_build reply_to = reverse");
        check(rw.return_path != NULL && strcmp(rw.return_path, "jane@example.com") == 0,
              "rewrite_build return_path = alias");
        check(rw.sender != NULL && strcmp(rw.sender, "jane@example.com") == 0,
              "rewrite_build sender = alias");
        reply_rewrite_free(&rw);
    }

    /* --- strip reverse alias from To/Cc --- */
    {
        char *m = strdup(
            "To: reply+deadbeef@example.com\r\n"
            "Cc: \"Bob\" <reply+deadbeef@example.com>, carol@example.com\r\n"
            "Subject: hi\r\n"
            "\r\n"
            "body\r\n");
        size_t mlen = strlen(m);
        char tmp[256];

        check(reply_strip_reverse(&m, &mlen, "reply+deadbeef@example.com") == VISAGE_OK,
              "strip_reverse returns OK");
        check(mail_header_get(m, mlen, "to", tmp, sizeof tmp) == -1,
              "strip_reverse removes now-empty To header");
        check(mail_header_get(m, mlen, "cc", tmp, sizeof tmp) == 0 &&
              strcmp(tmp, "carol@example.com") == 0,
              "strip_reverse strips reverse from Cc");
        reply_free(m);
    }

    /* --- strip reverse alias from To/Cc (RFC 5322 groups, R8) --- */
    {
        char *m; size_t mlen; char tmp[512];

        /* (a) group with the reverse alias + a surviving member */
        m = strdup("To: Friends: \"Bob\" <reply+deadbeef@example.com>, carol@example.com;\r\n\r\n");
        mlen = strlen(m);
        check(reply_strip_reverse(&m, &mlen, "reply+deadbeef@example.com") == VISAGE_OK,
              "group: strip returns OK");
        check(mail_header_get(m, mlen, "to", tmp, sizeof tmp) == 0 &&
              strcmp(tmp, "Friends: carol@example.com;") == 0,
              "group: strips reverse, keeps group + survivor");
        reply_free(m);

        /* (b) group whose only member is the reverse alias -> whole group removed */
        m = strdup("To: Friends: reply+deadbeef@example.com;\r\n"
                   "Cc: keep@example.com\r\n\r\n");
        mlen = strlen(m);
        check(reply_strip_reverse(&m, &mlen, "reply+deadbeef@example.com") == VISAGE_OK,
              "group-only: strip returns OK");
        check(mail_header_get(m, mlen, "to", tmp, sizeof tmp) == -1,
              "group-only: now-empty group removed");
        check(mail_header_get(m, mlen, "cc", tmp, sizeof tmp) == 0 &&
              strcmp(tmp, "keep@example.com") == 0,
              "group-only: Cc untouched");
        reply_free(m);

        /* (c) group without the reverse alias -> unchanged */
        m = strdup("To: Friends: bob@example.com, carol@example.com;\r\n\r\n");
        mlen = strlen(m);
        check(reply_strip_reverse(&m, &mlen, "reply+deadbeef@example.com") == VISAGE_OK,
              "group-unchanged: strip returns OK");
        check(mail_header_get(m, mlen, "to", tmp, sizeof tmp) == 0 &&
              strcmp(tmp, "Friends: bob@example.com, carol@example.com;") == 0,
              "group-unchanged: header unchanged");
        reply_free(m);

        /* (d) two groups + a bare mailbox */
        m = strdup("To: G1: reply+deadbeef@example.com;, "
                   "G2: a@example.com, reply+deadbeef@example.com;, "
                   "keep@example.com\r\n\r\n");
        mlen = strlen(m);
        check(reply_strip_reverse(&m, &mlen, "reply+deadbeef@example.com") == VISAGE_OK,
              "two-groups: strip returns OK");
        check(mail_header_get(m, mlen, "to", tmp, sizeof tmp) == 0 &&
              strcmp(tmp, "G2: a@example.com;, keep@example.com") == 0,
              "two-groups: empty group dropped, others stripped");
        reply_free(m);

        /* (e) nested group (inner group fully stripped) */
        m = strdup("To: Outer: inner: reply+deadbeef@example.com;, carol@example.com;\r\n\r\n");
        mlen = strlen(m);
        check(reply_strip_reverse(&m, &mlen, "reply+deadbeef@example.com") == VISAGE_OK,
              "nested: strip returns OK");
        check(mail_header_get(m, mlen, "to", tmp, sizeof tmp) == 0 &&
              strcmp(tmp, "Outer: carol@example.com;") == 0,
              "nested: inner group removed, outer preserved");
        reply_free(m);

        /* (f) nested group where the inner group survives (wrapping preserved) */
        m = strdup("To: Outer: inner: keep@example.com;, reply+deadbeef@example.com;\r\n\r\n");
        mlen = strlen(m);
        check(reply_strip_reverse(&m, &mlen, "reply+deadbeef@example.com") == VISAGE_OK,
              "nested-survive: strip returns OK");
        check(mail_header_get(m, mlen, "to", tmp, sizeof tmp) == 0 &&
              strcmp(tmp, "Outer: inner: keep@example.com;;") == 0,
              "nested-survive: inner group wrapping preserved");
        reply_free(m);

        /* (g) unclosed group -> kept verbatim (conservative, no crash) */
        m = strdup("To: Friends: reply+deadbeef@example.com\r\n\r\n");
        mlen = strlen(m);
        check(reply_strip_reverse(&m, &mlen, "reply+deadbeef@example.com") == VISAGE_OK,
              "unclosed-group: strip returns OK");
        check(mail_header_get(m, mlen, "to", tmp, sizeof tmp) == 0 &&
              strcmp(tmp, "Friends: reply+deadbeef@example.com") == 0,
              "unclosed-group: kept verbatim (reverse not stripped)");
        reply_free(m);
    }

    check(store_close(s) == VISAGE_OK, "store_close returns OK");

    if (failures) {
        printf("reply_check: %d FAILURE(S)\n", failures);
        return 1;
    }
    printf("reply_check: ALL PASS\n");
    return 0;
}
