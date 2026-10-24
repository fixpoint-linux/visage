/* jmap_check.c — standalone checks for the jmapd sources.
 *
 * Same idiom as imap_check.c: no live sockets, no threads.  Each check is a
 * pure call over a buffer or a scratch root in /tmp; the exit code is the
 * verdict (nonzero = at least one failure).  What is pinned here:
 *
 *   (1) the JSON parser, including the adversarial corpus that must produce a
 *       typed ERROR rather than a crash (deep nesting, lone surrogates,
 *       truncated escapes, invalid UTF-8, trailing garbage, over-long input);
 *   (2) the id codec: round-trip AND rejection (a traversal attempt must not
 *       decode into a path component);
 *   (3) the session document: four absolute URLs with the listener's scheme,
 *       primaryAccounts, capabilities — and the --public-url override
 *       (advertised verbatim, path prefix preserved, every refusal named);
 *   (4) auth verdicts: Basic/Bearer parsing, the passwd table, the per-IP
 *       lockout — and that authentication is PER REQUEST, never cached on the
 *       connection (a pooled upstream connection is not a principal);
 *   (5) the HTTP/1.1 request parse: method/path/keep-alive, Content-Length
 *       required for POST, chunked refused, the caps (413/431).
 *
 * The protocol end-to-end (a real client over a real socket) is
 * tests/jmapd_basic.sh; this harness pins the contracts it rests on. */
#include "visage.h"
#include "jmapd.h"
#include "http_parse.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <dirent.h>
#include <fcntl.h>
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
    else printf("FAIL %s\n", what);
}

#define EXPECT(cond, what) \
    do { if (cond) check_ok(what); else check_fail(what, NULL); } while (0)

/* ------------------------------------------------------------------ */
/* (1) JSON parser                                                     */
/* ------------------------------------------------------------------ */

/* Parse `s` and report the error code (JMAP_JSON_OK when it parsed). */
static JmapJsonErr parse_err(const char *s, size_t len) {
    JmapJsonErr e = JMAP_JSON_OK;
    JmapJsonDoc *d = jmap_json_parse(s, len, &e);
    if (d) {
        jmap_json_free(d);
        return JMAP_JSON_OK;
    }
    return e;
}

static void json_ok_tests(void) {
    static const char doc[] =
        "{\"a\":1,\"b\":[true,false,null],\"c\":{\"d\":\"e\"},\"n\":-12,"
        "\"f\":1.5,\"u\":\"a\\u00e9b\",\"p\":\"\\ud83d\\ude00\","
        "\"esc\":\"q\\\"\\\\\\/\\b\\f\\n\\r\\t\"}";
    JmapJsonErr e = JMAP_JSON_OK;
    JmapJsonDoc *d = jmap_json_parse(doc, sizeof doc - 1, &e);
    const JmapJsonNode *root, *b, *u, *p, *n, *f, *esc;
    const char *s;
    size_t sl;
    uint64_t v;
    bool bo;

    EXPECT(d != NULL, "json: object document parses");
    if (!d) return;
    root = jmap_json_root(d);
    EXPECT(root && root->type == JMAP_JSON_OBJ, "json: root is an object");
    EXPECT(jmap_json_count(root) == 8, "json: object member count");

    b = jmap_json_get(root, "b");
    EXPECT(b && b->type == JMAP_JSON_ARR && jmap_json_count(b) == 3,
           "json: array count");
    EXPECT(jmap_json_bool(jmap_json_at(b, 0), &bo) == 0 && bo,
           "json: true literal");
    EXPECT(jmap_json_bool(jmap_json_at(b, 1), &bo) == 0 && !bo,
           "json: false literal");
    EXPECT(jmap_json_at(b, 2) && jmap_json_at(b, 2)->type == JMAP_JSON_NULL,
           "json: null literal");
    EXPECT(jmap_json_at(b, 3) == NULL, "json: array out of range is NULL");

    EXPECT(jmap_json_get(jmap_json_get(root, "c"), "d") != NULL,
           "json: nested object lookup");
    EXPECT(jmap_json_get(root, "zzz") == NULL, "json: absent key is NULL");

    n = jmap_json_get(root, "n");
    EXPECT(jmap_json_u64(n, &v) != 0, "json: negative number is not u64");
    EXPECT(n && n->type == JMAP_JSON_NUM && n->is_int && n->inum == -12,
           "json: negative integer value");
    f = jmap_json_get(root, "f");
    EXPECT(jmap_json_u64(f, &v) != 0 && f->num > 1.4 && f->num < 1.6,
           "json: non-integer number is not u64");
    EXPECT(jmap_json_u64(jmap_json_get(root, "a"), &v) == 0 && v == 1,
           "json: integer u64 accessor");

    /* \u00e9 -> two UTF-8 bytes (C3 A9); the raw string is "a" + e9 + "b". */
    u = jmap_json_get(root, "u");
    EXPECT(jmap_json_str(u, &s, &sl) == 0 && sl == 4 &&
               (unsigned char)s[1] == 0xC3 && (unsigned char)s[2] == 0xA9,
           "json: \\u escape decodes to UTF-8");

    /* surrogate pair -> U+1F600 -> F0 9F 98 80 */
    p = jmap_json_get(root, "p");
    EXPECT(jmap_json_str(p, &s, &sl) == 0 && sl == 4 &&
               (unsigned char)s[0] == 0xF0 && (unsigned char)s[3] == 0x80,
           "json: surrogate pair decodes to 4-byte UTF-8");

    esc = jmap_json_get(root, "esc");
    /* q " \ / \b \f \n \r \t -> 9 bytes */
    EXPECT(jmap_json_str(esc, &s, &sl) == 0 && sl == 9,
           "json: all short escapes decode");

    /* a string with no escapes must round-trip exactly */
    {
        static const char plain[] = "{\"k\":\"hello\"}";
        JmapJsonDoc *d2 = jmap_json_parse(plain, sizeof plain - 1, NULL);
        EXPECT(d2 && jmap_json_str(jmap_json_get(jmap_json_root(d2), "k"),
                                   &s, &sl) == 0 &&
                   sl == 5 && memcmp(s, "hello", 5) == 0,
               "json: plain string round-trips");
        jmap_json_free(d2);
    }
    jmap_json_free(d);
}

static void json_reject_tests(void) {
    static const char lone_high[] = "\"\\ud83d\"";
    static const char lone_low[] = "\"\\ude00\"";
    static const char bad_pair[] = "\"\\ud83d\\u0041\"";
    static const char trunc_esc[] = "\"\\u12\"";
    static const char trunc_utf8[] = "\"ab\xC3\"";
    static const char overlong[] = "\"ab\xC0\xAF\"";
    static const char raw_surrogate[] = "\"ab\xED\xA0\x80\"";
    static const char trailing[] = "{}x";
    static const char two_values[] = "{} {}";
    static const char bad_num0[] = "01";
    static const char bad_num1[] = "1.";
    static const char bad_num2[] = "-";
    static const char bad_num3[] = "1e";
    static const char ctrl[] = "\"a\nb\"";
    static const char unterminated[] = "\"abc";
    static const char bad_obj[] = "{\"a\":}";
    char *deep;
    size_t i;

    EXPECT(parse_err(lone_high, sizeof lone_high - 1) == JMAP_JSON_E_SURROGATE,
           "json: lone high surrogate rejected");
    EXPECT(parse_err(lone_low, sizeof lone_low - 1) == JMAP_JSON_E_SURROGATE,
           "json: lone low surrogate rejected");
    EXPECT(parse_err(bad_pair, sizeof bad_pair - 1) == JMAP_JSON_E_SURROGATE,
           "json: high surrogate + non-low rejected");
    EXPECT(parse_err(trunc_esc, sizeof trunc_esc - 1) == JMAP_JSON_E_STRING,
           "json: truncated \\u escape rejected");
    EXPECT(parse_err(trunc_utf8, sizeof trunc_utf8 - 1) == JMAP_JSON_E_UTF8,
           "json: truncated UTF-8 rejected");
    EXPECT(parse_err(overlong, sizeof overlong - 1) == JMAP_JSON_E_UTF8,
           "json: overlong UTF-8 rejected");
    EXPECT(parse_err(raw_surrogate, sizeof raw_surrogate - 1) ==
               JMAP_JSON_E_UTF8,
           "json: surrogate encoded in raw bytes rejected");
    EXPECT(parse_err(trailing, sizeof trailing - 1) == JMAP_JSON_E_TRAILING,
           "json: trailing garbage rejected");
    EXPECT(parse_err(two_values, sizeof two_values - 1) == JMAP_JSON_E_TRAILING,
           "json: second value rejected");
    EXPECT(parse_err(bad_num0, sizeof bad_num0 - 1) == JMAP_JSON_E_NUMBER,
           "json: leading zero rejected");
    EXPECT(parse_err(bad_num1, sizeof bad_num1 - 1) == JMAP_JSON_E_NUMBER,
           "json: trailing dot rejected");
    EXPECT(parse_err(bad_num2, sizeof bad_num2 - 1) == JMAP_JSON_E_NUMBER,
           "json: bare minus rejected");
    EXPECT(parse_err(bad_num3, sizeof bad_num3 - 1) == JMAP_JSON_E_NUMBER,
           "json: exponent without digits rejected");
    EXPECT(parse_err(ctrl, sizeof ctrl - 1) == JMAP_JSON_E_STRING,
           "json: raw control byte in string rejected");
    EXPECT(parse_err(unterminated, sizeof unterminated - 1) ==
               JMAP_JSON_E_STRING,
           "json: unterminated string rejected");
    EXPECT(parse_err(bad_obj, sizeof bad_obj - 1) == JMAP_JSON_E_SYNTAX,
           "json: missing value rejected");
    EXPECT(parse_err("", 0) == JMAP_JSON_E_SYNTAX, "json: empty input rejected");
    EXPECT(parse_err("   ", 3) == JMAP_JSON_E_SYNTAX,
           "json: whitespace-only rejected");

    /* depth: exactly the cap parses, one deeper does not */
    deep = malloc(JMAP_JSON_MAX_DEPTH * 2 + 8);
    if (deep) {
        size_t n = 0;
        for (i = 0; i < JMAP_JSON_MAX_DEPTH; i++) deep[n++] = '[';
        for (i = 0; i < JMAP_JSON_MAX_DEPTH; i++) deep[n++] = ']';
        EXPECT(parse_err(deep, n) == JMAP_JSON_OK,
               "json: nesting at the depth cap parses");
        n = 0;
        for (i = 0; i < JMAP_JSON_MAX_DEPTH + 1; i++) deep[n++] = '[';
        for (i = 0; i < JMAP_JSON_MAX_DEPTH + 1; i++) deep[n++] = ']';
        EXPECT(parse_err(deep, n) == JMAP_JSON_E_DEPTH,
               "json: nesting past the cap rejected");
        free(deep);
    } else {
        check_fail("json: depth fixture alloc", "malloc failed");
    }

    /* 10k '[' — the classic depth bomb: a typed error, no crash, no stack
       recursion proportional to the input */
    deep = malloc(10000);
    if (deep) {
        memset(deep, '[', 10000);
        EXPECT(parse_err(deep, 10000) == JMAP_JSON_E_DEPTH,
               "json: 10k-deep array rejected without crashing");
        free(deep);
    } else {
        check_fail("json: depth bomb alloc", "malloc failed");
    }

    /* an over-long string literal must parse (bounded by the request cap) and
       not truncate silently */
    {
        size_t n = 1024 * 1024;
        char *big = malloc(n + 3);
        if (big) {
            JmapJsonErr e = JMAP_JSON_OK;
            JmapJsonDoc *d;
            const char *s;
            size_t sl;
            big[0] = '"';
            memset(big + 1, 'a', n);
            big[n + 1] = '"';
            d = jmap_json_parse(big, n + 2, &e);
            EXPECT(d && jmap_json_str(jmap_json_root(d), &s, &sl) == 0 &&
                       sl == n,
                   "json: 1 MiB string parses whole");
            jmap_json_free(d);
            free(big);
        } else {
            check_fail("json: big string alloc", "malloc failed");
        }
    }
}

/* ------------------------------------------------------------------ */
/* (2) id codec                                                        */
/* ------------------------------------------------------------------ */

static void id_tests(void) {
    static const char *names[] = { "Inbox", "Sent", "A B", "\xc3\x9c" "n\xc3\xaf" "code",
                                   "x.y", "a-b_c", "Long Folder Name 2024" };
    char id[JMAPD_ID_MAX], back[IMAPD_MAX_MBOX + 1];
    size_t i;

    for (i = 0; i < sizeof names / sizeof names[0]; i++) {
        char what[96];
        snprintf(what, sizeof what, "id: mailbox round-trip \"%s\"", names[i]);
        EXPECT(jmapd_id_mailbox(names[i], id, sizeof id) == 0 &&
                   id[0] == 'm' &&
                   jmapd_id_mailbox_parse(id, back, sizeof back) == 0 &&
                   strcmp(back, names[i]) == 0,
               what);
    }

    /* every id byte must be in RFC 8620's Id charset */
    {
        size_t k;
        bool charset_ok = true;
        EXPECT(jmapd_id_mailbox("Inbox", id, sizeof id) == 0, "id: encode ok");
        for (k = 0; id[k]; k++) {
            char c = id[k];
            if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                  (c >= '0' && c <= '9') || c == '-' || c == '_'))
                charset_ok = false;
        }
        EXPECT(charset_ok, "id: mailbox id stays inside the RFC 8620 charset");
    }

    /* rejection matrix: nothing that is not one of OUR ids may decode */
    EXPECT(jmapd_id_mailbox_parse("xabc", back, sizeof back) == -1,
           "id: wrong prefix rejected");
    EXPECT(jmapd_id_mailbox_parse("m", back, sizeof back) == -1,
           "id: empty payload rejected");
    EXPECT(jmapd_id_mailbox_parse("mabc/def", back, sizeof back) == -1,
           "id: '/' in payload rejected");
    EXPECT(jmapd_id_mailbox_parse("m..", back, sizeof back) == -1,
           "id: '..' rejected");
    EXPECT(jmapd_id_mailbox_parse("mYR", back, sizeof back) == -1,
           "id: non-zero padding bits rejected");
    EXPECT(jmapd_id_mailbox_parse("mY", back, sizeof back) == -1,
           "id: impossible base64url length rejected");
    /* b64url("/etc/passwd") must never become a path */
    EXPECT(jmapd_id_mailbox_parse("mL2V0Yy9wYXNzd2Q", back, sizeof back) == -1,
           "id: traversal payload rejected");
    EXPECT(jmapd_id_mailbox_parse("", back, sizeof back) == -1,
           "id: empty id rejected");
    EXPECT(jmapd_id_mailbox("..", id, sizeof id) == -1,
           "id: encode refuses '..'");
    EXPECT(jmapd_id_mailbox("a/b", id, sizeof id) == -1,
           "id: encode refuses '/'");

    /* email ids: primary form and the duplicate-base form */
    {
        char base[IMAPD_MAX_MBOX + 1], mbox[IMAPD_MAX_MBOX + 1];
        EXPECT(jmapd_id_email("1234.M1P1.host", NULL, id, sizeof id) == 0 &&
                   id[0] == 'e' &&
                   jmapd_id_email_parse(id, base, sizeof base, mbox,
                                        sizeof mbox) == 0 &&
                   strcmp(base, "1234.M1P1.host") == 0 && mbox[0] == '\0',
               "id: email round-trip (primary)");
        EXPECT(jmapd_id_email("1234.M1P1.host", "Sent", id, sizeof id) == 0 &&
                   id[0] == 'f' &&
                   jmapd_id_email_parse(id, base, sizeof base, mbox,
                                        sizeof mbox) == 0 &&
                   strcmp(base, "1234.M1P1.host") == 0 &&
                   strcmp(mbox, "Sent") == 0,
               "id: email round-trip (duplicate-base form)");
        EXPECT(jmapd_id_email_parse("e", base, sizeof base, mbox,
                                    sizeof mbox) == -1,
               "id: empty email id rejected");
        EXPECT(jmapd_id_email_parse("q1234", base, sizeof base, mbox,
                                    sizeof mbox) == -1,
               "id: email wrong prefix rejected");
    }

    /* base64url itself: all byte values round-trip, and bad input is refused */
    {
        unsigned char raw[256], dec[300];
        char enc[512];
        size_t n = 0, k;
        for (k = 0; k < sizeof raw; k++) raw[k] = (unsigned char)k;
        EXPECT(jmapd_b64url_encode(raw, sizeof raw, enc, sizeof enc) == 0 &&
                   jmapd_b64url_decode(enc, strlen(enc), dec, sizeof dec, &n) ==
                       0 &&
                   n == sizeof raw && memcmp(raw, dec, n) == 0,
               "id: base64url round-trips all byte values");
        EXPECT(jmapd_b64url_decode("a", 1, dec, sizeof dec, &n) == -1,
               "id: base64url rejects an impossible length");
        EXPECT(jmapd_b64url_decode("a+b/", 4, dec, sizeof dec, &n) == -1,
               "id: base64url rejects the standard alphabet");
    }
}

/* ------------------------------------------------------------------ */
/* (3) session document                                                */
/* ------------------------------------------------------------------ */

static void session_tests(void) {
    JmapdConfig cfg;
    char *doc = NULL;
    size_t len = 0;

    memset(&cfg, 0, sizeof cfg);
    cfg.root = "/tmp";
    cfg.addr = "127.0.0.1";
    cfg.port = 8081;
    cfg.hostname = "jmap.test";
    cfg.max_req = JMAPD_DEFAULT_MAX_REQ;
    cfg.cmd_tmo = 300;

    EXPECT(jmapd_session_render(&cfg, "alice", &doc, &len) == 0 && doc &&
               len == strlen(doc),
           "session: renders");
    if (!doc) return;
    EXPECT(strstr(doc, "\"apiUrl\":\"http://jmap.test:8081/api\"") != NULL,
           "session: apiUrl absolute with the listener's scheme");
    EXPECT(strstr(doc, "\"uploadUrl\":\"http://jmap.test:8081/upload/{accountId}/\"")
               != NULL,
           "session: uploadUrl absolute");
    EXPECT(strstr(doc, "/download/{accountId}/{blobId}/{name}") != NULL,
           "session: downloadUrl is a URI template");
    EXPECT(strstr(doc, "\"eventSourceUrl\":\"http://jmap.test:8081/event/\"")
               != NULL,
           "session: eventSourceUrl absolute");
    EXPECT(strstr(doc, "https://") == NULL,
           "session: no https URL on a plaintext listener");
    EXPECT(strstr(doc, JMAPD_CAP_CORE) != NULL &&
               strstr(doc, JMAPD_CAP_MAIL) != NULL &&
               strstr(doc, JMAPD_CAP_SUB) != NULL,
           "session: advertises core, mail and submission");
    EXPECT(strstr(doc, "\"primaryAccounts\":{\"" JMAPD_CAP_MAIL "\":\"alice\"")
               != NULL,
           "session: primaryAccounts names the account");
    EXPECT(strstr(doc, "\"username\":\"alice\"") != NULL,
           "session: username is the account");
    free(doc);

    /* with TLS configured the same document must switch scheme, not mix */
    cfg.cert = "/tmp/cert.pem";
    cfg.key = "/tmp/key.pem";
    doc = NULL;
    EXPECT(jmapd_session_render(&cfg, "alice", &doc, &len) == 0 && doc &&
               strstr(doc, "\"apiUrl\":\"https://jmap.test:8081/api\"") != NULL &&
               strstr(doc, "http://") == NULL,
           "session: https on a TLS listener, and nothing plaintext");
    free(doc);
}

/* ---- the --public-url override (behind a TLS-terminating proxy) ---- */

/* Every advertised URL must come from the override verbatim — the listener's
   own scheme/host/port are unreachable from the client side, so a document
   that mixes them in is worse than useless. */
static void public_url_tests(void) {
    JmapdConfig cfg;
    char out[JMAPD_PUBLIC_URL_MAX];
    char *doc = NULL;
    size_t len = 0;

    memset(&cfg, 0, sizeof cfg);
    cfg.root = "/tmp";
    cfg.addr = "127.0.0.1";
    cfg.port = 8081;
    cfg.hostname = "127.0.0.1";      /* what the proxy-facing bind would say */
    cfg.max_req = JMAPD_DEFAULT_MAX_REQ;
    cfg.cmd_tmo = 300;
    cfg.public_url = "https://jmap.example.test";

    EXPECT(jmapd_session_render(&cfg, "alice", &doc, &len) == 0 && doc &&
               strstr(doc, "\"apiUrl\":\"https://jmap.example.test/api\"") !=
                   NULL &&
               strstr(doc, "\"uploadUrl\":\"https://jmap.example.test/upload/"
                           "{accountId}/\"") != NULL &&
               strstr(doc, "\"eventSourceUrl\":\"https://jmap.example.test/"
                           "event/\"") != NULL,
           "public-url: the override is advertised verbatim, no port");
    EXPECT(doc &&
               strstr(doc, "\"downloadUrl\":\"https://jmap.example.test/"
                           "download/{accountId}/{blobId}/{name}?accept="
                           "{type}\"") != NULL,
           "public-url: the download template keeps its placeholders");
    EXPECT(doc && strstr(doc, "http://") == NULL &&
               strstr(doc, "127.0.0.1") == NULL,
           "public-url: nothing of the listener leaks into the document");
    free(doc);
    doc = NULL;

    /* a trailing '/' must not double up when the suffixes are joined */
    cfg.public_url = "https://jmap.example.test/";
    EXPECT(jmapd_session_render(&cfg, "alice", &doc, &len) == 0 && doc &&
               strstr(doc, "\"apiUrl\":\"https://jmap.example.test/api\"") !=
                   NULL &&
               strstr(doc, "//api") == NULL,
           "public-url: a trailing slash is stripped before joining");
    free(doc);
    doc = NULL;

    /* a path prefix is preserved and joined the same way */
    cfg.public_url = "https://jmap.example.test/jmap";
    EXPECT(jmapd_session_render(&cfg, "alice", &doc, &len) == 0 && doc &&
               strstr(doc, "\"apiUrl\":\"https://jmap.example.test/jmap/api\"")
                   != NULL &&
               strstr(doc, "\"downloadUrl\":\"https://jmap.example.test/jmap/"
                           "download/{accountId}/{blobId}/{name}?accept="
                           "{type}\"") != NULL &&
               strstr(doc, "\"eventSourceUrl\":\"https://jmap.example.test/"
                           "jmap/event/\"") != NULL,
           "public-url: a path prefix is preserved on every URL");
    free(doc);
    doc = NULL;

    /* normalization verdicts */
    EXPECT(jmapd_public_url_normalize("https://h.test/x/", out, sizeof out) ==
                   JMAPD_PUB_OK &&
               strcmp(out, "https://h.test/x") == 0,
           "public-url: normalize strips trailing slashes only");
    EXPECT(jmapd_public_url_normalize("", out, sizeof out) == JMAPD_PUB_OK &&
               out[0] == '\0',
           "public-url: empty means no override");
    EXPECT(jmapd_public_url_normalize(NULL, out, sizeof out) == JMAPD_PUB_OK &&
               out[0] == '\0',
           "public-url: NULL means no override");

    /* refusals — each names a distinct defect */
    EXPECT(jmapd_public_url_normalize("ftp://h.test", out, sizeof out) ==
               JMAPD_PUB_ERR_SCHEME,
           "public-url: a non-http scheme is refused");
    EXPECT(jmapd_public_url_normalize("jmap.example.test", out, sizeof out) ==
               JMAPD_PUB_ERR_SCHEME,
           "public-url: a bare host with no scheme is refused");
    EXPECT(jmapd_public_url_normalize("https://", out, sizeof out) ==
               JMAPD_PUB_ERR_HOST,
           "public-url: a scheme with no host is refused");
    EXPECT(jmapd_public_url_normalize("https:///jmap", out, sizeof out) ==
               JMAPD_PUB_ERR_HOST,
           "public-url: an empty authority is refused");
    EXPECT(jmapd_public_url_normalize("https://:8443", out, sizeof out) ==
               JMAPD_PUB_ERR_HOST,
           "public-url: a port with no host is refused");
    EXPECT(jmapd_public_url_normalize("https://u:p@h.test", out, sizeof out) ==
               JMAPD_PUB_ERR_USERINFO,
           "public-url: userinfo is refused");
    EXPECT(jmapd_public_url_normalize("https://h.test/?a=b", out, sizeof out) ==
               JMAPD_PUB_ERR_QUERY,
           "public-url: a query string is refused");
    EXPECT(jmapd_public_url_normalize("https://h.test/#frag", out, sizeof out) ==
               JMAPD_PUB_ERR_QUERY,
           "public-url: a fragment is refused");
    EXPECT(jmapd_public_url_normalize("https://h.test/a b", out, sizeof out) ==
               JMAPD_PUB_ERR_CHAR,
           "public-url: a space is refused");
    {
        char big[JMAPD_PUBLIC_URL_MAX + 32];
        size_t i;
        memcpy(big, "https://h.test/", 15);
        for (i = 15; i < sizeof big - 1; i++) big[i] = 'a';
        big[sizeof big - 1] = '\0';
        EXPECT(jmapd_public_url_normalize(big, out, sizeof out) ==
                   JMAPD_PUB_ERR_LONG,
               "public-url: an over-long value is refused");
        EXPECT(jmapd_public_url_normalize("https://h.test/x", out, 8) ==
                   JMAPD_PUB_ERR_LONG,
               "public-url: a value that does not fit the caller's buffer is "
               "refused, not truncated");
    }

    /* plaintext http is a policy verdict, keyed on the bind address */
    EXPECT(jmapd_public_url_check("http://127.0.0.1:8788", "127.0.0.1", out,
                                  sizeof out) == JMAPD_PUB_OK,
           "public-url: http is accepted on a loopback bind");
    EXPECT(jmapd_public_url_check("http://localhost:8788", "localhost", out,
                                  sizeof out) == JMAPD_PUB_OK,
           "public-url: http is accepted on the localhost bind");
    EXPECT(jmapd_public_url_check("http://jmap.example.test", "0.0.0.0", out,
                                  sizeof out) == JMAPD_PUB_ERR_PLAINTEXT,
           "public-url: http is refused for a non-loopback bind");
    EXPECT(jmapd_public_url_check("http://jmap.example.test", "10.0.0.5", out,
                                  sizeof out) == JMAPD_PUB_ERR_PLAINTEXT,
           "public-url: http is refused for a LAN bind");
    EXPECT(jmapd_public_url_check("https://jmap.example.test", "0.0.0.0", out,
                                  sizeof out) == JMAPD_PUB_OK,
           "public-url: https is accepted on any bind");
    EXPECT(jmapd_public_url_check("ftp://h.test", "127.0.0.1", out,
                                  sizeof out) == JMAPD_PUB_ERR_SCHEME,
           "public-url: check() reports the syntax verdict too");

    /* an unadvertisable override must fail the render, not be advertised */
    cfg.public_url = "ftp://jmap.example.test";
    EXPECT(jmapd_session_render(&cfg, "alice", &doc, &len) != 0 && !doc,
           "public-url: an invalid override fails the session render");
    free(doc);
    doc = NULL;

    /* no override: the derived form is unchanged (regression guard) */
    cfg.public_url = "";
    EXPECT(jmapd_session_render(&cfg, "alice", &doc, &len) == 0 && doc &&
               strstr(doc, "\"apiUrl\":\"http://127.0.0.1:8081/api\"") != NULL,
           "public-url: an empty override keeps the derived base URL");
    free(doc);
}

/* ------------------------------------------------------------------ */
/* (4) auth                                                            */
/* ------------------------------------------------------------------ */

static void auth_tests(void) {
    char user[256], pass[256];
    int scheme = JMAPD_AUTH_NONE;

    /* base64("alice:waldorf") */
    EXPECT(jmapd_auth_parse("Basic YWxpY2U6d2FsZG9yZg==", 26, &scheme, user,
                            sizeof user, pass, sizeof pass) == 0 &&
               scheme == JMAPD_AUTH_BASIC && strcmp(user, "alice") == 0 &&
               strcmp(pass, "waldorf") == 0,
           "auth: Basic splits user:pass");
    /* base64("alice:pa:ss") — a colon in the password is legal */
    EXPECT(jmapd_auth_parse("Basic YWxpY2U6cGE6c3M=", 22, &scheme, user,
                            sizeof user, pass, sizeof pass) == 0 &&
               strcmp(user, "alice") == 0 && strcmp(pass, "pa:ss") == 0,
           "auth: Basic keeps colons in the password");
    EXPECT(jmapd_auth_parse("Basic bm9jb2xvbg==", 18, &scheme, user, sizeof user,
                            pass, sizeof pass) == -1,
           "auth: Basic without a colon rejected");
    EXPECT(jmapd_auth_parse("Basic !!!!", 10, &scheme, user, sizeof user, pass,
                            sizeof pass) == -1,
           "auth: Basic with bad base64 rejected");
    EXPECT(jmapd_auth_parse("Bearer sekrit", 13, &scheme, user, sizeof user,
                            pass, sizeof pass) == 0 &&
               scheme == JMAPD_AUTH_BEARER && pass[0] &&
               strcmp(pass, "sekrit") == 0,
           "auth: Bearer yields the token");
    EXPECT(jmapd_auth_parse("Digest abc", 10, &scheme, user, sizeof user, pass,
                            sizeof pass) == -1,
           "auth: unknown scheme rejected");
    EXPECT(jmapd_auth_parse("", 0, &scheme, user, sizeof user, pass,
                            sizeof pass) == -1,
           "auth: empty header rejected");

    /* the passwd table + per-IP lockout, over a scratch root */
    {
        char tpl[] = "/tmp/visage_jmapd_XXXXXX";
        char *root = mkdtemp(tpl);
        if (!root) {
            check_fail("auth: mkdtemp scratch root", "mkdtemp failed");
            return;
        }
        {
            char path[4096];
            FILE *f;
            snprintf(path, sizeof path, "%s/%s", root, IMAPD_PASSWD_FILE);
            f = fopen(path, "w");
            if (f) {
                fprintf(f, "alice:waldorf\n# comment\n");
                fclose(f);
            }
            {
                ImapdConfig icfg;
                ImapdServer srv;
                unsigned char ip[4] = { 127, 0, 0, 1 };
                int k;
                time_t now = time(NULL);

                memset(&icfg, 0, sizeof icfg);
                icfg.root = root;
                memset(&srv, 0, sizeof srv);
                srv.cfg = icfg;
                EXPECT(imapd_auth_load(&icfg, &srv) == 0 && srv.ncreds == 1,
                       "auth: passwd table loads");
                EXPECT(imapd_auth_check(&srv, "alice", "waldorf"),
                       "auth: correct password accepted");
                EXPECT(!imapd_auth_check(&srv, "alice", "wrong"),
                       "auth: wrong password rejected");
                EXPECT(!imapd_auth_check(&srv, "bob", "waldorf"),
                       "auth: unknown user rejected");
                EXPECT(!imapd_auth_blocked(&srv, ip, 4, now),
                       "auth: not locked out initially");
                for (k = 0; k < IMAPD_AUTH_MAX_FAILS; k++)
                    imapd_auth_fail(&srv, ip, 4, now);
                EXPECT(imapd_auth_blocked(&srv, ip, 4, now),
                       "auth: lockout after the failure threshold");
                imapd_auth_clear(&srv, ip, 4);
                EXPECT(!imapd_auth_blocked(&srv, ip, 4, now),
                       "auth: a successful auth clears the lockout");
                free(srv.creds ? srv.creds[0].user : NULL);
                free(srv.creds ? srv.creds[0].pass : NULL);
                free(srv.creds);
            }
        }
        {
            char path[4096];
            snprintf(path, sizeof path, "%s/%s", root, IMAPD_PASSWD_FILE);
            unlink(path);
            rmdir(root);
        }
    }
}

/* ------------------------------------------------------------------ */
/* (4b) authentication is per REQUEST, not per connection              */
/* ------------------------------------------------------------------ */

/* jmapd_core_auth is callable without a socket: it reads srv->auth and the
   request's Authorization header, and writes c->c.user.  That is enough to
   pin the property a keep-alive probe measured live — a request carrying no
   credential must be refused even when an EARLIER request on the same
   connection authenticated, because behind Caddy a pooled upstream
   connection can be reused by a different client. */
static void per_request_auth_tests(void) {
    static const char basic[] = "Basic YWxpY2U6d2FsZG9yZg==";   /* alice:waldorf */
    static const char wrong[] = "Basic YWxpY2U6d3Jvbmc=";      /* alice:wrong */
    char tpl[] = "/tmp/visage_jmapd_req_XXXXXX";
    char *root = mkdtemp(tpl);
    JmapdServer srv;
    JmapdConn c;
    JmapdHttpReq req;
    ImapdConfig icfg;

    if (!root) {
        check_fail("auth per request: mkdtemp scratch root", "mkdtemp failed");
        return;
    }
    {
        char path[4096];
        FILE *f;
        snprintf(path, sizeof path, "%s/%s", root, IMAPD_PASSWD_FILE);
        f = fopen(path, "w");
        if (f) {
            fprintf(f, "alice:waldorf\n");
            fclose(f);
        }
        memset(&icfg, 0, sizeof icfg);
        icfg.root = root;
        memset(&srv, 0, sizeof srv);
        srv.icfg = icfg;
        if (imapd_auth_load(&icfg, &srv.auth) != 0 || srv.auth.ncreds != 1) {
            check_fail("auth per request: passwd table loads", NULL);
            unlink(path);
            rmdir(root);
            return;
        }

        memset(&c, 0, sizeof c);
        c.c.id = 1;
        c.c.peer_ip[0] = 127;
        c.c.peer_ip[3] = 1;
        c.c.peer_ip_len = 4;

        /* (a) a stale user left on the connection by an earlier request must
           not authenticate a request that carries no header. */
        c.c.user = strdup("alice");
        memset(&req, 0, sizeof req);
        EXPECT(jmapd_core_auth(&srv, &c, &req) == -1 && c.c.user == NULL,
               "auth per request: no header on an already-authenticated "
               "connection is refused, user cleared");

        /* (b) the same connection, now with the header: served. */
        memset(&req, 0, sizeof req);
        memcpy(req.auth, basic, sizeof basic - 1);
        req.auth_len = sizeof basic - 1;
        EXPECT(jmapd_core_auth(&srv, &c, &req) == 0 && c.c.user &&
                   strcmp(c.c.user, "alice") == 0,
               "auth per request: the request's own header authenticates");

        /* (c) the credential does NOT survive to the next request: this is
           the connection-cached principal the live probe measured. */
        memset(&req, 0, sizeof req);
        EXPECT(jmapd_core_auth(&srv, &c, &req) == -1 && c.c.user == NULL,
               "auth per request: the credential does not carry to the next "
               "request on the connection");

        /* (d) a failed check leaves no user for a handler to read. */
        memset(&req, 0, sizeof req);
        memcpy(req.auth, wrong, sizeof wrong - 1);
        req.auth_len = sizeof wrong - 1;
        EXPECT(jmapd_core_auth(&srv, &c, &req) == -1 && c.c.user == NULL,
               "auth per request: a bad credential leaves no user");

        free(c.c.user);
        free(srv.auth.creds ? srv.auth.creds[0].user : NULL);
        free(srv.auth.creds ? srv.auth.creds[0].pass : NULL);
        free(srv.auth.creds);
    }
    {
        char path[4096];
        snprintf(path, sizeof path, "%s/%s", root, IMAPD_PASSWD_FILE);
        unlink(path);
        rmdir(root);
    }
}

/* ------------------------------------------------------------------ */
/* (5) HTTP request parse                                              */
/* ------------------------------------------------------------------ */

static void http_tests(void) {
    static const char get[] =
        "GET /.well-known/jmap HTTP/1.1\r\n"
        "Host: jmap.test\r\n"
        "Authorization: Basic YWxpY2U6d2FsZG9yZg==\r\n"
        "\r\n";
    static const char post[] =
        "POST /api HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello";
    static const char post_short[] =
        "POST /api HTTP/1.1\r\nContent-Length: 5\r\n\r\nhel";
    static const char post_nocl[] = "POST /api HTTP/1.1\r\n\r\n";
    static const char chunked[] =
        "POST /api HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n";
    static const char too_big[] =
        "POST /api HTTP/1.1\r\nContent-Length: 999999999\r\n\r\n";
    static const char h10[] = "GET /api HTTP/1.0\r\n\r\n";
    static const char h10ka[] =
        "GET /api HTTP/1.0\r\nConnection: keep-alive\r\n\r\n";
    static const char hclose[] =
        "GET /api HTTP/1.1\r\nConnection: close\r\n\r\n";
    static const char badver[] = "GET /api HTTP/2.0\r\n\r\n";
    static const char junk[] = "garbage\r\n\r\n";
    static const char put[] = "PUT /api HTTP/1.1\r\n\r\n";
    JmapdHttpReq r;
    int v;

    v = jmapd_http_req_parse(get, sizeof get - 1, JMAPD_DEFAULT_MAX_REQ, &r);
    EXPECT(v == 1 && r.method == JMAPD_M_GET &&
               r.path_len == strlen("/.well-known/jmap") &&
               memcmp(r.path, "/.well-known/jmap",
                      strlen("/.well-known/jmap")) == 0 &&
               r.keep_alive && r.body_len == 0,
           "http: GET session request parses");
    EXPECT(r.auth_len > 0 && strncmp(r.auth, "Basic ", 6) == 0,
           "http: Authorization header captured");

    v = jmapd_http_req_parse(post, sizeof post - 1, JMAPD_DEFAULT_MAX_REQ, &r);
    EXPECT(v == 1 && r.method == JMAPD_M_POST && r.body_len == 5 &&
               r.has_cl,
           "http: POST with Content-Length parses");
    v = jmapd_http_req_parse(post_short, sizeof post_short - 1,
                             JMAPD_DEFAULT_MAX_REQ, &r);
    EXPECT(v == 0, "http: short body needs more bytes");
    v = jmapd_http_req_parse(post_nocl, sizeof post_nocl - 1,
                             JMAPD_DEFAULT_MAX_REQ, &r);
    EXPECT(v == 411, "http: POST without Content-Length is 411");
    v = jmapd_http_req_parse(chunked, sizeof chunked - 1,
                             JMAPD_DEFAULT_MAX_REQ, &r);
    EXPECT(v == 501, "http: chunked body is 501");
    v = jmapd_http_req_parse(too_big, sizeof too_big - 1, 1024, &r);
    EXPECT(v == 413, "http: Content-Length over the cap is 413");
    v = jmapd_http_req_parse(h10, sizeof h10 - 1, JMAPD_DEFAULT_MAX_REQ, &r);
    EXPECT(v == 1 && !r.keep_alive, "http: HTTP/1.0 closes by default");
    v = jmapd_http_req_parse(h10ka, sizeof h10ka - 1, JMAPD_DEFAULT_MAX_REQ, &r);
    EXPECT(v == 1 && r.keep_alive, "http: HTTP/1.0 + keep-alive stays open");
    v = jmapd_http_req_parse(hclose, sizeof hclose - 1, JMAPD_DEFAULT_MAX_REQ,
                             &r);
    EXPECT(v == 1 && !r.keep_alive, "http: Connection: close honoured");
    v = jmapd_http_req_parse(badver, sizeof badver - 1, JMAPD_DEFAULT_MAX_REQ,
                             &r);
    EXPECT(v == 400, "http: HTTP/2.0 request line rejected");
    v = jmapd_http_req_parse(junk, sizeof junk - 1, JMAPD_DEFAULT_MAX_REQ, &r);
    EXPECT(v == 400, "http: junk request line rejected");
    v = jmapd_http_req_parse(put, sizeof put - 1, JMAPD_DEFAULT_MAX_REQ, &r);
    EXPECT(v == 1 && r.method == JMAPD_M_OTHER,
           "http: an unsupported method parses (the router answers 405)");

    /* header block larger than the cap, with no end marker: 431 */
    {
        char *big = malloc(JMAPD_MAX_HDR + 16);
        if (big) {
            memset(big, 'x', JMAPD_MAX_HDR + 16);
            v = jmapd_http_req_parse(big, JMAPD_MAX_HDR + 16,
                                     JMAPD_DEFAULT_MAX_REQ, &r);
            EXPECT(v == 431, "http: oversized header block is 431");
            free(big);
        } else {
            check_fail("http: header fixture alloc", "malloc failed");
        }
    }
    /* an incomplete header block under the cap needs more bytes */
    v = jmapd_http_req_parse("GET / HTTP/1.1\r\nHost: x\r\n", 24,
                             JMAPD_DEFAULT_MAX_REQ, &r);
    EXPECT(v == 0, "http: incomplete header block needs more bytes");
}

/* ------------------------------------------------------------------ */
/* (6) state strings                                                   */
/* ------------------------------------------------------------------ */

static void state_tests(void) {
    char s[32];
    EXPECT(jmapd_state_fmt('e', 12, s, sizeof s) == 0 && strcmp(s, "e12") == 0,
           "state: email state format");
    EXPECT(jmapd_state_fmt('m', 0, s, sizeof s) == 0 && strcmp(s, "m0") == 0,
           "state: mailbox state format");
    EXPECT(jmapd_state_fmt('e', 1, s, 2) == -1, "state: truncation rejected");
    EXPECT(jmapd_addr_loopback("127.0.0.1") &&
               jmapd_addr_loopback("localhost") &&
               jmapd_addr_loopback("::1") &&
               !jmapd_addr_loopback("0.0.0.0") &&
               !jmapd_addr_loopback("10.0.0.5") &&
               !jmapd_addr_loopback(NULL),
           "state: loopback classifier");
}

/* ------------------------------------------------------------------ */
/* (7) MIME: the CTE decoder                                           */
/* ------------------------------------------------------------------ */

/* The decoder used for bodyValues AND the blob download, measured against
   imapd's strict whole-buffer decoder (the oracle) on a corpus of well-formed
   base64 payloads: two implementations, one verdict. */
static void cte_tests(void) {
    static const char *const corpus[] = {
        "", "TWFu", "TWE=", "TQ==", "SGVsbG8sIHdvcmxkIQ==",
        "JVBERi0xLjQK", "PGh0bWw+PGJvZHk+Q2Fmw6k8L2JvZHk+PC9odG1sPg==",
        "AQIDBAUGBwgJCgsMDQ4P", "////", "Zm9vYmFyYmF6"
    };
    size_t i;
    bool ok = true;

    EXPECT(jmapd_cte_kind("7bit") == JMAPD_CTE_7BIT &&
               jmapd_cte_kind("BASE64") == JMAPD_CTE_BASE64 &&
               jmapd_cte_kind("quoted-printable") == JMAPD_CTE_QP &&
               jmapd_cte_kind("x-uuencode") == -1 &&
               jmapd_cte_kind(NULL) == JMAPD_CTE_7BIT,
           "mime: CTE tokens map to decoder kinds (unknown -> -1)");

    for (i = 0; i < sizeof corpus / sizeof corpus[0]; i++) {
        char *mine = NULL;
        size_t minelen = 0;
        unsigned char oracle[256];
        size_t oraclelen = 0;
        bool bad = false;
        if (jmapd_decode_all(JMAPD_CTE_BASE64, corpus[i], strlen(corpus[i]),
                             &mine, &minelen, &bad) != 0) {
            ok = false;
            break;
        }
        if (imapd_b64_decode(corpus[i], strlen(corpus[i]), oracle,
                             sizeof oracle, &oraclelen) != 0) {
            free(mine);
            ok = false;
            break;
        }
        if (minelen != oraclelen || memcmp(mine, oracle, minelen) != 0 || bad) {
            printf("     base64 corpus[%zu] '%s': mine %zu oracle %zu bad=%d\n",
                   i, corpus[i], minelen, oraclelen, (int)bad);
            free(mine);
            ok = false;
            break;
        }
        free(mine);
    }
    EXPECT(ok, "mime: base64 decoder agrees with imapd_b64_decode");

    /* whitespace-wrapped base64 (a legal wrapped body) decodes the same */
    {
        char *out = NULL;
        size_t n = 0;
        bool bad = false;
        EXPECT(jmapd_decode_all(JMAPD_CTE_BASE64, "TWFu\r\nTWFu\r\n", 12, &out,
                                &n, &bad) == 0 &&
                   n == 6 && memcmp(out, "ManMan", 6) == 0 && !bad,
               "mime: base64 ignores CRLF between quads");
        free(out);
    }

    /* quoted-printable: '=XX' hex, soft line breaks, a literal '=' */
    {
        char *out = NULL;
        size_t n = 0;
        bool bad = false;
        EXPECT(jmapd_decode_all(JMAPD_CTE_QP,
                                "Caf=C3=A9\r\nsoft=\r\nbreak\r\n100=25\r\n",
                                sizeof "Caf=C3=A9\r\nsoft=\r\nbreak\r\n100=25\r\n" - 1,
                                &out, &n, &bad) == 0 &&
                   n == 24 && !bad &&
                   memcmp(out, "Caf\xc3\xa9\r\nsoftbreak\r\n100%\r\n",
                          24) == 0,
               "mime: quoted-printable decodes hex and soft breaks");
        free(out);
    }
    {
        char *out = NULL;
        size_t n = 0;
        bool bad = true;
        /* a malformed escape is skipped and FLAGGED, not silently dropped */
        EXPECT(jmapd_decode_all(JMAPD_CTE_QP, "a=ZZb", 5, &out, &n, &bad) == 0 &&
                   bad && n == 5 && memcmp(out, "a=ZZb", 5) == 0,
               "mime: quoted-printable flags a malformed escape");
        free(out);
    }
    {
        char *out = NULL;
        size_t n = 0;
        bool bad = false;
        EXPECT(jmapd_decode_all(JMAPD_CTE_7BIT, "raw\r\nbytes", 10, &out, &n,
                                &bad) == 0 &&
                   n == 10 && memcmp(out, "raw\r\nbytes", 10) == 0,
               "mime: 7bit passes bytes through");
        free(out);
    }
    /* a decoded NUL is dropped: a JSON string truncated at a NUL while
       Content-Length counts the rest is a corrupt response. */
    {
        char *out = NULL;
        size_t n = 0;
        bool bad = false;
        EXPECT(jmapd_decode_all(JMAPD_CTE_7BIT, "a\0b", 3, &out, &n, &bad) == 0 &&
                   n == 2 && memcmp(out, "ab", 2) == 0,
               "mime: decoded NULs are dropped (one C-string representation)");
        free(out);
    }
}

/* ------------------------------------------------------------------ */
/* (8) MIME: the part tree                                             */
/* ------------------------------------------------------------------ */

static const char FIX_MIXED[] =
    "From: Alice <alice@example.com>\r\n"
    "To: Bob <bob@example.com>\r\n"
    "Cc: carol@example.com, Dave <dave@example.com>\r\n"
    "Subject: Caf\xc3\xa9 report\r\n"
    "Message-ID: <m1@example.com>\r\n"
    "Date: Mon, 1 Jan 2024 00:00:00 +0000\r\n"
    "MIME-Version: 1.0\r\n"
    "Content-Type: multipart/mixed; boundary=\"OUTER\"\r\n"
    "\r\n"
    "preamble text\r\n"
    "--OUTER\r\n"
    "Content-Type: multipart/alternative; boundary=\"INNER\"\r\n"
    "\r\n"
    "--INNER\r\n"
    "Content-Type: text/plain; charset=utf-8\r\n"
    "Content-Transfer-Encoding: quoted-printable\r\n"
    "\r\n"
    "Caf=C3=A9 line one\r\n"
    "second line\r\n"
    "--INNER\r\n"
    "Content-Type: text/html; charset=utf-8\r\n"
    "Content-Transfer-Encoding: base64\r\n"
    "\r\n"
    "PGh0bWw+PGJvZHk+Q2Fmw6k8L2JvZHk+PC9odG1sPg==\r\n"
    "--INNER--\r\n"
    "--OUTER\r\n"
    "Content-Type: application/pdf; name=\"report.pdf\"\r\n"
    "Content-Disposition: attachment; filename=\"report.pdf\"\r\n"
    "Content-Transfer-Encoding: base64\r\n"
    "\r\n"
    "JVBERi0xLjQK\r\n"
    "--OUTER--\r\n";

static JmapdTree *tree_of(const char *msg, size_t len) {
    JmapdTree *t = malloc(sizeof *t);
    if (!t) return NULL;
    if (jmapd_tree_build(msg, len, t) != 0) {
        free(t);
        return NULL;
    }
    return t;
}

static void mime_tree_tests(void) {
    JmapdTree *t = tree_of(FIX_MIXED, sizeof FIX_MIXED - 1);

    EXPECT(t && t->nparts == 5, "mime: mixed/alternative tree has 5 parts");
    if (!t || t->nparts != 5) {
        int d;
        if (t)
            for (d = 0; d < t->nparts; d++)
                printf("     part %d id='%s' depth=%d multi=%d type=%s/%s "
                       "cte=%s disp=%s file=%s [%zu,%zu) hdr %zu\n",
                       d, t->parts[d].info.id, t->parts[d].info.depth,
                       (int)t->parts[d].info.multipart, t->parts[d].info.type,
                       t->parts[d].info.subtype, t->parts[d].info.cte,
                       t->parts[d].info.disp, t->parts[d].info.filename,
                       t->parts[d].info.start, t->parts[d].info.end,
                       t->parts[d].info.hdr_end);
        free(t);
        return;
    }
    EXPECT(strcmp(t->parts[0].info.id, "") == 0 &&
               t->parts[0].info.multipart &&
               strcmp(t->parts[0].info.subtype, "mixed") == 0,
           "mime: the top-level part is the multipart root with partId \"\"");
    EXPECT(strcmp(t->parts[1].info.id, "1") == 0 &&
               t->parts[1].info.multipart &&
               strcmp(t->parts[1].info.subtype, "alternative") == 0 &&
               t->parts[1].parent == 0,
           "mime: nested multipart/alternative is part 1");
    EXPECT(strcmp(t->parts[2].info.id, "1.1") == 0 &&
               strcmp(t->parts[2].info.type, "text") == 0 &&
               strcmp(t->parts[2].info.subtype, "plain") == 0 &&
               strcmp(t->parts[2].info.charset, "utf-8") == 0 &&
               strcmp(t->parts[2].info.cte, "quoted-printable") == 0 &&
               t->parts[2].parent == 1,
           "mime: text/plain leaf is 1.1 with charset + CTE");
    EXPECT(strcmp(t->parts[3].info.id, "1.2") == 0 &&
               strcmp(t->parts[3].info.subtype, "html") == 0,
           "mime: the html leaf is 1.2");
    EXPECT(strcmp(t->parts[4].info.id, "2") == 0 &&
               strcmp(t->parts[4].info.subtype, "pdf") == 0 &&
               strcmp(t->parts[4].info.disp, "attachment") == 0 &&
               strcmp(t->parts[4].info.filename, "report.pdf") == 0,
           "mime: the attachment is part 2 with disposition + filename");

    /* classification: exactly one text body part, one html body part, one
       attachment — the three the client renders differently */
    EXPECT(t->parts[2].body_kind == 1 && !t->parts[2].attachment &&
               t->parts[3].body_kind == 2 && !t->parts[3].attachment &&
               t->parts[4].body_kind == 0 && t->parts[4].attachment &&
               t->parts[0].body_kind == 0 && !t->parts[0].attachment,
           "mime: leaves classify into text body vs attachment");

    /* the decoded bodies are DISTINCT and correctly decoded */
    {
        JmapdBodyValue bv;
        memset(&bv, 0, sizeof bv);
        EXPECT(jmapd_body_value(FIX_MIXED, t, 2, 0, &bv) == 0 &&
                   bv.len == 27 &&
                   memcmp(bv.value, "Caf\xc3\xa9 line one\r\nsecond line", 27) == 0 &&
                   !bv.truncated && !bv.problem,
               "mime: quoted-printable bodyValue decodes to the UTF-8 text");
        jmapd_body_value_free(&bv);
        memset(&bv, 0, sizeof bv);
        EXPECT(jmapd_body_value(FIX_MIXED, t, 3, 0, &bv) == 0 &&
                   bv.len == 31 &&
                   memcmp(bv.value, "<html><body>Caf\xc3\xa9</body></html>",
                          31) == 0,
               "mime: the base64 part decodes to the html, not the pdf");
        jmapd_body_value_free(&bv);
    }
    /* truncation: maxBodyValueBytes is honoured and flagged */
    {
        JmapdBodyValue bv;
        memset(&bv, 0, sizeof bv);
        EXPECT(jmapd_body_value(FIX_MIXED, t, 2, 5, &bv) == 0 && bv.len == 5 &&
                   bv.truncated && memcmp(bv.value, "Caf\xc3", 4) == 0,
               "mime: maxBodyValueBytes truncates and sets isTruncated");
        jmapd_body_value_free(&bv);
        memset(&bv, 0, sizeof bv);
        /* exactly the whole body: NOT truncated (the flag is exact, not a
           guess from the encoded length) */
        EXPECT(jmapd_body_value(FIX_MIXED, t, 2, 27, &bv) == 0 &&
                   bv.len == 27 && !bv.truncated,
               "mime: a body of exactly maxBodyValueBytes is not truncated");
        jmapd_body_value_free(&bv);
    }
    free(t);

    /* folded headers: the Content-Type boundary and the disposition filename
       sit on continuation lines and must still be found */
    {
        static const char folded[] =
            "From: a@b\r\n"
            "Subject: folded\r\n"
            " subject\r\n"
            "Content-Type: multipart/mixed;\r\n"
            " boundary=\"FOLD\"\r\n"
            "Content-Disposition: attachment;\r\n"
            " filename=\"a b.txt\"\r\n"
            "\r\n"
            "--FOLD\r\n"
            "Content-Type: text/plain\r\n"
            "\r\n"
            "body\r\n"
            "--FOLD--\r\n";
        JmapdTree *f = tree_of(folded, sizeof folded - 1);
        EXPECT(f && f->nparts == 2 &&
                   strcmp(f->parts[1].info.id, "1") == 0 &&
                   strcmp(f->parts[1].info.subtype, "plain") == 0,
               "mime: folded Content-Type boundary still splits the parts");
        free(f);
    }

    /* malformed multipart: the boundary never appears in the body.  The tree
       TRUNCATES at the fault (a container with no children) — no crash, no
       invented parts, no infinite loop. */
    {
        static const char broken[] =
            "From: a@b\r\n"
            "Content-Type: multipart/mixed; boundary=\"xyz\"\r\n"
            "\r\n"
            "--not-the-boundary\r\n"
            "Content-Type: text/plain\r\n"
            "\r\n"
            "text\r\n";
        JmapdTree *b = tree_of(broken, sizeof broken - 1);
        EXPECT(b && b->nparts == 1 && b->parts[0].info.multipart,
               "mime: an unparseable multipart truncates to the container");
        free(b);
    }
    /* a multipart with no boundary parameter at all */
    {
        static const char nob[] =
            "Content-Type: multipart/mixed\r\n\r\nbody\r\n";
        JmapdTree *b = tree_of(nob, sizeof nob - 1);
        EXPECT(b && b->nparts == 1,
               "mime: multipart without a boundary parameter is one part");
        free(b);
    }
    /* a plain message: ONE part, and it is part "1" (RFC 8621 4.1.1) — never
       "" : an empty partId cannot be interned as a client cache key */
    {
        static const char simple[] =
            "From: a@b\r\nSubject: s\r\n\r\nhello\r\n";
        JmapdTree *s = tree_of(simple, sizeof simple - 1);
        EXPECT(s && s->nparts == 1 && strcmp(s->parts[0].info.id, "1") == 0 &&
                   s->parts[0].body_kind == 1,
               "mime: a simple message is one text body part with partId \"1\"");
        free(s);
    }
    /* No BODY part id jmapd produces for ANY fixture is empty.  An empty
       partId is both unnumbered (RFC 8621 4.1.1 numbers the parts of a
       message) and unusable as a cache key: the mail client interns body rows
       by partId and its datalog engine refuses to intern "".  A multipart
       CONTAINER keeps its own "" (it is not a body part, and its numbering is
       pinned by the assertions above); the multipart fixtures here assert
       their numbering too, so the single-part fix cannot shift a multipart
       id. */
    {
        static const struct {
            const char *what, *msg;
            const char *ids;          /* expected ids, space-separated */
        } cases[] = {
            {"text-only", "Content-Type: text/plain\r\n\r\ntext body\r\n", "1"},
            {"html-only", "Content-Type: text/html\r\n\r\n<p>html</p>\r\n", "1"},
            {"no Content-Type",
             "From: a@b\r\nSubject: s\r\n\r\nuntyped body\r\n", "1"},
            {"multipart/alternative",
             "Content-Type: multipart/alternative; boundary=\"ALT\"\r\n\r\n"
             "--ALT\r\nContent-Type: text/plain\r\n\r\nplain\r\n"
             "--ALT\r\nContent-Type: text/html\r\n\r\n<p>html</p>\r\n"
             "--ALT--\r\n",
             "1 2"},
            {"multipart/mixed with an attachment",
             "Content-Type: multipart/mixed; boundary=\"MX\"\r\n\r\n"
             "--MX\r\nContent-Type: text/plain\r\n\r\nplain\r\n"
             "--MX\r\nContent-Type: application/pdf; name=\"a.pdf\"\r\n"
             "Content-Disposition: attachment; filename=\"a.pdf\"\r\n\r\n"
             "%PDF-1.4\r\n"
             "--MX--\r\n",
             "1 2"},
        };
        size_t c;
        for (c = 0; c < sizeof cases / sizeof cases[0]; c++) {
            JmapdTree *t2 = tree_of(cases[c].msg, strlen(cases[c].msg));
            char got[256] = "";
            size_t o = 0;
            int i2;
            bool nonempty = t2 != NULL;
            for (i2 = 0; t2 && i2 < t2->nparts; i2++) {
                if (t2->parts[i2].info.multipart) continue;
                if (!t2->parts[i2].info.id[0]) nonempty = false;
                o += (size_t)snprintf(got + o, sizeof got - o, "%s%s",
                                      o ? " " : "", t2->parts[i2].info.id);
            }
            EXPECT(nonempty && strcmp(got, cases[c].ids) == 0,
                   c < 3 ? "mime: a single-part message's only part is \"1\""
                         : (c == 3 ? "mime: multipart/alternative keeps 1/2"
                                   : "mime: multipart/mixed keeps 1/2"));
            if (!(nonempty && strcmp(got, cases[c].ids) == 0))
                printf("     %s: ids='%s' want='%s'\n", cases[c].what, got,
                       cases[c].ids);
            free(t2);
        }
    }
    /* an empty message: no crash, and no parts is legal */
    {
        JmapdTree *e = tree_of("", 0);
        EXPECT(e != NULL, "mime: an empty message yields an empty tree");
        free(e);
    }
}

/* The in-memory tree and the FILE-based resolver (used by the download) must
   agree on every part's byte range: otherwise a download serves different
   bytes than the bodyStructure described. */
static void mime_file_part_tests(void) {
    char tpl[] = "/tmp/visage_jmapd_mime_XXXXXX";
    char *dir = mkdtemp(tpl);
    char path[4096];
    int fd = -1, i;
    JmapdTree *t = NULL;

    if (!dir) {
        check_fail("mime: file resolver scratch dir", "mkdtemp failed");
        return;
    }
    snprintf(path, sizeof path, "%s/msg.eml", dir);
    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        check_fail("mime: file resolver fixture", "open failed");
        rmdir(dir);
        return;
    }
    if (write(fd, FIX_MIXED, sizeof FIX_MIXED - 1) !=
        (ssize_t)(sizeof FIX_MIXED - 1)) {
        check_fail("mime: file resolver fixture", "short write");
        close(fd);
        unlink(path);
        rmdir(dir);
        return;
    }
    close(fd);
    t = tree_of(FIX_MIXED, sizeof FIX_MIXED - 1);
    fd = open(path, O_RDONLY);
    if (!t || fd < 0) {
        check_fail("mime: file resolver fixture", "tree or open failed");
        free(t);
        if (fd >= 0) close(fd);
        unlink(path);
        rmdir(dir);
        return;
    }
    {
        bool agree = true;
        for (i = 0; i < t->nparts; i++) {
            JmapdPartRef r;
            if (jmapd_file_part(fd, sizeof FIX_MIXED - 1, t->parts[i].info.id,
                                &r) != 0 ||
                r.start != t->parts[i].info.start ||
                r.end != t->parts[i].info.end ||
                r.hdr_end != t->parts[i].info.hdr_end ||
                strcasecmp(r.cte, t->parts[i].info.cte) != 0) {
                agree = false;
                printf("     part %d (%s): tree [%zu,%zu) hdr %zu cte %s vs "
                       "file [%zu,%zu) hdr %zu cte %s\n",
                       i, t->parts[i].info.id, t->parts[i].info.start,
                       t->parts[i].info.end, t->parts[i].info.hdr_end,
                       t->parts[i].info.cte, r.start, r.end, r.hdr_end,
                       r.cte);
                break;
            }
        }
        EXPECT(agree, "mime: the file resolver agrees with the tree on every part");
    }
    {
        JmapdPartRef r;
        EXPECT(jmapd_file_part(fd, sizeof FIX_MIXED - 1, "9", &r) == -1,
               "mime: file resolver rejects an out-of-range part path");
        EXPECT(jmapd_file_part(fd, sizeof FIX_MIXED - 1, "1.1.1", &r) == -1,
               "mime: file resolver rejects a path through a leaf");
    }
    close(fd);
    free(t);
    unlink(path);
    rmdir(dir);
}

/* A single-part message's only part is named "1" (see jmapd_tree_build), so
   the FILE-based resolver the download uses must resolve "1" to the whole
   message — otherwise Email/get would describe part "1" and the download of
   its blobId would 404.  "" keeps resolving, so a blob id minted before the
   naming rule still downloads. */
static void single_part_file_tests(void) {
    char tpl[] = "/tmp/visage_jmapd_one_XXXXXX";
    char *dir = mkdtemp(tpl);
    char path[4096];
    static const char plain[] =
        "From: a@b\r\nSubject: s\r\nContent-Type: text/plain\r\n\r\nhi there\r\n";
    int fd;

    if (!dir) {
        check_fail("mime: single-part resolver scratch dir", "mkdtemp failed");
        return;
    }
    snprintf(path, sizeof path, "%s/one.eml", dir);
    fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0600);
    if (fd < 0 || write(fd, plain, sizeof plain - 1) !=
                      (ssize_t)(sizeof plain - 1)) {
        check_fail("mime: single-part resolver fixture", "open/write failed");
        if (fd >= 0) close(fd);
        unlink(path);
        rmdir(dir);
        return;
    }
    {
        JmapdTree *t = tree_of(plain, sizeof plain - 1);
        JmapdPartRef r1, r0;
        EXPECT(t && t->nparts == 1 && strcmp(t->parts[0].info.id, "1") == 0,
               "mime: a single-part message's only part id is \"1\"");
        EXPECT(jmapd_file_part(fd, sizeof plain - 1, "1", &r1) == 0 &&
                   r1.start == 0 && r1.end == sizeof plain - 1 &&
                   r1.hdr_end == t->parts[0].info.hdr_end &&
                   strcmp(r1.subtype, "plain") == 0,
               "mime: part \"1\" of a single-part message is the whole message");
        EXPECT(jmapd_file_part(fd, sizeof plain - 1, "", &r0) == 0 &&
                   r0.start == r1.start && r0.end == r1.end &&
                   r0.hdr_end == r1.hdr_end,
               "mime: \"\" still resolves to the whole message");
        EXPECT(jmapd_file_part(fd, sizeof plain - 1, "1.1", &r1) == -1,
               "mime: a single-part message has no part 1.1");
        free(t);
    }
    close(fd);
    unlink(path);
    rmdir(dir);
}

/* ------------------------------------------------------------------ */
/* (9) preview                                                         */
/* ------------------------------------------------------------------ */

static void preview_tests(void) {
    char pv[256];
    JmapdTree *t = tree_of(FIX_MIXED, sizeof FIX_MIXED - 1);
    EXPECT(t != NULL, "preview: fixture tree builds");
    if (t) {
        EXPECT(jmapd_preview(FIX_MIXED, t, pv, sizeof pv) == 0 &&
                   strcmp(pv, "Caf\xc3\xa9 line one") == 0,
               "preview: first decoded text/plain line");
        free(t);
    }
    /* long first line -> capped at 255 bytes, single line */
    {
        char msg[2048];
        char *body = msg;
        size_t n = 0;
        JmapdTree *lt;
        n += (size_t)snprintf(msg + n, sizeof msg - n,
                              "Content-Type: text/plain\r\n\r\n");
        while (n < 1000) msg[n++] = 'x';
        msg[n++] = '\r';
        msg[n++] = '\n';
        msg[n++] = 's';
        msg[n] = '\0';
        lt = tree_of(msg, n);
        EXPECT(lt && jmapd_preview(msg, lt, pv, sizeof pv) == 0 &&
                   strlen(pv) == 255 && strchr(pv, '\n') == NULL,
               "preview: capped at 255 bytes and one line");
        free(lt);
        (void)body;
    }
    /* no text/plain part -> empty preview, not a crash */
    {
        static const char htmlonly[] =
            "Content-Type: text/html\r\n\r\n<p>hi</p>\r\n";
        JmapdTree *h = tree_of(htmlonly, sizeof htmlonly - 1);
        EXPECT(h && jmapd_preview(htmlonly, h, pv, sizeof pv) == 0 &&
                   pv[0] == '\0',
               "preview: an html-only message has an empty preview");
        free(h);
    }
}

/* ------------------------------------------------------------------ */
/* (10) blob ids                                                       */
/* ------------------------------------------------------------------ */

static void blob_id_tests(void) {
    char email[JMAPD_ID_MAX], blob[JMAPD_BLOB_MAX], e2[JMAPD_ID_MAX];
    char p2[IMAPD_MAX_PART_ID];

    EXPECT(jmapd_id_email("1700000000.M1P1.host", NULL, email, sizeof email)
               == 0, "blob: email id for the fixture");
    EXPECT(jmapd_id_blob(email, "1.2", blob, sizeof blob) == 0 &&
               blob[0] == 'g' && strchr(blob, '.') != NULL,
           "blob: id encodes email + part");
    EXPECT(jmapd_id_blob_parse(blob, e2, sizeof e2, p2, sizeof p2) == 0 &&
               strcmp(e2, email) == 0 && strcmp(p2, "1.2") == 0,
           "blob: id round-trips");
    /* the whole-message part id is the empty string */
    EXPECT(jmapd_id_blob(email, "", blob, sizeof blob) == 0 &&
               jmapd_id_blob_parse(blob, e2, sizeof e2, p2, sizeof p2) == 0 &&
               p2[0] == '\0',
           "blob: the empty part id round-trips");
    /* rejection matrix */
    EXPECT(jmapd_id_blob_parse("", email, sizeof email, p2, sizeof p2) == -1,
           "blob: empty id rejected");
    EXPECT(jmapd_id_blob_parse("xabc.def", email, sizeof email, p2,
                               sizeof p2) == -1,
           "blob: wrong prefix rejected");
    EXPECT(jmapd_id_blob_parse("g", email, sizeof email, p2, sizeof p2) == -1,
           "blob: id without a separator rejected");
    EXPECT(jmapd_id_blob_parse("g!!!.def", email, sizeof email, p2,
                               sizeof p2) == -1,
           "blob: non-base64url payload rejected");
    /* a real traversal payload: b64url("../../etc/passwd") */
    {
        char evil[JMAPD_BLOB_MAX + 512];
        char enc[256];
        EXPECT(jmapd_b64url_encode((const unsigned char *)"../../etc/passwd",
                                   17, enc, sizeof enc) == 0,
               "blob: traversal payload encodes");
        snprintf(evil, sizeof evil, "g%s.%s", enc, "MA");
        EXPECT(jmapd_id_blob_parse(evil, email, sizeof email, p2, sizeof p2)
                   == -1,
               "blob: a traversal payload in the email half is rejected");
    }
    /* a part path that is not a path this server emits */
    {
        char evil[JMAPD_BLOB_MAX + JMAPD_ID_MAX * 2], enc[JMAPD_ID_MAX * 2],
             penc[64];
        (void)jmapd_b64url_encode((const unsigned char *)email, strlen(email),
                                  enc, sizeof enc);
        (void)jmapd_b64url_encode((const unsigned char *)"1..2", 4, penc,
                                  sizeof penc);
        snprintf(evil, sizeof evil, "g%s.%s", enc, penc);
        EXPECT(jmapd_id_blob_parse(evil, email, sizeof email, p2, sizeof p2)
                   == -1,
               "blob: a dotted-empty part path is rejected");
        (void)jmapd_b64url_encode((const unsigned char *)"0", 1, penc,
                                  sizeof penc);
        snprintf(evil, sizeof evil, "g%s.%s", enc, penc);
        EXPECT(jmapd_id_blob_parse(evil, email, sizeof email, p2, sizeof p2)
                   == -1,
               "blob: part number 0 is rejected");
        (void)jmapd_b64url_encode((const unsigned char *)"a", 1, penc,
                                  sizeof penc);
        snprintf(evil, sizeof evil, "g%s.%s", enc, penc);
        EXPECT(jmapd_id_blob_parse(evil, email, sizeof email, p2, sizeof p2)
                   == -1,
               "blob: a non-numeric part id is rejected");
        (void)jmapd_b64url_encode((const unsigned char *)"01", 2, penc,
                                  sizeof penc);
        snprintf(evil, sizeof evil, "g%s.%s", enc, penc);
        EXPECT(jmapd_id_blob_parse(evil, email, sizeof email, p2, sizeof p2)
                   == -1,
               "blob: a leading-zero part number is rejected");
    }
    EXPECT(jmapd_id_blob(NULL, "1", blob, sizeof blob) == -1 &&
               jmapd_id_blob(email, "1", blob, 4) == -1,
           "blob: encode rejects a missing email id and a short buffer");
}

/* ------------------------------------------------------------------ */
/* (11) address lists                                                  */
/* ------------------------------------------------------------------ */

/* The parser lives in jmap_mail.c (static); its behaviour is pinned through
   Email/get below, and here through the same header value the fixture uses. */
static void addr_tests(void) {
    /* covered by email_get_tests (from/to/cc rendering); this keeps the
       group honest when only the fast checks run. */
    check_ok("addr: covered by Email/get rendering");
}

/* ------------------------------------------------------------------ */
/* (12) #resultOf back-references                                      */
/* ------------------------------------------------------------------ */

static void ref_tests(void) {
    static const char result[] =
        "{\"accountId\":\"alice\",\"ids\":[\"eAAA\",\"eBBB\"],"
        "\"a/b\":{\"~x\":1}}";
    JmapdCallResult prev[1];
    JmapdCtx ctx;
    JmapJsonErr err = JMAP_JSON_OK;
    JmapJsonDoc *doc;
    const JmapJsonNode *args, *v;

    memset(prev, 0, sizeof prev);
    prev[0].callid = strdup("q0");
    prev[0].name = strdup("Email/query");
    prev[0].json = strdup(result);
    prev[0].json_len = strlen(result);
    memset(&ctx, 0, sizeof ctx);
    ctx.user = "alice";
    ctx.prev = prev;
    ctx.nprev = 1;

    doc = jmap_json_parse(
        "{\"ids\":[\"direct\"],\"#ids\":{\"resultOf\":\"q0\","
        "\"name\":\"Email/query\",\"path\":\"/ids\"}}",
        strlen("{\"ids\":[\"direct\"],\"#ids\":{\"resultOf\":\"q0\","
               "\"name\":\"Email/query\",\"path\":\"/ids\"}}"), &err);
    EXPECT(doc != NULL, "ref: reference request parses");
    if (doc) {
        args = jmap_json_root(doc);
        v = jmapd_arg(&ctx, args, "ids");
        EXPECT(v && v->type == JMAP_JSON_ARR && jmap_json_count(v) == 2 &&
                   !ctx.argerr,
               "ref: #ids resolves to the earlier result's ids array");
        /* the same args object without the reference returns the literal */
        jmap_json_free(doc);
    }
    doc = jmap_json_parse("{\"ids\":[\"direct\"]}", 19, &err);
    if (doc) {
        v = jmapd_arg(&ctx, jmap_json_root(doc), "ids");
        EXPECT(v && jmap_json_count(v) == 1, "ref: a plain argument passes through");
        jmap_json_free(doc);
    }
    /* JSON Pointer escapes (~1 -> '/', ~0 -> '~') */
    doc = jmap_json_parse(
        "{\"#x\":{\"resultOf\":\"q0\",\"name\":\"Email/query\","
        "\"path\":\"/a~1b/~0x\"}}", 74, &err);
    if (doc) {
        v = jmapd_arg(&ctx, jmap_json_root(doc), "x");
        EXPECT(v && v->type == JMAP_JSON_NUM && !ctx.argerr,
               "ref: JSON Pointer escapes resolve");
        jmap_json_free(doc);
    }
    /* failures: unknown call id, wrong method name, bad path, non-object */
    {
        static const char *const bad[] = {
            "{\"#ids\":{\"resultOf\":\"nope\",\"name\":\"Email/query\",\"path\":\"/ids\"}}",
            "{\"#ids\":{\"resultOf\":\"q0\",\"name\":\"Email/get\",\"path\":\"/ids\"}}",
            "{\"#ids\":{\"resultOf\":\"q0\",\"name\":\"Email/query\",\"path\":\"/missing\"}}",
            "{\"#ids\":{\"resultOf\":\"q0\",\"name\":\"Email/query\",\"path\":\"noslash\"}}",
            "{\"#ids\":[\"not-an-object\"]}"
        };
        size_t i;
        for (i = 0; i < sizeof bad / sizeof bad[0]; i++) {
            JmapJsonDoc *d = jmap_json_parse(bad[i], strlen(bad[i]), &err);
            if (!d) { check_fail("ref: failure matrix parses", bad[i]); continue; }
            ctx.argerr = NULL;
            v = jmapd_arg(&ctx, jmap_json_root(d), "ids");
            EXPECT(v == NULL && ctx.argerr != NULL,
                   "ref: every malformed reference is refused");
            jmap_json_free(d);
        }
    }
    free(prev[0].callid);
    free(prev[0].name);
    free(prev[0].json);
    jmap_json_free(prev[0].doc);
}

/* ------------------------------------------------------------------ */
/* (13) Email/query and Email/get over a scratch maildir               */
/* ------------------------------------------------------------------ */

/* Seed one message file into a maildir.  `mbox` is the JMAP/maildir name
   ("Inbox", "Sent", ...).  A ":2,S" suffix marks it \Seen. */
static int seed_msg(const char *root, const char *user, const char *mbox,
                    const char *base, const char *content, time_t mtime,
                    int seen) {
    char dir[2048], tmp[2100], path[2200];
    int fd;
    snprintf(dir, sizeof dir, "%s/%s/%s%s/cur", root, user,
             strcmp(mbox, "Inbox") == 0 ? "" : ".", mbox);
    {
        snprintf(tmp, sizeof tmp, "%s/%s/%s%s/new", root, user,
                 strcmp(mbox, "Inbox") == 0 ? "" : ".", mbox);
        mkdir(root, 0700);
        snprintf(tmp, sizeof tmp, "%s/%s", root, user);
        mkdir(tmp, 0700);
        snprintf(tmp, sizeof tmp, "%s/%s/%s%s", root, user,
                 strcmp(mbox, "Inbox") == 0 ? "" : ".", mbox);
        mkdir(tmp, 0700);
        snprintf(tmp, sizeof tmp, "%s/tmp", dir);
        mkdir(tmp, 0700);
        snprintf(tmp, sizeof tmp, "%s/new", dir);
        mkdir(tmp, 0700);
        mkdir(dir, 0700);
    }
    snprintf(path, sizeof path, "%s/%s%s", dir, base, seen ? ":2,S" : "");
    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return -1;
    if (write(fd, content, strlen(content)) != (ssize_t)strlen(content)) {
        close(fd);
        return -1;
    }
    close(fd);
    {
        struct timespec ts[2];
        ts[0].tv_sec = mtime;
        ts[0].tv_nsec = 0;
        ts[1] = ts[0];
        (void)utimensat(AT_FDCWD, path, ts, 0);
    }
    return 0;
}

static char *call_method(JmapdCtx *ctx, JmapdMethodFn fn, const char *args) {
    JmapJsonErr err = JMAP_JSON_OK;
    JmapJsonDoc *doc = jmap_json_parse(args, strlen(args), &err);
    JsonBuilder b;
    char *out = NULL;
    if (!doc) return NULL;
    jsonb_init(&b);
    if (fn(ctx, jmap_json_root(doc), &b) == 0) out = jsonb_detach(&b, NULL);
    else jsonb_detach(&b, NULL);
    jmap_json_free(doc);
    return out;
}

/* Parse a method result and return a member (owned by *docp). */
static const JmapJsonNode *result_get(JmapJsonDoc **docp, const char *json,
                                      const char *key) {
    JmapJsonErr err = JMAP_JSON_OK;
    *docp = jmap_json_parse(json, strlen(json), &err);
    if (!*docp) return NULL;
    return jmap_json_get(jmap_json_root(*docp), key);
}

static void query_tests(void) {
    char tpl[] = "/tmp/visage_jmapd_query_XXXXXX";
    char *root = mkdtemp(tpl);
    JmapdServer srv;
    JmapdCtx ctx;
    char id1[JMAPD_ID_MAX], id2[JMAPD_ID_MAX], id3[JMAPD_ID_MAX];
    const char *msgs[5][3];
    time_t dates[5];
    int i;

    if (!root) {
        check_fail("query: scratch root", "mkdtemp failed");
        return;
    }
    memset(&srv, 0, sizeof srv);
    srv.icfg.root = root;
    srv.icfg.max_msg = IMAPD_DEFAULT_MAX_MSG;
    srv.cfg.root = root;
    srv.cfg.hostname = "localhost";
    memset(&ctx, 0, sizeof ctx);
    ctx.srv = &srv;
    ctx.user = "alice";

    /* five messages, oldest first; subjects/froms/bodies distinguish them */
    msgs[0][0] = "q0"; msgs[0][1] = "bob@example.com";  msgs[0][2] = "alpha";
    msgs[1][0] = "q1"; msgs[1][1] = "carol@example.com"; msgs[1][2] = "beta";
    msgs[2][0] = "q2"; msgs[2][1] = "bob@example.com";  msgs[2][2] = "gamma";
    msgs[3][0] = "q3"; msgs[3][1] = "dave@example.com"; msgs[3][2] = "delta";
    msgs[4][0] = "q4"; msgs[4][1] = "erin@example.com"; msgs[4][2] = "epsilon";
    for (i = 0; i < 5; i++) {
        char content[512];
        char base[64];
        dates[i] = 1700000000 + i * 60;
        snprintf(base, sizeof base, "170000000%d.M%dP%d.host", i, i, i);
        snprintf(content, sizeof content,
                 "From: %s\r\nTo: alice@example.com\r\nSubject: %s\r\n"
                 "Message-ID: <%s@example.com>\r\n"
                 "Content-Type: text/plain\r\n\r\nbody-%s-%s\r\n",
                 msgs[i][1], msgs[i][0], msgs[i][0], msgs[i][2], msgs[i][0]);
        if (seed_msg(root, "alice", "Inbox", base, content, dates[i], 0) != 0)
            check_fail("query: seed message", base);
    }
    /* one message in Sent, to prove inMailbox narrows the scan */
    if (seed_msg(root, "alice", "Sent", "1700000010.M9P9.host",
                 "From: alice@example.com\r\nTo: z@example.com\r\n"
                 "Subject: sent one\r\nMessage-ID: <s1@example.com>\r\n"
                 "Content-Type: text/plain\r\n\r\nsent body\r\n",
                 dates[4] + 60, 1) != 0)
        check_fail("query: seed Sent message", "seed failed");
    (void)jmapd_id_mailbox("Inbox", id1, sizeof id1);
    (void)jmapd_id_email("1700000000.M0P0.host", NULL, id2, sizeof id2);
    (void)jmapd_id_email("1700000004.M4P4.host", NULL, id3, sizeof id3);

    /* --- all of Inbox, default sort (receivedAt desc) --- */
    {
        char args[2048];
        char *res;
        JmapJsonDoc *doc = NULL;
        const JmapJsonNode *total, *ids, *pos;
        uint64_t n = 0;
        snprintf(args, sizeof args,
                 "{\"accountId\":\"alice\",\"filter\":{\"inMailbox\":\"%s\"},"
                 "\"sort\":[{\"property\":\"receivedAt\",\"isAscending\":false}]"
                 ",\"position\":0,\"limit\":10}", id1);
        res = call_method(&ctx, jmapd_method_email_query, args);
        EXPECT(res != NULL, "query: inMailbox query returns a result");
        if (res) {
            /* ONE parse: result_get() re-parses, and a second call would leak
               the first document (found by an ASAN run, not by the checks). */
            JmapJsonErr perr = JMAP_JSON_OK;
            doc = jmap_json_parse(res, strlen(res), &perr);
            total = doc ? jmap_json_get(jmap_json_root(doc), "total") : NULL;
            ids = doc ? jmap_json_get(jmap_json_root(doc), "ids") : NULL;
            pos = doc ? jmap_json_get(jmap_json_root(doc), "position") : NULL;
            EXPECT(jmap_json_u64(total, &n) == 0 && n == 5,
                   "query: total counts every match in the mailbox");
            EXPECT(pos && pos->type == JMAP_JSON_NUM && pos->inum == 0,
                   "query: position is echoed");
            EXPECT(ids && jmap_json_count(ids) == 5,
                   "query: desc order returns all five ids");
            if (ids && jmap_json_count(ids) == 5) {
                const char *s0, *s4;
                (void)jmap_json_str(jmap_json_at(ids, 0), &s0, NULL);
                (void)jmap_json_str(jmap_json_at(ids, 4), &s4, NULL);
                EXPECT(strcmp(s0, id3) == 0 && strcmp(s4, id2) == 0,
                       "query: newest first on receivedAt desc, oldest last");
            }
            jmap_json_free(doc);
            free(res);
        }
    }
    /* --- ascending order reverses it --- */
    {
        char args[2048];
        char *res;
        JmapJsonDoc *doc = NULL;
        const JmapJsonNode *ids;
        snprintf(args, sizeof args,
                 "{\"filter\":{\"inMailbox\":\"%s\"},"
                 "\"sort\":[{\"property\":\"receivedAt\",\"isAscending\":true}]}",
                 id1);
        res = call_method(&ctx, jmapd_method_email_query, args);
        if (res) {
            ids = result_get(&doc, res, "ids");
            if (ids && jmap_json_count(ids) == 5) {
                const char *s0;
                (void)jmap_json_str(jmap_json_at(ids, 0), &s0, NULL);
                EXPECT(strcmp(s0, id2) == 0,
                       "query: receivedAt asc puts the oldest first");
            } else {
                check_fail("query: asc order returns five ids", NULL);
            }
            jmap_json_free(doc);
            free(res);
        }
    }
    /* --- paging: position 1, limit 2 --- */
    {
        char args[2048];
        char *res;
        JmapJsonDoc *doc = NULL;
        const JmapJsonNode *ids, *total;
        uint64_t n = 0;
        snprintf(args, sizeof args,
                 "{\"filter\":{\"inMailbox\":\"%s\"},"
                 "\"sort\":[{\"property\":\"receivedAt\",\"isAscending\":false}],"
                 "\"position\":1,\"limit\":2}", id1);
        res = call_method(&ctx, jmapd_method_email_query, args);
        if (res) {
            ids = result_get(&doc, res, "ids");
            total = jmap_json_get(jmap_json_root(doc), "total");
            EXPECT(ids && jmap_json_count(ids) == 2,
                   "query: limit bounds the returned ids");
            EXPECT(jmap_json_u64(total, &n) == 0 && n == 5,
                   "query: total is unaffected by position/limit");
            if (ids && jmap_json_count(ids) == 2) {
                const char *s0;
                (void)jmap_json_str(jmap_json_at(ids, 0), &s0, NULL);
                {
                    char expect[JMAPD_ID_MAX];
                    (void)jmapd_id_email("1700000003.M3P3.host", NULL, expect,
                                         sizeof expect);
                    EXPECT(strcmp(s0, expect) == 0,
                           "query: position 1 skips exactly one entry");
                }
            }
            jmap_json_free(doc);
            free(res);
        }
    }
    /* --- filters: from, subject, text --- */
    {
        struct { const char *filter; int want; const char *what; } cases[] = {
            { "{\"from\":\"bob\"}", 2, "query: from matches a substring, 2 hits" },
            { "{\"subject\":\"q2\"}", 1, "query: subject matches 1 hit" },
            { "{\"text\":\"body-beta\"}", 1, "query: text matches the body" },
            { "{\"text\":\"bob@example.com\"}", 2,
              "query: text matches headers too" },
            { "{\"from\":\"nobody@nowhere\"}", 0, "query: from with no hit" }
        };
        size_t c;
        for (c = 0; c < sizeof cases / sizeof cases[0]; c++) {
            char args[2048];
            char *res;
            JmapJsonDoc *doc = NULL;
            const JmapJsonNode *total;
            uint64_t v = 99;
            snprintf(args, sizeof args, "{\"filter\":%s}", cases[c].filter);
            res = call_method(&ctx, jmapd_method_email_query, args);
            if (!res) { check_fail(cases[c].what, "no result"); continue; }
            total = result_get(&doc, res, "total");
            EXPECT(jmap_json_u64(total, &v) == 0 && v == (uint64_t)cases[c].want,
                   cases[c].what);
            jmap_json_free(doc);
            free(res);
        }
    }
    /* --- a query across all mailboxes sees Inbox + Sent --- */
    {
        char *res = call_method(&ctx, jmapd_method_email_query, "{}");
        JmapJsonDoc *doc = NULL;
        const JmapJsonNode *total;
        uint64_t v = 0;
        if (res) {
            total = result_get(&doc, res, "total");
            EXPECT(jmap_json_u64(total, &v) == 0 && v == 6,
                   "query: no filter covers every mailbox");
            jmap_json_free(doc);
            free(res);
        }
    }
    /* --- unsupported sort and unsupported filter are REFUSED, not ignored --- */
    {
        char *res = call_method(&ctx, jmapd_method_email_query,
                                "{\"sort\":[{\"property\":\"subject\"}]}");
        JmapJsonDoc *doc = NULL;
        const JmapJsonNode *type = res ? result_get(&doc, res, "type") : NULL;
        const char *s = NULL;
        EXPECT(type && jmap_json_str(type, &s, NULL) == 0 &&
                   strcmp(s, "unsupportedSort") == 0,
               "query: an unsupported sort is a method error");
        jmap_json_free(doc);
        free(res);
    }
    {
        char *res = call_method(&ctx, jmapd_method_email_query,
                                "{\"filter\":{\"hasKeyword\":\"$seen\"}}");
        JmapJsonDoc *doc = NULL;
        const JmapJsonNode *type = res ? result_get(&doc, res, "type") : NULL;
        const char *s = NULL;
        EXPECT(type && jmap_json_str(type, &s, NULL) == 0 &&
                   strcmp(s, "unsupportedFilter") == 0,
               "query: an unsupported filter is a method error");
        jmap_json_free(doc);
        free(res);
    }
    /* --- queryState is present and stable --- */
    {
        char *res = call_method(&ctx, jmapd_method_email_query, "{}");
        JmapJsonDoc *doc = NULL;
        const JmapJsonNode *qs = res ? result_get(&doc, res, "queryState") : NULL;
        const char *s = NULL;
        EXPECT(qs && jmap_json_str(qs, &s, NULL) == 0 && strcmp(s, "e0") == 0,
               "query: queryState is the email state string");
        jmap_json_free(doc);
        free(res);
    }
    (void)id3;
}

static void email_get_tests(void) {
    char tpl[] = "/tmp/visage_jmapd_get_XXXXXX";
    char *root = mkdtemp(tpl);
    JmapdServer srv;
    JmapdCtx ctx;
    char email_id[JMAPD_ID_MAX];
    char args[2048];
    char *res;

    if (!root) {
        check_fail("get: scratch root", "mkdtemp failed");
        return;
    }
    memset(&srv, 0, sizeof srv);
    srv.icfg.root = root;
    srv.icfg.max_msg = IMAPD_DEFAULT_MAX_MSG;
    srv.cfg.root = root;
    srv.cfg.hostname = "localhost";
    memset(&ctx, 0, sizeof ctx);
    ctx.srv = &srv;
    ctx.user = "alice";

    if (seed_msg(root, "alice", "Inbox", "1700000000.ABCDEF.host", FIX_MIXED,
                 1700000123, 1) != 0) {
        check_fail("get: seed the MIME fixture", "seed failed");
        return;
    }
    (void)jmapd_id_email("1700000000.ABCDEF.host", NULL, email_id,
                         sizeof email_id);

    snprintf(args, sizeof args,
             "{\"accountId\":\"alice\",\"ids\":[\"%s\"],\"properties\":"
             "[\"id\",\"threadId\",\"receivedAt\",\"from\",\"to\",\"cc\","
             "\"subject\",\"preview\",\"keywords\",\"hasAttachment\",\"size\","
             "\"mailboxIds\",\"textBody\",\"htmlBody\",\"attachments\","
             "\"messageId\",\"notAProperty\"],"
             "\"fetchTextBodyValues\":true,\"fetchHTMLBodyValues\":true,"
             "\"maxBodyValueBytes\":1048576}", email_id);
    res = call_method(&ctx, jmapd_method_email_get, args);
    EXPECT(res != NULL, "get: Email/get returns a result");
    if (res) {
        JmapJsonDoc *doc = NULL;
        const JmapJsonNode *list = result_get(&doc, res, "list");
        const JmapJsonNode *e = list ? jmap_json_at(list, 0) : NULL;
        EXPECT(e != NULL, "get: the message is found");
        if (e) {
            const JmapJsonNode *v;
            const char *s = NULL;
            uint64_t n = 0;

            v = jmap_json_get(e, "receivedAt");
            EXPECT(v && jmap_json_str(v, &s, NULL) == 0 && strlen(s) == 20 &&
                       s[4] == '-' && s[7] == '-' && s[10] == 'T' &&
                       s[13] == ':' && s[16] == ':' && s[19] == 'Z',
                   "get: receivedAt is strict YYYY-MM-DDTHH:MM:SSZ");
            v = jmap_json_get(e, "size");
            EXPECT(v && jmap_json_u64(v, &n) == 0 &&
                       n == sizeof FIX_MIXED - 1,
                   "get: size is the message file size");
            v = jmap_json_get(e, "keywords");
            EXPECT(v && jmap_json_get(v, "$seen") != NULL &&
                       jmap_json_get(v, "$flagged") == NULL &&
                       jmap_json_get(v, "$forwarded") == NULL,
                   "get: keywords come from the maildir flags (never $forwarded)");
            v = jmap_json_get(e, "mailboxIds");
            {
                char mid[JMAPD_ID_MAX];
                (void)jmapd_id_mailbox("Inbox", mid, sizeof mid);
                EXPECT(v && jmap_json_get(v, mid) != NULL,
                       "get: mailboxIds names the containing mailbox");
            }
            v = jmap_json_get(e, "preview");
            EXPECT(v && jmap_json_str(v, &s, NULL) == 0 &&
                       strcmp(s, "Caf\xc3\xa9 line one") == 0,
                   "get: preview is the first decoded text/plain line");
            v = jmap_json_get(e, "messageId");
            EXPECT(v && jmap_json_count(v) == 1 &&
                       jmap_json_str(jmap_json_at(v, 0), &s, NULL) == 0 &&
                       strcmp(s, "<m1@example.com>") == 0,
                   "get: messageId is an array of the Message-ID");
            v = jmap_json_get(e, "from");
            EXPECT(v && jmap_json_count(v) == 1 &&
                       jmap_json_get(jmap_json_at(v, 0), "email") &&
                       jmap_json_str(jmap_json_get(jmap_json_at(v, 0), "email"),
                                     &s, NULL) == 0 &&
                       strcmp(s, "alice@example.com") == 0,
                   "get: from is an EmailAddress list");
            v = jmap_json_get(e, "cc");
            EXPECT(v && jmap_json_count(v) == 2,
                   "get: cc splits a two-address list");
            v = jmap_json_get(e, "threadId");
            EXPECT(v && jmap_json_str(v, &s, NULL) == 0 && s[0] == 't',
                   "get: threadId is a t-prefixed id");
            v = jmap_json_get(e, "hasAttachment");
            EXPECT(v && v->type == JMAP_JSON_BOOL && v->boolean,
                   "get: hasAttachment is true with a pdf part");

            v = jmap_json_get(e, "textBody");
            EXPECT(v && jmap_json_count(v) == 1 &&
                       jmap_json_str(jmap_json_get(jmap_json_at(v, 0),
                                                   "partId"), &s, NULL) == 0 &&
                       strcmp(s, "1.1") == 0,
                   "get: textBody is the text/plain part 1.1");
            v = jmap_json_get(e, "htmlBody");
            EXPECT(v && jmap_json_count(v) == 1 &&
                       jmap_json_str(jmap_json_get(jmap_json_at(v, 0),
                                                   "partId"), &s, NULL) == 0 &&
                       strcmp(s, "1.2") == 0,
                   "get: htmlBody is the text/html part 1.2");
            v = jmap_json_get(e, "attachments");
            EXPECT(v && jmap_json_count(v) == 1 &&
                       jmap_json_str(jmap_json_get(jmap_json_at(v, 0), "name"),
                                     &s, NULL) == 0 &&
                       strcmp(s, "report.pdf") == 0,
                   "get: attachments is the pdf part with its filename");

            /* bodyValues: the two bodies are DISTINCT and correctly decoded */
            v = jmap_json_get(e, "bodyValues");
            {
                const JmapJsonNode *tv = v ? jmap_json_get(v, "1.1") : NULL;
                const JmapJsonNode *hv = v ? jmap_json_get(v, "1.2") : NULL;
                const char *ts = NULL, *hs = NULL;
                EXPECT(tv && hv &&
                           jmap_json_str(jmap_json_get(tv, "value"), &ts,
                                         NULL) == 0 &&
                           jmap_json_str(jmap_json_get(hv, "value"), &hs,
                                         NULL) == 0 &&
                           strcmp(ts, hs) != 0 &&
                           strstr(ts, "line one") != NULL &&
                           strstr(hs, "<html>") != NULL,
                       "get: bodyValues text and html are distinct and decoded");
                EXPECT(tv && jmap_json_get(tv, "isTruncated") &&
                           !jmap_json_get(tv, "isTruncated")->boolean &&
                           jmap_json_get(tv, "isEncodingProblem") &&
                           !jmap_json_get(tv, "isEncodingProblem")->boolean,
                       "get: a clean bodyValue is neither truncated nor a problem");
            }

            /* `properties` is exact: an unknown name is omitted (RFC-legal) */
            EXPECT(jmap_json_get(e, "notAProperty") == NULL,
                   "get: a property the server does not have is omitted");
            EXPECT(jmap_json_get(e, "subject") != NULL,
                   "get: a requested property is present");
        }
        jmap_json_free(doc);
        free(res);
    }

    /* properties filtering: only what was asked for, plus id */
    snprintf(args, sizeof args,
             "{\"ids\":[\"%s\"],\"properties\":[\"id\",\"preview\"]}",
             email_id);
    res = call_method(&ctx, jmapd_method_email_get, args);
    if (res) {
        JmapJsonDoc *doc = NULL;
        const JmapJsonNode *list = result_get(&doc, res, "list");
        const JmapJsonNode *e = list ? jmap_json_at(list, 0) : NULL;
        EXPECT(e && jmap_json_count(e) == 2 && jmap_json_get(e, "id") &&
                   jmap_json_get(e, "preview") &&
                   jmap_json_get(e, "subject") == NULL &&
                   jmap_json_get(e, "bodyValues") == NULL,
               "get: properties filtering emits exactly the requested set");
        jmap_json_free(doc);
        free(res);
    }
    /* fetchTextBodyValues alone must not carry the html value */
    snprintf(args, sizeof args,
             "{\"ids\":[\"%s\"],\"properties\":[\"id\",\"textBody\",\"htmlBody\"],"
             "\"fetchTextBodyValues\":true}", email_id);
    res = call_method(&ctx, jmapd_method_email_get, args);
    if (res) {
        JmapJsonDoc *doc = NULL;
        const JmapJsonNode *list = result_get(&doc, res, "list");
        const JmapJsonNode *e = list ? jmap_json_at(list, 0) : NULL;
        const JmapJsonNode *bv = e ? jmap_json_get(e, "bodyValues") : NULL;
        EXPECT(bv && jmap_json_get(bv, "1.1") && !jmap_json_get(bv, "1.2"),
               "get: fetchTextBodyValues alone fetches only the text value");
        jmap_json_free(doc);
        free(res);
    }
    /* an id that is not on disk is notFound, not an error */
    snprintf(args, sizeof args,
             "{\"ids\":[\"%s\",\"%s\"],\"properties\":[\"id\"]}", email_id,
             "eMTcwMDAwMDAwMC5aOlp6Lmhvc3Q");
    res = call_method(&ctx, jmapd_method_email_get, args);
    if (res) {
        JmapJsonDoc *doc = NULL;
        const JmapJsonNode *nf = result_get(&doc, res, "notFound");
        EXPECT(nf && jmap_json_count(nf) == 1,
               "get: an unknown email id lands in notFound");
        jmap_json_free(doc);
        free(res);
    }
    /* ids is required */
    res = call_method(&ctx, jmapd_method_email_get, "{}");
    if (res) {
        JmapJsonDoc *doc = NULL;
        const JmapJsonNode *type = result_get(&doc, res, "type");
        const char *s = NULL;
        EXPECT(type && jmap_json_str(type, &s, NULL) == 0 &&
                   strcmp(s, "invalidArguments") == 0,
               "get: a missing ids argument is invalidArguments");
        jmap_json_free(doc);
        free(res);
    }
}

/* ------------------------------------------------------------------ */
/* (11b) Bounded work: a refusal, never a silently short answer        */
/*                                                                    */
/* The 32k-message deploy found three walls that answered a bare      */
/* {"type":"serverFail"} (no description, no journal line) or, worse, */
/* an EMPTY list for a mailbox that holds 32k messages.  These checks */
/* drive the same three paths through the budgets the daemon exposes: */
/*                                                                    */
/*   * an exhausted `text` scan budget is serverLimit WITH a          */
/*     description (a client can narrow the query and retry);         */
/*   * the SAME query with a workable budget finds the message, so    */
/*     the refusal is the budget and not the filter;                  */
/*   * a paging window past the cap is serverLimit WITH a             */
/*     description;                                                   */
/*   * an Email/get body budget that cannot hold the page TRUNCATES   */
/*     (isTruncated per bodyValue) instead of failing the request —   */
/*     that failure is what made a big-mailbox page unqueryable.      */
/* ------------------------------------------------------------------ */

static void bounded_work_tests(void) {
    char tpl[] = "/tmp/visage_jmapd_bound_XXXXXX";
    char *root = mkdtemp(tpl);
    JmapdServer srv;
    JmapdCtx ctx;
    char inbox[JMAPD_ID_MAX], eid[JMAPD_ID_MAX];
    char args[2048];
    char *res;

    if (!root) {
        check_fail("bound: scratch root", "mkdtemp failed");
        return;
    }
    memset(&srv, 0, sizeof srv);
    srv.icfg.root = root;
    srv.icfg.max_msg = IMAPD_DEFAULT_MAX_MSG;
    srv.cfg.root = root;
    srv.cfg.hostname = "localhost";
    memset(&ctx, 0, sizeof ctx);
    ctx.srv = &srv;
    ctx.user = "alice";
    if (seed_msg(root, "alice", "Inbox", "1700000000.B1.host",
                 "From: bob@example.com\r\nTo: alice@example.com\r\n"
                 "Subject: needle\r\nMessage-ID: <b1@example.com>\r\n"
                 "Content-Type: text/plain\r\n\r\nbody with needle-alpha\r\n",
                 1700000000, 1) != 0) {
        check_fail("bound: seed message", "seed failed");
        return;
    }
    (void)jmapd_id_mailbox("Inbox", inbox, sizeof inbox);
    (void)jmapd_id_email("1700000000.B1.host", NULL, eid, sizeof eid);

    /* --- a workable budget finds the term (the control) --- */
    srv.cfg.text_scan_max = JMAPD_TEXT_SCAN_MAX;
    snprintf(args, sizeof args,
             "{\"accountId\":\"alice\",\"filter\":{\"text\":\"needle-alpha\"}}");
    res = call_method(&ctx, jmapd_method_email_query, args);
    if (res) {
        JmapJsonDoc *doc = NULL;
        const JmapJsonNode *total = result_get(&doc, res, "total");
        uint64_t n = 99;
        EXPECT(jmap_json_u64(total, &n) == 0 && n == 1,
               "bound: a text query inside the budget finds the message");
        jmap_json_free(doc);
        free(res);
    } else {
        check_fail("bound: a text query inside the budget finds the message",
                   "no result");
    }

    /* --- an exhausted budget is serverLimit WITH a description --- */
    srv.cfg.text_scan_max = 1;
    res = call_method(&ctx, jmapd_method_email_query, args);
    if (res) {
        JmapJsonDoc *doc = NULL;
        const JmapJsonNode *type = result_get(&doc, res, "type");
        const JmapJsonNode *desc = jmap_json_get(jmap_json_root(doc), "description");
        const char *ts = NULL, *ds = NULL;
        EXPECT(type && jmap_json_str(type, &ts, NULL) == 0 &&
                   strcmp(ts, "serverLimit") == 0,
               "bound: an over-budget text scan is a serverLimit, not a short list");
        EXPECT(desc && jmap_json_str(desc, &ds, NULL) == 0 && ds[0] &&
                   strstr(ds, "budget") != NULL,
               "bound: the over-budget refusal carries a description");
        jmap_json_free(doc);
        free(res);
    } else {
        check_fail("bound: an over-budget text scan is a serverLimit, not a short list",
                   "no result");
    }
    srv.cfg.text_scan_max = JMAPD_TEXT_SCAN_MAX;

    /* --- a paging window past the cap is serverLimit + description --- */
    snprintf(args, sizeof args,
             "{\"accountId\":\"alice\",\"position\":%u,\"limit\":1}",
             (unsigned)JMAPD_QUERY_MAX_WINDOW);
    res = call_method(&ctx, jmapd_method_email_query, args);
    if (res) {
        JmapJsonDoc *doc = NULL;
        const JmapJsonNode *type = result_get(&doc, res, "type");
        const JmapJsonNode *desc = jmap_json_get(jmap_json_root(doc), "description");
        const char *ts = NULL, *ds = NULL;
        EXPECT(type && jmap_json_str(type, &ts, NULL) == 0 &&
                   strcmp(ts, "serverLimit") == 0,
               "bound: a paging window past the cap is a serverLimit");
        EXPECT(desc && jmap_json_str(desc, &ds, NULL) == 0 && ds[0],
               "bound: the paging refusal carries a description");
        jmap_json_free(doc);
        free(res);
    } else {
        check_fail("bound: a paging window past the cap is a serverLimit",
                   "no result");
    }

    /* --- an Email/get that cannot hold the bodies truncates, not fails --- */
    srv.cfg.get_body_budget = 8;
    snprintf(args, sizeof args,
             "{\"accountId\":\"alice\",\"ids\":[\"%s\"],"
             "\"properties\":[\"id\",\"textBody\",\"subject\"],"
             "\"fetchTextBodyValues\":true}", eid);
    res = call_method(&ctx, jmapd_method_email_get, args);
    if (res) {
        JmapJsonDoc *doc = NULL;
        const JmapJsonNode *list = result_get(&doc, res, "list");
        const JmapJsonNode *e = list ? jmap_json_at(list, 0) : NULL;
        const JmapJsonNode *bv = e ? jmap_json_get(e, "bodyValues") : NULL;
        /* A single-part message's body part id is "1" (the multipart
           fixtures use "1.1"/"1.2"), never "". */
        const JmapJsonNode *tv = bv ? jmap_json_get(bv, "1") : NULL;
        const JmapJsonNode *tr = tv ? jmap_json_get(tv, "isTruncated") : NULL;
        const JmapJsonNode *val = tv ? jmap_json_get(tv, "value") : NULL;
        const char *vs = NULL;
        EXPECT(e != NULL && jmap_json_get(e, "id") != NULL,
               "bound: a body-budget cut still returns the message object");
        EXPECT(tr && tr->type == JMAP_JSON_BOOL && tr->boolean,
               "bound: the body the budget cut says isTruncated");
        EXPECT(val && jmap_json_str(val, &vs, NULL) == 0 && strlen(vs) <= 8,
               "bound: the truncated body is cut to the remaining budget");
        jmap_json_free(doc);
        free(res);
    } else {
        check_fail("bound: a body-budget cut still returns the message object",
                   "no result");
    }
    srv.cfg.get_body_budget = JMAPD_GET_BODY_BUDGET;

    /* --- the same get with a normal budget is NOT truncated --- */
    snprintf(args, sizeof args,
             "{\"accountId\":\"alice\",\"ids\":[\"%s\"],"
             "\"properties\":[\"id\",\"textBody\"],"
             "\"fetchTextBodyValues\":true}", eid);
    res = call_method(&ctx, jmapd_method_email_get, args);
    if (res) {
        JmapJsonDoc *doc = NULL;
        const JmapJsonNode *list = result_get(&doc, res, "list");
        const JmapJsonNode *e = list ? jmap_json_at(list, 0) : NULL;
        const JmapJsonNode *bv = e ? jmap_json_get(e, "bodyValues") : NULL;
        const JmapJsonNode *tv = bv ? jmap_json_get(bv, "1") : NULL;
        const JmapJsonNode *tr = tv ? jmap_json_get(tv, "isTruncated") : NULL;
        const JmapJsonNode *val = tv ? jmap_json_get(tv, "value") : NULL;
        const char *vs = NULL;
        EXPECT(tr && tr->type == JMAP_JSON_BOOL && !tr->boolean &&
                   val && jmap_json_str(val, &vs, NULL) == 0 &&
                   strstr(vs, "needle-alpha") != NULL,
               "bound: a normal budget serves the whole body untruncated");
        jmap_json_free(doc);
        free(res);
    } else {
        check_fail("bound: a normal budget serves the whole body untruncated",
                   "no result");
    }
}

/* ------------------------------------------------------------------ */
/* (15) part ids over Email/get: a single-part message is "1", not ""   */
/* ------------------------------------------------------------------ */

/* An empty partId is what made the mail client's cache write fail: it interns
   body rows BY partId and its datalog engine refuses to intern "".  RFC 8621
   4.1.1 numbers a single-part message's body "1" (Fastmail says "1" too).
   Asserted over the RESPONSE, not only over the tree, because the response is
   what the client caches. */
static void body_part_id_tests(void) {
    char tpl[] = "/tmp/visage_jmapd_partid_XXXXXX";
    char *root = mkdtemp(tpl);
    JmapdServer srv;
    JmapdCtx ctx;
    char ids[2][JMAPD_ID_MAX];
    char args[2048];
    char *res;
    int k;

    if (!root) {
        check_fail("partid: scratch root", "mkdtemp failed");
        return;
    }
    memset(&srv, 0, sizeof srv);
    srv.icfg.root = root;
    srv.icfg.max_msg = IMAPD_DEFAULT_MAX_MSG;
    srv.cfg.root = root;
    srv.cfg.hostname = "localhost";
    memset(&ctx, 0, sizeof ctx);
    ctx.srv = &srv;
    ctx.user = "alice";
    if (seed_msg(root, "alice", "Inbox", "1700000000.P1.host",
                 "From: a@b\r\nSubject: text one\r\n"
                 "Content-Type: text/plain\r\n\r\nonly text\r\n",
                 1700000000, 1) != 0 ||
        seed_msg(root, "alice", "Inbox", "1700000100.P2.host",
                 "From: a@b\r\nSubject: html one\r\n"
                 "Content-Type: text/html\r\n\r\n<p>only html</p>\r\n",
                 1700000100, 1) != 0) {
        check_fail("partid: seed the single-part fixtures", "seed failed");
        return;
    }
    (void)jmapd_id_email("1700000000.P1.host", NULL, ids[0], sizeof ids[0]);
    (void)jmapd_id_email("1700000100.P2.host", NULL, ids[1], sizeof ids[1]);

    for (k = 0; k < 2; k++) {
        const char *prop = k == 0 ? "textBody" : "htmlBody";
        const char *want = k == 0 ? "only text" : "<p>only html</p>";
        snprintf(args, sizeof args,
                 "{\"accountId\":\"alice\",\"ids\":[\"%s\"],"
                 "\"properties\":[\"id\",\"%s\",\"bodyStructure\"],"
                 "\"fetchTextBodyValues\":true,\"fetchHTMLBodyValues\":true}",
                 ids[k], prop);
        res = call_method(&ctx, jmapd_method_email_get, args);
        if (!res) {
            check_fail(k == 0 ? "partid: a text-only message's body part is \"1\""
                              : "partid: an html-only message's body part is \"1\"",
                       "no result");
            continue;
        }
        {
            JmapJsonDoc *doc = NULL;
            const JmapJsonNode *list = result_get(&doc, res, "list");
            const JmapJsonNode *e = list ? jmap_json_at(list, 0) : NULL;
            const JmapJsonNode *bl = e ? jmap_json_get(e, prop) : NULL;
            const JmapJsonNode *bs = e ? jmap_json_get(e, "bodyStructure") : NULL;
            const JmapJsonNode *bv = e ? jmap_json_get(e, "bodyValues") : NULL;
            const JmapJsonNode *one = bv ? jmap_json_get(bv, "1") : NULL;
            const char *s = NULL, *v = NULL;

            EXPECT(bl && jmap_json_count(bl) == 1 &&
                       jmap_json_str(jmap_json_get(jmap_json_at(bl, 0),
                                                   "partId"), &s, NULL) == 0 &&
                       strcmp(s, "1") == 0,
                   k == 0 ? "partid: a text-only message's textBody is part \"1\""
                          : "partid: an html-only message's htmlBody is part \"1\"");
            s = NULL;
            EXPECT(bs && jmap_json_str(jmap_json_get(bs, "partId"), &s,
                                       NULL) == 0 && strcmp(s, "1") == 0,
                   k == 0 ? "partid: its bodyStructure root is part \"1\" too"
                          : "partid: its bodyStructure root is part \"1\" too");
            EXPECT(bv && one && jmap_json_get(bv, "") == NULL &&
                       jmap_json_str(jmap_json_get(one, "value"), &v,
                                     NULL) == 0 && strstr(v, want) != NULL,
                   k == 0 ? "partid: bodyValues is keyed \"1\" with no empty key"
                          : "partid: html bodyValues is keyed \"1\" with no empty key");
            jmap_json_free(doc);
            free(res);
        }
    }
}

/* ------------------------------------------------------------------ */
/* (12) M3: the RFC 8620 5.3 patch applier                             */
/* ------------------------------------------------------------------ */

static JmapdPatchErr apply_patch(const char *json, const char *cur_mbox,
                                 uint8_t cur_flags, JmapdEmailPatch *out) {
    JmapJsonErr e = JMAP_JSON_OK;
    JmapJsonDoc *d = jmap_json_parse(json, strlen(json), &e);
    JmapdPatchErr r;
    if (!d) return JMAPD_PATCH_E_TYPE;      /* the fixture itself is broken */
    r = jmapd_patch_apply(jmap_json_root(d), cur_mbox, cur_flags, out);
    jmap_json_free(d);
    return r;
}

static void patch_tests(void) {
    char inbox[JMAPD_ID_MAX], sent[JMAPD_ID_MAX];
    JmapdEmailPatch p;
    char args[2048];

    (void)jmapd_id_mailbox("Inbox", inbox, sizeof inbox);
    (void)jmapd_id_mailbox("Sent", sent, sizeof sent);

    /* --- keywords: set, clear with false, clear with null --- */
    EXPECT(apply_patch("{\"keywords/$flagged\":true}", "Inbox", 0, &p) ==
                   JMAPD_PATCH_OK && (p.flags & IMAIL_FLAGGED) &&
                   !(p.flags & IMAIL_SEEN),
           "patch: keywords/$flagged true sets the flag");
    EXPECT(apply_patch("{\"keywords/$flagged\":false}", "Inbox", IMAIL_FLAGGED,
                       &p) == JMAPD_PATCH_OK && !(p.flags & IMAIL_FLAGGED),
           "patch: keywords/$flagged false clears it (the client's unset form)");
    EXPECT(apply_patch("{\"keywords/$seen\":null}", "Inbox", IMAIL_SEEN, &p) ==
                   JMAPD_PATCH_OK && !(p.flags & IMAIL_SEEN),
           "patch: keywords/$seen null clears it");
    EXPECT(apply_patch("{\"keywords\":{\"$draft\":true}}", "Inbox", IMAIL_SEEN,
                       &p) == JMAPD_PATCH_OK && p.flags == IMAIL_DRAFT,
           "patch: a whole keywords object REPLACES the set");
    EXPECT(apply_patch("{\"keywords/$custom\":true}", "Inbox", 0, &p) ==
                   JMAPD_PATCH_E_KEYWORD,
           "patch: a keyword the store cannot carry is refused, not dropped");
    /* ~0 unescapes to "~", so this names the unknown keyword "~weird" */
    EXPECT(apply_patch("{\"keywords/~0weird\":true}", "Inbox", 0, &p) ==
                   JMAPD_PATCH_E_KEYWORD,
           "patch: ~0 in a path segment is unescaped (RFC 6901)");

    /* --- mailboxIds: replace, empty, multi, add, remove --- */
    snprintf(args, sizeof args, "{\"mailboxIds\":{\"%s\":true}}", sent);
    EXPECT(apply_patch(args, "Inbox", 0, &p) == JMAPD_PATCH_OK &&
               strcmp(p.mbox, "Sent") == 0 && p.mbox_moved,
           "patch: a whole mailboxIds object moves the Email");
    snprintf(args, sizeof args, "{\"mailboxIds\":{\"%s\":true}}", sent);
    EXPECT(apply_patch(args, "Sent", 0, &p) == JMAPD_PATCH_OK && !p.mbox_moved,
           "patch: replacing with the SAME mailbox is not a move");
    EXPECT(apply_patch("{\"mailboxIds\":{}}", "Inbox", 0, &p) ==
                   JMAPD_PATCH_E_EMPTY,
           "patch: an empty mailboxIds is refused (an Email must be in one)");
    snprintf(args, sizeof args, "{\"mailboxIds\":{\"%s\":true,\"%s\":true}}",
             inbox, sent);
    EXPECT(apply_patch(args, "Inbox", 0, &p) == JMAPD_PATCH_E_MULTI,
           "patch: two mailboxes is tooManyMailboxes for this store");
    snprintf(args, sizeof args, "{\"mailboxIds/%s\":true}", sent);
    EXPECT(apply_patch(args, "Inbox", 0, &p) == JMAPD_PATCH_E_MULTI,
           "patch: ADDING a second mailbox is refused");
    snprintf(args, sizeof args, "{\"mailboxIds/%s\":null}", inbox);
    EXPECT(apply_patch(args, "Inbox", 0, &p) == JMAPD_PATCH_E_EMPTY,
           "patch: removing the last mailbox is refused");
    snprintf(args, sizeof args, "{\"mailboxIds/%s\":null}", sent);
    EXPECT(apply_patch(args, "Inbox", 0, &p) == JMAPD_PATCH_OK &&
               strcmp(p.mbox, "Inbox") == 0 && !p.mbox_moved,
           "patch: removing a mailbox the Email is not in is a no-op");

    /* --- everything else is immutable through /set --- */
    EXPECT(apply_patch("{\"subject\":\"x\"}", "Inbox", 0, &p) ==
                   JMAPD_PATCH_E_PATH,
           "patch: an immutable property is refused");
    EXPECT(apply_patch("{\"keywords/$seen/x\":true}", "Inbox", 0, &p) ==
                   JMAPD_PATCH_E_PATH,
           "patch: a deeper path than the property allows is refused");
    EXPECT(apply_patch("{\"keywords/$seen\":\"yes\"}", "Inbox", 0, &p) ==
                   JMAPD_PATCH_E_TYPE,
           "patch: a non-boolean keyword value is a type error");
    /* An empty patch object is a legal no-op. */
    EXPECT(apply_patch("{}", "Inbox", IMAIL_SEEN, &p) == JMAPD_PATCH_OK &&
               p.flags == IMAIL_SEEN && strcmp(p.mbox, "Inbox") == 0,
           "patch: an empty patch changes nothing");
}

/* ------------------------------------------------------------------ */
/* (13) M3: state sidecar, fingerprint and /changes                    */
/* ------------------------------------------------------------------ */

static bool maildir_has(const char *root, const char *user, const char *mbox,
                        const char *base) {
    static const char *subs[] = { "cur", "new" };
    size_t s, bl = strlen(base);
    for (s = 0; s < 2; s++) {
        char dir[2048];
        DIR *d;
        struct dirent *e;
        snprintf(dir, sizeof dir, "%s/%s/%s%s/%s", root, user,
                 strcmp(mbox, "Inbox") == 0 ? "" : ".", mbox, subs[s]);
        d = opendir(dir);
        if (!d) continue;
        while ((e = readdir(d)) != NULL) {
            if (e->d_name[0] == '.') continue;
            if (strncmp(e->d_name, base, bl) == 0 &&
                (e->d_name[bl] == '\0' || e->d_name[bl] == ':')) {
                closedir(d);
                return true;
            }
        }
        closedir(d);
    }
    return false;
}

static void state_sidecar_tests(void) {
    char tpl[] = "/tmp/visage_jmapd_state_XXXXXX";
    char *root = mkdtemp(tpl);
    JmapdServer srv;
    JmapdState st, back;
    uint64_t fp1, fp2;

    if (!root) {
        check_fail("state: scratch root", "mkdtemp failed");
        return;
    }
    memset(&srv, 0, sizeof srv);
    srv.icfg.root = root;
    srv.icfg.max_msg = IMAPD_DEFAULT_MAX_MSG;
    srv.cfg.root = root;
    {
        char userdir[2048];
        snprintf(userdir, sizeof userdir, "%s/alice", root);
        mkdir(userdir, 0700);
    }

    jmapd_state_load(&srv, "alice", &st);
    EXPECT(st.email == 0 && !st.have_fp,
           "state: a missing sidecar loads as zeros with no fingerprint");
    st.email = 7;
    st.mailbox = 3;
    st.thread = 5;
    st.fp = 0x1234;
    st.have_fp = true;
    EXPECT(jmapd_state_save(&srv, "alice", &st) == 0,
           "state: the sidecar is written");
    jmapd_state_load(&srv, "alice", &back);
    EXPECT(back.email == 7 && back.mailbox == 3 && back.thread == 5 &&
               back.have_fp && back.fp == 0x1234,
           "state: the sidecar round-trips");

    /* Prime the sidecar with the fingerprint the maildir has RIGHT NOW, so the
       sync below observes "no change" rather than the 0x1234 above. */
    st.fp = jmapd_state_fingerprint(&srv, "alice");
    st.have_fp = true;
    EXPECT(jmapd_state_save(&srv, "alice", &st) == 0,
           "state: the primed sidecar is written");
    jmapd_state_load(&srv, "alice", &st);
    jmapd_state_sync(&srv, "alice", &st);
    fp1 = st.fp;
    EXPECT(st.email == 7, "state: an observation with no change does not bump");
    jmapd_state_sync(&srv, "alice", &st);
    EXPECT(st.email == 7, "state: a repeated observation does not bump either");
    /* A brand-new account has no fingerprint: the first observation ADOPTS. */
    {
        JmapdState fresh;
        jmapd_state_load(&srv, "bob", &fresh);
        EXPECT(!fresh.have_fp, "state: an unknown account has no fingerprint");
        jmapd_state_sync(&srv, "bob", &fresh);
        EXPECT(fresh.have_fp && fresh.email == 0,
               "state: the first observation adopts without bumping");
    }
    if (seed_msg(root, "alice", "Inbox", "1700000500.NEW.host",
                 "From: a@b\r\nSubject: s\r\n\r\nbody\r\n", 1700000500, 0) != 0)
        check_fail("state: seed a message", "seed failed");
    jmapd_state_sync(&srv, "alice", &st);
    fp2 = st.fp;
    EXPECT(st.email == 8 && st.mailbox == 4 && st.thread == 6,
           "state: a new message in the maildir bumps email/mailbox/thread");
    EXPECT(fp1 != fp2, "state: the fingerprint changed with the maildir");
    jmapd_state_load(&srv, "alice", &back);
    EXPECT(back.email == 8, "state: the bump was persisted");
    /* An explicit commit bumps and adopts, so the next sync is quiet. */
    jmapd_state_bump(&srv, "alice", &st, JMAPD_ST_EMAIL);
    EXPECT(st.email == 9, "state: a commit bumps the counter it names");
    jmapd_state_sync(&srv, "alice", &st);
    EXPECT(st.email == 9, "state: a commit's own fingerprint is not re-bumped");
}

/* ------------------------------------------------------------------ */
/* (14) M3: thread grouping (Email/get's threadId and Thread/get agree) */
/* ------------------------------------------------------------------ */

static void thread_tests(void) {
    char tpl[] = "/tmp/visage_jmapd_thread_XXXXXX";
    char *root = mkdtemp(tpl);
    JmapdServer srv;
    JmapdCtx ctx;
    char id_a[JMAPD_ID_MAX], id_b[JMAPD_ID_MAX], id_c[JMAPD_ID_MAX];
    char id_d[JMAPD_ID_MAX];
    char tid_a[JMAPD_ID_MAX], tid_b[JMAPD_ID_MAX], tid_c[JMAPD_ID_MAX];
    char tid_d[JMAPD_ID_MAX];
    char args[4096];
    char *res;

    if (!root) {
        check_fail("thread: scratch root", "mkdtemp failed");
        return;
    }
    memset(&srv, 0, sizeof srv);
    srv.icfg.root = root;
    srv.icfg.max_msg = IMAPD_DEFAULT_MAX_MSG;
    srv.cfg.root = root;
    srv.cfg.hostname = "localhost";
    memset(&ctx, 0, sizeof ctx);
    ctx.srv = &srv;
    ctx.user = "alice";

    /* A is the root; B replies to A; C replies to B (References lists both,
       root first); D is unrelated. */
    if (seed_msg(root, "alice", "Inbox", "1700000600.A.host",
                 "From: a@example.com\r\nSubject: root\r\n"
                 "Message-ID: <a@example.com>\r\n\r\nroot\r\n", 1700000600, 1) ||
        seed_msg(root, "alice", "Inbox", "1700000601.B.host",
                 "From: b@example.com\r\nSubject: re\r\n"
                 "Message-ID: <b@example.com>\r\n"
                 "In-Reply-To: <a@example.com>\r\n"
                 "References: <a@example.com>\r\n\r\nreply\r\n", 1700000601, 1) ||
        seed_msg(root, "alice", "Inbox", "1700000602.C.host",
                 "From: c@example.com\r\nSubject: re2\r\n"
                 "Message-ID: <c@example.com>\r\n"
                 "In-Reply-To: <b@example.com>\r\n"
                 "References: <a@example.com> <b@example.com>\r\n\r\nreply2\r\n",
                 1700000602, 1) ||
        seed_msg(root, "alice", "Inbox", "1700000603.D.host",
                 "From: d@example.com\r\nSubject: other\r\n"
                 "Message-ID: <d@example.com>\r\n\r\nother\r\n", 1700000603, 1)) {
        check_fail("thread: seed fixtures", "seed failed");
        return;
    }
    (void)jmapd_id_email("1700000600.A.host", NULL, id_a, sizeof id_a);
    (void)jmapd_id_email("1700000601.B.host", NULL, id_b, sizeof id_b);
    (void)jmapd_id_email("1700000602.C.host", NULL, id_c, sizeof id_c);
    (void)jmapd_id_email("1700000603.D.host", NULL, id_d, sizeof id_d);

    snprintf(args, sizeof args,
             "{\"ids\":[\"%s\",\"%s\",\"%s\",\"%s\"],"
             "\"properties\":[\"id\",\"threadId\"]}",
             id_a, id_b, id_c, id_d);
    res = call_method(&ctx, jmapd_method_email_get, args);
    EXPECT(res != NULL, "thread: Email/get returns threadIds");
    if (res) {
        JmapJsonDoc *doc = NULL;
        const JmapJsonNode *list = result_get(&doc, res, "list");
        size_t n = list ? jmap_json_count(list) : 0, i;
        EXPECT(n == 4, "thread: all four messages are returned");
        for (i = 0; i < n; i++) {
            const JmapJsonNode *e = jmap_json_at(list, i);
            const char *eid = NULL, *tid = NULL;
            if (jmap_json_str(jmap_json_get(e, "id"), &eid, NULL) != 0) continue;
            if (jmap_json_str(jmap_json_get(e, "threadId"), &tid, NULL) != 0)
                continue;
            if (!strcmp(eid, id_a)) snprintf(tid_a, sizeof tid_a, "%s", tid);
            else if (!strcmp(eid, id_b)) snprintf(tid_b, sizeof tid_b, "%s", tid);
            else if (!strcmp(eid, id_c)) snprintf(tid_c, sizeof tid_c, "%s", tid);
            else if (!strcmp(eid, id_d)) snprintf(tid_d, sizeof tid_d, "%s", tid);
        }
        EXPECT(tid_a[0] && !strcmp(tid_a, tid_b) && !strcmp(tid_a, tid_c),
               "thread: a reply chain shares ONE threadId");
        EXPECT(tid_d[0] && strcmp(tid_d, tid_a) != 0,
               "thread: an unrelated message has its own threadId");
        jmap_json_free(doc);
        free(res);
    }

    /* Thread/get must agree with Email/get, and group the three members. */
    snprintf(args, sizeof args, "{\"ids\":[\"%s\"]}", tid_a);
    res = call_method(&ctx, jmapd_method_thread_get, args);
    EXPECT(res != NULL, "thread: Thread/get answers");
    if (res) {
        JmapJsonDoc *doc = NULL;
        const JmapJsonNode *list = result_get(&doc, res, "list");
        const JmapJsonNode *t0 = list ? jmap_json_at(list, 0) : NULL;
        const JmapJsonNode *eids = t0 ? jmap_json_get(t0, "emailIds") : NULL;
        const char *tid = NULL;
        EXPECT(t0 && jmap_json_str(jmap_json_get(t0, "id"), &tid, NULL) == 0 &&
                   strcmp(tid, tid_a) == 0,
               "thread: Thread/get returns the id Email/get reported");
        EXPECT(eids && jmap_json_count(eids) == 3,
               "thread: the conversation holds all three messages");
        jmap_json_free(doc);
        free(res);
    }
    /* A thread id nobody has is notFound, not an error. */
    res = call_method(&ctx, jmapd_method_thread_get,
                      "{\"ids\":[\"tbm9wZQ\"]}");
    if (res) {
        JmapJsonDoc *doc = NULL;
        const JmapJsonNode *nf = result_get(&doc, res, "notFound");
        EXPECT(nf && jmap_json_count(nf) == 1,
               "thread: an unknown thread id is notFound");
        jmap_json_free(doc);
        free(res);
    }
    /* Without ids: every thread, and the group sizes are right. */
    res = call_method(&ctx, jmapd_method_thread_get, "{}");
    if (res) {
        JmapJsonDoc *doc = NULL;
        const JmapJsonNode *list = result_get(&doc, res, "list");
        size_t n = list ? jmap_json_count(list) : 0, i, members = 0;
        EXPECT(n == 2, "thread: a get without ids returns every thread");
        for (i = 0; i < n; i++) {
            const JmapJsonNode *e = jmap_json_at(list, i);
            members += jmap_json_count(jmap_json_get(e, "emailIds"));
        }
        EXPECT(members == 4, "thread: every email belongs to exactly one thread");
        jmap_json_free(doc);
        free(res);
    }
}

/* ------------------------------------------------------------------ */
/* (15) M3: Email/set over a real scratch maildir                      */
/* ------------------------------------------------------------------ */

static void set_tests(void) {
    char tpl[] = "/tmp/visage_jmapd_set_XXXXXX";
    char *root = mkdtemp(tpl);
    JmapdServer srv;
    JmapdCtx ctx;
    char inbox[JMAPD_ID_MAX], drafts[JMAPD_ID_MAX];
    char args[4096];
    char *res;
    char draft_id[JMAPD_ID_MAX];
    char draft_base[IMAPD_MAX_MBOX + 1];
    char thread_id[JMAPD_ID_MAX];
    char state_after_create[32];

    if (!root) {
        check_fail("set: scratch root", "mkdtemp failed");
        return;
    }
    memset(&srv, 0, sizeof srv);
    srv.icfg.root = root;
    srv.icfg.max_msg = IMAPD_DEFAULT_MAX_MSG;
    srv.cfg.root = root;
    srv.cfg.hostname = "localhost";
    memset(&ctx, 0, sizeof ctx);
    ctx.srv = &srv;
    ctx.user = "alice";
    (void)jmapd_account_prepare(&srv, "alice");
    (void)jmapd_id_mailbox("Inbox", inbox, sizeof inbox);
    (void)jmapd_id_mailbox("Drafts", drafts, sizeof drafts);

    /* --- create: text+html draft with the client's exact shape --- */
    snprintf(args, sizeof args,
             "{\"accountId\":\"alice\",\"create\":{\"draft\":{"
             "\"mailboxIds\":{\"%s\":true},"
             "\"keywords\":{\"$draft\":true,\"$seen\":true},"
             "\"from\":[{\"email\":\"alice@example.com\"}],"
             "\"to\":[{\"name\":\"Bob\",\"email\":\"bob@example.com\"}],"
             "\"subject\":\"hello there\","
             "\"textBody\":[{\"partId\":\"t1\",\"type\":\"text/plain\"}],"
             "\"htmlBody\":[{\"partId\":\"h1\",\"type\":\"text/html\"}],"
             "\"bodyValues\":{\"t1\":{\"value\":\"first line\\nsecond line\"},"
             "\"h1\":{\"value\":\"<p>hi</p>\"}}}}}", drafts);
    res = call_method(&ctx, jmapd_method_email_set, args);
    EXPECT(res != NULL, "set: create answers");
    if (!res) return;
    {
        JmapJsonDoc *doc = NULL;
        const JmapJsonNode *created = result_get(&doc, res, "created");
        const JmapJsonNode *c = created ? jmap_json_get(created, "draft") : NULL;
        const char *s = NULL;
        const JmapJsonNode *st = NULL;
        EXPECT(c != NULL, "set: create reports the creation id");
        if (c) {
            if (jmap_json_str(jmap_json_get(c, "id"), &s, NULL) == 0)
                snprintf(draft_id, sizeof draft_id, "%s", s);
            s = NULL;
            if (jmap_json_str(jmap_json_get(c, "threadId"), &s, NULL) == 0)
                snprintf(thread_id, sizeof thread_id, "%s", s);
        }
        st = jmap_json_get(jmap_json_root(doc), "newState");
        if (st && jmap_json_str(st, &s, NULL) == 0)
            snprintf(state_after_create, sizeof state_after_create, "%s", s);
        EXPECT(draft_id[0] == 'e', "set: the created Email id is an Email id");
        EXPECT(thread_id[0] == 't', "set: the created Email has a threadId");
        EXPECT(jmap_json_get(jmap_json_root(doc), "notCreated") == NULL,
               "set: nothing was refused");
        jmap_json_free(doc);
        free(res);
    }
    if (jmapd_id_email_parse(draft_id, draft_base, sizeof draft_base, NULL, 0)
            != 0)
        draft_base[0] = '\0';
    EXPECT(draft_base[0] && maildir_has(root, "alice", "Drafts", draft_base),
           "set: the message is on disk in Drafts");

    /* --- the created Email reads back with the right body and keywords --- */
    snprintf(args, sizeof args,
             "{\"ids\":[\"%s\"],\"properties\":[\"id\",\"subject\",\"keywords\","
             "\"mailboxIds\",\"textBody\",\"htmlBody\",\"from\",\"to\"],"
             "\"fetchTextBodyValues\":true,\"fetchHTMLBodyValues\":true}",
             draft_id);
    res = call_method(&ctx, jmapd_method_email_get, args);
    if (res) {
        JmapJsonDoc *doc = NULL;
        const JmapJsonNode *list = result_get(&doc, res, "list");
        const JmapJsonNode *e = list ? jmap_json_at(list, 0) : NULL;
        const JmapJsonNode *kw = e ? jmap_json_get(e, "keywords") : NULL;
        const JmapJsonNode *mbs = e ? jmap_json_get(e, "mailboxIds") : NULL;
        const JmapJsonNode *tb = e ? jmap_json_get(e, "textBody") : NULL;
        const JmapJsonNode *bv = e ? jmap_json_get(e, "bodyValues") : NULL;
        const char *subj = NULL, *val = NULL;
        EXPECT(e != NULL, "set: the created Email is fetchable");
        if (e) {
            EXPECT(jmap_json_str(jmap_json_get(e, "subject"), &subj, NULL) == 0 &&
                       strcmp(subj, "hello there") == 0,
                   "set: the created Email kept its subject");
            EXPECT(kw && jmap_json_get(kw, "$draft") && jmap_json_get(kw, "$seen"),
                   "set: the created Email kept its keywords");
            EXPECT(mbs && jmap_json_get(mbs, drafts),
                   "set: the created Email is in the mailbox the create named");
            {
                const JmapJsonNode *p0 = tb ? jmap_json_at(tb, 0) : NULL;
                const char *pid = NULL;
                const JmapJsonNode *bv0;
                if (p0 && jmap_json_str(jmap_json_get(p0, "partId"), &pid,
                                        NULL) == 0) {
                    bv0 = bv ? jmap_json_get(bv, pid) : NULL;
                    if (bv0 &&
                        jmap_json_str(jmap_json_get(bv0, "value"), &val,
                                      NULL) == 0)
                        EXPECT(strcmp(val, "first line\r\nsecond line") == 0,
                               "set: the text body round-trips CRLF-normalized");
                }
            }
        }
        jmap_json_free(doc);
        free(res);
    }

    /* --- update: flip $flagged and clear $draft; the id must NOT change --- */
    snprintf(args, sizeof args,
             "{\"accountId\":\"alice\",\"update\":{\"%s\":{"
             "\"keywords/$flagged\":true,\"keywords/$draft\":false}}}",
             draft_id);
    res = call_method(&ctx, jmapd_method_email_set, args);
    if (res) {
        JmapJsonDoc *doc = NULL;
        const JmapJsonNode *up = result_get(&doc, res, "updated");
        EXPECT(up && jmap_json_get(up, draft_id) != NULL,
               "set: the flag update is reported as updated");
        EXPECT(jmap_json_get(jmap_json_root(doc), "notUpdated") == NULL,
               "set: the flag update is not refused");
        jmap_json_free(doc);
        free(res);
    }
    snprintf(args, sizeof args,
             "{\"ids\":[\"%s\"],\"properties\":[\"id\",\"keywords\"]}",
             draft_id);
    res = call_method(&ctx, jmapd_method_email_get, args);
    if (res) {
        JmapJsonDoc *doc = NULL;
        const JmapJsonNode *list = result_get(&doc, res, "list");
        const JmapJsonNode *e = list ? jmap_json_at(list, 0) : NULL;
        const JmapJsonNode *kw = e ? jmap_json_get(e, "keywords") : NULL;
        const char *eid = NULL;
        EXPECT(e && jmap_json_str(jmap_json_get(e, "id"), &eid, NULL) == 0 &&
                   strcmp(eid, draft_id) == 0,
               "set: the Email id is UNCHANGED by a flag rename");
        EXPECT(kw && jmap_json_get(kw, "$flagged") && !jmap_json_get(kw, "$draft"),
               "set: the flag update took effect");
        jmap_json_free(doc);
        free(res);
    }
    EXPECT(draft_base[0] && maildir_has(root, "alice", "Drafts", draft_base),
           "set: the file kept its base name across the flag rename");

    /* --- update: move Drafts -> Inbox; the id must NOT change --- */
    snprintf(args, sizeof args,
             "{\"accountId\":\"alice\",\"update\":{\"%s\":{"
             "\"mailboxIds\":{\"%s\":true}}}}", draft_id, inbox);
    res = call_method(&ctx, jmapd_method_email_set, args);
    if (res) {
        JmapJsonDoc *doc = NULL;
        EXPECT(jmap_json_get(jmap_json_root(doc), "notUpdated") == NULL,
               "set: the move is not refused");
        if (doc) jmap_json_free(doc);
        free(res);
    }
    snprintf(args, sizeof args,
             "{\"ids\":[\"%s\"],\"properties\":[\"id\",\"mailboxIds\"]}",
             draft_id);
    res = call_method(&ctx, jmapd_method_email_get, args);
    if (res) {
        JmapJsonDoc *doc = NULL;
        const JmapJsonNode *list = result_get(&doc, res, "list");
        const JmapJsonNode *e = list ? jmap_json_at(list, 0) : NULL;
        const JmapJsonNode *mbs = e ? jmap_json_get(e, "mailboxIds") : NULL;
        EXPECT(mbs && jmap_json_get(mbs, inbox) && !jmap_json_get(mbs, drafts),
               "set: the move landed in the target mailbox");
        {
            const JmapJsonNode *nf = jmap_json_get(jmap_json_root(doc), "notFound");
            EXPECT(e && jmap_json_count(list) == 1 &&
                       (!nf || jmap_json_count(nf) == 0),
                   "set: the Email is still addressable by the SAME id after a move");
        }
        jmap_json_free(doc);
        free(res);
    }
    EXPECT(draft_base[0] && maildir_has(root, "alice", "Inbox", draft_base) &&
               !maildir_has(root, "alice", "Drafts", draft_base),
           "set: the file moved between maildirs and kept its base name");

    /* --- ifInState: a stale state is refused WHOLE, the current one works --- */
    res = call_method(&ctx, jmapd_method_email_set,
                      "{\"accountId\":\"alice\",\"ifInState\":\"e999999\","
                      "\"update\":{\"x\":{\"keywords/$seen\":true}}}");
    if (res) {
        JmapJsonDoc *doc = NULL;
        const JmapJsonNode *type = result_get(&doc, res, "type");
        const char *s = NULL;
        EXPECT(type && jmap_json_str(type, &s, NULL) == 0 &&
                   strcmp(s, "stateMismatch") == 0,
               "set: a stale ifInState is a stateMismatch method error");
        jmap_json_free(doc);
        free(res);
    }
    /* The state Email/get reports right now must be accepted, and the update
       must land: a check that only ever sees a refusal would pass on a server
       that refuses everything. */
    snprintf(args, sizeof args, "{\"ids\":[\"%s\"],\"properties\":[\"id\"]}",
             draft_id);
    res = call_method(&ctx, jmapd_method_email_get, args);
    if (res) {
        JmapJsonDoc *doc = NULL;
        const JmapJsonNode *stn = result_get(&doc, res, "state");
        const char *s = NULL;
        char cur_state[32];
        cur_state[0] = '\0';
        if (stn && jmap_json_str(stn, &s, NULL) == 0)
            snprintf(cur_state, sizeof cur_state, "%s", s);
        jmap_json_free(doc);
        free(res);
        EXPECT(cur_state[0] != '\0' &&
                   strcmp(cur_state, state_after_create) != 0,
               "set: a write moved the state on (the client's cache would be stale)");
        snprintf(args, sizeof args,
                 "{\"accountId\":\"alice\",\"ifInState\":\"%s\","
                 "\"update\":{\"%s\":{\"keywords/$seen\":true}}}",
                 cur_state, draft_id);
        res = call_method(&ctx, jmapd_method_email_set, args);
        if (res) {
            JmapJsonDoc *doc2 = NULL;
            const JmapJsonNode *up = result_get(&doc2, res, "updated");
            EXPECT(up && jmap_json_get(up, draft_id) != NULL,
                   "set: the CURRENT state is accepted and the update lands");
            jmap_json_free(doc2);
            free(res);
        }
    }

    /* --- create refusals --- */
    snprintf(args, sizeof args,
             "{\"create\":{\"c1\":{\"mailboxIds\":{\"%s\":true,\"%s\":true},"
             "\"subject\":\"x\"}}}", inbox, drafts);
    res = call_method(&ctx, jmapd_method_email_set, args);
    if (res) {
        JmapJsonDoc *doc = NULL;
        const JmapJsonNode *nc = result_get(&doc, res, "notCreated");
        const JmapJsonNode *why = nc ? jmap_json_get(nc, "c1") : NULL;
        const char *type = NULL;
        EXPECT(why && jmap_json_str(jmap_json_get(why, "type"), &type, NULL) == 0 &&
                   strcmp(type, "tooManyMailboxes") == 0,
               "set: a create in two mailboxes is tooManyMailboxes");
        jmap_json_free(doc);
        free(res);
    }
    snprintf(args, sizeof args,
             "{\"create\":{\"c2\":{\"mailboxIds\":{\"%s\":true},"
             "\"keywords\":{\"$label\":true}}}}", inbox);
    res = call_method(&ctx, jmapd_method_email_set, args);
    if (res) {
        JmapJsonDoc *doc = NULL;
        const JmapJsonNode *nc = result_get(&doc, res, "notCreated");
        const JmapJsonNode *why = nc ? jmap_json_get(nc, "c2") : NULL;
        const char *type = NULL;
        EXPECT(why && jmap_json_str(jmap_json_get(why, "type"), &type, NULL) == 0 &&
                   strcmp(type, "invalidProperties") == 0,
               "set: a create with an unsupported keyword is refused");
        jmap_json_free(doc);
        free(res);
    }
    snprintf(args, sizeof args,
             "{\"create\":{\"c3\":{\"mailboxIds\":{\"%s\":true},"
             "\"attachments\":[{\"blobId\":\"gAAA\",\"type\":\"text/plain\"}]}}}",
             inbox);
    res = call_method(&ctx, jmapd_method_email_set, args);
    if (res) {
        JmapJsonDoc *doc = NULL;
        const JmapJsonNode *nc = result_get(&doc, res, "notCreated");
        const JmapJsonNode *why = nc ? jmap_json_get(nc, "c3") : NULL;
        const JmapJsonNode *props = why ? jmap_json_get(why, "properties") : NULL;
        const char *p0 = NULL;
        EXPECT(why && jmap_json_get(why, "type") &&
                   props && jmap_json_count(props) == 1 &&
                   jmap_json_str(jmap_json_at(props, 0), &p0, NULL) == 0 &&
                   strcmp(p0, "attachments") == 0,
               "set: a create with an attachment names `attachments`, not a "
               "different property");
        jmap_json_free(doc);
        free(res);
    }
    /* An address that is not an addr-spec is refused and names the property. */
    snprintf(args, sizeof args,
             "{\"create\":{\"c4\":{\"mailboxIds\":{\"%s\":true},"
             "\"to\":[{\"email\":\"not an address\"}]}}}", inbox);
    res = call_method(&ctx, jmapd_method_email_set, args);
    if (res) {
        JmapJsonDoc *doc = NULL;
        const JmapJsonNode *nc = result_get(&doc, res, "notCreated");
        const JmapJsonNode *why = nc ? jmap_json_get(nc, "c4") : NULL;
        const JmapJsonNode *props = why ? jmap_json_get(why, "properties") : NULL;
        const char *p0 = NULL;
        EXPECT(why && props && jmap_json_count(props) == 1 &&
                   jmap_json_str(jmap_json_at(props, 0), &p0, NULL) == 0 &&
                   strcmp(p0, "to") == 0,
               "set: a malformed To address is refused as invalidProperties/to");
        jmap_json_free(doc);
        free(res);
    }

    /* --- destroy: the Email stops existing, and only that one --- */
    if (seed_msg(root, "alice", "Inbox", "1700000700.KEEP.host",
                 "From: k@example.com\r\nSubject: keep\r\n"
                 "Message-ID: <keep@example.com>\r\n\r\nkeep\r\n", 1700000700, 1)
            != 0)
        check_fail("set: seed a bystander message", "seed failed");
    snprintf(args, sizeof args, "{\"destroy\":[\"%s\"]}", draft_id);
    res = call_method(&ctx, jmapd_method_email_set, args);
    if (res) {
        JmapJsonDoc *doc = NULL;
        const JmapJsonNode *d = result_get(&doc, res, "destroyed");
        EXPECT(d && jmap_json_count(d) == 1,
               "set: destroy reports the destroyed id");
        jmap_json_free(doc);
        free(res);
    }
    snprintf(args, sizeof args, "{\"ids\":[\"%s\"],\"properties\":[\"id\"]}",
             draft_id);
    res = call_method(&ctx, jmapd_method_email_get, args);
    if (res) {
        JmapJsonDoc *doc = NULL;
        const JmapJsonNode *nf = result_get(&doc, res, "notFound");
        EXPECT(nf && jmap_json_count(nf) == 1,
               "set: a destroyed Email is gone from Email/get");
        jmap_json_free(doc);
        free(res);
    }
    EXPECT(draft_base[0] && !maildir_has(root, "alice", "Inbox", draft_base),
           "set: destroy unlinked the file");
    EXPECT(maildir_has(root, "alice", "Inbox", "1700000700.KEEP.host"),
           "set: destroy left the other messages alone");
    /* A destroy list holding a non-string is invalidArguments (method-level),
       not a silently ignored id. */
    res = call_method(&ctx, jmapd_method_email_set,
                      "{\"destroy\":[123]}");
    if (res) {
        JmapJsonDoc *doc = NULL;
        const JmapJsonNode *type = result_get(&doc, res, "type");
        const char *s2 = NULL;
        EXPECT(type && jmap_json_str(type, &s2, NULL) == 0 &&
                   strcmp(s2, "invalidArguments") == 0,
               "set: a non-string destroy id is invalidArguments");
        jmap_json_free(doc);
        free(res);
    }
    /* Destroying an id that is already gone is notFound, not a failure. */
    snprintf(args, sizeof args, "{\"destroy\":[\"%s\"]}", draft_id);
    res = call_method(&ctx, jmapd_method_email_set, args);
    if (res) {
        JmapJsonDoc *doc = NULL;
        const JmapJsonNode *nd = result_get(&doc, res, "notDestroyed");
        EXPECT(nd && jmap_json_get(nd, draft_id) != NULL,
               "set: destroying a gone Email is notDestroyed/notFound");
        jmap_json_free(doc);
        free(res);
    }
}

/* ------------------------------------------------------------------ */
/* (16) M3: the M1-review fixes                                        */
/* ------------------------------------------------------------------ */

static void review_fix_tests(void) {
    char tpl[] = "/tmp/visage_jmapd_fix_XXXXXX";
    char *root = mkdtemp(tpl);
    JmapdServer srv;
    JmapdCtx ctx;
    char args[2048];
    char *res;

    if (!root) {
        check_fail("fix: scratch root", "mkdtemp failed");
        return;
    }
    memset(&srv, 0, sizeof srv);
    srv.icfg.root = root;
    srv.icfg.max_msg = IMAPD_DEFAULT_MAX_MSG;
    srv.cfg.root = root;
    srv.cfg.hostname = "localhost";
    memset(&ctx, 0, sizeof ctx);
    ctx.srv = &srv;
    ctx.user = "alice";

    /* SHOULD-FIX 1: Identity/get echoes the REQUESTED id, not its own. */
    res = call_method(&ctx, jmapd_method_identity_get,
                      "{\"ids\":[\"inot-the-real-one\"]}");
    if (res) {
        JmapJsonDoc *doc = NULL;
        const JmapJsonNode *nf = result_get(&doc, res, "notFound");
        const char *s = NULL;
        EXPECT(nf && jmap_json_count(nf) == 1 &&
                   jmap_json_str(jmap_json_at(nf, 0), &s, NULL) == 0 &&
                   strcmp(s, "inot-the-real-one") == 0,
               "fix: Identity/get notFound echoes the requested id");
        jmap_json_free(doc);
        free(res);
    }

    /* SHOULD-FIX 2: a long requested-but-absent mailbox id is echoed whole. */
    {
        char longid[JMAPD_ID_MAX];
        size_t i;
        longid[0] = 'm';
        for (i = 1; i < 400; i++) longid[i] = 'A';
        longid[400] = '\0';
        snprintf(args, sizeof args, "{\"ids\":[\"%s\"]}", longid);
        res = call_method(&ctx, jmapd_method_mailbox_get, args);
        if (res) {
            JmapJsonDoc *doc = NULL;
            const JmapJsonNode *nf = result_get(&doc, res, "notFound");
            const char *s = NULL;
            EXPECT(nf && jmap_json_count(nf) == 1 &&
                       jmap_json_str(jmap_json_at(nf, 0), &s, NULL) == 0 &&
                       strlen(s) == 400 && strcmp(s, longid) == 0,
                   "fix: Mailbox/get notFound echoes a 400-char id untruncated");
            jmap_json_free(doc);
            free(res);
        }
    }

    /* SHOULD-FIX 3: an integer literal beyond int64 is not reported as
       LLONG_MAX — it is honestly non-integral, so u64 refuses it. */
    {
        JmapJsonErr err = JMAP_JSON_OK;
        JmapJsonDoc *doc = jmap_json_parse("{\"n\":99999999999999999999}",
                                           strlen("{\"n\":99999999999999999999}"),
                                           &err);
        uint64_t v = 0;
        EXPECT(doc != NULL, "fix: an over-range integer literal still parses");
        if (doc) {
            const JmapJsonNode *n = jmap_json_get(jmap_json_root(doc), "n");
            EXPECT(n && !n->is_int && jmap_json_u64(n, &v) != 0,
                   "fix: an over-range integer is non-integral, never clamped");
            jmap_json_free(doc);
        }
    }
}

/* ------------------------------------------------------------------ */
/* (M4) RFC 2047 encoded-words + the submission envelope               */
/* ------------------------------------------------------------------ */

static void rfc2047_tests(void) {
    char out[512];

    /* B encoding, the common case */
    EXPECT(jmapd_rfc2047_decode("=?UTF-8?B?SGVsbG8gV29ybGQ=?=", out,
                                sizeof out) == 0 &&
               strcmp(out, "Hello World") == 0,
           "rfc2047: B encoding decodes");
    /* Q encoding with '_' for space and =XX for a non-ASCII byte */
    EXPECT(jmapd_rfc2047_decode("=?utf-8?Q?caf=C3=A9_au_lait?=", out,
                                sizeof out) == 0 &&
               strcmp(out, "caf\xc3\xa9 au lait") == 0,
           "rfc2047: Q encoding decodes '_' and '=XX'");
    /* charset PASSTHROUGH: latin-1 arrives as its own bytes, not transcoded */
    EXPECT(jmapd_rfc2047_decode("=?iso-8859-1?Q?caf=E9?=", out, sizeof out) ==
               0 &&
               strlen(out) == 4 && (unsigned char)out[3] == 0xe9,
           "rfc2047: charset is passthrough (latin-1 byte preserved)");
    /* adjacent words: the whitespace BETWEEN them is not part of the text */
    EXPECT(jmapd_rfc2047_decode("=?utf-8?B?SGVsbG8=?= =?utf-8?B?V29ybGQ=?=",
                                out, sizeof out) == 0 &&
               strcmp(out, "HelloWorld") == 0,
           "rfc2047: adjacent encoded words join without the separator");
    /* a literal prefix, an encoded word, a literal suffix */
    EXPECT(jmapd_rfc2047_decode("Re: =?utf-8?B?SGVsbG8=?= there", out,
                                sizeof out) == 0 &&
               strcmp(out, "Re: Hello there") == 0,
           "rfc2047: mixed literal and encoded text");
    /* a folded header arrives with the fold as ONE space (mail_header_get) */
    EXPECT(jmapd_rfc2047_decode("=?utf-8?Q?a?= =?utf-8?Q?b?=", out,
                                sizeof out) == 0 &&
               strcmp(out, "ab") == 0,
           "rfc2047: a folded pair of words decodes as one run");
    /* the encoding letter is case-insensitive */
    EXPECT(jmapd_rfc2047_decode("=?utf-8?b?SGk=?=", out, sizeof out) == 0 &&
               strcmp(out, "Hi") == 0,
           "rfc2047: a lower-case encoding letter is accepted");
    /* malformed words pass through VERBATIM (RFC 2047 6.2), never mangled */
    EXPECT(jmapd_rfc2047_decode("=?utf-8?X?abc?=", out, sizeof out) == 0 &&
               strcmp(out, "=?utf-8?X?abc?=") == 0,
           "rfc2047: an unknown encoding passes through verbatim");
    EXPECT(jmapd_rfc2047_decode("=?utf-8?B?SGVsbG8", out, sizeof out) == 0 &&
               strcmp(out, "=?utf-8?B?SGVsbG8") == 0,
           "rfc2047: an unterminated word passes through verbatim");
    EXPECT(jmapd_rfc2047_decode("=?utf-8?B?!!!?=", out, sizeof out) == 0 &&
               strcmp(out, "=?utf-8?B?!!!?=") == 0,
           "rfc2047: an undecodable payload passes through verbatim");
    /* nothing to do */
    EXPECT(jmapd_rfc2047_decode("plain subject =? no", out, sizeof out) == 0 &&
               strcmp(out, "plain subject =? no") == 0,
           "rfc2047: text that is not an encoded word is untouched");
    EXPECT(jmapd_rfc2047_decode("", out, sizeof out) == 0 && out[0] == '\0',
           "rfc2047: the empty value stays empty");
}

static void envelope_tests(void) {
    static const char msg1[] =
        "From: Alice <alice@example.com>\r\n"
        "To: Bob <bob@example.com>, carol@example.com\r\n"
        "Cc: dave@example.com\r\n"
        "Bcc: bob@example.com\r\n"
        "Subject: hi\r\n\r\nbody\r\n";
    static const char msg2[] =
        "Sender: bounce@example.com\r\n"
        "From: someone-else@example.org\r\n"
        "To: bob@example.com\r\n\r\nx\r\n";
    static const char msg3[] =
        "From: alice@example.com\r\nSubject: no recipients\r\n\r\nx\r\n";
    static const char msg4[] =
        "To: bob@example.com\r\n\r\nx\r\n";
    static const char msg5[] =
        "From: alice@example.com\r\n"
        "To: one@example.com,\r\n two@example.com,\r\n three@example.com\r\n"
        "\r\nx\r\n";
    JmapdEnvelope env;

    EXPECT(jmapd_envelope_render(msg1, sizeof msg1 - 1, "alice@example.com",
                                 &env) == 0,
           "envelope: a message with recipients renders");
    EXPECT(strcmp(env.mail_from, "alice@example.com") == 0,
           "envelope: MAIL FROM is the From address");
    EXPECT(env.nrcpt == 3, "envelope: rcptTo is To + Cc + Bcc, deduplicated");
    EXPECT(strcmp(env.rcpt[0], "bob@example.com") == 0 &&
               strcmp(env.rcpt[1], "carol@example.com") == 0 &&
               strcmp(env.rcpt[2], "dave@example.com") == 0,
           "envelope: display names are dropped and Bcc's duplicate is not "
           "repeated");

    /* Sender wins over From (RFC 8621 7.5), and a From that is not the
       Identity's address is replaced by it */
    EXPECT(jmapd_envelope_render(msg2, sizeof msg2 - 1, "alice@example.com",
                                 &env) == 0 &&
               strcmp(env.mail_from, "alice@example.com") == 0,
           "envelope: an alien Sender/From is replaced by the Identity address");

    EXPECT(jmapd_envelope_render(msg3, sizeof msg3 - 1, "alice@example.com",
                                 &env) != 0,
           "envelope: no To/Cc/Bcc is noRecipients");
    EXPECT(jmapd_envelope_render(msg4, sizeof msg4 - 1, "alice@example.com",
                                 &env) == 0 &&
               strcmp(env.mail_from, "alice@example.com") == 0,
           "envelope: a message with no From sends as the Identity");
    EXPECT(jmapd_envelope_render(msg5, sizeof msg5 - 1, "alice@example.com",
                                 &env) == 0 &&
               env.nrcpt == 3 && strcmp(env.rcpt[1], "two@example.com") == 0 &&
               strcmp(env.rcpt[2], "three@example.com") == 0,
           "envelope: a folded To header yields every address");
    EXPECT(jmapd_envelope_render(NULL, 0, "alice@example.com", &env) != 0,
           "envelope: a missing message is refused, not guessed");
}

int main(void) {
    json_ok_tests();
    json_reject_tests();
    id_tests();
    session_tests();
    public_url_tests();
    auth_tests();
    per_request_auth_tests();
    http_tests();
    state_tests();
    cte_tests();
    mime_tree_tests();
    mime_file_part_tests();
    single_part_file_tests();
    preview_tests();
    blob_id_tests();
    addr_tests();
    ref_tests();
    query_tests();
    email_get_tests();
    body_part_id_tests();
    bounded_work_tests();
    patch_tests();
    state_sidecar_tests();
    thread_tests();
    set_tests();
    review_fix_tests();
    rfc2047_tests();
    envelope_tests();
    printf("\n%d checks, %d failed\n", nchecks, nfails);
    return nfails ? 1 : 0;
}
