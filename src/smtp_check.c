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
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <signal.h>

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
    EXPECT(smtp_tls_valid("implicit") == 0, "tls_valid accepts implicit");
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

/* ---- loopback routing proof (offline, no internet) ---- */

struct stub_result {
    char mail[256];
    char rcpt[256];
};

/* Read one CRLF (or bare-LF) terminated line into buf (NUL-terminated,
   terminator stripped).  Returns the line length (excl. terminator) or -1. */
static int stub_read_line(int fd, char *buf, size_t bufsz) {
    size_t n = 0;
    for (;;) {
        if (n + 1 >= bufsz) return -1;
        char c;
        ssize_t r = read(fd, &c, 1);
        if (r <= 0) return -1;
        buf[n++] = c;
        if (n >= 2 && buf[n - 2] == '\r' && buf[n - 1] == '\n') {
            buf[n - 2] = '\0';
            return (int)(n - 2);
        }
        if (buf[n - 1] == '\n') {
            buf[n - 1] = '\0';
            return (int)(n - 1);
        }
    }
}

static int stub_write_all(int fd, const char *s) {
    size_t len = strlen(s), off = 0;
    while (off < len) {
        ssize_t w = write(fd, s + off, len - off);
        if (w <= 0) return -1;
        off += (size_t)w;
    }
    return 0;
}

/* Minimal SMTP server for ONE transaction (plaintext, no AUTH/STARTTLS): the
   point is to record WHICH listener smtp_out_send connected to, not to
   exercise TLS/AUTH (covered elsewhere).  Persists the MAIL FROM / RCPT TO it
   receives to outpath BEFORE the final reply so the parent can read it even if
   the child is killed right after smtp_out_send returns. */
static void stub_serve(int listen_fd, const char *outpath) {
    struct stub_result res;
    memset(&res, 0, sizeof res);
    int cfd = accept(listen_fd, NULL, NULL);
    if (cfd < 0) _exit(2);

    char line[512];
    if (stub_write_all(cfd, "220 stub ESMTP ready\r\n") != 0) _exit(3);
    if (stub_read_line(cfd, line, sizeof line) < 0) _exit(3);      /* EHLO */
    if (stub_write_all(cfd, "250-stub\r\n250 8BITMIME\r\n") != 0) _exit(3);

    if (stub_read_line(cfd, line, sizeof line) < 0) _exit(3);      /* MAIL FROM */
    strncpy(res.mail, line, sizeof res.mail - 1);
    res.mail[sizeof res.mail - 1] = '\0';
    if (stub_write_all(cfd, "250 OK\r\n") != 0) _exit(3);

    if (stub_read_line(cfd, line, sizeof line) < 0) _exit(3);      /* RCPT TO */
    strncpy(res.rcpt, line, sizeof res.rcpt - 1);
    res.rcpt[sizeof res.rcpt - 1] = '\0';

    /* Persist the envelope now (before DATA/final reply) so the parent never
       races the child's exit. */
    int f = open(outpath, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (f >= 0) {
        (void)write(f, &res, sizeof res);
        close(f);
    }

    if (stub_write_all(cfd, "250 OK\r\n") != 0) _exit(3);
    if (stub_read_line(cfd, line, sizeof line) < 0) _exit(3);      /* DATA */
    if (stub_write_all(cfd, "354 go\r\n") != 0) _exit(3);
    for (;;) {                                                    /* body + "." */
        if (stub_read_line(cfd, line, sizeof line) < 0) _exit(3);
        if (strcmp(line, ".") == 0) break;
    }
    if (stub_write_all(cfd, "250 OK\r\n") != 0) _exit(3);
    (void)stub_read_line(cfd, line, sizeof line);                  /* QUIT */
    (void)stub_write_all(cfd, "221 bye\r\n");
    _exit(0);
}

/* Bind a loopback ephemeral listener, fork a child to serve one transaction,
   and return the bound port + child pid. */
static int stub_spawn(uint16_t *port_out, pid_t *pid_out, const char *outpath) {
    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    if (lfd < 0) return -1;
    int one = 1;
    (void)setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = 0;
    if (bind(lfd, (struct sockaddr *)&sa, sizeof sa) != 0 ||
        listen(lfd, 4) != 0) {
        close(lfd);
        return -1;
    }
    socklen_t slen = sizeof sa;
    if (getsockname(lfd, (struct sockaddr *)&sa, &slen) != 0) {
        close(lfd);
        return -1;
    }
    uint16_t port = ntohs(sa.sin_port);

    pid_t pid = fork();
    if (pid < 0) {
        close(lfd);
        return -1;
    }
    if (pid == 0) {
        stub_serve(lfd, outpath);
        _exit(1);
    }
    close(lfd);
    *port_out = port;
    *pid_out = pid;
    return 0;
}

/* Prove end-to-end that smtp_out_send connects to the relay SELECTED by
   smtp_relay_for: a normal forward goes to the local relay listener, a
   reverse reply goes to the reply_relay listener, and neither crosses over. */
static void relay_routing_test(void) {
    char pathA[64], pathB[64];
    snprintf(pathA, sizeof pathA, "/tmp/visage_rr_local_%d", (int)getpid());
    snprintf(pathB, sizeof pathB, "/tmp/visage_rr_reply_%d", (int)getpid());
    unlink(pathA);
    unlink(pathB);

    uint16_t port_local = 0, port_reply = 0;
    pid_t pid_local = -1, pid_reply = -1;
    if (stub_spawn(&port_local, &pid_local, pathA) != 0 ||
        stub_spawn(&port_reply, &pid_reply, pathB) != 0) {
        check_fail("relay routing (stub_spawn)", "failed to spawn loopback stubs");
        return;
    }

    Config cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.hostname = "test.local";
    cfg.limits.cmd_timeout = 5;
    cfg.limits.data_timeout = 5;
    cfg.relay.host = "127.0.0.1";
    cfg.relay.port = port_local;
    cfg.relay.tls = "none";
    cfg.relay.auth.enabled = false;
    cfg.relay.retries = 0;
    cfg.reply_relay.host = "127.0.0.1";
    cfg.reply_relay.port = port_reply;
    cfg.reply_relay.tls = "none";
    cfg.reply_relay.auth.enabled = false;
    cfg.reply_relay.retries = 0;

    const char body[] = "Subject: routing-test\r\n\r\nhello\r\n";
    char status[256];
    int sres;

    /* normal forward -> local relay */
    {
        Config one = cfg;
        one.relay = *smtp_relay_for(&cfg, false);
        one.relay.retries = 0;
        sres = smtp_out_send(NULL, &one, "from@test.local",
                             "normal-dest@test.local", body, sizeof body - 1,
                             status, sizeof status);
        EXPECT(sres == SMTP_OK,
               "relay routing: normal forward delivered (local relay)");
    }

    /* reverse reply -> reply relay */
    {
        Config one = cfg;
        one.relay = *smtp_relay_for(&cfg, true);
        one.relay.retries = 0;
        sres = smtp_out_send(NULL, &one, "alias@test.local",
                             "external@example.com", body, sizeof body - 1,
                             status, sizeof status);
        EXPECT(sres == SMTP_OK,
               "relay routing: reverse reply delivered (reply relay)");
    }

    /* Reap (kill first: a child still blocked in accept() — i.e. the send
       failed at connect — must not wedge the test). */
    (void)kill(pid_local, SIGTERM);
    (void)kill(pid_reply, SIGTERM);
    (void)waitpid(pid_local, NULL, 0);
    (void)waitpid(pid_reply, NULL, 0);

    struct stub_result rA, rB;
    memset(&rA, 0, sizeof rA);
    memset(&rB, 0, sizeof rB);
    {
        int f = open(pathA, O_RDONLY);
        if (f >= 0) { (void)read(f, &rA, sizeof rA); close(f); }
        f = open(pathB, O_RDONLY);
        if (f >= 0) { (void)read(f, &rB, sizeof rB); close(f); }
    }
    unlink(pathA);
    unlink(pathB);

    EXPECT(strstr(rA.rcpt, "normal-dest@test.local") != NULL,
           "relay routing: local relay received the normal forward");
    EXPECT(strstr(rB.rcpt, "external@example.com") != NULL,
           "relay routing: reply relay received the reverse reply");
    EXPECT(strstr(rA.rcpt, "external@example.com") == NULL,
           "relay routing: local relay did NOT receive the reply");
    EXPECT(strstr(rB.rcpt, "normal-dest@test.local") == NULL,
           "relay routing: reply relay did NOT receive the normal forward");
}

/* smtp_relay_for picks reply_relay for reverse-alias replies and relay for
   normal forwards.  This is the pure decision behind queue_deliver_one's
   one-shot Config: the SELECTED relay's host/port/auth/tls are copied into
   one_shot.relay before smtp_out_send, so this single ternary is the whole
   reply-vs-forward routing switch. */
static void relay_select_test(void) {
    Config cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.relay.host = "local-relay";
    cfg.relay.port = 2526;
    cfg.reply_relay.host = "external-relay";
    cfg.reply_relay.port = 587;

    EXPECT(smtp_relay_for(&cfg, false) == &cfg.relay,
           "relay_for normal forward -> local relay");
    EXPECT(smtp_relay_for(&cfg, true) == &cfg.reply_relay,
           "relay_for reverse reply -> reply relay");
    EXPECT(strcmp(smtp_relay_for(&cfg, true)->host, "external-relay") == 0 &&
               smtp_relay_for(&cfg, true)->port == 587,
           "relay_for reply relay carries host:port");
    EXPECT(strcmp(smtp_relay_for(&cfg, false)->host, "local-relay") == 0 &&
               smtp_relay_for(&cfg, false)->port == 2526,
           "relay_for local relay carries host:port");
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

    /* reverse-alias reply vs normal forward relay selection */
    relay_select_test();

    /* end-to-end loopback routing (reply -> reply relay, forward -> local) */
    relay_routing_test();

    printf("\n%d checks, %d failed\n", nchecks, nfails);
    return nfails ? 1 : 0;
}
