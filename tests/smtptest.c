/* smtptest.c — raw-socket SMTP client for the visage S8 e2e harness.
 *
 * No external dependencies; pure POSIX sockets.  Performs a complete SMTP
 * submission dialogue against a server and asserts each expected reply code:
 *
 *   connect -> 220 greeting
 *          -> EHLO          -> 250
 *          -> MAIL FROM:<F>  -> 250
 *          -> RCPT TO:<T>    -> 250
 *          -> DATA           -> 354
 *          -> <body>.<CRLF>  -> 250
 *          -> QUIT
 *
 * Usage:  smtptest HOST PORT FROM TO BODYFILE
 *
 * Reads the RFC5322 message body from BODYFILE and sends it verbatim
 * (dot-stuffed, so a leading '.' on any line is doubled) followed by the
 * CRLF.CRLF terminator.  Every read/write is bounded by a timeout; a reply
 * code that does not match the expected value (or any I/O timeout / short
 * read) aborts with a nonzero exit status.
 *
 * Exit codes: 0 all replies matched; 1 SMTP/reply mismatch or I/O error;
 * 2 usage error. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <poll.h>

#define IO_TIMEOUT_MS 10000   /* per read/write timeout                    */
#define MAX_LINE      4096    /* max one SMTP line we will read            */
#define MAX_MSG       (1u << 20)  /* max body we will send                 */

/* ------------------------------------------------------------------ */
/* Bounded I/O                                                         */
/* ------------------------------------------------------------------ */

static int wait_fd(int fd, short events, int timeout_ms) {
    struct pollfd p;
    p.fd = fd;
    p.events = events;
    p.revents = 0;
    for (;;) {
        int r = poll(&p, 1, timeout_ms);
        if (r > 0) return 0;
        if (r == 0) return -1;              /* timed out */
        if (errno == EINTR) continue;
        return -1;
    }
}

static int send_all(int fd, const char *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        if (wait_fd(fd, POLLOUT, IO_TIMEOUT_MS) != 0) return -1;
        ssize_t n = send(fd, buf + off, len - off, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) return -1;
        off += (size_t)n;
    }
    return 0;
}

/* Read one CRLF- (or bare-LF-) terminated line into buf[0..bufsz).  Returns 0
   and NUL-terminates buf on success; -1 on timeout/EOF/too-long. */
static int read_line(int fd, char *buf, size_t bufsz) {
    size_t n = 0;
    for (;;) {
        if (n + 1 >= bufsz) return -1;      /* line too long */
        if (wait_fd(fd, POLLIN, IO_TIMEOUT_MS) != 0) return -1;
        ssize_t r = read(fd, buf + n, 1);
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (r == 0) return -1;              /* EOF */
        n++;
        if (buf[n - 1] == '\n') {
            buf[n] = '\0';
            return 0;
        }
    }
}

/* Read a complete (possibly multiline) SMTP reply.  The first line's code is
   returned via *code; multiline replies (ddd-...) are consumed until the
   terminating ddd-<space> line.  Returns 0 on success, -1 on error. */
static int read_reply(int fd, int *code) {
    int first = -1;
    for (;;) {
        char line[MAX_LINE];
        if (read_line(fd, line, sizeof line) != 0) return -1;
        if (line[0] < '0' || line[0] > '9') return -1;
        if (line[1] < '0' || line[1] > '9') return -1;
        if (line[2] < '0' || line[2] > '9') return -1;
        int c = (line[0] - '0') * 100 + (line[1] - '0') * 10 + (line[2] - '0');
        if (first < 0) {
            first = c;
        } else if (c != first) {
            return -1;                      /* code changed mid-reply */
        }
        char sep = line[3];
        if (sep == ' ') {                   /* final line */
            *code = c;
            return 0;
        }
        if (sep != '-') return -1;          /* malformed */
    }
}

/* Send cmd (may be NULL to skip) then read a reply and assert its code. */
static int exchange(int fd, const char *cmd, int want) {
    if (cmd && send_all(fd, cmd, strlen(cmd)) != 0) {
        fprintf(stderr, "smtptest: write failed: %s\n", strerror(errno));
        return 1;
    }
    int code = 0;
    if (read_reply(fd, &code) != 0) {
        fprintf(stderr, "smtptest: read failed / timed out\n");
        return 1;
    }
    if (code != want) {
        fprintf(stderr, "smtptest: expected reply %d, got %d\n", want, code);
        return 1;
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 6) {
        fprintf(stderr, "usage: smtptest HOST PORT FROM TO BODYFILE\n");
        return 2;
    }
    const char *host = argv[1];
    const char *port = argv[2];
    const char *from = argv[3];
    const char *to   = argv[4];
    const char *bfile = argv[5];

    /* Load the message body. */
    FILE *f = fopen(bfile, "rb");
    if (!f) {
        fprintf(stderr, "smtptest: cannot open %s: %s\n", bfile, strerror(errno));
        return 2;
    }
    char *body = malloc(MAX_MSG + 1);
    if (!body) { fclose(f); fprintf(stderr, "smtptest: out of memory\n"); return 1; }
    size_t blen = fread(body, 1, MAX_MSG, f);
    if (ferror(f)) { fclose(f); free(body); fprintf(stderr, "smtptest: read error on %s\n", bfile); return 1; }
    fclose(f);
    body[blen] = '\0';

    /* Resolve + connect. */
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, port, &hints, &res) != 0) {
        fprintf(stderr, "smtptest: cannot resolve %s:%s\n", host, port);
        free(body);
        return 1;
    }
    int fd = -1;
    for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
        int s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (s < 0) continue;
        if (connect(s, ai->ai_addr, ai->ai_addrlen) == 0) { fd = s; break; }
        close(s);
    }
    freeaddrinfo(res);
    if (fd < 0) {
        fprintf(stderr, "smtptest: connect to %s:%s failed: %s\n",
                host, port, strerror(errno));
        free(body);
        return 1;
    }

    int rc = 0;

    /* greeting: 220 */
    if (exchange(fd, NULL, 220) != 0) rc = 1;

    /* EHLO: 250 */
    if (rc == 0 && exchange(fd, "EHLO testclient\r\n", 250) != 0) rc = 1;

    /* MAIL FROM: 250 */
    if (rc == 0) {
        char cmd[MAX_LINE];
        snprintf(cmd, sizeof cmd, "MAIL FROM:<%s>\r\n", from);
        if (exchange(fd, cmd, 250) != 0) rc = 1;
    }

    /* RCPT TO: 250 */
    if (rc == 0) {
        char cmd[MAX_LINE];
        snprintf(cmd, sizeof cmd, "RCPT TO:<%s>\r\n", to);
        if (exchange(fd, cmd, 250) != 0) rc = 1;
    }

    /* DATA: 354 */
    if (rc == 0 && exchange(fd, "DATA\r\n", 354) != 0) rc = 1;

    /* Body (dot-stuffed) + CRLF.CRLF terminator, then 250. */
    if (rc == 0) {
        /* Dot-stuff: double any leading '.' on a line. */
        char *stuffed = NULL;
        size_t off = 0, cap = blen + blen + 8;   /* generous upper bound */
        stuffed = malloc(cap);
        if (!stuffed) {
            fprintf(stderr, "smtptest: out of memory\n");
            rc = 1;
        } else {
            size_t i = 0;
            bool at_bol = true;
            while (i < blen) {
                char ch = body[i];
                if (at_bol && ch == '.') stuffed[off++] = '.';
                stuffed[off++] = ch;
                at_bol = (ch == '\n');
                i++;
            }
            /* Ensure the body ends with CRLF before the terminator. */
            if (off == 0 || (stuffed[off - 1] != '\n'))
                stuffed[off++] = '\r', stuffed[off++] = '\n';
            if (send_all(fd, stuffed, off) != 0 ||
                send_all(fd, "\r\n.\r\n", 5) != 0) {
                fprintf(stderr, "smtptest: body write failed\n");
                rc = 1;
            }
            free(stuffed);
        }
        if (rc == 0 && exchange(fd, NULL, 250) != 0) rc = 1;
    }

    /* QUIT (best-effort). */
    (void)send_all(fd, "QUIT\r\n", 6);

    close(fd);
    free(body);
    return rc;
}
