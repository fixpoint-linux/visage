/* relay_fake.c — recording SMTP server for the visage S8 e2e harness.
 *
 * No external dependencies; pure POSIX sockets.  Listens on 127.0.0.1:PORT and
 * serves inbound SMTP submissions serially (one connection at a time) as the
 * fake outbound relay that the visage daemon forwards to.  For every accepted
 * connection it records the full client dialogue verbatim to
 * OUTDIR/dialogue-<seq>.txt and the de-dot-stuffed message body to
 * OUTDIR/msg-<seq>.eml, then replies with the standard SMTP codes
 * (220/250/354/250/221).  The sequence number increments per connection.
 *
 * The loop keeps accepting connections until terminated (SIGTERM/SIGINT) so a
 * single run can record the forward message and the reply round-trip.
 *
 * Usage:  relay_fake PORT OUTDIR
 *
 * Exit codes: 0 normal exit; 1 bind/setup failure; 2 usage error. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>

#define IO_TIMEOUT_MS 15000  /* per read/write timeout                    */
#define MAX_LINE      4096   /* max one SMTP command line                 */
#define GROW_STEP     8192   /* body buffer growth step                   */

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

static int reply(int fd, const char *line) {
    return send_all(fd, line, strlen(line));
}

/* Read one CRLF- (or bare-LF-) terminated line into a heap buffer.  On success
   returns 0 and sets *out to a malloc'd NUL-terminated string with the CRLF
   stripped; *len is the byte count excluding NUL.  Returns -1 on timeout/EOF. */
static int read_line(int fd, char **out, size_t *len) {
    size_t cap = 128, n = 0;
    char *buf = malloc(cap);
    if (!buf) return -1;
    for (;;) {
        if (n + 1 >= cap) {
            cap *= 2;
            char *nb = realloc(buf, cap);
            if (!nb) { free(buf); return -1; }
            buf = nb;
        }
        if (wait_fd(fd, POLLIN, IO_TIMEOUT_MS) != 0) { free(buf); return -1; }
        ssize_t r = read(fd, buf + n, 1);
        if (r < 0) {
            if (errno == EINTR) continue;
            free(buf);
            return -1;
        }
        if (r == 0) { free(buf); return -1; }   /* EOF */
        n++;
        if (buf[n - 1] == '\n') {
            buf[n] = '\0';
            /* strip trailing CR (if any) from the returned line */
            size_t outlen = n;
            if (outlen > 0 && buf[outlen - 1] == '\n') outlen--;
            if (outlen > 0 && buf[outlen - 1] == '\r') outlen--;
            buf[outlen] = '\0';
            *out = buf;
            *len = outlen;
            return 0;
        }
    }
}

static int append_bytes(char **buf, size_t *len, size_t *cap,
                        const char *data, size_t n) {
    if (*len + n + 1 > *cap) {
        size_t ncap = *cap ? *cap : GROW_STEP;
        while (*len + n + 1 > ncap) ncap *= 2;
        char *nb = realloc(*buf, ncap);
        if (!nb) return -1;
        *buf = nb;
        *cap = ncap;
    }
    memcpy(*buf + *len, data, n);
    *len += n;
    (*buf)[*len] = '\0';
    return 0;
}

/* Handle one fully-established client connection.  Records the dialogue to
   dialogue-<seq>.txt and the de-dotted body to msg-<seq>.eml. */
static void handle_conn(int fd, const char *outdir, unsigned seq) {
    char path[1024];
    int rn;
    FILE *dlog = NULL, *mfile = NULL;

    /* Open the recording files for this connection. */
    rn = snprintf(path, sizeof path, "%s/dialogue-%u.txt", outdir, seq);
    if (rn > 0 && (size_t)rn < sizeof path) dlog = fopen(path, "w");
    rn = snprintf(path, sizeof path, "%s/msg-%u.eml", outdir, seq);
    if (rn > 0 && (size_t)rn < sizeof path) mfile = fopen(path, "w");

    if (dlog) fprintf(dlog, "C: <connect>\n");

    /* Greeting. */
    if (reply(fd, "220 relay_fake ESMTP ready\r\n") != 0) {
        if (dlog) fprintf(dlog, "S: 220 relay_fake ESMTP ready\n");
        goto done;
    }
    if (dlog) fprintf(dlog, "S: 220 relay_fake ESMTP ready\n");

    for (;;) {
        char *line = NULL;
        size_t llen = 0;
        if (read_line(fd, &line, &llen) != 0) break;
        if (dlog) { fwrite(line, 1, llen, dlog); fputc('\n', dlog); }

        if (strncmp(line, "QUIT", 4) == 0) {
            reply(fd, "221 2.0.0 Bye\r\n");
            free(line);
            break;
        } else if (strncmp(line, "EHLO", 4) == 0 ||
                   strncmp(line, "HELO", 4) == 0) {
            reply(fd, "250 relay_fake\r\n");
            free(line);
        } else if (strncmp(line, "MAIL", 4) == 0) {
            reply(fd, "250 2.1.0 OK\r\n");
            free(line);
        } else if (strncmp(line, "RCPT", 4) == 0) {
            reply(fd, "250 2.1.5 OK\r\n");
            free(line);
        } else if (strncmp(line, "DATA", 4) == 0) {
            free(line);
            if (reply(fd, "354 End data with <CR><LF>.<CR><LF>\r\n") != 0)
                break;
            if (dlog) fprintf(dlog, "S: 354 End data\n");
            /* Read the message body until the CRLF.CRLF terminator. */
            char *body = NULL;
            size_t blen = 0, bcap = 0;
            bool term = false;
            for (;;) {
                char *bl = NULL;
                size_t bln = 0;
                if (read_line(fd, &bl, &bln) != 0) { free(bl); break; }
                if (dlog) { fwrite(bl, 1, bln, dlog); fputc('\n', dlog); }
                if (bln == 1 && bl[0] == '.') {   /* terminator */
                    free(bl);
                    term = true;
                    break;
                }
                /* De-dot-stuff: strip one leading '.' from stuffed lines. */
                size_t start = 0;
                if (bln >= 2 && bl[0] == '.' && bl[1] == '.') start = 1;
                if (append_bytes(&body, &blen, &bcap, bl + start, bln - start) != 0 ||
                    append_bytes(&body, &blen, &bcap, "\n", 1) != 0) {
                    free(bl);
                    free(body);
                    break;
                }
                free(bl);
            }
            if (term && mfile && body) {
                fwrite(body, 1, blen, mfile);
            }
            free(body);
            reply(fd, "250 2.0.0 OK queued\r\n");
            if (dlog) fprintf(dlog, "S: 250 2.0.0 OK queued\n");
        } else if (strncmp(line, "RSET", 4) == 0 ||
                   strncmp(line, "NOOP", 4) == 0) {
            reply(fd, "250 2.0.0 OK\r\n");
            free(line);
        } else {
            /* Unknown / AUTH: refuse politely. */
            reply(fd, "502 5.5.1 Command not implemented\r\n");
            free(line);
        }
    }

done:
    if (dlog) { fflush(dlog); fclose(dlog); }
    if (mfile) { fflush(mfile); fclose(mfile); }
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: relay_fake PORT OUTDIR\n");
        return 2;
    }
    long port = atol(argv[1]);
    const char *outdir = argv[2];
    if (port <= 0 || port > 65535) {
        fprintf(stderr, "relay_fake: invalid port %s\n", argv[1]);
        return 2;
    }

    int ls = socket(AF_INET, SOCK_STREAM, 0);
    if (ls < 0) {
        fprintf(stderr, "relay_fake: socket: %s\n", strerror(errno));
        return 1;
    }
    int one = 1;
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)port);
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(ls, (struct sockaddr *)&sa, sizeof sa) != 0) {
        fprintf(stderr, "relay_fake: bind %s:%ld: %s\n",
                "127.0.0.1", port, strerror(errno));
        close(ls);
        return 1;
    }
    if (listen(ls, 8) != 0) {
        fprintf(stderr, "relay_fake: listen: %s\n", strerror(errno));
        close(ls);
        return 1;
    }

    fprintf(stderr, "relay_fake: listening on 127.0.0.1:%ld recording to %s\n",
            port, outdir);

    unsigned seq = 0;
    for (;;) {
        int cfd = accept(ls, NULL, NULL);
        if (cfd < 0) {
            if (errno == EINTR) continue;
            break;
        }
        seq++;
        handle_conn(cfd, outdir, seq);
        close(cfd);
    }
    close(ls);
    return 0;
}
