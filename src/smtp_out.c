/* smtp_out.c — outbound SMTP relay client (slice S4).
 *
 * Full delivery dialogue against Config.relay:
 *   connect (bounded timeout) -> 220 greeting -> EHLO -> [AUTH PLAIN] ->
 *   MAIL FROM -> RCPT TO -> DATA -> dot-stuffed body -> CRLF.CRLF ->
 *   final reply -> QUIT -> close.
 *
 * Reply-code mapping: 2xx/3xx = ok, 4xx = tempfail, 5xx = permfail. Connect
 * failures and 4xx replies are retried up to Config.relay.retries additional
 * times with exponential backoff; 5xx is permanent and is never retried.
 * STARTTLS is deferred: any Config.relay.tls other than "none" is rejected
 * with SMTP_ERROR ("tls not supported").
 *
 * Bounds: every server line is capped at SMTP_MAX_LINE bytes; each read/write
 * is bounded by Config.limits.cmd_timeout (the DATA payload uses data_timeout,
 * falling back to cmd_timeout); the connect uses a fixed
 * SMTP_CONNECT_TIMEOUT_MS. No unbounded buffers are used. */
#include "visage.h"
#include "smtp.h"
#include "mail.h"

#include <sys/socket.h>
#include <netdb.h>
#include <poll.h>
#include <fcntl.h>

#define SMTP_CONNECT_TIMEOUT_MS 10000  /* bounded connect timeout (10 s)   */
#define SMTP_DEFAULT_TIMEOUT    60     /* fallback when a *timeout == 0     */
#define SMTP_MAX_CRED_LEN       4096   /* sanity cap on AUTH PLAIN payload  */
#define SMTP_WRITE_CHUNK        65536  /* bound each blocking send()        */

static const char b64_tab[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* ------------------------------------------------------------------ */
/* Shared helpers (declared in smtp.h)                                */
/* ------------------------------------------------------------------ */

const char *smtp_status_str(int status) {
    switch (status) {
    case SMTP_OK:       return "ok";
    case SMTP_TEMPFAIL: return "tempfail";
    case SMTP_PERMFAIL: return "permfail";
    case SMTP_ERROR:    return "error";
    default:            return "unknown";
    }
}

int smtp_reply_code(const char *line, int *code) {
    if (!line || !code) return -1;
    if (line[0] < '0' || line[0] > '9') return -1;
    if (line[1] < '0' || line[1] > '9') return -1;
    if (line[2] < '0' || line[2] > '9') return -1;
    *code = (line[0] - '0') * 100 + (line[1] - '0') * 10 + (line[2] - '0');
    return 0;
}

int smtp_b64_encode(const void *in, size_t inlen, char *out, size_t outsz,
                    size_t *outlen) {
    if (outlen) *outlen = 0;
    if (!in || !out || !outlen) return -1;
    if (inlen > SIZE_MAX / 2) return -1;    /* guard the size arithmetic      */
    size_t req = ((inlen + 2) / 3) * 4 + 1; /* encoded length + NUL terminator */
    if (outsz < req) return -1;

    const unsigned char *p = (const unsigned char *)in;
    size_t i = 0, o = 0;
    while (i + 3 <= inlen) {
        uint32_t v = ((uint32_t)p[i] << 16) | ((uint32_t)p[i + 1] << 8) |
                     (uint32_t)p[i + 2];
        out[o++] = b64_tab[(v >> 18) & 0x3f];
        out[o++] = b64_tab[(v >> 12) & 0x3f];
        out[o++] = b64_tab[(v >> 6) & 0x3f];
        out[o++] = b64_tab[v & 0x3f];
        i += 3;
    }
    if (inlen - i == 1) {
        uint32_t v = (uint32_t)p[i] << 16;
        out[o++] = b64_tab[(v >> 18) & 0x3f];
        out[o++] = b64_tab[(v >> 12) & 0x3f];
        out[o++] = '=';
        out[o++] = '=';
    } else if (inlen - i == 2) {
        uint32_t v = ((uint32_t)p[i] << 16) | ((uint32_t)p[i + 1] << 8);
        out[o++] = b64_tab[(v >> 18) & 0x3f];
        out[o++] = b64_tab[(v >> 12) & 0x3f];
        out[o++] = b64_tab[(v >> 6) & 0x3f];
        out[o++] = '=';
    }
    out[o] = '\0';
    *outlen = o;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Small internal helpers                                             */
/* ------------------------------------------------------------------ */

static void set_status(char *out, size_t outsz, const char *msg) {
    if (!out || outsz == 0) return;
    snprintf(out, outsz, "%s", msg ? msg : "");
}

static bool has_crlf(const char *s) {
    if (!s) return false;
    return strchr(s, '\r') != NULL || strchr(s, '\n') != NULL;
}

/* Map a 3-digit SMTP reply code to its delivery class. */
static int smtp_class(int code) {
    if (code >= 200 && code < 400) return SMTP_OK;
    if (code >= 400 && code < 500) return SMTP_TEMPFAIL;
    if (code >= 500 && code < 600) return SMTP_PERMFAIL;
    return SMTP_ERROR;
}

/* Convert a timeout in seconds to poll() milliseconds (int32_t-bounded).
   0 seconds means "no timeout" (poll blocks indefinitely). */
static int timeout_ms(uint32_t seconds) {
    if (seconds == 0) return -1;
    uint64_t ms = (uint64_t)seconds * 1000u;
    if (ms > 2147483647) ms = 2147483647;
    return (int)ms;
}

/* ------------------------------------------------------------------ */
/* Bounded I/O primitives                                             */
/* ------------------------------------------------------------------ */

/* Read one CRLF-terminated line (tolerating a bare LF) into buf[0..bufsz).
   Returns 0 and sets *outlen (including the terminator) on success; -1 on
   timeout, EOF, I/O error, or a line that would exceed bufsz bytes. */
static int smtp_read_line(int fd, uint32_t tmo, char *buf, size_t bufsz,
                          size_t *outlen) {
    size_t n = 0;
    for (;;) {
        if (n >= bufsz) return -1;                 /* line too long */
        struct pollfd pfd;
        pfd.fd = fd;
        pfd.events = POLLIN;
        pfd.revents = 0;
        int pr = poll(&pfd, 1, timeout_ms(tmo));
        if (pr < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (pr == 0) return -1;                    /* timed out */
        ssize_t r = read(fd, buf + n, 1);
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (r == 0) return -1;                     /* EOF */
        n++;
        if (n >= 2 && buf[n - 2] == '\r' && buf[n - 1] == '\n') {
            *outlen = n;
            return 0;
        }
        if (buf[n - 1] == '\n') {                  /* tolerate bare LF */
            *outlen = n;
            return 0;
        }
    }
}

/* Read one complete (possibly multi-line) SMTP reply. The first line's text
   (after "ddd " or "ddd-") is copied into text[0..textsz). Returns 0 and
   sets *code on success; -1 on any error or malformed reply. */
static int smtp_read_reply(int fd, uint32_t tmo, int *code, char *text,
                           size_t textsz) {
    if (code) *code = 0;
    if (text && textsz) text[0] = '\0';

    int first = -1;
    for (;;) {
        char line[SMTP_MAX_LINE];
        size_t n = 0;
        if (smtp_read_line(fd, tmo, line, sizeof line, &n) != 0)
            return -1;

        int lc = 0;
        if (n < 4 || smtp_reply_code(line, &lc) != 0)
            return -1;
        char sep = line[3];
        if (sep != ' ' && sep != '-')
            return -1;

        if (first < 0) {
            first = lc;
            size_t tlen = n;
            if (tlen >= 2 && line[tlen - 2] == '\r' && line[tlen - 1] == '\n')
                tlen -= 2;
            else if (tlen >= 1 && line[tlen - 1] == '\n')
                tlen -= 1;
            size_t start = 4;
            size_t copylen = (tlen > start) ? (tlen - start) : 0;
            if (text && textsz > 0) {
                if (copylen > textsz - 1) copylen = textsz - 1;
                memcpy(text, line + start, copylen);
                text[copylen] = '\0';
            }
        } else if (lc != first) {
            return -1;                             /* code changed mid-reply */
        }

        if (sep == ' ') {
            *code = first;
            return 0;
        }
    }
}

/* Write exactly len bytes, bounded by tmo seconds, handling partial writes
   and EINTR. Returns 0 on success, -1 on timeout/error. */
static int smtp_write_all(int fd, const char *buf, size_t len, uint32_t tmo) {
    size_t off = 0;
    while (off < len) {
        struct pollfd pfd;
        pfd.fd = fd;
        pfd.events = POLLOUT;
        pfd.revents = 0;
        int pr = poll(&pfd, 1, timeout_ms(tmo));
        if (pr < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (pr == 0) return -1;                    /* timed out */
        size_t chunk = len - off;
        if (chunk > SMTP_WRITE_CHUNK) chunk = SMTP_WRITE_CHUNK;
        ssize_t w = send(fd, buf + off, chunk, MSG_NOSIGNAL);
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (w == 0) return -1;
        off += (size_t)w;
    }
    return 0;
}

/* Send one command line (including its CRLF) and read the reply into *code.
   The first reply line's text is copied into status_out. Returns 0 on
   success, -1 on a write/read failure. */
static int smtp_exchange(int fd, uint32_t tmo, const char *cmd, int *code,
                         char *status_out, size_t status_sz) {
    if (smtp_write_all(fd, cmd, strlen(cmd), tmo) != 0) {
        set_status(status_out, status_sz, "write failed");
        return -1;
    }
    char text[SMTP_MAX_LINE];
    if (smtp_read_reply(fd, tmo, code, text, sizeof text) != 0) {
        set_status(status_out, status_sz, "read failed");
        return -1;
    }
    set_status(status_out, status_sz, text);
    return 0;
}

/* Build "<verb><addr>\r\n" into buf (bounded). Returns 0, or -1 if it would
   not fit. */
static int build_addr_cmd(char *buf, size_t bufsz, const char *verb,
                          const char *addr) {
    int n = snprintf(buf, bufsz, "%s<%s>\r\n", verb, addr);
    if (n < 0 || (size_t)n >= bufsz) return -1;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Connect                                                            */
/* ------------------------------------------------------------------ */

/* Blocking TCP connect to relay.host:port with a bounded timeout. Tries each
   address returned by getaddrinfo in turn. Returns the connected fd, or -1
   (with a message in status_out). */
static int smtp_connect(const Config *c, char *status_out, size_t status_sz) {
    char portstr[16];
    snprintf(portstr, sizeof portstr, "%u", c->relay.port);

    struct addrinfo hints;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo *res = NULL;
    int gai = getaddrinfo(c->relay.host, portstr, &hints, &res);
    if (gai != 0) {
        set_status(status_out, status_sz, gai_strerror(gai));
        return -1;
    }

    int fd = -1;
    for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
        int s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (s < 0) continue;

        int fl = fcntl(s, F_GETFL, 0);
        if (fl < 0 || fcntl(s, F_SETFL, fl | (int)O_NONBLOCK) < 0) {
            close(s);
            continue;
        }

        int rc = connect(s, ai->ai_addr, ai->ai_addrlen);
        if (rc < 0 && errno != EINPROGRESS) {
            close(s);
            continue;
        }

        struct pollfd pfd;
        pfd.fd = s;
        pfd.events = POLLOUT;
        pfd.revents = 0;
        if (poll(&pfd, 1, SMTP_CONNECT_TIMEOUT_MS) <= 0) {
            close(s);
            continue;
        }

        int soerr = 0;
        uint32_t slen = sizeof soerr;
        if (getsockopt(s, SOL_SOCKET, SO_ERROR, &soerr, &slen) < 0 ||
            soerr != 0) {
            close(s);
            continue;
        }

        if (fcntl(s, F_SETFL, fl) < 0) {           /* restore blocking mode */
            close(s);
            continue;
        }

        fd = s;
        break;
    }
    freeaddrinfo(res);

    if (fd < 0)
        set_status(status_out, status_sz, "connect failed");
    return fd;
}

/* ------------------------------------------------------------------ */
/* AUTH PLAIN                                                         */
/* ------------------------------------------------------------------ */

/* Perform "AUTH PLAIN <base64(authzid NUL authcid NUL passwd)>". We use
   authzid = authcid = username. Returns a status class (SMTP_OK on 235,
   SMTP_TEMPFAIL on 4xx, SMTP_PERMFAIL on 5xx, SMTP_ERROR otherwise). */
static int smtp_auth_plain(int fd, uint32_t tmo, const ConfigRelayAuth *auth,
                           char *status_out, size_t status_sz) {
    const char *u = auth->username ? auth->username : "";
    const char *p = auth->password ? auth->password : "";
    size_t ulen = strlen(u);
    size_t plen = strlen(p);
    if (ulen > SMTP_MAX_CRED_LEN || plen > SMTP_MAX_CRED_LEN) {
        set_status(status_out, status_sz, "auth credentials too long");
        return SMTP_ERROR;
    }

    size_t plainlen = 1 + ulen + 1 + plen;   /* \0 + authcid + \0 + passwd */
    if (plainlen > SMTP_MAX_CRED_LEN) {
        set_status(status_out, status_sz, "auth credentials too long");
        return SMTP_ERROR;
    }

    char *plain = malloc(plainlen);
    if (!plain) {
        set_status(status_out, status_sz, "out of memory");
        return SMTP_ERROR;
    }
    char *w = plain;
    *w++ = '\0';                         /* empty authzid (RFC 4616-compliant) */
    memcpy(w, u, ulen); w += ulen;
    *w++ = '\0';
    memcpy(w, p, plen); w += plen;

    size_t b64cap = ((plainlen + 2) / 3) * 4;
    char *b64 = malloc(b64cap + 1);
    if (!b64) {
        free(plain);
        set_status(status_out, status_sz, "out of memory");
        return SMTP_ERROR;
    }
    size_t elen = 0;
    if (smtp_b64_encode(plain, plainlen, b64, b64cap + 1, &elen) != 0) {
        free(plain);
        free(b64);
        set_status(status_out, status_sz, "base64 encode failed");
        return SMTP_ERROR;
    }
    free(plain);

    /* "AUTH PLAIN " (11 bytes) + encoded + CRLF */
    size_t cmdlen = 11 + elen + 2;
    char *cmd = malloc(cmdlen + 1);
    if (!cmd) {
        free(b64);
        set_status(status_out, status_sz, "out of memory");
        return SMTP_ERROR;
    }
    memcpy(cmd, "AUTH PLAIN ", 11);
    memcpy(cmd + 11, b64, elen);
    memcpy(cmd + 11 + elen, "\r\n", 2);
    cmd[cmdlen] = '\0';
    free(b64);

    int code = 0;
    int r = smtp_exchange(fd, tmo, cmd, &code, status_out, status_sz);
    free(cmd);
    if (r != 0) return SMTP_TEMPFAIL;
    if (code != 235)
        return (smtp_class(code) == SMTP_OK) ? SMTP_ERROR : smtp_class(code);
    return SMTP_OK;
}

/* ------------------------------------------------------------------ */
/* DATA payload                                                       */
/* ------------------------------------------------------------------ */

/* Dot-stuff the body and send it followed by the "CRLF . CRLF" terminator. */
static int smtp_send_data(int fd, uint32_t dtmo, const char *body,
                          size_t bodylen) {
    char *stuffed = NULL;
    size_t slen = 0;
    if (mail_stuff_dots(body, bodylen, &stuffed, &slen) != 0)
        return -1;
    int rc = smtp_write_all(fd, stuffed, slen, dtmo);
    if (rc == 0)
        rc = smtp_write_all(fd, "\r\n.\r\n", 5, dtmo);
    mail_free(stuffed);
    return rc;
}

/* ------------------------------------------------------------------ */
/* Dialogue                                                           */
/* ------------------------------------------------------------------ */

static void smtp_backoff(uint32_t attempt) {
    /* attempt is 1-based: sleep 1s, 2s, 4s, 8s, 16s, then capped at 30s. */
    uint32_t exp = attempt - 1;
    uint32_t sec = (exp > 4) ? 30u : (1u << exp);
    sleep(sec);
}

static int smtp_dialogue(int fd, const Config *c, uint32_t tmo, uint32_t dtmo,
                         const char *body, size_t bodylen,
                         const char *mail_cmd, const char *rcpt_cmd,
                         char *status_out, size_t status_sz) {
    char text[SMTP_MAX_LINE];
    int code = 0;
    int cls;

    /* 1. greeting: expect 220 */
    if (smtp_read_reply(fd, tmo, &code, text, sizeof text) != 0) {
        set_status(status_out, status_sz, "no greeting");
        return SMTP_TEMPFAIL;
    }
    set_status(status_out, status_sz, text);
    if (code != 220)
        return (code >= 400) ? smtp_class(code) : SMTP_ERROR;

    /* 2. EHLO */
    const char *helo = (c->hostname && *c->hostname) ? c->hostname : "localhost";
    char ehlo_cmd[SMTP_MAX_LINE];
    int n = snprintf(ehlo_cmd, sizeof ehlo_cmd, "EHLO %s\r\n", helo);
    if (n < 0 || (size_t)n >= sizeof ehlo_cmd) {
        set_status(status_out, status_sz, "EHLO name too long");
        return SMTP_ERROR;
    }
    if (smtp_exchange(fd, tmo, ehlo_cmd, &code, status_out, status_sz) != 0)
        return SMTP_TEMPFAIL;
    if ((cls = smtp_class(code)) != SMTP_OK)
        return cls;

    /* 3. AUTH PLAIN (if enabled) */
    if (c->relay.auth.enabled) {
        cls = smtp_auth_plain(fd, tmo, &c->relay.auth, status_out, status_sz);
        if (cls != SMTP_OK)
            return cls;
    }

    /* 4. MAIL FROM */
    if (smtp_exchange(fd, tmo, mail_cmd, &code, status_out, status_sz) != 0)
        return SMTP_TEMPFAIL;
    if ((cls = smtp_class(code)) != SMTP_OK)
        return cls;

    /* 5. RCPT TO */
    if (smtp_exchange(fd, tmo, rcpt_cmd, &code, status_out, status_sz) != 0)
        return SMTP_TEMPFAIL;
    if ((cls = smtp_class(code)) != SMTP_OK)
        return cls;

    /* 6. DATA: expect 354 */
    if (smtp_exchange(fd, tmo, "DATA\r\n", &code, status_out, status_sz) != 0)
        return SMTP_TEMPFAIL;
    if (code != 354)
        return (smtp_class(code) == SMTP_OK) ? SMTP_ERROR : smtp_class(code);

    /* 7. dot-stuffed body + terminator */
    if (smtp_send_data(fd, dtmo, body, bodylen) != 0) {
        set_status(status_out, status_sz, "data write failed");
        return SMTP_TEMPFAIL;
    }

    /* 8. final reply: 250/251 = accepted */
    if (smtp_read_reply(fd, tmo, &code, text, sizeof text) != 0) {
        set_status(status_out, status_sz, "no reply after DATA");
        return SMTP_TEMPFAIL;
    }
    set_status(status_out, status_sz, text);
    if (code != 250 && code != 251)
        return (smtp_class(code) == SMTP_OK) ? SMTP_ERROR : smtp_class(code);

    /* 9. QUIT (best-effort; do not block waiting for the 221) */
    (void)smtp_write_all(fd, "QUIT\r\n", 6, tmo);

    return SMTP_OK;
}

/* ------------------------------------------------------------------ */
/* Public entry point                                                 */
/* ------------------------------------------------------------------ */

int smtp_out_send(Store *s, const Config *c, const char *from, const char *to,
                  const char *body, size_t bodylen, char *status_out,
                  size_t status_sz) {
    (void)s;   /* reserved for delivery logging (later slices) */
    set_status(status_out, status_sz, "");

    if (!c || !from || !to || !body) {
        set_status(status_out, status_sz, "bad arguments");
        return SMTP_ERROR;
    }
    if (!c->relay.host || !*c->relay.host) {
        set_status(status_out, status_sz, "no relay host configured");
        return SMTP_ERROR;
    }
    if (c->relay.tls && strcmp(c->relay.tls, "none") != 0) {
        set_status(status_out, status_sz, "tls not supported");
        return SMTP_ERROR;
    }
    if (has_crlf(from) || has_crlf(to)) {
        set_status(status_out, status_sz, "invalid envelope address");
        return SMTP_ERROR;
    }
    if (!*from || !*to) {
        set_status(status_out, status_sz, "empty envelope address");
        return SMTP_ERROR;
    }

    uint32_t tmo = c->limits.cmd_timeout ? c->limits.cmd_timeout
                                         : SMTP_DEFAULT_TIMEOUT;
    uint32_t dtmo = c->limits.data_timeout ? c->limits.data_timeout : tmo;

    char mail_cmd[SMTP_MAX_LINE];
    char rcpt_cmd[SMTP_MAX_LINE];
    if (build_addr_cmd(mail_cmd, sizeof mail_cmd, "MAIL FROM:", from) != 0 ||
        build_addr_cmd(rcpt_cmd, sizeof rcpt_cmd, "RCPT TO:", to) != 0) {
        set_status(status_out, status_sz, "envelope address too long");
        return SMTP_ERROR;
    }

    uint32_t retries = c->relay.retries;
    for (uint32_t attempt = 0;; attempt++) {
        if (attempt > 0)
            smtp_backoff(attempt);

        int fd = smtp_connect(c, status_out, status_sz);
        if (fd < 0) {
            if (attempt >= retries)
                return SMTP_TEMPFAIL;
            continue;
        }

        int rc = smtp_dialogue(fd, c, tmo, dtmo, body, bodylen, mail_cmd,
                               rcpt_cmd, status_out, status_sz);
        close(fd);

        if (rc == SMTP_OK || rc == SMTP_PERMFAIL || rc == SMTP_ERROR)
            return rc;
        /* SMTP_TEMPFAIL (4xx or transport): retry if attempts remain */
        if (attempt >= retries)
            return SMTP_TEMPFAIL;
    }
}
