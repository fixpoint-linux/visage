/* smtp_in.c — inbound SMTP server (slice S5).
 *
 * A poll()-based, single-threaded event loop (dnsd precedent; no fork/thread —
 * datalog-dafsa is single-writer). Accepts connections on Config.listen, runs
 * a per-connection SMTP state machine (220 greet -> HELO/EHLO -> MAIL -> RCPT*
 * -> DATA -> RSET/NOOP/QUIT), enforces every configured limit, de-dot-stuffs
 * the DATA payload, spools a durable copy, and forwards each message through
 * the alias/reply routing (see reply.h) via smtp_out_send.
 *
 * Bounds: every command line is capped at SMTP_MAX_LINE; the DATA payload is
 * capped at twice the configured message size (dot-stuffing can add ~1 byte
 * per line, so a 2x ceiling is always safe) and re-checked after de-dot;
 * recipient count and per-line length are enforced during accumulation.
 * Command and DATA reads are idle-timed with Config.limits.cmd_timeout and
 * data_timeout respectively. */
#include "visage.h"
#include "smtp.h"
#include "mail.h"
#include "reply.h"
#include "dkim.h"

#include <sys/socket.h>
#include <netdb.h>
#include <poll.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <time.h>

/* ------------------------------------------------------------------ */
/* Constants                                                          */
/* ------------------------------------------------------------------ */

#define SMTP_IN_DEFAULT_MAX_MSG (32u * 1024u * 1024u) /* fallback max message */
#define SMTP_IN_DEFAULT_TIMEOUT 60                    /* fallback idle timeout */
#define SMTP_IN_LISTEN_BACKLOG 128
#define SMTP_IN_RECV_CHUNK     4096

/* log relation "dir" column codes (raw u32). */
#define LOG_DIR_IN  1u
#define LOG_DIR_OUT 2u

/* Session states. */
enum { ST_INIT = 0, ST_HELO, ST_MAIL, ST_DATA };

/* ------------------------------------------------------------------ */
/* Extra-fd hook                                                      */
/* ------------------------------------------------------------------ */

/* Another subsystem (the admin HTTP listener) can register a listener fd whose
   readiness is multiplexed into this loop via smtp_in_add_extra_fd.  Because
   datalog is single-writer, SMTP and HTTP share one poll loop. */
#define SMTP_IN_MAX_EXTRA 8

typedef struct ExtraFd {
    int      fd;
    void   (*cb)(int fd, void *user);
    void    *user;
} ExtraFd;

static ExtraFd s_extra[SMTP_IN_MAX_EXTRA];
static size_t  s_nextra;

int smtp_in_add_extra_fd(int fd, void (*cb)(int fd, void *user), void *user) {
    if (fd < 0 || !cb || s_nextra >= SMTP_IN_MAX_EXTRA) return VISAGE_EPARAM;
    s_extra[s_nextra].fd = fd;
    s_extra[s_nextra].cb = cb;
    s_extra[s_nextra].user = user;
    s_nextra++;
    return VISAGE_OK;
}

/* ------------------------------------------------------------------ */
/* Per-connection HTTP registration (R4)                              */
/* ------------------------------------------------------------------ */

/* The admin HTTP server (http.c) registers each accepted connection here so
   its fd is multiplexed into this poll loop alongside SMTP connections — a
   NON-BLOCKING HTTP state machine that shares the loop fairly with SMTP
   (datalog is single-writer, so everything runs on one thread).  Handles are
   stable indices into a fixed slot table; a slot is released by
   smtp_in_http_close() (the caller owns and closes the fd itself). */
#define SMTP_IN_MAX_HTTP 32   /* max concurrent admin HTTP conns (HTTP_MAX_CONNS) */

typedef struct HttpSlot {
    bool     used;
    int      fd;                /* owned by the HTTP layer; polled here */
    short    events;            /* POLLIN / POLLOUT to poll for */
    uint32_t idle_timeout_sec;  /* 0 = no idle timeout */
    time_t   last_act;          /* last readable/writable dispatch (idle clock) */
    void   (*on_readable)(int fd, void *user);
    void   (*on_writable)(int fd, void *user);
    void   (*on_closed)(int fd, void *user);   /* idle-timeout notification */
    void    *user;
} HttpSlot;

static HttpSlot s_http[SMTP_IN_MAX_HTTP];

int smtp_in_register_http_conn(int fd,
        void (*on_readable)(int fd, void *user),
        void (*on_writable)(int fd, void *user),
        void (*on_closed)(int fd, void *user),
        uint32_t idle_timeout_sec, void *user) {
    int i;
    if (fd < 0 || !on_readable || !on_writable) return VISAGE_EPARAM;
    for (i = 0; i < SMTP_IN_MAX_HTTP; i++) {
        if (!s_http[i].used) {
            s_http[i].used = true;
            s_http[i].fd = fd;
            s_http[i].events = POLLIN;
            s_http[i].idle_timeout_sec = idle_timeout_sec;
            s_http[i].last_act = time(NULL);
            s_http[i].on_readable = on_readable;
            s_http[i].on_writable = on_writable;
            s_http[i].on_closed = on_closed;
            s_http[i].user = user;
            return i;   /* the handle */
        }
    }
    return VISAGE_ENOMEM;   /* connection table full */
}

void smtp_in_http_set_events(int handle, short events) {
    if (handle < 0 || handle >= SMTP_IN_MAX_HTTP) return;
    if (!s_http[handle].used) return;
    s_http[handle].events = events;
}

void smtp_in_http_close(int handle) {
    if (handle < 0 || handle >= SMTP_IN_MAX_HTTP) return;
    s_http[handle].used = false;
    s_http[handle].fd = -1;
    s_http[handle].events = 0;
    s_http[handle].on_readable = NULL;
    s_http[handle].on_writable = NULL;
    s_http[handle].on_closed = NULL;
    s_http[handle].user = NULL;
}

/* Idle-timeout a HTTP conn: release its slot, then notify the owner so it can
   close the fd and free its per-connection state. */
static void http_slot_idle_close(int handle) {
    int fd = s_http[handle].fd;
    void (*on_closed)(int, void *) = s_http[handle].on_closed;
    void *user = s_http[handle].user;
    smtp_in_http_close(handle);
    if (on_closed) on_closed(fd, user);
}

/* ------------------------------------------------------------------ */
/* Per-connection state                                               */
/* ------------------------------------------------------------------ */

typedef struct Conn {
    int    fd;
    int    state;              /* ST_* */
    bool   closed;             /* close once the output buffer drains */
    char  *from;               /* reverse-path (owned; "" = null path) */
    char **rcpts;              /* accepted RCPT addresses (owned strings) */
    size_t nrcpts, rcpt_cap;
    char  *in;                 /* command input buffer (owned) */
    size_t in_len, in_cap;
    char  *data;               /* DATA input buffer (owned, dot-stuffed) */
    size_t data_len, data_cap;
    char  *out;                /* reply output buffer (owned) */
    size_t out_len, out_off, out_cap;
    time_t last_act;           /* last activity (idle-timeout clock) */
} Conn;

typedef struct Server {
    const Config *cfg;
    Store        *store;
    int           listen_fd;
    Conn        **conns;
    size_t        nconns, conn_cap;
    /* effective limits (0 replaced with defaults) */
    uint32_t max_line, max_msg, max_rcpts, cmd_tmo, data_tmo;
    uint64_t raw_cap;          /* bounded DATA accumulation ceiling */
} Server;

/* ------------------------------------------------------------------ */
/* Small helpers                                                      */
/* ------------------------------------------------------------------ */

/* ASCII case-insensitive compare over exactly n bytes (stops at NUL). */
static int ascii_strncasecmp(const char *a, const char *b, size_t n) {
    while (n-- > 0) {
        char ca = *a++;
        char cb = *b++;
        if (ca >= 'A' && ca <= 'Z') ca = (char)(ca + 32);
        if (cb >= 'A' && cb <= 'Z') cb = (char)(cb + 32);
        if (ca != cb) return (unsigned char)ca - (unsigned char)cb;
        if (ca == '\0') return 0;
    }
    return 0;
}

/* ASCII case-insensitive full-string equality. */
static bool ascii_ieq_str(const char *a, const char *b) {
    while (*a && *b) {
        char ca = *a++, cb = *b++;
        if (ca >= 'A' && ca <= 'Z') ca = (char)(ca + 32);
        if (cb >= 'A' && cb <= 'Z') cb = (char)(cb + 32);
        if (ca != cb) return false;
    }
    return *a == *b;
}

/* Append n bytes to a heap buffer (NUL-terminated). Grows geometrically.
   Returns 0, or -1 on overflow/allocation failure. */
static int buf_append(char **buf, size_t *len, size_t *cap,
                      const char *src, size_t n) {
    size_t need, nc;
    char *nb;
    if (n == 0) return 0;
    need = *len + n;
    if (need + 1 > *cap) {
        nc = *cap ? *cap : 256;
        while (nc < need + 1) {
            if (nc > SIZE_MAX / 2) return -1;
            nc *= 2;
        }
        nb = realloc(*buf, nc);
        if (!nb) return -1;
        *buf = nb;
        *cap = nc;
    }
    memcpy(*buf + *len, src, n);
    *len = need;
    (*buf)[*len] = '\0';
    return 0;
}

static void set_nonblock(int fd) {
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl < 0) return;
    (void)fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

/* Create a directory and every missing parent (like mkdir -p). Ignores an
   existing component. Returns 0 on success, -1 on error. */
static int mkdir_p(const char *path) {
    char *tmp;
    size_t plen, i;
    int rc = 0;
    if (!path || !path[0]) return -1;
    tmp = strdup(path);
    if (!tmp) return -1;
    plen = strlen(tmp);
    for (i = 1; i < plen; i++) {
        if (tmp[i] == '/') {
            tmp[i] = '\0';
            if (mkdir(tmp, 0755) != 0 && errno != EEXIST) { rc = -1; goto out; }
            tmp[i] = '/';
        }
    }
    if (mkdir(tmp, 0755) != 0 && errno != EEXIST) rc = -1;
out:
    free(tmp);
    return rc;
}

/* Write len bytes to a file (bounded; NUL bytes are fine). Returns 0 on
   success. */
static int write_file(const char *path, const char *data, size_t len) {
    FILE *f = fopen(path, "wb");
    size_t w;
    int rc;
    if (!f) return -1;
    w = fwrite(data, 1, len, f);
    rc = fclose(f);
    if (w != len || rc != 0) return -1;
    return 0;
}

/* Write len bytes to a file and fsync it before returning.  Used for the
   durable outbound spool so a queue row can never reference a body whose
   bytes have not reached stable storage (spool-commit-before-send).  Returns
   0 on success. */
static int write_file_fsync(const char *path, const char *data, size_t len) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    size_t off = 0;
    if (fd < 0) return -1;
    while (off < len) {
        ssize_t w = write(fd, data + off, len - off);
        if (w < 0) {
            if (errno == EINTR) continue;
            close(fd);
            return -1;
        }
        if (w == 0) { close(fd); return -1; }
        off += (size_t)w;
    }
    if (fsync(fd) != 0) { close(fd); return -1; }
    if (close(fd) != 0) return -1;
    return 0;
}

/* Read a whole file into a freshly-malloc'd, NUL-terminated buffer (*out/
   *outlen).  Returns 0 on success, -1 on error (missing file, I/O, alloc). */
static int read_file(const char *path, char **out, size_t *outlen) {
    struct stat st;
    int fd;
    char *buf;
    size_t off = 0;

    if (!path || !out || !outlen) return -1;
    *out = NULL;
    *outlen = 0;

    fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    if (fstat(fd, &st) != 0 || st.st_size < 0) { close(fd); return -1; }
    buf = malloc((size_t)st.st_size + 1);
    if (!buf) { close(fd); return -1; }
    while (off < (size_t)st.st_size) {
        ssize_t r = read(fd, buf + off, (size_t)st.st_size - off);
        if (r < 0) {
            if (errno == EINTR) continue;
            free(buf);
            close(fd);
            return -1;
        }
        if (r == 0) break;   /* file shrank: return what was read */
        off += (size_t)r;
    }
    close(fd);
    buf[off] = '\0';
    *out = buf;
    *outlen = off;
    return 0;
}

/* Build the durable outbound spool path "<spool>/<msgid>.<k>.out.eml". */
static int spool_out_path(const Config *cfg, uint32_t msgid, uint32_t k,
                          char *buf, size_t bufsz) {
    int n = snprintf(buf, bufsz, "%s/%u.%u.out.eml", cfg->storage.spool,
                     msgid, k);
    if (n < 0 || (size_t)n >= bufsz) return -1;
    return 0;
}

/* True if every byte is printable ASCII (no control chars, no space). */
static bool path_clean(const char *p) {
    const unsigned char *q = (const unsigned char *)p;
    while (*q) {
        if (*q < 0x21 || *q > 0x7e) return false;
        /* The reverse-path flows into reply_from_rewrite()'s quoted-string
         * display name ("<S> via <A>"), so reject the characters that would
         * break out of the quotes / brackets and produce a malformed From:.
         * (CR/LF are already rejected by the 0x21..0x7e range above.) */
        if (*q == '"' || *q == '<' || *q == '>') return false;
        q++;
    }
    return true;
}

/* ------------------------------------------------------------------ */
/* Reply output                                                       */
/* ------------------------------------------------------------------ */

/* Flush as much of the pending output buffer as the socket will accept. */
static void conn_flush(Conn *c) {
    while (c->out_off < c->out_len) {
        ssize_t n = send(c->fd, c->out + c->out_off, c->out_len - c->out_off,
                         MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) return;
            c->closed = true;
            return;
        }
        if (n == 0) { c->closed = true; return; }
        c->out_off += (size_t)n;
    }
    c->out_len = c->out_off = 0;
}

/* Queue a NUL-terminated reply line (with its CRLF) and try to flush it. */
static void conn_reply(Conn *c, const char *text) {
    if (buf_append(&c->out, &c->out_len, &c->out_cap, text, strlen(text)) != 0) {
        c->closed = true;
        return;
    }
    conn_flush(c);
}

/* ------------------------------------------------------------------ */
/* Session lifecycle                                                  */
/* ------------------------------------------------------------------ */

static void conn_reset(Conn *c, int new_state) {
    size_t i;
    free(c->from);
    c->from = NULL;
    for (i = 0; i < c->nrcpts; i++) free(c->rcpts[i]);
    free(c->rcpts);
    c->rcpts = NULL;
    c->nrcpts = 0;
    c->rcpt_cap = 0;
    free(c->data);
    c->data = NULL;
    c->data_len = 0;
    c->data_cap = 0;
    c->state = new_state;
}

static void conn_destroy(Conn *c) {
    size_t i;
    if (c->fd >= 0) close(c->fd);
    free(c->from);
    for (i = 0; i < c->nrcpts; i++) free(c->rcpts[i]);
    free(c->rcpts);
    free(c->in);
    free(c->data);
    free(c->out);
    free(c);
}

/* Append one accepted RCPT address. Returns 0, or -1 on allocation failure. */
static int conn_add_rcpt(Conn *c, const char *rcpt) {
    char **na;
    char *dup;
    if (c->nrcpts == c->rcpt_cap) {
        size_t nc = c->rcpt_cap ? c->rcpt_cap * 2 : 4;
        na = realloc(c->rcpts, nc * sizeof *na);
        if (!na) return -1;
        c->rcpts = na;
        c->rcpt_cap = nc;
    }
    dup = strdup(rcpt);
    if (!dup) return -1;
    c->rcpts[c->nrcpts++] = dup;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Command argument parsing (also unit-tested via smtp.h)             */
/* ------------------------------------------------------------------ */

/* Parse "KEY:<path>" out of a command tail. KEY is matched case-insensitively
   (e.g. "FROM"/"TO"). On success the (possibly empty) address between '<' and
   '>' is copied NUL-terminated into path, and *params points at the text after
   '>'. Returns 0, or -1 on malformed input. */
static int parse_addr_arg(const char *rest, const char *key, char *path,
                          size_t pathsz, const char **params) {
    size_t klen = strlen(key);
    const char *p;
    const char *gt;
    size_t plen;

    if (ascii_strncasecmp(rest, key, klen) != 0) return -1;
    p = rest + klen;
    while (*p == ' ') p++;
    if (*p != ':') return -1;
    p++;
    while (*p == ' ') p++;
    if (*p != '<') return -1;
    p++;
    gt = strchr(p, '>');
    if (!gt) return -1;
    plen = (size_t)(gt - p);
    if (plen >= pathsz) return -1;
    memcpy(path, p, plen);
    path[plen] = '\0';
    *params = gt + 1;
    return 0;
}

int smtp_in_parse_size(const char *params, uint64_t *size, bool *present) {
    const char *p;
    if (present) *present = false;
    if (!params || !size) return 0;
    p = params;
    while (*p) {
        const char *tok;
        size_t tlen = 0;
        while (*p == ' ') p++;
        tok = p;
        while (*p && *p != ' ') { p++; tlen++; }
        if (tlen >= 5 && ascii_strncasecmp(tok, "SIZE=", 5) == 0) {
            const char *d = tok + 5;
            size_t dlen = tlen - 5;
            uint64_t v = 0;
            size_t i;
            if (dlen == 0) return -1;
            for (i = 0; i < dlen; i++) {
                char ch = d[i];
                if (ch < '0' || ch > '9') return -1;
                if (v > (UINT64_MAX - (uint64_t)(ch - '0')) / 10) return -1;
                v = v * 10 + (uint64_t)(ch - '0');
            }
            *size = v;
            if (present) *present = true;
            return 0;
        }
    }
    return 0;
}

RcptDecision smtp_in_rcpt_ok(Store *s, const Config *cfg, const char *rcpt) {
    char *local = NULL, *domain = NULL;
    char *sender = NULL, *alias = NULL;
    char **dests = NULL;
    size_t ndests = 0, i;
    int served = 0;
    int r;

    if (!s || !cfg || !rcpt) return RCPT_ERR;
    if (mail_addr_parse(rcpt, &local, &domain) != 0) return RCPT_NOROUTE;

    for (i = 0; i < cfg->ndomains; i++) {
        if (cfg->domains[i] && ascii_ieq_str(cfg->domains[i], domain)) {
            served = 1;
            break;
        }
    }
    mail_addr_free(local, domain);
    if (!served) return RCPT_BAD_DOMAIN;

    r = reply_route_inbound(s, cfg, rcpt, &sender, &alias);
    if (r == 1) { free(sender); free(alias); return RCPT_OK; }
    if (r < 0)   { free(sender); free(alias); return RCPT_ERR; }

    if (store_resolve(s, rcpt, &dests, &ndests) != VISAGE_OK) return RCPT_ERR;
    if (ndests > 0) { store_free_strvec(dests, ndests); return RCPT_OK; }
    store_free_strvec(dests, ndests);

    if (cfg->catch_all && cfg->catch_all[0]) return RCPT_OK;
    return RCPT_NOROUTE;
}

/* ------------------------------------------------------------------ */
/* Durable outbound delivery queue (S-A2)                             */
/* ------------------------------------------------------------------ */

/* Bump attempts and either requeue (next_ts = now + backoff) or, once
   max_attempts is exceeded, mark permfail and drop the spool body. */
static void queue_requeue(Server *srv, uint32_t msgid, uint32_t k,
                          const char *from, const char *to, uint32_t attempts,
                          uint32_t now, uint32_t max_attempts,
                          const char *spoolpath) {
    Store *s = srv->store;
    attempts++;
    if (attempts > max_attempts) {
        if (store_queue_set_status(s, msgid, k, "permfail", attempts, 0)
                != VISAGE_OK)
            fprintf(stderr, "visage: queue: set_status(permfail) failed "
                    "msgid=%u k=%u; row left in prior status\n", msgid, k);
        (void)unlink(spoolpath);
        (void)store_log_add(s, msgid, now, LOG_DIR_OUT, from, to, "permfail");
    } else {
        if (store_queue_set_status(s, msgid, k, "queued", attempts,
                                   now + smtp_backoff_sec(attempts))
                != VISAGE_OK)
            fprintf(stderr, "visage: queue: set_status(queued) failed "
                    "msgid=%u k=%u; row left in prior status (recovered at "
                    "restart)\n", msgid, k);
        (void)store_log_add(s, msgid, now, LOG_DIR_OUT, from, to, "tempfail");
    }
}

/* Attempt one delivery of a due tuple: flip to "delivering", read the
   durably-spooled body, smtp_out_send (its in-attempt retries are the inner
   loop), then transition to delivered / permfail / queued. */
static void queue_deliver_one(Server *srv, uint32_t msgid, uint32_t k,
                              const char *from, const char *to,
                              uint32_t attempts) {
    Store *s = srv->store;
    const Config *cfg = srv->cfg;
    char spoolpath[4096];
    char *body = NULL;
    size_t bodylen = 0;
    char status[128];
    uint32_t now = (uint32_t)time(NULL);
    uint32_t max_attempts =
        cfg->relay.max_attempts ? cfg->relay.max_attempts : 100u;
    int sres;

    /* Flip to delivering (narrows the double-send crash window; startup
       recovery resets a delivering-left-by-crash back to queued). */
    if (store_queue_set_status(s, msgid, k, "delivering", attempts, 0)
            != VISAGE_OK) {
        /* First flip failed: the row is still "queued" with next_ts 0, so it
           would be re-picked immediately -> hot loop.  Log loudly and push its
           next_ts into the future (best effort) to break the spin without
           losing the delivery. */
        fprintf(stderr, "visage: queue: set_status(delivering) failed "
                "msgid=%u k=%u; deferring\n", msgid, k);
        (void)store_queue_set_status(s, msgid, k, "queued", attempts,
                                     now + smtp_backoff_sec(attempts + 1));
        return;
    }

    if (spool_out_path(cfg, msgid, k, spoolpath, sizeof spoolpath) != 0) {
        /* Path too long (would have failed at enqueue too).  Do not loop. */
        if (store_queue_set_status(s, msgid, k, "permfail", attempts, 0)
                != VISAGE_OK)
            fprintf(stderr, "visage: queue: set_status(permfail) failed "
                    "msgid=%u k=%u (spool path too long)\n", msgid, k);
        (void)store_log_add(s, msgid, now, LOG_DIR_OUT, from, to, "permfail");
        return;
    }

    if (read_file(spoolpath, &body, &bodylen) != 0) {
        /* Cannot read the body (transient I/O/alloc, or external deletion):
           requeue rather than lose the message; bounded by max_attempts. */
        queue_requeue(srv, msgid, k, from, to, attempts, now, max_attempts,
                      spoolpath);
        return;
    }

    sres = smtp_out_send(s, cfg, from, to, body, bodylen, status, sizeof status);
    free(body);

    switch (sres) {
    case SMTP_OK:
        if (store_queue_set_status(s, msgid, k, "delivered", attempts, 0)
                != VISAGE_OK)
            fprintf(stderr, "visage: queue: set_status(delivered) failed "
                    "msgid=%u k=%u\n", msgid, k);
        (void)unlink(spoolpath);
        (void)store_log_add(s, msgid, now, LOG_DIR_OUT, from, to, "delivered");
        break;
    case SMTP_PERMFAIL:
        if (store_queue_set_status(s, msgid, k, "permfail", attempts, 0)
                != VISAGE_OK)
            fprintf(stderr, "visage: queue: set_status(permfail) failed "
                    "msgid=%u k=%u\n", msgid, k);
        (void)unlink(spoolpath);
        (void)store_log_add(s, msgid, now, LOG_DIR_OUT, from, to, "permfail");
        break;
    default:   /* SMTP_TEMPFAIL and SMTP_ERROR: retry across attempts */
        queue_requeue(srv, msgid, k, from, to, attempts, now, max_attempts,
                      spoolpath);
        break;
    }
}

/* --- re-drive collection ------------------------------------------- */

typedef struct {
    uint32_t msgid;
    uint32_t k;
    char    *from;
    char    *to;
    uint32_t attempts;
} QueueItem;

typedef struct {
    QueueItem *items;
    size_t     n, cap;
    int        oom;
} QueueCollect;

static int queue_collect_cb(uint32_t msgid, uint32_t k, const char *from,
                            const char *to, uint32_t attempts, void *user) {
    QueueCollect *qc = (QueueCollect *)user;
    QueueItem *it;

    if (qc->n == qc->cap) {
        size_t nc = qc->cap ? qc->cap * 2 : 16;
        QueueItem *na = realloc(qc->items, nc * sizeof *na);
        if (!na) { qc->oom = 1; return 1; }
        qc->items = na;
        qc->cap = nc;
    }
    it = &qc->items[qc->n];
    it->msgid = msgid;
    it->k = k;
    it->from = strdup(from);
    it->to = strdup(to);
    it->attempts = attempts;
    if (!it->from || !it->to) { qc->oom = 1; return 1; }
    qc->n++;
    return 0;
}

/* Re-drive every delivery whose status is "queued" and next_ts <= now.
   Collect-then-mutate is load-bearing: the due-walk is read-only, and each
   delivery's transition happens AFTER the walk returns, because dafsa
   add/delete realloc the states array mid-walk (mutating inside the callback
   would be a use-after-free). */
static void queue_redrive(Server *srv) {
    Store *s = srv->store;
    QueueCollect qc;
    size_t i;
    uint32_t now = (uint32_t)time(NULL);

    memset(&qc, 0, sizeof qc);
    if (store_queue_due(s, now, queue_collect_cb, &qc) != VISAGE_OK || qc.oom) {
        for (i = 0; i < qc.n; i++) {
            free(qc.items[i].from);
            free(qc.items[i].to);
        }
        free(qc.items);
        return;   /* items stay queued; the next tick retries */
    }

    for (i = 0; i < qc.n; i++) {
        queue_deliver_one(srv, qc.items[i].msgid, qc.items[i].k,
                          qc.items[i].from, qc.items[i].to,
                          qc.items[i].attempts);
        free(qc.items[i].from);
        free(qc.items[i].to);
    }
    free(qc.items);
}

/* Durably enqueue one outbound delivery and attempt it immediately via the
   shared re-drive path (low-latency first attempt).  `sanitized` is the
   ALREADY-sanitized outbound body produced by the caller (From/Reply-To
   headers already carry the reverse token; the revmap fact is already
   persisted) — do NOT re-sanitize or re-mint a token here.  Returns 0 when the
   delivery is durably accepted (spool fsync + queue row), -1 on any hard
   failure (mkdir/spool write/fsync/store_queue_add) so the caller can refuse
   acceptance (451). */
static int queue_enqueue(Server *srv, uint32_t msgid, uint32_t k,
                         const char *from, const char *to,
                         const char *sanitized, size_t slen) {
    Store *s = srv->store;
    const Config *cfg = srv->cfg;
    char spoolpath[4096];
    uint32_t now = (uint32_t)time(NULL);

    /* 1. Durably spool the sanitized body BEFORE the queue row, so a queue row
       can never reference a body that has not reached stable storage. */
    if (mkdir_p(cfg->storage.spool) != 0 ||
        spool_out_path(cfg, msgid, k, spoolpath, sizeof spoolpath) != 0 ||
        write_file_fsync(spoolpath, sanitized, slen) != 0) {
        store_log_add(s, msgid, now, LOG_DIR_OUT, from, to, "error");
        return -1;
    }

    /* 2. Commit the queue row (WAL-append + fsync inside store_queue_add). */
    if (store_queue_add(s, msgid, k, from, to) != VISAGE_OK) {
        (void)unlink(spoolpath);   /* orphaned body: nothing references it */
        store_log_add(s, msgid, now, LOG_DIR_OUT, from, to, "error");
        return -1;
    }
    store_log_add(s, msgid, now, LOG_DIR_OUT, from, to, "queued");

    /* 3. Low-latency first attempt via the shared re-drive path. */
    queue_redrive(srv);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Forwarding                                                         */
/* ------------------------------------------------------------------ */

/* DKIM-sign the sanitized outbound body in place when a signing config
   matches the alias's domain.  On any failure (no config, address parse,
   key load/sign error) the buffer is left UNCHANGED so the caller enqueues the
   unsigned copy — availability over signature, no mail loss.  On success the
   old sanitized buffer is freed and replaced with the signed one. */
static void forward_sign(const Config *cfg, const char *alias,
                         char **sanitized, size_t *slen) {
    char *local = NULL, *domain = NULL;
    ConfigDkim *dk;
    char *signed_msg = NULL;
    size_t signed_len = 0;

    if (mail_addr_parse(alias, &local, &domain) != 0) return;
    dk = config_dkim_find(cfg, domain);
    mail_addr_free(local, domain);
    if (!dk) return;

    if (dkim_sign(*sanitized, *slen, dk->domain, dk->selector, dk->private_key,
                  &signed_msg, &signed_len) != 0) {
        fprintf(stderr, "visage: dkim: sign failed for domain '%s'; "
                        "forwarding unsigned\n",
                dk->domain ? dk->domain : "(null)");
        return;
    }
    mail_free(*sanitized);
    *sanitized = signed_msg;
    *slen = signed_len;
}

/* Forward one sanitized copy of the message through `alias` to `dest`.
   Mints a reverse-alias token (or a plain rewrite for a null reverse-path)
   and durably enqueues the sanitized message for outbound delivery.  Returns
   0 when `dest` was durably enqueued, -1 when it could not be (token/revmap/
   sanitize/enqueue failure) so the caller can refuse acceptance (451). */
static int forward_one(Server *srv, const char *msg, size_t msglen,
                       const char *sender, const char *alias, const char *dest,
                       uint32_t msgid, uint32_t ts, uint32_t k) {
    Store *s = srv->store;
    const Config *cfg = srv->cfg;
    MailRewrite rw;
    bool rw_owned = false;
    char token[64], reverse[384], received[512];
    char *sanitized = NULL;
    size_t slen = 0;
    int rc;

    memset(&rw, 0, sizeof rw);

    if (sender[0] != '\0') {
        if (reply_token_gen(token, sizeof token) != VISAGE_OK ||
            reply_make_reverse(cfg, token, alias, reverse, sizeof reverse) != VISAGE_OK ||
            reply_rewrite_build(sender, alias, reverse, &rw) != VISAGE_OK) {
            store_log_add(s, msgid, ts, LOG_DIR_OUT, alias, dest, "error");
            return -1;
        }
        /* Persist the reply token -> (original sender, alias) mapping so an
           inbound reply to reply+<token>@domain can be routed back. Without
           this the reverse alias is written into the headers but never
           resolvable, and the reply is rejected at RCPT time. */
        if (store_revmap_add(s, token, sender, alias) != VISAGE_OK) {
            reply_rewrite_free(&rw);
            store_log_add(s, msgid, ts, LOG_DIR_OUT, alias, dest, "error");
            return -1;
        }
        rw_owned = true;
    } else {
        /* null reverse-path (bounce): no reply alias, route plainly. */
        rw.from = alias;
        rw.sender = alias;
        rw.reply_to = alias;
        rw.return_path = "";
    }

    snprintf(received, sizeof received, "from %s by %s",
             sender[0] ? sender : "<>",
             (cfg->hostname && cfg->hostname[0]) ? cfg->hostname : "localhost");
    rw.received = received;

    rc = mail_sanitize_for_forward(msg, msglen, &rw, &sanitized, &slen);
    if (rw_owned) reply_rewrite_free(&rw);
    if (rc != 0) {
        store_log_add(s, msgid, ts, LOG_DIR_OUT, alias, dest, "error");
        return -1;
    }

    forward_sign(cfg, alias, &sanitized, &slen);

    rc = queue_enqueue(srv, msgid, k, alias, dest, sanitized, slen);
    mail_free(sanitized);
    return (rc == 0) ? 0 : -1;
}

/* Forward a message to every destination of a normal alias, or to the
   catch-all when the alias is unknown and a catch-all is configured.  Returns
   0 when every required destination was durably enqueued (or no enqueue was
   required), -1 when resolve failed or any destination could not be enqueued. */
static int forward_alias(Server *srv, const char *msg, size_t msglen,
                         const char *sender, const char *rcpt,
                         uint32_t msgid, uint32_t ts, uint32_t *k) {
    Store *s = srv->store;
    char **dests = NULL;
    size_t ndests = 0, i;
    int failed = 0;
    const char *remote = sender[0] ? sender : "<>";

    if (store_resolve(s, rcpt, &dests, &ndests) != VISAGE_OK) {
        store_log_add(s, msgid, ts, LOG_DIR_IN, rcpt, remote, "error");
        return -1;
    }
    if (ndests == 0) {
        if (srv->cfg->catch_all && srv->cfg->catch_all[0]) {
            if (forward_one(srv, msg, msglen, sender, rcpt, srv->cfg->catch_all,
                            msgid, ts, (*k)++) != 0)
                failed = 1;
        } else {
            store_log_add(s, msgid, ts, LOG_DIR_IN, rcpt, remote, "rejected");
        }
        store_free_strvec(dests, ndests);
        return failed ? -1 : 0;
    }
    for (i = 0; i < ndests; i++)
        if (forward_one(srv, msg, msglen, sender, rcpt, dests[i], msgid, ts,
                        (*k)++) != 0)
            failed = 1;
    store_free_strvec(dests, ndests);
    return failed ? -1 : 0;
}

/* Forward an inbound reply (a reply-token recipient) back to the original
   sender: envelope MAIL FROM=alias, RCPT TO=sender; headers From=alias,
   To=sender (the reverse alias is stripped from To/Cc). */
/* Forward an inbound reply (a reply-token recipient) back to the original
   sender: envelope MAIL FROM=alias, RCPT TO=sender; headers From=alias,
   To=sender (the reverse alias is stripped from To/Cc).  Returns 0 when the
   reply was durably enqueued, -1 when it could not be (sanitize/header/enqueue
   failure) so the caller can refuse acceptance (451). */
static int forward_reply(Server *srv, const char *msg, size_t msglen,
                         const char *alias_addr, const char *dest,
                         const char *reverse, const char *owner,
                         uint32_t msgid, uint32_t ts, uint32_t k) {
    Store *s = srv->store;
    const Config *cfg = srv->cfg;
    MailRewrite rw;
    char received[512];
    char *sanitized = NULL;
    size_t slen = 0;
    int rc;

    memset(&rw, 0, sizeof rw);
    rw.from = alias_addr;
    rw.sender = alias_addr;
    rw.reply_to = alias_addr;
    rw.return_path = alias_addr;

    snprintf(received, sizeof received, "from %s by %s",
             (owner && owner[0]) ? owner : "<>",
             (cfg->hostname && cfg->hostname[0]) ? cfg->hostname : "localhost");
    rw.received = received;

    if (mail_sanitize_for_forward(msg, msglen, &rw, &sanitized, &slen) != 0) {
        store_log_add(s, msgid, ts, LOG_DIR_OUT, alias_addr, dest, "error");
        return -1;
    }

    (void)reply_strip_reverse(&sanitized, &slen, reverse);
    if (mail_header_set(&sanitized, &slen, "To", dest) != 0) {
        store_log_add(s, msgid, ts, LOG_DIR_OUT, alias_addr, dest, "error");
        mail_free(sanitized);
        return -1;
    }

    forward_sign(cfg, alias_addr, &sanitized, &slen);

    rc = queue_enqueue(srv, msgid, k, alias_addr, dest, sanitized, slen);
    mail_free(sanitized);
    return (rc == 0) ? 0 : -1;
}

/* ------------------------------------------------------------------ */
/* Message delivery (end of DATA)                                     */
/* ------------------------------------------------------------------ */

static void deliver_message(Server *srv, Conn *c, time_t now) {
    Store *s = srv->store;
    const Config *cfg = srv->cfg;
    char *msg = c->data;
    size_t msglen = c->data_len;
    uint32_t msgid, ts;
    uint32_t k = 0;   /* per-msgid destination ordinal (0-based, stable) */
    size_t i;
    int failed = 0;   /* any destination not durably enqueued -> 451 */

    if (mail_unstuff_dots(msg, &msglen) != 0) {
        conn_reply(c, "451 4.3.0 Temporary processing error\r\n");
        return;
    }
    if (msglen > (size_t)srv->max_msg) {
        conn_reply(c, "552 5.3.4 Message exceeds fixed limit\r\n");
        c->closed = true;
        return;
    }

    msgid = store_next_msgid(s);
    ts = (uint32_t)now;

    /* The msgid counter is exhausted (wrap at 2^32) or the store failed to
     * allocate one.  Fail closed rather than proceed with a colliding msgid=0
     * (every message would share it and overwrite the same spool file). */
    if (msgid == 0) {
        conn_reply(c, "451 4.3.0 Message-id allocation failure\r\n");
        c->closed = true;
        return;
    }

    /* Spool a durable copy (best-effort; forwarding proceeds regardless). */
    if (msgid != 0 && mkdir_p(cfg->storage.spool) == 0) {
        char spoolpath[4096];
        int n = snprintf(spoolpath, sizeof spoolpath, "%s/%u.eml",
                         cfg->storage.spool, msgid);
        if (n >= 0 && (size_t)n < sizeof spoolpath)
            (void)write_file(spoolpath, msg, msglen);
    }

    for (i = 0; i < c->nrcpts; i++) {
        const char *rcpt = c->rcpts[i];
        char *rep_sender = NULL, *rep_alias = NULL;
        int r = reply_route_inbound(s, cfg, rcpt, &rep_sender, &rep_alias);
        if (r == 1) {
            if (forward_reply(srv, msg, msglen, rep_alias, rep_sender, rcpt,
                              c->from, msgid, ts, k++) != 0)
                failed = 1;
            free(rep_sender);
            free(rep_alias);
            continue;
        }
        free(rep_sender);
        free(rep_alias);
        if (r < 0) {
            store_log_add(s, msgid, ts, LOG_DIR_IN, rcpt,
                          c->from && c->from[0] ? c->from : "<>", "error");
            failed = 1;   /* routing error: not durably accepted */
            continue;
        }
        if (forward_alias(srv, msg, msglen, c->from ? c->from : "", rcpt,
                          msgid, ts, &k) != 0)
            failed = 1;
    }

    /* Refuse acceptance (451) when any destination was not durably enqueued;
       a partial failure is at-least-once-safe: the client resends, and the
       already-delivered destinations may be re-delivered (a duplicate, which
       is within the accepted at-least-once tolerance — the resend gets a fresh
       msgid, so (msgid,k) does not de-dup across a 451 resend). */
    conn_reply(c, failed ? "451 4.3.0 Temporary queue failure\r\n"
                         : "250 2.0.0 OK: queued\r\n");
}

/* ------------------------------------------------------------------ */
/* DATA input                                                         */
/* ------------------------------------------------------------------ */

/* Scan raw (dot-stuffed) DATA bytes for the end-of-message terminator
   (CRLF.CRLF, tolerating bare-LF and bare-CR lines). Enforces the per-line
   limit (allowing one stuffed dot) and a total raw ceiling. Returns 1 when the
   terminator is found (setting *msg_end to its offset and *term_len to its
   length), 0 when more data is needed, -1 when a limit is exceeded. */
static int data_scan(const char *buf, size_t len, uint32_t max_line,
                     uint64_t max_total, size_t *msg_end, size_t *term_len) {
    size_t i = 0;
    size_t line_start = 0;
    uint64_t line_max = (uint64_t)max_line + 1;

    while (i < len) {
        char ch = buf[i];
        if (ch == '\n') {
            size_t content_end = i;
            size_t clen;
            if (content_end > line_start && buf[content_end - 1] == '\r')
                content_end--;
            clen = content_end - line_start;
            if ((uint64_t)clen > line_max) return -1;
            if (clen == 1 && buf[line_start] == '.') {
                *msg_end = line_start;
                *term_len = i + 1 - line_start;
                return 1;
            }
            line_start = i + 1;
            i++;
            continue;
        }
        if (ch == '\r') {
            size_t content_end;
            size_t clen;
            if (i + 1 < len && buf[i + 1] == '\n') { i++; continue; }
            content_end = i;
            clen = content_end - line_start;
            if ((uint64_t)clen > line_max) return -1;
            if (clen == 1 && buf[line_start] == '.') {
                *msg_end = line_start;
                *term_len = i + 1 - line_start;
                return 1;
            }
            line_start = i + 1;
            i++;
            continue;
        }
        i++;
    }
    if ((uint64_t)len > max_total) return -1;
    if ((uint64_t)(len - line_start) > line_max) return -1;
    return 0;
}

static void process_commands(Server *srv, Conn *c, time_t now);

static void process_data(Server *srv, Conn *c, time_t now) {
    size_t msg_end = 0, term_len = 0;
    int r = data_scan(c->data, c->data_len, srv->max_line, srv->raw_cap,
                      &msg_end, &term_len);
    if (r < 0) {
        conn_reply(c, "552 5.3.4 Message exceeds fixed limits\r\n");
        c->closed = true;
        return;
    }
    if (r == 0) return;   /* need more data */

    {
        size_t leftover_start = msg_end + term_len;
        size_t leftover = c->data_len - leftover_start;
        if (leftover > 0) {
            if (buf_append(&c->in, &c->in_len, &c->in_cap,
                           c->data + leftover_start, leftover) != 0) {
                c->closed = true;
                free(c->data);
                c->data = NULL;
                c->data_len = c->data_cap = 0;
                return;
            }
        }
        c->data_len = msg_end;
    }

    deliver_message(srv, c, now);
    conn_reset(c, ST_HELO);

    if (!c->closed && c->in_len > 0)
        process_commands(srv, c, now);
}

/* ------------------------------------------------------------------ */
/* Command handling                                                   */
/* ------------------------------------------------------------------ */

static void do_helo(Server *srv, Conn *c, bool ehlo) {
    const char *hn = (srv->cfg->hostname && srv->cfg->hostname[0])
                         ? srv->cfg->hostname : "localhost";
    conn_reset(c, ST_HELO);
    if (ehlo) {
        size_t cap = strlen(hn) + 64;
        char *buf = malloc(cap);
        if (!buf) { conn_reply(c, "250 OK\r\n"); return; }
        snprintf(buf, cap, "250-%s\r\n250-8BITMIME\r\n250-SIZE %u\r\n250 OK\r\n",
                 hn, srv->max_msg);
        conn_reply(c, buf);
        free(buf);
    } else {
        size_t cap = strlen(hn) + 16;
        char *buf = malloc(cap);
        if (!buf) { conn_reply(c, "250 OK\r\n"); return; }
        snprintf(buf, cap, "250 %s\r\n", hn);
        conn_reply(c, buf);
        free(buf);
    }
}

static void do_mail(Server *srv, Conn *c, const char *rest) {
    char path[SMTP_MAX_LINE];
    const char *params = NULL;
    uint64_t size = 0;
    bool has_size = false;

    if (c->state != ST_HELO) {
        conn_reply(c, "503 5.5.1 Error: send HELO/EHLO first\r\n");
        return;
    }
    if (parse_addr_arg(rest, "FROM", path, sizeof path, &params) != 0) {
        conn_reply(c, "501 5.5.4 Syntax: MAIL FROM:<address>\r\n");
        return;
    }
    if (!path_clean(path)) {
        conn_reply(c, "501 5.5.4 Invalid reverse-path\r\n");
        return;
    }
    if (smtp_in_parse_size(params, &size, &has_size) != 0) {
        conn_reply(c, "501 5.5.4 Bad SIZE parameter\r\n");
        return;
    }
    if (has_size && size > (uint64_t)srv->max_msg) {
        conn_reply(c, "552 5.3.4 Message size exceeds fixed limit\r\n");
        return;
    }

    free(c->from);
    c->from = strdup(path);   /* may be "" for a null reverse-path */
    if (!c->from) {
        conn_reply(c, "451 4.3.0 Storage allocation failure\r\n");
        return;
    }
    c->state = ST_MAIL;
    conn_reply(c, "250 2.1.0 OK\r\n");
}

static void do_rcpt(Server *srv, Conn *c, const char *rest) {
    char path[SMTP_MAX_LINE];
    const char *params = NULL;
    char *local = NULL, *domain = NULL;
    RcptDecision d;

    if (c->state != ST_MAIL) {
        conn_reply(c, "503 5.5.1 Error: need MAIL first\r\n");
        return;
    }
    if (srv->max_rcpts != 0 && c->nrcpts >= (size_t)srv->max_rcpts) {
        conn_reply(c, "452 4.5.3 Too many recipients\r\n");
        return;
    }
    if (parse_addr_arg(rest, "TO", path, sizeof path, &params) != 0) {
        conn_reply(c, "501 5.5.4 Syntax: RCPT TO:<address>\r\n");
        return;
    }
    (void)params;
    if (path[0] == '\0') {
        conn_reply(c, "501 5.5.4 Empty recipient\r\n");
        return;
    }
    if (mail_addr_parse(path, &local, &domain) != 0) {
        conn_reply(c, "501 5.5.4 Invalid recipient address\r\n");
        return;
    }
    mail_addr_free(local, domain);

    d = smtp_in_rcpt_ok(srv->store, srv->cfg, path);
    switch (d) {
    case RCPT_OK:
        if (conn_add_rcpt(c, path) != 0) {
            conn_reply(c, "451 4.3.0 Storage allocation failure\r\n");
            return;
        }
        conn_reply(c, "250 2.1.5 OK\r\n");
        break;
    case RCPT_ERR:
        conn_reply(c, "451 4.3.0 Temporary routing failure\r\n");
        break;
    default:
        conn_reply(c, "550 5.1.1 User unknown\r\n");
        break;
    }
}

static void do_data(Server *srv, Conn *c) {
    (void)srv;
    if (c->state != ST_MAIL) {
        conn_reply(c, "503 5.5.1 Error: need RCPT first\r\n");
        return;
    }
    if (c->nrcpts == 0) {
        conn_reply(c, "503 5.5.1 Error: no valid recipients\r\n");
        return;
    }
    conn_reply(c, "354 End data with <CR><LF>.<CR><LF>\r\n");
    free(c->data);
    c->data = NULL;
    c->data_len = 0;
    c->data_cap = 0;
    c->state = ST_DATA;
}

static void handle_command(Server *srv, Conn *c, char *line) {
    char *p = line;
    char *sp;
    size_t vlen;
    char *rest;

    while (*p == ' ') p++;
    sp = strchr(p, ' ');
    vlen = sp ? (size_t)(sp - p) : strlen(p);
    rest = sp ? sp + 1 : p + strlen(p);
    while (*rest == ' ') rest++;

    if (vlen == 4 && ascii_strncasecmp(p, "EHLO", 4) == 0) {
        if (!*rest) { conn_reply(c, "501 5.5.4 EHLO requires a domain\r\n"); return; }
        do_helo(srv, c, true);
    } else if (vlen == 4 && ascii_strncasecmp(p, "HELO", 4) == 0) {
        if (!*rest) { conn_reply(c, "501 5.5.4 HELO requires a domain\r\n"); return; }
        do_helo(srv, c, false);
    } else if (vlen == 4 && ascii_strncasecmp(p, "MAIL", 4) == 0) {
        do_mail(srv, c, rest);
    } else if (vlen == 4 && ascii_strncasecmp(p, "RCPT", 4) == 0) {
        do_rcpt(srv, c, rest);
    } else if (vlen == 4 && ascii_strncasecmp(p, "DATA", 4) == 0) {
        do_data(srv, c);
    } else if (vlen == 4 && ascii_strncasecmp(p, "RSET", 4) == 0) {
        conn_reset(c, (c->state == ST_INIT) ? ST_INIT : ST_HELO);
        conn_reply(c, "250 2.0.0 OK\r\n");
    } else if (vlen == 4 && ascii_strncasecmp(p, "NOOP", 4) == 0) {
        conn_reply(c, "250 2.0.0 OK\r\n");
    } else if (vlen == 4 && ascii_strncasecmp(p, "QUIT", 4) == 0) {
        conn_reply(c, "221 2.0.0 Bye\r\n");
        c->closed = true;
    } else if (vlen == 4 && ascii_strncasecmp(p, "VRFY", 4) == 0) {
        conn_reply(c, "252 2.5.2 Cannot VRFY user\r\n");
    } else if (vlen == 4 && ascii_strncasecmp(p, "EXPN", 4) == 0) {
        conn_reply(c, "252 2.5.2 Cannot EXPN list\r\n");
    } else if ((vlen == 8 && ascii_strncasecmp(p, "STARTTLS", 8) == 0) ||
               (vlen == 4 && ascii_strncasecmp(p, "AUTH", 4) == 0)) {
        conn_reply(c, "502 5.5.1 Command not implemented\r\n");
    } else {
        conn_reply(c, "500 5.5.2 Command not recognized\r\n");
    }
}

static void process_commands(Server *srv, Conn *c, time_t now) {
    (void)now;
    for (;;) {
        size_t i = 0;
        size_t linelen, consumed;
        if (c->closed) return;
        while (i < c->in_len && c->in[i] != '\n') i++;
        if (i == c->in_len) {
            if (c->in_len > SMTP_MAX_LINE) {
                conn_reply(c, "500 5.5.2 Line too long\r\n");
                c->closed = true;
            }
            return;
        }
        /* Hard-enforce the cap on newline-terminated lines too: a command
         * line can otherwise grow past SMTP_MAX_LINE if its \n arrives in a
         * later recv() chunk (the no-newline branch above only fires when the
         * buffer holds no terminator yet).  i is the index of the '\n', so
         * i bytes precede it. */
        if (i > (size_t)srv->max_line) {
            conn_reply(c, "500 5.5.2 Line too long\r\n");
            c->closed = true;
            return;
        }
        linelen = i;
        if (linelen > 0 && c->in[linelen - 1] == '\r') linelen--;
        c->in[linelen] = '\0';
        handle_command(srv, c, c->in);
        consumed = i + 1;
        memmove(c->in, c->in + consumed, c->in_len - consumed);
        c->in_len -= consumed;
    }
}

static void conn_readable(Server *srv, Conn *c, time_t now) {
    char tmp[SMTP_IN_RECV_CHUNK];
    ssize_t n = recv(c->fd, tmp, sizeof tmp, 0);
    if (n < 0) {
        if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) return;
        c->closed = true;
        return;
    }
    if (n == 0) {
        c->closed = true;
        return;
    }
    c->last_act = now;

    if (c->state == ST_DATA) {
        if ((uint64_t)c->data_len + (uint64_t)n > srv->raw_cap) {
            conn_reply(c, "552 5.3.4 Message exceeds fixed limit\r\n");
            c->closed = true;
            return;
        }
        if (buf_append(&c->data, &c->data_len, &c->data_cap, tmp, (size_t)n) != 0) {
            conn_reply(c, "451 4.3.0 Storage allocation failure\r\n");
            c->closed = true;
            return;
        }
        process_data(srv, c, now);
    } else {
        if (buf_append(&c->in, &c->in_len, &c->in_cap, tmp, (size_t)n) != 0) {
            conn_reply(c, "500 5.5.2 Line too long\r\n");
            c->closed = true;
            return;
        }
        process_commands(srv, c, now);
    }
}

/* ------------------------------------------------------------------ */
/* Event loop                                                         */
/* ------------------------------------------------------------------ */

static uint32_t conn_timeout(const Server *srv, const Conn *c) {
    return (c->state == ST_DATA) ? srv->data_tmo : srv->cmd_tmo;
}

static int poll_timeout_ms(const Server *srv, time_t now) {
    int ms = -1;
    size_t i;
    for (i = 0; i < srv->nconns; i++) {
        const Conn *c = srv->conns[i];
        uint32_t tmo = conn_timeout(srv, c);
        time_t elapsed, remain;
        int rms;
        if (tmo == 0) continue;
        elapsed = (now > c->last_act) ? (now - c->last_act) : 0;
        if (elapsed >= (time_t)tmo) return 0;
        remain = (time_t)tmo - elapsed;
        rms = (int)(remain * 1000);
        if (rms > 2147483647) rms = 2147483647;
        if (ms < 0 || rms < ms) ms = rms;
    }

    /* HTTP conn idle deadline: wake poll() so the idle sweep can reap a
       trickling admin conn even when nothing else is scheduled. */
    for (i = 0; i < SMTP_IN_MAX_HTTP; i++) {
        const HttpSlot *h = &s_http[i];
        time_t elapsed, remain;
        int rms;
        if (!h->used || h->idle_timeout_sec == 0) continue;
        elapsed = (now > h->last_act) ? (now - h->last_act) : 0;
        if (elapsed >= (time_t)h->idle_timeout_sec) return 0;
        remain = (time_t)h->idle_timeout_sec - elapsed;
        rms = (int)(remain * 1000);
        if (rms > 2147483647) rms = 2147483647;
        if (ms < 0 || rms < ms) ms = rms;
    }

    /* Queue re-drive deadline: wake poll() when the soonest queued next_ts is
       reached so an otherwise-idle daemon still re-drives on schedule.  A
       due-now item (next_ts <= now) yields 0 ms -> poll returns immediately.
       Capped at 30 s (matches the backoff cap). */
    {
        uint32_t next_due = store_queue_next_due(srv->store);
        if (next_due != UINT32_MAX) {
            uint32_t now32 = (uint32_t)now;
            uint32_t delta = (next_due > now32) ? (next_due - now32) : 0;
            int qms;
            if (delta > 30) delta = 30;
            qms = (int)(delta * 1000);
            if (ms < 0 || qms < ms) ms = qms;
        }
    }
    return ms;
}

static void server_accept(Server *srv, time_t now) {
    for (;;) {
        int fd = accept(srv->listen_fd, NULL, NULL);
        Conn *c;
        char g[512];
        int gn;

        if (fd < 0) {
            if (errno == EINTR) continue;
            return;   /* EAGAIN/EWOULDBLOCK or error */
        }
        set_nonblock(fd);

        c = calloc(1, sizeof *c);
        if (!c) { close(fd); continue; }
        c->fd = fd;
        c->state = ST_INIT;
        c->last_act = now;

        if (srv->nconns == srv->conn_cap) {
            size_t nc = srv->conn_cap ? srv->conn_cap * 2 : 16;
            Conn **na = realloc(srv->conns, nc * sizeof *na);
            if (!na) { conn_destroy(c); continue; }
            srv->conns = na;
            srv->conn_cap = nc;
        }
        srv->conns[srv->nconns++] = c;

        gn = snprintf(g, sizeof g, "220 %s ESMTP visage\r\n",
                      (srv->cfg->hostname && srv->cfg->hostname[0])
                          ? srv->cfg->hostname : "localhost");
        if (gn < 0 || (size_t)gn >= sizeof g)
            conn_reply(c, "220 localhost ESMTP visage\r\n");
        else
            conn_reply(c, g);
    }
}

static void server_poll(Server *srv) {
    struct pollfd *pfds = NULL;
    size_t pfds_cap = 0;

    for (;;) {
        time_t now = time(NULL);
        size_t nfds, n_before, i, http_base;

        /* idle timeout */
        for (i = 0; i < srv->nconns; i++) {
            Conn *c = srv->conns[i];
            uint32_t tmo = conn_timeout(srv, c);
            if (tmo != 0 && now > c->last_act &&
                (now - c->last_act) >= (time_t)tmo) {
                conn_reply(c, "421 4.4.2 Timeout - closing connection\r\n");
                c->closed = true;
            }
        }

        /* idle timeout (admin HTTP conns) */
        for (i = 0; i < SMTP_IN_MAX_HTTP; i++) {
            HttpSlot *h = &s_http[i];
            if (!h->used || h->idle_timeout_sec == 0) continue;
            if (now > h->last_act &&
                (now - h->last_act) >= (time_t)h->idle_timeout_sec)
                http_slot_idle_close((int)i);
        }

        /* Re-drive any due durable-queue deliveries.  Idempotent and a no-op
           when nothing is due (full walk, filtered). */
        queue_redrive(srv);

        /* build pollfd array: [0] SMTP listen, [1..] extra listeners,
           then SMTP conns, then a fixed block of HTTP conn slots. */
        nfds = 1 + s_nextra + srv->nconns + SMTP_IN_MAX_HTTP;
        if (nfds > pfds_cap) {
            free(pfds);
            pfds = malloc(nfds * sizeof *pfds);
            if (!pfds) break;
            pfds_cap = nfds;
        }
        pfds[0].fd = srv->listen_fd;
        pfds[0].events = POLLIN;
        pfds[0].revents = 0;
        for (i = 0; i < s_nextra; i++) {
            pfds[i + 1].fd = s_extra[i].fd;
            pfds[i + 1].events = POLLIN;
            pfds[i + 1].revents = 0;
        }
        for (i = 0; i < srv->nconns; i++) {
            Conn *c = srv->conns[i];
            pfds[1 + s_nextra + i].fd = c->fd;
            if (c->closed) {
                pfds[1 + s_nextra + i].events = (c->out_off < c->out_len) ? POLLOUT : 0;
            } else {
                pfds[1 + s_nextra + i].events = POLLIN;
                if (c->out_off < c->out_len) pfds[1 + s_nextra + i].events |= POLLOUT;
            }
            pfds[1 + s_nextra + i].revents = 0;
        }
        http_base = 1 + s_nextra + srv->nconns;
        for (i = 0; i < SMTP_IN_MAX_HTTP; i++) {
            const HttpSlot *h = &s_http[i];
            pfds[http_base + i].fd = h->used ? h->fd : -1;   /* poll skips -1 */
            pfds[http_base + i].events = h->used ? h->events : 0;
            pfds[http_base + i].revents = 0;
        }

        {
            int tmo = poll_timeout_ms(srv, now);
            int pr = poll(pfds, nfds, tmo);
            if (pr < 0) {
                if (errno == EINTR) continue;
                break;
            }
        }

        n_before = srv->nconns;

        if (pfds[0].revents & POLLIN)
            server_accept(srv, now);

        /* dispatch extra-fd listeners (may add SMTP connections) */
        for (i = 0; i < s_nextra; i++)
            if (pfds[i + 1].revents & (POLLIN | POLLHUP | POLLERR))
                s_extra[i].cb(s_extra[i].fd, s_extra[i].user);

        for (i = 0; i < n_before; i++) {
            Conn *c = srv->conns[i];
            short rev = pfds[1 + s_nextra + i].revents;
            if (c->closed) {
                if (rev & POLLOUT) conn_flush(c);
                continue;
            }
            if (rev & (POLLIN | POLLHUP | POLLERR))
                conn_readable(srv, c, now);
            if (!c->closed && (rev & POLLOUT))
                conn_flush(c);
        }

        /* dispatch admin HTTP conns (readable, then writable) */
        for (i = 0; i < SMTP_IN_MAX_HTTP; i++) {
            HttpSlot *h = &s_http[i];
            short rev;
            if (!h->used) continue;
            rev = pfds[http_base + i].revents;
            if (rev & (POLLIN | POLLHUP | POLLERR)) {
                h->last_act = now;
                if (h->on_readable) h->on_readable(h->fd, h->user);
            }
            if (h->used && (rev & POLLOUT)) {
                h->last_act = now;
                if (h->on_writable) h->on_writable(h->fd, h->user);
            }
        }

        /* destroy closed connections whose output has drained */
        for (i = 0; i < srv->nconns; ) {
            Conn *c = srv->conns[i];
            if (c->closed && c->out_off >= c->out_len) {
                conn_destroy(c);
                srv->conns[i] = srv->conns[srv->nconns - 1];
                srv->nconns--;
            } else {
                i++;
            }
        }
    }
    free(pfds);
}

/* ------------------------------------------------------------------ */
/* Listener + entry point                                             */
/* ------------------------------------------------------------------ */

static int make_listener(const Config *cfg) {
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    struct addrinfo *ai;
    char portstr[16];
    int fd = -1;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    snprintf(portstr, sizeof portstr, "%u", cfg->listen.port);
    if (getaddrinfo(cfg->listen.address, portstr, &hints, &res) != 0)
        return -1;

    for (ai = res; ai; ai = ai->ai_next) {
        int s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (s < 0) continue;
        {
            int one = 1;
            (void)setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
        }
        if (bind(s, ai->ai_addr, ai->ai_addrlen) < 0) { close(s); continue; }
        if (listen(s, SMTP_IN_LISTEN_BACKLOG) < 0) { close(s); continue; }
        fd = s;
        break;
    }
    freeaddrinfo(res);
    if (fd < 0) return -1;
    set_nonblock(fd);
    return fd;
}

static void server_init(Server *srv, const Config *c, Store *s) {
    memset(srv, 0, sizeof *srv);
    srv->cfg = c;
    srv->store = s;
    srv->max_line = c->limits.line ? c->limits.line : SMTP_MAX_LINE;
    srv->max_msg = c->limits.message ? c->limits.message : SMTP_IN_DEFAULT_MAX_MSG;
    srv->max_rcpts = c->limits.rcpts;
    srv->cmd_tmo = c->limits.cmd_timeout ? c->limits.cmd_timeout : SMTP_IN_DEFAULT_TIMEOUT;
    srv->data_tmo = c->limits.data_timeout ? c->limits.data_timeout : SMTP_IN_DEFAULT_TIMEOUT;
    srv->raw_cap = (uint64_t)srv->max_msg * 2 + 16;
}

int smtp_in_main(const Config *c, const Store *s) {
    Server srv;
    if (!c || !s) return VISAGE_EPARAM;
    server_init(&srv, c, (Store *)s);
    srv.listen_fd = make_listener(c);
    if (srv.listen_fd < 0) return VISAGE_ERR;

    /* Startup recovery: reset any delivery left "delivering" by a crash, then
       drain everything due before serving (at-least-once). */
    (void)store_queue_reset_delivering((Store *)s);
    queue_redrive(&srv);

    server_poll(&srv);
    close(srv.listen_fd);
    return VISAGE_OK;
}
