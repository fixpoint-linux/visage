/* jmapd_submit.c — EmailSubmission/set (RFC 8621 7.5): the outbox path.
 *
 * Creating an EmailSubmission SENDS the message.  What that means here:
 *
 *   1. the envelope is rendered from the message (or taken from the client's
 *      "envelope" argument): MAIL FROM is the first address of Sender, else
 *      From, replaced by the Identity's address when it differs (RFC 8621 7.5
 *      requires the Identity's address when the message's own is not allowed);
 *      RCPT TO is the deduplicated set of To/Cc/Bcc addr-specs;
 *   2. the message bytes are handed to ONE worker thread (the
 *      src/outbox_deliver.c precedent: mutex + condvar queue, bounded depth
 *      and bytes) which runs smtp_out_send_host() against the configured
 *      outbox relay (default 127.0.0.1:465, implicit TLS, AUTH PLAIN when a
 *      user is configured).  The poll loop only appends to the queue;
 *   3. the submitted Email is MOVED to the Sent mailbox — before any
 *      onSuccessUpdateEmail patch, because the mail-hub client's patch removes
 *      "mailboxIds/<drafts>", which in this one-mailbox-per-Email store is
 *      only a legal patch once the message has left Drafts (see
 *      handoff-jmapd-m3-result GAPS (a));
 *   4. onSuccessUpdateEmail is applied as the implicit Email/set call RFC 8621
 *      7.5 specifies — through the same patch applier and maildir writes as
 *      Email/set, never a private copy of them.
 *
 * ACCEPTED IS NOT DELIVERED.  RFC 8621 is explicit that a created submission
 * means the server took responsibility for the message, not that a remote host
 * accepted it.  This implementation is stricter than it has to be and says so:
 * it WAITS (bounded, --submit-wait, default 5 s; 0 means do not wait at all)
 * for the worker's outcome, so that a relay that refuses the message can be
 * reported as notCreated in the SAME response and the draft is left in Drafts.
 * A submission whose outcome does not arrive within the window is answered
 * created — the RFC-legal answer — and the worker's verdict is logged when it
 * lands.  The cost is named rather than hidden: the event loop is stalled for
 * at most that window, and only while a submission is in flight.
 *
 * SUBMISSION OUTCOMES.  Four, and each is distinguishable in the log:
 *
 *   delivered                  the relay accepted every recipient: answered
 *                              created, filed in Sent with $seen, ledgered.
 *   refused                    the relay refused within the window: answered
 *                              notCreated, NOTHING sent, the draft stays in
 *                              Drafts and is not ledgered (resubmittable).
 *   accepted-without-verdict   --submit-wait elapsed with no verdict: answered
 *                              created, filed in Sent with $seen AND ledgered
 *                              while delivery is still unknown.
 *   duplicate-refused          the Email is already in the ledger: notCreated
 *                              /forbidden, nothing sent.
 *
 * The third is the one with a cost, so it is stated: because the message is
 * already marked sent and ledgered when the window closes, a LATE refusal
 * ("late worker verdict lost") leaves a message that is marked sent, was never
 * delivered, and is REFUSED on any resubmission until 4096 newer ids evict the
 * ledger entry.  The alternatives are worse: deferring the Sent filing until
 * the verdict makes a delivered message look like a draft, and ledgering only
 * on a confirmed acceptance re-opens a duplicate send after a timeout-then-
 * success.  At-most-once wins; the verdict is un-reportable by construction
 * (there is no EmailSubmission/get to ask).
 *
 * AT MOST ONCE.  The plan's DECISION 6 chose the outbox (which owns DKIM,
 * DMARC and MX routing) over a direct submit, and the price of that path is
 * that the outbox does not re-drive a spool it has not queued.  A second
 * submission of the same Email would therefore be a duplicate delivery to
 * every recipient, so it is refused: <root>/<user>/jmapd-submitted records
 * what has been sent (bounded, oldest dropped), and a repeat answers
 * notCreated/forbidden.
 *
 * NOT IMPLEMENTED, named: EmailSubmission/get and /query (the client never
 * calls them), undoStatus cancellation (every submission here is "final" the
 * moment the worker starts, so an update answers the RFC 8621 "cannotUnsend"),
 * and a separate implicit Email/set response object — a patch that fails after
 * the message has left is logged, because reporting the submission as failed
 * would be a lie about a message that was already sent.
 */
#include "visage.h"
#include "jmapd.h"
#include "mail.h"
#include "smtp.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <strings.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* SMTP timeouts for one submission dialogue.  Bounded on purpose: the worker
   may block (it is the only thread that touches smtp_out.c's process-global
   mbedTLS state, exactly as outbox_deliver.c does), the poll loop may not. */
#define SUB_CMD_TMO   30
#define SUB_DATA_TMO  120

/* ------------------------------------------------------------------ */
/* The outbox queue + worker                                           */
/* ------------------------------------------------------------------ */

enum { SUB_FREE = 0, SUB_QUEUED, SUB_RUNNING, SUB_DONE };

typedef struct JmapdSubmitJob {
    int      state;
    bool     waited;     /* a request is waiting for this slot's outcome */
    char    *msg;        /* owned until the slot is reused */
    size_t   msglen;
    char     from[256];
    char     rcpt[JMAPD_SUBMIT_MAX_RCPT][256];
    size_t   nrcpt;
    bool     ok;         /* at least one recipient was accepted */
    bool     tempfail;   /* every failure was a 4xx / transport failure */
    char     status[256];/* the relay's own words, for the log + SetError */
} JmapdSubmitJob;

typedef struct JmapdSubmit {
    pthread_mutex_t lock;
    pthread_cond_t  work;
    pthread_cond_t  done;
    pthread_t       thread;
    bool            started, stop;
    Config          scfg;     /* smtp_out_send_host's view of the outbox */
    const char     *host;
    uint16_t        port;
    JmapdSubmitJob  slot[JMAPD_SUBMIT_QUEUE_JOBS];
    size_t          bytes;    /* queued message bytes */
    unsigned long   nsent, nfailed;
} JmapdSubmit;

static void slot_release(JmapdSubmitJob *j) {
    free(j->msg);
    j->msg = NULL;
    j->msglen = 0;
    j->nrcpt = 0;
    j->ok = false;
    j->tempfail = false;
    j->status[0] = '\0';
    j->waited = false;
    j->state = SUB_FREE;
}

/* Run the SMTP dialogue for one job.  Called ONLY from the worker thread. */
static void job_deliver(JmapdSubmit *s, JmapdSubmitJob *job) {
    size_t i;
    bool any_tempfail = false, all_tempfail = true;

    for (i = 0; i < job->nrcpt; i++) {
        char status[256];
        int rc = smtp_out_send_host(&s->scfg, s->host, s->port, job->from,
                                    job->rcpt[i], job->msg, job->msglen,
                                    status, sizeof status);
        if (rc == SMTP_OK) {
            job->ok = true;
            all_tempfail = false;
            continue;
        }
        if (rc == SMTP_TEMPFAIL) any_tempfail = true;
        else all_tempfail = false;
        snprintf(job->status, sizeof job->status, "%.80s -> %s: %.120s",
                 job->rcpt[i], smtp_status_str(rc),
                 status[0] ? status : "");
        fprintf(stderr, "jmapd submission: relay %s:%u refused %s: %s\n",
                s->host, (unsigned)s->port, job->rcpt[i],
                status[0] ? status : smtp_status_str(rc));
        fflush(stderr);
    }
    job->tempfail = !job->ok && all_tempfail && any_tempfail;
    if (!job->ok && job->status[0] == '\0')
        snprintf(job->status, sizeof job->status, "no recipient accepted");
}

static void *submit_worker(void *arg) {
    JmapdSubmit *s = arg;
    for (;;) {
        JmapdSubmitJob *job = NULL;
        int i;

        pthread_mutex_lock(&s->lock);
        for (;;) {
            for (i = 0; i < JMAPD_SUBMIT_QUEUE_JOBS; i++)
                if (s->slot[i].state == SUB_QUEUED) {
                    job = &s->slot[i];
                    break;
                }
            if (job || s->stop) break;
            pthread_cond_wait(&s->work, &s->lock);
        }
        if (!job) {   /* stop && queue drained */
            pthread_mutex_unlock(&s->lock);
            break;
        }
        job->state = SUB_RUNNING;
        s->bytes -= job->msglen;
        pthread_mutex_unlock(&s->lock);

        job_deliver(s, job);

        pthread_mutex_lock(&s->lock);
        if (job->ok) s->nsent++;
        else s->nfailed++;
        if (!job->waited) {
            /* The requester's --submit-wait window closed before this verdict
               landed: it was answered created-without-verdict, and nothing can
               carry this outcome back to the client.  Named, not dropped in
               silence — a refusal here means a message that is marked sent,
               ledgered and unsendable but was never delivered. */
            fprintf(stderr,
                    "jmapd submission: late worker verdict lost: %s: %s\n",
                    job->from,
                    job->ok ? "relay accepted (the client already got created)"
                            : (job->status[0] ? job->status
                                              : "relay refused (the message is "
                                                "already marked sent)"));
            fflush(stderr);
        }
        job->state = SUB_DONE;
        pthread_cond_broadcast(&s->done);
        pthread_mutex_unlock(&s->lock);
    }
    return NULL;
}

int jmapd_submit_init(JmapdServer *srv) {
    JmapdSubmit *s;
    size_t i;

    if (!srv) return -1;
    s = calloc(1, sizeof *s);
    if (!s) return -1;
    s->host = srv->cfg.outbox_host;
    s->port = srv->cfg.outbox_port;

    /* The outbox precedent (src/outbox_deliver.c): a Config built by memset,
       never by config_load — jmapd links neither Dhall nor datalog, and the
       only fields smtp_out.c reads are the relay's and the timeouts'. */
    memset(&s->scfg, 0, sizeof s->scfg);
    s->scfg.relay.host = (char *)srv->cfg.outbox_host;
    s->scfg.relay.port = srv->cfg.outbox_port;
    s->scfg.relay.tls = (char *)((srv->cfg.outbox_tls && srv->cfg.outbox_tls[0])
                                     ? srv->cfg.outbox_tls
                                     : "implicit");
    s->scfg.relay.retries = 0;   /* one attempt: the response carries the verdict */
    if (srv->cfg.outbox_user && srv->cfg.outbox_user[0]) {
        s->scfg.relay.auth.enabled = true;
        s->scfg.relay.auth.username = (char *)srv->cfg.outbox_user;
        s->scfg.relay.auth.password = (char *)srv->cfg.outbox_pass;
    }
    s->scfg.limits.cmd_timeout = SUB_CMD_TMO;
    s->scfg.limits.data_timeout = SUB_DATA_TMO;

    for (i = 0; i < JMAPD_SUBMIT_QUEUE_JOBS; i++) s->slot[i].state = SUB_FREE;
    pthread_mutex_init(&s->lock, NULL);
    pthread_cond_init(&s->work, NULL);
    {
        /* s->done is waited on with a DEADLINE (--submit-wait), so it must run
           on a MONOTONIC clock: an NTP step must not stretch or collapse the
           poll loop's stall beyond the configured window. */
        pthread_condattr_t attr;
        pthread_condattr_init(&attr);
        pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
        if (pthread_cond_init(&s->done, &attr) != 0) {
            pthread_condattr_destroy(&attr);
            pthread_cond_destroy(&s->work);
            pthread_mutex_destroy(&s->lock);
            free(s);
            return -1;
        }
        pthread_condattr_destroy(&attr);
    }
    if (pthread_create(&s->thread, NULL, submit_worker, s) != 0) {
        pthread_cond_destroy(&s->done);
        pthread_cond_destroy(&s->work);
        pthread_mutex_destroy(&s->lock);
        free(s);
        return -1;
    }
    s->started = true;
    srv->submit = s;
    return 0;
}

void jmapd_submit_stop(JmapdServer *srv) {
    JmapdSubmit *s;
    size_t i;
    if (!srv || !srv->submit) return;
    s = srv->submit;
    pthread_mutex_lock(&s->lock);
    s->stop = true;
    pthread_cond_broadcast(&s->work);
    pthread_mutex_unlock(&s->lock);
    if (s->started) pthread_join(s->thread, NULL);
    for (i = 0; i < JMAPD_SUBMIT_QUEUE_JOBS; i++) slot_release(&s->slot[i]);
    pthread_cond_destroy(&s->done);
    pthread_cond_destroy(&s->work);
    pthread_mutex_destroy(&s->lock);
    free(s);
    srv->submit = NULL;
}

/* Copy one envelope+message into a queue slot, wake the worker, and wait up to
   wait_ms for the outcome.  The message buffer is CONSUMED (freed here).

   Returns 0 with *ok / status filled in, 1 when the queue is full (the caller
   answers a refusal and the message has NOT been sent), or 2 when the outcome
   did not arrive in time (the submission is accepted but undelivered as far as
   this response can know). */
static int submit_queue(JmapdServer *srv, const char *from,
                        char rcpt[][256], size_t nrcpt, char *msg,
                        size_t msglen, uint32_t wait_ms, bool *ok,
                        bool *tempfail, char *status, size_t statussz) {
    JmapdSubmit *s = srv->submit;
    JmapdSubmitJob *job = NULL;
    size_t i;
    int rc = 0;

    *ok = false;
    *tempfail = false;
    if (status && statussz) status[0] = '\0';
    if (!s) {
        free(msg);
        return 1;
    }
    if (!from || nrcpt == 0 || nrcpt > JMAPD_SUBMIT_MAX_RCPT) {
        free(msg);
        return 1;
    }

    pthread_mutex_lock(&s->lock);
    /* Reap slots whose outcome nobody is waiting for any more. */
    for (i = 0; i < JMAPD_SUBMIT_QUEUE_JOBS; i++)
        if (s->slot[i].state == SUB_DONE && !s->slot[i].waited)
            slot_release(&s->slot[i]);
    for (i = 0; i < JMAPD_SUBMIT_QUEUE_JOBS; i++)
        if (s->slot[i].state == SUB_FREE) {
            job = &s->slot[i];
            break;
        }
    if (!job || s->bytes + msglen > JMAPD_SUBMIT_QUEUE_BYTES) {
        pthread_mutex_unlock(&s->lock);
        free(msg);
        return 1;
    }
    job->state = SUB_QUEUED;
    job->waited = true;
    job->msg = msg;
    job->msglen = msglen;
    snprintf(job->from, sizeof job->from, "%s", from);
    job->nrcpt = nrcpt;
    for (i = 0; i < nrcpt; i++)
        snprintf(job->rcpt[i], sizeof job->rcpt[i], "%s", rcpt[i]);
    job->ok = false;
    job->tempfail = false;
    job->status[0] = '\0';
    s->bytes += msglen;
    pthread_cond_signal(&s->work);

    {
        struct timespec deadline;
        clock_gettime(CLOCK_MONOTONIC, &deadline);
        deadline.tv_sec += (time_t)(wait_ms / 1000u);
        deadline.tv_nsec += (long)(wait_ms % 1000u) * 1000000L;
        if (deadline.tv_nsec >= 1000000000L) {
            deadline.tv_sec += 1;
            deadline.tv_nsec -= 1000000000L;
        }
        while (job->state != SUB_DONE) {
            /* ETIMEDOUT is the configured window elapsing, and wait_ms == 0
               means ZERO: fire-and-forget, answered created at once. */
            if (pthread_cond_timedwait(&s->done, &s->lock, &deadline) != 0) {
                if (job->state != SUB_DONE) { rc = 2; break; }
                break;
            }
        }
    }
    if (job->state == SUB_DONE) {
        *ok = job->ok;
        *tempfail = job->tempfail;
        if (status && statussz) snprintf(status, statussz, "%s", job->status);
        slot_release(job);
        rc = 0;
    } else {
        job->waited = false;   /* the worker's verdict is logged, not returned */
    }
    pthread_mutex_unlock(&s->lock);
    return rc;
}

/* ------------------------------------------------------------------ */
/* The submitted-email ledger                                          */
/* ------------------------------------------------------------------ */

static int ledger_path(JmapdServer *srv, const char *user, char *out,
                       size_t outsz) {
    int n;
    if (!user || !imapd_user_ok(user)) return -1;
    /* Beside jmapd-state: same root, same per-account directory (icfg.root is
       the maildir root both daemons serve). */
    n = snprintf(out, outsz, "%s/%s/%s", srv->icfg.root, user,
                 JMAPD_LEDGER_FILE);
    return (n < 0 || (size_t)n >= outsz) ? -1 : 0;
}

/* Read the ledger into a heap buffer.  Returns 0 (with *buf NULL when the file
   is absent) or -1. */
static int ledger_read(JmapdServer *srv, const char *user, char **buf,
                       size_t *buflen) {
    char path[4096];
    char *b;
    size_t cap = 256u * 1024u, got = 0;
    int fd;

    *buf = NULL;
    *buflen = 0;
    if (ledger_path(srv, user, path, sizeof path) != 0) return -1;
    fd = open(path, O_RDONLY);
    if (fd < 0) return 0;   /* nothing sent yet */
    b = malloc(cap + 1);
    if (!b) { close(fd); return -1; }
    for (;;) {
        ssize_t r;
        if (got == cap) break;   /* bounded: an over-long ledger is truncated */
        r = read(fd, b + got, cap - got);
        if (r < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (r == 0) break;
        got += (size_t)r;
    }
    close(fd);
    b[got] = '\0';
    *buf = b;
    *buflen = got;
    return 0;
}

/* Is this Email already in the ledger?  1 yes, 0 no, -1 on error. */
static int ledger_has(JmapdServer *srv, const char *user, const char *id) {
    char *buf;
    size_t len, i = 0, idlen = strlen(id);
    int found = 0;

    if (ledger_read(srv, user, &buf, &len) != 0) return -1;
    if (!buf) return 0;
    while (i < len && !found) {
        size_t j = i;
        while (j < len && buf[j] != '\n') j++;
        if (j - i == idlen && memcmp(buf + i, id, idlen) == 0) found = 1;
        i = j + 1;
    }
    free(buf);
    return found;
}

/* Record one submitted Email (tmp + rename, keeping the newest JMAPD_LEDGER_MAX
   entries).  Best effort: a read-only root means the next submission of the
   same Email is not refused, which is logged, not hidden. */
static void ledger_add(JmapdServer *srv, const char *user, const char *id) {
    char path[4096], tmp[4200];
    char *buf = NULL, *nb;
    size_t len = 0, i = 0, nlines = 0, skip;
    int fd;

    if (ledger_path(srv, user, path, sizeof path) != 0) return;
    if (ledger_read(srv, user, &buf, &len) != 0) return;
    for (i = 0; i < len; i++)
        if (buf[i] == '\n') nlines++;
    skip = (nlines >= JMAPD_LEDGER_MAX) ? (nlines - JMAPD_LEDGER_MAX + 1) : 0;

    /* Everything from the skip-th line onwards, then the new id. */
    i = 0;
    while (i < len && skip > 0) {
        while (i < len && buf[i] != '\n') i++;
        if (i < len) i++;
        skip--;
    }
    nb = malloc(len - i + strlen(id) + 2);
    if (!nb) { free(buf); return; }
    memcpy(nb, buf + i, len - i);
    memcpy(nb + (len - i), id, strlen(id));
    nb[len - i + strlen(id)] = '\n';
    free(buf);

    snprintf(tmp, sizeof tmp, "%s.tmp", path);
    fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd >= 0) {
        size_t total = len - i + strlen(id) + 1, off = 0;
        while (off < total) {
            ssize_t w = write(fd, nb + off, total - off);
            if (w <= 0) {
                if (w < 0 && errno == EINTR) continue;
                break;
            }
            off += (size_t)w;
        }
        close(fd);
        if (off == total && rename(tmp, path) == 0) {
            free(nb);
            return;
        }
        (void)unlink(tmp);
    }
    fprintf(stderr, "jmapd submission: could not record %s in %s: %s\n", id,
            path, strerror(errno));
    fflush(stderr);
    free(nb);
}

/* ------------------------------------------------------------------ */
/* The envelope (pure: src/jmap_check.c drives this without a socket)  */
/* ------------------------------------------------------------------ */

/* Append every addr-spec of one address-list header value to the envelope's
   rcptTo, skipping duplicates (a repeated RCPT TO would deliver twice) and
   recording an overflow instead of silently dropping the tail. */
static void env_add_rcpt(JmapdEnvelope *env, const char *value) {
    char tmp[JMAPD_SUBMIT_MAX_RCPT][256];
    size_t n, i, k;

    if (!value || !value[0]) return;
    n = jmapd_addr_list(value, tmp, JMAPD_SUBMIT_MAX_RCPT);
    for (i = 0; i < n; i++) {
        bool dup = false;
        for (k = 0; k < env->nrcpt; k++)
            if (strcasecmp(env->rcpt[k], tmp[i]) == 0) {
                dup = true;
                break;
            }
        if (dup) continue;
        if (env->nrcpt >= JMAPD_SUBMIT_MAX_RCPT) {
            env->overflow = true;
            break;
        }
        snprintf(env->rcpt[env->nrcpt], sizeof env->rcpt[0], "%s", tmp[i]);
        env->nrcpt++;
    }
}

int jmapd_envelope_render(const char *msg, size_t msglen, const char *identity,
                          JmapdEnvelope *out) {
    char hdr[1024], first[256];

    if (!out) return -1;
    memset(out, 0, sizeof *out);
    if (!msg) return -1;

    /* MAIL FROM: the first address of Sender, else From. */
    hdr[0] = '\0';
    (void)mail_header_get(msg, msglen, "Sender", hdr, sizeof hdr);
    if (hdr[0] == '\0')
        (void)mail_header_get(msg, msglen, "From", hdr, sizeof hdr);
    if (jmapd_first_addr(hdr, first, sizeof first) != 0) first[0] = '\0';
    /* RFC 8621 7.5: when the message's own address is not one the Identity may
       send as, the Identity's address is used instead.  This server has one
       address per account, so "not allowed" is "not ours". */
    if (identity && identity[0] &&
        (first[0] == '\0' || strcasecmp(first, identity) != 0))
        snprintf(out->mail_from, sizeof out->mail_from, "%s", identity);
    else
        snprintf(out->mail_from, sizeof out->mail_from, "%s", first);

    /* RCPT TO: the deduplicated To + Cc + Bcc.  mail_header_get leaves the
       buffer untouched when the header is absent, so it is cleared first —
       otherwise a message with no Cc would inherit the To value. */
    hdr[0] = '\0';
    (void)mail_header_get(msg, msglen, "To", hdr, sizeof hdr);
    env_add_rcpt(out, hdr);
    hdr[0] = '\0';
    (void)mail_header_get(msg, msglen, "Cc", hdr, sizeof hdr);
    env_add_rcpt(out, hdr);
    hdr[0] = '\0';
    (void)mail_header_get(msg, msglen, "Bcc", hdr, sizeof hdr);
    env_add_rcpt(out, hdr);
    return out->nrcpt == 0 ? -1 : 0;
}

/* Is this a syntactically valid RFC 5321 mailbox (mail.c's strict parser)? */
static bool addr_valid(const char *s) {
    char *local = NULL, *domain = NULL;
    bool ok = mail_addr_parse(s, &local, &domain) == 0;
    mail_addr_free(local, domain);
    return ok;
}

/* ------------------------------------------------------------------ */
/* EmailSubmission/set                                                 */
/* ------------------------------------------------------------------ */

/* jsonb_detach HANDS BACK the buffer rather than freeing it (json.c's
   contract), so a section that is spliced and then dropped must free it. */
static void jb_discard(JsonBuilder *b) {
    char *p = jsonb_detach(b, NULL);
    free(p);
}

/* One created submission, kept for onSuccessUpdateEmail's resolution. */
typedef struct SubCreated {
    char id[64];             /* the server id we answered ("s<n>") */
    char cid[JMAPD_ID_MAX];  /* the CLIENT's creation id — what a "#cid" key in
                                this same request names (RFC 8621 7.5: the
                                server id is not yet known to the client) */
    char email_id[JMAPD_ID_MAX];
} SubCreated;

/* Is this an EmailSubmission id THIS server issues ("s" + a counter)?  Used to
   tell "a submission you sent, which cannot be unsent" from "no such object"
   on update/destroy, since v1 keeps no submission records (only the ledger of
   submitted Email ids). */
static bool sub_id_ours(const char *id) {
    size_t i;
    if (!id || id[0] != 's' || id[1] == '\0') return false;
    for (i = 1; id[i]; i++)
        if (id[i] < '0' || id[i] > '9') return false;
    return true;
}

/* Resolve an onSuccessUpdateEmail / onSuccessDestroyEmail key: "#<creationId>"
   names a create in THIS call by its CLIENT id (RFC 8621 7.5 — the server id
   is not yet known to the client in the same request); a bare key may name a
   server id.  Both forms are checked against the ids actually recorded. */
static const char *sub_email_of(const SubCreated *created, size_t ncreated,
                                const char *key, size_t keylen) {
    size_t i;
    bool ref = keylen > 1 && key[0] == '#';
    if (ref) {
        key++;
        keylen--;
    }
    for (i = 0; i < ncreated; i++) {
        const char *want = ref ? created[i].cid : created[i].id;
        if (strlen(want) == keylen && memcmp(want, key, keylen) == 0)
            return created[i].email_id;
    }
    return NULL;
}

/* Locate one Email by JMAP id.  Returns 0 with *loc filled, or -1. */
static int sub_locate(JmapdServer *srv, const char *user, const char *email_id,
                      JmapdEmail *loc) {
    memset(loc, 0, sizeof *loc);
    if (jmapd_id_email_parse(email_id, loc->base, sizeof loc->base, loc->mbox,
                             sizeof loc->mbox) != 0)
        return -1;
    snprintf(loc->id, sizeof loc->id, "%s", email_id);
    if (jmapd_email_locate(srv, user, loc, 1) != 0) return -1;
    return loc->found ? 0 : -1;
}

/* File the submitted Email in the Sent mailbox and mark it read.
 *
 * $draft is CLEARED and $seen set as part of the submission, not left to the
 * client's onSuccessUpdateEmail: a message that has been sent is not a draft,
 * and a client that only moves it would otherwise show it as one again on the
 * next refresh (RFC 8621 7.5 lets the server adjust the message "in accordance
 * with the server's policy").  The Email id survives: a maildir move renames
 * the file and keeps its base name.
 *
 * Returns 0 when the Email is in Sent afterwards, -1 otherwise. */
static int sub_move_to_sent(JmapdServer *srv, const char *user,
                            const JmapdEmail *loc) {
    const char *sent = jmapd_role_mbox("sent");
    uint8_t flags = (uint8_t)((loc->flags | IMAIL_SEEN) & ~IMAIL_DRAFT);
    Mbox mb;
    Imail *m = NULL;
    uint32_t uv = 0, uid = 0;
    size_t i;
    int rc = -1;

    if (!sent) return -1;
    if (imapd_mbox_peek(&srv->icfg, user, loc->mbox, &mb) != 0) return -1;
    for (i = 0; i < mb.nmsgs; i++)
        if (mb.msgs[i].base && strcmp(mb.msgs[i].base, loc->base) == 0) {
            m = &mb.msgs[i];
            break;
        }
    if (m) {
        if (m->flags != flags) (void)imapd_mbox_store(&mb, m->uid, flags);
        if (strcmp(loc->mbox, sent) == 0)
            rc = 0;   /* already filed; only the keywords needed changing */
        else if (imapd_mbox_file(&srv->icfg, user, &mb, m->uid, sent, true, &uv,
                                 &uid) == 0)
            rc = 0;
    }
    imapd_mbox_close(&mb);
    return rc;
}

/* The SetError builder for one notCreated entry (RFC 8620 5.3 + RFC 8621
   7.5's extra types).  `extra` is emitted verbatim before the closing brace. */
static void sub_error(JsonBuilder *b, const char *type, const char *prop,
                      const char *desc, const char *extra) {
    jsonb_begin_object(b);
    jsonb_key(b, "type");
    jsonb_str(b, type);
    if (prop && prop[0]) {
        jsonb_comma(b);
        jsonb_key(b, "properties");
        jsonb_begin_array(b);
        jsonb_str(b, prop);
        jsonb_end_array(b);
    }
    if (desc && desc[0]) {
        jsonb_comma(b);
        jsonb_key(b, "description");
        jsonb_str(b, desc);
    }
    if (extra && extra[0]) {
        jsonb_comma(b);
        jmapd_jb_lit(b, extra);
    }
    jsonb_end_object(b);
}

/* How many offending rcptTo addresses an invalidRecipients answer names. */
#define SUB_MAX_INVALID 8

/* Read a JSON array of Address objects into the envelope's rcptTo.
 *
 * Nothing is silently dropped: an address that does not parse is recorded in
 * `invalid` (RFC 8621 7.5 requires the SetError to LIST them), and an
 * over-long list sets *overflow so the caller can answer tooManyRecipients
 * rather than quietly sending to a prefix of the recipients. */
static size_t sub_rcpt_from_json(const JmapJsonNode *arr,
                                 char out[][256], size_t max, size_t *overflow,
                                 char invalid[][256], size_t invalid_max,
                                 size_t *ninvalid, bool *shape_bad) {
    size_t n = 0, i, cnt;
    *overflow = 0;
    *ninvalid = 0;
    *shape_bad = false;
    if (!arr || arr->type != JMAP_JSON_ARR) { *shape_bad = true; return 0; }
    cnt = jmap_json_count(arr);
    for (i = 0; i < cnt; i++) {
        const JmapJsonNode *e = jmap_json_at(arr, i);
        const char *s;
        size_t sl;
        if (!e || e->type != JMAP_JSON_OBJ ||
            jmap_json_str(jmap_json_get(e, "email"), &s, &sl) != 0 || sl == 0) {
            *shape_bad = true;
            continue;
        }
        if (sl >= 256 || !addr_valid(s)) {
            if (*ninvalid < invalid_max)
                snprintf(invalid[(*ninvalid)++], 256, "%.*s", (int)sl, s);
            else
                (*ninvalid)++;
            continue;
        }
        if (n >= max) {
            (*overflow)++;
            continue;
        }
        snprintf(out[n], 256, "%.*s", (int)sl, s);
        n++;
    }
    return n;
}

int jmapd_method_email_submission_set(JmapdCtx *ctx, const JmapJsonNode *args,
                                      JsonBuilder *out) {
    JmapdServer *srv = ctx->srv;
    const char *user = ctx->user;
    const JmapJsonNode *create = jmapd_arg(ctx, args, "create");
    const JmapJsonNode *update = jmapd_arg(ctx, args, "update");
    const JmapJsonNode *destroy = jmapd_arg(ctx, args, "destroy");
    const JmapJsonNode *ifstate = jmapd_arg(ctx, args, "ifInState");
    const JmapJsonNode *onupd = jmapd_arg(ctx, args, "onSuccessUpdateEmail");
    const JmapJsonNode *ondel = jmapd_arg(ctx, args, "onSuccessDestroyEmail");
    JmapdState st;
    char old_state[32], new_state[32];
    char identity_id[JMAPD_ID_MAX], identity_addr[256];
    JsonBuilder created_b, notcreated_b, notupdated_b, notdestroyed_b;
    SubCreated *subs = NULL;
    size_t nsubs = 0;
    /* v1 refuses every update and destroy of a submission (there is nothing to
       unsend and no record to delete), so there is no `updated`/`destroyed`
       section to build: RFC 8620 5.3 wants them null/absent in that case. */
    unsigned changed = 0, ncreated = 0, nnotc = 0, nnotu = 0, nnotd = 0;

    if (ctx->argerr) { jmapd_jb_method_error(out, ctx->argerr); return 0; }

    jmapd_state_load(srv, user, &st);
    jmapd_state_sync(srv, user, &st);
    if (jmapd_state_fmt('s', st.submission, old_state, sizeof old_state) != 0)
        return -1;
    if (ifstate && ifstate->type != JMAP_JSON_NULL) {
        const char *s;
        if (jmap_json_str(ifstate, &s, NULL) != 0) {
            jmapd_jb_method_error(out, "invalidArguments");
            return 0;
        }
        if (strcmp(s, old_state) != 0) {
            jmapd_jb_method_error(out, "stateMismatch");
            return 0;
        }
    }
    if (create && create->type == JMAP_JSON_NULL) create = NULL;
    if (update && update->type == JMAP_JSON_NULL) update = NULL;
    if (destroy && destroy->type == JMAP_JSON_NULL) destroy = NULL;
    if (onupd && onupd->type == JMAP_JSON_NULL) onupd = NULL;
    if (ondel && ondel->type == JMAP_JSON_NULL) ondel = NULL;
    if ((create && create->type != JMAP_JSON_OBJ) ||
        (update && update->type != JMAP_JSON_OBJ) ||
        (destroy && destroy->type != JMAP_JSON_ARR) ||
        (onupd && onupd->type != JMAP_JSON_OBJ) ||
        (ondel && ondel->type != JMAP_JSON_ARR)) {
        jmapd_jb_method_error(out, "invalidArguments");
        return 0;
    }
    if ((create ? jmap_json_count(create) : 0) +
            (update ? jmap_json_count(update) : 0) +
            (destroy ? jmap_json_count(destroy) : 0) > JMAPD_MAX_SET) {
        jmapd_jb_method_error(out, "requestTooLarge");
        return 0;
    }
    if (jmapd_identity_id(user, identity_id, sizeof identity_id) != 0) return -1;
    if (jmapd_identity_email(srv, user, identity_addr,
                             sizeof identity_addr) != 0) {
        /* --identity longer than an SMTP reverse-path can carry: refuse the
           call rather than send a truncated envelope address. */
        jmapd_jb_method_error(out, "serverFail");
        return 0;
    }

    /* Each response section is built as its own OBJECT so it can be spliced
       with jmapd_jb_lit: an empty section is simply never spliced (RFC 8620
       5.3 allows the map to be null/absent). */
    jsonb_init(&created_b);      jsonb_begin_object(&created_b);
    jsonb_init(&notcreated_b);   jsonb_begin_object(&notcreated_b);
    jsonb_init(&notupdated_b);   jsonb_begin_object(&notupdated_b);
    jsonb_init(&notdestroyed_b); jsonb_begin_object(&notdestroyed_b);
    subs = calloc(JMAPD_MAX_SET, sizeof *subs);
    if (!subs) goto fail;

    /* ---- create: the send itself ---- */
    if (create && jmap_json_count(create) > 0) {
        size_t nc = jmap_json_count(create), k;
        if (nc > JMAPD_MAX_SET) nc = JMAPD_MAX_SET;
        for (k = 0; k < nc; k++) {
            const JmapJsonNode *e = jmap_json_at(create, k);
            const char *cid, *identity, *email_id;
            size_t identity_len = 0, email_id_len = 0;
            const JmapJsonNode *env;
            JmapdEmail loc;
            JmapdEnvelope envelope;
            char *msg = NULL;
            size_t msglen = 0;
            char subid[64], send_at[32];
            bool ok = false, tempfail = false, env_ok = true;
            char status[256];
            int qrc;

            if (!e || !e->key) continue;
            cid = e->key;
            if (e->type != JMAP_JSON_OBJ ||
                jmap_json_str(jmap_json_get(e, "identityId"), &identity,
                              &identity_len) != 0 ||
                jmap_json_str(jmap_json_get(e, "emailId"), &email_id,
                              &email_id_len) != 0 ||
                identity_len == 0 || email_id_len == 0 ||
                email_id_len >= JMAPD_ID_MAX) {
                jsonb_key(&notcreated_b, cid);
                sub_error(&notcreated_b, "invalidProperties", NULL,
                          "identityId and emailId are required", NULL);
                nnotc++;
                continue;
            }
            if (identity_len != strlen(identity_id) ||
                memcmp(identity, identity_id, identity_len) != 0) {
                jsonb_key(&notcreated_b, cid);
                sub_error(&notcreated_b, "invalidProperties", "identityId",
                          "no such identity", NULL);
                nnotc++;
                continue;
            }
            {
                char eid[JMAPD_ID_MAX];
                snprintf(eid, sizeof eid, "%.*s", (int)email_id_len, email_id);
                if (sub_locate(srv, user, eid, &loc) != 0) {
                    jsonb_key(&notcreated_b, cid);
                    sub_error(&notcreated_b, "invalidProperties", "emailId",
                              "no such email", NULL);
                    nnotc++;
                    continue;
                }
            }
            if (ledger_has(srv, user, loc.id) > 0) {
                jsonb_key(&notcreated_b, cid);
                sub_error(&notcreated_b, "forbidden", "emailId",
                          "this email was already submitted", NULL);
                nnotc++;
                continue;
            }
            if (jmapd_read_file(srv, loc.path, loc.size, &msg, &msglen) != 0 ||
                !msg) {
                jsonb_key(&notcreated_b, cid);
                sub_error(&notcreated_b, "serverFail", NULL,
                          "could not read the message", NULL);
                nnotc++;
                free(msg);
                continue;
            }
            /* The SEND limit is the submission queue's, not the read cap: the
               whole message must be resident while the worker runs
               (JMAPD_SUBMIT_QUEUE_BYTES < max_msg, so the read never
               truncates below it).  Checked HERE, before admission, so a
               too-large draft is answered tooLarge with the real limit
               instead of submit_queue's "the submission queue is full". */
            if (msglen > JMAPD_SUBMIT_QUEUE_BYTES) {
                char extra[64];
                snprintf(extra, sizeof extra, "\"maxSize\":%u",
                         (unsigned)JMAPD_SUBMIT_QUEUE_BYTES);
                jsonb_key(&notcreated_b, cid);
                sub_error(&notcreated_b, "tooLarge", NULL,
                          "the message is larger than this server sends",
                          extra);
                nnotc++;
                free(msg);
                continue;
            }

            /* The envelope: from the client when given, else from the
               message.  Rendered BEFORE the Bcc header is stripped, because
               the Bcc recipients ARE part of rcptTo. */
            env = jmap_json_get(e, "envelope");
            if (env && env->type != JMAP_JSON_NULL) {
                const JmapJsonNode *mf = jmap_json_get(env, "mailFrom");
                const JmapJsonNode *rt = jmap_json_get(env, "rcptTo");
                const char *mfaddr = NULL;
                size_t mflen = 0, nover = 0, ninvalid = 0;
                char invalid[SUB_MAX_INVALID][256];
                bool shape_bad = false;
                memset(&envelope, 0, sizeof envelope);
                if (env->type != JMAP_JSON_OBJ ||
                    jmap_json_str(jmap_json_get(mf, "email"), &mfaddr,
                                  &mflen) != 0 ||
                    mflen == 0 || mflen >= sizeof envelope.mail_from) {
                    env_ok = false;
                } else {
                    snprintf(envelope.mail_from, sizeof envelope.mail_from,
                             "%.*s", (int)mflen, mfaddr);
                    /* The client's own envelope goes into an SMTP command, so
                       it is validated here, not trusted. */
                    if (!addr_valid(envelope.mail_from)) env_ok = false;
                }
                if (!env_ok) {
                    jsonb_key(&notcreated_b, cid);
                    sub_error(&notcreated_b, "forbiddenMailFrom", "envelope",
                              "the envelope From is not a valid address", NULL);
                    nnotc++;
                    free(msg);
                    continue;
                }
                envelope.nrcpt = sub_rcpt_from_json(
                    rt, envelope.rcpt, JMAPD_SUBMIT_MAX_RCPT, &nover, invalid,
                    SUB_MAX_INVALID, &ninvalid, &shape_bad);
                if (shape_bad || ninvalid) {
                    jsonb_key(&notcreated_b, cid);
                    jsonb_begin_object(&notcreated_b);
                    jsonb_key(&notcreated_b, "type");
                    jsonb_str(&notcreated_b, "invalidRecipients");
                    jsonb_comma(&notcreated_b);
                    jsonb_key(&notcreated_b, "invalidRecipients");
                    jsonb_begin_array(&notcreated_b);
                    {
                        size_t z, nz = ninvalid < SUB_MAX_INVALID
                                           ? ninvalid
                                           : SUB_MAX_INVALID;
                        for (z = 0; z < nz; z++) {
                            if (z) jsonb_comma(&notcreated_b);
                            jsonb_str(&notcreated_b, invalid[z]);
                        }
                    }
                    jsonb_end_array(&notcreated_b);
                    jsonb_end_object(&notcreated_b);
                    nnotc++;
                    free(msg);
                    continue;
                }
                if (nover) {
                    char extra[64];
                    snprintf(extra, sizeof extra, "\"maxRecipients\":%u",
                             (unsigned)JMAPD_SUBMIT_MAX_RCPT);
                    jsonb_key(&notcreated_b, cid);
                    sub_error(&notcreated_b, "tooManyRecipients", NULL, NULL,
                              extra);
                    nnotc++;
                    free(msg);
                    continue;
                }
            } else if (jmapd_envelope_render(msg, msglen, identity_addr,
                                             &envelope) != 0) {
                jsonb_key(&notcreated_b, cid);
                sub_error(&notcreated_b, "noRecipients", NULL,
                          "the message has no To, Cc or Bcc recipient", NULL);
                nnotc++;
                free(msg);
                continue;
            }
            if (envelope.nrcpt == 0) {
                jsonb_key(&notcreated_b, cid);
                sub_error(&notcreated_b, "noRecipients", NULL, NULL, NULL);
                nnotc++;
                free(msg);
                continue;
            }
            if (envelope.overflow) {
                char extra[64];
                snprintf(extra, sizeof extra, "\"maxRecipients\":%u",
                         (unsigned)JMAPD_SUBMIT_MAX_RCPT);
                jsonb_key(&notcreated_b, cid);
                sub_error(&notcreated_b, "tooManyRecipients", NULL,
                          "the message has more recipients than this server "
                          "accepts in one submission", extra);
                nnotc++;
                free(msg);
                continue;
            }
            if (envelope.mail_from[0] == '\0') {
                snprintf(envelope.mail_from, sizeof envelope.mail_from, "%s",
                         identity_addr);
            }

            /* RFC 8621 7.5: the Bcc header MUST be removed from the message
               as delivered.  The maildir copy keeps it (it is the user's own
               record of who was blind-copied); only the submitted bytes lose
               it. */
            (void)mail_header_remove(&msg, &msglen, "Bcc");

            qrc = submit_queue(srv, envelope.mail_from, envelope.rcpt,
                               envelope.nrcpt, msg, msglen,
                               srv->cfg.submit_wait,
                               &ok, &tempfail, status, sizeof status);
            msg = NULL;   /* consumed (freed or queued) by submit_queue */
            if (qrc == 1) {
                jsonb_key(&notcreated_b, cid);
                sub_error(&notcreated_b, "serverUnavailable", NULL,
                          "the submission queue is full", NULL);
                nnotc++;
                continue;
            }
            if (qrc == 0 && !ok) {
                /* The relay refused: NOTHING was sent, so the submission does
                   not exist and the draft keeps its keywords and mailbox. */
                jsonb_key(&notcreated_b, cid);
                sub_error(&notcreated_b,
                          tempfail ? "serverUnavailable" : "serverFail", NULL,
                          status[0] ? status : "the relay refused the message",
                          NULL);
                nnotc++;
                continue;
            }

            /* Accepted.  RFC 8621 7.5: the Email is the user's record, so it
               moves to Sent (the client's patch removes it from Drafts), then
               the onSuccessUpdateEmail patches are applied. */
            if (sub_move_to_sent(srv, user, &loc) != 0)
                fprintf(stderr,
                        "jmapd submission: %s: sent, but could not be filed in "
                        "Sent\n", loc.id);
            ledger_add(srv, user, loc.id);
            st.submission++;
            if (jmapd_state_fmt('s', st.submission, subid, sizeof subid) != 0)
                goto fail;
            jmapd_iso8601_utc(time(NULL), send_at, sizeof send_at);

            snprintf(subs[nsubs].id, sizeof subs[nsubs].id, "%s", subid);
            snprintf(subs[nsubs].cid, sizeof subs[nsubs].cid, "%s", cid);
            snprintf(subs[nsubs].email_id, sizeof subs[nsubs].email_id, "%s",
                     loc.id);
            nsubs++;

            jsonb_key(&created_b, cid);
            jsonb_begin_object(&created_b);
            jsonb_key(&created_b, "id");         jsonb_str(&created_b, subid);
            jsonb_comma(&created_b);
            jsonb_key(&created_b, "emailId");    jsonb_str(&created_b, loc.id);
            jsonb_comma(&created_b);
            jsonb_key(&created_b, "identityId");
            jsonb_str(&created_b, identity_id);
            jsonb_comma(&created_b);
            jsonb_key(&created_b, "sendAt");     jsonb_str(&created_b, send_at);
            jsonb_comma(&created_b);
            jsonb_key(&created_b, "undoStatus");
            jsonb_str(&created_b, "final");
            jsonb_end_object(&created_b);
            ncreated++;
            changed++;
            if (qrc == 2)
                fprintf(stderr,
                        "jmapd submission: %s: accepted-without-verdict: no "
                        "relay verdict within %u ms; filed in Sent and "
                        "recorded as sent, delivery unknown (a later refusal "
                        "leaves it marked sent and refused on resubmission)\n",
                        loc.id, (unsigned)srv->cfg.submit_wait);
        }
    }

    /* ---- update: every submission here is already final ---- */
    if (update && jmap_json_count(update) > 0) {
        size_t nu = jmap_json_count(update), k;
        for (k = 0; k < nu && k < JMAPD_MAX_SET; k++) {
            const JmapJsonNode *e = jmap_json_at(update, k);
            if (!e || !e->key) continue;
            jsonb_key(&notupdated_b, e->key);
            if (sub_id_ours(e->key)) {
                /* RFC 8621 7.5's own SetError for this: the message cannot be
                   unsent once it has been handed to the relay. */
                sub_error(&notupdated_b, "cannotUnsend", "undoStatus", NULL,
                          NULL);
            } else {
                sub_error(&notupdated_b, "notFound", NULL, NULL, NULL);
            }
            nnotu++;
        }
    }
    if (destroy && jmap_json_count(destroy) > 0) {
        size_t nd = jmap_json_count(destroy), k;
        for (k = 0; k < nd && k < JMAPD_MAX_SET; k++) {
            const char *id;
            if (jmap_json_str(jmap_json_at(destroy, k), &id, NULL) != 0) continue;
            jsonb_key(&notdestroyed_b, id);
            if (sub_id_ours(id))
                sub_error(&notdestroyed_b, "forbidden", NULL,
                          "a submission record is kept", NULL);
            else
                sub_error(&notdestroyed_b, "notFound", NULL, NULL, NULL);
            nnotd++;
        }
    }

    /* ---- the implicit Email/set (RFC 8621 7.5) ---- */
    if (onupd) {
        size_t nk = jmap_json_count(onupd), k;
        for (k = 0; k < nk; k++) {
            const JmapJsonNode *m = jmap_json_at(onupd, k);
            const char *email_id;
            JmapdEmail loc;
            const char *err_type = NULL;
            char desc[320];
            if (!m || !m->key) continue;
            email_id = sub_email_of(subs, nsubs, m->key, m->keylen);
            if (!email_id) {
                /* A key naming no submission of THIS call is not an error (the
                   RFC allows naming an earlier submission, which v1 does not
                   track) — but a patch the server did not apply must not be
                   silent: the client would otherwise believe it landed. */
                fprintf(stderr,
                        "jmapd submission: onSuccessUpdateEmail key '%.*s' "
                        "names no submission created here; patch not applied\n",
                        (int)m->keylen, m->key);
                fflush(stderr);
                continue;
            }
            if (sub_locate(srv, user, email_id, &loc) != 0) continue;
            if (jmapd_email_update(srv, user, &loc, m, &err_type, desc,
                                   sizeof desc, &changed) != 0) {
                /* The message has LEFT: reporting the submission as failed
                   would be a lie.  The patch failure is logged, and the
                   client's next Email/get shows the truth. */
                fprintf(stderr,
                        "jmapd submission: %s: onSuccessUpdateEmail failed "
                        "(%s: %s); the message was already sent\n",
                        email_id, err_type ? err_type : "serverFail", desc);
                fflush(stderr);
            }
        }
    }
    if (ondel) {
        size_t nk = jmap_json_count(ondel), k;
        for (k = 0; k < nk; k++) {
            const char *key;
            size_t keylen;
            const char *email_id;
            if (jmap_json_str(jmap_json_at(ondel, k), &key, &keylen) != 0)
                continue;
            email_id = sub_email_of(subs, nsubs, key, keylen);
            if (!email_id) {
                fprintf(stderr,
                        "jmapd submission: onSuccessDestroyEmail id '%.*s' "
                        "names no submission created here; destroy not "
                        "applied\n", (int)keylen, key);
                fflush(stderr);
                continue;
            }
            {
                JmapdEmail loc;
                Mbox mb;
                Imail *im;
                size_t i;
                if (sub_locate(srv, user, email_id, &loc) != 0) continue;
                if (imapd_mbox_peek(&srv->icfg, user, loc.mbox, &mb) != 0)
                    continue;
                im = NULL;
                for (i = 0; i < mb.nmsgs; i++)
                    if (mb.msgs[i].base && strcmp(mb.msgs[i].base, loc.base) == 0) {
                        im = &mb.msgs[i];
                        break;
                    }
                if (im && imapd_mbox_expunge(&mb, im->uid) == 0) changed++;
                imapd_mbox_close(&mb);
            }
        }
    }

    if (changed) {
        /* Bump the observable state AND persist (jmapd_state_bump saves the
           whole struct, so the submission counter above is written with it). */
        jmapd_state_bump(srv, user, &st,
                         JMAPD_ST_EMAIL | JMAPD_ST_MAILBOX | JMAPD_ST_THREAD);
    }
    if (jmapd_state_fmt('s', st.submission, new_state, sizeof new_state) != 0)
        goto fail;

    jsonb_end_object(&created_b);
    jsonb_end_object(&notcreated_b);
    jsonb_end_object(&notupdated_b);
    jsonb_end_object(&notdestroyed_b);

    jsonb_begin_object(out);
    jsonb_key(out, "accountId"); jsonb_str(out, user);
    jsonb_comma(out);
    jsonb_key(out, "oldState");  jsonb_str(out, old_state);
    jsonb_comma(out);
    jsonb_key(out, "newState");  jsonb_str(out, new_state);
    if (ncreated) {
        jsonb_comma(out);
        jsonb_key(out, "created");
        jmapd_jb_lit(out, created_b.buf);
    }
    if (nnotc) {
        jsonb_comma(out);
        jsonb_key(out, "notCreated");
        jmapd_jb_lit(out, notcreated_b.buf);
    }
    if (nnotu) {
        jsonb_comma(out);
        jsonb_key(out, "notUpdated");
        jmapd_jb_lit(out, notupdated_b.buf);
    }
    if (nnotd) {
        jsonb_comma(out);
        jsonb_key(out, "notDestroyed");
        jmapd_jb_lit(out, notdestroyed_b.buf);
    }
    jsonb_end_object(out);

    free(subs);
    jb_discard(&created_b);
    jb_discard(&notcreated_b);
    jb_discard(&notupdated_b);
    jb_discard(&notdestroyed_b);
    return 0;

fail:
    free(subs);
    jb_discard(&created_b);
    jb_discard(&notcreated_b);
    jb_discard(&notupdated_b);
    jb_discard(&notdestroyed_b);
    return -1;
}
