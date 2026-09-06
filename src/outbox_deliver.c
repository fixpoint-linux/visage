/* outbox_deliver.c — off-thread direct-MX delivery queue for the outbox daemon.
 *
 * The poll loop (outbox_main.c) must never block on outbound SMTP or DNS: a
 * reply whose first-leg delivery targets the local ingress (visage) would
 * otherwise wedge the whole single-threaded daemon, because visage has to
 * connect BACK to outbox (the reply_relay hop) to finish that delivery.
 *
 * So DATA completion (outbox_submit.c) spools + DKIM-signs the message and
 * hands a COPY to this queue; a dedicated worker thread drains it and runs the
 * same RFC 5321 direct-MX delivery the inline path used (auth_dns_mx /
 * auth_dns_addr -> smtp_out_send_host with bounded connect/cmd/data timeouts
 * and per-recipient backoff).  The poll thread only appends to the queue
 * (a bounded critical section), so it keeps accepting and servicing SMTP
 * connections — including visage's reply_relay callback — while any number of
 * deliveries are in flight or hung on a slow MX.
 *
 * Threading: exactly ONE worker thread.  It is the sole caller of the DNS and
 * smtp_out machinery (their process-global state — the DNS resolver override,
 * mbedTLS client contexts — is written once at startup and only read here), so
 * nothing races with the poll thread's inbound/TLS/DKIM state.  The queue is
 * mutex + condvar protected and capped (jobs + message bytes): an accepted
 * submission past the cap is refused 4xx at DATA time instead of being
 * enqueued, so an authenticated submitter cannot OOM the daemon (queued mail
 * is lost — v1 does not re-drive the spool).
 */
#include "outbox.h"
#include "visage.h"
#include "auth_results.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>

/* Maximum number of resolved delivery targets (MXs x addresses + A fallback). */
#define DELIVER_MAX_TARGETS (AUTH_MAX_MX * AUTH_MAX_ADDRS + AUTH_MAX_ADDRS)

/* Per-domain MX route cache: TTL + slot count.  Only the worker thread runs
   DNS + delivery (see the threading note above), so this stays lock-free. */
#define DELIVER_MX_CACHE_SLOTS 8
#define DELIVER_MX_CACHE_TTL   300

/* ------------------------------------------------------------------ */
/* Queue                                                              */
/* ------------------------------------------------------------------ */

void outbox_delivery_queue_init(OutboxDeliveryQueue *q) {
    memset(q, 0, sizeof *q);
    pthread_mutex_init(&q->lock, NULL);
    pthread_cond_init(&q->cond, NULL);
    q->max_jobs = OUTBOX_DEFAULT_QUEUE_MAX_JOBS;
    q->max_bytes = OUTBOX_DEFAULT_QUEUE_MAX_BYTES;
}

void outbox_delivery_queue_destroy(OutboxDeliveryQueue *q) {
    pthread_cond_destroy(&q->cond);
    pthread_mutex_destroy(&q->lock);
}

static void job_free(OutboxDeliveryJob *job) {
    size_t i;
    if (!job) return;
    free(job->from);
    for (i = 0; i < job->nrcpts; i++) free(job->rcpts[i]);
    free(job->rcpts);
    free(job->msg);
    free(job->rcpt_done);
    free(job);
}

int outbox_delivery_enqueue(OutboxDeliveryQueue *q, const char *from,
                            char *const *rcpts, size_t nrcpts,
                            const char *msg, size_t msglen) {
    OutboxDeliveryJob *job;
    size_t i;

    if (!q || !rcpts || (nrcpts > 0 && !msg)) return -1;

    job = calloc(1, sizeof *job);
    if (!job) return -1;
    job->from = strdup(from ? from : "");
    if (!job->from) goto fail;
    if (nrcpts > 0) {
        job->rcpts = calloc(nrcpts, sizeof *job->rcpts);
        if (!job->rcpts) goto fail;
        for (i = 0; i < nrcpts; i++) {
            job->rcpts[i] = strdup(rcpts[i] ? rcpts[i] : "");
            if (!job->rcpts[i]) goto fail;
        }
        job->nrcpts = nrcpts;
    }
    job->msg = malloc(msglen ? msglen : 1);
    if (!job->msg) goto fail;
    if (msglen) memcpy(job->msg, msg, msglen);
    job->msglen = msglen;
    if (nrcpts > 0) {
        job->rcpt_done = calloc(nrcpts, 1);
        if (!job->rcpt_done) goto fail;
    }
    job->due = 0;          /* due immediately */
    job->attempt = 1;

    pthread_mutex_lock(&q->lock);
    if (q->shutdown) {   /* producer is past the point of accepting new work */
        pthread_mutex_unlock(&q->lock);
        goto fail;
    }
    /* Cap check + accounting under the lock: bytes tracks job->msglen (the
       dominant term; envelope/rcpts are bounded by max_rcpts and counted via
       njobs).  Caller turns -2 into a 4xx reply. */
    if ((q->max_jobs && q->njobs >= q->max_jobs) ||
        (q->max_bytes && q->bytes + job->msglen > q->max_bytes)) {
        pthread_mutex_unlock(&q->lock);
        job_free(job);
        return -2;   /* cap: caller replies 452 4.3.1 (queue full) */
    }
    if (q->tail)
        q->tail->next = job;
    else
        q->head = job;
    q->tail = job;
    q->njobs++;
    q->bytes += job->msglen;
    pthread_cond_signal(&q->cond);
    pthread_mutex_unlock(&q->lock);
    return 0;

fail:
    job_free(job);
    return -1;
}

void outbox_delivery_shutdown(OutboxDeliveryQueue *q) {
    pthread_mutex_lock(&q->lock);
    q->shutdown = true;
    pthread_cond_broadcast(&q->cond);
    pthread_mutex_unlock(&q->lock);
}

/* ------------------------------------------------------------------ */
/* Direct-MX delivery (moved verbatim from outbox_submit.c)           */
/* ------------------------------------------------------------------ */

/* Small per-domain MX route cache.  Only successful resolutions are cached —
   DNS failures and empty routes stay per-attempt, preserving the original
   retry semantics.  Worker-thread-only (see threading note at top). */
typedef struct {
    char   domain[256];
    time_t filled;
    size_t nips;
    char   ips[DELIVER_MAX_TARGETS][INET6_ADDRSTRLEN];
} DeliverMxRoute;
static DeliverMxRoute mx_cache[DELIVER_MX_CACHE_SLOTS];
static size_t mx_cache_next;

static bool mx_cache_get(const char *domain, char (*ips)[INET6_ADDRSTRLEN],
                         size_t *nips) {
    time_t now = time(NULL);
    size_t i;
    for (i = 0; i < DELIVER_MX_CACHE_SLOTS; i++) {
        DeliverMxRoute *e = &mx_cache[i];
        if (e->domain[0] == '\0') continue;
        if (now - e->filled > DELIVER_MX_CACHE_TTL) continue;
        if (strcmp(e->domain, domain) != 0) continue;
        memcpy(ips, e->ips, e->nips * sizeof e->ips[0]);
        *nips = e->nips;
        return true;
    }
    return false;
}

static void mx_cache_put(const char *domain, char (*ips)[INET6_ADDRSTRLEN],
                         size_t nips) {
    DeliverMxRoute *e;
    if (domain[0] == '\0' || strlen(domain) >= sizeof e->domain) return;
    e = &mx_cache[mx_cache_next];
    mx_cache_next = (mx_cache_next + 1) % DELIVER_MX_CACHE_SLOTS;
    strcpy(e->domain, domain);
    e->filled = time(NULL);
    memcpy(e->ips, ips, nips * sizeof ips[0]);
    e->nips = nips;
}

/* Deliver ONE envelope to ONE recipient via the configured internal relay (the
 * visage MX): the relay host:port is fixed by config, so no MX/DNS resolution
 * happens.  ONE attempt per call — the worker re-enqueues TEMPFAILs with a
 * backoff due-time instead of this function sleeping between retries (which
 * held the single worker hostage). */
static int deliver_internal(OutboxServer *srv, const char *from,
                            const char *rcpt, const char *msg, size_t msglen,
                            char *status, size_t status_sz) {
    return smtp_out_send_host(&srv->deliver_cfg_internal,
                              srv->cfg.internal_relay_host,
                              srv->cfg.internal_relay_port, from, rcpt, msg,
                              msglen, status, status_sz);
}

/* Resolve ONE recipient domain to its delivery targets (RFC 5321 MX
 * preference order; empty/no MX -> fall back to the domain A record), via the
 * per-domain cache when fresh.  Returns 0 when *nips targets are available,
 * else SMTP_PERMFAIL / SMTP_TEMPFAIL with status_out filled in. */
static int deliver_resolve(const char *domain,
                           char (*ips)[INET6_ADDRSTRLEN], size_t *nips,
                           char *status, size_t status_sz) {
    AuthMx mx[AUTH_MAX_MX];
    size_t nmx = 0;
    int mxrc;

    if (mx_cache_get(domain, ips, nips)) return 0;

    mxrc = auth_dns_mx(domain, mx, AUTH_MAX_MX, &nmx);
    if (mxrc < 0) {
        snprintf(status, status_sz, "DNS MX query failed");
        return SMTP_TEMPFAIL;
    }

    if (nmx > 0) {
        size_t i;
        for (i = 0; i < nmx; i++) {
            AuthAddr addrs[AUTH_MAX_ADDRS];
            size_t na = 0, k;
            if (auth_dns_addr(mx[i].host, addrs, AUTH_MAX_ADDRS, &na) < 0)
                continue;
            for (k = 0; k < na && *nips < DELIVER_MAX_TARGETS; k++) {
                if (addrs[k].len == 4) {
                    if (!inet_ntop(AF_INET, addrs[k].ip, ips[*nips],
                                   sizeof ips[*nips]))
                        continue;
                } else if (addrs[k].len == 16) {
                    if (!inet_ntop(AF_INET6, addrs[k].ip, ips[*nips],
                                   sizeof ips[*nips]))
                        continue;
                } else {
                    continue;
                }
                (*nips)++;
            }
        }
        auth_mx_free(mx, nmx);
        if (*nips == 0) {
            snprintf(status, status_sz,
                     "MX hosts present but none resolved to an address");
            return SMTP_TEMPFAIL;
        }
    } else {
        AuthAddr addrs[AUTH_MAX_ADDRS];
        size_t na = 0, k;
        auth_mx_free(mx, nmx);
        if (auth_dns_addr(domain, addrs, AUTH_MAX_ADDRS, &na) < 0) {
            snprintf(status, status_sz, "DNS A/AAAA query failed");
            return SMTP_TEMPFAIL;
        }
        for (k = 0; k < na && *nips < DELIVER_MAX_TARGETS; k++) {
            if (addrs[k].len == 4) {
                if (!inet_ntop(AF_INET, addrs[k].ip, ips[*nips],
                               sizeof ips[*nips]))
                    continue;
            } else if (addrs[k].len == 16) {
                if (!inet_ntop(AF_INET6, addrs[k].ip, ips[*nips],
                               sizeof ips[*nips]))
                    continue;
            } else {
                continue;
            }
            (*nips)++;
        }
        if (*nips == 0) {
            snprintf(status, status_sz, "no MX and no A/AAAA record");
            return SMTP_PERMFAIL;
        }
    }

    mx_cache_put(domain, ips, *nips);
    return 0;
}

/* Deliver ONE envelope to ONE recipient: ONE attempt (target rotation
 * ips[(attempt-1) % nips] across MX preference + address order).  Returns
 * SMTP_OK / SMTP_PERMFAIL / SMTP_TEMPFAIL and fills status_out; the worker
 * re-enqueues TEMPFAIL/SMTP_ERROR with the next backoff due-time. */
static int deliver_recipient(OutboxServer *srv, const char *from,
                             const char *rcpt, const char *msg, size_t msglen,
                             uint32_t attempt, char *status, size_t status_sz) {
    char domain[256];
    char ips[DELIVER_MAX_TARGETS][INET6_ADDRSTRLEN];
    size_t nips = 0;

    snprintf(status, status_sz, "no route");
    if (outbox_addr_domain(rcpt, domain, sizeof domain) != 0) {
        snprintf(status, status_sz, "invalid recipient address");
        return SMTP_PERMFAIL;
    }

    /* Internal-domain routing: a served-domain recipient belongs to the user's
       own mail system, so hand it to the configured internal relay (visage MX)
       for reverse-alias/alias forwarding — NOT the public MX (which for these
       domains resolves back to our own ingress and used to self-deliver). */
    if (srv->cfg.internal_relay_host && srv->cfg.internal_relay_host[0] &&
        outbox_domain_internal(&srv->cfg, domain))
        return deliver_internal(srv, from, rcpt, msg, msglen, status,
                                status_sz);

    {
        int rr = deliver_resolve(domain, ips, &nips, status, status_sz);
        if (rr != 0) return rr;
    }

    return smtp_out_send_host(&srv->deliver_cfg, ips[(attempt - 1) % nips],
                              srv->cfg.deliver_port, from, rcpt, msg,
                              msglen, status, status_sz);
}

/* ------------------------------------------------------------------ */
/* Worker                                                             */
/* ------------------------------------------------------------------ */

/* One delivery pass over the job's still-pending recipients at the job's
 * current attempt.  Every recipient keeps its own attempt count in lockstep
 * (the old inline loop ran one recipient to exhaustion before starting the
 * next, holding the worker for the full backoff chain).  Returns 1 when the
 * job must be retried — re-append it with the next backoff due-time — or 0
 * when every recipient reached a terminal outcome (each logged once, like the
 * old per-recipient loop did). */
static int job_deliver(OutboxServer *srv, OutboxDeliveryJob *job) {
    uint32_t max_attempts = srv->cfg.max_attempts
                                ? srv->cfg.max_attempts
                                : OUTBOX_DEFAULT_MAX_ATTEMPTS;
    size_t pending = 0;
    size_t i;

    for (i = 0; i < job->nrcpts; i++) {
        char status[512];
        int rc;
        if (job->rcpt_done[i]) continue;
        rc = deliver_recipient(srv, job->from, job->rcpts[i], job->msg,
                               job->msglen, job->attempt, status,
                               sizeof status);
        if (rc == SMTP_OK || rc == SMTP_PERMFAIL) {
            job->rcpt_done[i] = 1;
        } else if (job->attempt >= max_attempts) {
            job->rcpt_done[i] = 1;
            snprintf(status, sizeof status,
                     "temporary failure after %u attempts", max_attempts);
        } else {
            pending++;              /* SMTP_TEMPFAIL / SMTP_ERROR: retry */
            continue;
        }
        fprintf(stderr, "outbox: delivery %s -> %s: %s\n",
                job->from && job->from[0] ? job->from : "<>", job->rcpts[i],
                status);
    }
    if (pending == 0) return 0;
    job->attempt++;
    job->due = time(NULL) + (time_t)smtp_backoff_sec(job->attempt);
    return 1;
}

/* Re-append a TEMPFAILed job for its next attempt.  Deliberately past the
   queue caps: the job was already admitted, and dropping it here would lose
   accepted mail (njobs/bytes were decremented at dequeue and restored here,
   so the caps keep accounting for it). */
static void queue_reappend(OutboxDeliveryQueue *q, OutboxDeliveryJob *job) {
    pthread_mutex_lock(&q->lock);
    job->next = NULL;
    if (q->tail)
        q->tail->next = job;
    else
        q->head = job;
    q->tail = job;
    q->njobs++;
    q->bytes += job->msglen;
    pthread_mutex_unlock(&q->lock);
}

void *outbox_delivery_worker(void *arg) {
    OutboxServer *srv = arg;
    OutboxDeliveryQueue *q = &srv->delivery;

    for (;;) {
        OutboxDeliveryJob *job = NULL;

        /* Pick the first DUE job (FIFO within a tick); otherwise wait until
           the earliest due-time (or new work) and re-check.  After shutdown
           every job is due immediately: drain-then-exit, no backoff waits. */
        pthread_mutex_lock(&q->lock);
        for (;;) {
            OutboxDeliveryJob *it;
            time_t next_due = 0;
            time_t now = time(NULL);
            for (it = q->head; it; it = it->next) {
                if (q->shutdown || it->due <= now) { job = it; break; }
                if (next_due == 0 || it->due < next_due) next_due = it->due;
            }
            if (job || (q->head == NULL && q->shutdown)) break;
            if (q->head == NULL) {
                pthread_cond_wait(&q->cond, &q->lock);
            } else {
                struct timespec ts;
                ts.tv_sec = next_due;
                ts.tv_nsec = 0;
                pthread_cond_timedwait(&q->cond, &q->lock, &ts);
            }
        }
        if (job != NULL) {
            if (job == q->head) {
                q->head = job->next;
                if (q->head == NULL) q->tail = NULL;
            } else {
                OutboxDeliveryJob *prev = q->head;
                while (prev->next != job) prev = prev->next;
                prev->next = job->next;
                if (q->tail == job) q->tail = prev;
            }
            job->next = NULL;
            q->njobs--;
            q->bytes -= job->msglen;
        }
        pthread_mutex_unlock(&q->lock);

        if (job == NULL)
            break;   /* shutdown && queue drained */
        if (job_deliver(srv, job))
            queue_reappend(q, job);
        else
            job_free(job);
    }
    return NULL;
}
