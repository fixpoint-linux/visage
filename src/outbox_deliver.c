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

/* Deliver ONE envelope to ONE recipient via the configured internal relay (the
 * visage MX): the relay host:port is fixed by config, so no MX/DNS resolution
 * happens.  Same bounded connect/cmd/data timeouts and per-attempt backoff as
 * the direct-MX path (smtp_out_send_host is called with retries == 0 and this
 * loop drives the attempts). */
static int deliver_internal(OutboxServer *srv, const char *from,
                            const char *rcpt, const char *msg, size_t msglen,
                            char *status, size_t status_sz) {
    uint32_t max_attempts = srv->cfg.max_attempts
                                ? srv->cfg.max_attempts
                                : OUTBOX_DEFAULT_MAX_ATTEMPTS;
    uint32_t attempt;

    for (attempt = 1; attempt <= max_attempts; attempt++) {
        int rc;
        if (attempt > 1)
            sleep(smtp_backoff_sec(attempt));
        rc = smtp_out_send_host(&srv->deliver_cfg_internal,
                                srv->cfg.internal_relay_host,
                                srv->cfg.internal_relay_port, from, rcpt, msg,
                                msglen, status, status_sz);
        if (rc == SMTP_OK) return SMTP_OK;
        if (rc == SMTP_PERMFAIL) return SMTP_PERMFAIL;
        /* SMTP_TEMPFAIL / SMTP_ERROR: retry */
    }
    snprintf(status, status_sz, "temporary failure after %u attempts",
             max_attempts);
    return SMTP_TEMPFAIL;
}

/* Deliver ONE envelope to ONE recipient via its domain's MX list (RFC 5321:
 * lowest preference first; empty/no MX -> fall back to the domain A record).
 * Returns SMTP_OK / SMTP_PERMFAIL / SMTP_TEMPFAIL and fills status_out. */
static int deliver_recipient(OutboxServer *srv, const char *from,
                             const char *rcpt, const char *msg, size_t msglen,
                             char *status, size_t status_sz) {
    char domain[256];
    AuthMx mx[AUTH_MAX_MX];
    size_t nmx = 0;
    char ips[DELIVER_MAX_TARGETS][INET6_ADDRSTRLEN];
    size_t nips = 0;
    int mxrc;

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
            for (k = 0; k < na && nips < DELIVER_MAX_TARGETS; k++) {
                if (addrs[k].len == 4) {
                    if (!inet_ntop(AF_INET, addrs[k].ip, ips[nips],
                                   sizeof ips[nips]))
                        continue;
                } else if (addrs[k].len == 16) {
                    if (!inet_ntop(AF_INET6, addrs[k].ip, ips[nips],
                                   sizeof ips[nips]))
                        continue;
                } else {
                    continue;
                }
                nips++;
            }
        }
        auth_mx_free(mx, nmx);
        if (nips == 0) {
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
        for (k = 0; k < na && nips < DELIVER_MAX_TARGETS; k++) {
            if (addrs[k].len == 4) {
                if (!inet_ntop(AF_INET, addrs[k].ip, ips[nips], sizeof ips[nips]))
                    continue;
            } else if (addrs[k].len == 16) {
                if (!inet_ntop(AF_INET6, addrs[k].ip, ips[nips], sizeof ips[nips]))
                    continue;
            } else {
                continue;
            }
            nips++;
        }
        if (nips == 0) {
            snprintf(status, status_sz, "no MX and no A/AAAA record");
            return SMTP_PERMFAIL;
        }
    }

    /* Try targets in order (MX preference, then address order), rotating
       across the list with exponential backoff up to max_attempts.  5xx is
       permanent and stops the loop; 4xx/transport errors advance to the next
       target. */
    {
        uint32_t attempt;
        uint32_t max_attempts = srv->cfg.max_attempts
                                    ? srv->cfg.max_attempts
                                    : OUTBOX_DEFAULT_MAX_ATTEMPTS;
        for (attempt = 1; attempt <= max_attempts; attempt++) {
            const char *target = ips[(attempt - 1) % nips];
            int rc;
            if (attempt > 1)
                sleep(smtp_backoff_sec(attempt));
            rc = smtp_out_send_host(&srv->deliver_cfg, target,
                                    srv->cfg.deliver_port, from, rcpt, msg,
                                    msglen, status, status_sz);
            if (rc == SMTP_OK) return SMTP_OK;
            if (rc == SMTP_PERMFAIL) return SMTP_PERMFAIL;
            /* SMTP_TEMPFAIL / SMTP_ERROR: try the next target */
        }
        snprintf(status, status_sz, "temporary failure after %u attempts",
                 max_attempts);
        return SMTP_TEMPFAIL;
    }
}

/* ------------------------------------------------------------------ */
/* Worker                                                             */
/* ------------------------------------------------------------------ */

static void job_deliver(OutboxServer *srv, OutboxDeliveryJob *job) {
    size_t i;
    for (i = 0; i < job->nrcpts; i++) {
        char status[512];
        (void)deliver_recipient(srv, job->from, job->rcpts[i], job->msg,
                                job->msglen, status, sizeof status);
        fprintf(stderr, "outbox: delivery %s -> %s: %s\n",
                job->from && job->from[0] ? job->from : "<>", job->rcpts[i],
                status);
    }
}

void *outbox_delivery_worker(void *arg) {
    OutboxServer *srv = arg;
    OutboxDeliveryQueue *q = &srv->delivery;

    for (;;) {
        OutboxDeliveryJob *job = NULL;

        pthread_mutex_lock(&q->lock);
        while (q->head == NULL && !q->shutdown)
            pthread_cond_wait(&q->cond, &q->lock);
        if (q->head != NULL) {
            job = q->head;
            q->head = job->next;
            if (q->head == NULL) q->tail = NULL;
            q->njobs--;
            q->bytes -= job->msglen;
        }
        pthread_mutex_unlock(&q->lock);

        if (job == NULL)
            break;   /* shutdown && queue drained */
        job_deliver(srv, job);
        job_free(job);
    }
    return NULL;
}
