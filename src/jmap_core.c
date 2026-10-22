/* jmap_core.c — jmapd's request layer: authentication, the session resource
 * (RFC 8620 2) and the /api method-call loop (RFC 8620 3).
 *
 * Everything here is protocol plumbing; the mail-specific methods live in
 * jmap_mail.c.  Authentication reuses imapd's credential table and per-IP
 * lockout verbatim (imapd_auth_check / imapd_auth_fail / imapd_auth_blocked),
 * so jmapd and imapd share <root>/imapd.passwd and one brute-force policy.
 *
 * Method calls are dispatched from a static table.  A name that is not in the
 * table is a REQUEST-level error (unknownMethod, HTTP 400) per RFC 8620 3.6.2 —
 * not a method-level error — because the request cannot be interpreted at all.
 * #resultOf back-references resolve against the earlier calls' rendered results
 * (RFC 8620 3.7), which is why each result is built in its own buffer first. */
#include "visage.h"
#include "jmapd.h"
#include "http_parse.h"

#include <sys/socket.h>
#include <arpa/inet.h>
#include <time.h>

/* ------------------------------------------------------------------ */
/* Response-builder helpers (json.c's builder has no null/literal/raw) */
/* ------------------------------------------------------------------ */

/* Append a raw JSON literal ("null", "true", a number) to a builder.  json.c
   exposes only typed emitters, and its buffer fields are public, so this is
   the smallest honest way to reach the same buffer without editing a file
   whose other callers are validated. */
void jmapd_jb_lit(JsonBuilder *b, const char *lit) {
    size_t n = strlen(lit), nc;
    char *nb;
    if (b->err) return;
    if (b->len + n + 1 > b->cap) {
        nc = b->cap ? b->cap : 256;
        while (nc < b->len + n + 1) {
            if (nc > ((size_t)-1) / 2) { b->err = 1; return; }
            nc *= 2;
        }
        nb = realloc(b->buf, nc);
        if (!nb) { b->err = 1; return; }
        b->buf = nb;
        b->cap = nc;
    }
    memcpy(b->buf + b->len, lit, n);
    b->len += n;
    b->buf[b->len] = '\0';
}

void jmapd_jb_u64(JsonBuilder *b, uint64_t v) {
    char tmp[24];
    snprintf(tmp, sizeof tmp, "%llu", (unsigned long long)v);
    jmapd_jb_lit(b, tmp);
}

/* A method-level error object: {"type":"..."} (RFC 8620 3.6.1). */
void jmapd_jb_method_error(JsonBuilder *b, const char *type) {
    jsonb_begin_object(b);
    jsonb_key(b, "type");
    jsonb_str(b, type);
    jsonb_end_object(b);
}

/* ------------------------------------------------------------------ */
/* Session tracing                                                     */
/* ------------------------------------------------------------------ */

void jmapd_log(const JmapdConn *c, const char *event, const char *user,
               const char *detail) {
    char ip[INET6_ADDRSTRLEN];
    ip[0] = '\0';
    if (c->c.peer_ip_len == 4)
        (void)inet_ntop(AF_INET, c->c.peer_ip, ip, sizeof ip);
    else if (c->c.peer_ip_len == 16)
        (void)inet_ntop(AF_INET6, c->c.peer_ip, ip, sizeof ip);
    if (ip[0] == '\0') snprintf(ip, sizeof ip, "unknown");
    fprintf(stderr, "jmapd %s sess=%u proto=jmap peer=%s user=%s%s%s\n", event,
            (unsigned)c->c.id, ip, (user && user[0]) ? user : "-",
            detail ? " " : "", detail ? detail : "");
    fflush(stderr);
}

/* ------------------------------------------------------------------ */
/* Pure helpers                                                        */
/* ------------------------------------------------------------------ */

bool jmapd_addr_loopback(const char *addr) {
    if (!addr || !addr[0]) return false;
    if (strcmp(addr, "localhost") == 0 || strcmp(addr, "::1") == 0)
        return true;
    return strncmp(addr, "127.", 4) == 0;
}

int jmapd_state_fmt(char type, uint64_t n, char *out, size_t outsz) {
    int r = snprintf(out, outsz, "%c%llu", type, (unsigned long long)n);
    if (r < 0 || (size_t)r >= outsz) return -1;
    return 0;
}

int jmapd_auth_parse(const char *v, size_t vlen, int *scheme, char *user,
                     size_t usersz, char *pass, size_t passsz) {
    size_t i = 0;
    if (!v || !scheme || !user || !pass) return -1;
    user[0] = '\0';
    pass[0] = '\0';
    while (i < vlen && (v[i] == ' ' || v[i] == '\t')) i++;
    if (vlen - i >= 6 && http_ci_eq(v + i, "Basic ", 6)) {
        unsigned char raw[1024];
        size_t rawlen = 0, k, colon = SIZE_MAX;
        i += 6;
        while (i < vlen && (v[i] == ' ' || v[i] == '\t')) i++;
        if (imapd_b64_decode(v + i, vlen - i, raw, sizeof raw - 1, &rawlen) != 0)
            return -1;
        raw[rawlen] = '\0';
        for (k = 0; k < rawlen; k++)
            if (raw[k] == ':') { colon = k; break; }
        if (colon == SIZE_MAX) return -1;
        if (colon + 1 > usersz || rawlen - colon > passsz) return -1;
        memcpy(user, raw, colon);
        user[colon] = '\0';
        memcpy(pass, raw + colon + 1, rawlen - colon - 1);
        pass[rawlen - colon - 1] = '\0';
        *scheme = JMAPD_AUTH_BASIC;
        return 0;
    }
    if (vlen - i >= 7 && http_ci_eq(v + i, "Bearer ", 7)) {
        size_t n;
        i += 7;
        while (i < vlen && (v[i] == ' ' || v[i] == '\t')) i++;
        n = vlen - i;
        while (n > 0 && (v[i + n - 1] == ' ' || v[i + n - 1] == '\t')) n--;
        if (n == 0 || n + 1 > passsz) return -1;
        memcpy(pass, v + i, n);
        pass[n] = '\0';
        *scheme = JMAPD_AUTH_BEARER;
        return 0;
    }
    return -1;
}

/* ------------------------------------------------------------------ */
/* Session resource                                                    */
/* ------------------------------------------------------------------ */

/* scheme://host:port for this listener.  The scheme is the one the socket
   actually speaks — https when TLS is configured, http on the plaintext
   loopback dev bind.  A client that trusts this document must never be told a
   scheme the listener does not serve. */
static int base_url(const JmapdConfig *cfg, char *out, size_t outsz) {
    int n = snprintf(out, outsz, "%s://%s:%u", cfg->cert ? "https" : "http",
                     (cfg->hostname && cfg->hostname[0]) ? cfg->hostname
                                                         : "localhost",
                     (unsigned)cfg->port);
    if (n < 0 || (size_t)n >= outsz) return -1;
    return 0;
}

static int jmapd_url_join(const char *base, const char *suffix, char *out,
                    size_t outsz) {
    int n = snprintf(out, outsz, "%s%s", base, suffix);
    if (n < 0 || (size_t)n >= outsz) return -1;
    return 0;
}

int jmapd_session_render(const JmapdConfig *cfg, const char *account_id,
                         char **out, size_t *outlen) {
    JsonBuilder b;
    char base[512], url[768], state[32];
    const char *acct = account_id ? account_id : "";
    int rc = -1;

    if (!cfg || !out || !outlen) return -1;
    *out = NULL;
    *outlen = 0;
    if (base_url(cfg, base, sizeof base) != 0) return -1;
    if (jmapd_state_fmt('s', 0, state, sizeof state) != 0) return -1;

    jsonb_init(&b);
    jsonb_begin_object(&b);

    /* ---- capabilities ---- */
    jsonb_key(&b, "capabilities");
    jsonb_begin_object(&b);
    jsonb_key(&b, JMAPD_CAP_CORE);
    jsonb_begin_object(&b);
    jsonb_key(&b, "maxSizeUpload");         jmapd_jb_u64(&b, 0);
    jsonb_comma(&b);
    jsonb_key(&b, "maxConcurrentUpload");   jmapd_jb_u64(&b, 0);
    jsonb_comma(&b);
    jsonb_key(&b, "maxSizeRequest");        jmapd_jb_u64(&b, cfg->max_req);
    jsonb_comma(&b);
    jsonb_key(&b, "maxConcurrentRequests"); jmapd_jb_u64(&b, 4);
    jsonb_comma(&b);
    jsonb_key(&b, "maxCallsInRequest");     jmapd_jb_u64(&b, JMAPD_MAX_CALLS);
    jsonb_comma(&b);
    jsonb_key(&b, "maxObjectsInGet");       jmapd_jb_u64(&b, JMAPD_MAX_OBJECTS);
    jsonb_comma(&b);
    jsonb_key(&b, "maxObjectsInSet");       jmapd_jb_u64(&b, JMAPD_MAX_OBJECTS);
    jsonb_comma(&b);
    jsonb_key(&b, "collationAlgorithms");
    jsonb_begin_array(&b);
    jsonb_str(&b, "i;ascii-casemap");
    jsonb_end_array(&b);
    jsonb_end_object(&b);
    jsonb_comma(&b);
    jsonb_key(&b, JMAPD_CAP_MAIL);
    jsonb_begin_object(&b);
    jsonb_end_object(&b);
    jsonb_comma(&b);
    jsonb_key(&b, JMAPD_CAP_SUB);
    jsonb_begin_object(&b);
    jsonb_key(&b, "maxDelayedSend");        jmapd_jb_u64(&b, 0);
    jsonb_comma(&b);
    jsonb_key(&b, "submissionExtensions");
    jsonb_begin_object(&b);
    jsonb_end_object(&b);
    jsonb_end_object(&b);
    jsonb_end_object(&b);                   /* capabilities */
    jsonb_comma(&b);

    /* ---- accounts ---- */
    jsonb_key(&b, "accounts");
    jsonb_begin_object(&b);
    jsonb_key(&b, acct);
    jsonb_begin_object(&b);
    jsonb_key(&b, "name");       jsonb_str(&b, acct);
    jsonb_comma(&b);
    jsonb_key(&b, "isPersonal"); jsonb_bool(&b, 1);
    jsonb_comma(&b);
    jsonb_key(&b, "isReadOnly"); jsonb_bool(&b, 0);
    jsonb_comma(&b);
    jsonb_key(&b, "accountCapabilities");
    jsonb_begin_object(&b);
    jsonb_key(&b, JMAPD_CAP_CORE);
    jsonb_begin_object(&b);
    jsonb_end_object(&b);
    jsonb_comma(&b);
    jsonb_key(&b, JMAPD_CAP_MAIL);
    jsonb_begin_object(&b);
    jsonb_key(&b, "maxMailboxesPerEmail");       jmapd_jb_lit(&b, "null");
    jsonb_comma(&b);
    jsonb_key(&b, "maxMailboxDepth");            jmapd_jb_lit(&b, "null");
    jsonb_comma(&b);
    jsonb_key(&b, "maxSizeMailboxName");         jmapd_jb_u64(&b, IMAPD_MAX_MBOX);
    jsonb_comma(&b);
    /* v1 composes text/html bodies only (the mail-hub client sends no
       attachments); the MIME builder refuses attachments rather than dropping
       them, and says so here. */
    jsonb_key(&b, "maxSizeAttachmentsPerEmail"); jmapd_jb_u64(&b, 0);
    jsonb_comma(&b);
    jsonb_key(&b, "emailQuerySortOptions");
    jsonb_begin_array(&b);
    jsonb_str(&b, "receivedAt");
    jsonb_end_array(&b);
    jsonb_comma(&b);
    jsonb_key(&b, "mayCreateTopLevelMailbox");   jsonb_bool(&b, 1);
    jsonb_end_object(&b);
    jsonb_comma(&b);
    jsonb_key(&b, JMAPD_CAP_SUB);
    jsonb_begin_object(&b);
    jsonb_key(&b, "maxDelayedSend");             jmapd_jb_u64(&b, 0);
    jsonb_comma(&b);
    jsonb_key(&b, "submissionExtensions");
    jsonb_begin_object(&b);
    jsonb_end_object(&b);
    jsonb_end_object(&b);
    jsonb_end_object(&b);                   /* accountCapabilities */
    jsonb_end_object(&b);                   /* account */
    jsonb_end_object(&b);                   /* accounts */
    jsonb_comma(&b);

    /* ---- primaryAccounts ---- */
    jsonb_key(&b, "primaryAccounts");
    jsonb_begin_object(&b);
    jsonb_key(&b, JMAPD_CAP_MAIL); jsonb_str(&b, acct);
    jsonb_comma(&b);
    jsonb_key(&b, JMAPD_CAP_SUB);  jsonb_str(&b, acct);
    jsonb_end_object(&b);
    jsonb_comma(&b);

    jsonb_key(&b, "username"); jsonb_str(&b, acct);
    jsonb_comma(&b);

    /* ---- the four URLs the client requires (all absolute, one scheme) ---- */
    if (jmapd_url_join(base, "/api", url, sizeof url) != 0) goto out;
    jsonb_key(&b, "apiUrl");        jsonb_str(&b, url);
    jsonb_comma(&b);
    if (jmapd_url_join(base, "/upload/{accountId}/", url, sizeof url) != 0) goto out;
    jsonb_key(&b, "uploadUrl");     jsonb_str(&b, url);
    jsonb_comma(&b);
    /* RFC 8620 2: a URI Template with {accountId}/{blobId}/{name}; the client
       also substitutes {type} for the Content-Type it will send. */
    if (jmapd_url_join(base, "/download/{accountId}/{blobId}/{name}?accept={type}",
                 url, sizeof url) != 0) goto out;
    jsonb_key(&b, "downloadUrl");   jsonb_str(&b, url);
    jsonb_comma(&b);
    if (jmapd_url_join(base, "/event/", url, sizeof url) != 0) goto out;
    jsonb_key(&b, "eventSourceUrl"); jsonb_str(&b, url);
    jsonb_comma(&b);

    jsonb_key(&b, "state"); jsonb_str(&b, state);
    jsonb_end_object(&b);

    *out = jsonb_detach(&b, outlen);
    rc = *out ? 0 : -1;
out:
    if (rc != 0) jsonb_detach(&b, NULL);
    return rc;
}

/* ------------------------------------------------------------------ */
/* Authentication                                                      */
/* ------------------------------------------------------------------ */

/* Resolve the Authorization header to a user.  Basic carries the user; Bearer
   carries only a token, so the account is whichever passwd entry the token
   matches (constant-time per candidate).  Returns 0 with *user set (owned by
   the caller's buffer) or -1. */
static int auth_resolve(JmapdServer *srv, const JmapdHttpReq *req,
                        char *user, size_t usersz) {
    char pass[512];
    int scheme = JMAPD_AUTH_NONE;
    size_t i;

    if (req->auth_len == 0) return -1;
    if (jmapd_auth_parse(req->auth, req->auth_len, &scheme, user, usersz, pass,
                         sizeof pass) != 0)
        return -1;
    if (scheme == JMAPD_AUTH_BASIC)
        return imapd_auth_check(&srv->auth, user, pass) ? 0 : -1;
    if (scheme == JMAPD_AUTH_BEARER) {
        for (i = 0; i < srv->auth.ncreds; i++) {
            if (imapd_auth_check(&srv->auth, srv->auth.creds[i].user, pass)) {
                size_t l = strlen(srv->auth.creds[i].user);
                if (l + 1 > usersz) return -1;
                memcpy(user, srv->auth.creds[i].user, l + 1);
                return 0;
            }
        }
        return -1;
    }
    return -1;
}

/* Authenticate the connection.  Returns 0 and leaves c->c.user set on
   success; on failure logs the attempt, charges the per-IP lockout and
   returns -1 (the caller answers 401).  Exported because the download route
   is dispatched from jmapd_http.c and must not serve a byte before this. */
int jmapd_core_auth(JmapdServer *srv, JmapdConn *c, const JmapdHttpReq *req) {
    char user[IMAPD_MAX_USER + 1];
    time_t now = time(NULL);

    if (c->c.user) return 0;              /* already authenticated */
    if (imapd_auth_blocked(&srv->auth, c->c.peer_ip, c->c.peer_ip_len, now)) {
        jmapd_log(c, "auth-blocked", NULL, "reason=lockout");
        return -1;
    }
    user[0] = '\0';
    if (auth_resolve(srv, req, user, sizeof user) == 0) {
        imapd_auth_clear(&srv->auth, c->c.peer_ip, c->c.peer_ip_len);
        free(c->c.user);
        c->c.user = strdup(user);
        if (!c->c.user) return -1;
        jmapd_log(c, "auth-ok", c->c.user, NULL);
        return 0;
    }
    imapd_auth_fail(&srv->auth, c->c.peer_ip, c->c.peer_ip_len, now);
    jmapd_log(c, "auth-fail", user[0] ? user : NULL,
              req->auth_len ? "reason=bad-credential" : "reason=no-header");
    return -1;
}

/* ------------------------------------------------------------------ */
/* #resultOf back-references (RFC 8620 3.7)                            */
/* ------------------------------------------------------------------ */

/* Walk one JSON Pointer (RFC 6901) token into node.  Tokens are the object
   member names / array indices a JMAP client names in "path". */
static const JmapJsonNode *ptr_step(const JmapJsonNode *node, const char *tok,
                                    size_t toklen) {
    char key[JMAPD_MAX_REF_PATH + 1];
    size_t i, o = 0;
    if (!node) return NULL;
    if (node->type == JMAP_JSON_ARR) {
        size_t idx = 0;
        if (toklen == 0 || toklen > 9) return NULL;
        for (i = 0; i < toklen; i++) {
            if (tok[i] < '0' || tok[i] > '9') return NULL;
            idx = idx * 10 + (size_t)(tok[i] - '0');
        }
        return jmap_json_at(node, idx);
    }
    if (node->type != JMAP_JSON_OBJ) return NULL;
    /* unescape ~1 -> '/' and ~0 -> '~' (RFC 6901 3) */
    for (i = 0; i < toklen && o < sizeof key - 1; i++) {
        if (tok[i] == '~' && i + 1 < toklen) {
            if (tok[i + 1] == '1') { key[o++] = '/'; i++; continue; }
            if (tok[i + 1] == '0') { key[o++] = '~'; i++; continue; }
        }
        key[o++] = tok[i];
    }
    key[o] = '\0';
    return jmap_json_get(node, key);
}

static const JmapJsonNode *ptr_walk(const JmapJsonNode *node, const char *path,
                                    size_t pathlen) {
    size_t i = 0;
    int depth = 0;
    if (!node || !path) return NULL;
    if (pathlen == 0) return node;
    if (pathlen > JMAPD_MAX_REF_PATH || path[0] != '/') return NULL;
    while (i < pathlen) {
        size_t start;
        if (path[i] != '/' || ++depth > JMAPD_MAX_REF_DEPTH) return NULL;
        i++;
        start = i;
        while (i < pathlen && path[i] != '/') i++;
        node = ptr_step(node, path + start, i - start);
        if (!node) return NULL;
    }
    return node;
}

/* Resolve one {"resultOf","name","path"} reference.  Returns the referenced
   node, or NULL with ctx->argerr set. */
static const JmapJsonNode *resolve_ref(JmapdCtx *ctx, const JmapJsonNode *ref) {
    const JmapJsonNode *ro, *nm, *path;
    const char *ro_s, *nm_s, *path_s;
    size_t ro_l = 0, nm_l = 0, path_l = 0, i;

    if (!ref || ref->type != JMAP_JSON_OBJ) {
        ctx->argerr = "invalidResultReference";
        return NULL;
    }
    ro = jmap_json_get(ref, "resultOf");
    nm = jmap_json_get(ref, "name");
    path = jmap_json_get(ref, "path");
    if (jmap_json_str(ro, &ro_s, &ro_l) != 0 ||
        jmap_json_str(nm, &nm_s, &nm_l) != 0 ||
        jmap_json_str(path, &path_s, &path_l) != 0) {
        ctx->argerr = "invalidResultReference";
        return NULL;
    }
    /* Only an EARLIER call in this request may be referenced, and the client
       must name the method it actually called (RFC 8620 3.7). */
    for (i = 0; i < ctx->nprev; i++) {
        const JmapdCallResult *r = &ctx->prev[i];
        if (strlen(r->callid) != ro_l || memcmp(r->callid, ro_s, ro_l) != 0)
            continue;
        if (strlen(r->name) != nm_l || memcmp(r->name, nm_s, nm_l) != 0) {
            ctx->argerr = "invalidResultReference";
            return NULL;
        }
        if (!r->doc) {
            JmapJsonErr e = JMAP_JSON_OK;
            JmapJsonDoc *d = jmap_json_parse(r->json, r->json_len, &e);
            if (!d) {
                ctx->argerr = "invalidResultReference";
                return NULL;
            }
            ((JmapdCallResult *)r)->doc = d;
        }
        {
            const JmapJsonNode *v = ptr_walk(jmap_json_root(r->doc), path_s,
                                             path_l);
            if (!v) ctx->argerr = "invalidResultReference";
            return v;
        }
    }
    ctx->argerr = "invalidResultReference";
    return NULL;
}

const JmapJsonNode *jmapd_arg(JmapdCtx *ctx, const JmapJsonNode *args,
                              const char *key) {
    char refkey[64];
    const JmapJsonNode *v;
    size_t kl;
    if (!ctx || !key) return NULL;
    kl = strlen(key);
    if (kl + 2 > sizeof refkey) return NULL;
    snprintf(refkey, sizeof refkey, "#%s", key);
    if (args) {
        v = jmap_json_get(args, refkey);
        if (v) return resolve_ref(ctx, v);
        return jmap_json_get(args, key);
    }
    return NULL;
}

/* ------------------------------------------------------------------ */
/* Method table                                                        */
/* ------------------------------------------------------------------ */

typedef struct JmapdMethod {
    const char   *name;
    JmapdMethodFn fn;
} JmapdMethod;

static const JmapdMethod methods[] = {
    { "Mailbox/get",        jmapd_method_mailbox_get         },
    { "Identity/get",       jmapd_method_identity_get        },
    { "Email/query",        jmapd_method_email_query         },
    { "Email/get",          jmapd_method_email_get           },
    { "Email/set",          jmapd_method_email_set           },
    { "Thread/get",         jmapd_method_thread_get          },
    { "EmailSubmission/set", jmapd_method_email_submission_set },
    /* /changes answers cannotCalculateChanges: see jmap_state.c.  They are in
       the table because an unknown METHOD NAME is a request-level error that
       fails the whole request (RFC 8620 3.6.2) — a client asking for changes
       must get the method-level refusal instead. */
    { "Email/changes",      jmapd_method_email_changes       },
    { "Mailbox/changes",    jmapd_method_mailbox_changes     },
    { "Thread/changes",     jmapd_method_thread_changes      },
    { "Email/queryChanges", jmapd_method_email_query_changes },
};

static const JmapdMethod *method_find(const char *name, size_t len) {
    size_t i;
    for (i = 0; i < sizeof methods / sizeof methods[0]; i++)
        if (strlen(methods[i].name) == len &&
            memcmp(methods[i].name, name, len) == 0)
            return &methods[i];
    return NULL;
}

/* The `using` array must be an array of capability names we advertise. */
static bool using_ok(const JmapJsonNode *using) {
    size_t i, n;
    if (!using || using->type != JMAP_JSON_ARR) return false;
    n = jmap_json_count(using);
    if (n == 0 || n > JMAPD_MAX_CAPS) return false;
    for (i = 0; i < n; i++) {
        const JmapJsonNode *e = jmap_json_at(using, i);
        const char *s;
        size_t sl;
        if (jmap_json_str(e, &s, &sl) != 0) return false;
        if (!((sl == strlen(JMAPD_CAP_CORE) &&
               memcmp(s, JMAPD_CAP_CORE, sl) == 0) ||
              (sl == strlen(JMAPD_CAP_MAIL) &&
               memcmp(s, JMAPD_CAP_MAIL, sl) == 0) ||
              (sl == strlen(JMAPD_CAP_SUB) &&
               memcmp(s, JMAPD_CAP_SUB, sl) == 0)))
            return false;
    }
    return true;
}

/* A method's accountId, when present, must name this credential's account:
   one account per credential (plan SCOPE). */
static bool account_ok(const JmapJsonNode *args, const char *user) {
    const JmapJsonNode *a = jmap_json_get(args, "accountId");
    const char *s;
    size_t sl;
    if (!a || a->type == JMAP_JSON_NULL) return true;
    if (jmap_json_str(a, &s, &sl) != 0) return false;
    return sl == strlen(user) && memcmp(s, user, sl) == 0;
}

/* ------------------------------------------------------------------ */
/* /api                                                                */
/* ------------------------------------------------------------------ */

/* Request-level error body: {"type":"..."} with the HTTP status RFC 8620
   3.6.2 assigns to it (400 for every request-level error). */
static int request_error(const char *type, char **out, size_t *outlen) {
    char body[128];
    int n = snprintf(body, sizeof body, "{\"type\":\"%s\"}", type);
    if (n < 0 || (size_t)n >= sizeof body) return -1;
    *out = strdup(body);
    if (!*out) return -1;
    *outlen = (size_t)n;
    return 0;
}

static int api_call(JmapdServer *srv, const char *user, const char *body,
                    size_t bodylen, int *status, char **out, size_t *outlen) {
    JmapJsonErr jerr = JMAP_JSON_OK;
    JmapJsonDoc *doc;
    const JmapJsonNode *root, *calls, *using;
    JsonBuilder b;
    JmapdCallResult prev[JMAPD_MAX_CALLS];
    char state[32];
    size_t i, ncalls;

    doc = jmap_json_parse(body, bodylen, &jerr);
    if (!doc) {
        /* A body that is not JSON at all, or one that is valid JSON but not a
           JMAP request, are different request-level errors. */
        *status = 400;
        return request_error("notJSON", out, outlen);
    }
    root = jmap_json_root(doc);
    if (!root || root->type != JMAP_JSON_OBJ) {
        jmap_json_free(doc);
        *status = 400;
        return request_error("notRequest", out, outlen);
    }
    using = jmap_json_get(root, "using");
    if (!using_ok(using)) {
        jmap_json_free(doc);
        *status = 400;
        return request_error("unknownCapability", out, outlen);
    }
    calls = jmap_json_get(root, "methodCalls");
    if (!calls || calls->type != JMAP_JSON_ARR) {
        jmap_json_free(doc);
        *status = 400;
        return request_error("notRequest", out, outlen);
    }
    ncalls = jmap_json_count(calls);
    if (ncalls > JMAPD_MAX_CALLS) {
        jmap_json_free(doc);
        *status = 400;
        return request_error("limit", out, outlen);
    }

    /* `ifInState` is checked by the methods that take it (Email/set, M3) against
       the persisted per-account counter, not here: it is a method-level error on
       the call that carries it (RFC 8620 5.3), so the rest of the request must
       still run.  An unknown argument is otherwise ignored, as RFC 8620 allows. */

    /* Validate every call before running any: a request with one unknown
       method name is refused whole (RFC 8620 3.6.2 unknownMethod). */
    for (i = 0; i < ncalls; i++) {
        const JmapJsonNode *call = jmap_json_at(calls, i);
        const JmapJsonNode *nm = call ? jmap_json_at(call, 0) : NULL;
        const char *s;
        size_t sl;
        if (!call || call->type != JMAP_JSON_ARR || jmap_json_count(call) != 3 ||
            jmap_json_str(nm, &s, &sl) != 0 ||
            jmap_json_at(call, 1)->type != JMAP_JSON_OBJ ||
            jmap_json_at(call, 2)->type != JMAP_JSON_STR) {
            jmap_json_free(doc);
            *status = 400;
            return request_error("notRequest", out, outlen);
        }
        if (!method_find(s, sl)) {
            jmap_json_free(doc);
            *status = 400;
            return request_error("unknownMethod", out, outlen);
        }
    }

    jsonb_init(&b);
    jsonb_begin_object(&b);
    jsonb_key(&b, "methodResponses");
    jsonb_begin_array(&b);
    memset(prev, 0, sizeof prev);
    for (i = 0; i < ncalls; i++) {
        const JmapJsonNode *call = jmap_json_at(calls, i);
        const JmapJsonNode *nm = jmap_json_at(call, 0);
        const JmapJsonNode *args = jmap_json_at(call, 1);
        const JmapJsonNode *cid = jmap_json_at(call, 2);
        const char *name, *callid;
        size_t nl, rl = 0;
        const JmapdMethod *m;
        JmapdCtx ctx;
        JsonBuilder rb;
        char *rj;

        (void)jmap_json_str(nm, &name, &nl);
        (void)jmap_json_str(cid, &callid, NULL);
        m = method_find(name, nl);
        /* Each result is rendered into its own buffer and only then spliced
           into the response: a later call's #resultOf reference has to read
           this result back as JSON, and the response builder cannot be read. */
        jsonb_init(&rb);
        ctx.srv = srv;
        ctx.user = user;
        ctx.prev = prev;
        ctx.nprev = i;
        ctx.argerr = NULL;
        if (!m) {
            jmapd_jb_method_error(&rb, "unknownMethod");
        } else if (!account_ok(args, user)) {
            jmapd_jb_method_error(&rb, "accountNotFound");
        } else if (m->fn(&ctx, args, &rb) != 0) {
            jsonb_detach(&rb, NULL);
            goto fail;
        }
        if (ctx.argerr) {
            /* A back-reference that cannot be resolved is a METHOD error on
               this call, not a request-level failure: the rest of the request
               still runs (RFC 8620 3.7). */
            jsonb_detach(&rb, NULL);
            jsonb_init(&rb);
            jmapd_jb_method_error(&rb, ctx.argerr);
        }
        rj = jsonb_detach(&rb, &rl);
        if (!rj) goto fail;
        prev[i].callid = strdup(callid);
        prev[i].name = strdup(m ? m->name : name);
        prev[i].json = rj;
        prev[i].json_len = rl;
        if (!prev[i].callid || !prev[i].name) goto fail;

        if (i) jsonb_comma(&b);
        jsonb_begin_array(&b);
        jsonb_str(&b, m ? m->name : name);
        jsonb_comma(&b);
        jmapd_jb_lit(&b, rj);
        jsonb_comma(&b);
        jsonb_str(&b, callid);
        jsonb_end_array(&b);
        if (b.err) goto fail;
    }
    jsonb_end_array(&b);
    jsonb_comma(&b);
    jsonb_key(&b, "sessionState");
    if (jmapd_state_fmt('s', 0, state, sizeof state) != 0) {
        jmap_json_free(doc);
        jsonb_detach(&b, NULL);
        return -1;
    }
    jsonb_str(&b, state);
    jsonb_end_object(&b);

    jmap_json_free(doc);
    for (i = 0; i < ncalls; i++) {
        free(prev[i].callid);
        free(prev[i].name);
        free(prev[i].json);
        jmap_json_free(prev[i].doc);
    }
    *out = jsonb_detach(&b, outlen);
    if (!*out) return -1;
    *status = 200;
    return 0;

fail:
    jmap_json_free(doc);
    jsonb_detach(&b, NULL);
    for (i = 0; i < ncalls; i++) {
        free(prev[i].callid);
        free(prev[i].name);
        free(prev[i].json);
        jmap_json_free(prev[i].doc);
    }
    *status = 400;
    return request_error("serverFail", out, outlen);
}

/* ------------------------------------------------------------------ */
/* Router                                                              */
/* ------------------------------------------------------------------ */

/* Exact path match.  The length comes from the literal, never from a
   hand-counted constant: a mismatch here silently routes a GET session
   request into the POST handler. */
static bool path_is(const JmapdHttpReq *req, const char *lit) {
    size_t n = strlen(lit);
    return req->path_len == n && memcmp(req->path, lit, n) == 0;
}

int jmapd_core_handle(JmapdServer *srv, JmapdConn *c, const JmapdHttpReq *req,
                      const char *body, size_t bodylen, int *status,
                      const char **ctype, char **out, size_t *outlen) {
    static const char jtype[] = "application/json; charset=utf-8";
    *out = NULL;
    *outlen = 0;
    *status = 200;
    *ctype = jtype;

    if (jmapd_core_auth(srv, c, req) != 0) {
        *status = 401;
        return request_error("unauthorized", out, outlen) == 0 ? 0 : -1;
    }

    /* GET /.well-known/jmap (and /jmap/session): the session resource. */
    if (!path_is(req, "/jmap/session") && !path_is(req, "/.well-known/jmap"))
        return api_call(srv, c->c.user, body, bodylen, status, out, outlen);
    return jmapd_session_render(&srv->cfg, c->c.user, out, outlen) == 0 ? 0 : -1;
}
