/* config.c — evaluate a Dhall config file and walk its normal form into a
   Config struct (parse_source -> infer_type -> normalize -> walk the Term
   tree). No JSON round-trip. Mirrors compendium/src/config.c exactly; the
   record schema is sentinel-not-Optional (all fields present as concrete
   literals), so no Optional handling is needed. Strings/lists are heap-owned
   so config_free() can release them; on failure config_load() frees whatever
   was built. */
#include "dhall.h"
#include "visage.h"
#include "config.h"
#include <stdarg.h>
#include <string.h>
#include <strings.h>

static char cfg_err[256];
static void cfg_error(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt); vsnprintf(cfg_err, sizeof cfg_err, fmt, ap); va_end(ap);
}

/* Look up a record-literal field BY LABEL. normalize() sorts fields
   alphabetically, so index-based access is wrong. */
static Term *rec_get(Term *t, const char *label) {
    if (!t || t->tag != TmRecordLit) return NULL;
    for (int i = 0; i < t->as.rec.n; i++)
        if (!strcmp(t->as.rec.fs[i].label, label)) return t->as.rec.fs[i].value;
    return NULL;
}

/* Extract a flat Text literal into a heap string. Returns false on error. */
static bool text_dup(Term *t, char **out) {
    if (!t || t->tag != TmText || !t->as.text) { cfg_error("expected Text"); return false; }
    size_t n = 0;
    for (TextPart *p = t->as.text; p; p = p->next) {
        if (p->expr) { cfg_error("text interpolation not normalized"); return false; }
        if (p->lit) n += strlen(p->lit);
    }
    char *s = malloc(n + 1);
    if (!s) { cfg_error("out of memory"); return false; }
    s[0] = '\0';
    for (TextPart *p = t->as.text; p; p = p->next) if (p->lit) strcat(s, p->lit);
    *out = s;
    return true;
}

static bool nat_u64(Term *t, uint64_t *out) {
    if (!t || t->tag != TmConst || t->as.c.kind != C_NAT) { cfg_error("expected Natural"); return false; }
    if (t->as.c.bnat) { cfg_error("Natural exceeds uint64"); return false; }
    *out = t->as.c.nat;
    return true;
}

static bool bool_get(Term *t, bool *out) {
    if (!t || t->tag != TmConst || t->as.c.kind != C_BOOL) { cfg_error("expected Bool"); return false; }
    *out = t->as.c.b;
    return true;
}

/* Count elements in a TmCons/TmNil list. Returns -1 if t is not a list. */
static int list_len(Term *t) {
    int n = 0;
    for (Term *p = t;; p = p->as.cons.tail) {
        if (p->tag == TmNil) return n;
        if (p->tag != TmCons) { cfg_error("expected a list"); return -1; }
        n++;
    }
}

/* Allocate a heap array of the given element Terms, filled in order. */
static Term **list_collect(Term *t, int n) {
    Term **a = malloc(sizeof(Term *) * (size_t)(n > 0 ? n : 1));
    if (!a) { cfg_error("out of memory"); return NULL; }
    int i = 0;
    for (Term *p = t; p->tag == TmCons; p = p->as.cons.tail)
        a[i++] = p->as.cons.head;
    return a;
}

static char **dup_strlist(Term **elems, int n) {
    char **a = malloc(sizeof(char *) * (size_t)(n > 0 ? n : 1));
    if (!a) { cfg_error("out of memory"); return NULL; }
    for (int i = 0; i < n; i++) {
        char *s = NULL;
        if (!text_dup(elems[i], &s)) { free(a); return NULL; }
        a[i] = s;
    }
    return a;
}

static bool walk_config(Config *cfg, Term *nf) {
    if (!nf || nf->tag != TmRecordLit) { cfg_error("config must be a record"); return false; }

    if (!text_dup(rec_get(nf, "hostname"), &cfg->hostname)) return false;

    Term *dom = rec_get(nf, "domains");
    if (!dom) { cfg_error("config missing 'domains'"); return false; }
    int nd = list_len(dom);
    if (nd < 0) return false;
    Term **delems = list_collect(dom, nd);
    if (!delems) return false;
    cfg->domains = dup_strlist(delems, nd);
    free(delems);
    if (!cfg->domains) return false;
    cfg->ndomains = (size_t)nd;

    Term *listen = rec_get(nf, "listen");
    if (!listen) { cfg_error("config missing 'listen'"); return false; }
    if (!text_dup(rec_get(listen, "address"), &cfg->listen.address)) return false;
    uint64_t p = 0;
    if (!nat_u64(rec_get(listen, "port"), &p)) return false;
    cfg->listen.port = (uint32_t)p;

    Term *lim = rec_get(nf, "limits");
    if (!lim) { cfg_error("config missing 'limits'"); return false; }
    uint64_t v = 0;
    if (!nat_u64(rec_get(lim, "message"), &v)) return false;
    cfg->limits.message = (uint32_t)v;
    if (!nat_u64(rec_get(lim, "line"), &v)) return false;
    cfg->limits.line = (uint32_t)v;
    if (!nat_u64(rec_get(lim, "rcpts"), &v)) return false;
    cfg->limits.rcpts = (uint32_t)v;
    if (!nat_u64(rec_get(lim, "cmd_timeout"), &v)) return false;
    cfg->limits.cmd_timeout = (uint32_t)v;
    if (!nat_u64(rec_get(lim, "data_timeout"), &v)) return false;
    cfg->limits.data_timeout = (uint32_t)v;

    Term *rel = rec_get(nf, "relay");
    if (!rel) { cfg_error("config missing 'relay'"); return false; }
    if (!text_dup(rec_get(rel, "host"), &cfg->relay.host)) return false;
    if (!nat_u64(rec_get(rel, "port"), &p)) return false;
    cfg->relay.port = (uint32_t)p;
    if (!nat_u64(rec_get(rel, "retries"), &v)) return false;
    cfg->relay.retries = (uint32_t)v;
    if (!text_dup(rec_get(rel, "tls"), &cfg->relay.tls)) return false;
    {
        /* relay.max_attempts is the durable-queue re-drive cap.  Tolerate an
         * absent field (older configs) by defaulting to 100; a present 0 also
         * falls back to 100 at the usage site. */
        Term *maxa = rec_get(rel, "max_attempts");
        if (maxa) {
            if (!nat_u64(maxa, &v)) return false;
            cfg->relay.max_attempts = (uint32_t)v;
        } else {
            cfg->relay.max_attempts = 100;
        }
    }
    {
        /* relay.tls_ca is optional (older configs omit it): path to a PEM CA
         * bundle used for peer verification when tls == "starttls-verify";
         * empty means the embedded Mozilla bundle.  Default "" when absent. */
        Term *ca = rec_get(rel, "tls_ca");
        if (ca) {
            if (!text_dup(ca, &cfg->relay.tls_ca)) return false;
        } else {
            cfg->relay.tls_ca = strdup("");
            if (!cfg->relay.tls_ca) { cfg_error("out of memory"); return false; }
        }
    }
    Term *auth = rec_get(rel, "auth");
    if (!auth) { cfg_error("config missing 'relay.auth'"); return false; }
    if (!bool_get(rec_get(auth, "enabled"), &cfg->relay.auth.enabled)) return false;
    if (!text_dup(rec_get(auth, "username"), &cfg->relay.auth.username)) return false;
    if (!text_dup(rec_get(auth, "password"), &cfg->relay.auth.password)) return false;

    Term *stor = rec_get(nf, "storage");
    if (!stor) { cfg_error("config missing 'storage'"); return false; }
    if (!text_dup(rec_get(stor, "path"), &cfg->storage.path)) return false;
    if (!text_dup(rec_get(stor, "spool"), &cfg->storage.spool)) return false;

    Term *rep = rec_get(nf, "reply");
    if (!rep) { cfg_error("config missing 'reply'"); return false; }
    if (!text_dup(rec_get(rep, "prefix"), &cfg->reply.prefix)) return false;
    if (!text_dup(rec_get(rep, "separator"), &cfg->reply.separator)) return false;

    if (!text_dup(rec_get(nf, "catch_all"), &cfg->catch_all)) return false;

    Term *al = rec_get(nf, "aliases");
    if (!al) { cfg_error("config missing 'aliases'"); return false; }
    int na = list_len(al);
    if (na < 0) return false;
    Term **aelems = list_collect(al, na);
    if (!aelems) return false;
    cfg->aliases = calloc((size_t)(na > 0 ? na : 1), sizeof(ConfigAlias));
    if (!cfg->aliases) { free(aelems); cfg_error("out of memory"); return false; }
    cfg->naliases = (size_t)na;
    for (int i = 0; i < na; i++) {
        ConfigAlias *ca = &cfg->aliases[i];
        if (!text_dup(rec_get(aelems[i], "alias"), &ca->alias)) { free(aelems); return false; }
        Term *dests = rec_get(aelems[i], "destinations");
        if (!dests) { cfg_error("alias missing 'destinations'"); free(aelems); return false; }
        int ndst = list_len(dests);
        if (ndst < 0) { free(aelems); return false; }
        Term **dele = list_collect(dests, ndst);
        if (!dele) { free(aelems); return false; }
        ca->destinations = dup_strlist(dele, ndst);
        free(dele);
        if (!ca->destinations) { free(aelems); return false; }
        ca->ndestinations = (size_t)ndst;
    }
    free(aelems);

    Term *http = rec_get(nf, "http");
    if (!http) { cfg_error("config missing 'http'"); return false; }
    if (!text_dup(rec_get(http, "address"), &cfg->http.address)) return false;
    if (!nat_u64(rec_get(http, "port"), &p)) return false;
    cfg->http.port = (uint32_t)p;

    Term *adm = rec_get(nf, "admin");
    if (!adm) { cfg_error("config missing 'admin'"); return false; }
    if (!text_dup(rec_get(adm, "token"), &cfg->admin.token)) return false;

    {
        /* dkim is optional (older configs omit it): a list of signing configs
         * { domain, selector, private_key }.  Mirror the relay.tls_ca optional
         * field precedent — absent defaults to an empty list. */
        Term *dk = rec_get(nf, "dkim");
        if (dk) {
            int ndk = list_len(dk);
            if (ndk < 0) return false;
            Term **delems = list_collect(dk, ndk);
            if (!delems) return false;
            cfg->dkim = calloc((size_t)(ndk > 0 ? ndk : 1), sizeof(ConfigDkim));
            if (!cfg->dkim) { free(delems); cfg_error("out of memory"); return false; }
            cfg->ndkim = (size_t)ndk;
            for (int i = 0; i < ndk; i++) {
                ConfigDkim *cd = &cfg->dkim[i];
                if (!text_dup(rec_get(delems[i], "domain"), &cd->domain)) { free(delems); return false; }
                if (!text_dup(rec_get(delems[i], "selector"), &cd->selector)) { free(delems); return false; }
                if (!text_dup(rec_get(delems[i], "private_key"), &cd->private_key)) { free(delems); return false; }
            }
            free(delems);
        } else {
            cfg->ndkim = 0;
            cfg->dkim = NULL;
        }
    }

    return true;
}

ConfigDkim *config_dkim_find(const Config *cfg, const char *domain) {
    if (!cfg || !domain) return NULL;
    for (size_t i = 0; i < cfg->ndkim; i++) {
        if (cfg->dkim[i].domain &&
            strcasecmp(cfg->dkim[i].domain, domain) == 0)
            return &cfg->dkim[i];
    }
    return NULL;
}

int config_alias_read_only(const Config *cfg, const char *alias) {
    if (!cfg || !alias) return 0;
    for (size_t i = 0; i < cfg->naliases; i++) {
        if (cfg->aliases[i].alias &&
            strcasecmp(cfg->aliases[i].alias, alias) == 0)
            return 1;
    }
    return 0;
}

static char *read_all(FILE *f) {
    size_t cap = 65536, len = 0;
    char *buf = malloc(cap);
    if (!buf) return NULL;
    for (;;) {
        if (len == cap) { cap *= 2; char *nb = realloc(buf, cap); if (!nb) { free(buf); return NULL; } buf = nb; }
        size_t n = fread(buf + len, 1, cap - len, f);
        len += n;
        if (n == 0) break;
    }
    buf[len] = '\0';
    return buf;
}

int config_load(const char *path, Config *cfg, char *errbuf, size_t errcap) {
    memset(cfg, 0, sizeof *cfg);
    if (errbuf && errcap > 0) errbuf[0] = '\0';

    FILE *in = fopen(path, "rb");
    if (!in) { if (errbuf) snprintf(errbuf, errcap, "cannot open config file '%s'", path); return -1; }
    char *src = read_all(in);
    fclose(in);
    if (!src) { if (errbuf) snprintf(errbuf, errcap, "out of memory reading '%s'", path); return -1; }

    if (!dhall_arena) dhall_arena = arena_new();
    arena_reset(dhall_arena);

    ImportLoader *loader = import_loader_new();
    import_loader_push_root(loader, path);

    Parser p;
    memset(&p, 0, sizeof p);
    p.loader = loader;
    DhallError err;
    dhall_error_clear(&err);

    Term *t = parse_source(&p, src, path, &err);
    free(src);
    if (!t) {
        if (errbuf) snprintf(errbuf, errcap, "config parse error: %s", err.msg);
        import_loader_free(loader);
        return -1;
    }
    Term *ty = infer_type(&p, t, &err);
    if (!ty) {
        if (errbuf) snprintf(errbuf, errcap, "config type error: %s", err.msg);
        import_loader_free(loader);
        return -1;
    }
    normalize_clear_error();
    Term *nf = normalize(t);
    if (normalize_has_error()) {
        err = *normalize_get_error();
        if (errbuf) snprintf(errbuf, errcap, "config normalize error: %s", err.msg);
        import_loader_free(loader);
        return -1;
    }
    import_loader_free(loader);

    if (!walk_config(cfg, nf)) {
        if (errbuf) snprintf(errbuf, errcap, "config error: %s", cfg_err);
        config_free(cfg);
        return -1;
    }
    return 0;
}

void config_free(Config *cfg) {
    if (!cfg) return;
    free(cfg->hostname);
    for (size_t i = 0; i < cfg->ndomains; i++) free(cfg->domains[i]);
    free(cfg->domains);
    free(cfg->listen.address);
    free(cfg->relay.host);
    free(cfg->relay.tls);
    free(cfg->relay.tls_ca);
    free(cfg->relay.auth.username);
    free(cfg->relay.auth.password);
    free(cfg->storage.path);
    free(cfg->storage.spool);
    free(cfg->reply.prefix);
    free(cfg->reply.separator);
    free(cfg->catch_all);
    for (size_t i = 0; i < cfg->naliases; i++) {
        free(cfg->aliases[i].alias);
        for (size_t j = 0; j < cfg->aliases[i].ndestinations; j++)
            free(cfg->aliases[i].destinations[j]);
        free(cfg->aliases[i].destinations);
    }
    free(cfg->aliases);
    free(cfg->http.address);
    free(cfg->admin.token);
    for (size_t i = 0; i < cfg->ndkim; i++) {
        free(cfg->dkim[i].domain);
        free(cfg->dkim[i].selector);
        free(cfg->dkim[i].private_key);
    }
    free(cfg->dkim);
    memset(cfg, 0, sizeof *cfg);
}
