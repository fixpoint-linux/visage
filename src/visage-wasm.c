/* visage-wasm.c — browser-callable entry point for the visage email alias/forward
 * service. Built to wasm via emscripten INSTEAD OF main.c.
 *
 * Links ONLY the config/address-parsing core + the dhall-c interpreter:
 *   src/visage-wasm.c src/config.c src/mail.c + dhall-c core (12 TUs, no ssrf.c)
 * NOT linked: store.c (datalog-dafsa: disk-persistent DAFSA + WAL/flock/fsync),
 * smtp_in.c / smtp_out.c (SMTP sockets + state machine), dkim.c (mbedTLS),
 * reply.c (depends on store), http.c (visage's admin HTTP listener).
 *
 * The alias-resolution shown here is the SAME decision pipeline as
 * smtp_in_rcpt_ok() (src/smtp_in.c:500): parse the RFC5321 address with the real
 * mail_addr_parse(), gate on the served domain (case-insensitive), resolve against
 * the config's aliases (case-insensitive, matching the DAFSA store's lowercased
 * (domain,local) keys), then fall back to catch-all, else reject.  The only
 * difference from the daemon is WHERE aliases are read: the daemon seeds the DAFSA
 * store 1:1 from this Config struct at boot (store_seed_aliases) and resolves via
 * store_resolve(); here we read the struct directly, which is semantically
 * identical for the seeded aliases.  The reply+<token> reverse-alias path is
 * omitted (it needs the revmap store) — this demo covers alias/catch-all forwarding.
 *
 * Exports (all EMSCRIPTEN_KEEPALIVE):
 *   int         visage_load(const char *src)     — load a Dhall config string
 *   int         visage_resolve(const char *addr) — resolve one alias@domain
 *   const char *visage_err(void)                 — last error message
 *   const char *visage_json(void)                — last result as JSON
 *   int         visage_json_len(void)            — JSON length
 *
 * The Dhall config arrives as a JS string; we write it into emscripten MEMFS (via
 * plain fopen/fwrite — MEMFS backs libc stdio) and call the UNCHANGED config_load()
 * from src/config.c, so the full parse -> infer_type -> normalize -> walk pipeline
 * runs exactly as in the native binary.
 */
#include "dhall.h"
#include "visage.h"
#include "mail.h"
#include <emscripten.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static Config  g_cfg;
static int     g_loaded = 0;
static char    g_err[512];
static char   *g_json = NULL;
static size_t  g_json_len = 0;

/* ASCII case-insensitive full-string equality (mirrors smtp_in.c ascii_ieq_str). */
static bool ascii_ieq(const char *a, const char *b) {
    while (*a && *b) {
        char ca = *a++, cb = *b++;
        if (ca >= 'A' && ca <= 'Z') ca = (char)(ca + 32);
        if (cb >= 'A' && cb <= 'Z') cb = (char)(cb + 32);
        if (ca != cb) return false;
    }
    return *a == *b;
}

static void json_str(FILE *f, const char *s) {
    fputc('"', f);
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        unsigned char c = *p;
        switch (c) {
        case '"':  fputs("\\\"", f); break;
        case '\\': fputs("\\\\", f); break;
        case '\n': fputs("\\n",  f); break;
        case '\r': fputs("\\r",  f); break;
        case '\t': fputs("\\t",  f); break;
        default:
            if (c < 0x20) fprintf(f, "\\u%04x", c);
            else fputc(c, f);
        }
    }
    fputc('"', f);
}

/* Render a config summary (hostname, domains, aliases, catch_all) proving the
 * Dhall -> typechecked -> Config-struct pipeline succeeded. */
static void render_summary(void) {
    free(g_json);
    g_json = NULL;
    g_json_len = 0;
    FILE *f = open_memstream(&g_json, &g_json_len);
    if (!f) return;

    fprintf(f, "{\"hostname\":");
    json_str(f, g_cfg.hostname ? g_cfg.hostname : "");

    fprintf(f, ",\"domains\":[");
    for (size_t i = 0; i < g_cfg.ndomains; i++) {
        if (i) fputc(',', f);
        json_str(f, g_cfg.domains[i] ? g_cfg.domains[i] : "");
    }
    fprintf(f, "],\"naliases\":%zu,\"aliases\":[", g_cfg.naliases);
    for (size_t i = 0; i < g_cfg.naliases; i++) {
        if (i) fputc(',', f);
        ConfigAlias *a = &g_cfg.aliases[i];
        fprintf(f, "{\"alias\":");
        json_str(f, a->alias ? a->alias : "");
        fprintf(f, ",\"destinations\":[");
        for (size_t j = 0; j < a->ndestinations; j++) {
            if (j) fputc(',', f);
            json_str(f, a->destinations[j] ? a->destinations[j] : "");
        }
        fprintf(f, "]}");
    }
    fprintf(f, "],\"catch_all\":");
    json_str(f, g_cfg.catch_all ? g_cfg.catch_all : "");
    fprintf(f, ",\"listen\":");
    {
        char buf[128];
        snprintf(buf, sizeof buf, "%s:%u", g_cfg.listen.address, g_cfg.listen.port);
        json_str(f, buf);
    }
    fprintf(f, "}");
    fclose(f);
}

EMSCRIPTEN_KEEPALIVE
int visage_load(const char *src) {
    g_loaded = 0;
    g_err[0] = '\0';
    free(g_json);
    g_json = NULL;
    g_json_len = 0;
    config_free(&g_cfg);

    if (!src) { snprintf(g_err, sizeof g_err, "null config source"); return -1; }

    FILE *f = fopen("/config.dhall", "wb");
    if (!f) { snprintf(g_err, sizeof g_err, "MEMFS open failed"); return -1; }
    size_t len = strlen(src);
    if (len > 0 && fwrite(src, 1, len, f) != len) {
        fclose(f);
        snprintf(g_err, sizeof g_err, "MEMFS write failed");
        return -1;
    }
    fclose(f);

    int rc = config_load("/config.dhall", &g_cfg, g_err, sizeof g_err);
    if (rc != 0) return -1;

    g_loaded = 1;
    render_summary();
    return 0;
}

/* Resolve one alias@domain against the loaded config (mirrors smtp_in_rcpt_ok). */
EMSCRIPTEN_KEEPALIVE
int visage_resolve(const char *addr) {
    g_err[0] = '\0';
    free(g_json);
    g_json = NULL;
    g_json_len = 0;

    if (!g_loaded) { snprintf(g_err, sizeof g_err, "load a config first"); return -1; }
    if (!addr) { snprintf(g_err, sizeof g_err, "null address"); return -1; }

    char *local = NULL, *domain = NULL;
    const char *decision = "reject";
    const char *route = "";
    char **dests = NULL;
    size_t ndests = 0;

    FILE *f = open_memstream(&g_json, &g_json_len);
    if (!f) { snprintf(g_err, sizeof g_err, "out of memory"); return -1; }

    fprintf(f, "{\"addr\":");
    json_str(f, addr);

    if (mail_addr_parse(addr, &local, &domain) != 0) {
        /* malformed address -> RCPT_NOROUTE */
        fprintf(f, ",\"local\":null,\"domain\":null,\"decision\":\"reject\","
                   "\"route\":\"\",\"reason\":\"malformed address\","
                   "\"destinations\":[]}");
        fclose(f);
        return 0;
    }
    fprintf(f, ",\"local\":");
    json_str(f, local);
    fprintf(f, ",\"domain\":");
    json_str(f, domain);

    /* domain gate (case-insensitive, mirrors smtp_in_rcpt_ok) */
    int served = 0;
    for (size_t i = 0; i < g_cfg.ndomains; i++) {
        if (g_cfg.domains[i] && ascii_ieq(g_cfg.domains[i], domain)) { served = 1; break; }
    }

    if (!served) {
        decision = "reject";
        route = "";
        goto out;
    }

    /* alias resolution: case-insensitive full-string match of "local@domain"
     * against each configured alias (semantically identical to the DAFSA store's
     * lowercased (domain, local) prefix lookup). */
    {
        char key[512];
        int kn = snprintf(key, sizeof key, "%s@%s", local, domain);
        if (kn > 0 && (size_t)kn < sizeof key) {
            for (size_t i = 0; i < g_cfg.naliases; i++) {
                ConfigAlias *a = &g_cfg.aliases[i];
                if (a->alias && ascii_ieq(a->alias, key)) {
                    dests = a->destinations;
                    ndests = a->ndestinations;
                    decision = "accept";
                    route = "alias";
                    break;
                }
            }
        }
    }

    /* catch-all fallback */
    if (!ndests && g_cfg.catch_all && g_cfg.catch_all[0]) {
        dests = &g_cfg.catch_all;
        ndests = 1;
        decision = "accept";
        route = "catch_all";
    }

out:
    fprintf(f, ",\"decision\":");
    json_str(f, decision);
    fprintf(f, ",\"route\":");
    json_str(f, route);
    if (!served) {
        fprintf(f, ",\"reason\":\"domain not served\"");
    } else if (ndests == 0) {
        fprintf(f, ",\"reason\":\"no such alias\"");
    }
    fprintf(f, ",\"destinations\":[");
    for (size_t i = 0; i < ndests; i++) {
        if (i) fputc(',', f);
        json_str(f, dests[i] ? dests[i] : "");
    }
    fprintf(f, "]}");

    fclose(f);
    mail_addr_free(local, domain);
    return 0;
}

EMSCRIPTEN_KEEPALIVE
const char *visage_err(void) { return g_err; }

EMSCRIPTEN_KEEPALIVE
const char *visage_json(void) { return g_json ? g_json : ""; }

EMSCRIPTEN_KEEPALIVE
int visage_json_len(void) { return (int)g_json_len; }
