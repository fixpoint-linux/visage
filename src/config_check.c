/* config_check.c — standalone check that loads config.example.dhall and
   prints the parsed Config. Returns 0 on success, nonzero on any error. */
#include "visage.h"
#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int failures;

static void check(int cond, const char *what) {
    if (cond) {
        printf("PASS: %s\n", what);
    } else {
        printf("FAIL: %s\n", what);
        failures++;
    }
}

/* Assert storage.retention_days parses both ways: the explicit value in the
   example config and the DEFAULT (30) when the field is absent (older configs
   omit it).  The absent-field case needs a config that is NOT type-annotated
   with the new schema, so build one in a temp file and load it. */
static void check_retention(const char *example) {
    Config cfg;
    char err[512];

    if (config_load(example, &cfg, err, sizeof err) != 0) {
        check(0, "retention_days: explicit config loads");
        return;
    }
    check(cfg.storage.retention_days == 30,
          "retention_days explicit value == 30");
    config_free(&cfg);

    {
        static const char *const def_cfg =
            "{ hostname = \"h\"\n"
            ", domains = [ \"example.com\" ]\n"
            ", listen = { address = \"0.0.0.0\", port = 1 }\n"
            ", limits = { message = 100, line = 1000, rcpts = 10\n"
            "           , cmd_timeout = 30, data_timeout = 60 }\n"
            ", relay = { host = \"r\", port = 2\n"
            "          , auth = { enabled = False, username = \"\", password = \"\" }\n"
            "          , retries = 1, tls = \"none\" }\n"
            ", storage = { path = \"/tmp/x\", spool = \"/tmp/y\" }\n"
            ", reply = { prefix = \"reply\", separator = \"+\" }\n"
            ", catch_all = \"\"\n"
            ", aliases = [] : List { alias : Text, destinations : List Text }\n"
            ", http = { address = \"127.0.0.1\", port = 3 }\n"
            ", admin = { token = \"default-config-check-token\" }\n"
            "}\n";
        char tmp[64];
        int fd;
        FILE *f;
        int loaded;
        snprintf(tmp, sizeof tmp, "/tmp/visage_cfg_def_XXXXXX");
        fd = mkstemp(tmp);
        if (fd < 0) {
            check(0, "retention_days: default mkstemp");
        } else {
            f = fdopen(fd, "w");
            if (!f) { close(fd); unlink(tmp); check(0, "retention_days: default fdopen"); }
            else {
                fputs(def_cfg, f);
                fclose(f);
                loaded = (config_load(tmp, &cfg, err, sizeof err) == 0);
                check(loaded, "retention_days: absent-field config loads");
                if (loaded) {
                    check(cfg.storage.retention_days == 30,
                          "retention_days defaults to 30 when absent");
                    config_free(&cfg);
                }
                unlink(tmp);
            }
        }
    }
}

int main(int argc, char **argv) {
    const char *path = (argc > 1) ? argv[1] : "config.example.dhall";
    Config cfg;
    char err[512];

    if (config_load(path, &cfg, err, sizeof err) != 0) {
        fprintf(stderr, "config_check: failed to load '%s': %s\n", path, err);
        return 1;
    }

    printf("hostname:          %s\n", cfg.hostname);
    printf("domains (%zu):     ", cfg.ndomains);
    for (size_t i = 0; i < cfg.ndomains; i++)
        printf("%s%s", i ? ", " : "", cfg.domains[i]);
    printf("\n");
    printf("listen:            %s:%u\n", cfg.listen.address, cfg.listen.port);
    printf("limits:            message=%u line=%u rcpts=%u cmd_timeout=%u data_timeout=%u\n",
           cfg.limits.message, cfg.limits.line, cfg.limits.rcpts,
           cfg.limits.cmd_timeout, cfg.limits.data_timeout);
    printf("relay:             %s:%u retries=%u tls=%s max_attempts=%u tls_ca=%s auth(enabled=%s user=%s)\n",
           cfg.relay.host, cfg.relay.port, cfg.relay.retries, cfg.relay.tls,
           cfg.relay.max_attempts, cfg.relay.tls_ca,
           cfg.relay.auth.enabled ? "yes" : "no", cfg.relay.auth.username);
    printf("storage:           path=%s spool=%s retention_days=%u\n",
           cfg.storage.path, cfg.storage.spool, cfg.storage.retention_days);
    printf("reply:             prefix=%s separator=%s\n", cfg.reply.prefix, cfg.reply.separator);
    printf("catch_all:         '%s'\n", cfg.catch_all);
    printf("aliases (%zu):\n", cfg.naliases);
    for (size_t i = 0; i < cfg.naliases; i++) {
        printf("  %s ->", cfg.aliases[i].alias);
        for (size_t j = 0; j < cfg.aliases[i].ndestinations; j++)
            printf(" %s", cfg.aliases[i].destinations[j]);
        printf("\n");
    }
    printf("http:              %s:%u\n", cfg.http.address, cfg.http.port);
    printf("admin:             token=%s\n", cfg.admin.token);
    printf("dkim (%zu):\n", cfg.ndkim);
    for (size_t i = 0; i < cfg.ndkim; i++)
        printf("  domain=%s selector=%s private_key=%s\n",
               cfg.dkim[i].domain, cfg.dkim[i].selector, cfg.dkim[i].private_key);

    config_free(&cfg);

    /* retention_days explicit + default asserts. */
    check_retention(path);

    if (failures) {
        fprintf(stderr, "config_check: %d FAILURE(S)\n", failures);
        return 1;
    }
    return 0;
}
