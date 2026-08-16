/* config_check.c — standalone check that loads config.example.dhall and
   prints the parsed Config. Returns 0 on success, nonzero on any error. */
#include "visage.h"
#include "config.h"
#include <stdio.h>

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
    printf("storage:           path=%s spool=%s\n", cfg.storage.path, cfg.storage.spool);
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
    return 0;
}
