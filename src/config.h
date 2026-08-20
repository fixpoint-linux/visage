/* config.h — visage configuration: the Config struct and its Dhall loader.
   The struct mirrors the Dhall schema exactly (see config.example.dhall).
   Config is shared by every module via src/visage.h -> config.h. */
#ifndef VISAGE_CONFIG_H
#define VISAGE_CONFIG_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/* listen { address, port } */
typedef struct {
    char   *address;
    uint32_t port;
} ConfigListen;

/* limits { message, line, rcpts, cmd_timeout, data_timeout } (all Natural) */
typedef struct {
    uint32_t message;
    uint32_t line;
    uint32_t rcpts;
    uint32_t cmd_timeout;
    uint32_t data_timeout;
} ConfigLimits;

/* relay.auth { enabled, username, password } */
typedef struct {
    bool     enabled;
    char    *username;
    char    *password;
} ConfigRelayAuth;

/* relay { host, port, auth, retries, tls, max_attempts } */
typedef struct {
    char          *host;
    uint32_t       port;
    ConfigRelayAuth auth;
    uint32_t       retries;
    char          *tls;
    uint32_t       max_attempts;   /* durable-queue redrive cap (0 -> default) */
    char          *tls_ca;         /* PEM CA bundle path ("" -> embedded bundle) */
} ConfigRelay;

/* storage { path, spool, retention_days } */
typedef struct {
    char *path;
    char *spool;
    uint32_t retention_days;   /* spool GC age in days (0 = GC disabled) */
} ConfigStorage;

/* reply { prefix, separator } */
typedef struct {
    char *prefix;
    char *separator;
} ConfigReply;

/* aliases element: { alias, destinations : List Text } */
typedef struct {
    char  *alias;
    char **destinations;
    size_t ndestinations;
} ConfigAlias;

/* http { address, port } */
typedef struct {
    char    *address;
    uint32_t port;
} ConfigHttp;

/* admin { token } */
typedef struct {
    char *token;
} ConfigAdmin;

/* Maximum length of the admin bearer token.  The HTTP path parses the
   Authorization header into a 512-byte buffer (see http.c auth_ok), so a
   "Bearer <token>" token longer than ~505 chars can never authenticate; cap
   the configured value at 500 so config-check fails closed (fail-fast
   lockout) rather than silently shipping an unusable token. */
#define ADMIN_TOKEN_MAX_LEN 500

/* dkim element: { domain, selector, private_key } — domain is the signing
   domain (a=rsa-sha256, c=relaxed/relaxed), selector the DKIM selector, and
   private_key the operator PEM RSA private-key file path. */
typedef struct {
    char *domain;
    char *selector;
    char *private_key;
} ConfigDkim;

/* Top-level config record. Strings and arrays are heap-owned; release with
   config_free(). */
typedef struct Config {
    char        *hostname;
    char       **domains;
    size_t       ndomains;
    ConfigListen listen;
    ConfigLimits limits;
    ConfigRelay  relay;
    ConfigStorage storage;
    ConfigReply  reply;
    char        *catch_all;      /* "" = disabled */
    ConfigAlias *aliases;
    size_t       naliases;
    ConfigHttp   http;
    ConfigAdmin  admin;
    ConfigDkim  *dkim;           /* DKIM signing configs (may be empty) */
    size_t       ndkim;
} Config;

/* Load path into cfg (zeroed first). Returns 0 on success; on failure writes a
   NUL-terminated message into err (if errsz>0) and returns nonzero. */
int config_load(const char *path, Config *cfg, char *err, size_t errsz);

/* Find the DKIM signing config whose domain matches `domain`
   (case-insensitive); NULL when there is no match. */
ConfigDkim *config_dkim_find(const Config *cfg, const char *domain);

/* Nonzero if `alias` matches any config-declared alias (case-insensitive);
   such aliases are read-only through the admin API. */
int config_alias_read_only(const Config *cfg, const char *alias);

/* Free every heap allocation owned by cfg. */
void config_free(Config *cfg);

#endif /* VISAGE_CONFIG_H */
