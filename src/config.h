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

/* relay { host, port, auth, retries, tls } */
typedef struct {
    char          *host;
    uint32_t       port;
    ConfigRelayAuth auth;
    uint32_t       retries;
    char          *tls;
} ConfigRelay;

/* storage { path, spool } */
typedef struct {
    char *path;
    char *spool;
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
} Config;

/* Load path into cfg (zeroed first). Returns 0 on success; on failure writes a
   NUL-terminated message into err (if errsz>0) and returns nonzero. */
int config_load(const char *path, Config *cfg, char *err, size_t errsz);

/* Free every heap allocation owned by cfg. */
void config_free(Config *cfg);

#endif /* VISAGE_CONFIG_H */
