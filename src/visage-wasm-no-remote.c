/* visage-wasm-no-remote.c — stub the dhall-c HTTP import surface for the wasm
   demo build.

   The browser demo compiles dhall-c's import.c, which calls http_fetch /
   url_dirname / url_join for `http(s)://` imports.  In dhall-c's http.c the
   wasm path is a SYNCHRONOUS XMLHttpRequest with NO SSRF gate (the comment in
   http.c says "the browser owns connectivity"): a hostile pasted config with a
   hashed http:// import would make visitors' browsers probe arbitrary URLs
   before the sha256 check runs.  Rather than ship that, this TU replaces
   http.c for the demo build and makes remote imports fail immediately: no XHR
   is ever issued.

   http.c exports exactly these three non-static symbols (sha256_hex lives in
   sha256.c, which stays).  A config with an un-hashed http:// import already
   fails (sha256 required); with this stub ANY http:// import becomes a
   recoverable missing-import error (or uses its `?` fallback). */
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "dhall.h"

/* Never reached for remote resolution: import.c only calls these AFTER a
   successful http_fetch, which the stub below never performs. */
char *url_dirname(const char *url) {
    (void)url;
    return NULL;
}

char *url_join(const char *base_dir, const char *spec) {
    (void)base_dir;
    (void)spec;
    return NULL;
}

/* Remote (http/https) imports are disabled in the demo build: always report a
   recoverable missing import and return ABSENT, so a config referencing an
   http:// import fails cleanly (or falls back via `?`) without the browser
   ever issuing a network request. */
int http_fetch(const char *url, char **body, size_t *len, DhallError *err) {
    if (body) *body = NULL;
    if (len) *len = 0;
    dhall_error_set(err, ERR_MISSING, SPAN_NONE,
                    "missing import: remote (http) imports are disabled in the "
                    "demo build ('%s')", url);
    return HTTP_ABSENT;
}
