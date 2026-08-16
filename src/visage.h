/* visage.h — shared project header for the visage email alias & forwarding daemon.
   Common types, limits, and error codes for every translation unit.
   Module-specific structs/functions live in their own headers (or here,
   added by the slice implementers); keep this header lean. */
#ifndef VISAGE_H
#define VISAGE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <stdarg.h>

/* Version string. */
#ifndef VISAGE_VERSION
#define VISAGE_VERSION "0.1.0"
#endif

/* The two engine cores are embedded directly into the APE. Their headers
   live on the include paths (-I$(DHALL_C)/src -I$(DATALOG)/src). */
#ifdef __has_include
#  if __has_include(<dhall.h>)
#    include <dhall.h>
#  endif
#  if __has_include(<dl.h>)
#    include <dl.h>
#  endif
#endif

/* ------------------------------------------------------------------ */
/* Shared error codes                                                 */
/* ------------------------------------------------------------------ */
#define VISAGE_OK        0
#define VISAGE_ERR     (-1)
#define VISAGE_ENOMEM  (-2)
#define VISAGE_EPARAM  (-3)
#define VISAGE_ECONF   (-4)
#define VISAGE_ESTORE  (-5)

/* ------------------------------------------------------------------ */
/* Forward declarations / type placeholders. Slice implementers fill   */
/* in the real structs and functions in their own headers or here.     */
/* ------------------------------------------------------------------ */

/* config (src/config.h, src/config.c) — Config struct + Dhall loader. */
#include "config.h"

/* store (src/store.c) — datalog-dafsa wrapper. */
#include "store.h"

/* smtp_in / smtp_out (src/smtp_in.c, src/smtp_out.c). */
int smtp_in_main(const Config *c, const Store *s);
/* Multiplex an extra listener fd into the SMTP poll loop (used so the admin
   HTTP listener shares one event loop with SMTP — datalog is single-writer,
   so everything runs on one thread).  cb(fd, user) is invoked whenever the fd
   is readable.  Must be called before smtp_in_main.  Returns VISAGE_OK, or a
   negative error code if the registration table is full. */
int smtp_in_add_extra_fd(int fd, void (*cb)(int fd, void *user), void *user);
/* Per-connection admin HTTP registration (R4).  Registers an accepted HTTP
   connection's fd so it is multiplexed into the SMTP poll loop alongside SMTP
   connections (non-blocking, shared single-threaded event loop).  Returns a
   stable handle (>= 0) or a negative error code (VISAGE_EPARAM on bad args,
   VISAGE_ENOMEM when the connection table is full).  The caller owns the fd
   and closes it itself after smtp_in_http_close. */
int smtp_in_register_http_conn(int fd,
        void (*on_readable)(int fd, void *user),
        void (*on_writable)(int fd, void *user),
        void (*on_closed)(int fd, void *user),
        uint32_t idle_timeout_sec, void *user);
/* Re-arm which events (POLLIN/POLLOUT) the loop polls for a registered HTTP
   conn. */
void smtp_in_http_set_events(int handle, short events);
/* Release a registered HTTP conn's slot (idempotent).  Does NOT close the fd;
   the caller frees its own per-connection state and closes the fd. */
void smtp_in_http_close(int handle);
int smtp_out_send(Store *s, const Config *c, const char *from, const char *to,
                  const char *body, size_t bodylen, char *status_out,
                  size_t status_sz);

/* mail (src/mail.c) — address/header parsing and sanitize helpers. */

/* reply (src/reply.c) — reverse-alias token routing. */

/* http (src/http.c) — minimal admin HTTP endpoint.  Sets up the admin listener
   (Config.http), registers it as an extra fd on the SMTP loop, then runs the
   combined SMTP+HTTP poll loop. Returns 0 on a clean (error) exit, nonzero on
   a setup failure. */
int http_serve(Store *s, const Config *c);

/* main (src/main.c) — CLI + daemon entry point. */

#endif /* VISAGE_H */
