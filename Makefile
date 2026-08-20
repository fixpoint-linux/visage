CC      := cosmocc
# dhall-c and datalog-dafsa are vendored as git submodules; override with
# DHALL_C=../dhall-c / DATALOG=../datalog-dafsa to use sibling checkouts.
DHALL_C ?= vendor/dhall-c
DATALOG ?= vendor/datalog-dafsa
CFLAGS   = -std=c11 -O2 -g -Wall -Wextra -Werror -D_POSIX_C_SOURCE=200809L \
           -I $(DHALL_C)/src -I $(DATALOG)/src -I $(DATALOG)/vendor
CORE_DHALL = $(DHALL_C)/src/arena.c $(DHALL_C)/src/lexer.c $(DHALL_C)/src/parser.c \
             $(DHALL_C)/src/ast.c $(DHALL_C)/src/normalize.c $(DHALL_C)/src/typecheck.c \
             $(DHALL_C)/src/builtins.c $(DHALL_C)/src/serialize.c $(DHALL_C)/src/import.c \
             $(DHALL_C)/src/bignum.c $(DHALL_C)/src/sha256.c $(DHALL_C)/src/ssrf.c $(DHALL_C)/src/http.c
CORE_DATALOG = $(DATALOG)/vendor/dafsa.c $(DATALOG)/vendor/dafsa_state.c \
             $(DATALOG)/vendor/dafsa_core.c $(DATALOG)/vendor/dafsa_persist.c \
             $(DATALOG)/vendor/dafsa_view.c $(DATALOG)/vendor/dafsa_crc32.c \
             $(DATALOG)/vendor/dafsa_wal.c $(DATALOG)/vendor/dafsa_build.c \
             $(DATALOG)/vendor/dafsa_rank.c $(DATALOG)/vendor/dafsa_view_rank.c \
             $(DATALOG)/src/intern.c $(DATALOG)/src/termstore.c $(DATALOG)/src/relation.c \
             $(DATALOG)/src/vrelation.c $(DATALOG)/src/tupleset.c $(DATALOG)/src/parser.c \
             $(DATALOG)/src/compiler.c $(DATALOG)/src/vm.c $(DATALOG)/src/snapshot.c \
             $(DATALOG)/src/regexwalk.c $(DATALOG)/src/permindex.c $(DATALOG)/src/util.c \
             $(DATALOG)/src/dl.c $(DATALOG)/src/iter.c $(DATALOG)/src/magic.c \
             $(DATALOG)/src/topdown.c $(DATALOG)/src/analyze.c $(DATALOG)/src/schema.c \
             $(DATALOG)/src/typecheck.c $(DATALOG)/src/txnwal.c $(DATALOG)/src/index.c \
             $(DATALOG)/src/vector.c

# --- vendored mbedTLS (relay STARTTLS) ---------------------------------------
MBEDTLS_DIR   = vendor/mbedtls
MBEDTLS_SRC   = $(addprefix $(MBEDTLS_DIR)/library/, aes.c asn1parse.c \
    asn1write.c base64.c bignum.c bignum_core.c bignum_mod.c \
    bignum_mod_raw.c cipher.c cipher_wrap.c constant_time.c ctr_drbg.c \
    ecdh.c ecdsa.c ecp.c ecp_curves.c entropy.c entropy_poll.c error.c \
    gcm.c md.c oid.c pem.c pk.c pk_ecc.c pk_wrap.c pkparse.c platform.c \
    platform_util.c rsa.c rsa_alt_helpers.c sha1.c sha256.c sha512.c \
    ssl_cache.c ssl_ciphersuites.c ssl_client.c ssl_msg.c ssl_tls.c \
    ssl_tls12_client.c ssl_tls12_server.c version.c x509.c x509_crt.c)
MBEDTLS_OBJ   = $(MBEDTLS_SRC:$(MBEDTLS_DIR)/library/%.c=$(MBEDTLS_DIR)/build/%.o)
MBEDTLS_FLAGS = -I $(MBEDTLS_DIR)/include -I src \
    -DMBEDTLS_CONFIG_FILE='"mbedtls_visage_config.h"'

# Vendored third-party: compiled with the project warning set; if upstream
# ever trips -Werror here add the SPECIFIC -Wno-<warning> below — never patch
# the vendored sources. Empty today (gcc 14.1 + 3.6.7 expected clean).
MBEDTLS_WNO   =

$(MBEDTLS_DIR)/build:
	mkdir -p $@
$(MBEDTLS_DIR)/build/%.o: $(MBEDTLS_DIR)/library/%.c src/mbedtls_visage_config.h | $(MBEDTLS_DIR)/build
	$(CC) $(CFLAGS) $(MBEDTLS_WNO) $(MBEDTLS_FLAGS) -c -o $@ $<

tests/tls_selfcheck.com: tests/tls_selfcheck.c $(MBEDTLS_OBJ) src/mbedtls_visage_config.h
	$(CC) $(CFLAGS) $(MBEDTLS_FLAGS) -o $@ tests/tls_selfcheck.c $(MBEDTLS_OBJ)

tests/verify_selfcheck.com: tests/verify_selfcheck.c $(MBEDTLS_OBJ) src/mbedtls_visage_config.h src/data/cacert_pem.c
	$(CC) $(CFLAGS) $(MBEDTLS_FLAGS) -o $@ tests/verify_selfcheck.c $(MBEDTLS_OBJ) src/data/cacert_pem.c

SRC = src/config.c src/store.c src/smtp_in.c src/smtp_out.c src/mail.c src/reply.c src/dkim.c src/http.c src/admin.c src/http_parse.c src/json.c src/main.c
all: visage.com config_check.com store_check.com mail_check.com reply_check.com smtp_check.com http_check.com dkim_check.com tests/tls_selfcheck.com tests/verify_selfcheck.com
visage.com: $(SRC) src/visage.h src/config.h src/store.h $(CORE_DHALL) $(CORE_DATALOG) $(MBEDTLS_OBJ) src/data/cacert_pem.c src/data/admin_ui.c
	$(CC) $(CFLAGS) $(MBEDTLS_FLAGS) -o $@ $(SRC) $(CORE_DHALL) $(CORE_DATALOG) $(MBEDTLS_OBJ) src/data/cacert_pem.c src/data/admin_ui.c
config_check.com: src/config.c src/config_check.c src/config.h src/visage.h $(CORE_DHALL)
	$(CC) $(CFLAGS) -o $@ src/config.c src/config_check.c $(CORE_DHALL)
store_check.com: src/store.c src/store_check.c src/store.h src/visage.h $(CORE_DATALOG)
	$(CC) $(CFLAGS) -o $@ src/store.c src/store_check.c $(CORE_DATALOG)
store_bench.com: src/store.c src/store_bench.c src/store.h src/visage.h $(CORE_DATALOG)
	$(CC) $(CFLAGS) -o $@ src/store.c src/store_bench.c $(CORE_DATALOG)
mail_check.com: src/mail.c src/mail_check.c src/mail.h src/visage.h
	$(CC) $(CFLAGS) -o $@ src/mail.c src/mail_check.c
reply_check.com: src/reply.c src/reply_check.c src/reply.h src/store.c src/store.h src/mail.c src/mail.h src/config.h src/visage.h $(CORE_DATALOG)
	$(CC) $(CFLAGS) -o $@ src/reply.c src/reply_check.c src/store.c src/mail.c $(CORE_DATALOG)
smtp_check.com: src/smtp_in.c src/smtp_out.c src/store.c src/reply.c src/dkim.c src/config.c src/smtp_check.c src/smtp.h src/store.h src/reply.h src/mail.c src/mail.h src/config.h src/visage.h $(CORE_DHALL) $(CORE_DATALOG) $(MBEDTLS_OBJ) src/data/cacert_pem.c
	$(CC) $(CFLAGS) $(MBEDTLS_FLAGS) -o $@ src/smtp_in.c src/smtp_out.c src/store.c src/reply.c src/dkim.c src/config.c src/smtp_check.c src/mail.c $(CORE_DHALL) $(CORE_DATALOG) $(MBEDTLS_OBJ) src/data/cacert_pem.c
http_check.com: src/http_parse.c src/http_check.c src/http_parse.h src/admin.c \
    src/store.c src/json.c src/config.c src/visage.h src/config.h src/store.h \
    src/data/admin_ui.c $(CORE_DATALOG) $(CORE_DHALL)
	$(CC) $(CFLAGS) -o $@ src/admin.c src/http_parse.c src/store.c src/json.c \
	    src/config.c src/http_check.c $(CORE_DATALOG) $(CORE_DHALL) src/data/admin_ui.c
dkim_check.com: src/dkim.c src/dkim_check.c src/dkim.h src/mbedtls_visage_config.h $(MBEDTLS_OBJ)
	$(CC) $(CFLAGS) $(MBEDTLS_FLAGS) -o $@ src/dkim.c src/dkim_check.c $(MBEDTLS_OBJ)

# --- S8 e2e harness ---------------------------------------------------------
# smtptest is a standalone POSIX-socket tool (no visage/dep code).  relay_fake
# is likewise a socket tool but links the vendored mbedTLS to support its
# `--tls` mode (an mbedTLS server on the accepted socket).  They are built only
# via the `e2e` target and are NOT part of `all` (the full scenario needs live
# sockets / the host).
tests/smtptest.com: tests/smtptest.c
	$(CC) $(CFLAGS) -o $@ tests/smtptest.c
tests/relay_fake.com: tests/relay_fake.c $(MBEDTLS_OBJ) src/mbedtls_visage_config.h
	$(CC) $(CFLAGS) $(MBEDTLS_FLAGS) -o $@ tests/relay_fake.c $(MBEDTLS_OBJ)

e2e: visage.com config_check.com tests/smtptest.com tests/relay_fake.com
	./tests/run.sh

# --- browser wasm build (host: requires emscripten clang lld llvm nodejs) ----
wasm:
	./scripts/build-wasm.sh
	@node tests/wasm-smoke.js

# --- store benchmark + plots ----------------------------------------------
# Runs the store benchmark (seeds N in {1e3..1e6}, measures load throughput,
# warm/cold resolve latency, and on-disk size) into bench.csv, then renders
# the latency + size charts with a dependency-free python3 script.
# The full run seeds a 1e6-alias store and takes several minutes (revmap
# interner is super-linear) — allow a generous timeout.
bench: store_bench.com
	./store_bench.com
	python3 tools/bench_plot.py bench.csv docs/bench-latency.svg docs/bench-size.svg

# --- admin web UI embed --------------------------------------------------
# Regenerate src/data/admin_ui.c from the admin/ source files (index.html,
# app.js, style.css).  Both the source and the generated file are committed;
# this target is only needed when the UI sources change.
gen-admin:
	./tools/gen_admin_ui.sh

.PHONY: all e2e wasm bench gen-admin
