CC      := cosmocc
DHALL_C ?= ../dhall-c
DATALOG ?= ../datalog-dafsa
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
             $(DATALOG)/src/intern.c $(DATALOG)/src/termstore.c $(DATALOG)/src/relation.c \
             $(DATALOG)/src/vrelation.c $(DATALOG)/src/tupleset.c $(DATALOG)/src/parser.c \
             $(DATALOG)/src/compiler.c $(DATALOG)/src/vm.c $(DATALOG)/src/snapshot.c \
             $(DATALOG)/src/regexwalk.c $(DATALOG)/src/permindex.c $(DATALOG)/src/util.c \
             $(DATALOG)/src/dl.c $(DATALOG)/src/magic.c
SRC = src/config.c src/store.c src/smtp_in.c src/smtp_out.c src/mail.c src/reply.c src/http.c src/json.c src/main.c
all: visage.com config_check.com store_check.com mail_check.com reply_check.com smtp_check.com
visage.com: $(SRC) src/visage.h src/config.h src/store.h $(CORE_DHALL) $(CORE_DATALOG)
	$(CC) $(CFLAGS) -o $@ $(SRC) $(CORE_DHALL) $(CORE_DATALOG)
config_check.com: src/config.c src/config_check.c src/config.h src/visage.h $(CORE_DHALL)
	$(CC) $(CFLAGS) -o $@ src/config.c src/config_check.c $(CORE_DHALL)
store_check.com: src/store.c src/store_check.c src/store.h src/visage.h $(CORE_DATALOG)
	$(CC) $(CFLAGS) -o $@ src/store.c src/store_check.c $(CORE_DATALOG)
mail_check.com: src/mail.c src/mail_check.c src/mail.h src/visage.h
	$(CC) $(CFLAGS) -o $@ src/mail.c src/mail_check.c
reply_check.com: src/reply.c src/reply_check.c src/reply.h src/store.c src/store.h src/mail.c src/mail.h src/config.h src/visage.h $(CORE_DATALOG)
	$(CC) $(CFLAGS) -o $@ src/reply.c src/reply_check.c src/store.c src/mail.c $(CORE_DATALOG)
smtp_check.com: src/smtp_in.c src/smtp_out.c src/store.c src/reply.c src/smtp_check.c src/smtp.h src/store.h src/reply.h src/mail.c src/mail.h src/config.h src/visage.h $(CORE_DATALOG)
	$(CC) $(CFLAGS) -o $@ src/smtp_in.c src/smtp_out.c src/store.c src/reply.c src/smtp_check.c src/mail.c $(CORE_DATALOG)

# --- S8 e2e harness ---------------------------------------------------------
# smtptest + relay_fake are standalone POSIX-socket tools (no visage/dep code).
# They are built only via the `e2e` target and are NOT part of `all` (the full
# scenario needs live sockets / the host).
tests/smtptest.com: tests/smtptest.c
	$(CC) $(CFLAGS) -o $@ tests/smtptest.c
tests/relay_fake.com: tests/relay_fake.c
	$(CC) $(CFLAGS) -o $@ tests/relay_fake.c

e2e: visage.com config_check.com tests/smtptest.com tests/relay_fake.com
	./tests/run.sh

.PHONY: all e2e
