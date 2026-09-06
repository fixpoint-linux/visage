#!/usr/bin/env python3
"""Generate the visage Dhakefile.dhall (Make-free, dhake-driven, hash-verified).

Builds a single Dhakefile.dhall that:
  - compiles the mbedTLS objects (no pattern rules => an explicit `mbedtls` target)
  - builds all C binaries with host `cc`: the datalog/dhall-linking daemons and
    check tools against the Zig-built libdatalog.so + libdhall.so (glibc dynamic
    ELFs), the standalone mbedTLS check tools as plain ELFs (no APE/cosmocc)
  - builds the Elm MFE docs site
Every non-phony output pins `hash` (expected sha256) and every input source
pins `depsHash`.  Run `dhake --warn-hash-mismatch` to (re)capture actual output
hashes when a pinned hash goes stale.

Run:  python3 tools/gen_dhakefile.py  >  Dhakefile.dhall
"""
import hashlib, os, subprocess, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(ROOT)

def sha(p):
    # Outputs that don't exist yet get a placeholder pin; the real hash is
    # captured after the first build via `dhake --warn-hash-mismatch`.
    if not os.path.isfile(p):
        return "sha256:" + ("0"*64)
    return "sha256:" + hashlib.sha256(open(p,'rb').read()).hexdigest()

def exists(p):
    if not os.path.isfile(p):
        print(f"WARN missing {p}", file=sys.stderr)
    return p

# ---------- source lists (mirror Makefile) ----------
DHALL_C  = "vendor/dhall-c"
DATALOG  = "vendor/datalog-dafsa"
MBDIR    = "vendor/mbedtls"

def mb(*ns): return [exists(f"{MBDIR}/library/{n}") for n in ns]

mbedtls_lib = [
 "aes.c","asn1parse.c","asn1write.c","base64.c","bignum.c","bignum_core.c",
 "bignum_mod.c","bignum_mod_raw.c","cipher.c","cipher_wrap.c","constant_time.c",
 "ctr_drbg.c","ecdh.c","ecdsa.c","ecp.c","ecp_curves.c","entropy.c",
 "entropy_poll.c","error.c","gcm.c","md.c","oid.c","pem.c","pk.c","pk_ecc.c",
 "pk_wrap.c","pkparse.c","platform.c","platform_util.c","rsa.c",
 "rsa_alt_helpers.c","sha1.c","sha256.c","sha512.c","ssl_cache.c",
 "ssl_ciphersuites.c","ssl_client.c","ssl_msg.c","ssl_tls.c","ssl_tls12_client.c",
 "ssl_tls12_server.c","version.c","x509.c","x509_crt.c",
]
MBEDTLS_SRC = mb(*mbedtls_lib)
MBEDTLS_CONFIG = "src/mbedtls_visage_config.h"
DATA_CACERT = "src/data/cacert_pem.c"
DATA_ADMIN = "src/data/admin_ui.c"

SRC = ["src/config.c","src/store.c","src/smtp_in.c","src/smtp_in_tls.c","src/smtp_out.c",
       "src/mail.c","src/reply.c","src/dkim.c","src/auth_results.c","src/http.c","src/admin.c",
       "src/http_parse.c","src/json.c","src/main.c"]
HDRS = ["src/visage.h","src/config.h","src/store.h","src/mail.h","src/reply.h",
        "src/smtp.h","src/dkim.h","src/auth_results.h","src/http_parse.h","src/json.h"]
HDRS = [exists(h) for h in HDRS]

CFLAGS = ("-std=c11 -O2 -g -Wall -Wextra -Werror -D_POSIX_C_SOURCE=200809L "
          f"-I {DHALL_C}/src -I {DATALOG}/src -I {DATALOG}/vendor")
CCFLAGS = ("-std=c11 -O2 -g -Wall -Wextra -Werror -D_POSIX_C_SOURCE=200809L "
           "-D_DEFAULT_SOURCE "
           f"-I {DHALL_C}/src -I {DATALOG}/src -I {DATALOG}/vendor")
MBFLAGS = f"-I {MBDIR}/include -I src -DMBEDTLS_CONFIG_FILE='\"mbedtls_visage_config.h\"'"

# ---------- helpers to emit Dhall ----------
def dhall_string(s):
    return '"' + s.replace('\\','\\\\').replace('"','\\"') + '"'

def depshash_obs(files):
    """Emit a `depsHash = [ { path=..., hash=... }, ... ]` Dhall expr for a list of files."""
    if not files: return ""
    items = ",\n              ".join(
        f"{{ path = {dhall_string(p)}, hash = {dhall_string(sha(p))} }}" for p in files)
    return f"depsHash = [\n              {items}\n              ]\n            , "

def target(name, deps, recipe, out=None, arch="None Text", hash_srcs=None):
    """Emit a `{ mapKey, mapValue }` for a target.

    `deps`  — dependency target names AND source-file paths (in `deps:` list).
    `hash_srcs` — the subset of source FILES to pin in `depsHash` (excludes
                  target names like 'mbedtls' which aren't files). Defaults to
                  the file paths among `deps`.
    `out`   — output file path; if set, the target is non-phony and pins `hash`.
              (In this dhake, optional fields are OMITTED when absent.)
    """
    deps_s = ", ".join(dhall_string(d) for d in deps)
    phony = "True" if out is None else "False"
    if hash_srcs is None:
        hash_srcs = [d for d in deps if os.path.isfile(d)]
    # hash field: only emitted when the target has an output file
    hash_field = "" if out is None else f"hash = {dhall_string(sha(out))}\n            , "
    deps_obs = depshash_obs(hash_srcs)
    recipe_s = ",\n          ".join(f"< Shell = {dhall_string(r)} >" for r in recipe)
    return f"""        {{ mapKey = {dhall_string(name)}
        , mapValue =
            {{ deps = [ {deps_s} ]
            , phony = {phony}
            , recipe = [ {recipe_s} ]
            , {hash_field}{deps_obs}arch = {arch}
            }}
        }}"""

# ---------- build the targets ----------
T = []

# mbedTLS objects target (explicit; dhake has no pattern rules). To make `--verify`
# work as a clean CI gate, this is a NON-phony target whose single output is a
# deterministic empty stamp file (`touch` => 0 bytes => sha256 e3b0c442...).
# The recipe Shell-loops the 44 object compiles (idempotent: only (re)compile when
# the .o is missing or older than its .c) then touches the stamp, so the stamp only
# changes when a source (or config) changed. Each mbedTLS-linking binary depends on
# this target and links the .o files directly.
EMPTY_SHA = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
mb_obj_shell = ("set -e; mkdir -p %s/build; " % MBDIR)
for c in mbedtls_lib:
    obj = f"{MBDIR}/build/{c[:-2]}.o"
    mb_obj_shell += (f"if [ ! -f {obj} ] || [ {MBDIR}/library/{c} -nt {obj} ]; then "
                     f"cc {CCFLAGS} {MBFLAGS} -c -o {obj} {MBDIR}/library/{c}; fi; ")
mb_obj_shell += f"touch {MBDIR}/build/.stamp"
# dhake uses the target NAME as the output file path, so this target must be
# named after its output stamp. Binaries depend on 'vendor/mbedtls/build/.stamp'.
STAMP = f"{MBDIR}/build/.stamp"
T.append(target(STAMP,
    deps=[MBEDTLS_CONFIG] + MBEDTLS_SRC,
    recipe=[mb_obj_shell],
    out=STAMP))
# Force the stamp's pinned hash to the empty-file hash (the generator's sha() would
# hash the existing .stamp which is empty anyway).

mbtls_objs = [f"{MBDIR}/build/{c[:-2]}.o" for c in mbedtls_lib]
mbtls_objs_join = " ".join(mbtls_objs)

def link_cmd(out, srcs, extra_flags=""):
    return f"cc {CCFLAGS} {extra_flags} -o {out} {' '.join(srcs)}"

# --- datalog targets: host `cc` + Zig-built libdatalog.so ---
# Every target that links the datalog-dafsa engine uses the Zig-built glibc
# libdatalog.so in the sibling ../datalog-dafsa checkout instead of compiling
# the stale vendored C engine.  Targets compile with host `cc` into glibc
# dynamic ELFs and link the .so with an absolute rpath.  The vendored
# vendor/datalog-dafsa HEADERS are still used at compile time (the .so preserves
# the dl_*/dafsa_* ABI); only the vendored C engine sources are dropped from
# deps/recipe/depsHash.
DATALOG_SO_DIR = os.path.abspath(os.path.join(ROOT, "..", "datalog-dafsa", "zig-out", "lib"))
DLOG_LINK = f"-L {DATALOG_SO_DIR} -ldatalog -Wl,-rpath,{DATALOG_SO_DIR}"

def cc_link_datalog(out, srcs, extra_flags=""):
    return f"cc {CCFLAGS} {extra_flags} -o {out} {' '.join(srcs)} {DLOG_LINK}"

# The Zig-built engine .so these targets link.  Pinning it as a hash_src makes
# `dhake --verify` (and the dependency graph) detect an engine rebuild/output
# drift instead of silently relinking against a stale .so.
DATALOG_SO = os.path.join(DATALOG_SO_DIR, "libdatalog.so")

# --- dhall targets: host `cc` + Zig-built libdhall.so ---
# Same pattern as libdatalog.so: the vendored vendor/dhall-c submodule is pinned
# pre-Zig (07a069c, no zig/ dir), so visage links the Zig engine .so from the
# sibling ../dhall-c checkout instead of compiling the stale vendored C engine.
# The vendored dhall.h HEADER is still used at compile time (config.c compiles
# against the C ABI the .so mirrors); only the vendored C engine sources are
# dropped from deps/recipe/depsHash.
DHALL_SRC_DIR = os.path.abspath(os.path.join(ROOT, "..", "dhall-c", "zig", "src"))
DHALL_SO_DIR  = os.path.abspath(os.path.join(ROOT, "..", "dhall-c", "zig-out", "lib"))
DHALL_SO      = os.path.join(DHALL_SO_DIR, "libdhall.so")
DHALL_LINK    = f"-L {DHALL_SO_DIR} -ldhall -Wl,-rpath,{DHALL_SO_DIR}"

# abi.zig's transitive import closure (abi -> dhall/arena/ast/parser/normalize/
# import/sha256/typecheck, and their own imports).  Pinned so an engine-source
# change invalidates the .so build.
DHALL_ZIG = ["abi.zig","dhall.zig","arena.zig","ast.zig","parser.zig","normalize.zig",
             "import.zig","sha256.zig","bignum.zig","lexer.zig","builtins.zig",
             "http.zig","ssrf.zig","typecheck.zig"]
def dhz(*ns): return [exists(f"{DHALL_SRC_DIR}/{n}") for n in ns]
DHALL_ZIG_SRCS = dhz(*DHALL_ZIG)

def cc_link_dhall(out, srcs, extra_flags=""):
    return f"cc {CCFLAGS} {extra_flags} -o {out} {' '.join(srcs)} {DHALL_LINK}"

def cc_link_dhall_datalog(out, srcs, extra_flags=""):
    return f"cc {CCFLAGS} {extra_flags} -o {out} {' '.join(srcs)} {DHALL_LINK} {DLOG_LINK}"

# --- libdhall.so (Zig engine) ---
# The dhall-c interpreter core as a shared library, built from the Zig port via
# the proven build-obj + cc -shared + strip chain (build-obj emits deterministic
# output, so the hash pins).  The recipe runs from DHALL_SRC_DIR so abi.zig's
# sibling imports resolve; the .so lands next to libdatalog.so in the sibling
# checkout's zig-out/lib.
T.append(target(DHALL_SO,
    deps=DHALL_ZIG_SRCS,
    recipe=[
        f"mkdir -p {DHALL_SO_DIR} && cd {DHALL_SRC_DIR} && rm -f {DHALL_SO} && "
        "ZIG_GLOBAL_CACHE_DIR=/tmp/.zcache ZIG_LOCAL_CACHE_DIR=/tmp/.zlcache "
        "zig build-obj abi.zig -lc -dynamic -O ReleaseSafe -fno-stack-check "
        "-femit-bin=/tmp/visage-libdhall.o && "
        f"cc -shared -o {DHALL_SO} /tmp/visage-libdhall.o -lc "
        "-Wl,-soname,libdhall.so -Wl,--build-id=none && "
        f"strip --strip-all {DHALL_SO}"
    ],
    out=DHALL_SO))

# --- visage.com ---
v_srcs = SRC + MBEDTLS_SRC + [DATA_CACERT, DATA_ADMIN]
T.append(target("visage.com",
    deps=SRC + HDRS + MBEDTLS_SRC + [DATA_CACERT, DATA_ADMIN, MBEDTLS_CONFIG, DHALL_SO],
    recipe=[cc_link_dhall_datalog("visage.com", v_srcs, MBFLAGS)],
    out="visage.com",
    hash_srcs=SRC + HDRS + MBEDTLS_SRC + [DATA_CACERT, DATA_ADMIN, MBEDTLS_CONFIG, DATALOG_SO, DHALL_SO]))

# --- *_check tools (no mbedTLS unless noted) ---
T.append(target("config_check.com",
    deps=["src/config.c","src/config_check.c","src/config.h","src/visage.h", DHALL_SO],
    recipe=[cc_link_dhall("config_check.com", ["src/config.c","src/config_check.c"])],
    out="config_check.com",
    hash_srcs=["src/config.c","src/config_check.c","src/config.h","src/visage.h", DHALL_SO]))
T.append(target("store_check.com",
    deps=["src/store.c","src/store_check.c","src/store.h","src/visage.h"],
    recipe=[cc_link_datalog("store_check.com", ["src/store.c","src/store_check.c"])],
    out="store_check.com",
    hash_srcs=["src/store.c","src/store_check.c","src/store.h","src/visage.h", DATALOG_SO]))
T.append(target("store_bench.com",
    deps=["src/store.c","src/store_bench.c","src/store.h","src/visage.h"],
    recipe=[cc_link_datalog("store_bench.com", ["src/store.c","src/store_bench.c"])],
    out="store_bench.com",
    hash_srcs=["src/store.c","src/store_bench.c","src/store.h","src/visage.h", DATALOG_SO]))
T.append(target("mail_check.com",
    deps=["src/mail.c","src/mail_check.c","src/mail.h","src/visage.h"],
    recipe=[link_cmd("mail_check.com", ["src/mail.c","src/mail_check.c"])],
    out="mail_check.com"))
T.append(target("reply_check.com",
    deps=["src/reply.c","src/reply_check.c","src/reply.h","src/store.c","src/store.h",
          "src/mail.c","src/mail.h","src/config.h","src/visage.h"],
    recipe=[cc_link_datalog("reply_check.com", ["src/reply.c","src/reply_check.c","src/store.c",
                "src/mail.c"])],
    out="reply_check.com",
    hash_srcs=["src/reply.c","src/reply_check.c","src/reply.h","src/store.c","src/store.h",
          "src/mail.c","src/mail.h","src/config.h","src/visage.h", DATALOG_SO]))
T.append(target("smtp_check.com",
    deps=["src/smtp_in.c","src/smtp_in_tls.c","src/smtp_out.c","src/store.c",
          "src/reply.c","src/dkim.c","src/auth_results.c","src/config.c","src/smtp_check.c",
          "src/smtp.h","src/store.h","src/reply.h","src/mail.h","src/mail.c","src/config.h",
          "src/visage.h","src/dkim.h","src/auth_results.h"]
          + MBEDTLS_SRC + [DATA_CACERT, MBEDTLS_CONFIG, DHALL_SO],
    recipe=[cc_link_dhall_datalog("smtp_check.com", ["src/smtp_in.c","src/smtp_in_tls.c","src/smtp_out.c",
                "src/store.c","src/reply.c","src/dkim.c","src/auth_results.c","src/config.c",
                "src/smtp_check.c","src/mail.c"]
                + MBEDTLS_SRC + [DATA_CACERT], MBFLAGS)],
    out="smtp_check.com",
    hash_srcs=["src/smtp_in.c","src/smtp_in_tls.c","src/smtp_out.c","src/store.c",
          "src/reply.c","src/dkim.c","src/auth_results.c","src/config.c","src/smtp_check.c",
          "src/smtp.h","src/store.h","src/reply.h","src/mail.h","src/mail.c","src/config.h",
          "src/visage.h","src/dkim.h","src/auth_results.h"]
          + MBEDTLS_SRC + [DATA_CACERT, MBEDTLS_CONFIG, DATALOG_SO, DHALL_SO]))
T.append(target("http_check.com",
    deps=["src/http_parse.c","src/http_check.c","src/http_parse.h","src/admin.c",
          "src/store.c","src/json.c","src/config.c","src/visage.h","src/config.h",
          "src/store.h","src/json.h"] + [DATA_ADMIN, DHALL_SO],
    recipe=[cc_link_dhall_datalog("http_check.com", ["src/admin.c","src/http_parse.c","src/store.c",
                "src/json.c","src/config.c","src/http_check.c"]
                + [DATA_ADMIN])],
    out="http_check.com",
    hash_srcs=["src/http_parse.c","src/http_check.c","src/http_parse.h","src/admin.c",
          "src/store.c","src/json.c","src/config.c","src/visage.h","src/config.h",
          "src/store.h","src/json.h"] + [DATA_ADMIN, DATALOG_SO, DHALL_SO]))
T.append(target("dkim_check.com",
    deps=[STAMP] + ["src/dkim.c","src/dkim_check.c","src/dkim.h", MBEDTLS_CONFIG],
    recipe=[link_cmd("dkim_check.com", ["src/dkim.c","src/dkim_check.c"] + mbtls_objs, MBFLAGS)],
    out="dkim_check.com"))
T.append(target("auth_check.com",
    deps=[STAMP] + ["src/auth_results.c","src/dkim.c","src/mail.c","src/auth_check.c",
                    "src/auth_results.h","src/dkim.h", MBEDTLS_CONFIG],
    recipe=[link_cmd("auth_check.com", ["src/auth_results.c","src/dkim.c","src/mail.c",
                "src/auth_check.c"] + mbtls_objs, MBFLAGS)],
    out="auth_check.com"))

# --- imapd.com (companion IMAP mailbox server; STARTTLS via mbedTLS) ---
IMAPD_SRCS = ["src/imapd.c","src/imapd_ingest.c","src/imapd_imap.c",
              "src/imapd_tls.c","src/imap_maildir.c","src/mail.c",
              "src/pop3d.c"]
IMAPD_HDRS = ["src/imapd.h","src/mail.h","src/visage.h"]
T.append(target("imapd.com",
    deps=[STAMP] + IMAPD_SRCS + IMAPD_HDRS + [MBEDTLS_CONFIG],
    recipe=[link_cmd("imapd.com", IMAPD_SRCS + mbtls_objs, MBFLAGS)],
    out="imapd.com"))
T.append(target("imap_check.com",
    deps=[STAMP] + ["src/imap_maildir.c","src/imapd_imap.c","src/imapd_tls.c",
                    "src/mail.c","src/imap_check.c"]
         + IMAPD_HDRS + [MBEDTLS_CONFIG],
    recipe=[link_cmd("imap_check.com", ["src/imap_maildir.c","src/imapd_imap.c",
                "src/imapd_tls.c","src/mail.c","src/imap_check.c"] + mbtls_objs,
                MBFLAGS)],
    out="imap_check.com"))
T.append(target("imap_fuzz.com",
    deps=[STAMP] + ["src/imap_maildir.c","src/imapd_imap.c","src/imapd_tls.c",
                    "src/mail.c","src/imap_fuzz.c"]
         + IMAPD_HDRS + [MBEDTLS_CONFIG],
    recipe=[link_cmd("imap_fuzz.com", ["src/imap_maildir.c","src/imapd_imap.c",
                "src/imapd_tls.c","src/mail.c","src/imap_fuzz.c"] + mbtls_objs,
                MBFLAGS)],
    out="imap_fuzz.com"))

# --- outbox.com (standalone SMTP submission + direct-MX delivery daemon) ---
OUTBOX_SRCS = ["src/outbox_main.c","src/outbox_submit.c","src/outbox_deliver.c",
               "src/outbox_auth.c","src/smtp_out.c","src/mail.c",
               "src/auth_results.c","src/dkim.c","src/smtp_in_tls.c"]
OUTBOX_HDRS = ["src/outbox.h","src/smtp.h","src/mail.h","src/auth_results.h",
               "src/dkim.h","src/visage.h"]
# outbox_check.com shares everything except outbox_main.c (it has its own main).
OUTBOX_CHECK_SRCS = ["src/outbox_check.c","src/outbox_submit.c","src/outbox_deliver.c",
                     "src/outbox_auth.c","src/smtp_out.c","src/mail.c",
                     "src/auth_results.c","src/dkim.c","src/smtp_in_tls.c"]
T.append(target("outbox.com",
    deps=[STAMP] + OUTBOX_SRCS + OUTBOX_HDRS + [MBEDTLS_CONFIG, DATA_CACERT],
    recipe=[link_cmd("outbox.com", OUTBOX_SRCS + [DATA_CACERT] + mbtls_objs,
                     MBFLAGS + " -pthread")],
    out="outbox.com"))
T.append(target("outbox_check.com",
    deps=[STAMP] + ["src/outbox_check.c"] + OUTBOX_SRCS + OUTBOX_HDRS
         + [MBEDTLS_CONFIG, DATA_CACERT],
    recipe=[link_cmd("outbox_check.com",
                OUTBOX_CHECK_SRCS + [DATA_CACERT] + mbtls_objs,
                MBFLAGS + " -pthread")],
    out="outbox_check.com"))

# --- tests ---
T.append(target("tests/tls_selfcheck.com",
    deps=[STAMP] + ["tests/tls_selfcheck.c", MBEDTLS_CONFIG],
    recipe=[link_cmd("tests/tls_selfcheck.com", ["tests/tls_selfcheck.c"] + mbtls_objs, MBFLAGS)],
    out="tests/tls_selfcheck.com"))
T.append(target("tests/verify_selfcheck.com",
    deps=[STAMP] + ["tests/verify_selfcheck.c", MBEDTLS_CONFIG, DATA_CACERT],
    recipe=[link_cmd("tests/verify_selfcheck.com",
                ["tests/verify_selfcheck.c"] + mbtls_objs + [DATA_CACERT], MBFLAGS)],
    out="tests/verify_selfcheck.com"))
T.append(target("tests/smtptest.com",
    deps=["tests/smtptest.c"],
    recipe=[link_cmd("tests/smtptest.com", ["tests/smtptest.c"])],
    out="tests/smtptest.com"))
T.append(target("tests/relay_fake.com",
    deps=[STAMP] + ["tests/relay_fake.c", MBEDTLS_CONFIG],
    recipe=[link_cmd("tests/relay_fake.com", ["tests/relay_fake.c"] + mbtls_objs, MBFLAGS)],
    out="tests/relay_fake.com"))

# --- bench, e2e, gen-admin (phony) ---
T.append(target("bench",
    deps=["store_bench.com"],
    recipe=["./store_bench.com", "python3 tools/bench_plot.py bench.csv docs/bench-latency.svg docs/bench-size.svg"],
    out=None))
T.append(target("e2e",
    deps=["visage.com","config_check.com","tests/smtptest.com","tests/relay_fake.com",
          "imapd.com","tests/imapd_tls.sh","tests/pop3d_tls.sh",
          "tests/smtp_starttls.sh"],
    recipe=["./tests/run.sh", "./tests/imapd_tls.sh", "./tests/pop3d_tls.sh",
            "./tests/smtp_starttls.sh"],
    out=None))
T.append(target("gen-admin",
    deps=["tools/gen_admin_ui.sh"],
    recipe=["./tools/gen_admin_ui.sh"],
    out=None))

# --- site (from existing Dhakefile, now hash-pinned where deterministic) ---
T.append(target("mfe-framework",
    deps=[], recipe=["cd vendor/mfe-framework && npm ci && npm run build"], out=None))
T.append(target("vendor-mfe",
    deps=["mfe-framework"],
    recipe=["rm -rf vendor/@mfe",
            "mkdir -p vendor/@mfe/core vendor/@mfe/framework",
            "cp vendor/mfe-framework/packages/core/dist/*.js vendor/@mfe/core/",
            "cp vendor/mfe-framework/packages/framework/dist/*.js vendor/@mfe/framework/"],
    out=None))
site_deps = ["src/Main.elm","elm.json","vendor/design/src"]
T.append(target("dist/elm.js",
    deps=site_deps,
    recipe=["node_modules/elm/bin/elm make src/Main.elm --output=dist/elm.js --optimize"],
    out="dist/elm.js"))
ssg_deps = ["dist/elm.js","vendor-mfe","shell/index.html","shell/pages.js","shell/shell.js",
            "shell/templates/visage-landing.html","shell/templates/visage-compactness.html",
            "shell/templates/visage-security.html","shell/templates/visage-config.html",
            "shell/templates/visage-cli.html","shell/templates/visage-playground.html",
            "shell/templates/fixpoint.html","shell/mfe/visage-page.js",
            "shell/mfe/visage-playground.js","scripts/ssg.mjs","docs/visage.js",
            "docs/app.js","docs/bench-size.svg","docs/bench-latency.svg",
            "docs/vendor/codemirror.min.js","docs/vendor/codemirror.css",
            "docs/vendor/codemirror-simple.js","docs/vendor/dhall-mode.js"]
T.append(target("dist/index.html",
    deps=ssg_deps,
    recipe=["node scripts/ssg.mjs"],
    out="dist/index.html"))

# --- `all` aggregate (default): all C binaries; site reachable by name ---
all_deps = ["visage.com","config_check.com","store_check.com","store_bench.com",
            "mail_check.com","reply_check.com","smtp_check.com","http_check.com",
            "dkim_check.com","auth_check.com","imapd.com","imap_check.com","imap_fuzz.com",
            "tests/tls_selfcheck.com","tests/verify_selfcheck.com",
            "tests/smtptest.com","tests/relay_fake.com"]
T.append(target("all", deps=all_deps, recipe=[], out=None))

# ---------- emit Dhakefile.dhall ----------
out = []
out.append("""-- Dhakefile.dhall — build the entire visage repo with dhake (no Make).
--
-- One buildfile drives every build target (C binaries + mbedTLS + Elm
-- docs site), with hash-verified builds:
--   * `hash`     — expected sha256 of each non-phony output (verified after build)
--   * `depsHash` — expected sha256 of every input source (verified before build)
--
-- Usage:
--   ./vendor/dhake/dhake.com                    # build all (default target: `all`)
--   ./vendor/dhake/dhake.com visage.com         # one binary
--   ./vendor/dhake/dhake.com dist/index.html    # the Elm docs site
--   ./vendor/dhake/dhake.com e2e                # host integration tests
--   ./vendor/dhake/dhake.com bench              # store benchmark + plots
--   ./vendor/dhake/dhake.com --verify           # CI pre-flight: pin checks + up-to-date
--   ./vendor/dhake/dhake.com --warn-hash-mismatch TARGET  # re-pin stale hashes
--
-- Generated by tools/gen_dhakefile.py; do not hand-edit the hash pins.

let Action =
      < Shell : Text
      | Copy : { from : Text, to : Text }
      | Mkdir : < Plain : Text | Parents : { path : Text, parents : Bool } >
      | Rm : < Plain : Text | Recursive : { path : Text, recursive : Bool } >
      | Touch : Text
      | Move : { from : Text, to : Text }
      | Symlink : { from : Text, to : Text }
      | Chmod : { path : Text, mode : Text }
      | Echo : Text
      | Env : { key : Text, value : Text }
      | Run : { argv : List Text }
      >

let Target = { deps : List Text, phony : Bool, recipe : List Action
             , hash : Optional Text
             , depsHash : Optional (List { path : Text, hash : Text })
             , arch : Optional Text
             }

in  { targets = [""")
out.append("\n          , ".join(T))
out.append("""      ]
    , default = "all"
    }
""")
print("\n".join(out))
