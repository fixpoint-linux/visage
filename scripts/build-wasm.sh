#!/bin/sh
# Build the visage email alias service to wasm (emscripten), output to docs/.
# Adapted from compendium/scripts/build-wasm.sh.
# Requires: pacman -S emscripten clang lld llvm nodejs
#   (emscripten BUNDLES binaryen; do NOT also `pacman -S binaryen` — they conflict.)
set -euo pipefail
cd "$(dirname "$0")/.."

# dhall-c is vendored as a git submodule; override with DHALL_C=../dhall-c to
# use a sibling checkout instead.
DHALL_C="${DHALL_C:-vendor/dhall-c}"

EMCONF="$(mktemp)"
cat > "$EMCONF" <<'EOF'
import os
NODE_JS = '/usr/bin/node'
LLVM_ROOT = '/usr/bin'
BINARYEN_ROOT = '/usr'
EMSCRIPTEN_ROOT = '/usr/lib/emscripten'
CACHE = os.path.expanduser('~/.cache/emscripten')
EOF

EMCC=/usr/lib/emscripten/emcc
OUT="$(mktemp -d)"

# FORCE_FILESYSTEM=1 is required: visage-wasm.c writes the JS-provided config
# string into MEMFS via fopen/fwrite, and config_load() fopen()s it back.
COMMON="-O2 -I src -I $DHALL_C/src -s MODULARIZE=1 -s ALLOW_MEMORY_GROWTH=1 -s TOTAL_STACK=5242880 -s FORCE_FILESYSTEM=1"
RUNTIME="-s EXPORTED_RUNTIME_METHODS=ccall,cwrap,stringToUTF8,UTF8ToString,lengthBytesUTF8,HEAPU8"

# dhall-c interpreter core (mirrors compendium/scripts/build-wasm.sh): excludes its
# entry/extra TUs (main/wasm/bench/lsp/json), ssrf.c (never referenced by the wasm
# build), AND http.c — replaced by src/visage-wasm-no-remote.c (added below), which
# stubs out http_fetch/url_dirname/url_join so NO http:// import ever issues an
# XHR.  (In dhall-c's http.c the wasm path is a synchronous XMLHttpRequest with no
# SSRF gate, so a hostile pasted config could otherwise make visitors' browsers
# probe arbitrary URLs.)  sha256.c stays for the sha256: import check.
CORE="$DHALL_C/src/arena.c $DHALL_C/src/lexer.c $DHALL_C/src/parser.c $DHALL_C/src/ast.c $DHALL_C/src/normalize.c $DHALL_C/src/typecheck.c $DHALL_C/src/builtins.c $DHALL_C/src/serialize.c $DHALL_C/src/import.c $DHALL_C/src/bignum.c $DHALL_C/src/sha256.c"

# visage core + wasm entry. NO main.c (has its own main). NO store.c/smtp_*.c/
# dkim.c/reply.c/http.c — the DAFSA store (disk-persistent + flock/WAL), the SMTP
# socket state machines, and mbedTLS DKIM are irrelevant to the config+alias demo.
EM_CONFIG="$EMCONF" "$EMCC" $COMMON \
  -s EXPORT_NAME=createVisage \
  -s EXPORTED_FUNCTIONS=_visage_load,_visage_resolve,_visage_err,_visage_json,_visage_json_len,_malloc,_free \
  $RUNTIME \
  -o "$OUT/visage.js" \
  src/visage-wasm.c src/config.c src/mail.c src/visage-wasm-no-remote.c $CORE

mkdir -p docs
cp "$OUT/visage.js" "$OUT/visage.wasm" docs/ 2>/dev/null \
  || cp "$OUT"/visage.js "$OUT"/visage.wasm docs/
rm -rf "$OUT" "$EMCONF"
ls -la docs/visage.js docs/visage.wasm
echo "built docs/visage.js + docs/visage.wasm"
