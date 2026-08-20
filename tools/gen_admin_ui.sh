#!/bin/sh
# gen_admin_ui.sh — regenerate src/data/admin_ui.c from the admin web UI source.
# Run from the repo root.  Both admin/{index.html,app.js,style.css} (source of
# truth) and src/data/admin_ui.c (generated) are committed, mirroring the
# cacert_pem.c pattern (see tools/gen_cacert.sh).
set -eu
cd "$(dirname "$0")/.."

test -f admin/index.html || { echo "missing admin/index.html"; exit 1; }
test -f admin/app.js    || { echo "missing admin/app.js";    exit 1; }
test -f admin/style.css || { echo "missing admin/style.css"; exit 1; }

# Emit one embedded C string array for a source file.  $1 = C identifier
# suffix (e.g. index_html -> visage_admin_index_html), $2 = source path.
emit() {
    name="visage_admin_$1"
    awk -v name="$name" '
BEGIN {
  printf "const char %s[] =\n", name;
}
{
  gsub(/\\/, "\\\\");
  gsub(/"/, "\\\"");
  printf "\"%s\\n\"\n", $0;
}
END {
  print "\"\";";
  printf "const size_t %s_len = sizeof(%s) - 1;\n", name, name;
}
' "$2"
}

out="src/data/admin_ui.c"
{
  echo "/* admin_ui.c — GENERATED FILE. Do not edit by hand."
  echo " * Rebuild from admin/{index.html,app.js,style.css} via: tools/gen_admin_ui.sh"
  echo " * These embed the self-contained daemon-served admin web UI (no external"
  echo " * assets; served unauthenticated as a data-free static shell). */"
  echo "#include <stddef.h>"
  echo
  emit index_html admin/index.html
  echo
  emit app_js admin/app.js
  echo
  emit style_css admin/style.css
} > "$out"
echo "generated src/data/admin_ui.c"
