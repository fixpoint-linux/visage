#!/bin/sh
# gen_cacert.sh — regenerate src/data/cacert_pem.c from src/data/cacert.pem.
# Run from the repo root. The PEM source is fetched separately (host, network):
#   curl -fsSL https://curl.se/ca/cacert.pem -o src/data/cacert.pem
# Refresh policy: quarterly (see roadmap). Both cacert.pem (source of truth,
# byte-identical to upstream) and cacert_pem.c (generated) are committed.
set -eu
cd "$(dirname "$0")/.."
test -f src/data/cacert.pem || { echo "missing src/data/cacert.pem"; exit 1; }
awk '
BEGIN {
  print "/* cacert_pem.c — GENERATED FILE. Do not edit by hand.";
  print " * Rebuild from src/data/cacert.pem via: tools/gen_cacert.sh";
  print " * Source of truth: https://curl.se/ca/cacert.pem (Mozilla CA bundle).";
  print " * Refresh policy: quarterly (see roadmap). */";
  print "#include <stddef.h>";
  print "const char visage_cacert_pem[] =";
}
{
  gsub(/\\/, "\\\\");
  gsub(/"/, "\\\"");
  printf "\"%s\\n\"\n", $0;
}
END {
  print "\"\";";
  print "const size_t visage_cacert_pem_len = sizeof(visage_cacert_pem) - 1;";
}
' src/data/cacert.pem > src/data/cacert_pem.c
echo "generated src/data/cacert_pem.c"
