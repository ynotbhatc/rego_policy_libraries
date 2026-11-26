#!/usr/bin/env bash
# Build the OPA bundle that is published to GHCR. One definition of what goes in, used by the publish
# workflow and by `make check-bundle` (which CI runs on every pull request), so the published build is
# tested before it is ever published.
#
#   scripts/build_bundle.sh [output.tar.gz] [revision]
#
# What ships: runtime policy (.rego outside test trees) and the crosswalk data (crosswalk/**/data.json),
# which nist_800_53 and fedramp read as data.crosswalk.*. In bundle mode OPA loads only files named
# data.json / data.yaml as data, so sample and schema JSON elsewhere is never loaded; check_bundle.py fails
# the build if a data file appears anywhere but crosswalk/.
set -euo pipefail
OUT="${1:-bundle.tar.gz}"
REV="${2:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
OPA_BIN="${OPA:-opa}"
cd "$(dirname "$0")/.."
python3 scripts/gen_bundle_manifest.py "$REV" >/dev/null
"$OPA_BIN" build -b . --output "$OUT" \
  --ignore '*_test.rego' \
  --ignore 'test_*.rego' \
  --ignore 'tests' \
  --ignore '_framework_key_tests' \
  --ignore 'docs' \
  --ignore 'scripts' \
  --ignore 'tools' \
  --ignore 'standard' \
  --ignore 'schemas' \
  --ignore 'converters' \
  --ignore 'examples' \
  --ignore '.github' \
  --ignore '.git' \
  --ignore '.claude'
echo "bundle: $OUT ($(wc -c < "$OUT" | tr -d ' ') bytes, revision $REV)"
