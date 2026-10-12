#!/usr/bin/env bash
# Round-trip: the same fixture evaluated by the Rego target and by the WASM target
# must yield the same violation set, per CONTRACT.md rule 5.
# Needs an OPA binary with the wasm engine (opa_linux_amd64, not *_static; the
# Homebrew macOS build lacks it). Without the engine the test SKIPs loudly.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; ROOT="$(cd "$HERE/../../../.." && pwd)"
if ! echo '{"x":1}' | opa eval -I -t wasm 'input.x == 1' -f raw >/dev/null 2>&1; then
  echo "SKIP: this opa has no wasm engine (use opa_linux_amd64, not _static)"; exit 0
fi
fail=0
for fx in "$HERE"/fixtures/*.json; do
  name="$(basename "$fx" .json)"           # e.g. mas_trm-full  ->  pkg mas_trm, dir frameworks/financial/mas_trm
  pkg="${name%%-*}"
  dir="$(grep -rl --include='*.rego' "^package ${pkg}\.main$" "$ROOT" | grep -v tests | head -1 | xargs dirname)"
  q="data.${pkg}.main.violations"
  rego="$(opa eval -d "$dir" -i "$fx" "$q" -f json | python3 -c 'import json,sys; print(sorted(json.load(sys.stdin)["result"][0]["expressions"][0]["value"]))')"
  wasm="$(opa eval -t wasm -d "$dir" -i "$fx" "$q" -f json | python3 -c 'import json,sys; print(sorted(json.load(sys.stdin)["result"][0]["expressions"][0]["value"]))')"
  if [ "$rego" == "$wasm" ]; then echo "PASS $name ($(echo "$rego" | tr -cd ',' | wc -c | tr -d ' ')+ violations)"; else echo "FAIL $name: rego and wasm differ"; fail=1; fi
done
exit $fail
