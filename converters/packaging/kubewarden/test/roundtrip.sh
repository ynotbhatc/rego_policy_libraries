#!/usr/bin/env bash
# Round-trip (CONTRACT rule 5): adapter + policy evaluated by plain OPA on an AdmissionReview
# must deny exactly when the original policy reports violations, with the same messages.
# `kwctl run` is the in-engine equivalent where kwctl is installed.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; ROOT="$(cd "$HERE/../../../.." && pwd)"; OUT="$HERE/../out"
python3 "$HERE/../build.py" >/dev/null
fail=0
for fx in "$HERE"/fixtures/*.json; do
  name="$(basename "$fx" .json)"; pol="${name%%--*}"
  case "$pol" in
    k8s-pss-baseline|k8s-pss-restricted)
      prof="${pol#k8s-pss-}"
      orig="$(python3 -c "import json; d=json.load(open('$fx')); o=d['request']['object']; pod=o if o['kind']=='Pod' else {'kind':'Pod','metadata':o['metadata'],'spec':o['spec']['template']['spec']}; print(json.dumps({'pod':pod,'pss_profile':'$prof'}))" | opa eval -I -d "$ROOT/benchmarks/pss/kubernetes" 'data.k8s_pss.main.effective_violations' -f json | python3 -c 'import json,sys; print(sorted(json.load(sys.stdin)["result"][0]["expressions"][0]["value"]))')";;
    k8s-aac-admission)
      orig="$(opa eval -d "$ROOT/enforcement/kubernetes" -i "$fx" 'data.kubernetes.admission.violations' -f json | python3 -c 'import json,sys; print(sorted(json.load(sys.stdin)["result"][0]["expressions"][0]["value"]))')";;
    *) echo "unknown fixture $name"; exit 1;;
  esac
  got="$(opa eval -d "$OUT/$pol" -i "$fx" 'data.policy.main.response' -f json | python3 -c 'import json,sys; r=json.load(sys.stdin)["result"][0]["expressions"][0]["value"]; print(sorted([m for m in r["status"]["message"].split("; ") if m]), r["allowed"])')"
  exp="$orig $( [ "$orig" == "[]" ] && echo True || echo False )"
  if [ "$got" == "$exp" ]; then echo "PASS $name"; else echo "FAIL $name"; echo " expected: $exp"; echo " got     : $got"; fail=1; fi
done
exit $fail
