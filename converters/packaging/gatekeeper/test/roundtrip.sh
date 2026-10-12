#!/usr/bin/env bash
# Round-trip (CONTRACT rule 5), without a cluster: the generated adapter + rewritten libs,
# evaluated by plain OPA on a Gatekeeper-shaped input, must yield the same violation
# messages as the original policy on the same object. `gator test` is the in-cluster
# equivalent; run it where gator is installed.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; ROOT="$(cd "$HERE/../../../.." && pwd)"; OUT="$HERE/../out"
python3 "$HERE/../build.py" >/dev/null
fail=0
for fx in "$HERE"/fixtures/*.json; do
  name="$(basename "$fx" .json)"; tmpl="${name%%-*}"
  case "$tmpl" in
    k8spssprofile)
      if [[ "$name" == *unmappable* ]]; then
        n="$(opa eval -d "$OUT/roundtrip/$tmpl" -i "$fx" '[v.msg | some v in data.k8spssprofile.violation]' -f json | python3 -c 'import json,sys; v=json.load(sys.stdin)["result"][0]["expressions"][0]["value"]; print(len(v), any("refusing" in m for m in v))')"
        if [ "$n" == "1 True" ]; then echo "PASS $name (unmappable kind -> violation with reason)"; else echo "FAIL $name: $n"; fail=1; fi; continue
      fi
      orig_dir="$ROOT/benchmarks/pss/kubernetes"; orig_q='data.k8s_pss.main.effective_violations'
                   orig_in="$(python3 -c "import json,sys; d=json.load(open('$fx')); o=d['review']['object']; pod=o if o['kind']=='Pod' else {'kind':'Pod','metadata':o['metadata'],'spec':o['spec']['template']['spec']}; print(json.dumps({'pod':pod,'pss_profile':d.get('parameters',{}).get('profile','restricted')}))")";;
    k8saacadmission) orig_dir="$ROOT/enforcement/kubernetes"; orig_q='data.kubernetes.admission.violations'
                   orig_in="$(python3 -c "import json; d=json.load(open('$fx')); print(json.dumps({'request': d['review']}))")";;
    *) echo "unknown fixture $name"; exit 1;;
  esac
  a="$(echo "$orig_in" | opa eval -I -d "$orig_dir" "$orig_q" -f json | python3 -c 'import json,sys; print(sorted(json.load(sys.stdin)["result"][0]["expressions"][0]["value"]))')"
  b="$(opa eval -d "$OUT/roundtrip/$tmpl" -i "$fx" "[v.msg | some v in data.${tmpl}.violation]" -f json | python3 -c 'import json,sys; print(sorted(json.load(sys.stdin)["result"][0]["expressions"][0]["value"]))')"
  if [ "$a" == "$b" ]; then echo "PASS $name"; else echo "FAIL $name"; echo " original : $a"; echo " template : $b"; fail=1; fi
done
exit $fail
