---
name: regal-lint
description: Lint Rego with Regal before committing or opening a PR in this library. Catches the bug/idiom/performance classes that `opa test` and `opa fmt` miss — unused vars, rule/builtin shadowing, redundant existence checks, unsafe comparisons, deprecated constructs, fail-open `default` misuse. Defaults to the files changed vs main (so you see only what you touched, not the whole library's backlog), foregrounds real defects over style, and gives a GO / HOLD. Run it on any Rego change.
allowed-tools: Bash(regal *) Bash(git *) Bash(opa *) Bash(brew *) Bash(python3 *)
---

Lint the Rego change with **Regal**, the OPA-team linter, and report a **GO / HOLD**.

Regal complements the tools this repo already runs: `opa test` proves correctness,
`opa fmt` fixes formatting, and Regal catches the **bug / idiom / performance** layer
in between. The repo ships a calibrated `.regal/config.yaml` (it silences the three
rules that fight this library's deliberate conventions — `directory-package-mismatch`,
`rule-name-repeats-package`, and a raised `line-length` — and keeps every correctness
rule at full strength). Regal discovers that config automatically from the repo root.

## 1. Confirm Regal is available

```bash
regal version || echo "NOT INSTALLED — run: brew install regal   (or download from github.com/open-policy-agent/regal/releases)"
```

If it is not installed, stop and tell the user to install it; do not skip the lint.

## 2. Determine scope (default: changed files vs main)

```bash
ROOT="$(git rev-parse --show-toplevel)"; cd "$ROOT"
git fetch origin --quiet 2>/dev/null || true
# The .rego files this branch changed (added/modified) vs main:
CHANGED=$(git diff --name-only --diff-filter=d origin/main...HEAD -- '*.rego'; git diff --name-only --diff-filter=d -- '*.rego'; git ls-files --others --exclude-standard -- '*.rego')
CHANGED=$(printf '%s\n' $CHANGED | sort -u | grep -v '^$')
printf 'changed .rego files:\n%s\n' "$CHANGED"
```

If the user named a path or `--all`, lint that scope instead. With no changed files
and no argument, fall back to `--all` and say so.

## 3. Lint with full repo context, report only the in-scope violations

Lint the **whole repo** (so cross-file/aggregate rules like `unresolved-reference`
resolve correctly and don't false-positive), then filter the findings to the changed
files. This is more accurate than linting isolated files.

```bash
regal lint . --format json > /tmp/regal.json 2>/dev/null
python3 - "$CHANGED" <<'PY'
import sys, json, collections
changed = set(p for p in sys.argv[1].split() if p)
d = json.load(open('/tmp/regal.json'))
v = [x for x in d.get('violations', [])
     if (not changed) or x.get('location', {}).get('file') in changed]
cat = collections.Counter(x['category'] for x in v)
bugs = [x for x in v if x['category'] in ('bugs', 'performance')]
print(f"in-scope violations: {len(v)}   (bugs+performance: {len(bugs)})")
for c, n in cat.most_common():
    print(f"  {n:4}  {c}")
print("\n--- bugs / performance (the ones that matter) ---")
for x in bugs:
    loc = x.get('location', {})
    print(f"  {x['category']}/{x['title']}  {loc.get('file')}:{loc.get('row')}  — {x.get('description','')}")
PY
```

## 4. Verdict

- **HOLD** if any **`bugs/*`** or **`performance/*`** violation lands in the changed
  files — those are real defects (fail-open `default`, redundant existence check,
  leaked internal reference, unsafe comparison, etc.). Fix before merging.
- **GO** otherwise. Report the **style/idiomatic** counts as advisory — the author may
  clean them up, but they do not block. Note any `imports/unresolved-reference` that
  looks like a cross-file reference (it can be a false positive when a module reads
  `data.<other>` that the bundle resolves at runtime).

Fixing HOLD findings before the PR is the whole point of running this pre-merge — the
same intent as `/code-review`, one layer lower.
