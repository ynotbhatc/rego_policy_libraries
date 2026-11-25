#!/usr/bin/env python3
"""A missing fact must not silently drop a row out of a check (the `not f(x.y)` idiom).

Measured on OPA 1.22.4, with `x.y` missing:

    not x.y                 true        (a bare reference under `not`)
    not x.y == v            true        (equality of plain operands under `not`)
    not f(x.y)              UNDEFINED   (any call: builtin or function, also is_string / is_object / count)
    not x.y in S            UNDEFINED
    not x.y != v, < n ...   UNDEFINED   (every comparison operator other than ==)
    not f(r)                UNDEFINED   when r is a rule that has no value (r := input.a, a missing)

An undefined expression stops the rule body. In a violation rule that means no finding for the row or input that
lacks the field: the row drops out of the check and the control passes (fail-open). In a pass rule the same
expression is harmless: the rule does not pass (fail-closed).

This check parses every policy file with OPA's own parser (`opa parse --format json`) and reports:

  negated shapes
    neg-call        not f(... x.y ...)           a call whose arguments hold a reference that can be undefined
    neg-in          not x.y in S / not v in x.y
    neg-cmp         not x.y != v, not x.y < n, not f(x.y) == v, not [x.y] == [...]
    neg-var         v := x.y ... not f(v)        the same idiom split over two lines (the row drops at the assignment)
    neg-partial-fn  not f(g(a))                  g is a function of this package that is not defined for every argument
  sibling shapes (not negated; same effect in a violation body with no presence guard)
    cmp             x.y != v, x.y < n, x.y >= n ...   (x.y != null is a presence test and is not reported)
    count-zero      count(x.y) == 0, count(x.y) < 1
    to-number       to_number(x.y)
    get-default     object.get(x, k, <default>) where the default is the passing value: the comparison the
                    default feeds is false in a violation body, or true in a pass body

"A reference that can be undefined" is: an `input.` path; a field of a local variable (an iterated row, a function
parameter) unless the variable comes from a constant table of the package; a rule of the package that can be
undefined (`_m := input.a.b`), with or without a path; a key of a partial object rule. References inside a
comprehension nested in the expression do not count (a comprehension is always defined). `object.get(x.y, k, d)`
counts for `x.y`, not for `k`.

Every hit gets an effect from the rule it sits in:

    fail-open     a violation / deny / finding rule, or a collection named like one: missing -> no finding
    fail-closed   a pass / compliant rule, or a collection named like one: missing -> not passed (harmless)
    guarded       a hit on a field of an iterated row that an earlier positive line of the same rule already reads
                  (`contains(i.value, "x"); not contains(i.value, "y")`: the row is already filtered on the field), or a bare `x.y` line / `_has_key(obj, "k")` test before it
                  (an optional field), or a comparison / count / to_number after a type check of the same fact (is_number(x); x > 90) where the
                  package also reads that fact in a way that is defined when it is missing (a `not is_number(object.get(
                  ...))` evidence finding): the evidence rule's shape. Reported, never gated; --json shows the guard line.
    review        neither could be told from the rule's name or from how the package uses it; needs reading

Rule classes come from the rule name (violations, deny, *_missing, non_compliant ... / compliant, *_ok, valid_* ...)
and, for helpers, from how classified rules of the same package use them (a helper negated in a violation rule
is a pass helper; a helper used bare in a violation rule is a violation helper), to a fixed point.

The gate: `--check` fails on a hit that is not in the baseline when it is fail-open (any shape) or a negated shape to
review. fail-closed hits and sibling shapes to review are reported (summary, --json) and never gated. Baselines live in scripts/undefined_negation_baseline/<tree>.txt, one file per
top-level directory (benchmarks.txt, frameworks.txt ...), so trees are baselined independently. A tree with no
baseline file is reported and not gated. Every baseline entry carries a reason: a `# reason: <text>` line applies to
the entries below it until the next one; an entry with no reason, or a reason that starts with TODO, fails the
check. An entry that no longer matches a hit is stale and fails the check too (the baseline only shrinks).

    python3 scripts/check_undefined_negation.py                      # summary
    python3 scripts/check_undefined_negation.py --check              # exit 1 on a new hit, a stale or reasonless entry
    python3 scripts/check_undefined_negation.py --paths frameworks governance --check
    python3 scripts/check_undefined_negation.py --paths benchmarks --write-baseline
    python3 scripts/check_undefined_negation.py --json hits.json     # every hit, all effects
    python3 scripts/check_undefined_negation.py --list               # print the gated hits not in the baseline

--write-baseline rewrites the baseline of each tree in --paths (default: every tree): entries that still match keep
their reason, new ones land under `# reason: TODO`, which --check refuses until someone writes the reason.
Acceptable reasons: guarded elsewhere (name the guard), legitimately optional per <citation>, harmless (say why).

Fixing one: report the missing field as an evidence finding next to the check, e.g.

    violations contains msg if { some row in input.rows; not is_string(object.get(row, "name", null)); msg := ... }

or read the fact through object.get with a failing default, so the row stays in the check.

Needs OPA ($OPA, else `opa` on PATH).
"""
from __future__ import annotations
import argparse, base64, collections, concurrent.futures as cf, json, os, pathlib, re, subprocess, sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
BASELINE_DIR = ROOT / "scripts" / "undefined_negation_baseline"
SKIP_PREFIX = ("converters/", ".github/", ".git/", "tests/")
TEST_RE = re.compile(r"(^|/)(test_[^/]*|[^/]*_test\.rego)$")
GATED = ("fail-open", "review")
NEGATED_KINDS = ("neg-call", "neg-in", "neg-cmp", "neg-var", "neg-partial-fn")


def is_gated(hit):
    """negated shapes are gated unless the rule is a pass rule; sibling shapes only where the rule is a violation rule"""
    return hit["effect"] == "fail-open" or (hit["effect"] == "review" and hit["kind"] in NEGATED_KINDS)
SIBLING_KINDS = ("cmp", "count-zero", "to-number")
KINDS = ("neg-call", "neg-in", "neg-cmp", "neg-var", "neg-partial-fn", "cmp", "count-zero", "to-number", "get-default")

CMP_OPS = {"neq": "!=", "lt": "<", "lte": "<=", "gt": ">", "gte": ">="}
MEMBER = {"internal.member_2", "internal.member_3"}
SCALARS = {"string", "number", "boolean", "null"}
COMPREHENSIONS = {"arraycomprehension", "setcomprehension", "objectcomprehension"}

# rule-name vocabulary; violation words are tried first (non_compliant, invalid, not_ok ...)
V_NAME = re.compile(r"(violation|deny|denied|denial|finding|fail|non_?compl|noncompl|missing|invalid|issue|gap|"
                    r"error|warn|alert|risk|drift|unauthor|unapprov|exceed|expired|stale|overdue|detect|blocked|"
                    r"reason|problem|defect|bad_|_bad|insecure|weak|not_|^no_|without|lacks?_|unencrypted|"
                    r"unpatched|unsigned|untagged|unprotected|suspicious|malicious|anomal|deviation|breach|"
                    r"prohibited|forbidden|disallowed|noncurrent|unmet|unsatisf|outdated|orphan|flagged|"
                    r"foreign|offending|rejected|incident|threat|exposed|vulnerab|critical_|advisor|excessive|"
                    r"inappropriate|malformed|unreadable|unlocked|outside)", re.I)
P_NAME = re.compile(r"(compl|pass|_ok$|^ok_|^ok$|valid|satisf|_met$|^met_|allow|approved|^is_|^has_|_is_|_has_|"
                    r"implemented|enabled|configured|complete|current|secure|within|exempt|acceptable|"
                    r"authorized|protected|encrypted|enforced|present|exists|in_scope|applicable|success|"
                    r"healthy|ready|trusted|verified|signed|matches|permitted|adequate|sufficient|effective|"
                    r"established|documented|defined|covered|maintained|score|percentage|rate$|"
                    # benchmark conventions: p_1_2_3 (pass), e_1_2_3 (evidence present), r_1_2 / r_wn11_so_1 (rule holds)
                    r"^[a-z]_\d|^r_[a-z0-9]+_|_reported$|^applies$|assessable|"
                    r"ed$|recent$|strong$|_full$|appropriate|correct$|supported$|_set$|_off$|_on$|_tight$|_fast$|_low$|"
                    r"_annual|_partial$|at_least|_meets?$)", re.I)


def classify_name(name):
    if not name:
        return "other"
    if V_NAME.search(name):
        return "violation"
    if P_NAME.search(name):
        return "pass"
    return "other"


# ---------------------------------------------------------------------------------------------- parsing
def policy_files(root, paths=None):
    root = pathlib.Path(root)
    starts = [root / p for p in paths] if paths else [root]
    seen = set()
    for s in starts:
        files = [s] if s.is_file() else sorted(s.rglob("*.rego"))
        for f in files:
            rel = f.relative_to(root).as_posix()
            if rel in seen or rel.startswith(SKIP_PREFIX) or "/tests/" in rel or TEST_RE.search(rel):
                continue
            seen.add(rel)
            yield rel


def parse(path):
    out = subprocess.run([os.environ.get("OPA", "opa"), "parse", "--format", "json", "--json-include",
                          "locations,-comments", str(path)], capture_output=True, text=True)
    if out.returncode != 0:
        raise RuntimeError(f"opa parse failed for {path}: {out.stderr.strip()[:300]}")
    return json.loads(out.stdout)


def parse_tree(root, rels, workers=8):
    root = pathlib.Path(root)
    with cf.ThreadPoolExecutor(workers) as ex:
        return dict(zip(rels, ex.map(lambda r: parse(root / r), rels)))


def _text(node):
    loc = node.get("location") if isinstance(node, dict) else None
    if not loc or "text" not in loc:
        return ""
    try:
        return " ".join(base64.b64decode(loc["text"]).decode("utf-8", "replace").split())
    except Exception:
        return ""


def _row(node):
    return (node.get("location") or {}).get("row", 0) if isinstance(node, dict) else 0


def rule_name(rule):
    h = rule["head"]
    if "name" in h and h["name"]:
        return h["name"]
    ref = h.get("ref") or []
    return ref[0]["value"] if ref and isinstance(ref[0].get("value"), str) else None


def _pkg(ast):
    return ".".join(str(t["value"]) for t in ast["package"]["path"][1:])


def _trivial(body):
    return all(isinstance(e.get("terms"), dict) and e["terms"].get("type") == "boolean" and e["terms"].get("value") is True
               for e in body or [])


def _opname(term):
    if isinstance(term, dict) and term.get("type") == "ref" and all(isinstance(x.get("value"), str) for x in term["value"]):
        return ".".join(x["value"] for x in term["value"])
    return None


def _head(ref):
    """the name a reference starts with (None when it starts with a literal or a call)"""
    v = ref["value"][0]
    return v["value"] if v.get("type") == "var" and isinstance(v.get("value"), str) else None


def _literal_only(term):
    """a term with no reference, variable or call in it"""
    t = term.get("type")
    if t in SCALARS:
        return True
    if t in ("array", "set"):
        return all(_literal_only(x) for x in term["value"])
    if t == "object":
        return all(_literal_only(k) and _literal_only(v) for k, v in term["value"])
    return False


def _pyval(term):
    """Python value of a literal term (sets become frozensets); raises ValueError otherwise"""
    t = term.get("type")
    if t in ("string", "number", "boolean"):
        return term["value"]
    if t == "null":
        return None
    if t == "array":
        return tuple(_pyval(x) for x in term["value"])
    if t == "set":
        return frozenset(_pyval(x) for x in term["value"])
    if t == "object":
        return tuple(sorted((json.dumps(_pyval(k), default=str), _pyval(v)) for k, v in term["value"]))
    raise ValueError(t)


# ---------------------------------------------------------------------------------------------- package facts
class Package:
    """What the scan needs to know about the rules of one package (all its files together)."""

    def __init__(self):
        self.rules = collections.defaultdict(list)   # name -> [rule clause, ...] (else branches included)
        self.cls = {}                                # name -> violation | pass | other
        self.probed = {}                             # normalized path -> "file:line" of a line that is defined when
        #                                              the path is missing (not x.y, object.get(x, "y", d) ...)
        self.probed_neg = {}                         # the same, from negated lines only (`not f(object.get(x, k, null))`):
        #                                              a line that reports the missing case
        self._memo = {}

    def add(self, ast):
        for r in ast.get("rules") or []:
            n = rule_name(r)
            while r is not None:
                if n:
                    self.rules[n].append(r)
                r = r.get("else")

    def is_function(self, name):
        return any(c["head"].get("args") for c in self.rules.get(name, ()))

    def const_table(self, name):
        """every clause is `name := <literal>` with no body: indexing it with its own keys is always defined"""
        cl = self.rules.get(name)
        return bool(cl) and all("value" in c["head"] and "key" not in c["head"] and not c["head"].get("args")
                                and _literal_only(c["head"]["value"]) and _trivial(c.get("body")) for c in cl)

    def always_defined(self, name):
        """a rule that has a value whatever the input is (a bare reference to it is never undefined)"""
        if ("ad", name) not in self._memo:
            self._memo[("ad", name)] = False     # a cycle cannot happen in Rego; this only stops a runaway
            self._memo[("ad", name)] = self._always_defined(name)
        return self._memo[("ad", name)]

    def _always_defined(self, name):
        cl = self.rules.get(name)
        if not cl:
            return True          # unknown name (import, builtin): not ours to judge
        if any(c.get("default") for c in cl):
            return True
        h = cl[0]["head"]
        if "key" in h or len(h.get("ref") or []) > 1:
            return True          # partial set / object: empty when nothing matches
        # a clause whose body cannot fail and whose value cannot be undefined
        return any(self._total_body(c.get("body")) and "value" in c["head"] and self._total_value(c["head"]["value"]) for c in cl)

    def _total_body(self, body):
        """a body that holds on every input: nothing, or only `v := <value that is always defined>` lines"""
        for e in body or []:
            t = e.get("terms")
            if isinstance(t, dict) and t.get("type") == "boolean" and t.get("value") is True:
                continue
            if e.get("negated") or not isinstance(t, list) or len(t) != 3 or _opname(t[0]) != "assign" \
                    or t[1].get("type") != "var" or not self._total_value(t[2]):
                return False
        return True

    @staticmethod
    def _type_checks_only(body):
        """nothing, or only is_object(input) / is_object(x) style lines: they do not change which value the rule has"""
        for e in body or []:
            t = e.get("terms")
            if isinstance(t, dict) and t.get("type") == "boolean":
                continue
            if e.get("negated") or not isinstance(t, list) or not (_opname(t[0]) or "").startswith("is_"):
                return False
        return True

    def alias(self, name):
        """the term a rule is an alias of (`_facts := input`, `_in := input.tisax`), else None"""
        cl = [c for c in self.rules.get(name, ()) if not c.get("default")]
        if len(cl) != 1 or "key" in cl[0]["head"] or cl[0]["head"].get("args") or not self._type_checks_only(cl[0].get("body")):
            return None
        v = cl[0]["head"].get("value")
        return v if v is not None and v.get("type") in ("ref", "var") else None

    def _keys_of(self, term, depth=0):
        """the string keys every value of this term has: an object literal, a call of a function whose clauses all
        return object literals, or a rule that is one of those (None when it cannot be told)"""
        if term is None or depth > 4:
            return None
        t = term.get("type")
        if t == "object":
            return {k["value"] for k, _ in term["value"] if k.get("type") == "string"}
        if t == "call":
            fn = _opname(term["value"][0])
            if fn in self.rules and self.is_function(fn):
                return self._rule_keys(fn, depth)
        if t in ("ref", "var") and len(term["value"] if t == "ref" else [0]) == 1:
            n = _head(term) if t == "ref" else term["value"]
            if n in self.rules and not self.is_function(n):
                return self._rule_keys(n, depth)
        return None

    def _rule_keys(self, name, depth):
        keys = None
        for c in self.rules.get(name, ()):
            if c.get("default"):
                continue
            k = self._keys_of(c["head"].get("value"), depth + 1)
            if k is None:
                return None
            keys = k if keys is None else keys & k
        return keys

    def field_defined(self, name, key):
        """`name.key` is always defined: the rule is, and every value it can take is an object that has the key"""
        if not self.always_defined(name):
            return False
        return key in (self._rule_keys(name, 0) or ())

    def _total_value(self, term):
        t = term.get("type")
        if t in SCALARS or t in COMPREHENSIONS:
            return True
        if t in ("array", "set"):
            return all(self._total_value(x) for x in term["value"])
        if t == "object":
            return all(self._total_value(k) and self._total_value(v) for k, v in term["value"])
        if t == "var":
            return True
        if t == "ref":
            v = term["value"]
            head = _head(term)
            if head is None:
                return False
            if len(v) == 1:
                return head == "input" or self.always_defined(head)
            return self.const_table(head)
        if t == "call":
            op = _opname(term["value"][0])
            args = term["value"][1:]
            if op == "object.get":
                return len(args) == 3 and all(self._total_value(a) for a in (args[0], args[2]))
            if op in ("count", "sum", "concat", "sprintf", "object.keys", "is_string", "is_number", "is_boolean",
                      "is_object", "is_array", "is_null", "is_set", "time.now_ns", "max", "min", "array.concat",
                      "object.union", "union", "or", "and"):
                return all(self._total_value(a) for a in args)
            if op in self.rules and self.is_function(op):
                return self.total_function(op) and all(self._total_value(a) for a in args)
        return False

    def total_function(self, name, _seen=None):
        """a function defined for every argument: a default, or a clause whose body cannot fail (nothing, or
        only assignments of values that are always defined) and whose value is always defined. "Always defined"
        is about missing facts, not about types: count("x") is undefined, and that is the numeric-guard lint's job."""
        if ("tf", name) not in self._memo:
            self._memo[("tf", name)] = False
            self._memo[("tf", name)] = self._total_function(name)
        return self._memo[("tf", name)]

    def _total_function(self, name):
        cl = self.rules.get(name) or []
        if any(c.get("default") for c in cl):
            return True
        for c in cl:
            if not self._total_body(c.get("body")):
                continue
            if any(a.get("type") != "var" for a in c["head"].get("args") or []):
                continue         # f("x") := ... only matches one argument
            v = c["head"].get("value")
            if v is None or self._total_value(v):
                return True
        return False


# ---------------------------------------------------------------------------------------------- the scan
class Hit(dict):
    @property
    def key(self):
        return "\t".join((self["file"], self["rule"], self["kind"], self["text"]))


class Scanner:
    def __init__(self, asts):
        self.asts = asts
        self.pkgs = collections.defaultdict(Package)
        for f, a in asts.items():
            self.pkgs[_pkg(a)].add(a)
        for p in self.pkgs.values():
            self._classify(p)
        self.hits = []
        self._cur = None

    # ---- rule classes
    def _classify(self, p):
        for n in p.rules:
            p.cls[n] = classify_name(n)
            # `default r := false` makes r a pass-style flag whatever its name says (_b4d_critical_patches_current):
            # when the body is undefined the flag is false = not passed
            for c in p.rules[n]:
                v = c["head"].get("value")
                if c.get("default") and v is not None and v.get("type") == "boolean" and v.get("value") is False \
                        and "args" not in c["head"]:
                    p.cls[n] = "pass"
        for _ in range(6):
            changed = False
            for n, clauses in p.rules.items():
                ctx = p.cls[n]
                if ctx == "other":
                    continue
                for c in clauses:
                    for e in c.get("body") or []:
                        used = self._bare_use(e, p)
                        if used is None or p.cls.get(used) != "other":
                            continue
                        neg = bool(e.get("negated"))
                        p.cls[used] = ctx if not neg else ("pass" if ctx == "violation" else "violation")
                        changed = True
            if not changed:
                break

    @staticmethod
    def _bare_use(expr, p):
        """the package rule or function a body line is, when the line is nothing but `r`, `r[x]`, `f(a)` (+ not)"""
        t = expr.get("terms")
        if isinstance(t, dict) and t.get("type") == "ref":
            h = _head(t)
            return h if h in p.rules else None
        if isinstance(t, list) and t and t[0].get("type") == "ref":
            op = _opname(t[0])
            if op in p.rules:
                return op
            if op == "equal" and len(t) == 3:      # r == true / f(x) == true
                for a, b in ((t[1], t[2]), (t[2], t[1])):
                    if b.get("type") == "boolean" and b.get("value") is True:
                        if a.get("type") == "ref" and _head(a) in p.rules:
                            return _head(a)
                        if a.get("type") == "call" and _opname(a["value"][0]) in p.rules:
                            return _opname(a["value"][0])
        return None

    # ---- driver
    def run(self):
        for f, a in self.asts.items():
            p = self.pkgs[_pkg(a)]
            imports = set()
            for i in a.get("imports") or []:
                path = i["path"]["value"]
                alias = i.get("alias") or (path[-1].get("value") if path else None)
                if alias and path and path[0].get("value") != "input":
                    imports.add(alias)
            for r in a.get("rules") or []:
                n = rule_name(r)
                while r is not None:
                    self._rule(f, p, n, r, imports)
                    r = r.get("else")
        for h in self.hits:                       # guard hint: the same path is read elsewhere in a way that
            probed = self.pkgs[h["pkg"]].probed   # is defined when it is missing (to be confirmed by reading)
            own = f"{h['file']}:{h['line']}"
            h["guard"] = next((w for x in h["paths"] for w in probed.get(x, ()) if w != own), "")
            # a comparison after a type check of the same fact, with the missing case reported by a rule of the
            # package (object.get / not elsewhere): the evidence rule's own shape, not a dropped row
            if h["used"] and h["effect"] in ("fail-open", "review"):
                h["effect"] = "guarded"      # the same fact is read by a positive line earlier in the rule: that line is the filter
            if h["present"] and h["effect"] in ("fail-open", "review"):
                h["effect"] = "guarded"      # `_has_key(obj, "k")` earlier in the rule: an optional field, checked if present
            neg_guard = next((w for x in h["paths"] for w in self.pkgs[h["pkg"]].probed_neg.get(x, ()) if w != own), "")
            if neg_guard and h["kind"] in NEGATED_KINDS and h["effect"] in ("fail-open", "review"):
                h["guard"] = h["guard"] or neg_guard
                h["effect"] = "guarded"      # another negated line of the package reports the missing case (`not f(object.get(..))`)
            if h["kind"] == "get-default" and h["guard"] and h["effect"] == "fail-open":
                h["effect"] = "guarded"      # the same object.get(..) is also read by a line that reports the missing case
            if h["typed"] and h["guard"] and h["kind"] in SIBLING_KINDS and h["effect"] == "fail-open":
                h["effect"] = "guarded"
        return self.hits

    def _rule(self, f, p, name, rule, imports):
        h = rule["head"]
        env = {}
        for a in h.get("args") or []:
            for v in self._vars(a):
                env[v] = ("param", None)
        ctx = {"f": f, "p": p, "rule": name or "?", "cls": p.cls.get(name, "other"), "imports": imports, "coll": None,
               "env": env, "pkg": _pkg(self.asts[f]), "typed": set(), "present": set(), "used": set()}
        self._cur = p
        self._body(rule.get("body") or [], env, ctx)
        for part in ("key", "value"):
            if part in h and h[part] is not None:
                self._comprehensions(h[part], env, dict(ctx, coll=name))

    # ---- environment
    @staticmethod
    def _vars(term):
        t = term.get("type")
        if t == "var":
            return [term["value"]]
        if t in ("array", "set"):
            return [v for x in term["value"] for v in Scanner._vars(x)]
        if t == "object":
            return [v for _, x in term["value"] for v in Scanner._vars(x)]
        return []

    @staticmethod
    def _literal_rows(term):
        """[[a, b], [c, d]]: each row is a literal, so its positions are defined (the values in them may not be)"""
        return term.get("type") in ("array", "set") and bool(term["value"]) \
            and all(x.get("type") in ("array", "object") for x in term["value"])

    def _const(self, term, env, p):
        t = term.get("type")
        if _literal_only(term):
            return True
        if t in ("array", "set"):
            return all(self._const(x, env, p) for x in term["value"])
        if t == "object":
            return all(self._const(k, env, p) and self._const(v, env, p) for k, v in term["value"])
        if t == "var":
            return env.get(term["value"], (None,))[0] == "const"
        if t == "ref":
            head = _head(term)
            if head in env:
                return env[head][0] == "const"
            return p.const_table(head)
        if t == "call":
            op = _opname(term["value"][0])
            if op == "object.get":
                return self._const(term["value"][1], env, p)
            if op in ("object.keys", "sort", "array.concat", "union"):
                return all(self._const(a, env, p) for a in term["value"][1:])
        return False

    def _bind(self, expr, env, ctx):
        """record what the variables this body line binds come from"""
        p = ctx["p"]
        t = expr.get("terms")
        if isinstance(t, dict) and "symbols" in t:
            for s in t["symbols"]:
                if s.get("type") == "call" and _opname(s["value"][0]) in MEMBER:
                    *names, dom = s["value"][1:]
                    kind = "const" if self._const(dom, env, p) or self._literal_rows(dom) else "iter"
                    for n in names:
                        for v in self._vars(n):
                            env[v] = (kind, dom)
                elif s.get("type") == "var":
                    env.setdefault(s["value"], ("iter", None))
            return
        if isinstance(t, dict) and "domain" in t:
            return
        if isinstance(t, list) and len(t) == 3 and _opname(t[0]) in ("assign", "eq") and not expr.get("negated"):
            lhs, rhs = t[1], t[2]
            if lhs.get("type") != "var" and rhs.get("type") == "var":
                lhs, rhs = rhs, lhs
            if lhs.get("type") == "var":
                if self._const(rhs, env, p):
                    env[lhs["value"]] = ("const", rhs)
                elif rhs.get("type") == "ref" and any(x.get("type") == "var" and x["value"] not in env
                                                      for x in rhs["value"][1:]):
                    env[lhs["value"]] = ("iter", rhs)      # x := input.rows[_]
                else:
                    env[lhs["value"]] = ("assign", rhs)
            else:
                for v in self._vars(lhs):
                    env.setdefault(v, ("iter", rhs))
        # variables introduced as reference keys: input.rows[i]
        for ref in self._refs(t if isinstance(t, list) else [t] if isinstance(t, dict) and "type" in t else []):
            for x in ref["value"][1:]:
                if x.get("type") == "var" and x["value"] not in env:
                    env[x["value"]] = ("iter", None)

    def _refs(self, terms, into_comprehensions=False):
        """every reference term in the given terms (operators excluded), outermost first"""
        out = []

        def walk(term):
            t = term.get("type")
            if t == "ref":
                out.append(term)
                for x in term["value"][1:]:
                    walk(x)
            elif t == "call":
                for a in term["value"][1:]:
                    walk(a)
            elif t in ("array", "set"):
                for x in term["value"]:
                    walk(x)
            elif t == "object":
                for k, v in term["value"]:
                    walk(k)
                    walk(v)
        for term in terms:
            if isinstance(term, dict):
                walk(term)
        return out

    def _maybe_undefined(self, ref, env, ctx):
        """can this reference be undefined on some input?"""
        p = ctx["p"]
        v = ref["value"]
        head = _head(ref)
        path = v[1:]
        if head is None:
            return False
        if head == "input":
            return bool(path)
        if head == "data" or head in ctx["imports"]:
            return False
        if head in env:
            if not path:
                return False
            return env[head][0] != "const"
        if head in p.rules:
            if p.is_function(head):
                return False
            if p.const_table(head):
                return False
            if not path:
                return not p.always_defined(head)
            if len(path) == 1 and path[0].get("type") == "string" and p.field_defined(head, path[0]["value"]):
                return False
            return True
        return False

    def _undefined_refs(self, terms, env, ctx):
        """the references in these terms that can be undefined, object.get keys and defaults left out"""
        found = []

        def walk(term):
            t = term.get("type")
            if t == "ref":
                if self._maybe_undefined(term, env, ctx):
                    found.append(term)
                    return
                for x in term["value"][1:]:
                    walk(x)
            elif t == "call":
                args = term["value"][1:]
                if _opname(term["value"][0]) == "object.get" and len(args) == 3:
                    walk(args[0])
                    return
                for a in args:
                    walk(a)
            elif t in ("array", "set"):
                for x in term["value"]:
                    walk(x)
            elif t == "object":
                for k, val in term["value"]:
                    walk(k)
                    walk(val)
        for term in terms:
            if isinstance(term, dict):
                walk(term)
        return found

    def _partial_calls(self, terms, ctx):
        """calls, nested in these terms, to functions of the package that are not defined for every argument"""
        p = ctx["p"]
        found = []

        def walk(term):
            t = term.get("type")
            if t == "call":
                op = _opname(term["value"][0])
                if op in p.rules and p.is_function(op) and not p.total_function(op):
                    found.append(term)
                for a in term["value"][1:]:
                    walk(a)
            elif t in ("array", "set"):
                for x in term["value"]:
                    walk(x)
            elif t == "object":
                for k, val in term["value"]:
                    walk(k)
                    walk(val)
            elif t == "ref":
                for x in term["value"][1:]:
                    walk(x)
        for term in terms:
            if isinstance(term, dict):
                walk(term)
        return found

    def _assigned_from_undefined(self, terms, env, ctx):
        """local variables in these terms that were assigned from an expression that can be undefined"""
        out = []

        def walk(term):
            t = term.get("type")
            if t == "var":
                o = env.get(term["value"])
                if o and o[0] == "assign" and o[1] is not None and self._undefined_refs([o[1]], env, ctx):
                    out.append((term, o[1]))
            elif t == "ref":
                walk(term["value"][0])
                for x in term["value"][1:]:
                    walk(x)
            elif t == "call":
                for a in term["value"][1:]:
                    walk(a)
            elif t in ("array", "set"):
                for x in term["value"]:
                    walk(x)
            elif t == "object":
                for k, val in term["value"]:
                    walk(k)
                    walk(val)
        for term in terms:
            if isinstance(term, dict):
                walk(term)
        return out

    # ---- where a missing value is noticed (guard hints)
    def _norm(self, term, env, depth=0):
        """a reference as an input-rooted path where the body shows it: row.name -> input.rows[].name"""
        t = term.get("type")
        if depth > 6:
            return "?"
        if t == "var":
            o = env.get(term["value"])
            if o is None and self._cur and self._cur.alias(term["value"]) is not None and depth < 6:
                return self._norm(self._cur.alias(term["value"]), {}, depth + 1)
            if o and o[0] in ("iter", "const") and o[1] is not None:
                return self._norm(o[1], env, depth + 1) + "[]"
            if o and o[0] == "assign" and o[1] is not None and o[1].get("type") in ("ref", "call"):
                return self._norm(o[1], env, depth + 1)
            return "<arg>" if o and o[0] == "param" else term["value"]
        if t == "call":
            a = term["value"][1:]
            if _opname(term["value"][0]) == "object.get" and len(a) == 3:
                k = a[1]
                if k.get("type") == "string":
                    return self._norm(a[0], env, depth + 1) + "." + k["value"]
                if k.get("type") == "array" and all(x.get("type") == "string" for x in k["value"]):
                    return self._norm(a[0], env, depth + 1) + "".join("." + x["value"] for x in k["value"])
                return self._norm(a[0], env, depth + 1) + "[]"
            return "(" + _text(term) + ")"
        if t != "ref":
            return "?"
        head = term["value"][0]
        if head.get("type") == "var" and head["value"] in env:
            base = self._norm(head, env, depth + 1)
        else:
            al = self._cur.alias(head["value"]) if head.get("type") == "var" and self._cur else None
            base = self._norm(al, {}, depth + 1) if al is not None else str(head.get("value"))
        return base + "".join("." + x["value"] if x.get("type") == "string" else "[]" for x in term["value"][1:])

    def _probe(self, e, op, args, env, ctx):
        """record the paths this line reads in a way that is defined when the path is missing"""
        where = f"{ctx['f']}:{_row(e)}"
        probed = ctx["p"].probed
        if not e.get("negated"):                       # a type or value check earlier in the rule: the author
            if op and op.startswith("is_") and args and args[0].get("type") == "ref":   # chose to need this fact
                ctx["typed"].add(self._norm(args[0], env))
            elif op is None and args and args[0].get("type") == "ref":   # a bare `x.y` line: "if it is there ..."
                ctx["present"].add(self._norm(args[0], env))
            elif op and (op.split(".")[-1].lstrip("_") in ("has_key", "has_field") or op.split(".")[-1].lstrip("_").startswith("has_")) and len(args) == 2:
                # f(obj, "key") / f(obj, k): the key is tested for before it is read
                ctx["present"].add(self._norm(args[0], env) + ("." + args[1]["value"] if args[1].get("type") == "string" else "[]"))
            elif op in MEMBER and len(args) == 2 and args[1].get("type") == "call" \
                    and _opname(args[1]["value"][0]) == "object.keys" and len(args[1]["value"]) == 2:
                ctx["present"].add(self._norm(args[1]["value"][1], env) + ("." + args[0]["value"] if args[0].get("type") == "string" else "[]"))
            elif op == "equal" and len(args) == 2:
                for a, b in (args, args[::-1]):
                    if a.get("type") == "ref" and b.get("type") in SCALARS:
                        ctx["typed"].add(self._norm(a, env))
        pn = ctx["p"].probed_neg
        if e.get("negated"):
            if op is None and args and args[0].get("type") == "ref":
                probed.setdefault(self._norm(args[0], env), []).append(where)
                pn.setdefault(self._norm(args[0], env), []).append(where)
            elif op == "equal":
                for a in args:
                    if a.get("type") == "ref":
                        probed.setdefault(self._norm(a, env), []).append(where)
                        pn.setdefault(self._norm(a, env), []).append(where)

        def walk(term):
            t = term.get("type")
            if t == "call":
                if _opname(term["value"][0]) == "object.get" and len(term["value"]) == 4:
                    probed.setdefault(self._norm(term, env), []).append(where)
                    if e.get("negated"):
                        pn.setdefault(self._norm(term, env), []).append(where)
                for a in term["value"][1:]:
                    walk(a)
            elif t in ("array", "set"):
                for x in term["value"]:
                    walk(x)
            elif t == "object":
                for k, v in term["value"]:
                    walk(v)
        for a in args:
            if isinstance(a, dict):
                walk(a)

    # ---- bodies
    def _effect(self, ctx):
        cls = classify_name(ctx["coll"]) if ctx["coll"] is not None else ctx["cls"]
        if ctx["coll"] is not None and cls == "other":
            cls = ctx["p"].cls.get(ctx["coll"], "other")
        return {"violation": "fail-open", "pass": "fail-closed"}.get(cls, "review")

    def _hit(self, kind, expr, refs, ctx, effect=None, note="", paths=None):
        self.hits.append(Hit(file=ctx["f"], line=_row(expr), rule=ctx["rule"], kind=kind,
                             text=_text(expr)[:240], refs=sorted({_text(r) or "?" for r in refs}),
                             effect=effect or self._effect(ctx), where=ctx["coll"] or ctx["rule"], note=note,
                             paths=paths or sorted({self._norm(r, ctx["env"]) for r in refs}), guard="", pkg=ctx["pkg"],
                             present=bool(refs) and all(self._norm(r, ctx["env"]) in ctx["present"]
                                        for r in refs),
                             used=bool(refs) and all(self._used(self._norm(r, ctx["env"]), ctx["used"]) for r in refs),
                             typed=bool(refs) and all(self._norm(r, ctx["env"]) in ctx["typed"] for r in refs)))

    def _body(self, body, env, ctx):
        env = dict(env)
        for e in body:
            self._bind(e, env, ctx)
        for e in body:
            self._expr(e, env, ctx)

    def _comprehensions(self, term, env, ctx):
        """scan the bodies of the comprehensions inside a term"""
        if not isinstance(term, dict):
            return
        t = term.get("type")
        if t in COMPREHENSIONS:
            self._body(term["value"].get("body") or [], env, ctx)
            return
        if t in ("call", "array", "set", "ref"):
            for x in term["value"]:
                self._comprehensions(x, env, ctx)
        elif t == "object":
            for k, v in term["value"]:
                key = k.get("value") if k.get("type") == "string" else None
                self._comprehensions(k, env, ctx)
                self._comprehensions(v, env, dict(ctx, coll=key) if key else ctx)

    def _expr(self, e, env, ctx):
        t = e.get("terms")
        neg = bool(e.get("negated"))
        if isinstance(t, dict) and "domain" in t:                    # every
            inner = dict(env)
            for part in ("key", "value"):
                if t.get(part):
                    for v in self._vars(t[part]):
                        inner[v] = ("const" if self._const(t["domain"], env, ctx["p"]) else "iter", t["domain"])
            if neg and self._undefined_refs([t["domain"]], env, ctx):
                self._hit("neg-call", e, self._undefined_refs([t["domain"]], env, ctx), ctx)
            self._body(t.get("body") or [], inner, ctx)
            return
        if isinstance(t, dict) and "symbols" in t:
            for s in t["symbols"]:
                self._comprehensions(s, env, ctx)
            return
        terms = t if isinstance(t, list) else [t]
        op = _opname(terms[0]) if isinstance(t, list) else None
        args = terms[1:] if isinstance(t, list) else terms
        # comprehensions nested anywhere in the line; an assignment names the collection
        coll = ctx["coll"]
        if op in ("assign", "eq") and len(args) == 2 and args[0].get("type") == "var":
            coll = args[0]["value"]
        elif op in ("equal", "lt", "lte") and len(args) == 2 and self._zero_count_of_comprehension(op, args):
            coll = "violations"       # count([x | ...]) == 0: the comprehension collects offenders
        for a in args:
            self._comprehensions(a, env, dict(ctx, coll=coll) if coll != ctx["coll"] else ctx)

        ctx = dict(ctx, env=env)
        self._probe(e, op, args, env, ctx)
        if neg:
            self._negated(e, op, args, env, ctx)
        else:
            self._positive(e, op, args, env, ctx)
            if op not in ("assign", "eq"):
                self._mark_used(args, env, ctx)

    @staticmethod
    def _used(path, used):
        """read by an earlier positive line: the same field of an iterated row, or a parent of a field it read"""
        if "[]" in path and path in used:
            return True
        return any(u.startswith(path + ".") or u.startswith(path + "[") for u in used)

    def _mark_used(self, args, env, ctx):
        """a fact a positive line reads stops the body when it is missing: a later negation of it adds no new drop"""
        def walk(t):
            if not isinstance(t, dict):
                return
            ty = t.get("type")
            if ty == "ref":
                ctx["used"].add(self._norm(t, env))
                for x in t["value"][1:]:
                    walk(x)
            elif ty in ("call", "array", "set"):
                for x in (t["value"][1:] if ty == "call" else t["value"]):
                    walk(x)
            elif ty == "object":
                for k, v in t["value"]:
                    walk(k)
                    walk(v)
        for a in args:
            walk(a)

    @staticmethod
    def _zero_count_of_comprehension(op, args):
        a, b = args
        if a.get("type") != "call" or _opname(a["value"][0]) != "count" or len(a["value"]) != 2:
            return False
        if a["value"][1].get("type") not in COMPREHENSIONS or b.get("type") != "number":
            return False
        return (op == "equal" and b["value"] == 0) or (op == "lt" and b["value"] == 1) or (op == "lte" and b["value"] == 0)

    def _negated(self, e, op, args, env, ctx):
        if op is None:                                               # not x.y / not v
            return
        plain = lambda a: a.get("type") in ("ref", "var") or a.get("type") in SCALARS or _literal_only(a)
        if op == "equal" and all(plain(a) for a in args):
            self._get_default(e, op, args, env, ctx, negated=True)
            return                                                   # not x.y == v is true on a missing x.y
        refs = self._undefined_refs(args, env, ctx)
        if refs:
            kind = "neg-in" if op in MEMBER else "neg-cmp" if op in CMP_OPS or op == "equal" else "neg-call"
            self._hit(kind, e, refs, ctx)
            return
        via = self._assigned_from_undefined(args, env, ctx)
        if via:
            self._hit("neg-var", e, [o for _, o in via], ctx,
                      note="; ".join(f"{v['value']} := {_text(o)[:80]}" for v, o in via))
            return
        part = self._partial_calls(args, ctx)
        if part:
            self._hit("neg-partial-fn", e, part, ctx)
            return
        self._get_default(e, op, args, env, ctx, negated=True)

    def _positive(self, e, op, args, env, ctx):
        if op is None:
            self._get_default(e, op, args, env, ctx, negated=False)
            return
        if op in ("assign", "eq"):
            # to_number(x.y) on the right-hand side
            tn = self._to_number(args, env, ctx)
            if tn:
                self._hit("to-number", e, tn, ctx)
            return
        if op in CMP_OPS:
            direct = [a for a in args if a.get("type") == "ref" and self._maybe_undefined(a, env, ctx)]
            # x.y != null says "x.y is present": a presence test, not a value test
            if direct and not (op == "neq" and any(a.get("type") == "null" for a in args)):
                self._hit("cmp", e, direct, ctx)
                return
        if op in ("equal", "lt", "lte") and len(args) == 2:
            a, b = args
            if a.get("type") == "call" and _opname(a["value"][0]) == "count" and b.get("type") == "number":
                zero = (op == "equal" and b["value"] == 0) or (op == "lt" and b["value"] == 1) or (op == "lte" and b["value"] == 0)
                inner = a["value"][1]
                if zero and inner.get("type") == "ref" and self._maybe_undefined(inner, env, ctx):
                    self._hit("count-zero", e, [inner], ctx)
                    return
        tn = self._to_number(args, env, ctx)
        if tn:
            self._hit("to-number", e, tn, ctx)
            return
        self._get_default(e, op, args, env, ctx, negated=False)

    def _to_number(self, terms, env, ctx):
        found = []

        def walk(term):
            t = term.get("type")
            if t == "call":
                a = term["value"][1:]
                if _opname(term["value"][0]) == "to_number" and len(a) == 1 and a[0].get("type") == "ref" \
                        and self._maybe_undefined(a[0], env, ctx):
                    found.append(a[0])
                for x in a:
                    walk(x)
            elif t in ("array", "set"):
                for x in term["value"]:
                    walk(x)
        for term in terms:
            if isinstance(term, dict):
                walk(term)
        return found

    # ---- object.get with a passing default
    def _default_of(self, term, env):
        """(default value, wrapped in count?) when the term is object.get(_, _, <literal>), count(object.get(...))
        or a variable assigned one of those; None otherwise"""
        if term.get("type") == "var":
            o = env.get(term["value"])
            if o and o[0] in ("assign", "const") and o[1] is not None and o[1].get("type") == "call":
                return self._default_of(o[1], {})
            return None
        if term.get("type") != "call":
            return None
        op = _opname(term["value"][0])
        a = term["value"][1:]
        if op == "object.get" and len(a) == 3 and _literal_only(a[2]):
            try:
                return (_pyval(a[2]),)
            except ValueError:
                return None
        if op == "count" and len(a) == 1:
            inner = self._default_of(a[0], env)
            if inner is not None and isinstance(inner[0], (tuple, frozenset, str)):
                return (len(inner[0]),)
        return None

    @staticmethod
    def _holds(op, left, right):
        """does `left <op> right` hold in Rego for two literal values (None when it cannot be told)"""
        try:
            if op == "equal":
                return left == right and type(left) is type(right)
            if op == "neq":
                return not (left == right and type(left) is type(right))
            if isinstance(left, bool) or isinstance(right, bool) or left is None or right is None:
                return None
            if isinstance(left, (int, float)) and isinstance(right, (int, float)) or isinstance(left, str) and isinstance(right, str):
                return {"lt": left < right, "lte": left <= right, "gt": left > right, "gte": left >= right}[op]
        except TypeError:
            pass
        return None

    def _get_default(self, e, op, args, env, ctx, negated):
        cls = {"fail-open": "violation", "fail-closed": "pass"}.get(self._effect(ctx))
        if cls is None:
            return
        holds = None
        if op is None:                                               # bare object.get(...) / v
            d = self._default_of(args[0], env) if args[0].get("type") in ("call", "var") else None
            if d is None or args[0].get("type") == "var" and env.get(args[0]["value"], ("",))[0] == "const":
                return
            holds = d[0] is not False                                # anything but false is truthy as a body line
            if d[0] is None:
                holds = True
        elif op in ("equal", "neq", "lt", "lte", "gt", "gte") and len(args) == 2:
            for i in (0, 1):
                d = self._default_of(args[i], env)
                other = args[1 - i]
                if d is None or not _literal_only(other):
                    continue
                try:
                    o = _pyval(other)
                except ValueError:
                    continue
                if op == "neq" and type(o) is type(d[0]) and o == d[0]:
                    return          # v != <the default>: a presence test ("is it there?"), the opposite case is another rule's
                holds = self._holds(op, d[0], o) if i == 0 else self._holds(op, o, d[0])
                break
        if holds is None:
            return
        if negated:
            holds = not holds
        # violation body: the line is false with the default -> no finding; pass body: true with the default -> pass
        if (cls == "violation" and not holds) or (cls == "pass" and holds):
            src = args[0] if op is None else next((a for a in args if self._default_of(a, env) is not None), None)
            if src is not None and src.get("type") == "var" and env.get(src["value"], ("",))[0] == "assign":
                src = env[src["value"]][1]
            tgt = []
            if src is not None and src.get("type") == "call" and _opname(src["value"][0]) == "count":
                src = src["value"][1]
            if src is not None and src.get("type") == "call":
                tgt = [self._norm(src, env)]
            self._hit("get-default", e, [], ctx, effect="fail-open", paths=tgt,
                      note="the default passes" + (" (pass rule)" if cls == "pass" else ""))


def scan(root=ROOT, paths=None):
    rels = list(policy_files(root, paths))
    hits = Scanner(parse_tree(root, rels)).run()
    hits.sort(key=lambda h: (h["file"], h["line"], h["kind"]))
    return hits


# ---------------------------------------------------------------------------------------------- baseline
def tree_of(rel):
    return rel.split("/", 1)[0] if "/" in rel else "_root"


def read_baseline(path):
    """(Counter of entry keys, {key: reason}, [problems])"""
    entries, reasons, problems = collections.Counter(), {}, []
    reason = None
    if not path.exists():
        return entries, reasons, problems
    for n, line in enumerate(path.read_text().splitlines(), 1):
        if line.startswith("# reason:"):
            reason = line[len("# reason:"):].strip()
            continue
        if not line.strip() or line.startswith("#"):
            continue
        if not reason or reason.upper().startswith("TODO"):
            problems.append(f"{path.relative_to(ROOT) if path.is_relative_to(ROOT) else path}:{n}: entry without a reason "
                            f"(write a `# reason: ...` line above it): {line[:120]}")
        entries[line] += 1
        reasons.setdefault(line, reason or "TODO")
    return entries, reasons, problems


HEADER = """# Undefined-negation baseline for {tree}/ (scripts/check_undefined_negation.py).
# Hits that were read and left as they are. Every entry needs a reason: a `# reason:` line applies to the entries
# below it until the next one. Entry = file<TAB>rule<TAB>kind<TAB>expression. Fix a hit rather than adding it here;
# the check fails on an entry that no longer matches (delete it) and on an entry with no reason.
"""


def write_baseline(path, tree, gated, old_reasons):
    by_reason = collections.defaultdict(list)
    for h in gated:
        by_reason[old_reasons.get(h.key, "TODO")].append(h.key)
    out = [HEADER.format(tree=tree)]
    for reason in sorted(by_reason, key=lambda r: (r.upper().startswith("TODO"), r)):
        out.append(f"# reason: {reason}")
        out.extend(sorted(by_reason[reason]))
        out.append("")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(out))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--check", action="store_true", help="exit 1 on a new gated hit, a stale entry or an entry with no reason")
    ap.add_argument("--write-baseline", action="store_true", help="rewrite the baseline of each tree scanned")
    ap.add_argument("--paths", nargs="+", metavar="DIR", help="directories (or files) to scan, relative to the repo root")
    ap.add_argument("--json", metavar="FILE", help="write every hit (all effects) as JSON")
    ap.add_argument("--list", action="store_true", help="print the gated hits that are not in the baseline")
    ap.add_argument("--root", default=str(ROOT), help=argparse.SUPPRESS)
    ap.add_argument("--baseline-dir", default=None, help=argparse.SUPPRESS)
    a = ap.parse_args(argv)
    root = pathlib.Path(a.root).resolve()
    bdir = pathlib.Path(a.baseline_dir) if a.baseline_dir else (BASELINE_DIR if root == ROOT else root / "scripts" / "undefined_negation_baseline")

    hits = scan(root, a.paths)
    if a.json:
        pathlib.Path(a.json).write_text(json.dumps(hits, indent=1))
    by_tree = collections.defaultdict(list)
    for h in hits:
        by_tree[tree_of(h["file"])].append(h)
    whole_tree = lambda t: not a.paths or any(pathlib.PurePosixPath(p).as_posix().rstrip("/") == t for p in a.paths)

    rc = 0
    effects = collections.Counter(h["effect"] for h in hits)
    print(f"undefined negation: {len(hits)} hits ({effects['fail-open']} fail-open, {effects['review']} to review, "
          f"{effects['fail-closed']} fail-closed and harmless, {effects['guarded']} guarded by a type check and an evidence rule)")
    for tree in sorted(by_tree):
        gated = [h for h in by_tree[tree] if is_gated(h)]
        path = bdir / f"{tree}.txt"
        base, reasons, problems = read_baseline(path)
        if a.write_baseline:
            if not whole_tree(tree):
                print(f"  {tree}: not rewritten (--paths names part of the tree; pass the whole tree)")
                continue
            write_baseline(path, tree, gated, reasons)
            todo = sum(1 for h in gated if reasons.get(h.key, "TODO").upper().startswith("TODO"))
            print(f"  {tree}: wrote {len(gated)} entries to {path.name}" + (f", {todo} need a reason" if todo else ""))
            continue
        if not path.exists():
            print(f"  {tree}: {len(gated)} gated hits, no baseline file ({path.name}): not gated yet")
            continue
        cur = collections.Counter(h.key for h in gated)
        new = cur - base
        stale = (base - cur) if whole_tree(tree) else collections.Counter()
        print(f"  {tree}: {len(gated)} gated hits, {sum(new.values())} new, {sum(stale.values())} stale baseline entries, "
              f"{len(problems)} without a reason")
        if a.check or a.list:
            shown = set()
            for h in gated:
                if h.key in new and h.key not in shown:
                    shown.add(h.key)
                    print(f"    NEW {h['effect']} {h['kind']} {h['file']}:{h['line']} [{h['rule']}] {h['text']}")
            for k in sorted(stale):
                print(f"    STALE baseline entry (delete it): {k}")
            for pr in problems:
                print(f"    {pr}")
        if new or stale or problems:
            rc = 1
    if a.list and not a.check:
        return 0
    if rc and a.check:
        print("  a missing field must produce an evidence finding, not drop the row: see the docstring of this script")
    return rc if a.check else 0


if __name__ == "__main__":
    sys.exit(main())
