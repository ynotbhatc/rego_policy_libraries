#!/usr/bin/env python3
"""Every `input` path a set of Rego files reads, from OPA's own parser (`opa parse --format json`).

Used by scripts/check_bad_input_fails.py to build input documents for entrypoints that have no all-pass test
fixture: the module's own source says which facts it reads, so each of them can be sent with a bad value.

A path is a tuple of elements: a name ("mfa"), or ANY ("[]") for an element the rule iterates or supplies
(`input.items[_]`, `some x in input.items`, `input.users[name]`). What the scan follows:

  direct references          input.a.b.c, input["a"].b, object.get(input.a, "b", d), object.get(input, ["a", "b"], d)
  local aliases              x := input.a ; x.b            some x in input.items ; x.b        every x in ... { x.b }
                             comprehensions inherit the bindings of the body they sit in
  rule aliases               cfg := input.config  (or object.get(input, "config", {}), or a partial set of
                             input members) read elsewhere as cfg.x, data.<pkg>.cfg.x or through an import alias
  function parameters        f(o) if o.flag ; f(input.a)   -> a.flag        (any depth of helper calling helper)
  key parameters             fact(p) := object.get(input, p, null) ; fact(["a", "b"])   -> a.b
  functions returning input  section(n) := object.get(input, n, {}) ; section("iam").mfa   -> iam.mfa
  constant tables            some id, c in CHECKS ; object.get(input, c.path, null), input.controls[id]: a key
                             that comes from a literal table in the same library is expanded to each literal

What it does not follow: paths assembled at evaluation time (split("a.b", "."), concat, sprintf), keys taken
from input itself, and values passed through `with`. Those references are read as ANY or not at all; a module
that reads its facts that way needs a test fixture for the per-fact cases.

    python3 scripts/input_refs.py frameworks/management/hitrust      # print the paths one directory reads
"""
from __future__ import annotations
import json, os, pathlib, subprocess, sys

ANY = "[]"
ROUNDS = 8          # alias / helper chains longer than this are not followed
SITE_CAP = 4000     # paths one reference may expand to (constant tables)
COMPREHENSIONS = ("arraycomprehension", "setcomprehension", "objectcomprehension")


# One evaluation parses many files: rego.parse_module returns the AST `opa parse --format json` prints.
PARSE_QUERY = "x := {f: rego.parse_module(f, s) | some f, s in input}"


def parse_sources(sources):
    """{name: AST} for {name: source text}, in one `opa eval`."""
    out = subprocess.run([os.environ.get("OPA", "opa"), "eval", "-I", "-f", "json", PARSE_QUERY],
                         input=json.dumps(sources), capture_output=True, text=True)
    if out.returncode != 0:
        raise RuntimeError(f"opa eval rego.parse_module failed: {out.stderr.strip()[:300]}")
    return json.loads(out.stdout)["result"][0]["bindings"]["x"]


def _pkg(ast):
    return tuple(t["value"] for t in ast["package"]["path"][1:])


def _rule_name(rule):
    """The first element of a rule head's ref: `a.b.c := 1` is rule a."""
    h = rule["head"]
    ref = h.get("ref") or []
    if ref and isinstance(ref[0].get("value"), str):
        return ref[0]["value"]
    return h.get("name")


def _literal(term):
    """The Python value of a literal term, or raise ValueError when the term is not a literal."""
    t, v = term.get("type"), term.get("value")
    if t in ("string", "boolean", "null"):
        return v
    if t == "number":
        return float(v) if isinstance(v, str) and ("." in v or "e" in v.lower()) else int(v)
    if t in ("array", "set"):
        return [_literal(x) for x in v]
    if t == "object":
        out = {}
        for k, x in v:
            kk = _literal(k)
            if not isinstance(kk, (str, int, float)):
                raise ValueError
            out[str(kk)] = _literal(x)
        return out
    raise ValueError


def _is_sym(e):
    return isinstance(e, tuple)


def _symbolic(path):
    return any(_is_sym(e) for e in path)


class Scan:
    """Scan a set of parsed files. `paths[file]` holds the concrete input paths each file reads."""

    def __init__(self, asts):
        self.asts = asts
        self.pkg = {f: _pkg(a) for f, a in asts.items()}
        self.packages = set(self.pkg.values())
        self.imports = {}       # file -> {alias: data path tuple}
        self.func_names = set()  # (pkg, name) of rules with arguments
        self.consts = {}        # (pkg, name) -> literal value
        self.alias = {}         # (pkg, name) -> set of input paths the rule's value is
        self.templ = {}         # (pkg, fname) -> set of paths (symbolic) the function reads
        self.fret = {}          # (pkg, fname) -> set of paths (symbolic) the function returns
        self.paths = {f: set() for f in asts}
        self.deps = {f: set() for f in asts}   # file -> packages it references
        self.uses = {f: {} for f in asts}      # file -> {(table, (pkg, name)): smallest size a lookup saw}
        self._f = None
        for f, a in asts.items():
            imp = {}
            for i in a.get("imports") or []:
                p = i["path"]["value"]
                if p and p[0].get("value") == "data":
                    elems = tuple(x["value"] for x in p[1:] if isinstance(x.get("value"), str))
                    if elems:
                        imp[i.get("alias") or elems[-1]] = elems
                elif p and p[0].get("value") == "input":
                    elems = tuple(x["value"] for x in p[1:] if isinstance(x.get("value"), str))
                    imp[i.get("alias") or (elems[-1] if elems else "input")] = ("$input",) + elems
            self.imports[f] = imp
            for r in a.get("rules") or []:
                n = _rule_name(r)
                if n is None:
                    continue
                h = r["head"]
                if h.get("args"):
                    self.func_names.add((self.pkg[f], n))
                elif "value" in h and "key" not in h and len(h.get("ref") or []) <= 1:
                    try:
                        val = _literal(h["value"])
                    except (ValueError, KeyError, TypeError):
                        continue
                    if isinstance(val, (dict, list)) and not r.get("default"):
                        self.consts.setdefault((self.pkg[f], n), val)

    # ------------------------------------------------------------ driver
    def run(self):
        """Scan to a fixed point. A file is redone only when a rule or helper it looked up has grown since."""
        todo = list(self.asts)
        for _ in range(ROUNDS):
            for f in todo:
                self._f = f
                self.uses[f] = {}
                rules = []
                for r in self.asts[f].get("rules") or []:
                    while r is not None:
                        rules.append(r)
                        r = r.get("else")
                # helpers first: most files define them above or below their callers, never far away
                for r in sorted(rules, key=lambda r: not r["head"].get("args")):
                    self._rule(f, r)
            todo = [f for f in self.asts if any(len(tb.get(k, ())) != n for (tb, k), n in self._stale(f))]
            if not todo:
                break
        return self

    def _stale(self, f):
        tables = {"alias": self.alias, "templ": self.templ, "fret": self.fret}
        return (((tables[name], key), n) for (name, key), n in self.uses[f].items())

    def _get(self, name, key):
        table = {"alias": self.alias, "templ": self.templ, "fret": self.fret}[name]
        got = table.get(key, set())
        self.uses[self._f].setdefault((name, key), len(got))   # the smallest size any lookup in this pass saw
        return got

    # ------------------------------------------------------------ one rule
    def _rule(self, f, rule):
        h = rule["head"]
        pkg = self.pkg[f]
        name = _rule_name(rule)
        ctx = {"f": f, "pkg": pkg, "fn": None, "env": {}, "kenv": {}, "cenv": {}}
        args = h.get("args") or []
        if args:
            ctx["fn"] = (pkg, name)
            for i, a in enumerate(args):
                if a.get("type") == "var":
                    ctx["env"][a["value"]] = {(("$p", i),)}
                    ctx["kenv"][a["value"]] = i
        body = rule.get("body") or []
        self._body(body, ctx)
        for part in ("key", "value"):
            if part in h:
                self._visit(h[part], ctx)
        for t in (h.get("ref") or [])[1:]:
            self._visit(t, ctx)
        if name is None or rule.get("default"):
            return
        # what the rule's value is: an alias of an input path (rule) or a path built from parameters (function)
        val = set()
        if "value" in h and "key" not in h:
            val = self._resolve(h["value"], ctx)
        elif "key" in h and "value" not in h:     # partial set: `items contains x if ...`
            val = {p + (ANY,) for p in self._resolve(h["key"], ctx)}
        elif "key" in h and "value" in h:         # partial object: name[k] := v
            val = {p + (ANY,) for p in self._resolve(h["value"], ctx)}
        if not val:
            return
        if args:
            self.fret.setdefault((pkg, name), set()).update(val)
        else:
            self.alias.setdefault((pkg, name), set()).update(p for p in val if not _symbolic(p))

    def _body(self, body, ctx):
        for _ in range(2):       # bindings may be used before the line that makes them
            for e in body:
                self._bind(e, ctx)
        for e in body:
            self._expr(e, ctx)

    def _child(self, ctx):
        c = dict(ctx)
        c["env"], c["kenv"], c["cenv"] = dict(ctx["env"]), dict(ctx["kenv"]), dict(ctx["cenv"])
        return c

    # ------------------------------------------------------------ bindings
    def _set(self, var, paths, ctx, const=None):
        if var.get("type") != "var" or var["value"].startswith("$"):
            return
        n = var["value"]
        if paths:
            ctx["env"].setdefault(n, set()).update(paths)
        if const is not None:
            ctx["cenv"].setdefault(n, [])
            for c in const:
                if c not in ctx["cenv"][n] and len(ctx["cenv"][n]) < SITE_CAP:
                    ctx["cenv"][n].append(c)

    def _member(self, args, ctx):
        """`x in coll` / `k, x in coll`: bind the value to the members and the key to the keys."""
        coll = args[-1]
        members = {p + (ANY,) for p in self._resolve(coll, ctx)}
        cv = self._const(coll, ctx)
        vals = keys = None
        if cv is not None:
            vals, keys = [], []
            for c in cv:
                if isinstance(c, dict):
                    vals += list(c.values())
                    keys += list(c.keys())
                elif isinstance(c, list):
                    vals += c
        self._set(args[-2], members, ctx, vals)
        if len(args) == 3:
            self._set(args[0], set(), ctx, keys)

    def _bind(self, e, ctx):
        t = e.get("terms")
        if isinstance(t, dict) and "symbols" in t:
            for s in t["symbols"]:
                if s.get("type") == "call":
                    op = _opname(s["value"][0])
                    if op in ("internal.member_2", "internal.member_3"):
                        self._member(s["value"][1:], ctx)
            return
        if not isinstance(t, list) or not t:
            return
        op = _opname(t[0])
        if op in ("internal.member_2", "internal.member_3") and not e.get("negated"):
            if t[-2].get("type") == "var":
                self._member(t[1:], ctx)
            return
        if op in ("assign", "eq") and len(t) == 3:
            for a, b in ((t[1], t[2]), (t[2], t[1])):
                if a.get("type") == "var":
                    self._set(a, self._resolve(b, ctx), ctx, self._const(b, ctx))
                    # `x := coll[k]`: k walks the keys of a constant table
                    if b.get("type") == "ref":
                        self._iter_keys(b, ctx)
            return
        # a bare reference that iterates a constant table: CHECKS[id]
        for term in t if isinstance(t, list) else [t]:
            if isinstance(term, dict) and term.get("type") == "ref":
                self._iter_keys(term, ctx)

    def _iter_keys(self, ref, ctx):
        """`TABLE[k]` with k an unbound variable: k is each key of the table."""
        v = ref["value"]
        for i in range(1, len(v)):
            if v[i].get("type") == "var" and not v[i]["value"].startswith("$") and v[i]["value"] not in ctx["kenv"]:
                cv = self._const({"type": "ref", "value": v[:i]}, ctx) if i > 1 or v[0].get("type") == "var" else None
                if cv is None:
                    continue
                keys = []
                for c in cv:
                    if isinstance(c, dict):
                        keys += list(c.keys())
                if keys:
                    self._set(v[i], set(), ctx, keys)

    # ------------------------------------------------------------ constants
    def _const(self, term, ctx):
        """The literal values a term may hold (a list of candidates), or None when it is not a known constant."""
        t = term.get("type")
        if t == "var":
            n = term["value"]
            if n in ctx["cenv"]:
                return ctx["cenv"][n]
            c = self.consts.get((ctx["pkg"], n))
            return None if c is None or n in ctx["env"] else [c]
        if t == "ref":
            v = term["value"]
            head, rest = v[0], v[1:]
            base = None
            if head.get("type") == "var":
                n = head["value"]
                if n in ctx["cenv"]:
                    base = ctx["cenv"][n]
                elif n == "data" or self.imports[ctx["f"]].get(n, ("$input",))[:1] != ("$input",):
                    strs = 0
                    for x in rest:
                        if x.get("type") != "string":
                            break
                        strs += 1
                    lead = (self.imports[ctx["f"]].get(n) or ()) if n != "data" else ()
                    full = lead + tuple(x["value"] for x in rest[:strs])
                    for cut in range(len(full) - 1, 0, -1):
                        c = self.consts.get((full[:cut], full[cut]))
                        if c is not None:
                            base, rest = [c], rest[max(0, cut + 1 - len(lead)):]
                            break
                else:
                    c = self.consts.get((ctx["pkg"], n))
                    if c is not None and n not in ctx["env"]:
                        base = [c]
            if base is None:
                return None
            cur = list(base)
            for x in rest:
                nxt = []
                if x.get("type") == "string" or x.get("type") == "number":
                    k = str(x["value"])
                    for c in cur:
                        if isinstance(c, dict) and k in c:
                            nxt.append(c[k])
                        elif isinstance(c, list) and x.get("type") == "number" and int(k) < len(c):
                            nxt.append(c[int(k)])
                else:
                    ks = self._const(x, ctx) if x.get("type") == "var" and x["value"] in ctx["cenv"] else None
                    for c in cur:
                        if isinstance(c, dict):
                            nxt += [c[k] for k in c if ks is None or k in ks]
                        elif isinstance(c, list):
                            nxt += c
                cur = nxt[:SITE_CAP]
            return cur
        try:
            return [_literal(term)]
        except (ValueError, KeyError, TypeError):
            return None

    def _keys(self, term, ctx):
        """Key tuples an object.get key (or a bracket element) may be: [("a", "b"), ...]; None when unknown."""
        if term.get("type") == "var" and term["value"] in ctx["kenv"] and term["value"] not in ctx["cenv"]:
            return [(("$k", ctx["kenv"][term["value"]]),)]
        if term.get("type") == "array":       # ["a", key_param, "b"]
            outs = [()]
            for x in term["value"]:
                ks = self._keys(x, ctx)
                if ks is None:
                    ks = [(ANY,)]
                outs = [o + k for o in outs for k in ks if len(k) == 1][:SITE_CAP]
            return outs
        cv = self._const(term, ctx)
        if cv is None:
            return None
        out = []
        for c in cv:
            if isinstance(c, (str, int)) and not isinstance(c, bool):
                out.append((str(c),) if isinstance(c, str) else (ANY,))
            elif isinstance(c, list) and c and all(isinstance(x, (str, int)) and not isinstance(x, bool) for x in c):
                out.append(tuple(x if isinstance(x, str) else ANY for x in c))
        return out or None

    # ------------------------------------------------------------ resolution
    def _func(self, opterm, ctx):
        """(pkg, name) of a user function a call names, or None."""
        if opterm.get("type") != "ref":
            return None
        v = opterm["value"]
        if v[0].get("type") != "var":
            return None
        n = v[0]["value"]
        strs = tuple(x["value"] for x in v[1:] if x.get("type") == "string")
        if len(strs) != len(v) - 1:
            return None
        if n == "data" and len(strs) >= 2:
            key = (strs[:-1], strs[-1])
        elif n in self.imports[ctx["f"]] and self.imports[ctx["f"]][n][:1] != ("$input",):
            full = self.imports[ctx["f"]][n] + strs
            key = (full[:-1], full[-1])
        elif not strs:
            key = (ctx["pkg"], n)
        else:
            return None
        return key if key in self.func_names else None

    def _subst(self, templates, args, ctx):
        """Callee paths with the callee's parameters replaced by this call's arguments."""
        out = set()
        cache_p, cache_k = {}, {}
        for tp in templates:
            partial = [()]
            for e in tp:
                if _is_sym(e) and e[0] == "$p":
                    i = e[1]
                    if i not in cache_p:
                        cache_p[i] = self._resolve(args[i], ctx) if i < len(args) else set()
                    partial = [p + a for p in partial for a in cache_p[i]]
                elif _is_sym(e) and e[0] == "$k":
                    i = e[1]
                    if i not in cache_k:
                        cache_k[i] = (self._keys(args[i], ctx) if i < len(args) else None) or [(ANY,)]
                    partial = [p + k for p in partial for k in cache_k[i]]
                else:
                    partial = [p + (e,) for p in partial]
                if len(partial) > SITE_CAP:
                    partial = partial[:SITE_CAP]
                if not partial:
                    break
            out.update(partial)
        return out

    def _resolve(self, term, ctx):
        """The input paths (possibly symbolic) a term's value is; an empty set when it is not an input value."""
        t = term.get("type")
        if t == "var":
            n = term["value"]
            if n == "input":
                return {()}
            if n in ctx["env"]:
                return ctx["env"][n]
            imp = self.imports[ctx["f"]].get(n)
            if imp and imp[:1] == ("$input",):
                return {imp[1:]}
            if n in ctx["cenv"]:
                return set()
            return self._get("alias", (ctx["pkg"], n))
        if t == "call":
            v = term["value"]
            op = _opname(v[0])
            if op == "object.get" and len(v) == 4:
                base = self._resolve(v[1], ctx)
                if not base:
                    return set()
                ks = self._keys(v[2], ctx) or [(ANY,)]
                return {b + k for b in base for k in ks[:SITE_CAP]}
            fn = self._func(v[0], ctx)
            if fn is not None:
                return self._subst(self._get("fret", fn), v[1:], ctx)
            return set()
        if t != "ref":
            return set()
        v = term["value"]
        head, rest = v[0], v[1:]
        base = set()
        if head.get("type") == "var":
            n = head["value"]
            imp = self.imports[ctx["f"]].get(n)
            if n == "input":
                base = {()}
            elif n in ctx["env"]:
                base = ctx["env"][n]
            elif n in ctx["cenv"]:
                return set()
            elif n == "data" or (imp and imp[:1] != ("$input",)):
                lead = imp or ()
                strs = 0
                for x in rest:
                    if x.get("type") != "string":
                        break
                    strs += 1
                full = lead + tuple(x["value"] for x in rest[:strs])
                for cut in range(len(full) - 1, 0, -1):
                    if full[:cut] in self.packages:
                        self.deps[ctx["f"]].add(full[:cut])
                        base = self._get("alias", (full[:cut], full[cut]))
                        rest = rest[max(0, cut + 1 - len(lead)):]
                        break
                else:
                    for cut in range(len(full), 0, -1):
                        if full[:cut] in self.packages:
                            self.deps[ctx["f"]].add(full[:cut])
                            break
                    return set()
            elif imp:
                base = {imp[1:]}
            else:
                base = self._get("alias", (ctx["pkg"], n))
        else:
            base = self._resolve(head, ctx)
        if not base:
            return set()
        tails = [()]
        for x in rest:
            if x.get("type") == "string":
                ks = [(x["value"],)]
            elif x.get("type") == "var":
                ks = [k for k in (self._keys(x, ctx) or []) if len(k) == 1] or [(ANY,)]
            else:
                ks = [(ANY,)]
            tails = [tl + k for tl in tails for k in ks][:SITE_CAP]
        return {b + tl for b in base for tl in tails}

    # ------------------------------------------------------------ collection
    def _record(self, paths, ctx):
        for p in paths:
            if _symbolic(p):
                if ctx["fn"] is not None:
                    self.templ.setdefault(ctx["fn"], set()).add(p)
            elif p:
                self.paths[ctx["f"]].add(p)

    def _expr(self, e, ctx):
        t = e.get("terms")
        if isinstance(t, dict) and "domain" in t:            # every k, v in domain { body }
            self._visit(t["domain"], ctx)
            c = self._child(ctx)
            args = ([t["key"]] if t.get("key") else []) + [t["value"], t["domain"]]
            self._member(args, c)
            self._body(t.get("body") or [], c)
            return
        if isinstance(t, dict) and "symbols" in t:
            for s in t["symbols"]:
                self._visit(s, ctx)
            return
        if isinstance(t, list):
            # an expression is a call: [operator, args...]
            self._visit({"type": "call", "value": t}, ctx)
        elif isinstance(t, dict):
            self._visit(t, ctx)
        for w in e.get("with") or []:
            self._visit(w.get("value") or {}, ctx)

    def _visit(self, term, ctx):
        if not isinstance(term, dict):
            return
        t, v = term.get("type"), term.get("value")
        if t == "ref":
            self._record(self._resolve(term, ctx), ctx)
            if v and v[0].get("type") != "var":
                self._visit(v[0], ctx)
            for x in v[1:]:
                if x.get("type") not in ("string", "var", "number"):
                    self._visit(x, ctx)
        elif t == "var":
            if v == "input":
                return
            self._record(self._resolve(term, ctx), ctx)
        elif t == "call":
            self._record(self._resolve(term, ctx), ctx)
            fn = self._func(v[0], ctx)
            if fn is not None:
                self._record(self._subst(self._get("templ", fn), v[1:], ctx), ctx)
                self.deps[ctx["f"]].add(fn[0])
            for x in v[1:]:
                self._visit(x, ctx)
        elif t in ("array", "set"):
            for x in v:
                self._visit(x, ctx)
        elif t == "object":
            for k, x in v:
                self._visit(k, ctx)
                self._visit(x, ctx)
        elif t in COMPREHENSIONS:
            c = self._child(ctx)
            self._body(v.get("body") or [], c)
            for part in ("term", "key", "value"):
                if part in v:
                    self._visit(v[part], c)


def _opname(term):
    if not isinstance(term, dict) or term.get("type") != "ref":
        return None
    return ".".join(str(x.get("value")) for x in term["value"])


# ---------------------------------------------------------------- closure and documents
def closure(scan, start_files):
    """start_files plus every file of a package they reference, transitively."""
    by_pkg = {}
    for f, p in scan.pkg.items():
        by_pkg.setdefault(p, set()).add(f)
    seen, todo = set(), list(start_files)
    while todo:
        f = todo.pop()
        if f in seen or f not in scan.asts:
            continue
        seen.add(f)
        for p in scan.deps[f]:
            todo += [g for g in by_pkg.get(p, ()) if g not in seen]
    return seen


def maximal(paths):
    """Drop every path that is a proper prefix of another: what is left are the leaves."""
    ps = sorted(set(paths))
    out = []
    for i, p in enumerate(ps):
        nxt = ps[i + 1] if i + 1 < len(ps) else None
        if nxt is not None and nxt[:len(p)] == p and len(nxt) > len(p):
            continue
        out.append(p)
    return out


def document(paths, leaf):
    """One input document holding every path, each leaf set to `leaf`. An ANY element becomes a one-element
    list; where a node has both named children and an ANY child, the ANY child sits under the key "_any"."""
    tree = {}
    for p in paths:
        cur = tree
        for e in p:
            cur = cur.setdefault(e, {})

    def build(node):
        if not node:
            return json.loads(json.dumps(leaf))
        names = {k: build(v) for k, v in sorted(node.items()) if k != ANY}
        if ANY in node:
            if not names:
                return [build(node[ANY])]
            names["_any"] = build(node[ANY])
        return names

    doc = build(tree)
    if isinstance(doc, list):
        return {"_any": doc[0]}
    return doc if isinstance(doc, dict) else {}


def main(argv):
    root = pathlib.Path(argv[0])
    files = [f for f in sorted(root.rglob("*.rego")) if "/tests/" not in f.as_posix() and not f.name.startswith("test_")
             and not f.name.endswith("_test.rego")]
    asts = parse_sources({str(f): f.read_text(errors="ignore") for f in files})
    scan = Scan({f: asts[str(f)] for f in files}).run()
    for p in maximal(set().union(*scan.paths.values())):
        print(".".join(p))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
