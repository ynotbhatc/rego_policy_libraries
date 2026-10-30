#!/usr/bin/env python3
"""Import the SAP Security Baseline Template checks (ABAP) from SAP's own Focused Run CSA policies.

Source: https://github.com/SAP-samples/frun-csa-policies-best-practices (Apache-2.0),
        BaselinePolicies/SOS/v2.6/ABAP_ALL — one XML policy per Baseline requirement and priority.
        Each <checkitem> carries SAP's check id, the requirement text and the compliant condition
        in the CSA expression language (SQL-like, over a configuration store).

What this writes (all generated, never edited by hand):

    benchmarks/sap/abap/data/sap_baseline_v2_6_index.json    the registry: every check SAP publishes, with
                                                              whether this library assesses it from host facts
    benchmarks/sap/abap/sap_abap_baseline_registry.rego      the same registry as a Rego data module (the OPA
                                                              loader publishes *.rego only, so JSON is not enough)
    benchmarks/sap/abap/sap_abap_baseline_checks.rego        one violation rule per assessable NAME/VALUE check,
                                                              translated from the CSA condition

Translation scope (v1 — what a collector can read on the host without RFC or DB access):
    Parameters / ABAP_INSTANCE_PAHI  -> input.sap.abap.profile_parameters[name]
    TRANSPORT_TOOL                   -> input.sap.abap.transport_parameters[name]
    SAP_KERNEL                       -> input.sap.abap.kernel[name]        (KERN_REL, KERN_PATCHLEVEL, KERN_COMP_TIME)
    CRYPTOLIB                        -> input.sap.abap.cryptolib[name]     (CCL)
Every other store (user tables, authorizations, audit slots, RFC destinations, clients ...) is listed in the
registry as not assessable with the store named, so a projection never silently omits it.

Hand-written rules live in sap_abap_baseline_manual.rego; a `# MANUAL-CHECK: <id>` comment there claims the id,
and this importer marks it `basis: hand_written` instead of generating (or giving up on) it.

Usage:
    python3 -I scripts/import_sap_baseline.py --source <clone>/BaselinePolicies/SOS/v2.6/ABAP_ALL \
        --commit <sha> --out benchmarks/sap/abap
    python3 -I scripts/import_sap_baseline.py ... --check     # regenerate to a temp dir and diff (CI)
"""
from __future__ import annotations

import argparse
import datetime as _dt
import difflib
import json
import pathlib
import re
import sys
import xml.etree.ElementTree as ET

VERSION = "2.6.0"
NAME_VALUE_STORES = {
    "Parameters": ("profile_parameters", "profile_parameter"),
    "ABAP_INSTANCE_PAHI": ("profile_parameters", "profile_parameter"),
    "TRANSPORT_TOOL": ("transport_parameters", "transport_parameter"),
    "SAP_KERNEL": ("kernel", "kernel"),
    "CRYPTOLIB": ("cryptolib", "cryptolib"),
}
# Stores a host collector can read as files but whose checks are line/record shaped: hand-written only.
FILE_STORES = {"GW_SECINFO", "GW_REGINFO", "GW_PRXINFO", "MS_SECINFO"}
PRIORITY = {"p1": ("critical", "critical"), "p2": ("standard", "high"), "p3": ("extended", "medium")}
REQ_RE = re.compile(r"SAP Security Baseline requirement:\s+([A-Z]+-[A-Z])\s*:\s*(.+)")
PRIO_RE = re.compile(r"^\[(p[123])-(CRITICAL|STANDARD|EXTENDED)\]\s*(.*)$", re.S)


# ----------------------------------------------------------------------------------------------------------
# CSA expression language: tokenizer + recursive-descent parser -> AST
# ----------------------------------------------------------------------------------------------------------
TOKEN_RE = re.compile(
    r"""\s*(?:
        (?P<str>'(?:[^']|'')*')            |
        (?P<num>\d+(?:\.\d+)?)             |
        (?P<op>!=|<=|>=|=|<|>)             |
        (?P<lp>\()|(?P<rp>\))|(?P<comma>,) |
        (?P<word>[A-Za-z_][A-Za-z0-9_\-]*)
    )""",
    re.X,
)
KEYWORDS = {"and", "or", "not", "like", "like_regexpr", "in", "between", "escape"}


class ParseError(Exception):
    pass


def tokenize(src: str):
    pos, out = 0, []
    src = src.strip()
    while pos < len(src):
        m = TOKEN_RE.match(src, pos)
        if not m or m.end() == pos:
            raise ParseError(f"cannot tokenize at {src[pos:pos+30]!r}")
        pos = m.end()
        kind = m.lastgroup
        text = m.group(kind)
        if kind == "str":
            out.append(("str", text[1:-1].replace("''", "'")))
        elif kind == "num":
            out.append(("num", text))
        elif kind == "word":
            out.append(("kw", text.lower()) if text.lower() in KEYWORDS else ("word", text))
        else:
            out.append((kind, text))
    return out


class Parser:
    def __init__(self, src: str):
        self.toks = tokenize(src)
        self.i = 0

    def peek(self, k=0):
        return self.toks[self.i + k] if self.i + k < len(self.toks) else (None, None)

    def take(self, kind=None, text=None):
        t = self.peek()
        if kind and t[0] != kind or text and t[1] != text:
            raise ParseError(f"expected {kind or ''} {text or ''} got {t}")
        self.i += 1
        return t

    def parse(self):
        e = self.expr()
        if self.peek()[0] is not None:
            raise ParseError(f"trailing tokens {self.toks[self.i:]}")
        return e

    def expr(self):
        left = self.and_expr()
        while self.peek() == ("kw", "or"):
            self.take()
            left = ("or", left, self.and_expr())
        return left

    def and_expr(self):
        left = self.not_expr()
        while self.peek() == ("kw", "and"):
            self.take()
            left = ("and", left, self.not_expr())
        return left

    def not_expr(self):
        if self.peek() == ("kw", "not"):
            self.take()
            return ("not", self.not_expr())
        return self.primary()

    def primary(self):
        if self.peek()[0] == "lp":
            self.take()
            e = self.expr()
            self.take("rp")
            return e
        return self.comparison()

    def term(self):
        k, t = self.peek()
        if k == "str":
            self.take()
            return ("str", t)
        if k == "num":
            self.take()
            return ("num", t)
        if k == "word":
            self.take()
            if self.peek()[0] == "lp":  # function call
                self.take()
                args = []
                if self.peek()[0] != "rp":
                    args.append(self.term())
                    while self.peek()[0] == "comma":
                        self.take()
                        args.append(self.term())
                self.take("rp")
                return ("func", t.lower(), args)
            return ("col", t.upper())
        raise ParseError(f"unexpected token {self.peek()}")

    def comparison(self):
        lhs = self.term()
        neg = False
        if self.peek() == ("kw", "not"):
            self.take()
            neg = True
        k, t = self.peek()
        if k == "kw" and t in ("like", "like_regexpr"):
            self.take()
            pat = self.take("str")[1]
            esc = None
            if self.peek() == ("kw", "escape"):
                self.take()
                esc = self.take("str")[1]
            node = (t, lhs, pat, esc)
        elif k == "kw" and t == "in":
            self.take()
            self.take("lp")
            vals = [self.take("str")[1]]
            while self.peek()[0] == "comma":
                self.take()
                vals.append(self.take("str")[1])
            self.take("rp")
            node = ("in", lhs, vals)
        elif k == "kw" and t == "between":
            self.take()
            lo = self.term()
            self.take("kw", "and")
            hi = self.term()
            node = ("between", lhs, lo, hi)
        elif k == "op":
            self.take()
            node = ("cmp", t, lhs, self.term())
        else:
            raise ParseError(f"expected comparison after {lhs}, got {self.peek()}")
        return ("not", node) if neg else node


# ----------------------------------------------------------------------------------------------------------
# AST -> (target, DNF of literals); literal = (negated: bool, rego_expr: str)
# ----------------------------------------------------------------------------------------------------------
class Untranslatable(Exception):
    pass


def sql_like_to_regex(pat: str, esc: str | None, literal_underscore: bool = False) -> str:
    """SQL LIKE -> anchored RE2. `_` is a single-character wildcard in SQL; SAP parameter NAMES carry literal
    underscores (icm/HTTP/admin_0), so NAME patterns are converted with `_` literal."""
    out, i = [], 0
    while i < len(pat):
        c = pat[i]
        if esc and c == esc and i + 1 < len(pat):
            out.append(re.escape(pat[i + 1]))
            i += 2
            continue
        if c == "%":
            out.append(".*")
        elif c == "_" and not literal_underscore:
            out.append(".")
        else:
            out.append(re.escape(c))
        i += 1
    return "^" + "".join(out) + "$"


def check_regex(pat: str) -> str:
    """RE2 (OPA) has no lookaround or backreferences; HANA regex may use them."""
    if re.search(r"\(\?[=!<]", pat) or re.search(r"\\[1-9]", pat):
        raise Untranslatable("regex uses lookaround or backreference (not RE2)")
    try:
        re.compile(pat)
    except re.error as e:
        raise Untranslatable(f"regex does not compile: {e}")
    return pat


def rego_str(s: str) -> str:
    return json.dumps(s, ensure_ascii=False)


def rego_regex(pat: str) -> str:
    # Raw string when possible (keeps backslashes readable); Rego raw strings cannot hold a backtick.
    return "`" + pat + "`" if "`" not in pat else rego_str(pat)


def is_number(s: str) -> bool:
    return re.fullmatch(r"\d+(\.\d+)?", s) is not None


def value_term(t) -> str:
    """Rego expression for a term over the row VALUE (bound to `v`)."""
    kind = t[0]
    if kind == "col":
        if t[1] == "VALUE":
            return "v"
        raise Untranslatable(f"column {t[1]} is not VALUE")
    if kind == "func":
        f, args = t[1], t[2]
        if f in ("upper", "lower") and len(args) == 1:
            return f"{f}({value_term(args[0])})"
        if f == "substring" and len(args) == 3 and args[1][0] == "num" and args[2][0] == "num":
            start = max(int(args[1][1]) - 1, 0)  # HANA is 1-based (0 behaves as 1); Rego is 0-based
            return f"substring({value_term(args[0])}, {start}, {args[2][1]})"
        raise Untranslatable(f"function {f}/{len(args)}")
    raise Untranslatable(f"term {t}")


def literal(node) -> list[list[tuple[bool, str]]]:
    """Return DNF (list of conjunctions) of literals for a comparison node."""
    kind = node[0]
    if kind == "cmp":
        op, lhs, rhs = node[1], node[2], node[3]
        # length(VALUE) <op> N
        if lhs[0] == "func" and lhs[1] == "length":
            n = rhs[1]
            if rhs[0] not in ("num", "str") or not is_number(n):
                raise Untranslatable("length compared to non-number")
            return [[(False, f"count(v) {op if op != '=' else '=='} {int(float(n))}")]]
        # lpad(VALUE,n,'0') <op> 'NNNN'  -> numeric comparison
        if lhs[0] == "func" and lhs[1] == "lpad":
            if len(lhs[2]) != 3 or lhs[2][2] != ("str", "0") or rhs[0] != "str" or not is_number(rhs[1]):
                raise Untranslatable("lpad shape")
            return [[(False, f"{NUM_FN[op]}(v, {int(rhs[1])})")]]
        if rhs[0] == "col" or rhs[0] == "func":
            raise Untranslatable("right-hand side is a column or function")
        lv = value_term(lhs)
        rv = rhs[1]
        if op in ("=", "!="):
            if rhs[0] == "num":
                # VALUE = 0 (unquoted): the store holds strings; compare as string of the literal
                rv = rhs[1]
            return [[(False, f"{lv} {'==' if op == '=' else '!='} {rego_str(rv)}")]]
        # ordering on strings: numeric when both sides look numeric, dotted-version when the literal is dotted
        if lv != "v":
            raise Untranslatable("ordering on a transformed value")
        if is_number(rv) and "." not in rv:
            return [[(False, f"{NUM_FN[op]}(v, {int(rv)})")]]
        if re.fullmatch(r"\d+(\.\d+)+", rv):
            return [[(False, f"{VER_FN[op]}(v, {rego_str(rv)})")]]
        raise Untranslatable(f"ordering comparison against {rv!r}")
    if kind == "like":
        lv = value_term(node[1])
        return [[(False, f"regex.match({rego_regex(check_regex(sql_like_to_regex(node[2], node[3])))}, {lv})")]]
    if kind == "like_regexpr":
        lv = value_term(node[1])
        return [[(False, f"regex.match({rego_regex(check_regex(node[2]))}, {lv})")]]
    if kind == "in":
        lv = value_term(node[1])
        return [[(False, f"{lv} in {{{', '.join(rego_str(x) for x in node[2])}}}")]]
    if kind == "between":
        lhs, lo, hi = node[1], node[2], node[3]
        if lhs[0] == "func" and lhs[1] == "lpad" and lo[0] == "str" and hi[0] == "str" and is_number(lo[1]) and is_number(hi[1]):
            return [[(False, f"num_between(v, {int(lo[1])}, {int(hi[1])})")]]
        raise Untranslatable("between shape")
    raise Untranslatable(f"node {kind}")


NUM_FN = {">=": "num_ge", ">": "num_gt", "<=": "num_le", "<": "num_lt", "=": "num_eq", "!=": "num_ne"}
VER_FN = {">=": "ver_ge", ">": "ver_gt", "<=": "ver_le", "<": "ver_lt"}


def negate_dnf(dnf):
    """not (A1 and A2 ... or B1 ...)  ->  product of negated literals (CNF->DNF expansion); sizes here are tiny."""
    result = [[]]
    for conj in dnf:
        new = []
        for lit in conj:
            for r in result:
                new.append(r + [(not lit[0], lit[1])])
        result = new
    return result


def to_dnf(node) -> list[list[tuple[bool, str]]]:
    kind = node[0]
    if kind == "and":
        a, b = to_dnf(node[1]), to_dnf(node[2])
        return [x + y for x in a for y in b]
    if kind == "or":
        return to_dnf(node[1]) + to_dnf(node[2])
    if kind == "not":
        return negate_dnf(to_dnf(node[1]))
    return literal(node)


def split_target(node):
    """Peel `NAME = 'x' and <rest>` / `NAME like 'pat' and <rest>` off the AST. Returns (kind, name, rest)."""
    if node[0] == "and":
        tgt = split_target_atom(node[1])
        if tgt:
            return tgt[0], tgt[1], node[2]
        tgt = split_target_atom(node[2])
        if tgt:
            return tgt[0], tgt[1], node[1]
    tgt = split_target_atom(node)
    if tgt:
        return tgt[0], tgt[1], None
    raise Untranslatable("no NAME target")


def split_target_atom(node):
    if node[0] == "cmp" and node[1] == "=" and node[2] == ("col", "NAME") and node[3][0] == "str":
        return ("exact", node[3][1])
    if node[0] == "like" and node[1] == ("col", "NAME"):
        return ("pattern", sql_like_to_regex(node[2], node[3], literal_underscore=True))
    return None


def mentions_name_elsewhere(node) -> bool:
    if isinstance(node, tuple):
        if node == ("col", "NAME"):
            return True
        return any(mentions_name_elsewhere(c) for c in node[1:])
    if isinstance(node, list):
        return any(mentions_name_elsewhere(c) for c in node)
    return False


def translate(expr: str):
    """-> (target_kind, target, dnf). Raises Untranslatable."""
    try:
        ast = Parser(expr).parse()
    except ParseError as e:
        raise Untranslatable(f"parse: {e}")
    kind, name, rest = split_target(ast)
    if rest is None:
        raise Untranslatable("condition has no VALUE test")
    if mentions_name_elsewhere(rest):
        raise Untranslatable("condition joins on NAME more than once")
    dnf = to_dnf(rest)
    if len(dnf) > 12:
        raise Untranslatable(f"DNF too large ({len(dnf)} disjuncts)")
    return kind, name, dnf


# ----------------------------------------------------------------------------------------------------------
# XML reading
# ----------------------------------------------------------------------------------------------------------
def read_policy(path: pathlib.Path):
    text = path.read_text(encoding="utf-8")
    # The source is a downloaded tree: refuse DTDs outright (XXE / entity expansion) instead of parsing them.
    if re.search(r"<!(DOCTYPE|ENTITY)", text, re.I):
        raise SystemExit(f"{path}: contains a DTD/entity declaration; refusing to parse")
    m = REQ_RE.search(text)
    req_id, req_title = (m.group(1), " ".join(m.group(2).split())) if m else (path.stem, path.stem)
    root = ET.fromstring(text)
    items = []
    for store in root.iter("configstore"):
        sname = store.get("name")
        for ci in store.iter("checkitem"):
            comp = ci.find("compliant")
            items.append({
                "id": ci.get("id"),
                "desc": " ".join((ci.get("desc") or "").split()),
                "store": sname,
                "not_found": ci.get("not_found", ""),
                "system_attributes": ci.get("system_attributes", ""),
                "compliant": " ".join(comp.text.split()) if comp is not None and comp.text else "",
                "policy": root.get("id"),
                "policy_desc": root.get("desc"),
                "requirement": req_id,
                "requirement_title": req_title,
                "file": path.name,
            })
    return items


def rego_ident(check_id: str) -> str:
    return "ok_" + re.sub(r"[^A-Za-z0-9]", "_", check_id)


def build(source: pathlib.Path, commit: str, manual_ids: set[str]):
    raw = []
    for p in sorted(source.glob("*.xml")):
        raw.extend(read_policy(p))

    # group by id: the registry has one row per SAP check id; Parameters/PAHI twins and variants fold here
    by_id: dict[str, list[dict]] = {}
    order = []
    for it in raw:
        if it["id"] not in by_id:
            by_id[it["id"]] = []
            order.append(it["id"])
        by_id[it["id"]].append(it)

    registry, rules = [], []
    stats = {"translated": 0, "manual": 0, "untranslatable": 0, "other_store": 0, "variants_or": 0}
    for cid in order:
        rows = by_id[cid]
        first = rows[0]
        prio = PRIO_RE.match(first["desc"])
        level, severity = PRIORITY[prio.group(1)] if prio else ("extended", "medium")
        text = prio.group(3).strip() if prio else first["desc"]
        stores = sorted({r["store"] for r in rows})
        row = {
            "id": cid,
            "requirement": first["requirement"],
            "requirement_title": first["requirement_title"],
            "level": level,
            "severity": severity,
            "text": text,
            "stores": stores,
            "assessable": False,
            "basis": None,
            "parameter": None,
            "reason": None,
            "source_policy": first["policy"],
        }
        nv_rows = [r for r in rows if r["store"] in NAME_VALUE_STORES]
        if cid in manual_ids:
            row.update(assessable=True, basis="hand_written")
            stats["manual"] += 1
        elif nv_rows:
            exprs = []
            for r in nv_rows:
                if r["compliant"] not in exprs:
                    exprs.append(r["compliant"])
            fact_key, basis = NAME_VALUE_STORES[nv_rows[0]["store"]]
            try:
                parts = [translate(e) for e in exprs]
                kinds = {p[0] for p in parts}
                names = {p[1] for p in parts}
                if len(kinds) != 1 or len(names) != 1:
                    raise Untranslatable("variants target different parameters")
                kind, name = parts[0][0], parts[0][1]
                dnf = []
                for p in parts:
                    for conj in p[2]:
                        if conj not in dnf:
                            dnf.append(conj)
                if len(exprs) > 1:
                    stats["variants_or"] += 1
                not_found_ok = any(r["not_found"] == "positive" for r in nv_rows)
                row.update(assessable=True, basis=basis, parameter=name,
                           parameter_match="exact" if kind == "exact" else "regex")
                rules.append(emit_rule(cid, text, level, fact_key, kind, name, dnf, not_found_ok, len(exprs)))
                stats["translated"] += 1
            except Untranslatable as e:
                row["reason"] = f"condition not translatable in v1: {e}"
                row["parameter"] = None
                stats["untranslatable"] += 1
        elif any(r["store"] in FILE_STORES for r in rows):
            row["reason"] = f"file-shaped store {stores}: needs a hand-written rule"
            stats["other_store"] += 1
        else:
            row["reason"] = f"needs runtime data (store {', '.join(stores)}): RFC or database access, v2 scope"
            stats["other_store"] += 1
        registry.append(row)
    return registry, rules, stats


def emit_rule(cid, text, level, fact_key, kind, name, dnf, not_found_ok, nvariants) -> str:
    ident = rego_ident(cid)
    short = text if len(text) <= 160 else text[:157] + "..."
    short = short.replace('"', "'")
    out = [f"# {cid} [{level}] {short}"]
    if nvariants > 1:
        out.append(f"# SAP publishes {nvariants} variants of this check; a value that satisfies any of them passes.")
    if kind == "exact":
        out += [
            "violations contains msg if {",
            f"\tlevel_in_profile({rego_str(level)})",
            f"\tnot {ident}",
            f"\tmsg := sprintf({rego_str(cid + ': ' + short + ' (%s)')}, [state({rego_str(fact_key)}, {rego_str(name)})])",
            "}",
        ]
        if not_found_ok:
            out += [f"{ident} if {{ not has({rego_str(fact_key)}, {rego_str(name)}) }}"]
        for conj in dnf:
            body = [f"\tv := fact({rego_str(fact_key)}, {rego_str(name)})"] + ["\t" + lit_rego(neg, e) for neg, e in conj]
            out += [f"{ident} if {{"] + body + ["}"]
    else:
        out += [
            "violations contains msg if {",
            f"\tlevel_in_profile({rego_str(level)})",
            f"\tnot {ident}",
            f"\tmsg := sprintf({rego_str(cid + ': ' + short + ' (%s)')}, [pattern_state({rego_str(fact_key)}, {rego_regex(name)})])",
            "}",
        ]
        if not_found_ok:
            out += [f"{ident} if {{ count(facts_matching({rego_str(fact_key)}, {rego_regex(name)})) == 0 }}"]
        out += [
            f"{ident} if {{",
            f"\tms := facts_matching({rego_str(fact_key)}, {rego_regex(name)})",
            "\tcount(ms) > 0",
            f"\tevery v in ms {{ {ident}_row(v) }}",
            "}",
        ]
        for conj in dnf:
            out += [f"{ident}_row(v) if {{"] + ["\t" + lit_rego(neg, e) for neg, e in conj] + ["}"]
    return "\n".join(out) + "\n"


def lit_rego(neg: bool, expr: str) -> str:
    if not neg:
        return expr
    if " == " in expr and expr.startswith(("v ", "upper(", "lower(", "substring(")):
        return expr.replace(" == ", " != ", 1)
    if " != " in expr and expr.startswith(("v ", "upper(", "lower(", "substring(")):
        return expr.replace(" != ", " == ", 1)
    return "not " + expr


# ----------------------------------------------------------------------------------------------------------
# writers
# ----------------------------------------------------------------------------------------------------------
HEADER = """# GENERATED by scripts/import_sap_baseline.py — do not edit; re-run the importer.
# Source: SAP-samples/frun-csa-policies-best-practices @ {commit} (Apache-2.0),
#         BaselinePolicies/SOS/v2.6/ABAP_ALL = SAP Security Baseline Template v{version} (ABAP checks).
# The package METADATA block is in sap_abap_baseline.rego (one block per package).
package sap_abap_baseline.main

import rego.v1

"""


def _coverage_stamp(path: pathlib.Path) -> str:
    """`make coverage` stamps a custom.coverage block into every METADATA block, the generated registry's
    included; carry the committed stamp over so regenerating never un-stamps it (check-coverage would fail)."""
    if not path.exists():
        return ""
    m = re.search(r"^#   coverage:\n(?:#     .*\n)+", path.read_text(encoding="utf-8"), re.M)
    return m.group(0) if m else ""


def write_outputs(out: pathlib.Path, registry, rules, stats, commit: str) -> dict[str, str]:
    files = {}
    index = {
        "benchmark": "SAP Security Baseline Template",
        "version": VERSION,
        "stack": "ABAP",
        "source": {
            "repository": "https://github.com/SAP-samples/frun-csa-policies-best-practices",
            "path": "BaselinePolicies/SOS/v2.6/ABAP_ALL",
            "commit": commit,
            "license": "Apache-2.0",
        },
        "counts": {
            "checks": len(registry),
            "assessable": sum(1 for r in registry if r["assessable"]),
            "not_assessable": sum(1 for r in registry if not r["assessable"]),
            **stats,
        },
        "checks": registry,
    }
    files["data/sap_baseline_v2_6_index.json"] = json.dumps(index, indent=1, ensure_ascii=False) + "\n"

    reg_meta = ("# METADATA\n"
                "# title: \"SAP Security Baseline Template v2.6 — ABAP check registry (generated)\"\n"
                "# custom:\n#   class: security\n#   framework: sap_abap_baseline\n#   source: sap\n#   domains: [sap, erp]\n"
                + _coverage_stamp(out / "sap_abap_baseline_registry.rego"))
    reg_lines = [HEADER.format(commit=commit, version=VERSION)
                 .replace("# The package METADATA block is in sap_abap_baseline.rego (one block per package).\n", "")
                 .replace("package sap_abap_baseline.main", reg_meta + "package sap_abap_baseline.registry")]
    reg_lines.append("# One row per check SAP publishes for the ABAP stack. `assessable` says whether this library evaluates it\n"
                     "# from host-collected facts (v1); the rest carry the reason, so projections list them as not assessable.\n")
    reg_lines.append(f"benchmark := {rego_str('SAP Security Baseline Template v' + VERSION + ' (ABAP)')}\n")
    reg_lines.append(f"source_commit := {rego_str(commit)}\n\n")
    reg_lines.append("# Keyed by SAP's check id. Built from one object literal per Baseline requirement: the library's control\n"
                     "# counter (scripts/rego_ast.py) reads a top-level object literal of id-carrying rows as a check table, and\n"
                     "# these rows are bookkeeping, not checks.\n")
    reg_lines.append("checks := object.union_n(_by_requirement)\n\n")
    reg_lines.append("_by_requirement := [\n")
    current = None
    for r in registry:
        if r["requirement"] != current:
            if current is not None:
                reg_lines.append("\t},\n")
            current = r["requirement"]
            reg_lines.append(f"\t{{ # {current}: {r['requirement_title']}\n")
        reg_lines.append(f"\t\t{rego_str(r['id'])}: {{\n")
        for k in ("id", "requirement", "requirement_title", "level", "severity", "text", "assessable", "basis", "parameter", "reason"):
            v = r.get(k)
            if isinstance(v, bool):
                vs = "true" if v else "false"
            elif v is None:
                vs = "null"
            else:
                vs = rego_str(v)
            reg_lines.append(f"\t\t\t{rego_str(k)}: {vs},\n")
        reg_lines.append(f"\t\t\t\"stores\": [{', '.join(rego_str(s) for s in r['stores'])}],\n")
        reg_lines.append("\t\t},\n")
    reg_lines.append("\t},\n]\n")
    files["sap_abap_baseline_registry.rego"] = "".join(reg_lines)

    chk = [HEADER.format(commit=commit, version=VERSION)]
    chk.append(f"# {stats['translated']} checks translated from SAP's CSA conditions. Helpers (fact, has, state, num_*, ver_*,\n"
               "# level_in_profile) are defined in sap_abap_baseline.rego.\n\n")
    chk.append("\n".join(rules))
    files["sap_abap_baseline_checks.rego"] = "".join(chk)
    return files


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--source", required=True, type=pathlib.Path, help=".../BaselinePolicies/SOS/v2.6/ABAP_ALL")
    ap.add_argument("--commit", required=True, help="git commit of the SAP-samples checkout (recorded in the outputs)")
    ap.add_argument("--out", default="benchmarks/sap/abap", type=pathlib.Path)
    ap.add_argument("--check", action="store_true", help="fail if the committed outputs differ from a fresh run")
    a = ap.parse_args()
    manual = set()
    manual_file = a.out / "sap_abap_baseline_manual.rego"
    if manual_file.exists():
        manual = set(re.findall(r"^# MANUAL-CHECK:\s*(\S.*?)\s*$", manual_file.read_text(encoding="utf-8"), re.M))
    registry, rules, stats = build(a.source, a.commit, manual)
    files = write_outputs(a.out, registry, rules, stats, a.commit)
    if a.check:
        bad = 0
        for rel, content in files.items():
            p = a.out / rel
            cur = p.read_text(encoding="utf-8") if p.exists() else ""
            if cur != content:
                bad += 1
                sys.stdout.writelines(difflib.unified_diff(cur.splitlines(True), content.splitlines(True), str(p), "fresh"))
        sys.exit(1 if bad else 0)
    for rel, content in files.items():
        p = a.out / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        print(f"wrote {p}")
    print(json.dumps({"checks": len(registry), **stats}))
    for r in registry:
        if r["reason"] and r["reason"].startswith("condition not translatable"):
            print(f"  untranslatable: {r['id']}: {r['reason']}")


if __name__ == "__main__":
    main()
