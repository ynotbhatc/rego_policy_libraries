"""Shared reader for the runtime exports (SARIF, OCSF, OSCAL assessment-results).

Input: any JSON an `opa eval -f json` run produced (the `result[].expressions[].value` tree), a raw `data`
tree, or a single compliance_report object. The reader walks it and yields one Finding per violation,
mapped to the control inventory so every export uses the same rule ids as the OSCAL catalogs.

A report node is a dict with a "violations" key plus any of compliant / violation_count / failed_controls.
Its path (e.g. cis_rhel9.main) is the Rego package; the inventory maps the package to framework + file.
Violation messages carry the control id as a prefix ("CIS 1.3.1: ..."); a prefix the inventory does not know
(section-level fail-closed notices such as "CIS 1.1: FAIL-CLOSED ...") becomes an unmapped rule, kept and
flagged, never dropped.
"""
from __future__ import annotations
import json, re, sys, pathlib
from dataclasses import dataclass, field

ROOT = pathlib.Path(__file__).resolve().parents[3]  # converters/exports/_lib/findings.py -> repo root
sys.path.insert(0, str(ROOT / "scripts"))
from inventory_controls import inventory, _split  # noqa: E402
from rego_ast import ID_KEYS, TEXT_KEYS, policy_files  # noqa: E402

REPO = "https://github.com/ynotbhatc/rego_policy_libraries"
TOKEN_BAD = re.compile(r"[^A-Za-z0-9._-]+")


def token(s):
    t = re.sub(r"-{2,}", "-", TOKEN_BAD.sub("-", s).strip("-."))
    return t if t and (t[0].isalpha() or t[0] == "_") else "c-" + t


def version():
    m = re.search(r"^## \[(\d+\.\d+\.\d+)\]", (ROOT / "CHANGELOG.md").read_text(), re.M)
    return m.group(1) if m else "0.0.0"


@dataclass
class Rule:
    id: str            # <framework>-<control id> as a token: identical to the OSCAL control id
    label: str         # original control id ("CIS 1.3.1", "CCPA §7122(a)(1)")
    text: str          # control statement
    framework: str
    package: str
    file: str
    mapped: bool       # False when the message prefix is not a control the inventory knows


@dataclass
class Finding:
    rule: Rule
    message: str
    package: str
    report_path: str
    compliant: bool | None
    severity: str | None = None   # the module's own severity for this finding, when it states one


PKG_RE = re.compile(r"^package\s+([A-Za-z0-9_.]+)", re.M)
IMPORT_RE = re.compile(r"^import\s+data\.([A-Za-z0-9_.]+)", re.M)


def package_imports(root=ROOT):
    """{package: (dir, [imported data packages])} for every policy file. A `<key>.main` entrypoint that holds no
    controls of its own (nist_800_53.main, stig_rhel9.main) is a bridge: it imports the package that does the work
    (`import data.nist.sp800_53.main as _t`), so the exporters follow the import to find the framework."""
    out = {}
    for rel in policy_files(root):
        src = (root / rel).read_text(errors="ignore")
        m = PKG_RE.search(src)
        if m:
            d, imps = out.setdefault(m.group(1), (str(pathlib.PurePosixPath(rel).parent), []))
            imps.extend(i for i in IMPORT_RE.findall(src) if i not in imps)
    return out


@dataclass
class Index:
    by_pkg: dict = field(default_factory=dict)      # package -> inventory entries
    controls: dict = field(default_factory=dict)    # (framework, id) -> (Rule)
    imports: dict = field(default_factory=dict)     # package -> (dir, imported packages), for bridge entrypoints

    @classmethod
    def build(cls):
        ix = cls()
        ix.imports = package_imports(ROOT)
        for e in inventory(ROOT):
            ix.by_pkg.setdefault(e["package"], []).append(e)
            fw_tok = token(e["framework"])
            for c in e["controls"]:
                if c["id"].startswith(e["package"] + "#"):
                    continue  # synthesised ids never appear in messages
                rid = token(f"{fw_tok}-{c['id']}")
                ix.controls.setdefault((e["framework"], c["id"]), Rule(rid, c["id"], next((t for t in c["texts"] if t), c["id"]),
                                                                       e["framework"], e["package"], e["file"], True))
        return ix

    def framework_for(self, package, _seen=None):
        """cis_rhel9.main -> entries for the package; else, for a bridge entrypoint (a package with no controls of
        its own), the framework its imports resolve to; else the nearest parent package; else None."""
        if package in self.by_pkg:
            return self.by_pkg[package]
        bridged = self._via_imports(package, _seen or set())
        if bridged:
            return bridged
        parts = package.split(".")
        while parts:
            p = ".".join(parts)
            if p in self.by_pkg:
                return self.by_pkg[p]
            # an orchestrator (nist.sp800_53.main) is not in the inventory; its sibling family packages are, and
            # they share one framework: use it when they all agree
            if len(parts) > 1:
                sib = {e["framework"]: v for k, v in self.by_pkg.items() if k.startswith(".".join(parts[:-1]) + ".") for e in v}
                if len(sib) == 1:
                    return next(iter(sib.values()))
            parts.pop()
        # last resort: a package whose first segment matches (cis_rhel9.main ~ cis_rhel9.auditd)
        head = package.split(".")[0]
        hits = [v for k, v in self.by_pkg.items() if k.split(".")[0] == head]
        return hits[0] if hits else None

    def _via_imports(self, package, seen):
        """Follow a bridge's `import data.X` statements. The imports must agree on one framework; when they do not
        (a roll-up of several frameworks), keep those whose files sit under the bridge's own directory."""
        if package in seen or package not in self.imports:
            return None
        seen.add(package)
        d, imps = self.imports[package]
        found = {}
        for imp in imps:
            if imp in self.by_pkg:
                ents = self.by_pkg[imp]
            elif imp in self.imports and imp not in seen:
                ents = self._via_imports(imp, seen) or self._siblings(imp)
            else:
                ents = self._siblings(imp)
            if ents:
                found.setdefault(ents[0]["framework"], ents)
        if len(found) > 1:
            found = {fw: v for fw, v in found.items() if all(e["file"].startswith(d + "/") for e in v[:1])}
        return next(iter(found.values())) if len(found) == 1 else None

    def _siblings(self, package):
        """Entries of the packages under `package.` when they share one framework (nist.sp800_53.main is an
        orchestrator over nist.sp800_53.<family>), walking up one level at a time; None otherwise."""
        parts = package.split(".")
        while len(parts) > 1:
            pre = ".".join(parts[:-1]) + "."
            sib = {e["framework"]: v for k, v in self.by_pkg.items() if k.startswith(pre) for e in v}
            if len(sib) == 1:
                return next(iter(sib.values()))
            if sib:
                return None
            parts.pop()
        return None

    def rule_for(self, package, message):
        entries = self.framework_for(package)
        fw = entries[0]["framework"] if entries else token(package.split(".")[0])
        file = entries[0]["file"] if entries else ""
        cid, _ = _split(message)
        if cid and (fw, cid) in self.controls:
            return self.controls[(fw, cid)]
        # unmapped: keep the prefix as the label so a viewer still groups by it
        label = cid or "unmapped"
        rid = token(f"{token(fw)}-{label}")
        return self.controls.setdefault((fw, label), Rule(rid, label, message.split(":", 1)[-1].strip()[:200] or message, fw, package, file, False))

    def rule_for_row(self, package, row_id):
        """The catalog control a control_results row names, or None. A row id is the control id without the
        message prefix ("AC-2", "6.2.1.1"); the catalog keeps the label as messages write it ("NIST AC-2",
        "6.2.1.1"). Exact label first, then the one label ending in " <id>"; ambiguous or unknown -> None."""
        entries = self.framework_for(package)
        if not entries or not isinstance(row_id, str) or not row_id:
            return None
        fw = entries[0]["framework"]
        rule = self.controls.get((fw, row_id))
        if rule and rule.mapped:
            return rule
        hits = [r for (f, label), r in self.controls.items() if f == fw and r.mapped and label.endswith(" " + row_id)]
        return hits[0] if len(hits) == 1 else None


def _is_report(node):
    return isinstance(node, dict) and "violations" in node and any(k in node for k in ("compliant", "violation_count", "failed_controls", "overall_compliant"))


def _walk(node, path, out):
    if _is_report(node):
        out.append((path, node))
        return
    if isinstance(node, dict):
        for k, v in node.items():
            _walk(v, f"{path}.{k}" if path else k, out)
    elif isinstance(node, list):
        for i, v in enumerate(node):
            _walk(v, f"{path}[{i}]", out)


def _doc(src):
    """A path to a JSON file, or an already-loaded document (dict/list), -> (name, document)."""
    if isinstance(src, (dict, list)):
        return "<memory>", src
    return str(src), json.loads(pathlib.Path(src).read_text())


def load_reports(paths, key=None):
    """Yield (report_path, report) for every report node in the given inputs. Three input shapes:
      opa eval -f json            {"result": [{"expressions": [{"text": "data.<key>.main.compliance_report", "value": ...}]}]}
      OPA REST API response       {"result": {<compliance_report>}}   (POST /v1/data/<key>/main/compliance_report)
      a bare compliance_report    {"compliant": ..., "violations": [...], ...}
    The REST and bare shapes do not say which package produced them: `key` (the framework key of
    data.<key>.main.compliance_report) names it; without a key such a report is reported under the path ""."""
    top = f"{key}.main" if key else ""
    for p in paths:
        _, doc = _doc(p)
        if isinstance(doc, dict) and "result" in doc and isinstance(doc["result"], list):   # opa eval -f json
            for r in doc["result"]:
                for ex in r.get("expressions", []):
                    text = ex.get("text", "data")
                    base = re.sub(r"^data\.", "", text)
                    base = re.sub(r"\.(compliance_report|report)$", "", base)
                    if key and not re.fullmatch(r"[A-Za-z0-9_.]+", base):
                        base = top     # a query that is not a plain data path ({k: ...}, x := ...): the key names it
                    found = []
                    _walk(ex.get("value"), base if base != "data" else "", found)
                    yield from found
        elif isinstance(doc, dict) and isinstance(doc.get("result"), dict) and _is_report(doc["result"]):  # REST
            yield top, doc["result"]
        else:
            found = []
            _walk(doc, top, found)
            yield from found


OBJ_ID_KEYS = ID_KEYS + ("vuln_id",)
OBJ_TEXT_KEYS = ("rule_title",) + TEXT_KEYS + ("msg", "message", "violation", "fix_text")


def finding_text(m):
    """A violation as one line of text. Strings pass through. Object findings — the STIG modules emit
    {vuln_id, stig_id, severity, rule_title, status, ...} — become "<id>: <title>", so the same prefix rule
    that maps "CIS 1.3.1: ..." maps "OL09-00-002413: ..." to its catalog control. Anything else is dumped as
    JSON, never dropped."""
    if isinstance(m, str):
        return m
    if isinstance(m, dict):
        cid = next((str(m[k]).strip() for k in OBJ_ID_KEYS if isinstance(m.get(k), (str, int)) and str(m[k]).strip()), None)
        txt = next((m[k].strip() for k in OBJ_TEXT_KEYS if isinstance(m.get(k), str) and m[k].strip()), None)
        if cid and txt:
            return f"{cid}: {txt}"
        if cid:
            return f"{cid}: {json.dumps(m, ensure_ascii=False)}"
        if txt:
            return txt
    return json.dumps(m, ensure_ascii=False)


def finding_severity(m):
    """The finding's own severity when the module states one (STIG: "CAT I"/"CAT II"/"CAT III"; others: high/medium/low)."""
    return str(m["severity"]).strip() if isinstance(m, dict) and isinstance(m.get("severity"), str) and m["severity"].strip() else None


def findings(paths, ix=None, key=None):
    ix = ix or Index.build()
    out = []
    for rpath, rep in load_reports(paths, key):
        pkg = re.sub(r"\.(compliance_report|report)$", "", rpath).strip(".")
        viol = rep["violations"]
        msgs = list(viol.values()) if isinstance(viol, dict) else list(viol)
        for m in msgs:
            text = finding_text(m)
            out.append(Finding(ix.rule_for(pkg, text), text, pkg, rpath, rep.get("compliant", rep.get("overall_compliant")), finding_severity(m)))
    return out


def passes(paths, ix=None, key=None):
    """Rows a report's control_results marks "pass", resolved to catalog controls: [(Rule, row, package, report_path)].
    Only reports that carry control_results contribute; a row that does not resolve to exactly one catalog control is
    left out (never asserted), and so is any status other than "pass"."""
    ix = ix or Index.build()
    out = []
    for rpath, rep in load_reports(paths, key):
        rows = rep.get("control_results")
        if not isinstance(rows, list):
            continue
        pkg = re.sub(r"\.(compliance_report|report)$", "", rpath).strip(".")
        for row in rows:
            if isinstance(row, dict) and row.get("status") == "pass":
                rule = ix.rule_for_row(pkg, row.get("id"))
                if rule:
                    out.append((rule, row, pkg, rpath))
    return out


EVIDENCE_MISSING = re.compile(r"evidence missing|FAIL-CLOSED|not collected|(this is not a pass)", re.I)


@dataclass
class Assessed:
    """One control's outcome in one report. From a control_results row (row_id set): status is the row's
    ("pass", "fail", "evidence_missing", "not_attested", "not_applicable"; anything else is kept as given and
    treated as not satisfied), messages are the row's findings plus any violation that maps to the same control.
    From a violation alone (no control_results, or no row for its control): status "fail", or
    "evidence_missing" when the message says so, one message."""
    rule: Rule
    status: str
    messages: list
    package: str
    report_path: str
    basis: str | None = None
    severity: str | None = None
    row_id: str | None = None
    evidence: list | None = None

    @property
    def satisfied(self):
        return self.status == "pass"


def _pkg(rpath):
    return re.sub(r"\.(compliance_report|report)$", "", rpath).strip(".")


def assess(paths, ix=None, key=None):
    """Every control outcome the reports state, control_results first, violations after. Nothing is dropped: a
    row whose id is not a catalog control becomes an unmapped rule, a violation with no row stays a finding."""
    ix = ix or Index.build()
    out = []
    for rpath, rep in load_reports(paths, key):
        pkg = _pkg(rpath)
        rows = rep.get("control_results") if isinstance(rep.get("control_results"), list) else []
        by_rule = {}
        for row in rows:
            if not isinstance(row, dict):
                continue
            rid = row.get("id") if isinstance(row.get("id"), str) and row.get("id") else None
            rule = ix.rule_for_row(pkg, rid) if rid else None
            msgs = [finding_text(m) for m in (row.get("findings") or []) if m is not None] if isinstance(row.get("findings"), list) else []
            if rule is None:   # not a catalog control: keep it under its own id, flagged unmapped
                rule = ix.rule_for(pkg, f"{rid or 'unmapped'}: {msgs[0] if msgs else 'control_results row'}")
            status = row.get("status") if isinstance(row.get("status"), str) and row.get("status") else "unknown"
            sev = next((finding_severity(m) for m in (row.get("findings") or []) if finding_severity(m)), None) if isinstance(row.get("findings"), list) else None
            a = Assessed(rule, status, msgs, pkg, rpath, row.get("basis") if isinstance(row.get("basis"), str) else None,
                         sev, rid, row.get("evidence") if isinstance(row.get("evidence"), list) else None)
            out.append(a)
            by_rule.setdefault(rule.id, a)
        viol = rep["violations"]
        for m in (list(viol.values()) if isinstance(viol, dict) else list(viol)):
            text = finding_text(m)
            rule = ix.rule_for(pkg, text)
            row = by_rule.get(rule.id)
            if row is not None:
                if row.status == "pass":   # a violation for a control its row calls a pass: fail closed
                    row.status = "fail"
                if text not in row.messages:
                    row.messages.append(text)
                if row.severity is None:
                    row.severity = finding_severity(m)
                continue
            out.append(Assessed(rule, "evidence_missing" if EVIDENCE_MISSING.search(text) else "fail", [text], pkg, rpath,
                                severity=finding_severity(m)))
    return out
