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


@dataclass
class Index:
    by_pkg: dict = field(default_factory=dict)      # package -> inventory entries
    controls: dict = field(default_factory=dict)    # (framework, id) -> (Rule)

    @classmethod
    def build(cls):
        ix = cls()
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

    def framework_for(self, package):
        """cis_rhel9.main -> entries for the package, else the nearest parent package, else None."""
        parts = package.split(".")
        while parts:
            p = ".".join(parts)
            if p in self.by_pkg:
                return self.by_pkg[p]
            parts.pop()
        # last resort: a package whose first segment matches (cis_rhel9.main ~ cis_rhel9.auditd)
        head = package.split(".")[0]
        hits = [v for k, v in self.by_pkg.items() if k.split(".")[0] == head]
        return hits[0] if hits else None

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


def load_reports(paths):
    """Yield (report_path, report) for every report node in the given JSON files."""
    for p in paths:
        doc = json.loads(pathlib.Path(p).read_text())
        if isinstance(doc, dict) and "result" in doc and isinstance(doc["result"], list):   # opa eval -f json
            for r in doc["result"]:
                for ex in r.get("expressions", []):
                    text = ex.get("text", "data")
                    base = re.sub(r"^data\.", "", text)
                    base = re.sub(r"\.(compliance_report|report)$", "", base)
                    found = []
                    _walk(ex.get("value"), base if base != "data" else "", found)
                    yield from found
        else:
            found = []
            _walk(doc, "", found)
            yield from found


def findings(paths, ix=None):
    ix = ix or Index.build()
    out = []
    for rpath, rep in load_reports(paths):
        pkg = re.sub(r"\.(compliance_report|report)$", "", rpath).strip(".")
        viol = rep["violations"]
        msgs = list(viol.values()) if isinstance(viol, dict) else list(viol)
        for m in msgs:
            text = m if isinstance(m, str) else json.dumps(m, ensure_ascii=False)
            out.append(Finding(ix.rule_for(pkg, text), text, pkg, rpath, rep.get("compliant", rep.get("overall_compliant"))))
    return out
