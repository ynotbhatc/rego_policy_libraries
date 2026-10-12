#!/usr/bin/env python3
"""Rego → OSCAL 1.2.3 catalogs.

One catalog per framework (dist/catalogs/<framework>.json, committed so GRC tools can fetch them by URL)
and one combined catalog (out/all.json, attached to each release). Everything comes from
scripts/inventory_controls.py, which reads the Rego tree; nothing here is hand-kept.

Mapping
  framework            -> catalog (uuid5 of framework + version: stable across builds)
  Rego module (file)   -> group  (class "rego-module", title from METADATA)
  control id           -> control (id = <framework>-<id> as an OSCAL token; props label / alt-identifier keep the
                          original id; links point at the Rego file; class = METADATA class)
  check messages       -> parts: "statement" (first text) + one "assessment-objective" per further check
  module file          -> back-matter resource with an rlink to the file on GitHub

Deterministic: version and last-modified come from CHANGELOG.md, uuids from uuid5, so `git diff dist/` in CI
tells whether the committed catalogs are stale. `--out DIR` overrides the output root (tests use it).
"""
from __future__ import annotations
import json, re, sys, uuid, pathlib, argparse

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from inventory_controls import inventory  # noqa: E402

NS = "https://github.com/ynotbhatc/rego_policy_libraries/ns/oscal"
REPO = "https://github.com/ynotbhatc/rego_policy_libraries"
OSCAL_VERSION = "1.2.3"
TOKEN_BAD = re.compile(r"[^A-Za-z0-9._-]+")


def version_and_date():
    m = re.search(r"^## \[(\d+\.\d+\.\d+)\](?:\s*-\s*(\d{4}-\d{2}-\d{2}))?", (ROOT / "CHANGELOG.md").read_text(), re.M)
    if not m:
        return "0.0.0", "1970-01-01T00:00:00Z"
    return m.group(1), f"{m.group(2) or '1970-01-01'}T00:00:00Z"


def token(s):
    t = TOKEN_BAD.sub("-", s).strip("-.")
    t = re.sub(r"-{2,}", "-", t)
    if not t or not (t[0].isalpha() or t[0] == "_"):
        t = "c-" + t
    return t


def u5(*parts):
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"{REPO}/oscal/" + "/".join(parts)))


def build_catalog(fw, entries, version, stamp, blob):
    """entries: inventory rows for one framework. Controls with the same id across files are merged."""
    fw_tok = token(fw)
    groups, resources, seen = [], [], {}
    for e in sorted(entries, key=lambda x: x["file"]):
        res_uuid = u5(version, "resource", e["file"])
        resources.append({"uuid": res_uuid, "title": e["title"],
                          "props": [{"name": "rego-package", "ns": NS, "value": e["package"]}],
                          "rlinks": [{"href": f"{blob}/{e['file']}", "media-type": "text/plain"}]})
        group = {"id": token(f"{fw_tok}-{pathlib.Path(e['file']).stem}"), "class": "rego-module", "title": e["title"],
                 "props": [{"name": "rego-package", "ns": NS, "value": e["package"]},
                           {"name": "rego-file", "ns": NS, "value": e["file"]}], "controls": []}
        if e["class"]:
            group["props"].append({"name": "class", "ns": NS, "value": e["class"]})
        for c in e["controls"]:
            cid = token(f"{fw_tok}-{c['id']}") if not c["id"].startswith(e["package"] + "#") else token(f"{fw_tok}-{e['package']}-{c['id'].split('#')[1]}")
            # the statement should be the requirement, not a "flag must be declared" guard: push guards last
            texts = sorted([t for t in c["texts"] if t], key=lambda t: ("must be declared" in t or "cannot be assumed" in t, len(t) < 25)) or [f"Implemented by a Rego rule in {e['file']} (package {e['package']}); see the rule body."]
            if cid in seen:  # same control id in another module of this framework: merge
                ctl = seen[cid]
                prev = next(p["value"] for p in ctl["props"] if p["name"] == "label")
                if prev != c["id"]:
                    raise SystemExit(f"token collision in {fw}: {prev!r} and {c['id']!r} both map to {cid}")
                ctl["links"].append({"href": f"#{res_uuid}", "rel": "implementation"})
                for i, t in enumerate(texts, start=len(ctl["parts"])):
                    ctl["parts"].append({"id": f"{cid}_obj.{i}", "name": "assessment-objective", "prose": t})
                continue
            ctl = {"id": cid, "title": (texts[0][:200] if texts[0] else c["id"]),
                   "props": [{"name": "label", "value": c["id"]}, {"name": "alt-identifier", "value": c["id"]},
                             {"name": "rego-package", "ns": NS, "value": e["package"]}],
                   "links": [{"href": f"#{res_uuid}", "rel": "implementation"}],
                   "parts": [{"id": f"{cid}_stmt", "name": "statement", "prose": texts[0]}]}
            if e["class"]:
                ctl["class"] = e["class"]
            for i, t in enumerate(texts[1:], start=1):
                ctl["parts"].append({"id": f"{cid}_obj.{i}", "name": "assessment-objective", "prose": t})
            seen[cid] = ctl
            group["controls"].append(ctl)
        if group["controls"]:
            groups.append(group)
    title = next((e["title"] for e in entries if e["class"] and e["title"]), fw)
    return {"catalog": {
        "uuid": u5(version, "catalog", fw),
        "metadata": {"title": f"Rego Policy Libraries — {fw} ({title})", "last-modified": stamp, "version": version,
                     "oscal-version": OSCAL_VERSION,
                     "props": [{"name": "framework", "ns": NS, "value": fw},
                               {"name": "generator", "ns": NS, "value": "converters/exports/oscal/build.py"},
                               {"name": "authored-with", "ns": NS, "value": "Claude (Anthropic)"}],
                     "links": [{"href": REPO, "rel": "canonical"}],
                     "parties": [{"uuid": u5("party", "ynotbhatc"), "type": "organization", "name": "Rego Policy Libraries (ynotbhatc)",
                                  "links": [{"href": REPO}]}]},
        "groups": groups,
        "back-matter": {"resources": resources}}}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=None, help="write everything under this directory instead of dist/ + out/")
    a = ap.parse_args()
    version, stamp = version_and_date()
    blob = f"{REPO}/blob/v{version}"
    inv = inventory(ROOT)
    by = {}
    for e in inv:
        by.setdefault(e["framework"], []).append(e)
    dist = pathlib.Path(a.out) / "catalogs" if a.out else HERE / "dist" / "catalogs"
    out = pathlib.Path(a.out) if a.out else HERE / "out"
    dist.mkdir(parents=True, exist_ok=True); out.mkdir(parents=True, exist_ok=True)
    for old in dist.glob("*.json"):
        old.unlink()
    index, all_groups, all_res = [], [], []
    for fw in sorted(by):
        cat = build_catalog(fw, by[fw], version, stamp, blob)
        n = sum(len(g["controls"]) for g in cat["catalog"]["groups"])
        (dist / f"{fw}.json").write_text(json.dumps(cat, indent=1, ensure_ascii=False) + "\n")
        index.append({"framework": fw, "file": f"catalogs/{fw}.json", "controls": n, "modules": len(cat["catalog"]["groups"]),
                      "uuid": cat["catalog"]["uuid"]})
        all_groups.append({"id": token(fw), "class": "framework", "title": cat["catalog"]["metadata"]["title"], "groups": cat["catalog"]["groups"]})
        all_res.extend(cat["catalog"]["back-matter"]["resources"])
    total = sum(i["controls"] for i in index)
    (dist / "index.json").write_text(json.dumps({"version": version, "oscal-version": OSCAL_VERSION, "frameworks": len(index),
                                                "controls": total, "catalogs": index}, indent=1) + "\n")
    combined = {"catalog": {"uuid": u5(version, "catalog", "all"),
                            "metadata": {"title": "Rego Policy Libraries — all frameworks", "last-modified": stamp, "version": version,
                                         "oscal-version": OSCAL_VERSION,
                                         "props": [{"name": "generator", "ns": NS, "value": "converters/exports/oscal/build.py"},
                                                   {"name": "authored-with", "ns": NS, "value": "Claude (Anthropic)"}],
                                         "links": [{"href": REPO, "rel": "canonical"}]},
                            "groups": all_groups, "back-matter": {"resources": all_res}}}
    (out / "all.json").write_text(json.dumps(combined, indent=1, ensure_ascii=False) + "\n")
    print(f"oscal: {len(index)} catalogs, {total} controls, version {version} -> {dist.relative_to(ROOT) if not a.out else dist} ; combined -> {out / 'all.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
