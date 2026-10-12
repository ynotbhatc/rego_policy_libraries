#!/usr/bin/env python3
"""OSCAL 1.2.3 component-definition: the library as one software component whose implemented-requirements
point at every control in the per-framework catalogs (dist/catalogs/<framework>.json).

One control-implementation per framework (source = that catalog's raw URL at the release tag), one
implemented-requirement per control, each saying which Rego package and file evaluates it. Deterministic
(uuid5, version and date from CHANGELOG) so `git diff dist/` in CI says whether it is stale.

    python3 build_component.py [--out DIR]     # default: dist/component-definition.json
"""
from __future__ import annotations
import json, sys, pathlib, argparse, uuid
HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from build import version_and_date, u5, NS, REPO, OSCAL_VERSION  # noqa: E402

RAW = f"{REPO}/raw/v{{v}}/converters/exports/oscal/dist/catalogs/{{fw}}.json"


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--out", default=None); ap.add_argument("--catalogs", default=None)
    a = ap.parse_args()
    version, stamp = version_and_date()
    cat_dir = pathlib.Path(a.catalogs) if a.catalogs else HERE / "dist" / "catalogs"
    out = pathlib.Path(a.out) if a.out else HERE / "dist"
    out.mkdir(parents=True, exist_ok=True)
    index = json.loads((cat_dir / "index.json").read_text())
    impls, total = [], 0
    for row in index["catalogs"]:
        fw = row["framework"]
        cat = json.loads((cat_dir / f"{fw}.json").read_text())["catalog"]
        reqs = []
        for g in cat["groups"]:
            pkg = next(p["value"] for p in g["props"] if p["name"] == "rego-package")
            fil = next(p["value"] for p in g["props"] if p["name"] == "rego-file")
            for c in g["controls"]:
                label = next(p["value"] for p in c["props"] if p["name"] == "label")
                reqs.append({"uuid": u5(version, "impl-req", fw, c["id"]), "control-id": c["id"],
                             "description": f"Evaluated by Rego package {pkg} ({fil}): {c['parts'][0]['prose']}",
                             "props": [{"name": "label", "value": label},
                                       {"name": "rego-package", "ns": NS, "value": pkg},
                                       {"name": "rego-file", "ns": NS, "value": fil},
                                       {"name": "implementation-status", "value": "implemented"}]})
        total += len(reqs)
        impls.append({"uuid": u5(version, "control-impl", fw), "source": RAW.format(v=version, fw=fw),
                      "description": f"Controls of {fw} evaluated by the Rego Policy Libraries ({len(reqs)} controls, {row['modules']} Rego modules).",
                      "props": [{"name": "framework", "ns": NS, "value": fw}],
                      "implemented-requirements": reqs})
    doc = {"component-definition": {
        "uuid": u5(version, "component-definition"),
        "metadata": {"title": "Rego Policy Libraries — component definition", "last-modified": stamp, "version": version,
                     "oscal-version": OSCAL_VERSION,
                     "props": [{"name": "generator", "ns": NS, "value": "converters/exports/oscal/build_component.py"},
                               {"name": "authored-with", "ns": NS, "value": "Claude (Anthropic)"}],
                     "links": [{"href": REPO, "rel": "canonical"}]},
        "components": [{"uuid": u5(version, "component", "library"), "type": "software", "title": "Rego Policy Libraries",
                        "description": f"Open Policy Agent (Rego) compliance and security policy library, version {version}: evaluates the controls in the referenced catalogs from machine-collected facts and emits a compliance_report per framework.",
                        "purpose": "Automated evaluation of the referenced controls; produces OSCAL assessment-results, SARIF and OCSF findings.",
                        "props": [{"name": "version", "value": version}, {"name": "license", "ns": NS, "value": "Apache-2.0"}],
                        "links": [{"href": REPO, "rel": "canonical"}],
                        "responsible-roles": [{"role-id": "maintainer", "party-uuids": [u5("party", "ynotbhatc")]}],
                        "control-implementations": impls}],
        "back-matter": {"resources": []}}}
    doc["component-definition"]["metadata"]["roles"] = [{"id": "maintainer", "title": "Maintainer"}]
    doc["component-definition"]["metadata"]["parties"] = [{"uuid": u5("party", "ynotbhatc"), "type": "organization", "name": "Rego Policy Libraries (ynotbhatc)"}]
    del doc["component-definition"]["back-matter"]
    (out / "component-definition.json").write_text(json.dumps(doc, indent=1, ensure_ascii=False) + "\n")
    print(f"oscal component-definition: {len(impls)} control-implementations, {total} implemented-requirements -> {out / 'component-definition.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
