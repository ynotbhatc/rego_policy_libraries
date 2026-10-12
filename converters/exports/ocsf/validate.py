#!/usr/bin/env python3
"""Validate OCSF compliance_finding events (NDJSON or a JSON array) against the vendored class schemas
(schema/compliance_finding-1.9.0[.cloud].schema.json, from https://schema.ocsf.io/schema/classes/compliance_finding?profiles=[cloud];
the one matching each event's metadata.profiles is used).
Needs `jsonschema`. --online additionally posts the first event to https://schema.ocsf.io/api/v2/validate."""
import json, sys, pathlib, urllib.request
HERE = pathlib.Path(__file__).resolve().parent


def load_events(p):
    text = pathlib.Path(p).read_text()
    return json.loads(text) if text.lstrip().startswith("[") else [json.loads(l) for l in text.splitlines() if l.strip()]


def main():
    try:
        import jsonschema
    except ImportError:
        print("SKIP: jsonschema not installed (pip install jsonschema)"); return 2
    def validator(name):
        schema = json.loads((HERE / "schema" / name).read_text())
        return jsonschema.validators.validator_for(schema)(schema)
    # the class schema differs per profile set: events declaring metadata.profiles [cloud] get the cloud schema
    vals = {"": validator("compliance_finding-1.9.0.schema.json"), "cloud": validator("compliance_finding-1.9.0.cloud.schema.json")}
    def val_for(e):
        profiles = sorted(e.get("metadata", {}).get("profiles", []))
        if profiles not in ([], ["cloud"]):
            raise SystemExit(f"no vendored schema for profiles {profiles}")
        return vals["cloud" if profiles else ""]
    files = [a for a in sys.argv[1:] if a != "--online"]
    bad = 0
    for f in files:
        evs = load_events(f)
        errs = []
        for i, e in enumerate(evs):
            for err in val_for(e).iter_errors(e):
                errs.append(f"event {i} /{'/'.join(map(str, err.path))}: {err.message[:160]}")
                if len(errs) >= 5:
                    break
            if len(errs) >= 5:
                break
        if errs:
            bad += 1; print(f"FAIL {f}:"); [print("   ", x) for x in errs]
        else:
            print(f"ok   {f} ({len(evs)} events)")
        if "--online" in sys.argv and evs:
            req = urllib.request.Request("https://schema.ocsf.io/api/v2/validate", data=json.dumps(evs[0]).encode(),
                                         headers={"content-type": "application/json"})
            with urllib.request.urlopen(req, timeout=20) as r:
                res = json.loads(r.read())
            errs_on = res.get("errors", []); warns = res.get("warnings", [])
            print(f"     schema.ocsf.io validate: {len(errs_on)} errors, {len(warns)} warnings" + ("" if not errs_on else " :: " + "; ".join(x.get("message", "") for x in errs_on[:3])))
            if errs_on:
                bad += 1
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
