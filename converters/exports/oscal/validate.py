#!/usr/bin/env python3
"""Validate OSCAL JSON files against the vendored NIST schemas (schema/, OSCAL v1.2.3).

Needs the `jsonschema` package. The NIST schemas use \\p{L}/\\p{N} in token patterns, which Python's re does
not know; they are narrowed to ASCII classes here, which is stricter than the spec and fine for our ids.

Usage: python3 validate.py <file.json>...   (model picked from the top-level key: catalog / component-definition / assessment-results / profile)
"""
import json, sys, pathlib
HERE = pathlib.Path(__file__).resolve().parent
MODELS = {"catalog": "oscal_catalog_schema.json", "component-definition": "oscal_component_schema.json",
          "assessment-results": "oscal_assessment-results_schema.json",
          "profile": "oscal_profile_schema.json"}


def load_schema(name):
    raw = (HERE / "schema" / name).read_text().replace("\\\\p{L}", "[A-Za-z]").replace("\\\\p{N}", "[0-9]")
    return json.loads(raw)


def main():
    try:
        import jsonschema
    except ImportError:
        print("SKIP: jsonschema not installed (pip install jsonschema)"); return 2
    bad = 0
    cache = {}
    for f in sys.argv[1:]:
        doc = json.loads(pathlib.Path(f).read_text())
        model = next(iter(doc))
        if model not in MODELS:
            print(f"skip {f} (top-level key {model!r} is not an OSCAL model; index and summary files are not validated)"); continue
        if model not in cache:
            cache[model] = jsonschema.validators.validator_for(load_schema(MODELS[model]))(load_schema(MODELS[model]))
        errs = sorted(cache[model].iter_errors(doc), key=lambda e: list(e.path))[:5]
        if errs:
            bad += 1
            for e in errs:
                print(f"FAIL {f}: /{'/'.join(map(str, e.path))}: {e.message[:200]}")
        else:
            print(f"ok   {f} ({model})")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
