#!/usr/bin/env python3
"""Validate SARIF files against the vendored SARIF 2.1.0 schema (schema/sarif-2.1.0.json). Needs `jsonschema`."""
import json, sys, pathlib
HERE = pathlib.Path(__file__).resolve().parent


def validate_doc(doc, _cache={}):
    """Schema errors (up to 5) for one SARIF document, [] when it validates. Raises ImportError without jsonschema."""
    import jsonschema
    if "v" not in _cache:
        schema = json.loads((HERE / "schema" / "sarif-2.1.0.json").read_text())
        _cache["v"] = jsonschema.validators.validator_for(schema)(schema)
    return [f"/{'/'.join(map(str, e.path))}: {e.message[:200]}" for e in sorted(_cache["v"].iter_errors(doc), key=lambda e: list(e.path))[:5]]


def main():
    try:
        import jsonschema
    except ImportError:
        print("SKIP: jsonschema not installed (pip install jsonschema)"); return 2
    schema = json.loads((HERE / "schema" / "sarif-2.1.0.json").read_text())
    val = jsonschema.validators.validator_for(schema)(schema)
    bad = 0
    for f in sys.argv[1:]:
        errs = sorted(val.iter_errors(json.loads(pathlib.Path(f).read_text())), key=lambda e: list(e.path))[:5]
        if errs:
            bad += 1
            for e in errs:
                print(f"FAIL {f}: /{'/'.join(map(str, e.path))}: {e.message[:200]}")
        else:
            print(f"ok   {f}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
