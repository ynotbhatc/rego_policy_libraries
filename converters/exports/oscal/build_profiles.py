#!/usr/bin/env python3
"""Imported OSCAL 1.2.3 baseline profiles: NIST SP 800-53 Rev 5 (Low / Moderate / High / Privacy) and FedRAMP Rev 5
(Low / Moderate / High / LI-SaaS).

One profile per baseline (dist/profiles/<key>.json, committed). Each is a profile of OUR own that imports the NIST
SP 800-53 Rev 5 catalog (pinned raw URL) and selects exactly the controls the source baseline selects. Nothing else
is carried: no modify / alters / set-parameters, so FedRAMP parameter settings and control alterations are NOT in
these files; they are the control selection only.

Sources are fetched from pinned commits, verified against a pinned sha256 and cached under profiles/cache/
(git-ignored). A cached file whose hash matches is not downloaded again. No network and no cache -> exit 3 with a
one-line "SKIP:" message (the round-trip treats that like a missing jsonschema).

Mapping
  source profile            -> profile (uuid5 of key + library version: stable across builds)
  every with-ids entry      -> import of the NIST catalog, include-controls[0].with-ids, copied verbatim, original order
  source profile + catalog  -> back-matter resources (rlink to the pinned raw URL, source-commit / source-sha256 props)
  source uuid / title / oscal-version / sha256 / commit -> metadata props

Deterministic: version and last-modified come from CHANGELOG.md (same as build.py), uuids from uuid5, so `git diff
dist/` in CI tells whether the committed profiles are stale. `--out DIR` overrides the output root (tests use it).
"""
from __future__ import annotations
import json, sys, hashlib, pathlib, argparse, urllib.request, urllib.error

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(HERE))
from build import NS, REPO, OSCAL_VERSION, u5, version_and_date  # noqa: E402

CACHE = HERE / "profiles" / "cache"

NIST_COMMIT = "78650f02ad9321bb7b817846f8fbd4f2bcd620de"
NIST_BASE = f"https://raw.githubusercontent.com/usnistgov/oscal-content/{NIST_COMMIT}/nist.gov/SP800-53/rev5/json"
FEDRAMP_COMMIT = "76d0473eafe60676d4acbd6cd76362092c389c46"
# GSA/fedramp-automation no longer exists; the OSCAL Compass project mirrors it
FEDRAMP_BASE = f"https://raw.githubusercontent.com/oscal-compass-lab/fedramp-automation/{FEDRAMP_COMMIT}/dist/content/rev5/baselines/json"

CATALOG = {"key": "nist_800_53_rev5_catalog", "title": "NIST SP 800-53 Rev 5 catalog", "kind": "nist",
           "url": f"{NIST_BASE}/NIST_SP-800-53_rev5_catalog.json", "commit": NIST_COMMIT,
           "sha256": "01f37cf90ea99d92242c936cbfbdebcc338eef1f71454e2acac36cc56e9bc062", "source_oscal_version": "1.2.2"}


def _src(key, title, kind, fname, sha, ver):
    base, commit = (NIST_BASE, NIST_COMMIT) if kind == "nist" else (FEDRAMP_BASE, FEDRAMP_COMMIT)
    return {"key": key, "title": title, "kind": kind, "url": f"{base}/{fname}", "commit": commit,
            "sha256": sha, "source_oscal_version": ver}


SOURCES = [
    _src("nist_800_53_rev5_low", "NIST SP 800-53 Rev 5 Low", "nist", "NIST_SP-800-53_rev5_LOW-baseline_profile.json",
         "8fd206017c8d718b44bdef612c2ff321a9fd84d97a515c8ec33c4619accbef6e", "1.2.2"),
    _src("nist_800_53_rev5_moderate", "NIST SP 800-53 Rev 5 Moderate", "nist", "NIST_SP-800-53_rev5_MODERATE-baseline_profile.json",
         "9030dbf1f13169947eb97eb101b4bd2f00d3c151b100455a923ac75803f00ea1", "1.2.2"),
    _src("nist_800_53_rev5_high", "NIST SP 800-53 Rev 5 High", "nist", "NIST_SP-800-53_rev5_HIGH-baseline_profile.json",
         "60576970caef91b2cba56d46e5948b72e3b879434fc2a4840bc4179e5e75cfd7", "1.2.2"),
    _src("nist_800_53_rev5_privacy", "NIST SP 800-53 Rev 5 Privacy", "nist", "NIST_SP-800-53_rev5_PRIVACY-baseline_profile.json",
         "7e650c4397ad633eadeaf510baa523372849b1fa3e18207b6c6b70ed456224f9", "1.2.2"),
    _src("fedramp_rev5_low", "FedRAMP Rev 5 Low", "fedramp", "FedRAMP_rev5_LOW-baseline_profile.json",
         "b13459be3665380b559f10c500310668ce12c2ef71b3c8be997509659988265e", "1.0.4"),
    _src("fedramp_rev5_moderate", "FedRAMP Rev 5 Moderate", "fedramp", "FedRAMP_rev5_MODERATE-baseline_profile.json",
         "5db32cd3c31c3450c03168edd3db26641324c15971edf52163d2310ccdaa925f", "1.0.4"),
    _src("fedramp_rev5_high", "FedRAMP Rev 5 High", "fedramp", "FedRAMP_rev5_HIGH-baseline_profile.json",
         "cce692728b57fae69b25860aba7116426a3637d5b01eb02cd23b13c4eff868f4", "1.0.4"),
    _src("fedramp_rev5_li_saas", "FedRAMP Rev 5 LI-SaaS", "fedramp", "FedRAMP_rev5_LI-SaaS-baseline_profile.json",
         "3d11139325bf0dd23aa3b2185c42ea08f73f6c678c2103dfc75dad4728d353f7", "1.0.4"),
]


def cached_path(cache_dir, src):
    return pathlib.Path(cache_dir) / src["url"].rsplit("/", 1)[1]


def fetch(cache_dir=CACHE):
    """Download (or reuse) every source plus the NIST catalog; verify sha256. Returns {key: Path}.
    Exit 3 with a SKIP line when the network is unavailable and a file is not cached."""
    cache_dir = pathlib.Path(cache_dir)
    cache_dir.mkdir(parents=True, exist_ok=True)
    got = {}
    for src in SOURCES + [CATALOG]:
        dest = cached_path(cache_dir, src)
        if dest.exists() and hashlib.sha256(dest.read_bytes()).hexdigest() == src["sha256"]:
            got[src["key"]] = dest
            continue
        try:
            with urllib.request.urlopen(src["url"], timeout=60) as r:
                data = r.read()
        except (urllib.error.URLError, OSError) as ex:
            print(f"SKIP: {src['url'].rsplit('/', 1)[1]} is not cached and the network is unavailable ({ex})")
            sys.exit(3)
        digest = hashlib.sha256(data).hexdigest()
        if digest != src["sha256"]:
            raise SystemExit(f"sha256 mismatch for {src['url']}: expected {src['sha256']}, got {digest}")
        dest.write_bytes(data)
        got[src["key"]] = dest
    return got


def with_ids(profile):
    """Every with-ids entry across the profile's imports, in source order."""
    return [i for imp in profile["imports"] for ic in imp.get("include-controls", []) for i in ic.get("with-ids", [])]


def build_profile(src, source_doc, version, stamp):
    sp = source_doc["profile"]
    ids = with_ids(sp)
    if not ids:
        raise SystemExit(f"{src['key']}: source profile selects no controls")
    cat_res, src_res = u5(version, "resource", "catalog"), u5(version, "resource", "source", src["key"])
    return {"profile": {
        "uuid": u5(version, "profile", src["key"]),
        "metadata": {"title": f"Rego Policy Libraries — {src['title']} (imported baseline)", "last-modified": stamp, "version": version,
                     "oscal-version": OSCAL_VERSION,
                     "props": [{"name": "framework", "ns": NS, "value": src["key"]},
                               {"name": "source-url", "ns": NS, "value": src["url"]},
                               {"name": "source-commit", "ns": NS, "value": src["commit"]},
                               {"name": "source-sha256", "ns": NS, "value": src["sha256"]},
                               {"name": "source-oscal-version", "ns": NS, "value": sp["metadata"]["oscal-version"]},
                               {"name": "source-uuid", "ns": NS, "value": sp["uuid"]},
                               {"name": "source-title", "ns": NS, "value": sp["metadata"]["title"]},
                               {"name": "generator", "ns": NS, "value": "converters/exports/oscal/build_profiles.py"},
                               {"name": "authored-with", "ns": NS, "value": "Claude (Anthropic)"}],
                     "links": [{"href": REPO, "rel": "canonical"}],
                     "remarks": "Control selection only. FedRAMP parameter settings and control alterations (modify / set-parameters / alters) "
                                "are not carried from the source profile; this profile imports the NIST SP 800-53 Rev 5 catalog and selects "
                                "the same controls."},
        "imports": [{"href": CATALOG["url"], "include-controls": [{"with-ids": ids}]}],
        "merge": {"as-is": True},
        "back-matter": {"resources": [
            {"uuid": src_res, "title": sp["metadata"]["title"],
             "props": [{"name": "source-commit", "ns": NS, "value": src["commit"]},
                       {"name": "source-sha256", "ns": NS, "value": src["sha256"]}],
             "rlinks": [{"href": src["url"], "media-type": "application/json"}]},
            {"uuid": cat_res, "title": CATALOG["title"],
             "props": [{"name": "source-commit", "ns": NS, "value": CATALOG["commit"]},
                       {"name": "source-sha256", "ns": NS, "value": CATALOG["sha256"]}],
             "rlinks": [{"href": CATALOG["url"], "media-type": "application/json"}]}]}}}, len(ids)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=None, help="write profiles under this directory instead of dist/")
    ap.add_argument("--cache", default=str(CACHE), help="source cache directory")
    a = ap.parse_args()
    version, stamp = version_and_date()
    files = fetch(a.cache)
    dist = pathlib.Path(a.out) / "profiles" if a.out else HERE / "dist" / "profiles"
    dist.mkdir(parents=True, exist_ok=True)
    for old in dist.glob("*.json"):
        old.unlink()
    index, total = [], 0
    for src in sorted(SOURCES, key=lambda s: s["key"]):
        prof, n = build_profile(src, json.loads(files[src["key"]].read_text()), version, stamp)
        (dist / f"{src['key']}.json").write_text(json.dumps(prof, indent=1, ensure_ascii=False) + "\n")
        index.append({"key": src["key"], "file": f"profiles/{src['key']}.json", "uuid": prof["profile"]["uuid"],
                      "title": prof["profile"]["metadata"]["title"], "kind": src["kind"], "controls": n,
                      "source_url": src["url"], "source_commit": src["commit"]})
        total += n
    (dist / "index.json").write_text(json.dumps({"oscal-version": OSCAL_VERSION, "profiles": index}, indent=1) + "\n")
    print(f"oscal profiles: {len(index)} baselines, {total} control selections -> {dist.relative_to(ROOT) if not a.out else dist}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
