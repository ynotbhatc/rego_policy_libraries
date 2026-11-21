#!/usr/bin/env python3
"""Check standards.yaml against the modules (--offline) or against upstream release sources.

--offline (CI, no network):
  * every `custom.framework` key in the policy trees has an entry in standards.yaml, and every entry is a live key;
  * every standard with a known version carries a `literal` that contains the version and appears in a non-test
    .rego file of that key's directories, so the registry cannot drift from the module text;
  * every check names a known method with its required fields.
  Versions marked "unknown" are listed as warnings for a human to settle; they do not fail.

Network mode (monthly job): runs each check once and prints, per standard, one of
  newer    an upstream release newer than the implemented version (or a change since `checked_through`)
  review   the source moved but the result needs a human (an unversioned module, a new commit)
  current  nothing newer found
  manual   no machine-readable source; the watch URL is listed for the human sweep
  failed   the source could not be read or parsed — never treated as current
Exit codes: 0 all current/manual, 1 something newer or to review, 2 a check failed, 3 offline validation failed.

Methods (standards.yaml `check.method`):
  oscal_catalog   url                   NIST OSCAL catalog JSON, compares metadata.version (or check.implemented)
  github_release  repo                  latest GitHub release tag vs the version (or check.implemented)
  github_commit   repo [since]          HEAD commit vs the version (sha prefix), or any commit after `since`
  disa_stig_zip   stem                  probes <stem>_V<v>R<r+1>/_V<v+1>R1 _STIG.zip on dl.dod.cyber.mil
  disa_dated_zip  stem released         probes <stem>_Y<yy>M<mm>_STIG.zip for months after `released`
  ecfr            title parts checked_through   eCFR versioner API: amendment dates after checked_through
  page_regex      url pattern [known]   captures versions on a page; newer = greater than implemented, or (with
                                        `known`) any capture not listed
  manual / none   url [note]            listed only
  family          cis | disa            the shared family check in `families:`

Usage: python3 scripts/check_standard_releases.py [--offline] [--registry standards.yaml] [--json OUT] [--only KEY,...]
No credentials are read or sent. Set GITHUB_TOKEN only if the runner provides one (raises the API rate limit).
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

UA = "rego_policy_libraries-standards-check/1.0 (+https://github.com/ynotbhatc/rego_policy_libraries)"
TIMEOUT = 30
DISA_ZIP = "https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/"
MONTHS = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October",
          "November", "December"]
METHODS = {
    "oscal_catalog": ["url"], "github_release": ["repo"], "github_commit": ["repo"], "disa_stig_zip": ["stem"],
    "disa_dated_zip": ["stem", "released"], "ecfr": ["title", "parts", "checked_through"],
    "page_regex": ["url", "pattern"], "manual": [], "none": [],
}
FAMILY_METHODS = {"cis_monthly": ["url", "checked_against"], "disa_compilation": ["checked_against"]}
POLICY_TREES = ("benchmarks", "frameworks", "governance", "enforcement", "threat_detection", "crosswalk")


def load_registry(path: Path) -> dict:
    import yaml  # PyYAML ships on the GitHub runners and is already used by the opa-test job

    with path.open(encoding="utf-8") as fh:
        return yaml.safe_load(fh)


# ------------------------------------------------------------------ offline validation

def key_dirs() -> dict[str, set[Path]]:
    """{framework key: directories of the files whose package METADATA names that key}."""
    import json as _json
    import subprocess

    out: dict[str, set[Path]] = {}
    for tree in POLICY_TREES:
        if not (ROOT / tree).is_dir():
            continue
        res = subprocess.run(["opa", "inspect", "-a", "-f", "json", tree], cwd=ROOT, capture_output=True, text=True)
        if res.returncode != 0:
            sys.exit(f"opa inspect failed on {tree}:\n{res.stderr}")
        for ann in _json.loads(res.stdout).get("annotations") or []:
            a = ann.get("annotations", {})
            if a.get("scope") != "package":
                continue
            fw = (a.get("custom") or {}).get("framework")
            if isinstance(fw, str):
                out.setdefault(fw, set()).add((ROOT / ann["location"]["file"]).parent)
    return out


def is_test(p: Path) -> bool:
    return p.name.startswith("test_") or p.name.endswith("_test.rego") or "tests" in p.parts


def module_text(dirs: set[Path]) -> str:
    chunks = []
    for d in sorted(dirs):
        for f in sorted(d.glob("*.rego")):
            if not is_test(f):
                chunks.append(f.read_text(encoding="utf-8", errors="replace"))
    return "\n".join(chunks)


def bare(v: str) -> str:
    return re.sub(r"^v(?=\d)", "", str(v).strip())


def validate(reg: dict) -> tuple[list[str], list[str]]:
    errs: list[str] = []
    warns: list[str] = []
    fams = reg.get("families") or {}
    for name, fam in fams.items():
        m = fam.get("method")
        if m not in FAMILY_METHODS:
            errs.append(f"families.{name}: unknown method {m!r}")
            continue
        errs += [f"families.{name}: missing {f}" for f in FAMILY_METHODS[m] if not fam.get(f)]
    entries = reg.get("frameworks") or {}
    live = key_dirs()
    for k in sorted(set(live) - set(entries)):
        errs.append(f"{k}: framework key in the modules has no entry in standards.yaml")
    for k in sorted(set(entries) - set(live)):
        errs.append(f"{k}: entry in standards.yaml but no module declares custom.framework: {k}")
    for k, e in sorted(entries.items()):
        if k not in live:
            continue
        if not isinstance(e, dict):
            errs.append(f"{k}: entry must be a mapping")
            continue
        if e.get("internal") is True:
            if e.get("standards"):
                errs.append(f"{k}: internal entries carry no standards")
            continue
        stds = e.get("standards")
        if not isinstance(stds, list) or not stds:
            errs.append(f"{k}: needs `standards:` (or `internal: true`)")
            continue
        text = None
        for i, s in enumerate(stds):
            where = f"{k}.standards[{i}]"
            for f in ("standard", "version", "publisher", "check"):
                if not s.get(f):
                    errs.append(f"{where}: missing {f}")
            for f in ("version", "literal"):
                if f in s and not isinstance(s[f], str):
                    errs.append(f"{where}: {f} must be a quoted string (YAML read {s[f]!r} as {type(s[f]).__name__})")
            ver = str(s.get("version", ""))
            if ver == "unknown":
                warns.append(f"{where}: {s.get('standard')} — version not stated in the module")
            else:
                lit = s.get("literal")
                if not lit:
                    errs.append(f"{where}: version {ver!r} needs a `literal` found in the module text")
                else:
                    if ver != "current" and bare(ver) not in str(lit):
                        errs.append(f"{where}: version {ver!r} is not part of literal {lit!r}")
                    if text is None:
                        text = module_text(live[k])
                    if str(lit) not in text:
                        errs.append(f"{where}: literal {lit!r} not found in {k}'s module files")
            chk = s.get("check") or {}
            if "family" in chk:
                if chk["family"] not in fams:
                    errs.append(f"{where}: unknown family {chk['family']!r}")
                continue
            m = chk.get("method")
            if m not in METHODS:
                errs.append(f"{where}: unknown check method {m!r}")
                continue
            errs += [f"{where}: check.{f} missing" for f in METHODS[m] if not chk.get(f)]
            errs += [f"{where}: check.{f} must be a quoted string" for f in ("checked_through", "released", "since",
                     "implemented") if f in chk and not isinstance(chk[f], str)]
            if m == "page_regex":
                try:
                    if re.compile(chk["pattern"]).groups != 1:
                        errs.append(f"{where}: check.pattern needs exactly one capture group")
                except re.error as exc:
                    errs.append(f"{where}: check.pattern does not compile: {exc}")
    return errs, warns


# ------------------------------------------------------------------ network checks

class CheckFailed(Exception):
    pass


def fetch(url: str, *, method: str = "GET", accept: str | None = None) -> tuple[int, bytes]:
    headers = {"User-Agent": UA}
    if accept:
        headers["Accept"] = accept
    if "api.github.com" in url and os.environ.get("GITHUB_TOKEN"):
        headers["Authorization"] = f"Bearer {os.environ['GITHUB_TOKEN']}"
    req = urllib.request.Request(url, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return resp.status, (resp.read() if method == "GET" else b"")
    except urllib.error.HTTPError as exc:
        return exc.code, b""
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise CheckFailed(f"{url}: {exc}") from exc


def get_ok(url: str, **kw) -> bytes:
    code, body = fetch(url, **kw)
    if code != 200:
        raise CheckFailed(f"{url}: HTTP {code}")
    return body


def exists(url: str) -> bool:
    code, _ = fetch(url, method="HEAD")
    if code in (200, 404, 403):
        return code == 200
    raise CheckFailed(f"{url}: HTTP {code}")


def vkey(v: str) -> tuple:
    m = re.fullmatch(r"V(\d+)R(\d+)", str(v).strip())
    if m:
        return (int(m.group(1)), int(m.group(2)))
    return tuple(int(x) for x in re.findall(r"\d+", str(v))) or (0,)


def r(status: str, detail: str, latest: str | None = None) -> dict:
    return {"status": status, "detail": detail, "latest": latest}


def chk_oscal(c: dict, impl: str) -> dict:
    try:
        latest = json.loads(get_ok(c["url"]))["catalog"]["metadata"]["version"]
    except (KeyError, ValueError) as exc:
        raise CheckFailed(f"{c['url']}: no catalog.metadata.version ({exc})") from exc
    if vkey(latest) > vkey(impl):
        return r("newer", f"catalog version {latest} > {impl}", latest)
    return r("current", f"catalog version {latest}", latest)


def chk_github_release(c: dict, impl: str) -> dict:
    url = f"https://api.github.com/repos/{c['repo']}/releases/latest"
    code, body = fetch(url, accept="application/vnd.github+json")
    if code == 404:  # repo publishes tags only
        tags = json.loads(get_ok(f"https://api.github.com/repos/{c['repo']}/tags?per_page=1"))
        if not tags:
            raise CheckFailed(f"{c['repo']}: no releases or tags")
        tag, when = tags[0]["name"], ""
    elif code == 200:
        d = json.loads(body)
        tag, when = d["tag_name"], (d.get("published_at") or "")[:10]
    else:
        raise CheckFailed(f"{url}: HTTP {code}")
    if impl == "unknown":
        return r("review", f"latest release {tag} {when}; module pins no release", tag)
    if vkey(tag) > vkey(impl):
        return r("newer", f"release {tag} ({when}) > {impl}", tag)
    return r("current", f"latest release {tag}", tag)


def chk_github_commit(c: dict, impl: str) -> dict:
    d = json.loads(get_ok(f"https://api.github.com/repos/{c['repo']}/commits?per_page=1",
                          accept="application/vnd.github+json"))
    if not d:
        raise CheckFailed(f"{c['repo']}: no commits")
    sha, when = d[0]["sha"], d[0]["commit"]["committer"]["date"][:10]
    if c.get("since"):
        if when > c["since"]:
            return r("review", f"commits after {c['since']} (HEAD {sha[:8]}, {when})", sha[:8])
        return r("current", f"HEAD {sha[:8]} ({when})", sha[:8])
    if sha.startswith(impl):
        return r("current", f"HEAD is {impl}", sha[:8])
    return r("review", f"HEAD {sha[:8]} ({when}) differs from imported {impl}", sha[:8])


def chk_disa_zip(c: dict, impl: str) -> dict:
    m = re.fullmatch(r"V(\d+)R(\d+)", impl)
    if not m:
        raise CheckFailed(f"version {impl!r} is not VxRy")
    v, rel = int(m.group(1)), int(m.group(2))
    name = lambda vv, rr: f"{DISA_ZIP}{c['stem']}_V{vv}R{rr}_STIG.zip"  # noqa: E731
    have = exists(name(v, rel))
    # DISA withdraws superseded zips, so probe a few releases ahead (gaps happen) and the next major version
    later = [(v, rr) for rr in range(rel + 1, rel + 6)] + [(v + 1, 1), (v + 1, 2)]
    found = [f"V{vv}R{rr}" for vv, rr in later if exists(name(vv, rr))]
    if found:
        gone = "; implemented zip withdrawn" if not have else ""
        return r("newer", f"{c['stem']}_{found[-1]}_STIG.zip published (implemented {impl}{gone})", found[-1])
    if not have:
        raise CheckFailed(f"{name(v, rel)} not found and no later release: wrong stem, or the STIG left the library")
    return r("current", f"no release after {impl}", impl)


def month_iter(start: dt.date, end: dt.date):
    y, m = start.year, start.month
    while (y, m) <= (end.year, end.month):
        yield y, m
        y, m = (y + 1, 1) if m == 12 else (y, m + 1)


def chk_disa_dated(c: dict, impl: str) -> dict:
    y, m = (int(x) for x in str(c["released"]).split("-"))
    name = lambda yy, mm: f"{DISA_ZIP}{c['stem']}_Y{yy % 100:02d}M{mm:02d}_STIG.zip"  # noqa: E731
    have = exists(name(y, m))
    start = dt.date(y + (m == 12), m % 12 + 1, 1)
    newest = None
    for yy, mm in month_iter(start, dt.date.today()):
        if exists(name(yy, mm)):
            newest = f"{yy}-{mm:02d}"
    if newest:
        gone = "; implemented bundle withdrawn" if not have else ""
        return r("newer", f"{c['stem']} bundle dated {newest} published (implemented {impl}, {c['released']}{gone})",
                 newest)
    if not have:
        raise CheckFailed(f"{name(y, m)} not found and no later bundle: wrong stem or release month")
    return r("current", f"no bundle after {c['released']}", c["released"])


def chk_ecfr(c: dict, impl: str) -> dict:
    newest = ""
    for part in c["parts"]:
        url = f"https://www.ecfr.gov/api/versioner/v1/versions/title-{c['title']}.json?part={part}"
        try:
            vers = json.loads(get_ok(url, accept="application/json")).get("content_versions") or []
        except ValueError as exc:
            raise CheckFailed(f"{url}: bad JSON") from exc
        if not vers:
            raise CheckFailed(f"{url}: no versions")
        newest = max([newest] + [v["amendment_date"] for v in vers])
    if newest > str(c["checked_through"]):
        return r("newer", f"{c['title']} CFR {c['parts']} amended {newest} (reviewed through {c['checked_through']})",
                 newest)
    return r("current", f"last amendment {newest}", newest)


def chk_page_regex(c: dict, impl: str) -> dict:
    text = get_ok(c["url"]).decode("utf-8", errors="replace")
    caps = sorted(set(re.findall(c["pattern"], text)), key=vkey)
    if not caps:
        raise CheckFailed(f"{c['url']}: pattern matched nothing (page changed or blocked)")
    if c.get("known"):
        new = [x for x in caps if x not in {str(k) for k in c["known"]} and bare(x) != bare(impl)]
    else:
        new = [x for x in caps if vkey(x) > vkey(impl)]
    if new:
        return r("newer", f"page names {', '.join(new)} (implemented {impl})", new[-1])
    return r("current", f"page names {', '.join(caps)}", caps[-1])


def chk_cis_monthly(fam: dict) -> dict:
    text = get_ok(fam["url"]).decode("utf-8", errors="replace")
    posts = set(re.findall(r"CIS Benchmarks ((?:%s) \d{4}) Update" % "|".join(MONTHS), text))
    if not posts:
        raise CheckFailed(f"{fam['url']}: no 'CIS Benchmarks <Month> <Year> Update' post found")
    key = lambda s: (int(s.split()[1]), MONTHS.index(s.split()[0]))  # noqa: E731
    latest = max(posts, key=key)
    if key(latest) > key(fam["checked_against"]):
        return r("newer", f"'CIS Benchmarks {latest} Update' published (rows checked against {fam['checked_against']})",
                 latest)
    return r("current", f"latest monthly update {latest}", latest)


def chk_disa_compilation(fam: dict) -> dict:
    mon, yr = fam["checked_against"].split()
    start = dt.date(int(yr), MONTHS.index(mon) + 1, 1)
    url = lambda y, m: f"{DISA_ZIP}U_SRG-STIG_Library_{MONTHS[m - 1]}_{y}.zip"  # noqa: E731
    if not exists(url(start.year, start.month)):
        raise CheckFailed(f"{url(start.year, start.month)} not found")
    newest = None
    for y, m in list(month_iter(start, dt.date.today()))[1:]:
        if exists(url(y, m)):
            newest = f"{MONTHS[m - 1]} {y}"
    if newest:
        return r("newer", f"U_SRG-STIG_Library {newest} published (checked against {fam['checked_against']})", newest)
    return r("current", f"no compilation after {fam['checked_against']}", fam["checked_against"])


RUNNERS = {
    "oscal_catalog": chk_oscal, "github_release": chk_github_release, "github_commit": chk_github_commit,
    "disa_stig_zip": chk_disa_zip, "disa_dated_zip": chk_disa_dated, "ecfr": chk_ecfr, "page_regex": chk_page_regex,
}


def run_checks(reg: dict, only: set[str] | None) -> list[dict]:
    results: list[dict] = []
    fams = reg.get("families") or {}
    for name, fam in fams.items():
        try:
            res = (chk_cis_monthly if fam["method"] == "cis_monthly" else chk_disa_compilation)(fam)
        except CheckFailed as exc:
            res = r("failed", str(exc))
        results.append({"key": f"family:{name}", "standard": name, "version": fam.get("checked_against"), **res})
    for k, e in sorted((reg.get("frameworks") or {}).items()):
        if (only and k not in only) or e.get("internal"):
            continue
        for s in e.get("standards") or []:
            c = s.get("check") or {}
            impl = str(c.get("implemented", s.get("version")))
            if "family" in c:
                continue  # reported once by the family row
            m = c.get("method")
            if m in ("manual", "none"):
                res = r("manual", c.get("url", "") or c.get("note", ""))
            else:
                try:
                    res = RUNNERS[m](c, impl)
                except CheckFailed as exc:
                    res = r("failed", str(exc))
                except Exception as exc:  # a parser surprise is a failed check, never a pass
                    res = r("failed", f"{type(exc).__name__}: {exc}")
            results.append({"key": k, "standard": s.get("standard"), "version": s.get("version"), **res})
    return results


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--registry", default=str(ROOT / "standards.yaml"))
    ap.add_argument("--offline", action="store_true", help="validate the registry against the modules; no network")
    ap.add_argument("--json", help="write results to this file")
    ap.add_argument("--quiet", action="store_true", help="--offline: do not print the unknown-version warnings")
    ap.add_argument("--only", help="comma-separated framework keys (network mode)")
    args = ap.parse_args()
    reg = load_registry(Path(args.registry))

    if args.offline:
        errs, warns = validate(reg)
        for w in [] if args.quiet else warns:
            print(f"warning: {w}")
        for e in errs:
            print(f"error: {e}")
        n = len(reg.get("frameworks") or {})
        if errs:
            print(f"standards.yaml: {len(errs)} error(s) — fix the entry or the module text (see STANDARDS_UPDATE_REGISTRY.md)")
            return 3
        print(f"standards.yaml matches the modules: {n} keys, {len(warns)} version(s) unknown")
        return 0

    results = run_checks(reg, set(args.only.split(",")) if args.only else None)
    order = {"newer": 0, "review": 1, "failed": 2, "current": 3, "manual": 4}
    for x in sorted(results, key=lambda x: (order[x["status"]], x["key"])):
        if x["status"] != "manual":
            print(f"{x['status']:8} {x['key']:34} {x['standard']} [{x['version']}] — {x['detail']}")
    counts = {s: sum(1 for x in results if x["status"] == s) for s in order}
    print("summary: " + ", ".join(f"{v} {k}" for k, v in counts.items()))
    if args.json:
        Path(args.json).write_text(json.dumps({"generated": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
                                               "results": results}, indent=1, default=str) + "\n", encoding="utf-8")
    if counts["failed"]:
        return 2
    return 1 if counts["newer"] or counts["review"] else 0


if __name__ == "__main__":
    sys.exit(main())
