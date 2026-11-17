#!/usr/bin/env python3
"""CIS Debian Linux 13 Benchmark v1.1.1: every recommendation, from the benchmark's own workbook.

    python3 tools/cis_generators/gen_debian_13.py CIS_Debian_Linux_13_Benchmark_v1.1.1.xlsx [fields.json]

Needs openpyxl, and opa on PATH (the output is passed through `opa fmt`). Emits benchmarks/cis/debian_13/: one package per benchmark section (cis_debian_13.<section>),
the roll-up package cis_debian_13 and the bridge cis_debian_13.main (compliance_report), plus tests.

The Debian 13 v1.1.1 workbook carries the same 350 recommendation ids, Automated/Manual statuses and
profiles as Ubuntu 26.04 LTS v1.0.0, and the audit procedures agree except where listed below. So this
script imports gen_ubuntu_26_04.py (reader, builders, logic table, emitters; it is import-safe and is not
modified), replaces the entries that differ, and re-runs every workbook check against the Debian workbook:
count, Automated/Manual split, per-profile counts, the id set, the status of each id, a title keyword per
logic entry and the ids without a Workstation profile. Any mismatch aborts, so logic cannot attach to a
renumbered or re-scoped recommendation in a later workbook.

Differences from the Ubuntu 26.04 logic:
  * 6.2.3.2: the audit names execve AND execveat, for both arch=b32 and arch=b64;
  * 1.6.1-1.6.5: the banner checks reject the os-release ID, which is "debian" here;
  * the report carries violation_count (the library contract) beside the reference module's keys;
  * test fixtures name Debian paths and repositories.

Input fact contract: the ubuntu_26_04 module's, unchanged (no new input paths), so one collector feeds both.
Messages are our words (neutralize.publish_titles); the benchmark title is never written out.
"""
import json
import pathlib
import re
import subprocess
import sys

import gen_ubuntu_26_04 as ref

HERE = pathlib.Path(__file__).resolve().parent
OUT = HERE.parent.parent / "benchmarks" / "cis" / "debian_13"
PKG = "cis_debian_13"
GEN = "tools/cis_generators/gen_debian_13.py"
BENCH = "CIS Debian Linux 13 Benchmark v1.1.1"
VERSION = "v1.1.1"
EXPECTED_TOTAL, EXPECTED_AUTOMATED, EXPECTED_MANUAL = 350, 333, 17
# recommendations applicable to each profile (a Level 2 profile includes Level 1 of the same platform)
EXPECTED_PROFILE = {"level1_server": 274, "level2_server": 350, "level1_workstation": 265, "level2_workstation": 347}
# Server-only recommendations; the roll-up header names them
SERVER_ONLY = ["1.6.12", "2.1.21", "3.1.2"]

REF_PKG = "cis_ubuntu_26_04"
REF_GEN = "tools/cis_generators/gen_ubuntu_26_04.py"
REF_GEN_NAME = "gen_ubuntu_26_04.py"
REF_VERSION_LINE = '"version": "v1.0.0",'
REF_DOMAINS = "domains: [linux, ubuntu]"

# ── the reference generator's module globals, pointed at this benchmark ────────────────────────
ref.BENCH = BENCH
ref.SKIP_SHEETS = set(ref.SKIP_SHEETS) | {"Overview"}
ref.EXPECTED_MANUAL = EXPECTED_MANUAL

# ── logic that differs ─────────────────────────────────────────────────────────
# 6.2.3.2: both syscalls, each on both architectures.
ref.L["6.2.3.2"] = ref.audit(syscalls=[(["execve", "execveat"], ["euid"])], arches=True)
ref.KW["6.2.3.2"] = "another user"

# 1.6.1-1.6.5: OS/version escapes (\m \r \s \v) or the os-release ID.
SYSINFO = "(?i)(\\\\[mrsv]|\\bdebian\\b)"
# (old, new) applied to every string of the logic entries: rego lines and test fixtures
SWAPS = [
    (json.dumps(ref.SYSINFO), json.dumps(SYSINFO)),
    ("Welcome to Ubuntu 26.04 LTS", "Welcome to Debian GNU/Linux 13"),
    ("Ubuntu 26.04 LTS \\n \\l", "Debian GNU/Linux 13 \\n \\l"),
    ("Ubuntu 26.04 \\r", "Debian GNU/Linux 13 \\r"),
    ("archive.example.com/ubuntu resolute main", "deb.example.com/debian trixie main"),
    ("archive.example.com/ubuntu", "deb.example.com/debian"),
    ("ubuntu-archive-keyring.gpg", "debian-archive-keyring.gpg"),
    ("/etc/apt/sources.list.d/ubuntu.sources", "/etc/apt/sources.list.d/debian.sources"),
]
# fixture text inside the reference regression tests (applied to the emitted files)
FIXTURE_SWAPS = [
    ("archive.ubuntu.com/ubuntu noble main", "deb.debian.org/debian trixie main"),
    ("example.com/ubuntu", "example.com/debian"),
    ("Suites: noble", "Suites: trixie"),
]
SWAP_USED = {old: 0 for old, _ in SWAPS}


def swap(x):
    if isinstance(x, str):
        for old, new in SWAPS:
            if old in x:
                SWAP_USED[old] += 1
                x = x.replace(old, new)
        return x
    if isinstance(x, list):
        return [swap(v) for v in x]
    if isinstance(x, tuple):
        return tuple(swap(v) for v in x)
    if isinstance(x, dict):
        return {k: swap(v) for k, v in x.items()}
    return x


for _rid, _spec in ref.L.items():
    if _spec.manual:
        continue
    for _attr in ("ev_alts", "passes", "tp", "tf", "tm"):
        setattr(_spec, _attr, swap(getattr(_spec, _attr)))
_unused = [old for old, n in SWAP_USED.items() if n == 0]
if _unused:
    raise SystemExit(f"gen_ubuntu_26_04.py no longer holds the text these replacements expect: {_unused}")

# Regression tests for the Debian-specific logic (appended to the generated test files of those modules).
D13_TESTS = {
    "auditd": r'''
test_6_2_3_2_execve_without_execveat_flagged if {
	vs := data.cis_debian_13.auditd.violations with input as {"auditd": {"rules": [
		"-a always,exit -F arch=b32 -S execve -C euid!=uid -F auid!=unset -F key=user_emulation",
		"-a always,exit -F arch=b64 -S execve -C euid!=uid -F auid!=unset -F key=user_emulation",
	], "active_rules": [
		"-a always,exit -F arch=b32 -S execve -C euid!=uid -F auid!=unset -F key=user_emulation",
		"-a always,exit -F arch=b64 -S execve -C euid!=uid -F auid!=unset -F key=user_emulation",
	]}}
	count([v | some v in vs; startswith(v, "6.2.3.2: not met")]) == 1
}

test_6_2_3_2_single_arch_flagged if {
	vs := data.cis_debian_13.auditd.violations with input as {"auditd": {"rules": ["-a always,exit -F arch=b64 -S execve,execveat -C uid!=euid -F auid!=-1 -F key=user_emulation"], "active_rules": ["-a always,exit -F arch=b64 -S execve,execveat -C uid!=euid -F auid!=-1 -F key=user_emulation"]}}
	count([v | some v in vs; startswith(v, "6.2.3.2: not met")]) == 1
}

test_6_2_3_2_auditctl_form_accepted if {
	vs := data.cis_debian_13.auditd.violations with input as {"auditd": {"rules": [
		"-a always,exit -F arch=b64 -S execve,execveat -C uid!=euid -F auid!=-1 -F key=user_emulation",
		"-a always,exit -F arch=b32 -S execve,execveat -C uid!=euid -F auid!=-1 -F key=user_emulation",
	], "active_rules": [
		"-a always,exit -F arch=b64 -S execve,execveat -C uid!=euid -F auid!=-1 -F key=user_emulation",
		"-a always,exit -F arch=b32 -S execve,execveat -C uid!=euid -F auid!=-1 -F key=user_emulation",
	]}}
	count([v | some v in vs; startswith(v, "6.2.3.2: ")]) == 0
}
''',
    "main": r'''
test_violation_count_matches_violations if {
	r := data.cis_debian_13.main.compliance_report with input as {}
	r.violation_count == count(r.violations)
	r.violation_count > r.total_controls
	s := data.cis_debian_13.main.compliance_report with input as {"profile": "level2_workstation", "ssh": {"sshd_config_raw": "permitrootlogin no"}}
	s.violation_count == count(s.violations)
	s.failed_controls <= s.total_controls
}
''',
    "banners": r'''
test_1_6_2_os_release_id_flagged if {
	vs := data.cis_debian_13.banners.violations with input as {"initial_setup": {"issue_exists": true, "issue_content": "Welcome to DEBIAN"}}
	not "1.6.2: evidence missing — initial_setup.issue_exists/issue_content not collected" in vs
	count([v | some v in vs; startswith(v, "1.6.2: not met")]) == 1
}

test_1_6_2_longer_word_not_flagged if {
	vs := data.cis_debian_13.banners.violations with input as {"initial_setup": {"issue_exists": true, "issue_content": "Authorized debianists only"}}
	count([v | some v in vs; startswith(v, "1.6.2: ")]) == 0
}
''',
}


def rebrand(text):
    """Reference emitter output -> this module: package, generator name, version, metadata domain."""
    if text.count(REF_DOMAINS) > 1:
        raise SystemExit("more than one METADATA domains line in one file")
    for old, new in FIXTURE_SWAPS:
        text = text.replace(old, new)
    text = (text.replace(REF_PKG, PKG).replace(REF_GEN, GEN).replace(REF_GEN_NAME, pathlib.Path(GEN).name)
            .replace(REF_VERSION_LINE, f'"version": "{VERSION}",').replace(REF_DOMAINS, "domains: [linux, debian]"))
    left = re.findall(r"(?i).{0,40}(?:ubuntu|26\.04|resolute).{0,40}", text)
    if left:
        raise SystemExit(f"reference-module text left in the output: {left[:5]}")
    return text


def once(text, old, new):
    """Replace a piece of reference emitter output that must be there exactly once."""
    if text.count(old) != 1:
        raise SystemExit(f"gen_ubuntu_26_04.py output no longer holds {old!r} exactly once")
    return text.replace(old, new)


def with_tests(name, text):
    if name in D13_TESTS:
        text = text.rstrip("\n") + "\n\n" + D13_TESTS[name].strip("\n") + "\n"
    return text


def check(recs):
    """Abort on any count, id, status, profile or title-keyword mismatch with the workbook."""
    L, KW = ref.L, ref.KW
    a = sum(1 for r in recs.values() if r["assessment"] == "Automated")
    m = sum(1 for r in recs.values() if r["assessment"] == "Manual")
    if (len(recs), a, m) != (EXPECTED_TOTAL, EXPECTED_AUTOMATED, EXPECTED_MANUAL) or a + m != len(recs):
        raise SystemExit(f"workbook has {len(recs)} recommendations ({a} Automated, {m} Manual); expected "
                         f"{EXPECTED_TOTAL} ({EXPECTED_AUTOMATED}, {EXPECTED_MANUAL})")
    if set(L) != set(recs):
        raise SystemExit(f"logic/workbook mismatch: no logic {sorted(set(recs) - set(L), key=ref.sort_key)}; "
                         f"no recommendation {sorted(set(L) - set(recs), key=ref.sort_key)}")
    for rid, r in recs.items():
        if (r["assessment"] == "Manual") != L[rid].manual:
            raise SystemExit(f"{rid}: workbook says {r['assessment']}, logic table disagrees")
        title = " ".join(r["title"].split()).lower() + " "
        if " ".join(KW[rid].split()).lower() not in title and KW[rid].lower() not in title:
            raise SystemExit(f"{rid}: logic keyword {KW[rid]!r} not in the workbook title")
        if ref.level(r["profiles"], "Server") is None and ref.level(r["profiles"], "Workstation") is None:
            raise SystemExit(f"{rid}: no Level 1/2 Server or Workstation profile in the workbook")
    counts = {p: sum(1 for r in recs.values() if (ref.level(r["profiles"], kind) or 99) <= lv)
              for p, (kind, lv) in ref.PROFILES.items()}
    if counts != EXPECTED_PROFILE:
        raise SystemExit(f"profile counts {counts} differ from the expected {EXPECTED_PROFILE}")
    server_only = sorted((rid for rid, r in recs.items() if ref.level(r["profiles"], "Workstation") is None),
                         key=ref.sort_key)
    if server_only != SERVER_ONLY:
        raise SystemExit(f"recommendations without a Workstation profile: {server_only}, expected {SERVER_ONLY}")
    return a, m


def main():
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    recs, _ = ref.read_workbook(sys.argv[1])
    a, m = check(recs)
    recs = ref.publish_titles(recs)
    by_mod = {n: [] for n, _, _ in ref.SECTIONS}
    for rid in sorted(recs, key=ref.sort_key):
        by_mod[ref.section_of(rid)].append(rid)
    files = {}
    for name, title, _ in ref.SECTIONS:
        files[f"{name}.rego"] = ref.emit_module(name, title, by_mod[name], recs)
        files[f"tests/test_{name}.rego"] = with_tests(name, rebrand(ref.emit_tests(name, by_mod[name], recs)))
    files[f"{PKG}.rego"] = ref.emit_rollup(recs, by_mod)
    files[f"{PKG}_main.rego"] = once(once(
        ref.emit_main(recs), '\t"violations": _violations,\n',
        '\t"violations": _violations,\n\t"violation_count": count(_violations),\n'),
        "(plus profile and standard_total)", "(plus profile, standard_total and violation_count)")
    files[f"tests/test_{PKG}_main.rego"] = with_tests("main", once(once(
        ref.emit_rollup_tests(recs), "count(object.keys(r)) == 17", "count(object.keys(r)) == 18"),
        '"compliant", "violations", "section_results"', '"compliant", "violations", "violation_count", "section_results"'))
    (OUT / "tests").mkdir(parents=True, exist_ok=True)
    for rel, text in sorted(files.items()):  # only these files are written; nothing else in OUT is touched
        (OUT / rel).write_text(rebrand(text), encoding="utf-8")
    # canonical formatting, so a second run leaves the tree unchanged (the CI gate is `opa fmt -l`)
    try:
        subprocess.run(["opa", "fmt", "-w"] + [str(OUT / rel) for rel in sorted(files)], check=True)
    except FileNotFoundError:
        raise SystemExit("opa is not on PATH: the module was written but not formatted; run `opa fmt -w` on it")
    if len(sys.argv) > 2:  # input paths each control reads (for collector/mapper gap analysis)
        pathlib.Path(sys.argv[2]).write_text(json.dumps(
            {rid: [".".join(p) for p in ref.L[rid].reads] for rid in sorted(recs, key=ref.sort_key)}, indent=1))
    print(f"{len(recs)} recommendations ({a} Automated, {m} Manual) -> {OUT}")


if __name__ == "__main__":
    main()
