#!/usr/bin/env python3
"""DISA STIG for RHEL 9: the nine section modules and their per-rule tests, from a reviewed logic table.

    python3 tools/stig_generators/gen_rhel9.py          # writes benchmarks/stig/rhel_9/<section>.rego
                                                        # and benchmarks/stig/rhel_9/tests/test_<section>_rules.rego

Until 2026-11-18 the RHEL 9 modules were hand-maintained and re-stamped by stamp_catalog.py (a one-shot
re-keying: run again on its own output it retires and collides blocks, so it now refuses rhel_9). An
external audit found them id-accurate but check-inaccurate: a rule's condition did not test what the
rule's V2R10 check procedure tests. Every rule is now a reviewed entry in RULES below, written against
the full check text of the current XCCDF catalog (tools/stig_generators/catalogs/rhel_9.json, made by
parse_xccdf.py); the generator stamps vuln id, severity and title from that catalog and aborts if a rule
id is not in it (catalog id hard-gate).

Principles (each finding carries `check_type`, `detail` and `fix_text`):
  - the policy states the expected value; the collector supplies the OBSERVED value (the raw setting,
    the file content, the list of offenders), so the decision can be audited from the input;
  - FAIL-CLOSED: every rule names its evidence paths; an absent one makes the finding Open with detail
    "<STIG-ID>: evidence missing — <path> not collected";
  - Not_Applicable only where the check text has a Not Applicable clause, and only on explicit evidence
    (the clause's own fact, or an attestation `input.attest.<key> == true`);
  - "ask the SA" / "documented with the ISSO" clauses are attestations that can turn a failed machine
    check into Not_a_Finding; they stay Open until attested;
  - numeric comparisons are type-guarded (`_num` only yields a number for a number or a numeric string).

The section files keep the layout gen_oracle_linux.py derives oracle_linux_8 / oracle_linux_9 / rhel_10
from: block header `# <STIG-ID> | <V-ID> | <CAT>`, `finding_rhel_09_<n>` / `status_rhel_09_<n>`, a
one-line "rule_title", the COMPLIANCE AGGREGATION tail. Each file's METADATA (including the coverage
block `make coverage` writes) and the aggregation tail after the lists are carried over from the file.
The input contract is documented per rule (evidence paths) in rhel9_rules.py.
"""
import json, os, re, shutil, subprocess, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from rhel9_rules import RULES, SECTION_HELPERS  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "..", "benchmarks", "stig", "rhel_9")
CATS = os.path.join(HERE, "catalogs")
SEV = {"high": "CAT I", "medium": "CAT II", "low": "CAT III"}
LIBRARY = "October 2026 SRG-STIG library"
VERIFIED = "2026-11-18"
SECTIONS = ["account_auth", "audit_logging", "configuration_management", "file_permissions", "network",
            "pki_crypto", "services", "software_integrity", "ssh_config"]
BAR = "# " + "=" * 77
AGG_MARK = BAR + "\n# COMPLIANCE AGGREGATION"

HELPERS = r'''# evidence present: the value exists at the path (an explicit null counts as not collected)
_collected(path) if object.get(input, path, null) != null

# the value at path as a trimmed string: a string as given, an integer number in decimal
_str(path) := trim_space(v) if {
	v := object.get(input, path, null)
	is_string(v)
}

_str(path) := format_int(v, 10) if {
	v := object.get(input, path, null)
	is_number(v)
	v == floor(v)
}

# a keyword value (sshd, auditd, faillock ...), compared case-insensitively
_kw(path) := lower(s) if s := _str(path)

# the value at path as a number: a number, or a string holding a decimal integer; undefined otherwise
# (in OPA a string compares greater than any number and null <= 60 is true, so never compare raw input)
_num(path) := v if {
	v := object.get(input, path, null)
	is_number(v)
}

_num(path) := n if {
	v := object.get(input, path, null)
	is_string(v)
	regex.match(`^\s*-?[0-9]+\s*$`, v)
	n := to_number(trim_space(v))
}

# a dnf/yum boolean option as written in the file: "1", "true" or "yes" (letters case-insensitive)
_truthy(v) if v == true

_truthy(v) if v == 1

_truthy(v) if {
	is_string(v)
	lower(trim_space(v)) in {"1", "true", "yes"}
}

# an organizational attestation (SA / ISSO documentation the check text asks for)
_attested(key) if input.attest[key] == true'''


def ident(sid):
    return sid.lower().replace("-", "_")


def esc(s):
    return s.replace("\\", "\\\\").replace('"', '\\"')


def rego_list(paths):
    return "[" + ", ".join(json.dumps(list(p)) for p in paths) + "]"


def indent(lines):
    out = []
    for b in lines:
        first, *rest = b.split("\n")
        out += ["\t" + first] + rest
    return out


def deep_merge(a, b, where):
    for k, v in b.items():
        if isinstance(v, dict) and isinstance(a.get(k), dict):
            deep_merge(a[k], v, where)
        elif k in a and a[k] != v:
            raise SystemExit(f"green fixture conflict at {k!r} ({where}): {a[k]!r} vs {v!r}")
        else:
            a[k] = json.loads(json.dumps(v))


def block(sid, r, spec):
    i, sev = ident(sid), SEV[r["severity"]]
    title = esc(" ".join(r["title"].split()))
    o = [f"# {sid} | {r['vuln_id']} | {sev}"]
    if spec.get("comment"):
        o.append("# " + spec["comment"])
    name = spec["name"]
    kind = spec["kind"]
    if spec["ev"]:
        o.append(f'missing_{i} := [concat(".", p) | some p in {rego_list(spec["ev"])}; not _collected(p)]')
    else:
        o.append(f"missing_{i} := []")
    o += ["", f"default {name} := false", ""]
    for alt in spec["alts"]:
        o += [name + " if {", f"\tcount(missing_{i}) == 0"] + indent(alt) + ["}", ""]
    for alt in spec.get("attest_alts", []):
        o += [name + " if {"] + indent(alt) + ["}", ""]
    if spec.get("na"):
        o += [f"default na_{i} := false", ""]
        for alt in spec["na"]:
            o += [f"na_{i} if {{"] + indent(alt) + ["}", ""]
    o += [f'status_{i} := "Not_a_Finding" if {name}', ""]
    if spec.get("na"):
        o += [f'else := "Not_Applicable" if na_{i}', ""]
    o += ['else := "Open"', "", f'detail_{i} := "{sid}: Not_a_Finding" if {name}', ""]
    if spec.get("na"):
        o += [f'else := "{sid}: Not_Applicable — {esc(spec["na_expect"])}" if na_{i}', ""]
    o += [f'else := sprintf("%s: evidence missing — %s not collected", ["{sid}", concat(", ", missing_{i})]) if count(missing_{i}) > 0',
          "", f'else := "{sid}: check failed — {esc(spec["expect"])}"', ""]
    o += [f"finding_{i} := {{", f'\t"vuln_id": "{r["vuln_id"]}",', f'\t"stig_id": "{sid}",',
          f'\t"severity": "{sev}",', f'\t"rule_title": "{title}",', f'\t"check_type": "{kind}",',
          f'\t"status": status_{i},', f'\t"detail": detail_{i},', f'\t"fix_text": "{esc(spec["fix"])}",', "}", ""]
    return sev, f"finding_{i}", "\n".join(o)


def tests_for(sec, sid, spec, green_name):
    i = ident(sid)
    m = f"data.stig.rhel_9.{sec}"
    t = [f"test_{i}_pass if {{", f'\t{m}.status_{i} == "Not_a_Finding" with input as {green_name}', "}", ""]
    for n, bad in enumerate(spec["bad"], 1):
        t += [f"test_{i}_fail_{n} if {{",
              f"\tf := {m}.finding_{i} with input as object.union({green_name}, {json.dumps(bad)})",
              '\tf.status == "Open"', f'\tcontains(f.detail, "{sid}: check failed")', "}", ""]
    for n, p in enumerate(spec["ev"], 1):
        t += [f"test_{i}_evidence_missing_{n} if {{",
              f"\tf := {m}.finding_{i} with input as json.remove({green_name}, [{json.dumps(list(p))}])",
              '\tf.status == "Open"', f'\tcontains(f.detail, "{sid}: evidence missing — {esc(".".join(p))}")', "}", ""]
    for n, na in enumerate(spec.get("na_cases", []), 1):
        t += [f"test_{i}_not_applicable_{n} if {{",
              f"\tf := {m}.finding_{i} with input as object.union({green_name}, {json.dumps(na)})",
              '\tf.status == "Not_Applicable"', "}", ""]
    for n, ok in enumerate(spec.get("pass_cases", []), 2):
        t += [f"test_{i}_pass_{n} if {{",
              f'\t{m}.status_{i} == "Not_a_Finding" with input as object.union({green_name}, {json.dumps(ok)})', "}", ""]
    return t


def main():
    cat = json.load(open(os.path.join(CATS, "rhel_9.json")))
    by = {r["stig_id"]: r for r in cat["rules"]}
    missing = [sid for sid in RULES if sid not in by]
    if missing:
        raise SystemExit(f"rhel_9: rule ids not in the {cat['version']} catalog: {missing}")
    full_green, n_reviewed = {}, 0
    for sec in SECTIONS:
        path = os.path.join(OUT, f"{sec}.rego")
        text = open(path).read()
        k = "default compliant := false\n"
        header = text[:text.index(k) + len(k)]
        header = re.sub(r"(?m)^# STIG Version: .*$", f"# STIG Version: {cat['version']} | Released: {cat['release_date']}", header)
        header = re.sub(r"(?m)^# Rule ids, vuln ids, severities and titles stamped from[^\n]*\n(?:# \([^\n]*\n)?", "", header)
        header = re.sub(r"(?m)^# Generated by tools/stig_generators/gen_rhel9\.py[^\n]*\n(?:# and titles from the catalog[^\n]*\n)?", "", header)
        note = (f"# Generated by tools/stig_generators/gen_rhel9.py from the {LIBRARY} XCCDF ({VERIFIED}): ids, severities\n"
                "# and titles from the catalog, logic from the reviewed table in rhel9_rules.py (regenerate, don't hand-edit).\n")
        header = re.sub(r"(?m)^(# STIG Version: [^\n]*\n)", lambda m: m.group(1) + note, header, count=1)
        rest = text[text.index(AGG_MARK):]
        rest = rest[rest.index("violations contains"):]
        sec_rules = [(sid, s) for sid, s in RULES.items() if s["sec"] == sec]
        section_helpers = SECTION_HELPERS.get(sec, "").strip()
        out = [header.rstrip("\n"), "", BAR, "# SHARED HELPERS (tools/stig_generators/gen_rhel9.py)", BAR, "", HELPERS, ""]
        if section_helpers:
            out += [section_helpers, ""]
        groups = {"CAT I": [], "CAT II": [], "CAT III": []}
        names = {"CAT I": [], "CAT II": [], "CAT III": []}
        green, tests = {}, []
        for sid, spec in sec_rules:
            sev, fname, b = block(sid, by[sid], spec)
            groups[sev].append(b)
            names[sev].append(fname)
            n_reviewed += 1
            deep_merge(green, spec["green"], sid)
        for sid, spec in sec_rules:
            tests += tests_for(sec, sid, spec, "green_fixture")
        for sev, label in (("CAT I", "HIGH"), ("CAT II", "MEDIUM"), ("CAT III", "LOW")):
            if groups[sev]:
                out += [BAR, f"# {sev} - {label} SEVERITY", BAR, ""] + groups[sev]
        out += [AGG_MARK, BAR, ""]
        for sev, var in (("CAT I", "cat_i_findings"), ("CAT II", "cat_ii_findings"), ("CAT III", "cat_iii_findings")):
            if names[sev]:
                out.append(f"{var} := [\n" + "".join(f"\t{n},\n" for n in names[sev]) + "]\n")
            else:
                out.append(f"# No {sev} rule in this module. array.concat rather than the literal `[]`: OPA >= 1.22 types a literal\n"
                           f"# empty array as having no members and rejects iterating it (scripts/check_per_file_load.py).\n{var} := array.concat([], [])\n")
        out += ["findings := array.concat(cat_i_findings, array.concat(cat_ii_findings, cat_iii_findings))", "", rest.rstrip("\n"), ""]
        open(path, "w").write("\n".join(out))
        tpath = os.path.join(OUT, "tests", f"test_{sec}_rules.rego")
        if tests:
            deep_merge(full_green, green, sec)
            gs = json.dumps(green, indent="\t", sort_keys=True).replace("\n", "\n")
            t = [f"package stig.rhel_9.{sec}_rules_test", "", "import rego.v1", "",
                 "# Generated by tools/stig_generators/gen_rhel9.py: for every reviewed rule a pass, a fail per mutation, an",
                 "# evidence-missing test per evidence path and, where the check text has one, the Not Applicable case.", "",
                 f"green_fixture := {gs}", "",
                 "test_every_finding_open_on_empty_input if {",
                 f"\tfs := data.stig.rhel_9.{sec}.findings with input as {{}}",
                 '\tcount([f | some f in fs; f.status != "Open"]) == 0', "}", ""]
            t += ["test_section_compliant_on_green_fixture if {",
                  f"\tdata.stig.rhel_9.{sec}.compliant with input as green_fixture", "}", ""]
            open(tpath, "w").write("\n".join(t + tests).rstrip() + "\n")
        elif os.path.exists(tpath):
            os.remove(tpath)
    gpath = os.path.join(OUT, "tests", "test_rhel9_green.rego")
    if n_reviewed == len(RULES):
        gs = json.dumps(full_green, indent="\t", sort_keys=True)
        t = ["package stig.rhel_9.green_test", "", "import rego.v1", "",
             "# Generated by tools/stig_generators/gen_rhel9.py: the union of the section green fixtures passes every rule.", "",
             f"green_fixture := {gs}", "",
             "test_every_rule_not_a_finding_on_green_fixture if {",
             "\tr := data.stig.rhel_9.stig_assessment with input as green_fixture",
             f"\tr.summary.total_findings == {len(RULES)}", f"\tr.summary.not_a_finding == {len(RULES)}", "}", "",
             "test_main_compliant_on_green_fixture if {",
             "\tr := data.stig.rhel_9.main.compliance_report with input as green_fixture",
             "\tr.compliant == true", "\tr.violation_count == 0", "}"]
        open(gpath, "w").write("\n".join(t) + "\n")
    elif os.path.exists(gpath):
        os.remove(gpath)
    # opa fmt is the canonical layout (fixture literals, wrapped bodies); the output is idempotent under it
    opa = shutil.which("opa")
    if not opa:
        raise SystemExit("opa not on PATH: the generated files must be formatted with opa fmt")
    written = [os.path.join(OUT, f"{s}.rego") for s in SECTIONS]
    written += [os.path.join(OUT, "tests", f) for f in os.listdir(os.path.join(OUT, "tests"))
                if f.endswith("_rules.rego") or f == "test_rhel9_green.rego"]
    subprocess.run([opa, "fmt", "-w"] + written, check=True)
    sev = {}
    for sid in RULES:
        sev[SEV[by[sid]["severity"]]] = sev.get(SEV[by[sid]["severity"]], 0) + 1
    print(f"rhel_9: {len(RULES)} of {len(cat['rules'])} {cat['version']} rules {sev}; {n_reviewed} with tests")


if __name__ == "__main__":
    main()
