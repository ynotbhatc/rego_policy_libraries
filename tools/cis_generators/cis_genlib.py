"""Shared emitter for the NGINX / FortiGate CIS rego packages (input JSON from dump_workbook.py)."""
import json
import re

from neutralize import neutralize_title

ATT = "(manual review not attested)"

# Profile selection shared by the Level 1 / Level 2 generators (text for a module's helper section). The module must
# add `profile_violations` to its violations and define `recommendations` with a numeric `level` per id.
LEVEL_HELPERS = r'''# profile selection: input.cis_profile.level is the number 1 or 2 (Level 2 includes Level 1); absent => 2. Anything
# else ("2", 3, null, a cis_profile that is not an object) is invalid evidence: the report is scoped at Level 2, the
# stricter, and every Level 2 recommendation carries the finding, because the profile that decides them was not readable.
default _level := 2

_level := 1 if input.cis_profile.level == 1

_applies(id) if recommendations[id].level <= _level

default _level_invalid := false

_level_invalid if {
	cp := input.cis_profile
	not is_object(cp)
}

_level_invalid if {
	lv := input.cis_profile.level
	not lv in {1, 2}
}

_level_got := json.marshal(input.cis_profile.level) if is_object(input.cis_profile)

_level_got := json.marshal(cp) if {
	cp := input.cis_profile
	not is_object(cp)
}

_level_finding := sprintf("evidence invalid — cis_profile.level must be the number 1 or 2, got %s", [_level_got])

_v_profile contains sprintf("cis_profile.level: %s; the report is scoped at Level 2", [_level_finding]) if _level_invalid

_v_profile contains sprintf("%s: %s, so this Level 2 recommendation could not be scoped", [id, _level_finding]) if {
	_level_invalid
	some id, r in recommendations
	r.level == 2
}
'''
LEVEL_VIOLATIONS = ("# cis_profile.level that is not the number 1 or 2 (see _level_invalid)\n"
                    "profile_violations := sort([m | some m in _v_profile])\n")


def u(cid):
    return cid.replace(".", "_")


def norm_title(t):
    return re.sub(r"\s+", " ", t).strip()


def load_workbook_json(path):
    recs = json.load(open(path))
    out = {}
    for e in recs:
        sheets = [s for s in e["sheets"] if s not in ("Combined Profiles", "License", "Overview")]
        assert "Combined Profiles" in e["sheets"], e["id"]
        levels = sorted({int(re.match(r"Level (\d)", s).group(1)) for s in sheets})
        out[e["id"]] = {
            "title": norm_title(e["title"]),
            "assessment": e["status"],
            "level": levels[0],
            "profiles": sheets,
        }
    return out


def rego_str(s):
    return json.dumps(s, ensure_ascii=False)


def body(lines, indent="\t"):
    return "\n".join(indent + ln for ln in lines)


def emit_control(c, wb, setname, applies=None):
    """c: {id, kind: fact|attest, ok: [[lines]...], ev: [lines], label, attest}"""
    cid = c["id"]
    w = wb[cid]
    t = neutralize_title(w["title"])
    uu = u(cid)
    tag = f"# {cid} ({w['assessment']}, " + "; ".join(w["profiles"]) + ")"
    if w["assessment"] == "Manual" and c["kind"] == "fact":
        tag += " -- Manual in the workbook; decidable from configuration, so checked like Automated"
    out = [tag, f"default r_{uu} := false", ""]
    app = [f'_applies("{cid}")'] if applies else []
    if c["kind"] == "attest":
        out += [f"r_{uu} if {{", body(c.get("ok_extra", [])) if c.get("ok_extra") else None,
                f"\t{c['attest_root']}.attest.{c['attest']} == true", "}", ""]
        out = [x for x in out if x is not None]
        out += [f"{setname} contains {rego_str(f'{cid}: {t} {ATT}')} if {{"] + ["\t" + a for a in app] + [f"\tnot r_{uu}", "}", ""]
        return "\n".join(out)
    for ok in c["ok"]:
        out += [f"r_{uu} if {{", body(ok), "}", ""]
    out += [f"default e_{uu} := false", "", f"e_{uu} if {{", body(c["ev"]), "}", ""]
    miss = f"{cid}: evidence missing — {c['label']} not collected"
    out += [f"{setname} contains {rego_str(miss)} if {{"] + ["\t" + a for a in app] + [f"\tnot e_{uu}", "}", ""]
    # optional: c["typed"] = Rego set expressions of wrong-typed facts ("<path> must be <type>, got <value>"); any one fails
    # the control with an "evidence invalid" finding in place of the plain one. c["empty"] = (list expr, wording): the
    # list was collected and holds nothing, which is a failed control with its own wording, not missing evidence.
    gate = []
    if c.get("typed"):
        out += [f"x_{uu} := " + " | ".join(c["typed"]), ""]
        out += [f"{setname} contains msg if {{"] + ["\t" + a for a in app] + [
            f"\te_{uu}", f"\tsome m in x_{uu}", f'\tmsg := sprintf("%s: evidence invalid — %s", ["{cid}", m])', "}", ""]
        gate.append(f"\tcount(x_{uu}) == 0")
    if c.get("empty"):
        expr, wording = c["empty"]
        out += [f"{setname} contains {rego_str(f'{cid}: {t} ({wording})')} if {{"] + ["\t" + a for a in app] + [
            f"\te_{uu}", f"\tnot r_{uu}"] + gate + [f"\tcount({expr}) == 0", "}", ""]
        gate.append(f"\tcount({expr}) > 0")
    out += [f"{setname} contains {rego_str(f'{cid}: {t}')} if {{"] + ["\t" + a for a in app] + [f"\te_{uu}", f"\tnot r_{uu}"] + gate + ["}", ""]
    return "\n".join(out)


def emit_tests(pkg, controls, wb, green, attest_path):
    """Per control: pass on green, fail via patch, evidence-missing via patch (automated/fact)."""
    out = []
    for c in controls:
        cid = c["id"]
        uu = u(cid)
        t = neutralize_title(wb[cid]["title"])
        out.append(f"test_{uu}_pass if {{\n\tvs := b.violations with input as green\n\tnot _has_id(vs, \"{cid}\")\n}}\n")
        if c["kind"] == "attest":
            fail = [{"op": "replace", "path": f"{attest_path}/{c['attest']}", "value": False}]
            msg = f"{cid}: {t} {ATT}"
            out.append(f"test_{uu}_fail if {{\n\tinp := json.patch(green, {json.dumps(fail)})\n\tvs := b.violations with input as inp\n\t{rego_str(msg)} in vs\n}}\n")
            miss = [{"op": "remove", "path": f"{attest_path}/{c['attest']}"}]
            out.append(f"test_{uu}_not_attested_when_absent if {{\n\tinp := json.patch(green, {json.dumps(miss)})\n\tvs := b.violations with input as inp\n\t{rego_str(msg)} in vs\n}}\n")
            continue
        msg = f"{cid}: {t}"
        out.append(f"test_{uu}_fail if {{\n\tinp := json.patch(green, {json.dumps(c['fail'], ensure_ascii=False)})\n\tvs := b.violations with input as inp\n\t{rego_str(msg)} in vs\n}}\n")
        mmsg = f"{cid}: evidence missing — {c['label']} not collected"
        out.append(f"test_{uu}_evidence_missing if {{\n\tinp := json.patch(green, {json.dumps(c['miss'])})\n\tvs := b.violations with input as inp\n\t{rego_str(mmsg)} in vs\n\tnot {rego_str(msg)} in vs\n}}\n")
    return "\n".join(out)


def table(controls, wb, extra=None):
    t = {}
    for c in controls:
        w = wb[c["id"]]
        e = {"title": neutralize_title(w["title"]), "level": w["level"], "assessment": w["assessment"], "profiles": w["profiles"],
             "check": "attestation" if c["kind"] == "attest" else "configuration"}
        if extra:
            e.update(extra(c, w))
        t[c["id"]] = e
    return json.dumps(t, indent="\t", ensure_ascii=False)
