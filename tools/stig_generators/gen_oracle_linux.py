#!/usr/bin/env python3
"""Derive the Oracle Linux STIG modules from the RHEL modules by DISA rule title.

    python3 tools/stig_generators/gen_oracle_linux.py            # oracle_linux_9 from rhel_9

Oracle Linux and RHEL STIGs are written from the same SRG and share rule text almost
verbatim (OL9 V1R7: 354 of 450 titles identical to RHEL 9 V2R10 after the OS name is
normalised). A RHEL rule whose title matches an OL rule is emitted with the OL stig_id,
vuln_id, severity and title taken from the OL XCCDF catalog; the check logic, input
contract and fix text are the RHEL module's. Rules with no title match are not emitted —
they are listed in the aggregator header as the remaining work, never invented.

Catalog ID hard-gate: every emitted rule id exists in the current OL catalog by construction.
"""
import difflib, json, os, re, sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.join(HERE, "..", "..", "benchmarks", "stig")
CATS = os.path.join(HERE, "catalogs")

PLATFORMS = {
    "oracle_linux_9": {
        "src": "rhel_9", "src_prefix": "RHEL-09", "src_name": "RHEL 9", "src_ident": "rhel_09",
        "name": "Oracle Linux 9", "ident": "ol09", "domains": "[linux, oracle]",
        # Reviewed by hand against both check texts (2026-10-13): the RHEL module's own title is a paraphrase, so
        # the title match misses these; the LOGIC is the same requirement. Key = <section>:<RHEL id as written in
        # the module>. A value starting with "~" is a case-insensitive substring of the OL title that must match
        # exactly one rule (so a catalog change cannot silently re-point it).
        "overrides": {
            "account_auth:RHEL-09-611015": "OL09-00-001055", "account_auth:RHEL-09-611020": "OL09-00-003020",
            "account_auth:RHEL-09-611030": "OL09-00-001105", "account_auth:RHEL-09-611035": "OL09-00-001005",
            "account_auth:RHEL-09-611040": "OL09-00-001015", "account_auth:RHEL-09-611045": "OL09-00-001020",
            "account_auth:RHEL-09-611050": "OL09-00-001120", "account_auth:RHEL-09-611060": "OL09-00-001085",
            "account_auth:RHEL-09-611075": "OL09-00-002416", "account_auth:RHEL-09-611085": "OL09-00-003001",
            "account_auth:RHEL-09-611090": "OL09-00-003006",
            "audit_logging:RHEL-09-653010": "OL09-00-000441", "audit_logging:RHEL-09-653015": "OL09-00-000770",
            "audit_logging:RHEL-09-654040": "OL09-00-000500", "audit_logging:RHEL-09-654045": "OL09-00-000525",
            "audit_logging:RHEL-09-654050": "OL09-00-000670", "audit_logging:RHEL-09-654060": "OL09-00-000690",
            "audit_logging:RHEL-09-654065": "~immutable",
            "configuration_management:RHEL-09-211015": "OL09-00-002107", "configuration_management:RHEL-09-211050": "OL09-00-000070",
            "configuration_management:RHEL-09-212010": "OL09-00-000090", "configuration_management:RHEL-09-212020": "OL09-00-000256",
            "configuration_management:RHEL-09-213010": "OL09-00-002423", "configuration_management:RHEL-09-213035": "OL09-00-002430",
            "configuration_management:RHEL-09-214010": "~usb mass storage", "configuration_management:RHEL-09-214015": "OL09-00-000042",
            "file_permissions:RHEL-09-232015": "OL09-00-002512", "file_permissions:RHEL-09-232020": "OL09-00-002511",
            "file_permissions:RHEL-09-232025": "OL09-00-002548", "file_permissions:RHEL-09-232035": "OL09-00-002536",
            "network:RHEL-09-251020": "OL09-00-006020", "network:RHEL-09-251025": "OL09-00-006032",
            "network:RHEL-09-251035": "OL09-00-006031", "network:RHEL-09-251040": "OL09-00-006050",
            "network:RHEL-09-251045": "OL09-00-006024", "network:RHEL-09-251050": "OL09-00-006041",
            "network:RHEL-09-251055": "OL09-00-006001", "network:RHEL-09-251060": "OL09-00-000046",
            "pki_crypto:RHEL-09-671010": "OL09-00-000241", "pki_crypto:RHEL-09-671020": "OL09-00-000930",
            "pki_crypto:RHEL-09-672020": "OL09-00-000242", "pki_crypto:RHEL-09-672025": "OL09-00-000925",
            "pki_crypto:RHEL-09-672045": "OL09-00-000910",
            "services:RHEL-09-291025": "OL09-00-000135", "services:RHEL-09-291030": "OL09-00-000130",
            "services:RHEL-09-291060": "OL09-00-000100",
            "software_integrity:RHEL-09-251015": "OL09-00-000498", "software_integrity:RHEL-09-251025": "OL09-00-000302",
            "software_integrity:RHEL-09-252035": "OL09-00-000351",
            "ssh_config:RHEL-09-255015": "OL09-00-000251", "ssh_config:RHEL-09-255025": "OL09-00-000255",
            "ssh_config:RHEL-09-255030": "OL09-00-002343", "ssh_config:RHEL-09-255065": "OL09-00-002348",
            "ssh_config:RHEL-09-255045": "~terminated after 10 minutes", "ssh_config:RHEL-09-255050": "~terminate after becoming unresponsive",
            "ssh_config:RHEL-09-255085": "~x11",
        },
        # fuzzy title matches reviewed and refused: a different requirement that merely reads alike
        "reject": {"audit_logging:RHEL-09-653020", "software_integrity:RHEL-09-252020", "account_auth:RHEL-09-611070",
                   "file_permissions:RHEL-09-232070", "services:RHEL-09-291020", "ssh_config:RHEL-09-255020"},
    },
    # Oracle Linux 8 V2R10 from the Oracle Linux 9 module above (105 of its 377 titles are OL 9 titles verbatim);
    # generate oracle_linux_9 first, this reads its output.
    "oracle_linux_8": {
        "src": "oracle_linux_9", "src_prefix": "OL09", "src_name": "Oracle Linux 9", "src_ident": "ol09",
        "name": "Oracle Linux 8", "ident": "ol08", "domains": "[linux, oracle]",
        # reviewed against both check texts 2026-10-13; OL 8 splits several rules by OS minor version — the
        # 8.2-and-above variant is the faillock form the logic implements
        "overrides": {
            "account_auth:OL09-00-003020": "OL08-00-020011", "account_auth:OL09-00-002416": "OL08-00-020013",
            "account_auth:OL09-00-001105": "OL08-00-020230", "account_auth:OL09-00-001120": "OL08-00-020280",
            "account_auth:OL09-00-001055": "OL08-00-010110",
            "audit_logging:OL09-00-000645": "OL08-00-030480", "audit_logging:OL09-00-000640": "OL08-00-030490",
            "audit_logging:OL09-00-000545": "OL08-00-030200", "audit_logging:OL09-00-000525": "OL08-00-030150",
            "audit_logging:OL09-00-000670": "OL08-00-030550", "audit_logging:OL09-00-000690": "OL08-00-030360",
            "configuration_management:OL09-00-002413": "OL08-00-040170", "configuration_management:OL09-00-000047": "OL08-00-040080",
            "configuration_management:OL09-00-000042": "OL08-00-040026", "configuration_management:OL09-00-002107": "OL08-00-040171",
            "configuration_management:OL09-00-000301": "OL08-00-010360", "software_integrity:OL09-00-000351": "OL08-00-010561",
            "pki_crypto:OL09-00-000242": "OL08-00-010183", "services:OL09-00-000135": "OL08-00-040190",
            "network:OL09-00-006020": "OL08-00-040279", "configuration_management:OL09-00-002072": "OL08-00-010590",
            "ssh_config:OL09-00-002349": "OL08-00-010520",
        },
        "reject": {"services:OL09-00-000125"},
    },
}
SEV = {"high": "CAT I", "medium": "CAT II", "low": "CAT III"}
FUZZY = 0.86   # difflib ratio for a second-pass title match; every fuzzy pair is printed for review
BLOCK = re.compile(r"^# ([A-Z0-9]+-\d\d-\d+) \| (V-\d+) \| (CAT I{1,3})\n", re.M)
BANNER = re.compile(r"(?:^# =+\n)?^# CAT I{1,3} - [A-Z ]+SEVERITY\n(?:^# =+\n)?\n?", re.M)


def norm(t):
    t = re.sub(r"\b(oracle linux|ol|rhel|red hat enterprise linux)\s*[0-9]*\b", "<os>", t.lower())
    t = t.replace("dod", "dow").replace("syscalls", "system calls").replace("syscall", "system call")
    return re.sub(r"[\s.]+$", "", re.sub(r"\s+", " ", t)).strip()


def esc(s):
    return s.replace("\\", "\\\\").replace('"', '\\"')


def derive(key, cfg):
    cat = json.load(open(os.path.join(CATS, f"{key}.json")))
    src_cat = json.load(open(os.path.join(CATS, f"{cfg['src']}.json")))
    by_title = {}
    for r in cat["rules"]:
        by_title.setdefault(norm(r["title"]), r)
    src_by_id = {r["stig_id"]: r for r in src_cat["rules"]}
    srcdir = os.path.join(REPO, cfg["src"])
    outdir = os.path.join(REPO, key)
    os.makedirs(os.path.join(outdir, "tests"), exist_ok=True)
    name, ident, pfx = cfg["name"], cfg["ident"], cfg["src_prefix"]
    sections = sorted(f[:-5] for f in os.listdir(srcdir)
                      if f.endswith(".rego") and not f.startswith("stig_"))
    emitted, dropped, idmap, fuzzy = {}, [], {}, []
    for sec in sections:
        text = open(os.path.join(srcdir, f"{sec}.rego")).read()
        heads = list(BLOCK.finditer(text))
        tail_at = text.find("# =============================================================================\n# COMPLIANCE AGGREGATION")
        header = text[:heads[0].start()]
        title = re.search(r'^# title: "(.+)"', header, re.M).group(1).replace(cfg["src_name"], name)
        title = title.replace("OL 9", name)
        covers = re.search(r"^# Covers:.*$", header, re.M)
        blocks = []
        for i, h in enumerate(heads):
            end = heads[i + 1].start() if i + 1 < len(heads) else tail_at
            blocks.append((h.group(1), h.group(2), BANNER.sub("", text[h.start():end]).rstrip() + "\n"))
        kept = []
        for sid, vid, body in blocks:
            src = src_by_id.get(sid)
            # the library's own rule_title is the DISA title at the version the module was written against;
            # it stands in when the id has since left the RHEL catalog
            # Key on the finding's OWN rule_title, never on its stig_id: the RHEL 9 module's ids were found to
            # disagree with the current DISA catalog for 108 of 143 findings (2026-10-13), so the id cannot be
            # trusted to name the rule the logic implements; the title the author wrote next to the logic can.
            lib_title = re.search(r'"rule_title": "([^"\n]*)"', body)
            title_src = lib_title.group(1) if lib_title else (src["title"] if src else "")
            key2 = f"{sec}:{sid}"
            tgt, how = None, "exact"
            if key2 in cfg.get("overrides", {}):
                want = cfg["overrides"][key2]
                if want.startswith("~"):
                    hits = [r for r in cat["rules"] if want[1:].lower() in r["title"].lower()]
                    if len(hits) != 1:
                        print(f"  OVERRIDE {key2}: '{want}' matches {len(hits)} OL titles, not applied")
                    else:
                        tgt, how = hits[0], "override"
                else:
                    tgt, how = next(r for r in cat["rules"] if r["stig_id"] == want), "override"
            elif key2 in cfg.get("reject", set()):
                dropped.append((sec, sid, title_src + "  [fuzzy match refused]")); continue
            else:
                tgt = by_title.get(norm(title_src))
            if tgt is None and title_src:
                best = difflib.get_close_matches(norm(title_src), list(by_title), n=1, cutoff=FUZZY)
                if best:
                    tgt, how = by_title[best[0]], "fuzzy"
            if tgt is None or tgt["stig_id"] in {t["stig_id"] for t in idmap.values()}:
                dropped.append((sec, sid, title_src or "(no title)"))
                continue
            if how == "fuzzy":
                fuzzy.append((sid, tgt["stig_id"], title_src, tgt["title"], difflib.SequenceMatcher(None, norm(title_src), norm(tgt["title"])).ratio()))
            idmap[sid] = tgt
            tid = tgt["stig_id"]
            t_ident = re.sub(r"[^a-z0-9]+", "_", tid.lower())
            s_ident = re.sub(r"[^a-z0-9]+", "_", sid.lower())
            sev = SEV[tgt["severity"]]
            b = body.replace(sid, tid).replace(vid, tgt["vuln_id"]).replace(s_ident, t_ident)
            b = re.sub(r"^# " + re.escape(tid) + r" \| " + re.escape(tgt["vuln_id"]) + r" \| CAT I{1,3}$",
                       f"# {tid} | {tgt['vuln_id']} | {sev}", b, count=1, flags=re.M)
            b = re.sub(r'"severity": "CAT I{1,3}"', f'"severity": "{sev}"', b)
            b = re.sub(r'"rule_title": "[^"\n]*"', f'"rule_title": "{esc(tgt["title"])}"', b)
            kept.append((tid, sev, t_ident, b))
        # helper closure: a kept rule may call a function/rule defined in a block that was dropped
        def chunks(text):
            out = []
            for para in re.split(r"\n\s*\n", text):
                code = "\n".join(l for l in para.strip().splitlines() if not l.lstrip().startswith("#"))
                m = re.match(r"(?:default )?([a-z_][a-z0-9_]*)", code)
                if m and code:
                    out.append((m.group(1), para.strip()))
            return out
        defined = {n for _, _, _, b in kept for n, _ in chunks(b)}
        pool = {}   # name -> every clause of that definition (functions and rules may have several)
        for n, para in chunks(header):
            if n not in ("package", "import") and "compliant" not in para.split("\n")[0]:
                pool.setdefault(n, []).append(para)
        for sid, vid, body in blocks:
            for n, para in chunks(body):
                pool.setdefault(n, []).append(para)
        helpers = []
        changed = True
        while changed:
            changed = False
            referenced = set()
            for _, _, _, b in kept:
                referenced |= set(re.findall(r"\b([a-z_][a-z0-9_]*)\b", re.sub(r'"[^"\n]*"', '', b)))
            for h in helpers:
                referenced |= set(re.findall(r"\b([a-z_][a-z0-9_]*)\b", re.sub(r'"[^"\n]*"', '', h)))
            for n in sorted(referenced - defined):
                if n in pool:
                    helpers.extend(pool[n]); defined.add(n); changed = True
        if helpers:
            kept.append(("", "HELPERS", "", "# Shared helpers (defined in a source block whose rule " + name + " does not carry)\n\n" + "\n\n".join(helpers) + "\n"))
        emitted[sec] = kept
        by_sev = {"CAT I": [], "CAT II": [], "CAT III": []}
        for tid, sev, t_ident, b in kept:
            if sev in by_sev:
                by_sev[sev].append(f"finding_{t_ident}")
        o = [
            "# METADATA", f'# title: "{title}"', "# custom:", "#   class: security",
            f"#   framework: stig_{key}", "#   source: disa", f"#   domains: {cfg['domains']}",
            f"package stig.{key}.{sec}", "",
            f"# {title}", f"# STIG Version: {cat['version']} | Released: {cat['release_date']}",
            f"# Derived from stig/{cfg['src']}/{sec}.rego by DISA rule title: {name} and {cfg['src_name']} share the rule text;",
            f"# ids, vuln ids, severities and titles are the {name} XCCDF's (tools/stig_generators/gen_oracle_linux.py).",
        ]
        if covers:
            o.append(covers.group(0))
        o += ["", "import rego.v1", "", "default compliant := false", ""]
        for sev_name, label in (("HELPERS", "SHARED HELPERS"), ("CAT I", "CAT I - HIGH SEVERITY"), ("CAT II", "CAT II - MEDIUM SEVERITY"), ("CAT III", "CAT III - LOW SEVERITY")):
            group = [b for tid, sev, _, b in kept if sev == sev_name]
            if not group:
                continue
            o += ["# =============================================================================", f"# {label}",
                  "# =============================================================================", ""]
            for b in group:
                o += [b]
        o += ["# =============================================================================", "# COMPLIANCE AGGREGATION",
              "# =============================================================================", ""]
        for k2, var in (("CAT I", "cat_i_findings"), ("CAT II", "cat_ii_findings"), ("CAT III", "cat_iii_findings")):
            names = by_sev[k2]
            o.append(f"{var} := [" + ("\n" + "".join(f"\t{n},\n" for n in names) if names else "") + "]\n")
        o += ["findings := array.concat(cat_i_findings, array.concat(cat_ii_findings, cat_iii_findings))", "",
              "violations contains finding.stig_id if {", "\tsome finding in findings", '\tfinding.status == "Open"', "}", "",
              "open_cat_i contains f if {", "\tsome f in cat_i_findings", '\tf.status == "Open"', "}", "",
              "compliant if {", "\tcount(open_cat_i) == 0", "}", "",
              "compliance_report := {", f'\t"module": "{sec}",', '\t"total_findings": count(findings),',
              '\t"open_findings": count(violations),', '\t"cat_i_open": count(open_cat_i),', '\t"findings": findings,',
              '\t"compliant": compliant,', "}", ""]
        open(os.path.join(outdir, f"{sec}.rego"), "w").write("\n".join(o))
    n_rules = sum(1 for v in emitted.values() for k in v if k[1] != "HELPERS")
    seen = {f"{sec}:{sid}" for sec in sections for sid in BLOCK.findall(open(os.path.join(srcdir, f"{sec}.rego")).read()) for sid in [sid[0]]}
    for k in sorted(set(cfg.get("overrides", {})) | set(cfg.get("reject", set()))):
        if k not in seen:
            print(f"  UNUSED override/reject key {k}")
    # aggregator + alias + main test: the RHEL files with the platform tokens swapped
    def swap(s):
        s = s.replace(f"stig.{cfg['src']}", f"stig.{key}").replace(f"stig_{cfg['src']}", f"stig_{key}")
        s = s.replace(cfg["src"], key).replace(cfg["src_name"], name)
        s = s.replace("[linux, rhel]", cfg["domains"])
        s = re.sub(r"# STIG Version: .*", f"# STIG Version: {cat['version']} | Released: {cat['release_date']}", s)
        s = re.sub(r'"stig_title": ".*"', f'"stig_title": "{esc(cat["benchmark"])}"', s)
        s = re.sub(r'"version": "V\d+R\d+"', f'"version": "{cat["version"]}"', s)
        s = re.sub(r'"release_date": "\d{4}-\d\d-\d\d"', f'"release_date": "{cat["status_date"]}"', s)
        s = re.sub(r"(?m)^#   coverage:\n(?:#     .*\n)+", "", s)   # the stamper re-adds the block
        return s
    comp_src = [f for f in os.listdir(srcdir) if f.startswith("stig_") and f.endswith("_complete.rego")][0]
    comp = swap(open(os.path.join(srcdir, comp_src)).read())
    note = (f"# Implemented: {n_rules} of {len(cat['rules'])} {name} {cat['version']} rules — those whose DISA title matches a rule the\n"
            f"# {cfg['src_name']} modules implement. The remaining {len(cat['rules']) - n_rules} are tracked follow-up, not silent absence.\n")
    comp = comp.replace("\nimport rego.v1\n", "\n" + note + "\nimport rego.v1\n", 1)
    open(os.path.join(outdir, f"stig_{key}_complete.rego"), "w").write(comp)
    alias = swap(open(os.path.join(srcdir, f"stig_{cfg['src']}_main.rego")).read())
    open(os.path.join(outdir, f"stig_{key}_main.rego"), "w").write(alias)
    t = swap(open(os.path.join(srcdir, "tests", f"test_stig_{cfg['src']}_main.rego")).read())
    for sid, tgt in idmap.items():
        if sid in t:
            # the seeded-violation test names one rule: carry its OL id, vuln id and severity
            t = t.replace(sid, tgt["stig_id"])
            t = re.sub(r'f\.vuln_id == "V-\d+"', f'f.vuln_id == "{tgt["vuln_id"]}"', t)
            t = re.sub(r'\(V-\d+\)', f'({tgt["vuln_id"]})', t)
            t = re.sub(r'f\.severity == "CAT I{1,3}"', f'f.severity == "{SEV[tgt["severity"]]}"', t)
            t = re.sub(r'as an Open CAT I{1,3} finding', f'as an Open {SEV[tgt["severity"]]} finding', t)
    unmapped = [m for m in set(re.findall(pfx + r"-\d+", t))]
    if unmapped:
        # a seeded-violation test for a rule OL does not carry: drop that test block
        for sid in unmapped:
            t = re.sub(r"\n(?:#[^\n]*\n)*test_[a-z_]+ if \{(?:[^{}]|\{[^{}]*\})*" + re.escape(sid) + r"(?:[^{}]|\{[^{}]*\})*\}\n", "\n", t)
    open(os.path.join(outdir, "tests", f"test_stig_{key}_main.rego"), "w").write(t)
    print(f"{key}: {n_rules} rules in {len(sections)} modules from {cfg['src']} ({sum(len(BLOCK.findall(open(os.path.join(srcdir, s + '.rego')).read())) for s in sections)} source rules); "
          f"{len(dropped)} source rules without an OL title match; catalog {len(cat['rules'])} rules {cat['version']}")
    for sid, tid, a, b, r in fuzzy:
        print(f"  FUZZY {r:.2f} {sid} -> {tid}\n            {a}\n            {b}")
    for sec, sid, title in dropped:
        cands = difflib.get_close_matches(norm(title), list(by_title), n=3, cutoff=0.45)
        print(f"  dropped {sec:26s} {sid}  {title[:90]}")
        for c in cands:
            print(f"      ? {by_title[c]['stig_id']}  {by_title[c]['title'][:90]}")
    return idmap


if __name__ == "__main__":
    for key, cfg in PLATFORMS.items():
        derive(key, cfg)
