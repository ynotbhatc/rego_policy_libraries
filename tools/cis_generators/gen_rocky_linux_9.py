#!/usr/bin/env python3
"""CIS Rocky Linux 9 Benchmark v3.0.0: every recommendation, from the benchmark's own workbook.

    python3 tools/cis_generators/gen_rocky_linux_9.py CIS_Rocky_Linux_9_Benchmark_v3.0.0.xlsx [fields.json]

Needs openpyxl. The workbook is CIS-licensed and never committed.

Rocky Linux 9 v3.0.0 is the sibling of CIS Red Hat Enterprise Linux 9 v3.0.0. This script holds no logic of
its own: it points gen_rhel_9.py (reader, logic table, emitter, test builder) at the Rocky workbook and at
benchmarks/cis/rocky_linux_9/, package cis_rocky_linux_9. Nothing is assumed about the two benchmarks lining
up; the run reads the Rocky workbook and aborts unless

  * it holds exactly 352 recommendations, 329 Automated and 23 Manual;
  * every id has a logic entry and every logic entry an id, with the same Automated/Manual status;
  * the title keyword of every logic entry occurs in the Rocky title of that id;
  * the audit procedures are the ones the logic table was written from (AUDIT_DIGEST: a SHA-256 over id,
    status, profiles and whitespace-normalised audit procedure of every recommendation; the RHEL 9 v3.0.0
    workbook gives the same digest, which is what makes sharing the logic table correct, not a guess).

Profiles are read from the Rocky workbook's Level 1/2 - Server/Workstation sheets. If a later Rocky release
diverges, the digest check fails first: review each changed audit procedure, give this script its own logic
for those ids (g.L / g.KW entries replaced before g.main), then update the digest.

Layout and input contract are the rhel_9 module's, so one collector feeds both: the same fourteen section
packages (cis_rocky_linux_9.<section>), roll-up cis_rocky_linux_9, bridge cis_rocky_linux_9.main
(compliance_report) and Level 2 view cis_rocky_linux_9.l2. The extended-hardening modules of rhel_9 (STIG /
NIST) are not CIS recommendations and are not part of this module.
"""
import hashlib
import sys

import openpyxl

import gen_rhel_9 as g

PKG = "cis_rocky_linux_9"
BENCH = "CIS Rocky Linux 9 Benchmark v3.0.0"
OUT = g.HERE.parent.parent / "benchmarks" / "cis" / "rocky_linux_9"
AUDIT_DIGEST = "cb6d864aacbf69d866b12d0298c022fcb347b96f51f980543bc8d55d3f51bd2c"

# Wording of the shared emitter that describes rhel_9 history; restated for a module that has none.
REWORD = [
    (f"Kept as {PKG}.l2 for callers\n# of the v2.0.0 package; the", "The counterpart of cis_rhel9.l2; the"),
    ("v2.0.0", "rhel_9 v2.0.0"),
]


def audit_digest(path):
    """SHA-256 over (id, status, profiles, audit procedure with whitespace collapsed) of every recommendation."""
    wb = openpyxl.load_workbook(path, read_only=True)
    recs = {}
    for ws in wb.worksheets:
        if ws.title in g.SKIP_SHEETS:
            continue
        rows = ws.iter_rows(values_only=True)
        head = next(rows)
        for r in rows:
            d = dict(zip(head, r))
            if not d.get("Recommendation #"):
                continue
            rid = str(d["Recommendation #"]).strip()
            rec = recs.setdefault(rid, {"status": str(d["Assessment Status"]).strip(), "profiles": [],
                                        "audit": " ".join(str(d["Audit Procedure"]).split())})
            rec["profiles"].append(ws.title)
    h = hashlib.sha256()
    for rid in sorted(recs, key=g.sort_key):
        rec = recs[rid]
        h.update("\x1f".join([rid, rec["status"], ",".join(rec["profiles"]), rec["audit"]]).encode() + b"\x1e")
    return h.hexdigest()


def main():
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    digest = audit_digest(sys.argv[1])
    if digest != AUDIT_DIGEST:
        raise SystemExit(f"audit procedures, statuses or profiles differ from the ones the logic table was written "
                         f"from (digest {digest}): review the changed recommendations before regenerating")
    g.configure(OUT=OUT, PKG=PKG, GEN="tools/cis_generators/gen_rocky_linux_9.py", BENCH=BENCH, VERSION="v3.0.0",
                EXPECTED_TOTAL=352, EXPECTED_AUTOMATED=329, EXPECTED_MANUAL=23,
                FRAMEWORK="cis_rocky_linux_9", DOMAINS="linux, rocky", EXTENDED=False,
                REPORT_EXTRA=[("violation_count", "count(_violations)")], REWORD=REWORD)
    g.main(sys.argv)


if __name__ == "__main__":
    main()
