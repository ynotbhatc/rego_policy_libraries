#!/usr/bin/env python3
"""CIS Rocky Linux 8 Benchmark v3.0.0: every recommendation, from the benchmark's own workbook.

    python3 tools/cis_generators/gen_rocky_linux_8.py CIS_Rocky_Linux_8_Benchmark_v3.0.0.xlsx [fields.json]

Needs openpyxl. The workbook is CIS-licensed and never committed.

Rocky Linux 8 v3.0.0 is the sibling of CIS Red Hat Enterprise Linux 8 v4.0.0: the two workbooks carry the same
322 ids, titles, Automated/Manual statuses, profiles and audit procedures (the Rocky workbook adds only a
License sheet). This script holds no logic of its own: it points gen_rhel_8.py (logic table, helpers, emitter)
at benchmarks/cis/rocky_linux_8/, package cis_rocky_linux_8. Nothing is assumed: gen_rhel_8.main reads the
Rocky workbook and aborts unless the counts, statuses and title keywords match the logic table and the digest
of every id, status, profile and audit procedure equals gen_rhel_8.AUDIT_DIGEST, the one the table was written
from. If a later Rocky release diverges, the digest check fails first: review each changed audit procedure and
give this script its own logic for those ids (entries of gen_rhel_8.L / KW replaced before main), with its own
digest.

Layout and input contract are the rhel_8 module's, so one collector feeds both: fourteen section packages
(cis_rocky_linux_8.<section>), roll-up cis_rocky_linux_8, bridge cis_rocky_linux_8.main (compliance_report),
Level 2 view cis_rocky_linux_8.l2, and the section keys of the earlier rocky_linux_8 module.
"""
import sys

import gen_rhel_8 as g

g.configure(OUT=g.HERE.parent.parent / "benchmarks" / "cis" / "rocky_linux_8", PKG="cis_rocky_linux_8",
            GEN="tools/cis_generators/gen_rocky_linux_8.py", BENCH="CIS Rocky Linux 8 Benchmark v3.0.0",
            VERSION="v3.0.0", FRAMEWORK="cis_rocky_linux_8", DOMAINS="linux, rocky")

if __name__ == "__main__":
    g.main(sys.argv)
