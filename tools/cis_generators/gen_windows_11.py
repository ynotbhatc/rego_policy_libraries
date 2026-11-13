#!/usr/bin/env python3
"""Generate the CIS Microsoft Windows 11 Enterprise Benchmark v5.1.0 module from the benchmark's own workbook.

    python3 tools/cis_generators/gen_windows_11.py <CIS_Microsoft_Windows_11_Enterprise_Benchmark_v5.1.0.xlsx>

The workbook is CIS-licensed and is not committed. This is the Windows 10 Enterprise generator (gen_windows_10.py,
itself the Windows Server 2022 generator with the workstation profile model) pointed at the Windows 11 workbook: the
reader, the derivation, the evaluator changes and the test builder are its; this file holds only what differs.

Counts (v5.1.0 Combined Profiles): 535 recommendations -- 373 Level 1, 117 Level 2 and 45 in the BitLocker
profile (opt-in). 533 Automated, 2 Manual (1.2.3, 2.3.11.5). Windows 11 v5.1.0 publishes no Next Generation
Windows Security profile; `input.cis_profile.next_generation` is accepted for parity with the Windows 10 module
and selects nothing.

Differences from the Windows 10 tables found by running them against this workbook:
  * Windows 11 has no 'Block Microsoft accounts' security option, so the secedit-backed 2.3.1.x ids shift by one
    (2.3.1.1 guest account, 2.3.1.3 / 2.3.1.4 the renames), and 'Force logoff when logon hours expire' (Manual)
    is 2.3.11.5 rather than 2.3.11.6.
  * The IEEE 1394 device-setup-class deny list is 18.9.7.1.2 (Windows 10: 18.9.7.1.5).
  * Windows 11 has no 'Toggle user control over Insider builds' (Windows 10: 18.10.16.7).
  * 2.2.22 and 2.2.23 name RESTRICTED SERVICES\\PrintSpoolerService among the principals; its SID is in the
    Windows 10 generator's table (derived as the 2019 server generator documents).
"""
from __future__ import annotations

import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import gen_windows_10 as w10  # noqa: E402

EQ, NE = w10.EQ, w10.NE


def configure():
    w10.BENCHMARK = "CIS Microsoft Windows 11 Enterprise Benchmark"
    w10.SHORT = "Windows 11 Enterprise"
    w10.VERSION = "5.1.0"
    w10.PKG = "cis_windows_11"
    w10.DIR = "windows_11_modular"
    w10.TOTAL_RECS = 535
    w10.INDEX_NAME = "cis_windows_11_v5_1_index.json"
    w10.GENERATOR = "tools/cis_generators/gen_windows_11.py"

    secedit = dict(w10.SECEDIT)
    for old in ("2.3.1.2", "2.3.1.4", "2.3.1.5"):
        del secedit[old]
    secedit["2.3.1.1"] = ("EnableGuestAccount", EQ, 0)
    secedit["2.3.1.3"] = ("NewAdministratorName", NE, "Administrator")
    secedit["2.3.1.4"] = ("NewGuestName", NE, "Guest")
    w10.SECEDIT = secedit

    w10.MANUAL = {
        "1.2.3": "Administrator account lockout allowed",
        "2.3.11.5": "users forced off when logon hours expire",
    }

    overrides = dict(w10.REGISTRY_OVERRIDES)
    del overrides["18.10.16.7"]
    w10.REGISTRY_OVERRIDES = overrides

    w10.KEY_VALUES = {"18.9.7.1.2": w10.IEEE_1394_CLASSES}

    words = dict(w10.TITLE_WORDS)
    for old in ("2.3.1.2", "2.3.1.4", "2.3.1.5", "2.3.11.6", "18.9.7.1.5", "18.10.16.7"):
        del words[old]
    words.update({
        "2.3.1.1": "Guest account status",
        "2.3.1.3": "Rename administrator",
        "2.3.1.4": "Rename guest",
        "2.3.11.5": "logon hours expire",
        "18.9.7.1.2": "IEEE 1394",
    })
    w10.TITLE_WORDS = words

    # 5.6 is a plain "Disabled" row in Windows 11; the first "or Not Installed" service row is 5.3
    w10.NOT_INSTALLED_EXAMPLE = "5.3"

    # the lib and lib-test headers name the generator that wrote them
    w10.LIB_CHANGES = [(a, b.replace("windows_10_modular", w10.DIR).replace("gen_windows_10.py", "gen_windows_11.py"))
                       for a, b in w10.LIB_CHANGES]
    w10.LIB_TEST_CHANGES = [(a, b.replace("windows_10_modular", w10.DIR).replace("gen_windows_10.py", "gen_windows_11.py"))
                            for a, b in w10.LIB_TEST_CHANGES]


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    configure()
    w10.generate(sys.argv[1])


if __name__ == "__main__":
    main()
