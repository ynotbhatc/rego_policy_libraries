# Sunset STIG platforms

Platforms DISA has retired. A platform that leaves the SRG-STIG Library is recorded here,
never silently dropped; the last release DISA published is the one assessments should cite.

| Platform | Final DISA release | Sunset | Module removed | Successor |
|---|---|---|---|---|
| Windows 10 (`windows_10`, `stig.windows_10`) | V3R6 | Sunset by DISA — absent from the October 2026 SRG-STIG Library Compilation; Windows 10 reached end of support in October 2025 | 2026-11-10 (the 5-finding stub at `benchmarks/stig/windows_10/` is in git history before this date) | Windows 11 (`benchmarks/stig/windows_11/`) |

`ubuntu_20_04` keeps its own `SUNSET.md` in `benchmarks/stig/ubuntu_20_04/` with the module
content frozen for historical assessments.
