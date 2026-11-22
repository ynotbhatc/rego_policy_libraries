# SUNSET — no current DISA STIG for this platform

**Verified against the July 2026 SRG-STIG Library Compilation (2026-09-03):**
this platform's STIG is **absent from the current DISA library** (Ubuntu 20.04 LTS standard support ended
31 May 2025; ESM with Ubuntu Pro runs to May 2030).

**Final DISA release: V2R4, 01 Oct 2025** — still served as the standalone
`U_CAN_Ubuntu_20-04_LTS_V2R4_STIG.zip` (checked 2026-11-21). V2R4 adds UBTU-20-010001, the sunset control:
the release must be vendor supported, and DISA's discussion says the platform must be removed from the enclave
network or upgraded. No further releases are expected.

The module (2026-11-21) implements 4 of the 173 V2R4 rules, each against its check text: UBTU-20-010001
(attested vendor support), UBTU-20-010443 (DoD root CA), UBTU-20-010054 (minlen 15) and UBTU-20-010070
(remember 5). Before that it was a five-check stub on V2R1 with invented ids. It is retained for historical
assessments only; the remaining rules are not planned.

**Successor:** Ubuntu 22.04 LTS (`benchmarks/stig/ubuntu_22_04/`).

Do not wire this framework key into new assessments. The standards-update
registry tracks the STIG family's quarterly cycle.
