# NIST SP 800-161r1 (Cybersecurity Supply Chain Risk Management) mapped onto the
# substrate. 800-161 is itself a 800-53 SR overlay, so it exercises the
# SR-anchored substrate themes directly.

# METADATA
# title: "NIST SP 800-161r1 (Cybersecurity Supply Chain Risk Management) mapped onto the"
# custom:
#   class: security
#   framework: supply_chain_scrm_800_161
#   source: nist
#   domains: [supply-chain, us-federal]
#   coverage:
#     checks: 1
#     cited: 1
#     density: overlay
#     basis: role
#     tested: true
#     entrypoint: report
#     guard: n/a
#     as_of: v2.4.2
package supply_chain.scrm_800_161

import rego.v1

# Tailoring source record (C-SCRM level gate, tailoring table below):
#   Document: NIST SP 800-161 Rev. 1 update 1 (2024-11-01 update of May 2022)
#   URL:      https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-161r1-upd1.pdf
#   sha256:   d2bacbf4053adbbe11628f74f071077d8fd59ba99754a3aab34d7813c1cb3d40
#   Read:     2026-10-13
#   Table:    Appendix B "C-SCRM Control Summary", Table 6 "C-SCRM control
#             summary" (Table B-1 in the text), printed pp. 164-171. The C-SCRM
#             Baseline and Flow Down columns appear only there; Appendix A
#             gives a per-control "Level(s):" line.
#   Could not read: 0 rows.

reuses_substrate := ["sbom", "provenance", "dependencies", "vulns"]

# ── C-SCRM level gate ─────────────────────────────────────────────────────────
#
# input.scrm_800_161.level selects one column of the tailoring table below:
#   "baseline" | "flow_down" | "level_1" | "level_2" | "level_3"
# Absent evaluates "level_3" (strictest); any other value is itself a violation
# and evaluates "level_3". The columns are not nested: of the controls marked
# at Level 1, 27 are not marked at Level 3, and of those at Level 2, 40 are not;
# 10 C-SCRM Baseline and 7 Flow Down controls are not marked at Level 3.
# The substrate overlay above (reuses_substrate) is unchanged.

_levels := {"baseline", "flow_down", "level_1", "level_2", "level_3"}

default level := "level_3"

level := input.scrm_800_161.level if input.scrm_800_161.level in _levels

default level_defaulted := true

level_defaulted := false if input.scrm_800_161.level in _levels

violations contains msg if {
	v := input.scrm_800_161.level
	not v in _levels
	msg := sprintf("SP 800-161r1 Appendix B: unrecognized input.scrm_800_161.level %v, must be baseline, flow_down, level_1, level_2 or level_3 (evaluated at level_3)", [v])
}

report := {
	"framework": "NIST SP 800-161r1 (C-SCRM)",
	"reuses_substrate": reuses_substrate,
	"tailoring_source": "NIST SP 800-161r1-upd1, Appendix B, Table 6 (C-SCRM control summary)",
	"level": level,
	"level_defaulted": level_defaulted,
	"selected_controls": selected_controls,
	"selected_control_count": count(selected_controls),
	"control_counts": tailoring_counts,
	"violations": violations,
}

# ── C-SCRM tailoring table (Appendix B, Table 6) ──────────────────────────────
#
# Source:  NIST SP 800-161 Rev. 1 update 1, "Cybersecurity Supply Chain Risk
#          Management Practices for Systems and Organizations" (May 2022,
#          updated 2024-11-01), Appendix B "C-SCRM Control Summary", Table 6
#          "C-SCRM control summary" (the text calls it Table B-1; printed
#          pp. 164-171).
# URL:     https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-161r1-upd1.pdf
# sha256:  d2bacbf4053adbbe11628f74f071077d8fd59ba99754a3aab34d7813c1cb3d40
# Read:    2026-10-13
# Note:    the C-SCRM Baseline and Flow Down columns exist only in this
#          Appendix B table. Appendix A ("C-SCRM Security Controls") carries a
#          per-control "Level(s):" line and no Baseline or Flow Down marking.
#
# Transcription rules:
#   - Keys are SP 800-53 Rev. 5 ids in OSCAL token form (AC-3(8) -> ac-3.8).
#     MA-8 and SR-13 are C-SCRM controls with no SP 800-53 Rev. 5 parent
#     (asterisked in the table); they keep the same token form and are listed
#     in _new_controls (row field new_control).
#   - One boolean per column, true where the table prints an "x": C-SCRM
#     Baseline, Flow Down Control, Levels 1, 2 and 3.
#   - Read by word position from the PDF (each "x" assigned to the column
#     header it sits under and the identifier on its line), then checked
#     against an independent text extraction: the number of marks per row
#     agrees for all 297 rows.
#   - Could not read: 0 rows.
#   - Where Appendix A's "Level(s):" line differs from this table, the table
#     is transcribed as printed: CP-3(1) (Appendix A: 3; table: 2, 3), PL-10
#     (Appendix A: 1, 2; table: 2, 3), and Appendix A's SI-7 enhancement
#     labelled "(14) ... CODE AUTHENTICATION" (Level 3), which is SI-7(15) in
#     SP 800-53 Rev. 5 (table: SI-7(14) 2, 3; SI-7(15) 3).
#   - The 2024-11-01 update's change log adds RA-3(1) and PM-30 as Flow Down
#     and C-SCRM Baseline controls; both rows are marked so here.
#
# Measured (rows marked true): 297 rows; baseline 95, flow_down 69,
# level_1 76, level_2 236, level_3 251.

# [token, baseline, flow_down, level_1, level_2, level_3]
_tailoring_rows := [
	# Table 6, p. 164
	["ac-1", true, true, true, true, true],
	["ac-2", true, true, false, true, true],
	["ac-3", true, true, false, true, true],
	["ac-3.8", false, false, false, true, true],
	["ac-3.9", false, false, false, true, true],
	["ac-4", false, true, false, true, true],
	["ac-4.6", false, false, false, true, true],
	["ac-4.17", false, false, false, true, true],
	["ac-4.19", false, false, false, true, true],
	["ac-4.21", false, false, false, false, true],
	["ac-5", false, true, false, true, true],
	["ac-6.6", false, false, false, true, true],
	["ac-17", true, true, false, true, true],
	["ac-17.6", false, false, false, true, true],
	["ac-18", true, false, true, true, true],
	["ac-19", true, false, false, true, true],
	["ac-20", true, true, true, true, true],
	["ac-20.1", false, false, false, true, true],
	["ac-20.3", false, false, false, true, true],
	["ac-21", false, false, true, true, false],
	["ac-22", true, false, false, true, true],
	["ac-23", false, true, false, true, true],
	["ac-24", false, true, true, true, true],
	["at-1", true, false, true, true, false],
	["at-2.1", false, false, false, true, false],
	["at-2.2", true, true, false, true, false],
	["at-2.3", false, false, false, true, false],
	# Table 6, p. 165
	["at-2.4", false, false, false, true, false],
	["at-2.5", false, false, false, true, false],
	["at-2.6", false, false, false, true, false],
	["at-3", true, true, false, true, false],
	["at-3.2", false, false, false, true, false],
	["at-3.6", false, false, false, true, false],
	["at-4", true, false, false, true, false],
	["au-1", true, false, true, true, true],
	["au-2", true, true, true, true, true],
	["au-3", true, true, true, true, true],
	["au-6", true, false, false, true, true],
	["au-6.9", false, false, false, false, true],
	["au-10", false, false, false, false, true],
	["au-10.1", false, false, false, true, false],
	["au-10.2", false, false, false, true, true],
	["au-10.3", false, false, false, true, true],
	["au-12", true, true, false, true, true],
	["au-13", false, true, false, true, true],
	["au-14", false, true, false, true, true],
	["au-16", false, false, false, true, true],
	["au-16.2", false, true, false, true, true],
	["ca-1", true, false, true, true, true],
	["ca-2", true, false, false, true, true],
	["ca-2.2", false, false, false, false, true],
	["ca-2.3", false, false, false, false, true],
	["ca-3", true, true, false, false, true],
	["ca-5", true, false, false, true, true],
	["ca-6", true, false, true, true, true],
	["ca-7.3", false, false, false, false, true],
	["cm-1", true, false, true, true, true],
	["cm-2", true, true, false, true, true],
	["cm-2.6", false, false, false, true, true],
	["cm-3", false, true, false, true, true],
	["cm-3.1", false, false, false, true, true],
	["cm-3.2", false, false, false, true, true],
	["cm-3.4", false, false, false, true, true],
	["cm-3.8", false, false, false, true, true],
	["cm-4", true, false, false, false, true],
	# Table 6, p. 166
	["cm-4.1", false, false, false, false, true],
	["cm-5", true, false, false, true, true],
	["cm-5.1", false, false, false, false, true],
	["cm-5.6", false, false, false, false, true],
	["cm-6", true, true, false, true, true],
	["cm-6.1", false, false, false, false, true],
	["cm-6.2", false, false, false, false, true],
	["cm-7", true, true, false, false, true],
	["cm-7.1", false, false, false, true, true],
	["cm-7.4", false, false, false, true, true],
	["cm-7.5", false, false, false, false, true],
	["cm-7.6", false, false, false, true, true],
	["cm-7.7", false, false, false, false, true],
	["cm-7.8", false, false, false, true, true],
	["cm-7.9", false, false, false, true, true],
	["cm-8", true, true, false, true, true],
	["cm-8.1", false, false, false, false, true],
	["cm-8.2", false, false, false, false, true],
	["cm-8.4", false, false, false, false, true],
	["cm-8.6", false, false, false, false, true],
	["cm-8.7", false, false, false, false, true],
	["cm-8.8", false, false, false, true, true],
	["cm-8.9", false, false, false, false, true],
	["cm-8.10", false, false, false, false, true],
	["cm-9", false, true, false, true, true],
	["cm-9.1", false, false, false, true, true],
	["cm-10", true, false, false, true, true],
	["cm-10.1", false, false, false, true, true],
	["cm-11", true, false, false, true, true],
	["cm-12", false, false, false, true, true],
	["cm-12.1", false, false, false, true, true],
	["cm-13", false, false, false, true, true],
	["cm-14", false, false, false, false, true],
	["cp-1", true, false, true, true, true],
	["cp-2", true, false, false, true, true],
	["cp-2.1", false, false, false, true, true],
	["cp-2.2", false, false, false, true, true],
	["cp-2.7", false, true, false, false, true],
	["cp-2.8", false, false, false, false, true],
	# Table 6, p. 167
	["cp-3", true, true, false, true, true],
	["cp-3.1", false, false, false, true, true],
	["cp-4", true, false, false, true, true],
	["cp-6", false, false, false, true, true],
	["cp-6.1", false, false, false, true, true],
	["cp-7", false, false, false, true, true],
	["cp-8", false, false, false, true, true],
	["cp-8.3", false, false, false, true, true],
	["cp-8.4", false, false, false, true, true],
	["cp-11", false, false, false, true, true],
	["ia-1", true, false, true, true, true],
	["ia-2", true, true, true, true, true],
	["ia-3", false, false, true, true, true],
	["ia-4", true, true, false, true, true],
	["ia-4.6", false, false, true, true, true],
	["ia-5", true, true, false, true, true],
	["ia-5.5", false, false, false, false, true],
	["ia-5.9", false, false, false, false, true],
	["ia-8", true, false, false, true, true],
	["ia-9", false, true, false, true, true],
	["ir-1", true, true, true, true, true],
	["ir-2", true, true, false, true, true],
	["ir-3", false, false, false, true, true],
	["ir-4.6", false, false, true, true, true],
	["ir-4.7", false, false, true, true, true],
	["ir-4.10", false, true, false, true, false],
	["ir-4.11", false, false, false, false, true],
	["ir-5", true, false, false, true, true],
	["ir-6.3", false, true, false, false, true],
	["ir-7.2", false, true, false, false, true],
	["ir-8", true, true, false, true, true],
	["ir-9", false, true, false, false, true],
	["ma-1", true, true, true, true, true],
	["ma-2.2", false, false, false, false, true],
	["ma-3", false, false, false, true, true],
	["ma-3.1", false, false, false, false, true],
	["ma-3.2", false, false, false, false, true],
	["ma-3.3", false, false, false, false, true],
	["ma-4", true, true, false, true, true],
	["ma-4.3", false, false, false, true, true],
	["ma-5", true, false, false, true, true],
	["ma-5.4", false, true, false, true, true],
	# Table 6, p. 168
	["ma-6", false, false, false, false, true],
	["ma-7", false, false, false, false, true],
	["ma-8", false, false, false, false, true],
	["mp-1", true, false, true, true, false],
	["mp-4", false, true, true, true, false],
	["mp-5", false, false, true, true, false],
	["mp-6", true, true, false, true, true],
	["pe-1", true, false, true, true, true],
	["pe-2", true, true, false, true, true],
	["pe-2.1", false, false, false, true, true],
	["pe-3", true, false, false, true, true],
	["pe-3.1", false, false, false, true, true],
	["pe-3.2", false, false, false, true, true],
	["pe-3.5", false, false, false, true, true],
	["pe-6", true, false, true, true, true],
	["pe-16", true, false, false, false, true],
	["pe-17", false, false, false, false, true],
	["pe-18", false, false, true, true, true],
	["pe-20", false, false, false, true, true],
	["pe-23", false, true, false, true, true],
	["pl-1", true, false, false, true, false],
	["pl-2", true, true, false, false, true],
	["pl-4", true, false, false, true, true],
	["pl-7", false, false, false, false, true],
	["pl-8", false, false, false, true, true],
	["pl-8.2", false, false, false, true, true],
	["pl-9", false, false, true, true, false],
	["pl-10", true, false, false, true, true],
	["pm-2", false, false, true, true, false],
	["pm-3", false, false, true, true, false],
	["pm-4", false, false, false, true, true],
	["pm-5", false, true, false, true, true],
	["pm-6", false, false, true, true, false],
	["pm-7", false, false, true, true, false],
	["pm-8", false, false, true, false, false],
	["pm-9", false, false, true, false, false],
	["pm-10", false, false, true, true, false],
	["pm-11", false, false, true, true, true],
	["pm-12", false, false, true, true, true],
	["pm-13", false, false, true, true, false],
	["pm-14", false, false, true, true, false],
	["pm-15", false, false, true, true, false],
	["pm-16", false, false, true, true, false],
	["pm-17", false, false, false, true, false],
	["pm-18", false, true, true, true, false],
	["pm-19", false, false, true, false, false],
	# Table 6, p. 169
	["pm-20", false, false, true, true, false],
	["pm-21", false, false, true, true, false],
	["pm-22", false, false, true, true, false],
	["pm-23", false, false, true, false, false],
	["pm-25", false, false, false, true, false],
	["pm-26", false, false, false, true, true],
	["pm-27", false, false, false, true, true],
	["pm-28", false, false, true, false, false],
	["pm-29", false, false, true, false, false],
	["pm-30", true, true, true, true, false],
	["pm-31", false, false, true, true, true],
	["pm-32", false, false, false, true, true],
	["ps-1", true, true, true, true, true],
	["ps-3", true, true, false, true, true],
	["ps-6", true, true, false, true, true],
	["ps-7", true, false, false, true, false],
	["pt-1", false, true, true, true, true],
	["ra-1", true, false, true, true, true],
	["ra-2", true, false, true, true, true],
	["ra-3", true, false, true, true, true],
	["ra-3.1", true, true, true, true, true],
	["ra-5", true, true, false, true, true],
	["ra-5.3", false, false, false, true, true],
	["ra-5.6", false, false, false, true, true],
	["ra-7", true, false, true, true, true],
	["ra-9", false, true, true, true, true],
	["ra-10", false, false, true, true, true],
	["sa-1", true, false, true, true, true],
	["sa-2", true, false, true, true, false],
	["sa-3", true, false, true, true, true],
	["sa-4", true, false, true, true, true],
	["sa-4.5", false, false, false, false, true],
	["sa-4.7", false, false, false, true, true],
	["sa-4.8", false, false, false, true, true],
	["sa-5", true, false, false, false, true],
	["sa-8", true, false, true, true, true],
	["sa-9.1", false, false, false, true, true],
	["sa-9.3", false, false, true, true, true],
	["sa-9.4", false, false, false, false, true],
	# Table 6, p. 170
	["sa-9.5", false, false, false, false, true],
	["sa-10", false, false, false, true, true],
	["sa-11", false, false, true, true, true],
	["sa-15", false, false, false, true, true],
	["sa-15.3", false, false, false, true, true],
	["sa-15.4", false, false, false, true, true],
	["sa-15.8", false, false, false, false, true],
	["sa-16", false, false, false, true, true],
	["sa-17", false, false, false, true, true],
	["sa-20", false, false, false, true, true],
	["sa-21", false, true, false, true, true],
	["sa-21.1", false, false, false, true, true],
	["sa-22", true, false, false, true, true],
	["sc-1", true, false, true, true, true],
	["sc-4", false, false, false, true, true],
	["sc-5.2", false, false, false, true, false],
	["sc-7", true, true, false, true, false],
	["sc-7.13", false, true, false, false, true],
	["sc-7.14", false, false, false, true, true],
	["sc-7.19", false, false, false, false, true],
	["sc-8", false, true, false, true, true],
	["sc-18", false, false, false, false, true],
	["sc-18.2", false, false, false, false, true],
	["sc-27", false, false, false, true, true],
	["sc-28", false, true, false, true, true],
	["sc-29", false, false, false, true, true],
	["sc-30", false, false, false, true, true],
	["sc-30.2", false, false, false, true, true],
	["sc-30.3", false, false, false, true, true],
	["sc-30.4", false, false, false, true, true],
	["sc-30.5", false, false, false, true, true],
	["sc-36", false, true, false, true, true],
	["sc-37.1", false, false, false, true, true],
	["sc-38", false, false, false, true, true],
	["sc-47", false, false, true, true, true],
	["si-1", true, false, true, true, true],
	["si-2", true, true, false, true, true],
	["si-2.5", false, false, false, true, false],
	# Table 6, p. 171
	["si-3", true, true, false, true, true],
	["si-4", true, true, true, true, true],
	["si-4.17", false, false, false, true, true],
	["si-4.19", false, false, false, true, true],
	["si-5", true, true, true, true, true],
	["si-7", true, true, false, true, true],
	["si-7.14", false, false, false, true, true],
	["si-7.15", false, false, false, false, true],
	["si-12", true, false, false, false, true],
	["si-20", false, true, false, true, true],
	["sr-1", true, false, true, true, true],
	["sr-2", true, false, false, false, true],
	["sr-3", true, false, true, true, true],
	["sr-3.1", false, false, false, true, true],
	["sr-3.3", false, true, false, true, true],
	["sr-4", false, false, false, true, true],
	["sr-5", true, false, true, true, true],
	["sr-6", false, false, false, true, true],
	["sr-7", false, false, false, true, true],
	["sr-8", true, false, false, true, true],
	["sr-9", false, false, false, true, true],
	["sr-10", true, true, false, true, true],
	["sr-11", true, false, true, true, true],
	["sr-11.1", true, false, false, true, true],
	["sr-11.2", true, false, false, true, true],
	["sr-11.3", false, false, false, true, true],
	["sr-12", true, false, false, true, true],
	["sr-13", false, false, false, true, true],
]

# Asterisked in Table 6: C-SCRM controls not defined in SP 800-53 Rev. 5
_new_controls := {"ma-8", "sr-13"}

tailoring := {r[0]: row |
	some r in _tailoring_rows
	row := {
		"baseline": r[1],
		"flow_down": r[2],
		"level_1": r[3],
		"level_2": r[4],
		"level_3": r[5],
		"new_control": r[0] in _new_controls,
	}
}

tailoring_counts := {c: n |
	some c in _levels
	n := count([k | some k; row := tailoring[k]; row[c]])
}

selected_controls := sort([k | some k; row := tailoring[k]; row[level]])
