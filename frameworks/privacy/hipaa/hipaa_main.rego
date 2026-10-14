# HIPAA Administrative Simplification - aggregator (45 CFR Parts 160, 162 and 164, plus the HITECH Act).
#
# Every module below keys its controls to the regulation's own paragraph citations (45 CFR, 2025 annual
# edition, GovInfo bulk XML, sha256 5fb58263c7533af259dacbc0d72e097158b995551a0fb241c4f997d4ef856b52,
# retrieved 2026-10-13) and is fail-closed on its own:
#
#   module                 scope                                                     rows  facts  attested
#   hipaa.part160          Part 160 - general administrative requirements              8      0        8
#   hipaa.part162          Part 162 - transactions, code sets, identifiers            43      0       43
#   hipaa.security_rule    Part 164 Subpart C - Security Rule (§§ 164.308-164.316)    68     48       20
#   hipaa.hitech           Part 164 Subpart D - Breach Notification (§§ 164.400-414)  17      9        8
#                          + HITECH Act statutory checks (42 U.S.C.)                   7      7        -
#   hipaa.privacy_rule     Part 164 Subpart E - Privacy Rule (§§ 164.500-164.534)    110     37       73
#
# The Security Rule's technical safeguards are decided by the data-activity modules in this directory
# (access_control, audit_controls, integrity, authentication, transmission_security). Part 164 Subpart A
# (§ 164.105 hybrid and affiliated entities) is not yet carried as rows.
#
# Overall compliance requires every module to be compliant. Query: POST /v1/data/hipaa/main/report

# METADATA
# title: "HIPAA Administrative Simplification aggregator - 45 CFR Parts 160, 162 and 164 (Subparts C, D, E) and the HITECH Act"
# custom:
#   class: compliance
#   framework: hipaa
#   source: hhs
#   domains: [privacy, healthcare]
#   coverage:
#     checks: 0
#     cited: 0
#     density: orchestrator
#     basis: role
#     tested: true
#     entrypoint: report
#     guard: self
#     as_of: v2.4.2
package hipaa.main

import rego.v1

import data.hipaa.hitech
import data.hipaa.part160
import data.hipaa.part162
import data.hipaa.privacy_rule
import data.hipaa.security_rule

default security_rule_compliant := false

security_rule_compliant if security_rule.compliant

default privacy_rule_compliant := false

privacy_rule_compliant if privacy_rule.compliant

default hitech_compliant := false

hitech_compliant if hitech.compliant

default part160_compliant := false

part160_compliant if part160.compliant

default part162_compliant := false

part162_compliant if part162.compliant

default overall_compliant := false

overall_compliant if {
	part160_compliant
	part162_compliant
	security_rule_compliant
	hitech_compliant
	privacy_rule_compliant
}

_domains := [
	security_rule_compliant,
	privacy_rule_compliant,
	hitech_compliant,
	part160_compliant,
	part162_compliant,
]

domains_passing := count([d | some d in _domains; d == true])

# Individual safeguard scores (from the Security Rule)
_admin_score := 1 if security_rule.administrative_safeguards_compliant

else := 0

_phys_score := 1 if security_rule.physical_safeguards_compliant

else := 0

_tech_score := 1 if security_rule.technical_safeguards_compliant

else := 0

security_safeguards_score := (((_admin_score + _phys_score) + _tech_score) * 100) / 3

_part(compliant, r) := {
	"compliant": compliant,
	"controls": r.controls_total,
	"applicable": r.applicable,
	"satisfied": r.satisfied,
	"violation_count": r.violation_count,
	"details": r,
}

# One entry per module (named `sections`, the library's convention for a per-part breakdown).
sections := {
	"part_160": _part(part160_compliant, part160.compliance_report),
	"part_162": _part(part162_compliant, part162.compliance_report),
	"security_rule": _part(security_rule_compliant, security_rule.report),
	"hitech_act": _part(hitech_compliant, hitech.report),
	"privacy_rule": _part(privacy_rule_compliant, privacy_rule.report),
}

report := {
	"standard": "HIPAA Administrative Simplification (45 CFR Parts 160, 162, 164) + HITECH Act",
	"overall_compliant": overall_compliant,
	"compliant": overall_compliant,
	"domains": sections,
	"domains_passing": domains_passing,
	"domains_total": count(_domains),
	"security_safeguards_score_pct": security_safeguards_score,
}
