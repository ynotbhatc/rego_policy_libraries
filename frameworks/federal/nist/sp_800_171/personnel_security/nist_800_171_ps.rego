# METADATA
# title: "NIST SP 800-171 Rev 3 - Personnel Security (PS) Requirements"
# custom:
#   class: compliance
#   framework: nist_sp_800_171
#   source: nist
#   domains: [us-federal, security-controls]
#   coverage:
#     checks: 2
#     cited: 2
#     expected: 2
#     found: 2
#     scope: module
#     density: full
#     basis: declared-total
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package nist.sp800_171.personnel_security

import rego.v1

# NIST SP 800-171 Rev 3 - Personnel Security (PS) Requirements
#
# Ids are NIST SP 800-171 Rev 3 element identifiers from the NIST CPRT export
# (https://csrc.nist.gov/extensions/nudp/services/json/nudp/framework/version/SP_800_171_3_0_0/export/json?element=all, sha256 19d18ef88700e468..., retrieved 2026-10-13).
# The fact checks below were written against the Rev 2 statements; each is re-keyed to the Rev 3
# requirement that carries its Rev 2 slot. A Rev 2 slot withdrawn in Rev 3 with "Incorporated into"
# is keyed to the incorporating requirement(s); one withdrawn as "Addressed by", recategorized as
# NCO, technology-specific or for consistency with SP 800-53 is retired: its rule is kept for lineage
# but it emits no violation and is not a Rev 3 control. Rev 3 status per requirement (attestation
# plus these facts) is computed by nist_800_171_main.rego (package nist_800_171.main).
# Family: 03.09 Personnel Security — Protecting Controlled Unclassified Information (CUI)

# 03.09.01 Personnel Screening (Rev 2 3.9.1): Screen individuals prior to authorizing access to organizational systems containing CUI
default personnel_screening := false

personnel_screening if {
	input.nist_800_171.personnel_security.screening.background_checks_performed == true
	input.nist_800_171.personnel_security.screening.criteria_documented == true
	input.nist_800_171.personnel_security.screening.rescreening_policy == true
}

# 03.09.02 Personnel Termination and Transfer (Rev 2 3.9.2): Ensure CUI is protected during and after personnel actions such as terminations and transfers
default personnel_actions_protection := false

personnel_actions_protection if {
	input.nist_800_171.personnel_security.personnel_actions.termination_procedures == true
	input.nist_800_171.personnel_security.personnel_actions.transfer_procedures == true
	input.nist_800_171.personnel_security.personnel_actions.access_revocation_timely == true
	input.nist_800_171.personnel_security.personnel_actions.property_return_required == true
}

# Violations set
violations contains msg if {
	not personnel_screening
	msg := "NIST SP 800-171 03.09.01: Personnel screening must be performed prior to authorizing access to systems containing CUI"
}

violations contains msg if {
	not personnel_actions_protection
	msg := "NIST SP 800-171 03.09.02: CUI must be protected during and after personnel actions (terminations, transfers) with timely access revocation"
}

# Compliance aggregation
default compliant := false

compliant if count(violations) == 0

compliance_report := {
	"family": "03.09 Personnel Security",
	"standard": "NIST SP 800-171 Rev 3",
	"total_controls": 2,
	"violations": violations,
	"compliant": compliant,
	"controls": {
		"03.09.01_personnel_screening": personnel_screening,
		"03.09.02_personnel_actions_protection": personnel_actions_protection,
	},
}
