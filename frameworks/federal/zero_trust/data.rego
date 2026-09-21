package zero_trust.data

import rego.v1

# CISA Zero Trust Maturity Model (ZTMM) v2.0 — Data pillar.
#
# The Data pillar functions are Data Inventory Management, Data
# Categorization, Data Availability, Data Access, and Data Encryption,
# plus the pillar-level cross-cutting capabilities Visibility & Analytics,
# Automation & Orchestration, and Governance. Maturity advances through the
# stages Traditional -> Initial -> Advanced -> Optimal. NIST SP 800-207
# tenets inform the criteria.
#
# ZTMM does not publish a numbered control list, so the criteria below are
# AAC's operationalization of the pillar's functions into discrete,
# assessable statements. Each criterion is tagged with the maturity stage
# it represents and the function it exercises. This is AAC's assessment
# mapping, not a verbatim reproduction of the model.
criteria := {
	"DATA-1": {"stage": "initial", "function": "Data Inventory Management", "title": "A data inventory is maintained"},
	"DATA-2": {"stage": "advanced", "function": "Data Inventory Management", "title": "Data inventory is automated and continuously discovered"},
	"DATA-3": {"stage": "initial", "function": "Data Categorization", "title": "Data is categorized and labeled by sensitivity"},
	"DATA-4": {"stage": "advanced", "function": "Data Categorization", "title": "Data is automatically tagged/classified at creation"},
	"DATA-5": {"stage": "initial", "function": "Data Availability", "title": "Critical data is backed up with verified recovery"},
	"DATA-6": {"stage": "advanced", "function": "Data Availability", "title": "Data availability uses redundant, geographically distributed stores"},
	"DATA-7": {"stage": "advanced", "function": "Data Access", "title": "Access decisions use data category plus identity"},
	"DATA-8": {"stage": "optimal", "function": "Data Access", "title": "Access is dynamically authorized per-request from real-time risk"},
	"DATA-9": {"stage": "initial", "function": "Data Encryption", "title": "Data is encrypted at rest and in transit"},
	"DATA-10": {"stage": "optimal", "function": "Data Encryption", "title": "Encryption keys are centrally managed with automated rotation"},
	"DATA-11": {"stage": "advanced", "function": "Visibility & Analytics", "title": "Data Loss Prevention (DLP) is enforced and monitored"},
	"DATA-12": {"stage": "initial", "function": "Governance", "title": "Data lifecycle and retention policies are documented and enforced"},
}

attested(id) if input.zero_trust.data.criteria[id] == true

# Fail closed: an unattested criterion is a gap.
violation contains msg if {
	some id, m in criteria
	not attested(id)
	msg := sprintf("Zero Trust [Data] %s (%s / %s): %s — not met", [id, m.stage, m.function, m.title])
}

default pillar_compliant := false

pillar_compliant if count(violation) == 0

compliance_report := {
	"pillar": "Data",
	"criteria_evaluated": count(criteria),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": pillar_compliant,
}
