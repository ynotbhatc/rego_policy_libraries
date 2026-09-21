package cjis.physical_protection

import rego.v1

# FBI CJIS Security Policy — Policy Area 9: Physical Protection.
# Requirements are AAC's operationalization of the policy area (CJIS maps to NIST 800-53).
requirements := {
	"PP-1": {"area": 9, "title": "A physically secure location is established and documented for the storage, processing, and access of CJI"},
	"PP-2": {"area": 9, "title": "Physical access authorizations to the CJI area are issued, maintained, and reviewed for authorized personnel only"},
	"PP-3": {"area": 9, "title": "Physical access to the secure area is controlled and enforced at entry points to prevent unauthorized entry"},
	"PP-4": {"area": 9, "title": "Visitors to the physically secure area are identified, authorized, escorted, and monitored at all times"},
	"PP-5": {"area": 9, "title": "A visitor access record for the secure area is maintained and retained for the required period"},
	"PP-6": {"area": 9, "title": "Physical access devices (keys, badges, combinations) are inventoried, controlled, and changed when personnel change or devices are lost"},
	"PP-7": {"area": 9, "title": "Information system distribution and transmission lines within the secure area are protected from interception and damage"},
}

attested(id) if input.cjis.physical_protection.requirements[id] == true

# Fail closed: an unattested requirement is a gap.
violation contains msg if {
	some id, m in requirements
	not attested(id)
	msg := sprintf("CJIS [Physical Protection] %s: %s — not met", [id, m.title])
}

default area_compliant := false

area_compliant if count(violation) == 0

compliance_report := {
	"policy_area": 9,
	"area_name": "Physical Protection",
	"requirements_evaluated": count(requirements),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": area_compliant,
}
