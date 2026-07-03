# Consumer endpoint for the compliance-repo soc2 role.
# The role queries POST /v1/data/soc2/soc2_assessment and reads .compliant
# and .score. This lives in the bare `soc2` package (NOT soc2.main) so it
# resolves at data.soc2.soc2_assessment — the path the playbook queries.
# Security is the required common criteria; score = % of the 5 TSC passing.
package soc2

import rego.v1

import data.soc2.main

soc2_tsc_passing := count([c |
	some c in [
		main.security_compliant,
		main.availability_compliant,
		main.processing_integrity_compliant,
		main.confidentiality_compliant,
		main.privacy_compliant,
	]
	c == true
])

soc2_assessment := {
	"framework": "SOC 2 (2017 Trust Services Criteria)",
	"compliant": main.security_compliant,
	"score": round((100 * soc2_tsc_passing) / 5),
	"criteria_evaluated": 5,
	"criteria_passing": soc2_tsc_passing,
	"tsc_results": {
		"security": main.security_compliant,
		"availability": main.availability_compliant,
		"processing_integrity": main.processing_integrity_compliant,
		"confidentiality": main.confidentiality_compliant,
		"privacy": main.privacy_compliant,
	},
}
