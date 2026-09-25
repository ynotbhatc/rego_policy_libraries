# NIST SSDF (SP 800-218) mapped onto the supply-chain substrate (representative
# subset of practices). Like the SLSA file, this is a MAPPING: each practice is
# expressed via substrate rules, so `reuses_substrate` shows the overlap.
#
#   PS.2  Protect software integrity        -> signing
#   PS.3  Archive & provenance (SBOM)        -> sbom (+ provenance)
#   PW.4  Reuse well-secured components      -> dependencies
#   PW.7  Review & analyze code / changes    -> source_control
#   RV.*  Respond to vulnerabilities         -> vulns
#
# A GenAI profile (SSDF 800-218A) would add AI-contribution practices mapping to
# the same substrate plus an AI-attestation signal — left as a follow-on package.
package supply_chain.ssdf

import rego.v1

import data.supply_chain.substrate

practice_status := {
	"PS.2": substrate.signing_ok,
	"PS.3": substrate.sbom_ok,
	"PW.4": substrate.dependencies_ok,
	"PW.7": substrate.source_control_ok,
	"RV": substrate.vulns_ok,
}

met contains p if {
	some p, v in practice_status
	v == true
}

unmet contains p if {
	some p, v in practice_status
	v == false
}

reuses_substrate := ["signing", "sbom", "dependencies", "source_control", "vulns"]

report := {
	"framework": "NIST SSDF (SP 800-218)",
	"practices_met": count(met),
	"practices_total": count(practice_status),
	"reuses_substrate": reuses_substrate,
}
