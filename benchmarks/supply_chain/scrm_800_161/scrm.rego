# NIST SP 800-161r1 (Cybersecurity Supply Chain Risk Management) mapped onto the
# substrate. 800-161 is itself a 800-53 SR overlay, so it exercises the
# SR-anchored substrate themes directly.
package supply_chain.scrm_800_161

import rego.v1

reuses_substrate := ["sbom", "provenance", "dependencies", "vulns"]

report := {
	"framework": "NIST SP 800-161r1 (C-SCRM)",
	"reuses_substrate": reuses_substrate,
}
