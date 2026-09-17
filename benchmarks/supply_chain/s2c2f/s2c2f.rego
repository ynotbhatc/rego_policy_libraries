# OpenSSF Secure Supply Chain Consumption Framework (S2C2F) mapped onto the
# substrate. S2C2F is consumption-focused (ingesting third-party components), so
# it exercises the inventory, dependency, vulnerability, and integrity themes.
package supply_chain.s2c2f

import rego.v1

reuses_substrate := ["sbom", "dependencies", "vulns", "signing"]

report := {
	"framework": "OpenSSF S2C2F (consumption)",
	"reuses_substrate": reuses_substrate,
}
