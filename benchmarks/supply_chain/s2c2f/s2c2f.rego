# OpenSSF Secure Supply Chain Consumption Framework (S2C2F) mapped onto the
# substrate. S2C2F is consumption-focused (ingesting third-party components), so
# it exercises the inventory, dependency, vulnerability, and integrity themes.

# METADATA
# title: "OpenSSF Secure Supply Chain Consumption Framework (S2C2F) mapped onto the"
# custom:
#   class: security
#   framework: supply_chain_s2c2f
#   source: openssf
#   domains: [supply-chain, secure-development]
#   coverage:
#     checks: 0
#     cited: 0
#     density: unrecognised
#     basis: role
#     tested: false
#     entrypoint: report
#     as_of: v2.3.2
package supply_chain.s2c2f

import rego.v1

reuses_substrate := ["sbom", "dependencies", "vulns", "signing"]

report := {
	"framework": "OpenSSF S2C2F (consumption)",
	"reuses_substrate": reuses_substrate,
}
