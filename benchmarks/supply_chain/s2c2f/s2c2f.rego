# OpenSSF Secure Supply Chain Consumption Framework (S2C2F) v1.1 mapped onto the
# substrate. S2C2F is consumption-focused (ingesting third-party components), so
# it exercises the inventory, dependency, vulnerability, and integrity themes.
#
# S2C2F v1.1 (ossf/s2c2f release v1.1, 2022-10-19): 8 practices, 25 requirements,
# maturity level in brackets. Each requirement sits under one substrate theme:
#   dependencies  ING-1 [L1] ING-2 [L1] ING-3 [L3] ING-4 [L3] SCA-2 [L1] SCA-3 [L2]
#                 SCA-5 [L3] AUD-2 [L2] ENF-1 [L2] ENF-2 [L3]
#   vulns         SCA-1 [L1] SCA-4 [L3] INV-2 [L2] UPD-1 [L1] UPD-2 [L2] UPD-3 [L2]
#                 FIX-1 [L4]
#   sbom          INV-1 [L1] AUD-4 [L4] REB-3 [L4]
#   signing       AUD-3 [L2] REB-2 [L4] REB-4 [L4]
#   (no theme)    AUD-1 [L3] provenance of consumed OSS, REB-1 [L4] trusted
#                 rebuild — the substrate's provenance and build_hardening themes
#                 describe the organisation's own builds, not consumed packages.
# The overlay names themes only; no requirement is a separate check here.

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
#     density: overlay
#     basis: role
#     tested: true
#     entrypoint: report
#     guard: n/a
#     as_of: v2.4.2
package supply_chain.s2c2f

import rego.v1

reuses_substrate := ["sbom", "dependencies", "vulns", "signing"]

report := {
	"framework": "OpenSSF S2C2F v1.1 (consumption)",
	"reuses_substrate": reuses_substrate,
}
