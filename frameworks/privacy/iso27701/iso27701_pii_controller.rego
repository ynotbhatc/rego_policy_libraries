# METADATA
# title: "Iso27701 Pii Controller"
# custom:
#   class: compliance
#   framework: iso27701
#   source: iso
#   domains: [privacy, isms]
#   coverage:
#     checks: 0
#     cited: 0
#     density: unrecognised
#     basis: role
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.5.0
package iso27701.pii_controller

import rego.v1

# View over data.iso27701.main: the per-control results of Annex A / clause 7: PII controllers.
# Every control is evaluated once, in iso27701_main.rego; this package keeps its earlier name and its
# violations / compliant / compliance_report rules for callers that read one area.

violations := data.iso27701.main.module_reports.pii_controller.violations

default compliant := false

compliant if data.iso27701.main.module_reports.pii_controller.compliant == true

compliance_report := data.iso27701.main.module_reports.pii_controller
