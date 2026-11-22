# METADATA
# title: "Iso27701 Pii Processor"
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
package iso27701.pii_processor

import rego.v1

# View over data.iso27701.main: the per-control results of Annex B / clause 8: PII processors.
# Every control is evaluated once, in iso27701_main.rego; this package keeps its earlier name and its
# violations / compliant / compliance_report rules for callers that read one area.

violations := data.iso27701.main.module_reports.pii_processor.violations

default compliant := false

compliant if data.iso27701.main.module_reports.pii_processor.compliant == true

compliance_report := data.iso27701.main.module_reports.pii_processor
