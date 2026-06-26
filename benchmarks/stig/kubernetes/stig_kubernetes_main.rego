# Wrapper exposing the Kubernetes STIG compliance report at the package path
# expected by AAC's generic_framework_assessment.yml convention:
#
#   /v1/data/stig_kubernetes/main/compliance_report
#
# All policy logic lives in stig_kubernetes_complete.rego under
# `package stig.kubernetes`. This file is a thin alias so framework-key-based
# routing (`framework: stig_kubernetes` → URL `/v1/data/stig_kubernetes/main`)
# resolves cleanly without renaming the canonical package.

package stig_kubernetes.main

import rego.v1
import data.stig.kubernetes

# Upstream report uses "open_findings"; the generic playbook contract expects
# "violations". Merge a violations alias into the report so callers can use
# either name. Use object.union so existing keys (open_findings, etc.) survive.
compliance_report := object.union(kubernetes.compliance_report, {
    "violations":      kubernetes.compliance_report.open_findings,
    "violation_count": count(kubernetes.compliance_report.open_findings),
})

compliant := kubernetes.compliance_report.compliant

violations := kubernetes.compliance_report.open_findings
