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

compliance_report := kubernetes.compliance_report

compliant := kubernetes.compliance_report.compliant

violations := kubernetes.compliance_report.open_findings
