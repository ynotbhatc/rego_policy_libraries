# Wrapper exposing the OpenShift 4 STIG compliance report at the package path
# expected by AAC's generic_framework_assessment.yml convention:
#
#   /v1/data/stig_openshift_4/main/compliance_report
#
# All policy logic lives in stig_openshift_4_complete.rego under
# `package stig.openshift_4`. This file is a thin alias so framework-key-based
# routing (`framework: stig_openshift_4` → URL `/v1/data/stig_openshift_4/main`)
# resolves cleanly without renaming the canonical package.

package stig_openshift_4.main

import rego.v1
import data.stig.openshift_4

# Upstream report uses "open_findings"; the generic playbook contract expects
# "violations". Merge a violations alias into the report so callers can use
# either name.
compliance_report := object.union(openshift_4.compliance_report, {
    "violations":      openshift_4.compliance_report.open_findings,
    "violation_count": count(openshift_4.compliance_report.open_findings),
})

compliant := openshift_4.compliance_report.compliant

violations := openshift_4.compliance_report.open_findings
