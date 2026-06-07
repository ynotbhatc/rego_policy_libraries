# CIS Microsoft 365 Foundations Benchmark — Section 5 (Microsoft Fabric)
#
# Evaluates the facts emitted by aac.m365.m365_fabric_facts.
#
# A note about coverage: most Fabric / Power BI tenant settings
# live in the Fabric Admin REST API, not in Graph v1.0. The
# `graph_only_coverage` flag signals to operators that this
# evaluation isn't exhaustive — what's here is real, but a full
# Section 5 audit also needs the PowerShell / Fabric Admin REST
# path. We surface that explicitly rather than silently passing.

package cis_m365.fabric

import rego.v1

default compliant := false


control_implemented(control_id) if {
    input.controls_by_id[control_id] == "Implemented"
}


violation_5_1_1 contains msg if {
    not control_implemented("FabricGuestUserAccess")
    msg := "CIS 5.1.1: Fabric guest-user access not restricted"
}

violation_5_1_2 contains msg if {
    not control_implemented("FabricExternalSharing")
    msg := "CIS 5.1.2: Fabric external sharing not restricted; reports can leak data outside the tenant"
}

violation_5_1_3 contains msg if {
    not control_implemented("FabricServicePrincipalSignIn")
    msg := "CIS 5.1.3: Fabric service principal sign-in not governed"
}

violation_5_2_1 contains msg if {
    not control_implemented("FabricPublicInternetAccess")
    msg := "CIS 5.2.1: Fabric services accessible from public internet"
}

violation_5_3_1 contains msg if {
    not control_implemented("FabricExportDataLimits")
    msg := "CIS 5.3.1: Fabric export-data limits not configured; users can pull large extracts"
}

# Coverage gap evidence
violation_coverage contains msg if {
    input.controls_evaluable < 3
    msg := sprintf("CIS Section 5: Graph surface evaluated %d Fabric controls; the rest require the Fabric Admin REST API — supplement this evaluation with the operator-side Fabric audit", [input.controls_evaluable])
}


violations contains v if { some v in violation_5_1_1 }
violations contains v if { some v in violation_5_1_2 }
violations contains v if { some v in violation_5_1_3 }
violations contains v if { some v in violation_5_2_1 }
violations contains v if { some v in violation_5_3_1 }
violations contains v if { some v in violation_coverage }

compliant if { count(violations) == 0 }

compliance_report := {
    "section": "5",
    "name": "Microsoft Fabric",
    "controls_evaluated": 5,
    "violations": violations,
    "violation_count": count(violations),
    "compliant": compliant,
    "coverage_note": "Graph v1.0 doesn't expose the full Fabric admin surface; supplement with Fabric Admin REST API",
}
