# CIS Microsoft 365 Foundations Benchmark — Section 7 (Microsoft Teams)
#
# Evaluates the facts emitted by aac.m365.m365_teams_facts.

package cis_m365.teams

import rego.v1

default compliant := false


control_implemented(control_id) if {
    input.controls_by_id[control_id] == "Implemented"
}


violation_7_1_1 contains msg if {
    not control_implemented("TeamsExternalAccess")
    msg := "CIS 7.1.1: Teams external access not restricted; users can federate with arbitrary tenants"
}

violation_7_1_2 contains msg if {
    not control_implemented("TeamsGuestAccess")
    msg := "CIS 7.1.2: Teams guest access not properly scoped"
}

violation_7_2_1 contains msg if {
    not control_implemented("TeamsAnonymousJoin")
    msg := "CIS 7.2.1: anonymous users can join Teams meetings"
}

violation_7_2_2 contains msg if {
    not control_implemented("TeamsAutoAdmit")
    msg := "CIS 7.2.2: meeting auto-admit policy is too permissive; external attendees skip the lobby"
}

violation_7_3_1 contains msg if {
    not control_implemented("TeamsCloudRecording")
    msg := "CIS 7.3.1: cloud recording governance not configured"
}

violation_7_4_1 contains msg if {
    not control_implemented("TeamsThirdPartyApps")
    msg := "CIS 7.4.1: third-party Teams apps not restricted; users can install unvetted integrations"
}


violations contains v if { some v in violation_7_1_1 }
violations contains v if { some v in violation_7_1_2 }
violations contains v if { some v in violation_7_2_1 }
violations contains v if { some v in violation_7_2_2 }
violations contains v if { some v in violation_7_3_1 }
violations contains v if { some v in violation_7_4_1 }

compliant if { count(violations) == 0 }

compliance_report := {
    "section": "7",
    "name": "Microsoft Teams",
    "controls_evaluated": 6,
    "violations": violations,
    "violation_count": count(violations),
    "compliant": compliant,
}
