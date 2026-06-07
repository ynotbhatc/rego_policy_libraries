# CIS Microsoft 365 Foundations Benchmark — Section 6 (SharePoint Online)
#
# Evaluates the facts emitted by aac.m365.m365_sharepoint_facts.
# Uses Secure Score as the primary surface, with /admin/sharepoint/
# settings as a richer secondary source where reachable (beta API).

package cis_m365.sharepoint

import rego.v1

default compliant := false


control_implemented(control_id) if {
    input.controls_by_id[control_id] == "Implemented"
}


# 6.1.1 — legacy auth disabled
violation_6_1_1 contains msg if {
    not control_implemented("SharePointLegacyAuthDisabled")
    msg := "CIS 6.1.1: legacy authentication protocols enabled for SharePoint; modern-auth-only policy not enforced"
}

# Secondary check from /admin/sharepoint/settings (richer signal)
violation_6_1_1 contains msg if {
    input.settings_reachable
    input.legacy_auth_protocols_enabled == true
    msg := "CIS 6.1.1: legacyAuthProtocolsEnabled=true at the tenant level"
}

# 6.1.2 — external sharing scope
violation_6_1_2 contains msg if {
    not control_implemented("SharePointExternalSharing")
    msg := "CIS 6.1.2: external sharing not restricted; default is most-permissive"
}

# Stricter check: sharingCapability should be "ExternalUserAndGuestSharing"
# or stricter (NOT "ExistingExternalUserSharingOnly" alone, NOT
# "Disabled" unless that's the goal).
violation_6_1_2 contains msg if {
    input.settings_reachable
    input.sharing_capability == "ExternalUserAndGuestSharing"
    msg := "CIS 6.1.2: sharingCapability=ExternalUserAndGuestSharing is the most-permissive setting; restrict to ExistingExternalUserSharingOnly or Disabled"
}

# 6.2.1 — guest reshare
violation_6_2_1 contains msg if {
    not control_implemented("SharePointGuestSharing")
    msg := "CIS 6.2.1: guest users not restricted from resharing"
}

# 6.3.1 — re-auth for shared links
violation_6_3_1 contains msg if {
    not control_implemented("SharePointLinkReauth")
    msg := "CIS 6.3.1: re-authentication for shared links not enforced"
}

# 6.4.1 — default link type not anyone
violation_6_4_1 contains msg if {
    not control_implemented("SharePointDefaultLinkType")
    msg := "CIS 6.4.1: default shared link type isn't 'specific people' or 'organization-only'"
}

# Stricter check from settings
violation_6_4_1 contains msg if {
    input.settings_reachable
    input.default_sharing_link_type == "AnonymousAccess"
    msg := "CIS 6.4.1: defaultSharingLinkType=AnonymousAccess; new links create world-readable URLs by default"
}


violations contains v if { some v in violation_6_1_1 }
violations contains v if { some v in violation_6_1_2 }
violations contains v if { some v in violation_6_2_1 }
violations contains v if { some v in violation_6_3_1 }
violations contains v if { some v in violation_6_4_1 }

compliant if { count(violations) == 0 }

compliance_report := {
    "section": "6",
    "name": "Microsoft SharePoint",
    "controls_evaluated": 5,
    "violations": violations,
    "violation_count": count(violations),
    "compliant": compliant,
}
