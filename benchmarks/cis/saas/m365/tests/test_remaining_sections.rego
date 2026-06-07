# Rego tests for cis_m365 sections 2/3/5/6/7. Each section has the
# same shape — controls_by_id is the primary surface — so the tests
# compress: build a baseline input where every relevant control is
# "Implemented" (clean), then flip one at a time to confirm each
# control's violation rule fires.

package cis_m365.remaining_sections_test

import rego.v1

import data.cis_m365.defender
import data.cis_m365.purview
import data.cis_m365.fabric
import data.cis_m365.sharepoint
import data.cis_m365.teams


# ── Defender ─────────────────────────────────────────────────────────

defender_clean_input := {
    "controls_by_id": {
        "ATPSafeAttachments": "Implemented",
        "ATPSafeLinks": "Implemented",
        "AntiPhishPolicy": "Implemented",
        "MailboxIntelligence": "Implemented",
        "ZeroHourAutoPurge": "Implemented",
        "CommonAttachmentTypesFiltered": "Implemented",
        "AntiMalwarePolicy": "Implemented",
    },
}

test_defender_clean_is_compliant if {
    defender.compliant with input as defender_clean_input
}

test_defender_safe_attachments_violation if {
    inp := json.patch(defender_clean_input, [
        {"op": "replace", "path": "/controls_by_id/ATPSafeAttachments", "value": "NotImplemented"},
    ])
    some msg in defender.violation_2_1_1 with input as inp
    contains(msg, "Safe Attachments")
}

test_defender_zap_violation if {
    inp := json.patch(defender_clean_input, [
        {"op": "replace", "path": "/controls_by_id/ZeroHourAutoPurge", "value": "NotImplemented"},
    ])
    some msg in defender.violation_2_1_5 with input as inp
    contains(msg, "zero-hour auto-purge")
}


# ── Purview ──────────────────────────────────────────────────────────

purview_clean_input := {
    "controls_by_id": {
        "UnifiedAuditLogEnabled": "Implemented",
        "AuditLogRetention": "Implemented",
        "AlertsForMaliciousEmails": "Implemented",
        "DLPPolicy": "Implemented",
        "CustomerKeyEncryption": "Implemented",
        "InsiderRiskPolicy": "Implemented",
    },
    "audit_log_accessible": true,
    "ediscovery_cases_count": 1,
}

test_purview_clean_is_compliant if {
    purview.compliant with input as purview_clean_input
}

test_purview_audit_log_inaccessible_violation if {
    inp := json.patch(purview_clean_input, [
        {"op": "replace", "path": "/audit_log_accessible", "value": false},
    ])
    some msg in purview.violation_3_1_1 with input as inp
    contains(msg, "not reachable")
}

test_purview_dlp_violation if {
    inp := json.patch(purview_clean_input, [
        {"op": "replace", "path": "/controls_by_id/DLPPolicy", "value": "NotImplemented"},
    ])
    some msg in purview.violation_3_3_1 with input as inp
    contains(msg, "Data Loss Prevention")
}

test_purview_inactive_soft_finding if {
    inp := json.patch(purview_clean_input, [
        {"op": "replace", "path": "/ediscovery_cases_count", "value": 0},
    ])
    some s in purview.soft_findings with input as inp
    contains(s, "inactive evidence")
}


# ── Fabric ───────────────────────────────────────────────────────────

fabric_clean_input := {
    "controls_by_id": {
        "FabricGuestUserAccess": "Implemented",
        "FabricExternalSharing": "Implemented",
        "FabricServicePrincipalSignIn": "Implemented",
        "FabricPublicInternetAccess": "Implemented",
        "FabricExportDataLimits": "Implemented",
    },
    "controls_evaluable": 5,
}

test_fabric_clean_is_compliant if {
    fabric.compliant with input as fabric_clean_input
}

test_fabric_external_sharing_violation if {
    inp := json.patch(fabric_clean_input, [
        {"op": "replace", "path": "/controls_by_id/FabricExternalSharing", "value": "NotImplemented"},
    ])
    some msg in fabric.violation_5_1_2 with input as inp
    contains(msg, "external sharing")
}

test_fabric_coverage_violation_when_few_evaluable if {
    inp := json.patch(fabric_clean_input, [
        {"op": "replace", "path": "/controls_evaluable", "value": 1},
    ])
    some msg in fabric.violation_coverage with input as inp
    contains(msg, "Fabric Admin REST API")
}


# ── SharePoint ───────────────────────────────────────────────────────

sharepoint_clean_input := {
    "controls_by_id": {
        "SharePointLegacyAuthDisabled": "Implemented",
        "SharePointExternalSharing": "Implemented",
        "SharePointGuestSharing": "Implemented",
        "SharePointLinkReauth": "Implemented",
        "SharePointDefaultLinkType": "Implemented",
    },
    "settings_reachable": true,
    "legacy_auth_protocols_enabled": false,
    "sharing_capability": "ExistingExternalUserSharingOnly",
    "default_sharing_link_type": "Internal",
}

test_sharepoint_clean_is_compliant if {
    sharepoint.compliant with input as sharepoint_clean_input
}

test_sharepoint_external_sharing_most_permissive_violation if {
    inp := json.patch(sharepoint_clean_input, [
        {"op": "replace", "path": "/sharing_capability", "value": "ExternalUserAndGuestSharing"},
    ])
    some msg in sharepoint.violation_6_1_2 with input as inp
    contains(msg, "ExternalUserAndGuestSharing")
}

test_sharepoint_anonymous_default_link_violation if {
    inp := json.patch(sharepoint_clean_input, [
        {"op": "replace", "path": "/default_sharing_link_type", "value": "AnonymousAccess"},
    ])
    some msg in sharepoint.violation_6_4_1 with input as inp
    contains(msg, "AnonymousAccess")
}


# ── Teams ────────────────────────────────────────────────────────────

teams_clean_input := {
    "controls_by_id": {
        "TeamsExternalAccess": "Implemented",
        "TeamsGuestAccess": "Implemented",
        "TeamsAnonymousJoin": "Implemented",
        "TeamsAutoAdmit": "Implemented",
        "TeamsCloudRecording": "Implemented",
        "TeamsThirdPartyApps": "Implemented",
    },
}

test_teams_clean_is_compliant if {
    teams.compliant with input as teams_clean_input
}

test_teams_third_party_apps_violation if {
    inp := json.patch(teams_clean_input, [
        {"op": "replace", "path": "/controls_by_id/TeamsThirdPartyApps", "value": "NotImplemented"},
    ])
    some msg in teams.violation_7_4_1 with input as inp
    contains(msg, "third-party")
}

test_teams_anonymous_join_violation if {
    inp := json.patch(teams_clean_input, [
        {"op": "replace", "path": "/controls_by_id/TeamsAnonymousJoin", "value": "NotImplemented"},
    ])
    some msg in teams.violation_7_2_1 with input as inp
    contains(msg, "anonymous")
}
