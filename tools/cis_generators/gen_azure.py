"""CIS Microsoft Azure Foundations Benchmark v7.0.0 -> benchmarks/cis/azure/ (engine, entrypoint, Level 2 view, tests).

    python3 tools/cis_generators/gen_azure.py <workbook.xlsx | dump.json> benchmarks/cis/azure

The first argument is the CIS workbook (dumped through dump_workbook.py, needs openpyxl) or a JSON file that
dump_workbook.py already wrote. Ids, Level 1/Level 2 profile and Automated/Manual status come from the workbook;
the logic table below is hand-authored from each recommendation's audit procedure (Azure CLI / Resource Graph /
Microsoft Graph output). Every logic entry carries a keyword that must occur in the workbook title of its id, so
logic cannot attach to a renumbered recommendation. The run aborts on any count, id, status or keyword mismatch.
Wording is original (neutralize.py for titles; finding texts are written here). Helper rules live in
azure_lib.rego.tmpl. The generator writes only the files listed in OWNED and runs `opa fmt -w` on them.
"""
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from cis_genlib import ATT, load_workbook_json, rego_str, u  # noqa: E402
from neutralize import neutralize_title  # noqa: E402

BENCH = "CIS Microsoft Azure Foundations Benchmark"
VERSION = "v7.0.0"
EXPECTED = (128, 100, 28)  # recommendations, Automated, Manual
OWNED = ["cis_azure_foundations.rego", "cis_azure_main.rego", "l2_validation.rego",
         "tests/test_cis_azure_v7_controls.rego", "tests/test_cis_azure_v7_logic.rego",
         "tests/test_cis_azure_v7_reports.rego", "tests/test_cis_azure_v7_l2.rego"]


def load(path):
    if path.lower().endswith(".xlsx"):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "azure.json")
            subprocess.run([sys.executable, os.path.join(HERE, "dump_workbook.py"), path, out], check=True,
                           stderr=subprocess.DEVNULL)
            return load_workbook_json(out)
    return load_workbook_json(path)


def sort_key(cid):
    return [int(x) for x in cid.split(".")]


# ── the compliant fixture the generated tests patch ──────────────────────────────────
SUBID = "00000000-0000-0000-0000-000000000001"
SUB = f"/subscriptions/{SUBID}"
TEN = "11111111-1111-1111-1111-111111111111"
RG = f"{SUB}/resourceGroups/rg-core"
LAW = f"{RG}/providers/Microsoft.OperationalInsights/workspaces/law-core"
AG = f"{RG}/providers/microsoft.insights/actionGroups/ag-secops"
NET = f"{RG}/providers/Microsoft.Network"
WAF = f"{NET}/ApplicationGatewayWebApplicationFirewallPolicies/waf-appgw"
FDWAF = f"{NET}/frontdoorwebapplicationfirewallpolicies/waffd"
FD = f"{RG}/providers/Microsoft.Cdn/profiles/fd-prod"

ADMIN_OPS = [
    ("6.1.2.1", "create policy assignment", "Microsoft.Authorization/policyAssignments/write", False),
    ("6.1.2.2", "delete policy assignment", "Microsoft.Authorization/policyAssignments/delete", False),
    ("6.1.2.3", "create or update network security group", "Microsoft.Network/networkSecurityGroups/write", True),
    ("6.1.2.4", "delete network security group", "Microsoft.Network/networkSecurityGroups/delete", True),
    ("6.1.2.5", "create or update security solution", "Microsoft.Security/securitySolutions/write", True),
    ("6.1.2.6", "delete security solution", "Microsoft.Security/securitySolutions/delete", True),
    ("6.1.2.7", "create or update sql server firewall rule", "Microsoft.Sql/servers/firewallRules/write", True),
    ("6.1.2.8", "delete sql server firewall rule", "Microsoft.Sql/servers/firewallRules/delete", True),
    ("6.1.2.9", "create or update public ip address", "Microsoft.Network/publicIPAddresses/write", True),
    ("6.1.2.10", "delete public ip address", "Microsoft.Network/publicIPAddresses/delete", True),
    ("6.1.2.12", "create role assignment", "Microsoft.Authorization/roleAssignments/write", False),
    ("6.1.2.13", "delete role assignment", "Microsoft.Authorization/roleAssignments/delete", False),
    ("6.1.2.14", "policy exemption", "Microsoft.Authorization/policyExemptions/write", False),
    ("6.1.2.15", "delete diagnostic setting", "Microsoft.Insights/diagnosticSettings/delete", False),
    ("6.1.2.16", "delete resource lock", "Microsoft.Authorization/locks/delete", False),
    ("6.1.2.17", "key vault access policy", "Microsoft.KeyVault/vaults/accessPolicies/write", True),
]


def _alert(name, conds):
    return {"name": name, "enabled": True, "scopes": [SUB], "condition": {"allOf": conds},
            "actions": {"actionGroups": [{"actionGroupId": AG}]}}


ALERTS = [_alert(f"alert-{i}", [{"field": "category", "equals": "Administrative"}, {"field": "operationName", "equals": op}])
          for i, (_, _, op, _) in enumerate(ADMIN_OPS)]
ALERTS.append(_alert("alert-service-health", [{"field": "category", "equals": "ServiceHealth"}]))
SH = len(ALERTS) - 1

PLANS = ["CloudPosture", "Api", "VirtualMachines", "Containers", "StorageAccounts", "AppServices", "CosmosDbs",
         "OpenSourceRelationalDatabases", "SqlServers", "SqlServerVirtualMachines", "KeyVaults", "Arm", "AI"]
EXT = {
    "CloudPosture": ["AgentlessVmScanning"],
    "VirtualMachines": ["AgentlessVmScanning", "FileIntegrityMonitoring"],
    "Containers": ["ContainerRegistriesVulnerabilityAssessments", "AgentlessDiscoveryForKubernetes", "AgentlessVmScanning",
                   "ContainerSensor"],
    "AI": ["AIPromptEvidence"],
}
PRICINGS = [dict({"name": n, "pricingTier": "Standard", "extensions": [{"name": e, "isEnabled": "True"} for e in EXT.get(n, [])]},
                 **({"subPlan": "P2"} if n == "VirtualMachines" else {})) for n in PLANS]
PI = {n: i for i, n in enumerate(PLANS)}

DIAG = [{"name": "audit-to-law", "workspaceId": LAW, "logs": [{"categoryGroup": "audit", "enabled": True}]}]


def _rule(name, prio, direction, access, proto, src, dport, **kw):
    r = {"name": name, "priority": prio, "direction": direction, "access": access, "protocol": proto,
         "sourceAddressPrefix": src, "sourcePortRange": "*", "destinationAddressPrefix": "*", "destinationPortRange": dport}
    r.update(kw)
    return r


GREEN = {
    "subscription_id": SUBID,
    "tenant_id": TEN,
    "security_defaults": {"isEnabled": True},
    "users": [{"userPrincipalName": "alice@example.com", "perUserMfaState": "enforced"},
              {"userPrincipalName": "bob@example.com", "perUserMfaState": "enabled"}],
    "root_role_assignments": [],
    "role_definitions": [{"roleName": "VM Operator", "roleType": "CustomRole", "assignableScopes": [SUB],
                          "permissions": [{"actions": ["Microsoft.Compute/virtualMachines/start/action"]}]}],
    "role_assignments": [
        {"roleDefinitionName": "Owner", "scope": SUB, "principalId": "p-1", "principalType": "User"},
        {"roleDefinitionName": "Owner", "scope": SUB, "principalId": "p-2", "principalType": "User"},
        {"roleDefinitionName": "Role Based Access Control Administrator", "scope": f"{SUB}/resourceGroups/rg-app",
         "principalId": "p-3", "principalType": "User",
         "condition": "@Request[Microsoft.Authorization/roleAssignments:RoleDefinitionId] ForAnyOfAnyValues:GuidEquals {acdd72a7-3385-48ef-bd42-f606fba81ae7}"},
    ],
    "management_group_hierarchy_settings": {
        "defaultManagementGroup": "/providers/Microsoft.Management/managementGroups/landing-zones",
        "requireAuthorizationForGroupCreation": True, "tenantId": TEN},
    "role_assigned_service_principals": [
        {"displayName": "id-deploy", "servicePrincipalType": "ManagedIdentity", "passwordCredentials": []},
        {"displayName": "app-ci", "servicePrincipalType": "Application", "appId": "22222222-2222-2222-2222-222222222222",
         "appOwnerOrganizationId": TEN, "passwordCredentials": [], "application_password_credentials": []},
    ],
    "subscription_diagnostic_settings": [{"name": "activity-to-law", "workspaceId": LAW, "logs": [
        {"category": c, "enabled": True} for c in ["Administrative", "Alert", "Policy", "Security"]]}],
    "activity_log_alerts": ALERTS,
    "application_insights": [{"name": "appi-prod", "provisioningState": "Succeeded"}],
    "log_analytics_workspaces": [{"name": "law-core", "publicNetworkAccessForIngestion": "Disabled",
                                  "publicNetworkAccessForQuery": "Disabled"}],
    "network_security_groups": [{"name": "nsg-app", "securityRules": [
        _rule("allow-https-internal", 100, "Inbound", "Allow", "Tcp", "10.0.0.0/8", "443"),
        _rule("deny-all-in", 4000, "Inbound", "Deny", "*", "*", "*"),
        _rule("allow-https-out", 100, "Outbound", "Allow", "Tcp", "10.0.0.0/8", "443"),
        _rule("deny-all-out", 4000, "Outbound", "Deny", "*", "*", "*"),
    ]}],
    "application_gateways": [{"name": "agw-prod", "enableHttp2": True, "firewallPolicy": {"id": WAF},
                              "sslPolicy": {"policyType": "CustomV2", "minProtocolVersion": "TLSv1_3"},
                              "sslProfiles": [{"name": "inherit", "sslPolicy": None}]}],
    "application_gateway_waf_policies": [{"id": WAF, "name": "waf-appgw", "policySettings": {"requestBodyCheck": True, "state": "Enabled"},
                                          "managedRules": {"managedRuleSets": [
                                              {"ruleSetType": "OWASP", "ruleSetVersion": "3.2", "ruleGroupOverrides": []},
                                              {"ruleSetType": "Microsoft_BotManagerRuleSet", "ruleSetVersion": "1.1", "ruleGroupOverrides": []}]}}],
    "virtual_networks": [{"name": "vnet-core", "location": "eastus", "enableDdosProtection": True, "subnets": [
        {"name": "snet-app", "networkSecurityGroup": {"id": f"{NET}/networkSecurityGroups/nsg-app"}, "delegations": [],
         "defaultOutboundAccess": False},
        {"name": "GatewaySubnet", "networkSecurityGroup": None, "delegations": []},
    ]}],
    "regions_in_use": ["eastus"],
    "network_watchers": [{"name": "NetworkWatcher_eastus", "location": "eastus", "provisioningState": "Succeeded"}],
    "flow_logs": [
        {"name": "fl-vnet-core", "targetResourceId": f"{NET}/virtualNetworks/vnet-core", "enabled": True,
         "retentionPolicy": {"days": 90, "enabled": True}},
        {"name": "fl-nsg-app", "targetResourceId": f"{NET}/networkSecurityGroups/nsg-app", "enabled": True,
         "retentionPolicy": {"days": 0, "enabled": False}},
    ],
    "virtual_network_gateways": [
        {"name": "vgw-p2s", "vpnClientConfiguration": {"vpnAuthenticationTypes": ["AAD"]}},
        {"name": "vgw-s2s", "vpnClientConfiguration": None},
    ],
    "front_door_profiles": [{"name": "fd-prod", "endpoints": [{"id": f"{FD}/afdEndpoints/www"}],
                             "custom_domains": [{"id": f"{FD}/customDomains/www-example-com"}],
                             "security_policies": [{"name": "waf", "parameters": {
                                 "type": "WebApplicationFirewall", "wafPolicy": {"id": FDWAF},
                                 "associations": [{"domains": [{"id": f"{FD}/afdEndpoints/www"},
                                                               {"id": f"{FD}/customDomains/www-example-com"}],
                                                   "patternsToMatch": ["/*"]}]}}]}],
    "front_door_waf_policies": [{"id": FDWAF, "name": "waffd", "policySettings": {"enabledState": "Enabled", "mode": "Prevention"}}],
    "defender_pricings": PRICINGS,
    "defender_settings": [{"name": "WDATP", "enabled": True}],
    "virtual_machines": [
        {"name": "vm-linux", "osProfile": {"linuxConfiguration": {"patchSettings": {"assessmentMode": "AutomaticByPlatform"}}}},
        {"name": "vm-win", "osProfile": {"windowsConfiguration": {"patchSettings": {"assessmentMode": "AutomaticByPlatform"}}}},
    ],
    "security_contacts": [{"name": "default", "isEnabled": True, "emails": "secops@example.com",
                           "notificationsByRole": {"state": "On", "roles": ["Owner"]},
                           "notificationsSources": [{"sourceType": "Alert", "minimalSeverity": "High"},
                                                    {"sourceType": "AttackPath", "minimalRiskLevel": "Critical"}]}],
    "managed_hsms": [{"name": "hsm-core", "enablePurgeProtection": True, "publicNetworkAccess": "Disabled",
                      "privateEndpointConnections": [{"privateLinkServiceConnectionState": {"status": "Approved"}}],
                      "diagnostic_settings": DIAG}],
    "key_vaults": [
        {"name": "kv-rbac", "sku": {"name": "premium"}, "enableRbacAuthorization": True, "enablePurgeProtection": True,
         "publicNetworkAccess": "Disabled", "networkAcls": {"defaultAction": "Deny"},
         "privateEndpointConnections": [{"privateLinkServiceConnectionState": {"status": "Approved"}}],
         "diagnostic_settings": DIAG,
         "keys": [{"name": "cmk", "kid": "https://kv-rbac.vault.azure.net/keys/cmk", "kty": "RSA-HSM",
                   "attributes": {"enabled": True, "expires": "2027-06-30T00:00:00+00:00"},
                   "rotation_policy": {"expiresIn": "P2Y", "lifetimeActions": [
                       {"action": "Rotate", "timeAfterCreate": "P18M", "timeBeforeExpiry": None},
                       {"action": "Notify", "timeAfterCreate": None, "timeBeforeExpiry": "P30D"}]}}],
         "secrets": [{"name": "api-token", "attributes": {"enabled": True, "expires": "2027-01-31T00:00:00+00:00"}}],
         "certificates": [{"name": "tls-www", "policy": {"x509CertificateProperties": {"validityInMonths": 12}}}]},
    ],
    "bastion_hosts": [{"name": "bas-core", "sku": {"name": "Standard"}, "enableShareableLink": False}],
    "public_ip_addresses": [
        {"name": "pip-agw", "ddosSettings": {"protectionMode": "Enabled"}},
        {"name": "pip-fw", "ddosSettings": {"protectionMode": "VirtualNetworkInherited"},
         "ddos_protection_status": {"isWorkloadProtected": "True"}},
        {"name": "pip-nat", "natGateway": {"id": f"{NET}/natGateways/nat-core"}},
    ],
    "storage_accounts": [
        {"name": "stcore", "kind": "StorageV2", "publicNetworkAccess": "Disabled", "networkRuleSet": {"defaultAction": "Deny"},
         "defaultToOAuthAuthentication": True, "enableHttpsTrafficOnly": True, "minimumTlsVersion": "TLS1_2",
         "allowBlobPublicAccess": False,
         "blob_service_properties": {"deleteRetentionPolicy": {"enabled": True, "days": 7}}},
        {"name": "stfiles", "kind": "FileStorage", "publicNetworkAccess": "Disabled", "networkRuleSet": {"defaultAction": "Deny"},
         "defaultToOAuthAuthentication": True, "enableHttpsTrafficOnly": True, "minimumTlsVersion": "TLS1_2",
         "allowBlobPublicAccess": False},
    ],
    "attest": {},
}

# A vault on the legacy access-policy model whose key and secret have no expiry (8.3.3 / 8.3.5 fail cases).
LEGACY_KV = {"name": "kv-legacy", "sku": {"name": "standard"}, "enableRbacAuthorization": False,
             "keys": [{"name": "k-noexp", "kty": "RSA", "attributes": {"enabled": True}}],
             "secrets": [{"name": "s-noexp", "attributes": {"enabled": True}}], "certificates": []}

# ── logic table ──────────────────────────────────────────────────────────────────────
# F(id, keyword, evidence keys, findings, fail patch[, miss patch]): decided from collected facts.
#   findings: (message, [sprintf args], [rego body lines]); each becomes one violation rule that also requires the
#   recommendation to be in scope and its evidence present. Messages name the resource.
# A(id, keyword, attestation key): Manual recommendation, input.attest.<key> == true.
C = []
OBJECT_KEYS = {"security_defaults", "management_group_hierarchy_settings"}


def add(p, v):
    return {"op": "add", "path": p, "value": v}


def rm(p):
    return {"op": "remove", "path": p}


def F(cid, kw, ev, rules, fail, miss=None):
    C.append({"id": cid, "kw": kw, "kind": "fact", "ev": ev, "rules": rules, "fail": fail if isinstance(fail, list) else [fail],
              "miss": miss or [rm("/" + ev[0])]})


def A(cid, kw, key):
    C.append({"id": cid, "kw": kw, "kind": "attest", "attest": key})


def each(lst, var="x"):
    return f"some {var} in input.{lst}"


# Section 5: identity and access
F("5.1.1", "security defaults", ["security_defaults"],
  [("security defaults are not enabled in the tenant", [], ['not p_true(input.security_defaults, "isEnabled")'])],
  add("/security_defaults/isEnabled", False))
A("5.1.2", "register or join devices", "mfa_required_to_join_devices")
F("5.1.3", "per-user mfa", ["users"],
  [("user %s has per-user MFA state %v, not enabled or enforced", ["nm_user(x)", 'object.get(x, "perUserMfaState", "not collected")'],
    [each("users"), "not mfa_on(x)"])],
  add("/users/1/perUserMfaState", "disabled"))
A("5.1.4", "remember multifactor", "mfa_remember_trusted_devices_disabled")
A("5.3.1", "daily operations", "admin_accounts_not_used_daily")
A("5.3.2", "guest users", "guest_users_reviewed")
F("5.3.3", "user access administrator", ["root_role_assignments"],
  [("%v holds User Access Administrator at the root scope", ['object.get(x, "principalName", object.get(x, "principalId", "a principal"))'],
    [each("root_role_assignments"), 'role_is(x, "User Access Administrator")', 'object.get(x, "scope", "/") == "/"']),
   ("a root-scope role assignment was collected without its role name", [],
    [each("root_role_assignments"), 'not has_str(x, "roleDefinitionName")'])],
  add("/root_role_assignments/-", {"roleDefinitionName": "User Access Administrator", "scope": "/", "principalName": "admin@example.com"}))
A("5.3.4", "privileged", "privileged_role_assignments_reviewed")
A("5.3.5", "disabled user accounts", "disabled_users_hold_no_roles")
A("5.3.6", "tenant creator", "tenant_creator_assignments_reviewed")
A("5.3.7", "non-privileged", "non_privileged_role_assignments_reviewed")
F("5.4", "custom subscription administrator", ["role_definitions"],
  [("custom role %s grants every action (*) and is assignable at %s", ["role_name(x)", "s"],
    [each("role_definitions"), "custom_role(x)", '"*" in role_actions(x)', 'some s in p(x, "assignableScopes")',
     "wide_assignable_scope(s)"]),
   ("custom role %s: permissions or assignable scopes not collected", ["role_name(x)"],
    [each("role_definitions"), "custom_role(x)", "not role_collected(x)"])],
  add("/role_definitions/0/permissions/0/actions/-", "*"))
A("5.5", "resource locks", "resource_lock_admin_role_assigned")
A("5.6", "permit no one", "subscription_tenant_transfer_blocked")
F("5.7", "subscription owners", ["role_assignments"],
  [("%s has %d Owner assignments at subscription scope; 2 or 3 are expected", ["scope", "count(owners)"],
    ["some scope, owners in subscription_owners", "not count(owners) in {2, 3}"]),
   ("no role assignment at subscription scope was collected, so Owners cannot be counted", [],
    ["count(subscription_owners) == 0"])],
  rm("/role_assignments/1"))
F("5.8", "default management group", ["management_group_hierarchy_settings"],
  [("the default management group for new subscriptions is the root management group, is unset, or the tenant id was not collected", [],
    ["not default_management_group_not_root"])],
  add("/management_group_hierarchy_settings/defaultManagementGroup", f"/providers/Microsoft.Management/managementGroups/{TEN}"))
F("5.9", "creating management groups", ["management_group_hierarchy_settings"],
  [("creating a management group does not require write permission on the root management group", [],
    ['not p_true(input.management_group_hierarchy_settings, "requireAuthorizationForGroupCreation")'])],
  rm("/management_group_hierarchy_settings/requireAuthorizationForGroupCreation"))
A("5.10", "emergency access", "emergency_access_accounts_can_regain_access")
F("5.11", "client secrets", ["role_assigned_service_principals"],
  [("service principal %s holds an Azure role and has %d client secret(s)", ["sp_name(x)", "count(x.passwordCredentials)"],
    [each("role_assigned_service_principals"), "count(x.passwordCredentials) > 0"]),
   ("service principal %s: passwordCredentials not collected", ["sp_name(x)"],
    [each("role_assigned_service_principals"), "not sp_secrets_collected(x)"]),
   ("application behind service principal %s has %d client secret(s)", ["sp_name(x)", "count(x.application_password_credentials)"],
    [each("role_assigned_service_principals"), "sp_needs_app_credentials(x)", "count(x.application_password_credentials) > 0"]),
   ("application behind service principal %s: application_password_credentials not collected", ["sp_name(x)"],
    [each("role_assigned_service_principals"), "sp_needs_app_credentials(x)", "not has_list(x, \"application_password_credentials\")"])],
  [add("/role_assigned_service_principals/1/application_password_credentials/-", {"keyId": "k1", "displayName": "ci"}),
   rm("/role_assigned_service_principals/0/passwordCredentials")])
F("5.12", "role based access control administrator", ["role_assignments"],
  [("%v holds User Access Administrator at %s; delegate with a conditioned Role Based Access Control Administrator assignment",
    ["assignee(x)", "x.scope"], [each("role_assignments"), 'x.scope != "/"', 'role_is(x, "User Access Administrator")']),
   ("%v holds Role Based Access Control Administrator at %s without a condition", ["assignee(x)", "x.scope"],
    [each("role_assignments"), 'x.scope != "/"', 'role_is(x, "Role Based Access Control Administrator")', "not conditioned(x)"]),
   ("a role assignment was collected without its role name or scope", [],
    [each("role_assignments"), "not assignment_collected(x)"])],
  [rm("/role_assignments/2/condition"),
   add("/role_assignments/-", {"roleDefinitionName": "User Access Administrator", "scope": SUB, "principalId": "p-9"})])

# Section 6: logging and monitoring
F("6.1.1.1", "diagnostic setting", ["subscription_diagnostic_settings"],
  [("no subscription diagnostic setting sends an enabled activity log category to a destination", [],
    ["count([s | some s in input.subscription_diagnostic_settings; exporting_setting(s)]) == 0"])],
  add("/subscription_diagnostic_settings", []))
F("6.1.1.2", "appropriate categories", ["subscription_diagnostic_settings"],
  [("activity log category %s is not exported by any subscription diagnostic setting with a destination", ["cat"],
    ['some cat in ["Administrative", "Alert", "Policy", "Security"]', "not subscription_category_logged(cat)"])],
  add("/subscription_diagnostic_settings/0/logs/3/enabled", False))
A("6.1.1.3", "customer-managed key", "activity_log_storage_cmk_encrypted")
F("6.1.1.4", "logging for azure key vault", ["key_vaults"],
  [("key vault %s has no diagnostic setting that sends audit logs to a destination", ["nm(x)"],
    [each("key_vaults"), "is_array(x.diagnostic_settings)", "not audit_logging_on(x)"]),
   ("key vault %s: diagnostic_settings not collected", ["nm(x)"],
    [each("key_vaults"), "not has_list(x, \"diagnostic_settings\")"])],
  [add("/key_vaults/0/diagnostic_settings/0/logs/0/enabled", False), rm("/key_vaults/0/diagnostic_settings")])
A("6.1.1.5", "network security group flow logs", "nsg_flow_logs_sent_to_log_analytics")
A("6.1.1.6", "virtual network flow logs", "vnet_flow_logs_sent_to_log_analytics")
A("6.1.1.7", "microsoft graph activity logs", "graph_activity_logs_exported")
A("6.1.1.8", "microsoft entra activity logs", "entra_activity_logs_exported")
A("6.1.1.9", "intune logs", "intune_logs_sent_to_log_analytics")
for _i, (_cid, _kw, _op, _narrow) in enumerate(ADMIN_OPS):
    F(_cid, _kw, ["activity_log_alerts"],
      [(f"no enabled activity log alert with an action group covers {_op} for the subscription without extra conditions", [],
        [f'not operation_alerted("{_op}", {"true" if _narrow else "false"})'])],
      [add(f"/activity_log_alerts/{_i}/enabled", False),
       add(f"/activity_log_alerts/{_i}/condition/allOf/-", {"field": "resourceGroup", "equals": "rg-core"}),
       add(f"/activity_log_alerts/{_i}/actions/actionGroups", [])])
F("6.1.2.11", "service health", ["activity_log_alerts"],
  [("no enabled activity log alert with an action group covers Service Health for the subscription without narrowing conditions", [],
    ["not service_health_alerted"])],
  [add(f"/activity_log_alerts/{SH}/scopes", [RG]),
   add(f"/activity_log_alerts/{SH}/condition/allOf/-", {"field": "properties.impactedServices[*].ServiceName", "containsAny": ["Storage"]})])
F("6.1.3.1", "application insights", ["application_insights"],
  [("no Application Insights component exists in the subscription", [], ["count(input.application_insights) == 0"])],
  add("/application_insights", []))
A("6.1.4", "resource logging", "resource_logging_enabled_for_supported_services")
A("6.1.5", "skus", "production_resources_avoid_basic_free_consumption_skus")
F("6.1.6", "ingestion and queries", ["log_analytics_workspaces"],
  [("Log Analytics workspace %s allows public network access for %s", ["nm(x)", "what"],
    [each("log_analytics_workspaces"),
     'some k, what in {"publicNetworkAccessForIngestion": "ingestion", "publicNetworkAccessForQuery": "queries"}',
     'not p_ieq(x, k, "Disabled")'])],
  add("/log_analytics_workspaces/0/publicNetworkAccessForQuery", "Enabled"))
A("6.2", "resource locks", "mission_critical_resources_locked")

# Section 7: networking
NSG = "network_security_groups"
TCP = '{"tcp", "*", "any"}'
UDP = '{"udp", "*", "any"}'
TCPUDP = '{"tcp", "udp", "*", "any"}'


def nsg_exposure(cid, kw, what, protos, ports, bad_rule):
    F(cid, kw, [NSG],
      [(f"network security group %v rule %v allows {what} from the internet", ["nm(x)", "nm(r)"],
        [each(NSG), "some r in nsg_rules(x)", f"internet_inbound_allow(r, {protos}, {ports})"]),
       ("network security group %v: securityRules not collected", ["nm(x)"], [each(NSG), "not nsg_rules_collected(x)"]),
       ("network security group %v rule %v: access, direction, protocol, source or destination port not collected",
        ["nm(x)", "nm(r)"], [each(NSG), "some r in nsg_rules(x)", "not rule_complete(r)"])],
      add(f"/{NSG}/0/securityRules/-", bad_rule))


nsg_exposure("7.1.1", "rdp access", "RDP (TCP 3389)", TCP, "[3389]",
             _rule("rdp-any", 300, "Inbound", "Allow", "Tcp", "Internet", "3000-4000"))
nsg_exposure("7.1.2", "winrm access", "WinRM (TCP 5985/5986)", TCP, "[5985, 5986]",
             _rule("winrm", 300, "Inbound", "Allow", "*", "10.0.0.0/8", "22", destinationPortRange=None,
                   destinationPortRanges=["8080", "5986"], sourceAddressPrefix=None, sourceAddressPrefixes=["10.1.0.0/16", "::/0"]))
nsg_exposure("7.1.3", "http(s) access", "HTTP or HTTPS (TCP 80/443)", TCP, "[80, 443]",
             _rule("web", 300, "Inbound", "Allow", "TCP", "0.0.0.0/0", "80"))
nsg_exposure("7.1.4", "udp port access", "a commonly abused UDP service (53, 123, 161, 389, 1900)", UDP, "[53, 123, 161, 389, 1900]",
             _rule("dns", 300, "Inbound", "Allow", "Udp", "Any", "50-60"))
nsg_exposure("7.1.5", "ssh access", "SSH (TCP 22)", TCP, "[22]",
             _rule("ssh", 300, "Inbound", "Allow", "Tcp", "*", "*"))
nsg_exposure("7.1.6", "database port access", "a database port (1433, 1434, 1521, 3306, 5432, 6379, 27017)", TCPUDP,
             "[1433, 1434, 1521, 3306, 5432, 6379, 27017]",
             _rule("db", 300, "Inbound", "Allow", "Udp", "Internet", "6379"))
AGW = "application_gateways"
F("7.2.1", "http2", [AGW],
  [("application gateway %v does not have HTTP/2 enabled", ["nm(x)"], [each(AGW), 'not p_true(x, "enableHttp2")'])],
  rm(f"/{AGW}/0/enableHttp2"))
F("7.2.2", "tlsv1_2", [AGW],
  [("application gateway %v uses an SSL policy that allows TLS below 1.2", ["nm(x)"],
    [each(AGW), "some pol in gateway_ssl_policies(x)", "weak_ssl_policy(pol)"])],
  add(f"/{AGW}/0/sslProfiles/0/sslPolicy", {"policyType": "Predefined", "policyName": "AppGwSslPolicy20170401"}))
F("7.2.3", "tlsv1_3", [AGW],
  [("application gateway %v: the gateway or an SSL profile with its own policy does not set a minimum of TLS 1.3", ["nm(x)"],
    [each(AGW), "not gateway_tls13(x)"])],
  add(f"/{AGW}/0/sslProfiles/0/sslPolicy", {"policyType": "CustomV2", "minProtocolVersion": "TLSv1_2"}))
WAFP = "application_gateway_waf_policies"
for _cid, _kw, _pred, _what, _fail in [
        ("7.2.4", "bot protection", "bot_protection_on", "bot protection (Microsoft_BotManagerRuleSet, KnownBadBots not disabled)",
         add(f"/{WAFP}/0/managedRules/managedRuleSets/1/ruleGroupOverrides/-",
             {"ruleGroupName": "KnownBadBots", "rules": [{"ruleId": "Bot100100", "state": "Disabled"}]})),
        ("7.2.5", "request body inspection", "request_body_check_on", "request body inspection",
         add(f"/{WAFP}/0/policySettings/requestBodyCheck", False))]:
    F(_cid, _kw, [AGW, WAFP],
      [(f"application gateway %v: its WAF policy does not have {_what} enabled", ["nm(x)"],
        [each(AGW), "pol := gateway_waf_policy(x)", f"not {_pred}(pol)"]),
       ("application gateway %v has no WAF policy attached", ["nm(x)"], [each(AGW), "not gateway_waf_id(x)"]),
       ("application gateway %v: WAF policy %v not collected", ["nm(x)", "gateway_waf_id(x)"],
        [each(AGW), "gateway_waf_id(x)", "not gateway_waf_policy(x)"])],
      _fail, [rm(f"/{WAFP}")])
F("7.2.6", "azure application gateway", [AGW],
  [("application gateway %v has no WAF policy attached", ["nm(x)"], [each(AGW), "not gateway_waf_id(x)"])],
  rm(f"/{AGW}/0/firewallPolicy"))
A("7.3", "public ip addresses", "public_ip_addresses_reviewed")
VN = "virtual_networks"
F("7.4", "subnets are associated", [VN],
  [("subnet %v of virtual network %v has no network security group", ["nm(s)", "nm(x)"],
    [each(VN), "some s in nsg_subnets(x)", "not subnet_has_nsg(s)"]),
   ("virtual network %v: subnets not collected", ["nm(x)"], [each(VN), "not vnet_subnets(x)"])],
  rm(f"/{VN}/0/subnets/0/networkSecurityGroup"))
F("7.5", "network watcher", ["regions_in_use", "network_watchers"],
  [("region %v is in use but has no network watcher in the Succeeded state", ["r"],
    ["some r in input.regions_in_use", "not watcher_ok(r)"])],
  add("/network_watchers/0/provisioningState", "Failed"), [rm("/regions_in_use")])
FL = "flow_logs"
F("7.6", "virtual network flow log retention", [FL],
  [("virtual network flow log %v keeps logs for fewer than 90 days (or retention not collected)", ["nm(x)"],
    [each(FL), "flow_log_target_collected(x)", "not nsg_flow_log(x)", "not retention_ok(x)"]),
   ("flow log %v: targetResourceId not collected", ["nm(x)"], [each(FL), "not flow_log_target_collected(x)"])],
  add(f"/{FL}/0/retentionPolicy/days", 30))
VGW = "virtual_network_gateways"
F("7.7", "point-to-site", [VGW],
  [("VPN gateway %v accepts point-to-site authentication other than Microsoft Entra ID only", ["nm(x)"],
    [each(VGW), "p2s_configured(x)", "not p2s_entra_only(x)"]),
   ("VPN gateway %v: vpnClientConfiguration not collected", ["nm(x)"], [each(VGW), "not p2s_collected(x)"])],
  add(f"/{VGW}/0/vpnClientConfiguration/vpnAuthenticationTypes/-", "Certificate"))
F("7.8", "virtualnetwork", [NSG],
  [("network security group %v has no %v deny-all rule evaluated after its allow rules", ["nm(x)", "d"],
    [each(NSG), "is_array(nsg_rules(x))", 'some d in ["inbound", "outbound"]', "not deny_all_after_allows(x, d)"]),
   ("network security group %v: securityRules not collected", ["nm(x)"], [each(NSG), "not nsg_rules_collected(x)"])],
  add(f"/{NSG}/0/securityRules/3/priority", 50))
A("7.9", "network security perimeter", "network_security_perimeter_enforced")
FDP = "front_door_profiles"
F("7.10", "front door", [FDP, "front_door_waf_policies"],
  [("Front Door profile %v: endpoint or domain %v is not associated with an enabled WAF policy", ["nm(x)", "d"],
    [each(FDP), "front_door_collected(x)", "some d in front_door_domain_ids(x)", "not front_door_domain_protected(x, d)"]),
   ("Front Door profile %v: endpoints, custom_domains or security_policies not collected", ["nm(x)"],
    [each(FDP), "not front_door_collected(x)"])],
  add("/front_door_waf_policies/0/policySettings/enabledState", "Disabled"))
F("7.11", "default outbound access", [VN],
  [("subnet %v of virtual network %v does not have default outbound access disabled", ["nm(s)", "nm(x)"],
    [each(VN), "some s in outbound_subnets(x)", 'not p_false(s, "defaultOutboundAccess")']),
   ("virtual network %v: subnets not collected", ["nm(x)"], [each(VN), "not vnet_subnets(x)"])],
  rm(f"/{VN}/0/subnets/0/defaultOutboundAccess"))
F("7.12", "network security group flow log retention", [FL],
  [("network security group flow log %v is not enabled with retention of 0 or at least 90 days", ["nm(x)"],
    [each(FL), "nsg_flow_log(x)", 'not p_false(x, "enabled")', "not nsg_flow_log_ok(x)"]),
   ("flow log %v: targetResourceId not collected", ["nm(x)"], [each(FL), "not flow_log_target_collected(x)"])],
  add(f"/{FL}/1/retentionPolicy/days", 7))

# Section 8: security services
DP = "defender_pricings"


def plan(cid, kw, name, extra=None, fail=None, msg=None):
    rules = [(msg or f"Defender plan {name} is not on the Standard tier", [], [f'not plan_standard("{name}")'])]
    if extra:
        rules += extra
    F(cid, kw, [DP], rules, fail or add(f"/{DP}/{PI[name]}/pricingTier", "Free"))


plan("8.1.1.1", "cspm", "CloudPosture")
plan("8.1.2.1", "apis", "Api")
plan("8.1.3.1", "defender for servers", "VirtualMachines")
A("8.1.3.2", "vulnerability assessment", "defender_vulnerability_assessment_on")
F("8.1.3.3", "endpoint protection", ["defender_settings"],
  [("the Defender for Endpoint integration (WDATP setting) is not enabled", [], ['not defender_setting_on("WDATP")'])],
  add("/defender_settings/0/enabled", False))
F("8.1.3.4", "agentless scanning", [DP],
  [("agentless machine scanning is not on under Defender for Servers Plan 2 or Defender CSPM", [], ["not agentless_scanning_on"])],
  [add(f"/{DP}/{PI['VirtualMachines']}/extensions/0/isEnabled", "False"),
   add(f"/{DP}/{PI['CloudPosture']}/extensions/0/isEnabled", "False")])
F("8.1.3.5", "file integrity monitoring", [DP],
  [("file integrity monitoring is not on under Defender for Servers Plan 2", [],
    ['not plan_standard("VirtualMachines")']),
   ("file integrity monitoring is not on under Defender for Servers Plan 2", [],
    ['not plan_subplan("VirtualMachines", "P2")']),
   ("file integrity monitoring is not on under Defender for Servers Plan 2", [],
    ['not plan_extension_on("VirtualMachines", "FileIntegrityMonitoring")'])],
  add(f"/{DP}/{PI['VirtualMachines']}/subPlan", "P1"))
plan("8.1.4.1", "containers", "Containers",
     extra=[("Defender for Containers component %v is not enabled", ["e"],
             ['some e in ["ContainerRegistriesVulnerabilityAssessments", "AgentlessDiscoveryForKubernetes", "AgentlessVmScanning", "ContainerSensor"]',
              'not plan_extension_on("Containers", e)']),
            ("the deprecated Defender for Container Registries plan is present but not on the Standard tier", [],
             ["some c in input.defender_pricings", 'lower(c.name) == "containerregistry"', 'not p_ieq(c, "pricingTier", "Standard")'])],
     fail=add(f"/{DP}/{PI['Containers']}/extensions/3/isEnabled", False))
plan("8.1.5.1", "storage", "StorageAccounts")
plan("8.1.6.1", "app services", "AppServices")
plan("8.1.7.1", "cosmos db", "CosmosDbs")
plan("8.1.7.2", "open-source relational", "OpenSourceRelationalDatabases")
plan("8.1.7.3", "azure sql databases", "SqlServers")
plan("8.1.7.4", "sql servers on machines", "SqlServerVirtualMachines")
plan("8.1.8.1", "key vault", "KeyVaults")
plan("8.1.9.1", "resource manager", "Arm")
plan("8.1.10.1", "ai services", "AI")
F("8.1.10.2", "suspicious prompt evidence", [DP],
  [("the AIPromptEvidence component of the Defender for AI plan is not enabled", [], ['not plan_extension_on("AI", "AIPromptEvidence")'])],
  add(f"/{DP}/{PI['AI']}/extensions/0/isEnabled", "False"))
VM = "virtual_machines"
F("8.1.11", "operating systems for updates", [VM],
  [("virtual machine %v does not have periodic update assessment set to AutomaticByPlatform", ["nm(x)"],
    [each(VM), 'not "automaticbyplatform" in vm_assessment_modes(x)'])],
  rm(f"/{VM}/1/osProfile/windowsConfiguration/patchSettings/assessmentMode"))
A("8.1.12", "continuous export", "defender_alerts_exported_to_siem")
A("8.1.13", "security benchmark policies", "mcsb_policies_not_disabled")
SC = "security_contacts"
NO_DEFAULT = ("no default security contact was collected for the subscription", [], ["count(default_contacts) == 0"])
for _cid, _kw, _pred, _what, _fail in [
        ("8.1.14", "'owner' role", "contact_notifies_owners", "is not enabled or does not notify the Owner role",
         add(f"/{SC}/0/notificationsByRole/roles", ["AccountAdmin"])),
        ("8.1.15", "additional email addresses", "contact_has_emails", "has no additional email address",
         add(f"/{SC}/0/emails", "")),
        ("8.1.16", "severity", "contact_alert_severity_set", "does not send alert notifications with a minimum severity",
         rm(f"/{SC}/0/notificationsSources/0")),
        ("8.1.17", "attack paths", "contact_attack_path_set", "does not send attack path notifications with a minimum risk level",
         rm(f"/{SC}/0/notificationsSources/1"))]:
    F(_cid, _kw, [SC],
      [(f"the default security contact {_what}", [], ["some c in default_contacts", f"not {_pred}(c)"]), NO_DEFAULT],
      _fail)
A("8.1.18", "easm", "defender_easm_workspace_configured")
A("8.2.1", "iot hub", "defender_for_iot_hub_on")
HSM = "managed_hsms"
KV = "key_vaults"
A("8.3.1.1", "used when required", "managed_hsm_used_where_required")
F("8.3.1.2", "logging for azure key vault managed hsm", [HSM],
  [("Managed HSM %v has no diagnostic setting that sends audit logs to a destination", ["nm(x)"],
    [each(HSM), "is_array(x.diagnostic_settings)", "not audit_logging_on(x)"]),
   ("Managed HSM %v: diagnostic_settings not collected", ["nm(x)"], [each(HSM), "not has_list(x, \"diagnostic_settings\")"])],
  add(f"/{HSM}/0/diagnostic_settings/0/workspaceId", ""))
F("8.3.1.3", "hsm-protected", [KV],
  [("premium key vault %v: key %v is not HSM-protected", ["nm(x)", "nm(k)"],
    [each(KV), "kv_premium(x)", "some k in x.keys", "item_in_scope(k)", "not hsm_backed(k)"]),
   ("premium key vault %v: keys not collected", ["nm(x)"], [each(KV), "kv_premium(x)", "not has_list(x, \"keys\")"]),
   ("key vault %v: sku not collected", ["nm(x)"], [each(KV), "not sku_collected(x)"])],
  add(f"/{KV}/0/keys/0/kty", "RSA"))
F("8.3.1.4", "purge protection' is set to 'enabled' for azure key vault managed hsm", [HSM],
  [("Managed HSM %v does not have purge protection enabled", ["nm(x)"], [each(HSM), 'not p_true(x, "enablePurgeProtection")'])],
  add(f"/{HSM}/0/enablePurgeProtection", False))
F("8.3.1.5", "public network access' is 'disabled' for azure key vault managed hsm", [HSM],
  [("Managed HSM %v does not have public network access disabled", ["nm(x)"], [each(HSM), 'not p_ieq(x, "publicNetworkAccess", "Disabled")'])],
  rm(f"/{HSM}/0/publicNetworkAccess"))
F("8.3.1.6", "private endpoints are used to access azure key vault managed hsm", [HSM],
  [("Managed HSM %v has no approved private endpoint connection", ["nm(x)"], [each(HSM), "not approved_private_endpoint(x)"])],
  add(f"/{HSM}/0/privateEndpointConnections/0/privateLinkServiceConnectionState/status", "Pending"))
for _cid, _kw, _mode, _items, _what, _fail in [
        ("8.3.2", "keys in key vaults using rbac", "kv_rbac", "keys", "key", f"/{KV}/0/keys/0/attributes/expires"),
        ("8.3.3", "keys in key vaults using access policies", "kv_access_policy", "keys", "key", None),
        ("8.3.4", "secrets in key vaults using rbac", "kv_rbac", "secrets", "secret", f"/{KV}/0/secrets/0/attributes/expires"),
        ("8.3.5", "secrets in key vaults using access policies", "kv_access_policy", "secrets", "secret", None)]:
    F(_cid, _kw, [KV],
      [(f"key vault %v: enabled {_what} %v has no expiration date", ["nm(x)", "nm(k)"],
        [each(KV), f"{_mode}(x)", f"some k in x.{_items}", "item_in_scope(k)", "not has_expiry(k)"]),
       (f"key vault %v: {_items} not collected", ["nm(x)"], [each(KV), f"{_mode}(x)", f'not has_list(x, "{_items}")']),
       ("key vault %v: enableRbacAuthorization not collected", ["nm(x)"], [each(KV), "not kv_mode_known(x)"])],
      rm(_fail) if _fail else add(f"/{KV}/-", LEGACY_KV))
F("8.3.6", "validity period", [KV],
  [("key vault %v: certificate %v is issued for more than 12 months (or its validity is not collected)", ["nm(x)", "nm(c)"],
    [each(KV), "some c in x.certificates", "not cert_validity_ok(c)"]),
   ("key vault %v: certificates not collected", ["nm(x)"], [each(KV), "not has_list(x, \"certificates\")"])],
  add(f"/{KV}/0/certificates/0/policy/x509CertificateProperties/validityInMonths", 24))
F("8.3.7", "automatic key rotation", [KV],
  [("key vault %v: key %v has no rotation policy with a Rotate action and a usable trigger", ["nm(x)", "nm(k)"],
    [each(KV), "some k in x.keys", "item_in_scope(k)", "not auto_rotation(k)"]),
   ("key vault %v: keys not collected", ["nm(x)"], [each(KV), "not has_list(x, \"keys\")"])],
  add(f"/{KV}/0/keys/0/rotation_policy/lifetimeActions/0/action", "Notify"))
for _cid, _kw, _body, _what, _fail in [
        ("8.3.8", "'purge protection' is set to 'enabled'", 'not p_true(x, "enablePurgeProtection")', "does not have purge protection enabled",
         add(f"/{KV}/0/enablePurgeProtection", False)),
        ("8.3.9", "role based access control", 'not p_true(x, "enableRbacAuthorization")', "does not use Azure RBAC for data-plane access",
         add(f"/{KV}/0/enableRbacAuthorization", False)),
        ("8.3.10", "default network access rule", "not kv_network_restricted(x)",
         "neither denies by default in its firewall nor has public network access disabled",
         [add(f"/{KV}/0/publicNetworkAccess", "Enabled"), add(f"/{KV}/0/networkAcls/defaultAction", "Allow")]),
        ("8.3.11", "public network access is disabled", 'not p_ieq(x, "publicNetworkAccess", "Disabled")',
         "does not have public network access disabled", add(f"/{KV}/0/publicNetworkAccess", "Enabled")),
        ("8.3.12", "private endpoints are used to access azure key vault", "not has_private_endpoint(x)",
         "has no private endpoint connection", add(f"/{KV}/0/privateEndpointConnections", []))]:
    F(_cid, _kw, [KV], [(f"key vault %v {_what}", ["nm(x)"], [each(KV), _body])], _fail)
BH = "bastion_hosts"
F("8.4.1", "bastion host exists", [BH],
  [("no Azure Bastion host exists in the subscription", [], [f"count(input.{BH}) == 0"])], add(f"/{BH}", []))
F("8.4.2", "shareable link", [BH],
  [("Bastion host %v (Standard or Premium) has shareable links enabled", ["nm(x)"],
    [each(BH), "shareable_link_capable(x)", 'p_true(x, "enableShareableLink")']),
   ("Bastion host %v: sku not collected", ["nm(x)"], [each(BH), "not sku_collected(x)"])],
  add(f"/{BH}/0/enableShareableLink", True))
PIP = "public_ip_addresses"
F("8.5", "ddos protection is enabled on public ip", [PIP],
  [("public IP address %v is not protected by Azure DDoS Protection", ["nm(x)"], [each(PIP), "not nat_gateway_ip(x)", "not ddos_protected(x)"])],
  add(f"/{PIP}/1/ddos_protection_status/isWorkloadProtected", "False"))
F("8.6", "virtual networks", [VN],
  [("virtual network %v does not have DDoS Network Protection enabled", ["nm(x)"], [each(VN), 'not p_true(x, "enableDdosProtection")'])],
  add(f"/{VN}/0/enableDdosProtection", False))

# Section 9: storage
SA = "storage_accounts"
F("9.1.1", "soft delete for blobs", [SA],
  [("storage account %v does not keep deleted blobs for at least 7 days", ["nm(x)"],
    [each(SA), "blob_account(x)", "is_object(x.blob_service_properties)", "not blob_soft_delete_ok(x)"]),
   ("storage account %v: blob_service_properties not collected", ["nm(x)"],
    [each(SA), "blob_account(x)", 'not has_obj(x, "blob_service_properties")'])],
  add(f"/{SA}/0/blob_service_properties/deleteRetentionPolicy/days", 3))
for _cid, _kw, _body, _what, _fail in [
        ("9.2.1.1", "'public network access' is 'disabled' for storage", 'not p_ieq(x, "publicNetworkAccess", "Disabled")',
         "does not have public network access disabled", rm(f"/{SA}/0/publicNetworkAccess")),
        ("9.2.1.2", "default network access rule for storage", "not storage_default_deny(x)",
         "allows public network access without a default deny rule",
         [add(f"/{SA}/0/publicNetworkAccess", "Enabled"), add(f"/{SA}/0/networkRuleSet/defaultAction", "Allow")]),
        ("9.2.2.1", "default to microsoft entra authorization", 'not p_true(x, "defaultToOAuthAuthentication")',
         "does not default to Microsoft Entra authorization in the portal", rm(f"/{SA}/1/defaultToOAuthAuthentication")),
        ("9.2.3", "secure transfer", "not https_only(x)", "accepts requests over plain HTTP",
         add(f"/{SA}/0/enableHttpsTrafficOnly", False)),
        ("9.2.4", "minimum tls version", 'not storage_min_tls_ok(x)', "does not set the minimum TLS version to TLS1_2 or later",
         add(f"/{SA}/0/minimumTlsVersion", "TLS1_0")),
        ("9.2.5", "blob anonymous access", 'not p_false(x, "allowBlobPublicAccess")', "does not have anonymous blob access disabled",
         rm(f"/{SA}/1/allowBlobPublicAccess"))]:
    F(_cid, _kw, [SA], [(f"storage account %v {_what}", ["nm(x)"], [each(SA), _body])], _fail)

C.sort(key=lambda c: sort_key(c["id"]))
GREEN["attest"] = {c["attest"]: True for c in C if c["kind"] == "attest"}
TITLE_OVERRIDE = {
    "5.3.3": "no principal holds 'User Access Administrator' at the root scope",
    "5.3.5": "disabled user accounts must hold no read, write or owner role assignments",
}


# ── checks against the workbook ──────────────────────────────────────────────────────
def verify(wb):
    n_auto = sum(1 for w in wb.values() if w["assessment"] == "Automated")
    got = (len(wb), n_auto, len(wb) - n_auto)
    if got != EXPECTED:
        raise SystemExit(f"workbook has {got[0]} recommendations ({got[1]} Automated, {got[2]} Manual), expected {EXPECTED}")
    ids = [c["id"] for c in C]
    if len(ids) != len(set(ids)) or set(ids) != set(wb):
        raise SystemExit(f"logic/workbook mismatch: no logic {sorted(set(wb) - set(ids))}; no recommendation {sorted(set(ids) - set(wb))}")
    for c in C:
        w = wb[c["id"]]
        if (w["assessment"] == "Manual") != (c["kind"] == "attest"):
            raise SystemExit(f"{c['id']}: workbook says {w['assessment']}, logic table says {c['kind']}")
        if c["kw"].lower() not in w["title"].lower():
            raise SystemExit(f"{c['id']}: logic keyword {c['kw']!r} not in the workbook title")
        if len(w["profiles"]) != 1 or w["profiles"][0] not in ("Level 1", "Level 2"):
            raise SystemExit(f"{c['id']}: unexpected profiles {w['profiles']}")


def title(cid, wb):
    return TITLE_OVERRIDE.get(cid) or neutralize_title(wb[cid]["title"])


def section(cid):
    return cid.split(".")[0]


SECTION_NAMES = {"5": "identity_access", "6": "logging_monitoring", "7": "networking", "8": "security_services", "9": "storage"}


def ev_label(c):
    return " / ".join(f"input.{k}" for k in c["ev"])


def miss_msg(c):
    return f"{c['id']}: evidence missing — {ev_label(c)} not collected"


def att_msg(c, wb):
    return f"{c['id']}: {title(c['id'], wb)} (manual review not attested: set input.attest.{c['attest']} to true)"


def emit_control(c, wb):
    cid, uu = c["id"], u(c["id"])
    w = wb[cid]
    out = [f"# {cid} ({w['assessment']}, {w['profiles'][0]})"]
    if c["kind"] == "attest":
        out += [f"_messages contains {rego_str(att_msg(c, wb))} if {{", f'\t_in_scope("{cid}")',
                f'\tnot attested("{c["attest"]}")', "}", ""]
        return "\n".join(out)
    out += [f"default _ev_{uu} := false", "", f"_ev_{uu} if {{"] + [f'\tpresent("{k}")' for k in c["ev"]] + ["}", "",
            f"_messages contains {rego_str(miss_msg(c))} if {{", f'\t_in_scope("{cid}")', f"\tnot _ev_{uu}", "}", ""]
    t = title(cid, wb).replace("%", "%%")
    for detail, args, lines in c["rules"]:
        fmt = f"{cid}: {t} — {detail}"
        head = f"sprintf({rego_str(fmt)}, [{', '.join(args)}])" if args else rego_str(fmt.replace("%%", "%"))
        out += [f"_messages contains {head} if {{", f'\t_in_scope("{cid}")', f"\t_ev_{uu}"] + [f"\t{ln}" for ln in lines] + ["}", ""]
    return "\n".join(out)


def metadata(title_text, density, checks, entrypoint):
    return f'''# METADATA
# title: "{title_text}"
# custom:
#   class: security
#   framework: cis_azure
#   source: cis
#   domains: [cloud, azure]
#   coverage:
#     checks: {checks}
#     cited: 0
#     density: {density}
#     basis: {"size" if density == "sized" else "role"}
#     tested: true
#     entrypoint: {entrypoint}
#     guard: self
#     as_of: v2.4.2
'''


CONTRACT = """#   subscription_id / tenant_id      : the assessed subscription and its tenant (root management group id)
#   security_defaults                : GET graph /v1.0/policies/identitySecurityDefaultsEnforcementPolicy -> {isEnabled}
#   users[]                          : {userPrincipalName, perUserMfaState} (Graph beta /users/{id}/authentication/requirements)
#   root_role_assignments[]          : az role assignment list --scope / -> {roleDefinitionName, principalName, scope}
#   role_assignments[]               : az role assignment list --all --include-inherited -> {roleDefinitionName, scope,
#                                      principalId, principalName, principalType, condition}
#   role_definitions[]               : az role definition list --custom-role-only true -> {roleName, roleType, permissions[{actions}], assignableScopes}
#   management_group_hierarchy_settings : az account management-group hierarchy-settings list --name <tenant> (first entry)
#   role_assigned_service_principals[] : each role-holding service principal (az ad sp show) -> {displayName, servicePrincipalType,
#                                      appOwnerOrganizationId, passwordCredentials[], application_password_credentials[]
#                                      (az ad app credential list, for applications registered in this tenant)}
#   subscription_diagnostic_settings[] : az monitor diagnostic-settings subscription list -> {workspaceId|storageAccountId|..., logs[{category, enabled}]}
#   activity_log_alerts[]            : az monitor activity-log alert list -> {enabled, scopes[], condition{allOf[]}, actions{actionGroups[]}}
#   application_insights[]           : az monitor app-insights component show
#   log_analytics_workspaces[]       : {publicNetworkAccessForIngestion, publicNetworkAccessForQuery}
#   network_security_groups[]        : az network nsg list -> {name, securityRules[]} (rule fields as the CLI prints them)
#   application_gateways[]           : az network application-gateway list -> {enableHttp2, sslPolicy, sslProfiles[], firewallPolicy{id}}
#   application_gateway_waf_policies[] : az network application-gateway waf-policy list -> {id, policySettings, managedRules}
#   virtual_networks[]               : az network vnet list -> {enableDdosProtection, subnets[{name, networkSecurityGroup, delegations[], defaultOutboundAccess}]}
#   regions_in_use[]                 : the regions that hold resources (az resource list, distinct location)
#   network_watchers[]               : az network watcher list -> {location, provisioningState}
#   flow_logs[]                      : az network watcher flow-log list (every region) -> {targetResourceId, enabled, retentionPolicy{days}}
#   virtual_network_gateways[]       : az network vnet-gateway show -> {vpnClientConfiguration{vpnAuthenticationTypes[]}}
#   front_door_profiles[]            : az afd profile list, each with endpoints[], custom_domains[] and security_policies[] joined
#   front_door_waf_policies[]        : az network front-door waf-policy list -> {id, policySettings{enabledState}}
#   defender_pricings[]              : az security pricing list -> {name, pricingTier, subPlan, extensions[{name, isEnabled}]}
#   defender_settings[]              : Microsoft.Security/settings -> {name, enabled} (WDATP)
#   virtual_machines[]               : az vm list -> {osProfile{windowsConfiguration|linuxConfiguration{patchSettings{assessmentMode}}}}
#   security_contacts[]              : Microsoft.Security/securityContacts (2023-12-01-preview) -> {name, isEnabled, emails,
#                                      notificationsByRole{state, roles[]}, notificationsSources[{sourceType, minimalSeverity|minimalRiskLevel}]}
#   managed_hsms[]                   : az keyvault list --resource-type hsm -> {enablePurgeProtection, publicNetworkAccess,
#                                      privateEndpointConnections[], diagnostic_settings[] (joined)}
#   key_vaults[]                     : az keyvault show -> {sku, enableRbacAuthorization, enablePurgeProtection, publicNetworkAccess,
#                                      networkAcls, privateEndpointConnections[], diagnostic_settings[], keys[{kty, attributes,
#                                      rotation_policy}], secrets[{attributes}], certificates[{policy}]} (lists joined by the collector)
#   bastion_hosts[]                  : az network bastion list -> {sku{name}, enableShareableLink}
#   public_ip_addresses[]            : az network public-ip list -> {ddosSettings, natGateway, ddos_protection_status (joined)}
#   storage_accounts[]               : az storage account list -> {kind, publicNetworkAccess, networkRuleSet, defaultToOAuthAuthentication,
#                                      enableHttpsTrafficOnly, minimumTlsVersion, allowBlobPublicAccess, blob_service_properties (joined)}
#   attest.<key>                     : attestation booleans for the Manual recommendations (see `attestations`)
#   attest.activity_log_alert_scopes_recorded / attest.service_health_event_types_recorded : the organization's recorded
#                                      scoping decision that lets 6.1.2.3-6.1.2.10 and 6.1.2.17 use a narrower rule scope,
#                                      and 6.1.2.11 limit its event types
#   cis_profile.level                : 1 or 2 (default 2: every recommendation; Level 2 includes Level 1)
# Properties are read flat (as the Azure CLI prints them) or nested under "properties" (ARM / Resource Graph)."""


def engine(wb):
    ids = [c["id"] for c in C]
    l1 = [i for i in ids if wb[i]["level"] == 1]
    att = [c for c in C if c["kind"] == "attest"]
    n_auto = sum(1 for i in ids if wb[i]["assessment"] == "Automated")
    ev_keys = sorted({k for c in C if c["kind"] == "fact" for k in c["ev"]})
    parts = [metadata(f"{BENCH} {VERSION}", "sized", 0, "none"), "package cis_azure", "",
             f"# {BENCH} {VERSION}. Generated by tools/cis_generators/gen_azure.py from the CIS workbook: do not edit by",
             "# hand, regenerate.",
             f"# All {len(ids)} recommendations ({n_auto} Automated, {len(ids) - n_auto} Manual; {len(l1)} Level 1, {len(ids) - len(l1)} Level 2)",
             "# in five sections: 5 Identity, 6 Logging and Monitoring, 7 Networking, 8 Security Services, 9 Storage. Ids, profile",
             "# and status come from the workbook; messages are our own words.",
             "#",
             f"# The {n_auto} Automated recommendations are decided from collected resource inventories. Per-resource checks iterate",
             "# the collected list: an EMPTY list means no resources of that kind and passes, an ABSENT list raises",
             "# \"<id>: evidence missing — <input path> not collected\" (never a pass), and a resource that lacks the audited",
             "# property is a finding for that resource. Checks that need something to EXIST (an alert, a diagnostic",
             "# setting, Application Insights, a Bastion host, a security contact) fail on an empty list.",
             f"# The {len(att)} Manual recommendations pass only on an explicit attestation: input.attest.<key> == true.",
             "# input.cis_profile.level selects Level 1 (1) or Level 1 + Level 2 (2, the default); out-of-profile",
             "# recommendations raise nothing.",
             "#",
             "# This package is the engine. cis_azure.main (the /v1/data/cis_azure/main/compliance_report entrypoint) and",
             "# cis_azure.l2 (the Level 2 view) read its rules.",
             "#",
             "# Input contract (one subscription; field names are those of the Azure CLI / Microsoft Graph JSON output):",
             CONTRACT, "", "import rego.v1", "",
             "default compliant := false", "", "compliant if count(violations) == 0", "",
             "# ── profile ──────────────────────────────────────────────────────────────────────────",
             "default level := 2", "", 'level := 1 if lower(sprintf("%v", [input.cis_profile.level])) in {"1", "level1", "level 1", "level_1"}', "",
             "in_scope contains id if {", "\tsome id, r in recommendations", "\tr.level <= level", "}", "",
             "_in_scope(id) if id in in_scope", ""]
    rec = {}
    for c in C:
        w = wb[c["id"]]
        rec[c["id"]] = {"section": section(c["id"]), "level": w["level"], "assessment": w["assessment"],
                        "check": "attestation" if c["kind"] == "attest" else "configuration", "title": title(c["id"], wb)}
    parts += ["# ── recommendation table (ids, profile level and status from the workbook) ─────────────",
              "recommendations := " + json.dumps(rec, indent="\t", ensure_ascii=False), "",
              "# Manual recommendations: control id -> attestation key under input.attest.",
              "attestations := " + json.dumps({c["id"]: c["attest"] for c in att}, indent="\t"), "",
              "attested(key) if input.attest[key] == true", "",
              "# ── evidence ──────────────────────────────────────────────────────────────────────────",
              "# Automated recommendation -> the inventories it reads. Objects must be non-empty; every other key is a list.",
              "evidence := " + json.dumps({c["id"]: c["ev"] for c in C if c["kind"] == "fact"}, indent="\t"), "",
              "_object_keys := " + json.dumps(sorted(OBJECT_KEYS)).replace("[", "{").replace("]", "}"), "",
              "present(k) if {", "\tk in _object_keys", "\tis_object(input[k])", "\tcount(input[k]) > 0", "}", "",
              "present(k) if {", "\tnot k in _object_keys", "\tis_array(input[k])", "}", ""]
    parts.append(open(os.path.join(HERE, "azure_lib.rego.tmpl")).read())
    parts.append("# ── recommendations ───────────────────────────────────────────────────────────────────\n")
    for c in C:
        parts.append(emit_control(c, wb))
    parts.append(f'''# ── aggregate ─────────────────────────────────────────────────────────────────────────
violations := sort([v | some v in _messages])

control_id(v) := regex.find_n(`^[0-9]+(\\.[0-9]+)*`, v, 1)[0]

failing_controls := {{control_id(v) | some v in violations}}

total_controls := count(in_scope)

evidence_violations := [v | some v in violations; contains(v, ": evidence missing — ")]

section_names := {json.dumps(SECTION_NAMES)}

# Counts are distinct recommendations, never messages: one control can fail on many resources.
compliance_summary := {{
	"benchmark": "{BENCH} {VERSION}",
	"profile_level": level,
	"total_controls": total_controls,
	"passing_controls": total_controls - count(failing_controls),
	"failing_controls": count(failing_controls),
	"sections": {{name: {{
		"total": count({{id | some id in in_scope; recommendations[id].section == sec}}),
		"failed": count({{id | some id in failing_controls; recommendations[id].section == sec}}),
		"violations": [v | some v in violations; startswith(v, concat("", [sec, "."]))],
	}} |
		some sec, name in section_names
	}},
}}
''')
    # sanity: every evidence key is documented in the contract
    for k in ev_keys:
        assert f"#   {k}" in CONTRACT, k
    return "\n".join(parts)


def main_module(wb):
    return metadata(f"{BENCH} {VERSION}", "orchestrator", 1, "compliance_report") + f'''package cis_azure.main

import rego.v1

import data.cis_azure as bench

# {BENCH} {VERSION}
#
# Entry point for the cis_azure framework key. The {len(C)} recommendations are evaluated in
# cis_azure_foundations.rego (package cis_azure, which also documents the input contract); this module
# republishes them in the framework-key compliance_report shape. Generated by tools/cis_generators/gen_azure.py.
#
# total_controls is the number of recommendations in the selected profile (input.cis_profile.level:
# 1 => Level 1 only, otherwise Level 1 + Level 2). failed_controls counts distinct failing recommendations.
#
# OPA endpoint: POST http://<host>:8181/v1/data/cis_azure/main/compliance_report

default compliant := false

compliant if {{
	_facts_supplied
	count(violations) == 0
}}

violations contains v if some v in bench.violations

# Optional identity fields are read through defaulted helpers: an undefined field inside the object
# literal would make the whole report undefined (library rule #5).
default _entity_name := ""

_entity_name := input.entity_name

default _subscription_id := ""

_subscription_id := input.subscription_id

default _assessed_at := ""

_assessed_at := input.assessment_date

# ---------------------------------------------------------------------------
# FAIL-CLOSED GATE
#
# An input that carries no facts (only the profile selector or identity fields) is reported as fully
# non-compliant with an explicit violation, never as a pass. The engine also fails every recommendation
# whose evidence is missing, so a partial input cannot pass the controls it does not cover.
# ---------------------------------------------------------------------------
_non_fact_keys := {{"cis_profile", "entity_name", "assessment_date", "subscription_id", "tenant_id"}}

default _facts_supplied := false

_facts_supplied if count({{k | some k, _ in input; not k in _non_fact_keys}}) > 0

_no_facts_msg := sprintf(
	"FAIL-CLOSED: no facts supplied for %s — the assessment could not be evaluated. This is NOT a passing result; check that fact collection ran and produced input.",
	["cis_azure"],
)

default _total_controls := {len(C)}

_total_controls := bench.total_controls

_bench_violations := sort([v | some v in violations])

_violations := array.concat(_bench_violations, [_no_facts_msg]) if not _facts_supplied

_violations := _bench_violations if _facts_supplied

_failed := _total_controls if not _facts_supplied

_failed := min([_total_controls, count(bench.failing_controls)]) if _facts_supplied

_passed := max([0, _total_controls - _failed])

default _percentage := 0

_percentage := round((_passed * 100000) / _total_controls) / 1000 if _total_controls > 0

_level_ids(l) := {{id | some id in bench.in_scope; bench.recommendations[id].level == l}}

_level_failed(l) := count(_level_ids(l)) if not _facts_supplied

_level_failed(l) := count(_level_ids(l) & bench.failing_controls) if _facts_supplied

_section(s) := [v | some v in _violations; startswith(v, concat("", [s, "."]))]

compliance_report := {{
	"framework": "cis_azure",
	"benchmark": "{BENCH}",
	"version": "{VERSION}",
	"profile": sprintf("level%d", [bench.level]),
	"entity_name": _entity_name,
	"subscription_id": _subscription_id,
	"assessed_at": _assessed_at,
	"compliant": compliant,
	"total_controls": _total_controls,
	"standard_total": {len(C)},
	"passed_controls": _passed,
	"failed_controls": _failed,
	"compliance_percentage": _percentage,
	"level_1": {{"total": count(_level_ids(1)), "failed": _level_failed(1)}},
	"level_2": {{"total": count(_level_ids(2)), "failed": _level_failed(2)}},
	"violations": _violations,
	"violation_count": count(_violations),
	"evidence_missing_count": count(bench.evidence_violations),
	"section_results": {{
		"identity_access": _section("5"),
		"logging_monitoring": _section("6"),
		"networking": _section("7"),
		"security_services": _section("8"),
		"storage": _section("9"),
	}},
}}
'''


def l2_module(wb):
    n2 = sum(1 for c in C if wb[c["id"]]["level"] == 2)
    return metadata(f"{BENCH} {VERSION} - Level 2 Additional Controls", "section", 1, "compliance_report") + f'''package cis_azure.l2

# {BENCH} {VERSION} - Level 2 additional recommendations.
# The {n2} recommendations the workbook assigns to the Level 2 profile (Level 2 extends Level 1; cis_azure.main
# reports both). Each is evaluated once, in cis_azure_foundations.rego; this module selects the Level 2 subset
# and reports it as "CIS L2 <id>: ...". Generated by tools/cis_generators/gen_azure.py.

import rego.v1

import data.cis_azure as bench

default compliant := false

compliant if {{
	count(object.keys(input)) > 0
	count(violations) == 0
}}

l2_ids := {{id | some id, r in bench.recommendations; r.level == 2}}

control_id(v) := regex.find_n(`^[0-9]+(\\.[0-9]+)*`, v, 1)[0]

violations contains sprintf("CIS L2 %s", [v]) if {{
	some v in bench.violations
	control_id(v) in l2_ids
}}

failing_l2_controls := {{id | some v in bench.violations; id := control_id(v); id in l2_ids}}

compliance_report := {{
	"profile": "level2",
	"benchmark": "{BENCH} {VERSION}",
	"l2_controls": count(l2_ids),
	"l2_violations": count(failing_l2_controls),
	"l2_compliant": compliant,
	"l2_violation_list": sort([v | some v in violations]),
	"note": "Level 2 recommendations supplement Level 1. With input.cis_profile.level 1 the engine leaves them out and this view is empty.",
}}
'''


TEST_HEAD = '''package {pkg}

import rego.v1

import data.cis_azure as b

# {what} Generated by tools/cis_generators/gen_azure.py; regenerate, do not edit.

green := {green}

_has_id(vs, id) if {{
	some v in vs
	startswith(v, concat("", [id, ":"]))
}}
'''


def j(x):
    return json.dumps(x, ensure_ascii=False)


def control_tests(wb):
    out = [TEST_HEAD.format(pkg="cis_azure.v7_controls_test", green=json.dumps(GREEN, indent="\t", ensure_ascii=False),
                            what=f"Per-recommendation tests for {BENCH} {VERSION}: every recommendation has a pass test (green input) "
                                 "and a fail test; Automated recommendations also have an evidence-missing test; attestations fail "
                                 "when false or absent."),
           "test_green_input_is_compliant if {\n\tvs := b.violations with input as green\n\tcount(vs) == 0\n}\n"]
    for c in C:
        cid, uu = c["id"], u(c["id"])
        out.append(f'test_{uu}_pass if {{\n\tvs := b.violations with input as green\n\tnot _has_id(vs, "{cid}")\n}}\n')
        if c["kind"] == "attest":
            m = rego_str(att_msg(c, wb))
            key = c["attest"]
            out.append(f"test_{uu}_fail if {{\n\tinp := json.patch(green, {j([add('/attest/' + key, False)])})\n"
                       f"\tvs := b.violations with input as inp\n\t{m} in vs\n}}\n")
            out.append(f"test_{uu}_not_attested_when_absent if {{\n\tinp := json.patch(green, {j([rm('/attest/' + key)])})\n"
                       f"\tvs := b.violations with input as inp\n\t{m} in vs\n}}\n")
            continue
        mm = rego_str(miss_msg(c))
        out.append(f"test_{uu}_fail if {{\n\tinp := json.patch(green, {j(c['fail'])})\n\tvs := b.violations with input as inp\n"
                   f'\t_has_id(vs, "{cid}")\n\tnot {mm} in vs\n}}\n')
        out.append(f"test_{uu}_evidence_missing if {{\n\tinp := json.patch(green, {j(c['miss'])})\n"
                   f"\tvs := b.violations with input as inp\n\t{mm} in vs\n}}\n")
    return "\n".join(out)


def report_tests(wb):
    n1 = sum(1 for c in C if wb[c["id"]]["level"] == 1)
    n2 = len(C) - n1
    na = sum(1 for c in C if wb[c["id"]]["assessment"] == "Automated")
    return TEST_HEAD.format(pkg="cis_azure.main_test", green="data.cis_azure.v7_controls_test.green",
                            what="Report and profile tests (framework-key contract, fail-closed, Level 1 / Level 2).") + f'''
test_recommendation_count_matches_workbook if {{
	count(b.recommendations) == {len(C)}
	count([id | some id, r in b.recommendations; r.level == 1]) == {n1}
	count([id | some id, r in b.recommendations; r.level == 2]) == {n2}
	count([id | some id, r in b.recommendations; r.assessment == "Automated"]) == {na}
	count(b.attestations) == {len(C) - na}
}}

test_empty_input_level_2_default if {{
	r := data.cis_azure.main.compliance_report with input as {{}}
	r.compliant == false
	r.total_controls == {len(C)}
	r.failed_controls == {len(C)}
	r.passed_controls == 0
	r.compliance_percentage == 0
	r.violation_count == count(r.violations)
	some v in r.violations
	startswith(v, "FAIL-CLOSED: no facts supplied")
}}

test_empty_input_level_1 if {{
	r := data.cis_azure.main.compliance_report with input as {{"cis_profile": {{"level": 1}}}}
	r.compliant == false
	r.profile == "level1"
	r.total_controls == {n1}
	r.failed_controls == {n1}
	r.level_2.total == 0
}}

test_profile_only_input_is_fail_closed if {{
	r := data.cis_azure.main.compliance_report with input as {{"cis_profile": {{"level": 2}}, "subscription_id": "x"}}
	r.compliant == false
	r.failed_controls == r.total_controls
}}

test_every_recommendation_fails_on_empty_input if {{
	vs := b.violations with input as {{}}
	every id, _ in b.recommendations {{ _has_id(vs, id) }}
}}

test_green_report_compliant if {{
	r := data.cis_azure.main.compliance_report with input as green
	r.compliant == true
	r.failed_controls == 0
	r.passed_controls == {len(C)}
	r.compliance_percentage == 100
	r.level_1.total == {n1}
	r.level_2.total == {n2}
}}

test_level_1_ignores_level_2_findings if {{
	inp := json.patch(green, [{{"op": "add", "path": "/cis_profile", "value": {{"level": 1}}}}, {{"op": "remove", "path": "/bastion_hosts"}}])
	vs := b.violations with input as inp
	not _has_id(vs, "8.4.1")
	_has_id(vs, "8.4.2")
	r := data.cis_azure.main.compliance_report with input as inp
	r.total_controls == {n1}
	r.failed_controls == 1
}}

'''


def _nsg_case(name, rule, ids_hit, ids_clear):
    patch = j([add("/network_security_groups/0/securityRules/-", rule)])
    lines = [f"test_nsg_{name} if {{", f"\tinp := json.patch(green, {patch})", "\tvs := b.violations with input as inp"]
    lines += [f'\t_has_id(vs, "{i}")' for i in ids_hit] + [f'\tnot _has_id(vs, "{i}")' for i in ids_clear] + ["}", ""]
    return "\n".join(lines)


def l2_tests(wb):
    n2 = sum(1 for c in C if wb[c["id"]]["level"] == 2)
    return TEST_HEAD.format(pkg="cis_azure.l2_test", green="data.cis_azure.v7_controls_test.green",
                            what="Level 2 view tests.") + """
test_l2_view if {
	r := data.cis_azure.l2.compliance_report with input as {}
	r.l2_controls == {n2}
	r.l2_violations == {n2}
	r.l2_controls == count([id | some id, x in b.recommendations; x.level == 2])
	r.l2_compliant == false
	g := data.cis_azure.l2.compliance_report with input as green
	g.l2_compliant == true
	lvl1 := data.cis_azure.l2.compliance_report with input as object.union(green, {"cis_profile": {"level": 1}})
	lvl1.l2_violations == 0
}
""".replace("{n2}", str(n2))


def logic_tests():
    r = _rule
    out = [TEST_HEAD.format(pkg="cis_azure.v7_logic_test", green="data.cis_azure.v7_controls_test.green",
                            what="Edge cases: open sources, port ranges and lists, empty versus absent lists, missing "
                                 "properties, nested ARM properties, alert scoping.")]
    out += [
        _nsg_case("range_covering_rdp", r("a", 300, "Inbound", "Allow", "Tcp", "Internet", "3380-3390"), ["7.1.1"], ["7.1.5", "7.1.4"]),
        _nsg_case("range_beside_rdp", r("a", 300, "Inbound", "Allow", "Tcp", "Internet", "3390-4000"), [], ["7.1.1"]),
        _nsg_case("udp_not_rdp", r("a", 300, "Inbound", "Allow", "Udp", "*", "3389"), [], ["7.1.1"]),
        _nsg_case("any_protocol_any_port", r("a", 300, "Inbound", "Allow", "*", "0.0.0.0/0", "*"),
                  ["7.1.1", "7.1.2", "7.1.3", "7.1.4", "7.1.5", "7.1.6"], []),
        _nsg_case("ipv6_any_in_prefix_list", r("a", 300, "Inbound", "Allow", "Tcp", None, None, sourceAddressPrefixes=["10.0.0.0/8", "::/0"],
                                               destinationPortRanges=["22", "8443"]), ["7.1.5"], ["7.1.3"]),
        _nsg_case("private_source", r("a", 300, "Inbound", "Allow", "*", "192.0.2.0/24", "*"), [], ["7.1.1", "7.1.5", "7.1.6"]),
        _nsg_case("outbound_ignored", r("a", 300, "Outbound", "Allow", "*", "*", "*"), [], ["7.1.1", "7.1.5"]),
        _nsg_case("deny_ignored", r("a", 300, "Inbound", "Deny", "*", "Internet", "22"), [], ["7.1.5"]),
        _nsg_case("rule_missing_protocol", {"name": "half", "access": "Allow", "direction": "Inbound", "sourceAddressPrefix": "*",
                                            "destinationPortRange": "22"}, ["7.1.1", "7.1.5"], []),
        _nsg_case("allow_after_deny_all", r("late", 4090, "Inbound", "Allow", "Tcp", "10.0.0.0/8", "8080"), ["7.8"], ["7.1.1"]),
    ]
    out.append('''test_empty_lists_pass if {
	inp := json.patch(green, [
		{"op": "add", "path": "/storage_accounts", "value": []},
		{"op": "add", "path": "/network_security_groups", "value": []},
		{"op": "add", "path": "/key_vaults", "value": []},
		{"op": "add", "path": "/application_gateways", "value": []},
	])
	vs := b.violations with input as inp
	count(vs) == 0
}

test_absent_list_is_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/storage_accounts"}])
	vs := b.violations with input as inp
	"9.2.4: evidence missing — input.storage_accounts not collected" in vs
}

test_missing_property_is_a_finding if {
	inp := json.patch(green, [{"op": "remove", "path": "/storage_accounts/0/minimumTlsVersion"}, {"op": "remove", "path": "/key_vaults/0/enablePurgeProtection"}])
	vs := b.violations with input as inp
	_has_id(vs, "9.2.4")
	_has_id(vs, "8.3.8")
}

test_storage_tls13_minimum_meets_9_2_4 if {
	inp := json.patch(green, [{"op": "replace", "path": "/storage_accounts/0/minimumTlsVersion", "value": "TLS1_3"}])
	vs := b.violations with input as inp
	not _has_id(vs, "9.2.4")
}

test_storage_tls11_minimum_fails_9_2_4 if {
	inp := json.patch(green, [{"op": "replace", "path": "/storage_accounts/0/minimumTlsVersion", "value": "TLS1_1"}])
	vs := b.violations with input as inp
	_has_id(vs, "9.2.4")
}

test_nested_properties_shape if {
	inp := json.patch(green, [{"op": "add", "path": "/storage_accounts", "value": [{"name": "starm", "kind": "StorageV2", "properties": {
		"publicNetworkAccess": "Disabled", "networkAcls": {"defaultAction": "Deny"}, "defaultToOAuthAuthentication": true,
		"supportsHttpsTrafficOnly": true, "minimumTlsVersion": "TLS1_2", "allowBlobPublicAccess": false,
	}, "blob_service_properties": {"properties": {"deleteRetentionPolicy": {"enabled": true, "days": 14}}}}]}])
	vs := b.violations with input as inp
	count(vs) == 0
}

test_narrow_alert_scope_needs_recorded_decision if {
	inp := json.patch(green, [
		{"op": "add", "path": "/activity_log_alerts/2/scopes", "value": ["/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-core"]},
		{"op": "add", "path": "/activity_log_alerts/0/scopes", "value": ["/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-core"]},
	])
	vs := b.violations with input as inp
	_has_id(vs, "6.1.2.3")
	_has_id(vs, "6.1.2.1")
	inp2 := json.patch(inp, [{"op": "add", "path": "/attest/activity_log_alert_scopes_recorded", "value": true}])
	vs2 := b.violations with input as inp2
	not _has_id(vs2, "6.1.2.3")
	_has_id(vs2, "6.1.2.1")
}

test_alert_for_other_subscription_does_not_count if {
	inp := json.patch(green, [{"op": "add", "path": "/activity_log_alerts/0/scopes", "value": ["/subscriptions/99999999-0000-0000-0000-000000000000"]}])
	vs := b.violations with input as inp
	_has_id(vs, "6.1.2.1")
}

test_owner_count_bounds if {
	four := json.patch(green, [
		{"op": "add", "path": "/role_assignments/-", "value": {"roleDefinitionName": "Owner", "scope": "/subscriptions/00000000-0000-0000-0000-000000000001", "principalId": "p-4"}},
		{"op": "add", "path": "/role_assignments/-", "value": {"roleDefinitionName": "Owner", "scope": "/subscriptions/00000000-0000-0000-0000-000000000001", "principalId": "p-5"}},
	])
	_has_id(b.violations, "5.7") with input as four
	three := json.patch(green, [{"op": "add", "path": "/role_assignments/-", "value": {"roleDefinitionName": "Owner", "scope": "/subscriptions/00000000-0000-0000-0000-000000000001", "principalId": "p-4"}}])
	not _has_id(b.violations, "5.7") with input as three
}

test_ddos_skips_nat_gateway_ip if {
	inp := json.patch(green, [{"op": "add", "path": "/public_ip_addresses/-", "value": {"name": "pip-bare"}}])
	_has_id(b.violations, "8.5") with input as inp
}

test_flow_log_retention_zero_is_unlimited if {
	inp := json.patch(green, [{"op": "add", "path": "/flow_logs/0/retentionPolicy/days", "value": 0}])
	not _has_id(b.violations, "7.6") with input as inp
}

test_disabled_nsg_flow_log_out_of_scope if {
	inp := json.patch(green, [{"op": "add", "path": "/flow_logs/1/enabled", "value": false}, {"op": "add", "path": "/flow_logs/1/retentionPolicy/days", "value": 7}])
	not _has_id(b.violations, "7.12") with input as inp
}
''')
    return "\n".join(out)


def main():
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    wb = load(sys.argv[1])
    verify(wb)
    out = sys.argv[2]
    os.makedirs(os.path.join(out, "tests"), exist_ok=True)
    files = {"cis_azure_foundations.rego": engine(wb), "cis_azure_main.rego": main_module(wb), "l2_validation.rego": l2_module(wb),
             "tests/test_cis_azure_v7_controls.rego": control_tests(wb), "tests/test_cis_azure_v7_reports.rego": report_tests(wb),
             "tests/test_cis_azure_v7_logic.rego": logic_tests(), "tests/test_cis_azure_v7_l2.rego": l2_tests(wb)}
    assert sorted(files) == sorted(OWNED)
    paths = []
    for name, text in files.items():
        p = os.path.join(out, name)
        with open(p, "w") as fh:
            fh.write(text)
        paths.append(p)
    subprocess.run(["opa", "fmt", "-w"] + paths, check=True)
    n1 = sum(1 for w in wb.values() if w["level"] == 1)
    print(f"ok {len(C)} recommendations; L1 {n1}, L2 {len(C) - n1}; attest {sum(c['kind'] == 'attest' for c in C)}")


if __name__ == "__main__":
    main()
