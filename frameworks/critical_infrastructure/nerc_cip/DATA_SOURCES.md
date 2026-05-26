# NERC-CIP Compliance — Data Sources Reference

This document maps every `input.*` field consumed by the CIP-002 through CIP-015 Rego
policies to the real-world source system that must provide it for results to be valid.

The current demo uses a static YAML file
(`examples/nerc_cip_assessment_data.yml`) with hardcoded values. Replacing each
section below with live data is what turns the demo into a production compliance
engine.

---

## How data reaches OPA

```
Source Systems
     │
     ▼
Ansible Fact Collection (per playbook below)
     │
     ▼
nerc_cip_compliance_report.yml  ──POST──▶  OPA :8183/v1/data/nerc_cip_main
     │
     ▼
PostgreSQL compliance_results
```

The Ansible playbook builds a single JSON object and POSTs it as `input` to OPA.
Each section below maps to one or more keys in that object.

---

## CIP-002 — BES Cyber System Categorization

| Input field | Type | Source system | Collection method | Status |
|---|---|---|---|---|
| `bes_cyber_systems[].system_id` | string | CMDB / GIS asset registry | Query asset DB via REST API or JDBC | **Stubbed** |
| `bes_cyber_systems[].name` | string | CMDB | As above | **Stubbed** |
| `bes_cyber_systems[].impact_level` | enum `high\|medium\|low` | CMDB (CIP classification field) | As above | **Stubbed** |
| `bes_cyber_systems[].has_external_routable_connectivity` | bool | Network inventory / firewall policy | Firewall rule query or IPAM | **Stubbed** |
| `bes_cyber_systems[].esp_name` | string | CMDB / network diagram | As above | **Stubbed** |
| `bes_cyber_systems[].asset_type` | string | CMDB | As above | **Stubbed** |
| `categorization_documentation.criteria_defined` | bool | GRC platform (e.g. Archer, ServiceNow GRC) | Document existence check via API | **Stubbed** |
| `categorization_documentation.methodology_documented` | bool | GRC platform | As above | **Stubbed** |
| `categorization_documentation.rationale_provided` | bool | GRC platform | As above | **Stubbed** |
| `categorization_documentation.last_review_date` | ISO-8601 | GRC platform | Policy review date field | **Stubbed** |
| `categorization_documentation.cip_senior_manager_approved` | bool | GRC platform / DocuSign | Approval workflow record | **Stubbed** |
| `categorization_documentation.attachment1_used` | bool | GRC platform | Document metadata | **Stubbed** |
| `attachment1.high_impact_criteria.criterion_2_*.evaluated` | bool | GRC platform | CIP-002 Attachment 1 worksheet | **Stubbed** |
| `attachment1.medium_impact_criteria.criterion_3_*.evaluated` | bool | GRC platform | As above | **Stubbed** |
| `bes_environment_changes[]` | list | Change management (ServiceNow / Jira) | Query changes tagged "BES-environment" | **Stubbed** |
| `electronic_access_control_systems` | list | CMDB | Filter by asset category "EACS" | **Stubbed** |
| `physical_access_control_systems` | list | CMDB | Filter by asset category "PACS" | **Stubbed** |

**Ansible approach:** `community.general.uri` against CMDB REST API; or
`community.postgresql.postgresql_query` if asset data is in the compliance DB.

---

## CIP-003 — Security Management Controls

| Input field | Type | Source system | Collection method | Status |
|---|---|---|---|---|
| `cybersecurity_organization.senior_manager.designated` | bool | GRC / org chart | Manual attestation or HR API | **Stubbed** |
| `cybersecurity_organization.senior_manager.name` | string | HR system | HR API query for CIP-SM role | **Stubbed** |
| `cybersecurity_organization.senior_manager.authority_documented` | bool | GRC platform | Document existence check | **Stubbed** |
| `cybersecurity_policies.documented` | bool | GRC / SharePoint | Policy document API | **Stubbed** |
| `cybersecurity_policies.approved` | bool | GRC platform | Approval workflow status | **Stubbed** |
| `cybersecurity_policies.last_review_date` | epoch ns | GRC platform | Policy review date field | **Stubbed** |
| `cybersecurity_policies.cip_senior_manager_approved` | bool | GRC / DocuSign | Approval record | **Stubbed** |
| `cybersecurity_policies.areas.*` | bool ×7 | GRC platform | Policy coverage matrix | **Stubbed** |
| `information_sharing_plan.documented` | bool | GRC platform | Document existence | **Stubbed** |
| `information_sharing_plan.nerc_contact_included` | bool | GRC platform | Plan content check | **Stubbed** |
| `information_sharing_plan.last_review_date` | ISO-8601 | GRC platform | Review date field | **Stubbed** |
| `low_impact_plan.documented` | bool | GRC platform | Low-impact plan existence | **Stubbed** |
| `low_impact_plan.electronic_access_controls` | bool | GRC platform | Plan content verification | **Stubbed** |
| `low_impact_plan.cyber_security_incident_response` | bool | GRC platform | As above | **Stubbed** |
| `low_impact_plan.last_review_date` | ISO-8601 | GRC platform | Review date | **Stubbed** |
| `transient_cyber_assets.policy_documented` | bool | GRC platform | TCA policy existence | **Stubbed** |
| `transient_cyber_assets.controls.malicious_code_prevention` | bool | Endpoint management (e.g. SCCM, Ansible) | Verify AV/EDR deployed to TCAs | **Stubbed** |
| `transient_cyber_assets.controls.security_patches.applied` | bool | Patch management | Patch compliance query for TCAs | **Stubbed** |
| `transient_cyber_assets.asset_management.inventory_maintained` | bool | CMDB | TCA-category assets present in CMDB | **Stubbed** |
| `removable_media.policy_documented` | bool | GRC platform | Policy document existence | **Stubbed** |
| `removable_media.scanning_before_use` | bool | Endpoint/DLP system | DLP policy query | **Stubbed** |
| `removable_media.encryption_when_applicable` | bool | Endpoint/DLP | Encryption policy enforcement | **Stubbed** |

**Ansible approach:** Most of these are attestation fields. Collect via a survey
form or ServiceNow GRC REST API (`/api/now/table/u_cip_policy_attestation`).

---

## CIP-004 — Personnel & Training

| Input field | Type | Source system | Collection method | Status |
|---|---|---|---|---|
| `personnel[].person_id` | string | HR system / IAM (Active Directory) | AD group membership query for BES access groups | **Stubbed** |
| `personnel[].name` | string | HR / AD | As above | **Stubbed** |
| `personnel[].role` | string | HR / AD | Job title or CIP role attribute | **Stubbed** |
| `personnel[].risk_assessment_completed` | bool | HR / GRC | Background check completion flag | **Stubbed** |
| `personnel[].risk_assessment_date` | ISO-8601 | HR system | Background check date | **Stubbed** |
| `personnel[].training_completed` | bool | LMS (e.g. Cornerstone, Workday Learning) | Course completion query | **Stubbed** |
| `personnel[].training_date` | ISO-8601 | LMS | Completion date | **Stubbed** |
| `personnel[].access_authorized` | bool | IAM / PAM system | Access authorization record | **Stubbed** |
| `personnel_role_changes[]` | list | HR system | Role change events in last 7 days | **Stubbed** |
| `cyber_security_training.program_documented` | bool | GRC / LMS | Training program document existence | **Stubbed** |
| `cyber_security_training.content.*` | bool ×6 | LMS | Training curriculum coverage check | **Stubbed** |
| `security_awareness.program_documented` | bool | GRC platform | Program document | **Stubbed** |
| `security_awareness.quarterly_reinforcement` | bool | LMS / email platform | Quarterly delivery records | **Stubbed** |
| `security_awareness.last_reinforcement_date` | ISO-8601 | LMS | Last delivery date | **Stubbed** |

**Ansible approach:**
- AD group membership: `community.windows.win_domain_group_membership` or LDAP query
- LMS completion: `community.general.uri` against LMS REST API (Cornerstone `/api/v1/learning/completion`, Workday `/v1/workers/{id}/learningActivity`)
- HR: `community.general.uri` against Workday or PeopleSoft REST API

---

## CIP-005 — Electronic Security Perimeters

| Input field | Type | Source system | Collection method | Status |
|---|---|---|---|---|
| `electronic_security_perimeters[system_id].defined` | bool | CMDB / network documentation | Network diagram existence check | **Stubbed** |
| `electronic_security_perimeters[system_id].documented` | bool | GRC / CMDB | As above | **Stubbed** |
| `electronic_security_perimeters[system_id].network_diagram_current` | bool | GRC / CMDB | Last-updated date on diagram | **Stubbed** |
| `electronic_access_points[].type` | string | CMDB / firewall inventory | CMDB query for EAP-category assets | **Stubbed** |
| `electronic_access_points[].deny_by_default` | bool | Firewall (Palo Alto, Cisco ASA, pfSense) | Firewall policy API — check default deny rule | **Stubbed** |
| `network_port_management[system_id].ports_reviewed` | bool | Vulnerability scanner / CMDB | Nmap scan results or Tenable API | **Live (CIP-010 playbook)** |
| `network_port_management[system_id].unauthorized_ports` | list | Vulnerability scanner | Compare scan results against authorized port list | **Live (CIP-010 playbook)** |
| `remote_access.multi_factor` | bool | IAM / VPN gateway | VPN MFA policy query (Cisco ISE, Palo Alto GP) | **Stubbed** |
| `remote_access.uses_intermediary_device` | bool | Network topology / CMDB | Jump host presence in path | **Stubbed** |
| `remote_access.intermediary_device.in_esp` | bool | CMDB | Jump host ESP membership | **Stubbed** |
| `remote_access.session_management.idle_timeout_minutes` | int | VPN / jump host config | Ansible fact collection from jump host | **Stubbed** |
| `remote_access_sessions[].mfa_used` | bool | VPN / IAM logs | SIEM query or VPN API | **Stubbed** |
| `remote_access_sessions[].recorded` | bool | PAM / session recording | CyberArk / BeyondTrust session log query | **Stubbed** |

**Ansible approach:**
- Firewall rules: `paloaltonetworks.panos` collection, Cisco `ios_command`, or REST API
- VPN MFA: Cisco ISE REST API or Palo Alto GP XML API
- Port scanning: `community.general.nmcli` or delegate to a scanning role

---

## CIP-006 — Physical Security of BES Cyber Systems

| Input field | Type | Source system | Collection method | Status |
|---|---|---|---|---|
| `physical_security_perimeters[system_id].defined` | bool | GRC / physical security documentation | Document existence | **Stubbed** |
| `physical_security_perimeters[system_id].six_wall_border` | bool | Physical security documentation | Site survey record | **Stubbed** |
| `physical_access_controls[].access_method` | string | Physical Access Control System (PACS) | PACS API (Lenel, Software House, Genetec) | **Stubbed** |
| `physical_access_controls[].alerting_configured` | bool | PACS / alarm system | PACS alert configuration query | **Stubbed** |
| `physical_access_alerting.enabled` | bool | PACS / alarm system | PACS API | **Stubbed** |
| `physical_access_alerting.unauthorized_attempt_alert` | bool | PACS | PACS alert rule existence | **Stubbed** |
| `physical_access_alerting.after_hours_alert` | bool | PACS | PACS alert rule existence | **Stubbed** |
| `physical_access_alerting.response_procedures_documented` | bool | GRC platform | Procedure document existence | **Stubbed** |
| `visitor_control_program.visitor_log_maintained` | bool | PACS / paper log | PACS visitor record existence | **Stubbed** |
| `visitor_control_program.escort_procedures` | bool | GRC / physical security procedures | Procedure document | **Stubbed** |
| `visitor_control_program.last_log_review_date` | ISO-8601 | GRC / PACS | Review date field | **Stubbed** |
| `physical_security_plan.documented` | bool | GRC platform | Plan document existence | **Stubbed** |
| `physical_security_plan.last_quarterly_review_date` | ISO-8601 | GRC platform | Review date (must be within 15 months) | **Stubbed** |
| `physical_locations` | list | CMDB / GIS | Site/location records | **Stubbed** |
| `protected_cyber_assets` | list | CMDB | PCAs associated with each BCS | **Stubbed** |

**Ansible approach:**
- PACS integration: `community.general.uri` against Genetec REST API or Lenel OnGuard API
- Most fields are attestation-based; ServiceNow GRC or a custom compliance DB survey task

---

## CIP-007 — Systems Security Management

| Input field | Type | Source system | Collection method | Status |
|---|---|---|---|---|
| `system_configurations[system_id].os_type` | string | CMDB / Ansible facts | `ansible_distribution` gathered from system | **Partial** |
| `system_configurations[system_id].enabled_services` | list | Ansible facts | `ansible_facts.services` (live collection) | **Partial** |
| `network_port_management[system_id].open_ports` | list | Vulnerability scanner / Ansible | `community.general.nmcli` or nmap scan | **Live (CIP-010)** |
| `network_port_management[system_id].authorized_ports` | list | CMDB / change management | Authorized port list from CMDB or JSON file | **Stubbed** |
| `patch_management[system_id].patches_applied` | list | Patch management (RHSM, WSUS, Satellite) | RHSM API, Windows Update API, or Satellite 6 API | **Stubbed** |
| `patch_management[system_id].last_patch_date` | ISO-8601 | Patch management | As above | **Stubbed** |
| `patch_management[system_id].compliance_percentage` | float | Patch management | As above | **Stubbed** |
| `patch_management.ics_cert_monitoring` | bool | ICS-CERT / CISA feed | CISA advisory RSS/API subscription confirmation | **Stubbed** |
| `patch_management.tracking_process_documented` | bool | GRC platform | Process document existence | **Stubbed** |
| `security_patches[].cve_id` | string | Vulnerability scanner (Tenable, Qualys) | Tenable.io REST API or Qualys VMDR | **Stubbed** |
| `security_patches[].severity` | enum | Vulnerability scanner | As above | **Stubbed** |
| `security_patches[].applied` | bool | Patch management | Cross-reference vuln scan with patch DB | **Stubbed** |
| `malicious_code_protection[system_id].av_installed` | bool | Endpoint management (CrowdStrike, SCCM, Satellite) | CrowdStrike Falcon API or SCCM query | **Stubbed** |
| `malicious_code_protection[system_id].signatures_current` | bool | Endpoint management | Last definition update date | **Stubbed** |
| `malicious_code_protection[system_id].real_time_scanning` | bool | Endpoint management | AV policy configuration | **Stubbed** |
| `malicious_code_protection.alternate_controls_when_av_not_available` | bool | GRC / CMDB | For air-gapped OT assets without AV support | **Stubbed** |
| `system_access_controls[system_id].shared_accounts` | list | IAM / AD | AD query for shared accounts on system | **Stubbed** |
| `system_access_controls[system_id].default_accounts_disabled` | bool | Ansible facts | Check `/etc/passwd` or Windows local users | **Partial** |
| `user_accounts[].account_id` | string | IAM / AD | AD user query scoped to BES systems | **Stubbed** |
| `user_accounts[].has_access_to_bes_systems` | bool | IAM / PAM | AD group or PAM vault entitlement | **Stubbed** |
| `password_policy.minimum_length` | int | AD Group Policy / system config | `community.windows.win_security_policy` or `ansible_facts` pam config | **Stubbed** |
| `password_policy.complexity_required` | bool | AD GPO / PAM | As above | **Stubbed** |
| `password_policy.account_lockout_configured` | bool | AD GPO | `community.windows.win_security_policy` | **Stubbed** |
| `security_monitoring[system_id].logging_enabled` | bool | SIEM / syslog config | Ansible verify rsyslog/auditd config | **Stubbed** |
| `security_monitoring[system_id].events_forwarded` | bool | SIEM | Verify syslog destination configured | **Stubbed** |
| `security_event_alerting.failed_login_alert` | bool | SIEM (Splunk, QRadar, Elastic) | SIEM alert rule existence query | **Stubbed** |
| `security_event_alerting.last_review_date` | ISO-8601 | SIEM | Alert review record | **Stubbed** |

**Ansible approach:**
- Patch status: `ansible.builtin.package_facts` + compare against RHSM/Satellite 6 errata API
- AV/EDR: `community.general.uri` against CrowdStrike Falcon API (`/devices/v2`)
- Password policy: `community.windows.win_security_policy` (Windows) or read `/etc/security/pwquality.conf` (Linux)
- SIEM alerts: `community.general.uri` against Splunk REST (`/services/saved/searches`) or QRadar (`/api/analytics/rules`)

---

## CIP-008 — Incident Response

| Input field | Type | Source system | Collection method | Status |
|---|---|---|---|---|
| `incident_response_plan.documented` | bool | GRC / document management | Plan document existence and version | **Stubbed** |
| `incident_response_plan.approved` | bool | GRC / DocuSign | Approval record | **Stubbed** |
| `incident_response_plan.last_review_date` | ISO-8601 | GRC platform | Review date field | **Stubbed** |
| `incident_response_plan.processes.*` | bool ×6 | GRC / plan content | Plan content audit (manual or NLP extraction) | **Stubbed** |
| `incident_response_plan.reporting.nerc_notification_process` | bool | GRC / IRP | Plan section existence | **Stubbed** |
| `incident_response_plan.reporting.e_isac_notification` | bool | GRC / IRP | Plan section — E-ISAC portal account confirmed | **Stubbed** |
| `incident_response_plan.roles_and_responsibilities.defined` | bool | GRC / IRP | Plan section existence | **Stubbed** |
| `incident_response_team[].person_id` | string | HR / GRC | IR team roster from GRC or HR | **Stubbed** |
| `incident_response_team[].trained` | bool | LMS | IR training completion | **Stubbed** |
| `incident_response_testing.last_test_date` | ISO-8601 | GRC / exercise records | Exercise completion record | **Stubbed** |
| `incident_response_testing.test_type` | enum `tabletop\|functional\|full` | GRC | Exercise record | **Stubbed** |
| `incident_response_testing.lessons_learned_captured` | bool | GRC | After-action report existence | **Stubbed** |
| `reportable_cyber_incidents[].incident_id` | string | SIEM / ITSM (ServiceNow) | Query incidents tagged "CIP-008-reportable" | **Live (CIP-008 playbook)** |
| `reportable_cyber_incidents[].reported_to_nerc` | bool | E-ISAC / email records | E-ISAC submission confirmation | **Live (CIP-008 playbook)** |
| `reportable_cyber_incidents[].reported_within_1_hour` | bool | ITSM | Incident creation timestamp vs report timestamp | **Live (CIP-008 playbook)** |
| `incident_identification.criteria_documented` | bool | GRC / IRP | Criteria definition in plan | **Stubbed** |

**Ansible approach:**
- `cip_008_incident_response.yml` playbook is **live** — collects from ServiceNow and posts forensic facts
- E-ISAC reporting confirmation: currently manual; automate via E-ISAC portal API when available

---

## CIP-009 — Recovery Plans

| Input field | Type | Source system | Collection method | Status |
|---|---|---|---|---|
| `recovery_plans[system_id].documented` | bool | GRC / document management | Recovery plan existence per system | **Stubbed** |
| `recovery_plans[system_id].approved` | bool | GRC | Approval record | **Stubbed** |
| `recovery_plans[system_id].last_review_date` | ISO-8601 | GRC | Review date | **Stubbed** |
| `recovery_plans.roles_and_responsibilities.defined` | bool | GRC | Plan section | **Stubbed** |
| `recovery_plans.activation_criteria_documented` | bool | GRC | Plan section | **Stubbed** |
| `recovery_plans.network_reconnection.security_verification` | bool | GRC / network procedures | Reconnection procedure existence | **Stubbed** |
| `recovery_plans.log_preservation.forensic_preservation_addressed` | bool | GRC / plan | Forensic section existence | **Stubbed** |
| `recovery_plans.incident_response_coordination.aligned` | bool | GRC | Cross-reference IRP ↔ recovery plan | **Stubbed** |
| `recovery_plans.last_activation_test_date` | ISO-8601 | GRC / exercise records | Last activation test | **Stubbed** |
| `backup_procedures[system_id].backup_exists` | bool | Backup system (Veeam, NetBackup, AWS Backup) | Backup job status API | **Stubbed** |
| `backup_procedures[system_id].last_backup_date` | ISO-8601 | Backup system | Last successful backup date | **Stubbed** |
| `backup_procedures[system_id].backup_tested` | bool | Backup system / GRC | Restore test record | **Stubbed** |
| `backup_procedures[system_id].offsite_storage` | bool | Backup system | Offsite replication status | **Stubbed** |
| `recovery_testing[system_id].last_test_date` | ISO-8601 | GRC / exercise records | Recovery test record | **Stubbed** |
| `recovery_testing[system_id].test_type` | enum | GRC | Tabletop vs functional test | **Stubbed** |
| `qualifying_recovery_events[]` | list | ITSM / SIEM | Events that triggered a real recovery | **Stubbed** |

**Ansible approach:**
- Backup status: `community.general.uri` against Veeam Enterprise Manager API or AWS Backup API
- NetBackup: `community.general.uri` or NBRB (NetBackup REST API)
- Recovery test records: ServiceNow query on change/test records tagged "CIP-009"

---

## CIP-010 — Configuration Management

| Input field | Type | Source system | Collection method | Status |
|---|---|---|---|---|
| `baseline_configurations[system_id].established` | bool | CMDB / CIP-010 baseline store | Check baseline capture record in PostgreSQL | **Live (Template 116)** |
| `baseline_configurations[system_id].captured_date` | ISO-8601 | PostgreSQL compliance DB | Query `baseline_captures` table | **Live (Template 116)** |
| `baseline_configurations[system_id].components` | object | Ansible facts + CIP-010 playbook | OS, firmware, open ports, installed software | **Live (Template 116)** |
| `configuration_changes[].change_id` | string | Change management (ServiceNow) | Query changes for BES-scoped systems | **Stubbed** |
| `configuration_changes[].authorized` | bool | Change management | Change approval status | **Stubbed** |
| `configuration_changes[].tested` | bool | Change management | Change test evidence flag | **Stubbed** |
| `configuration_changes[].baseline_updated` | bool | CMDB / compliance DB | Baseline update record after change | **Stubbed** |
| `configuration_monitoring[system_id].active_monitoring` | bool | FIM / SIEM | Tripwire, AIDE, or auditd active | **Stubbed** |
| `configuration_monitoring[system_id].alerts_configured` | bool | FIM / SIEM | Alert rule for unauthorized change | **Stubbed** |
| `configuration_monitoring[system_id].last_review_date` | ISO-8601 | FIM / GRC | Last review of monitoring alerts | **Stubbed** |
| `configuration_change_management.process_documented` | bool | GRC platform | Process document existence | **Stubbed** |
| `configuration_change_management.approval_process_defined` | bool | GRC platform | Approval workflow existence | **Stubbed** |
| `configuration_change_management.rollback_procedures_defined` | bool | GRC platform | Rollback procedure existence | **Stubbed** |
| `software_integrity.hash_verification` | bool | Software distribution / CMDB | Hash verification process existence | **Stubbed** |
| `software_integrity.verification_process_documented` | bool | GRC platform | Process document | **Stubbed** |
| `transient_cyber_assets.config_management.inventory_maintained` | bool | CMDB | TCA asset records | **Stubbed** |
| `vulnerability_assessments[system_id].completed` | bool | Vulnerability scanner (Tenable, Qualys) | Scan completion record | **Stubbed** |
| `vulnerability_assessments[system_id].last_assessment_date` | ISO-8601 | Vulnerability scanner | Last scan date | **Stubbed** |
| `vulnerability_assessments[system_id].findings` | list | Vulnerability scanner | Open findings from Tenable.io or Qualys API | **Stubbed** |
| `vulnerability_monitoring.ics_cert_monitoring` | bool | GRC / subscription records | CISA ICS-CERT subscription confirmation | **Stubbed** |
| `vulnerability_monitoring.vendor_advisories_monitored` | bool | GRC | Vendor advisory subscription records | **Stubbed** |

**Ansible approach:**
- `cip_010_baseline_capture.yml` + Template 116 is **live** — captures OS, ports, packages into PostgreSQL
- Change records: `servicenow.itsm.change_request_info` module
- Vulnerability scanner: `community.general.uri` against Tenable.io (`/workbenches/assets/vulnerabilities`) or Qualys VMDR

---

## CIP-011 — Information Protection

| Input field | Type | Source system | Collection method | Status |
|---|---|---|---|---|
| `bes_cyber_system_information.classification_performed` | bool | GRC / DLP | Data classification program existence | **Stubbed** |
| `bes_cyber_system_information.inventory_maintained` | bool | GRC / document management | BCSI inventory existence | **Stubbed** |
| `bes_cyber_system_information.categories.*` | bool ×6 | GRC | BCSI category inventory completeness | **Stubbed** |
| `information_protection.procedures_documented` | bool | GRC | Protection procedure existence | **Stubbed** |
| `information_protection.access_controls_enforced` | bool | IAM / DLP (Symantec DLP, Microsoft Purview) | Access control verification | **Stubbed** |
| `information_protection.transmission_controls_implemented` | bool | DLP / network controls | Transmission policy enforcement | **Stubbed** |
| `bcsi_storage.encryption_at_rest` | bool | Storage / cloud platform | KMS/LUKS encryption status | **Stubbed** |
| `bcsi_storage.electronic.logging_enabled` | bool | SIEM / storage audit | Storage access logging | **Stubbed** |
| `bcsi_storage.physical.access_controlled` | bool | PACS | Physical storage access controls | **Stubbed** |
| `bcsi_access_list[].authorized` | bool | IAM | Access entitlement records | **Stubbed** |
| `bcsi_transmissions[].encrypted` | bool | Network / DLP | TLS enforcement on BCSI paths | **Stubbed** |
| `bcsi_third_party_sharing[].agreement_in_place` | bool | Contract management / GRC | NDA/DUA existence | **Stubbed** |
| `information_access[].is_bcsi` | bool | DLP / data classification | DLP classification tag | **Stubbed** |
| `information_disposal.media_sanitization` | bool | GRC / asset disposal records | Media disposal procedure and records | **Stubbed** |
| `media_disposals[].sanitization_verified` | bool | GRC / asset disposal | Destruction certificate existence | **Stubbed** |
| `system_redeployments[].data_cleared` | bool | GRC / CMDB | Redeployment checklist | **Stubbed** |
| `information_disposal.secure_deletion_methods` | bool | GRC platform | Deletion method documentation | **Stubbed** |

**Ansible approach:**
- Encryption at rest: `amazon.aws.s3_bucket_info`, `azure.azcollection.azure_rm_storageaccount_info`, or check LUKS on Linux
- DLP: Microsoft Purview REST API or Symantec DLP Enforce API
- Access logs: `community.general.uri` against SIEM API (Splunk `/services/search/jobs`)

---

## CIP-012 — Communications Protection Between Control Centers

| Input field | Type | Source system | Collection method | Status |
|---|---|---|---|---|
| `control_center_communications.inventory_maintained` | bool | CMDB / network documentation | Communication link inventory existence | **Stubbed** |
| `control_center_communications.criticality_assessed` | bool | GRC | Criticality assessment completion | **Stubbed** |
| `control_center_communications.links[].encrypted` | bool | Network device / VPN | Firewall/VPN tunnel status (Cisco, Palo Alto) | **Stubbed** |
| `control_center_communications.links[].authenticated` | bool | Network device | Authentication configuration on link | **Stubbed** |
| `control_center_communications.links[].availability_measures` | bool | Network / NOC | Redundancy and monitoring | **Stubbed** |
| `control_center_communications.last_test_date` | ISO-8601 | GRC / NOC records | Communication test record | **Stubbed** |
| `communication_monitoring.enabled` | bool | SIEM / NOC monitoring | Monitoring tool active status | **Stubbed** |
| `communication_monitoring.anomaly_detection` | bool | SIEM / IDS | Anomaly detection rule existence | **Stubbed** |
| `communication_monitoring.logging_implemented` | bool | SIEM | Log source confirmation | **Stubbed** |
| `communication_contingency.backup_links_exist` | bool | Network inventory | Backup circuit inventory | **Stubbed** |
| `communication_contingency.testing_performed` | bool | GRC / NOC | Failover test record | **Stubbed** |
| `communication_contingency.plans_documented` | bool | GRC | Contingency plan existence | **Stubbed** |

**Ansible approach:**
- VPN/link status: `cisco.ios.ios_command` (`show crypto ipsec sa`) or `paloaltonetworks.panos.panos_tunnel`
- Link encryption: query Palo Alto GP or Cisco ISE via REST
- Test records: ServiceNow query

---

## CIP-013 — Supply Chain Risk Management

| Input field | Type | Source system | Collection method | Status |
|---|---|---|---|---|
| `supply_chain_plan.documented` | bool | GRC platform | SCRM plan existence | **Stubbed** |
| `supply_chain_plan.approved` | bool | GRC / DocuSign | Approval record | **Stubbed** |
| `supply_chain_plan.cip_senior_manager_approved` | bool | GRC | CIP-SM approval record | **Stubbed** |
| `supply_chain_plan.last_review_date` | ISO-8601 | GRC | Review date | **Stubbed** |
| `supply_chain_plan.processes.*` | bool ×10 | GRC | Plan process coverage audit | **Stubbed** |
| `vendors[].vendor_id` | string | Procurement / CMDB | Vendor registry query | **Stubbed** |
| `vendors[].name` | string | Procurement system | As above | **Stubbed** |
| `vendors[].provides_bes_products` | bool | CMDB / procurement | Product-to-BES mapping | **Stubbed** |
| `vendor_contracts[vendor_id].cip_language_included` | bool | Contract management | Contract content check (CLM system) | **Stubbed** |
| `vendor_contracts[vendor_id].security_requirements_defined` | bool | Contract management | Contract security annex existence | **Stubbed** |
| `vendor_risk_assessments[vendor_id].completed` | bool | GRC / third-party risk | TPRM assessment completion | **Stubbed** |
| `vendor_risk_assessments[vendor_id].last_assessment_date` | ISO-8601 | GRC / TPRM | Assessment date | **Stubbed** |
| `supply_chain_monitoring.ics_cert_advisory_monitoring` | bool | GRC / subscription | CISA advisory subscription | **Stubbed** |
| `supply_chain_monitoring.vendor_bulletin_monitoring` | bool | GRC | Vendor bulletin tracking | **Stubbed** |
| `supply_chain_monitoring.threat_intelligence` | bool | TI platform (ISAC, Recorded Future) | TI feed subscription | **Stubbed** |
| `supply_chain_incident_response.vendor_contacts_current` | bool | GRC / contact directory | Vendor IR contact currency check | **Stubbed** |
| `supply_chain_incident_response.information_sharing_agreements` | bool | GRC / legal | ISA existence | **Stubbed** |

**Ansible approach:**
- Vendor registry: `community.general.uri` against procurement system (SAP Ariba, Coupa) REST API
- Contract management: Ironclad or Icertis REST API to check contract metadata
- TPRM: `community.general.uri` against BitSight or SecurityScorecard API for vendor ratings

---

## CIP-014 — Physical Security of Transmission Stations

| Input field | Type | Source system | Collection method | Status |
|---|---|---|---|---|
| `applicable_transmission_stations[].station_id` | string | GIS / CMDB | Transmission substation registry | **Stubbed** |
| `applicable_transmission_stations[].voltage_kv` | int | GIS / EMS | Station voltage rating | **Stubbed** |
| `transmission_risk_assessment.performed` | bool | GRC | Risk assessment completion | **Stubbed** |
| `transmission_risk_assessment.methodology.power_flow_analysis` | bool | EMS / power systems tools | Power flow analysis record | **Stubbed** |
| `transmission_risk_assessment.methodology.cascading_potential_assessed` | bool | EMS | Contingency analysis record | **Stubbed** |
| `transmission_risk_assessment.third_party_verification.performed` | bool | GRC | Third-party verifier engagement record | **Stubbed** |
| `transmission_risk_assessment.third_party_verification.unaffiliated` | bool | GRC / procurement | Verifier independence certification | **Stubbed** |
| `transmission_risk_assessment.third_party_verification.timely` | bool | GRC | Verification date within 90 days of assessment | **Stubbed** |
| `transmission_risk_assessment.third_party_verification.rc_notified` | bool | GRC / correspondence | Reliability Coordinator notification record | **Stubbed** |
| `station_security_plans[station_id].documented` | bool | GRC | Station physical security plan existence | **Stubbed** |
| `station_security_plans[station_id].law_enforcement_coordination` | bool | GRC / correspondence | Law enforcement coordination record | **Stubbed** |
| `transmission_topology_changes[]` | list | Change management / EMS | Network topology change events | **Stubbed** |

**Ansible approach:**
- EMS integration: ICCP/TASE.2 protocol bridge (complex OT integration — likely manual attestation initially)
- GIS: ESRI ArcGIS REST API or custom GIS query
- Law enforcement coordination: Manual attestation via ServiceNow GRC

---

## CIP-015 — Internal Network Security Monitoring (INSM)

| Input field | Type | Source system | Collection method | Status |
|---|---|---|---|---|
| `insm.systems[].system_id` | string | CMDB | High/medium impact BES systems with ERC | **Stubbed** |
| `insm.systems[].impact_categorization` | enum `high\|medium` | CMDB | CIP-002 impact level | **Stubbed** |
| `insm.systems[].has_external_routable_connectivity` | bool | Network inventory | Connectivity determination | **Stubbed** |
| `insm.systems[].network_baseline.established` | bool | INSM tool (Claroty, Dragos, Nozomi) | Baseline establishment confirmation | **Stubbed** |
| `insm.systems[].network_baseline.documented` | bool | GRC / INSM platform | Baseline document existence | **Stubbed** |
| `insm.systems[].anomaly_detection.implemented` | bool | INSM platform | Tool deployment status | **Stubbed** |
| `insm.systems[].anomaly_detection.covers_esp` | bool | INSM platform | Sensor placement coverage | **Stubbed** |
| `insm.systems[].malicious_comm_detection.capability_documented` | bool | GRC / INSM | Detection capability documentation | **Stubbed** |
| `insm.systems[].malicious_comm_detection.tools` | list | CMDB / INSM | Deployed tool inventory (Claroty, Dragos, Darktrace) | **Stubbed** |
| `insm.systems[].response_process.documented` | bool | GRC | Response procedure existence | **Stubbed** |
| `insm.systems[].response_process.includes_notification` | bool | GRC / IRP | Notification section in procedure | **Stubbed** |
| `insm.categorization_review_date` | ISO-8601 | GRC | Last CIP-015 categorization review | **Stubbed** |
| `insm.documentation_review.documented` | bool | GRC | Documentation review record | **Stubbed** |
| `insm.documentation_review.last_review_date` | ISO-8601 | GRC | Review date (must be within 15 months) | **Stubbed** |

**Ansible approach:**
- Claroty: `community.general.uri` against Claroty Platform REST API (`/api/v3/assets`, `/api/v3/alerts`)
- Dragos: `community.general.uri` against Dragos Platform API
- Nozomi Networks: `community.general.uri` against Guardian REST API (`/api/open/query/do?query=assets`)
- Darktrace: `community.general.uri` against Darktrace API (`/models`, `/alerts`)

---

## Summary by Source System

| Source system | CIP standards | Integration effort | Notes |
|---|---|---|---|
| **GRC platform** (ServiceNow GRC, Archer, Diligent) | All 14 | Medium | Most attestation fields; REST API available on all major platforms |
| **CMDB** (ServiceNow CMDB, Device42) | CIP-002, 005, 006, 007, 010, 013, 014, 015 | Medium | BES asset inventory is foundation for all CIP |
| **HR system** (Workday, PeopleSoft, SAP HCM) | CIP-004 | Medium | Personnel records, role changes, risk assessments |
| **LMS** (Cornerstone, Workday Learning, KnowBe4) | CIP-004 | Low–Medium | Training completion dates |
| **IAM / Active Directory** | CIP-004, 005, 007, 011 | Low | LDAP/AD queries; community.microsoft.ad collection |
| **Firewall / Network devices** (Cisco, Palo Alto) | CIP-005, 007, 012 | High | OT network equipment may lack REST APIs |
| **PACS** (Genetec, Lenel, Software House) | CIP-006 | Medium | Visitor logs, access records |
| **Patch management** (Satellite 6, WSUS, RHSM) | CIP-007, 010 | Low | ansible.builtin.package_facts + API |
| **Vulnerability scanner** (Tenable, Qualys) | CIP-007, 010 | Low | REST APIs well-documented |
| **SIEM** (Splunk, QRadar, Elastic) | CIP-007, 008, 011, 012 | Medium | Alert rule and log source queries |
| **INSM platform** (Claroty, Dragos, Nozomi, Darktrace) | CIP-015 | High | OT-specific APIs; may require on-prem connectivity |
| **Backup system** (Veeam, NetBackup, AWS Backup) | CIP-009 | Low | REST APIs available |
| **Change management** (ServiceNow ITSM) | CIP-008, 010, 013 | Low | servicenow.itsm Ansible collection |
| **EMS / SCADA** (OSIsoft PI, GE EMS) | CIP-014 | Very High | ICCP/TASE.2, OPC-UA; typically manual attestation initially |
| **Contract/CLM** (Ironclad, Icertis, SAP Ariba) | CIP-013 | Medium | REST APIs; vendor contract metadata |

---

## Recommended Implementation Sequence

1. **CMDB** — BES asset inventory drives every other CIP standard. Nothing else works without it.
2. **GRC platform** — Bulk of attestation fields; single integration covers CIP-002 through CIP-015 documentation checks.
3. **Patch + vulnerability scanner** — CIP-007/010; low effort, high audit value.
4. **IAM / Active Directory** — CIP-004 personnel and access; well-supported Ansible modules.
5. **SIEM** — CIP-007 alerting, CIP-008 incident detection; Splunk/QRadar have mature REST APIs.
6. **INSM platform** — CIP-015 is newest (effective 2026) and enforcement is ramping up; highest regulatory exposure.
7. **EMS / SCADA** — CIP-014 power flow analysis; complex OT integration, start with manual attestation and automate incrementally.

---

*Last updated: 2026-05-21*
*Policies: CIP-002 through CIP-015 (nerc_cip v1.0, opa-ot :8183)*
