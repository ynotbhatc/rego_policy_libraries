# Changelog

All notable changes to this library will be documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [Unreleased]

### Fixed — bad evidence never passes: every yes/no fact passes only as boolean `true` (audit 2026-11-24)
Breaking for collectors across most of the library. Before this release a fact sent as the string `"false"`, `"no"` or `"true"`, as null, as 0 or 1, or left out could clear a finding, and the report said compliant. Now a yes/no fact passes only as the JSON boolean `true`; a missing, null or wrong-typed fact fails the control and the finding names the problem (`evidence missing: <path> not collected`, `evidence invalid: <path> is not a boolean (got string)`). A number sent as a string no longer passes where a number is required, and a missing number no longer defaults to a passing value. A fact that switches an obligation off must be stated (`false`), never inferred from a missing field. The bad-input harness (`make check-bad-input`) now feeds every entrypoint empty input, string and null versions of every input path its sources read, and mutated copies of its all-pass fixtures: on the previous main it reported 3,101 failures; it reports 0 known failures now, and 361 accepted cases (291 lines in `scripts/bad_input_accepted.txt`), each with a written reason citing the standard, the rule id or the collector contract (`scripts/bad_input_accepted.txt`). The unit-test count rose from 43,926 to 46,565; every test finishes inside the 30-second cap on OPA 1.10.0 as well as 1.22.4 (the long sweeps run in slices, each file with a test that the slices cover the whole set). A valid all-true input still passes as before. Control ids, citations and declared totals are unchanged except where listed under Changed.

### Changed — breaking: facts a collector must send, or send with a different type (2026-11-24)
Check each list against your collector before moving the pin. "Number" means a JSON number, "boolean" a JSON boolean.

**All families**
- [ ] Booleans as JSON booleans and numbers as JSON numbers. An Ansible template that renders `"true"` or `"8"` (no `| bool`, `| int`) now fails every check that reads it, with an evidence finding.
- [ ] A section sent as null or as a non-object counts as not collected. Finding strings for missing or wrong-type evidence carry a suffix after the old text, so an exact-match on a finding string holds only for boolean `false`.

**SOX** (`sox.main`, `sox.itgc`, `sox.application_controls`)
- [ ] Post the SOX facts as `input.sox.<area>.<control>.<field>`, the shape `sox.simplified` and the input schema already used. The three modules used to read `data.sox` only. When the input has no `sox` key, `data.sox` is still read and the report says `evidence_source: "data"`; the two are never merged. As soon as the input carries a `sox` key (even `null`), `data.sox` is not read and `data_sox_ignored: true` says so, so a partial `input.sox` fails the missing checks as missing evidence. The fallback will be removed in a later release.

**CCPA, EU CRA, NYDFS, SWIFT**
- [ ] `ccpa.main.compliance_report.violations` holds one row per failing module (7 in all); the per-row detail moved to `findings`. A missing `revenue_tier` is a finding when the Article applies.
- [ ] CCPA, state `true` or `false`: `business_obligations.data_broker.applicable`, `risk_assessments.admt_provider.provides_admt_to_recipient_businesses`, `risk_assessments.timing.legacy_processing_continuing`, `cybersecurity_audits.auditor.internal`, `admt.access.aggregate_responses_used` (when ADMT is used).
- [ ] CRA `incident_reporting`: `actively_exploited_vuln_known`, `severe_incident_occurred`, `users_impacted`, and `corrective_measure_available` when a vulnerability is known; the clocks (`hours_since_aware_of_vuln`, `hours_since_aware_of_incident`, `days_since_*`) must be numbers whenever their flag is true.
- [ ] CRA `distributor`, `importer`, `substantial_modification`, `conformity_assessment`, `declaration_of_conformity`, `technical_documentation`, `authorised_representative`, `online_marketplace`, `oss_steward`, `cryptography.signing.in_use`, `foss.*`: every applicability and risk-awareness flag is a stated boolean (for example `product_is_imported`, `non_conformity_suspected`, `significant_risk_known`, `modification_classified_substantial`, `product_placed_on_market`, `authority_takedown_order_received`, `involved_in_development`); `corrective_action.severity`, `product_class`, `procedure_used` and `product.classification` are text when they apply. The per-package lists are in `schemas/input/cra_*`.
- [ ] NYDFS 500 and SWIFT CSP: no new fact; only the boolean type is enforced.


**Frameworks: privacy, federal, management, critical infrastructure**
- [ ] HIPAA: `access_control.users` (non-empty list) and `users[].shared_account` (boolean) on every account; `transmission_security.email.phi_sent_via_email` (boolean); `privileged_accounts` as `[]` when none and `vpn.split_tunneling_enabled` stated (advisory raised when not collected). A specification that the facts decide takes no attestation: an attestation sent as `false` while the facts pass is a new "evidence contradictory" finding in `security_rule`, `hitech` and `privacy_rule`.
- [ ] GLBA: `entity_type` (non-empty string; it used to default to "unknown"). FERPA, COPPA, ITAR, COBIT, NIST SSDF: booleans only.
- [ ] EU AI Act high-risk: the four applicability booleans, true or false (absent used to mean "does not apply").
- [ ] ISO 27001: `test_data.production_data_used` (boolean; A.8.33 fails without it); list facts as arrays (`user_management.unauthorized_users`, `privileged_access.shared_accounts`, `cryptography.policy.approved_algorithms`, `cryptography.algorithms_in_use`; `key_management.key_specifications` an array or object). ISO 42001: `organization_role` (non-empty string). The ISO 27001 test `test_data_controls_adequate` is renamed `production_test_data_controls_adequate`.
- [ ] FedRAMP: `data_residency.us_only_required` (every level) and `personnel_requirements.us_persons_required_for_admin` (Moderate, High, unknown level) as stated booleans; absent or null is evidence missing and the check applies, so `total_controls` on bare input rises from 10/11/12 to 11/13/13. Non-empty `data_residency.storage_locations` and `processing_locations` when SA-9(5) applies; non-empty `personnel` and `cryptography.algorithms_in_use`; KEV `due_date` and `assessment_date` as `YYYY-MM-DD`; `ato_expiry_days` a number when sent.
- [ ] SEC cyber disclosure and NIST SP 800-82: booleans for every fact (a frequency word in `governance.board.informed_of_risks_frequency` now fails).
- [ ] HITRUST (63 checks) and the 16 CSA CCM domains (549 checks): booleans only. No field added or renamed.
- [ ] AMI device: `security.tamper_status` is a string in the vocabulary `ok` or `tamper_detected` (case-insensitive, trimmed); anything else is an evidence finding.
- [ ] NIST SP 800-53 (Release 5.2.0): `sa_controls.development_process.logging_syntax.{format_defined, event_types_defined, detail_level_defined, developer_required}` (booleans) and `.components_not_conforming` (whole number, 0 passes); `si_controls.flaw_remediation.root_cause_analysis.{conducted, actions_developed, effectiveness_monitored}` (booleans) and `.issues_without_analysis`, `.actions_not_implemented` (whole numbers, 0 passes). Until sent, SA-15(13) and SI-2(7) report evidence missing, so an input that passed all 542 controls now passes 542 of 544 and is not compliant.
- [ ] CMMC: no new fact. `cmmc.main.compliance_report.violations` holds one row per failed practice (`violation_count == failed_controls + input_contract_violations`); the per-user and per-system rows moved to `findings`.
- [ ] IEC 62443, stated true or false per system: `wireless_access`, `remote_access_enabled`, `default_credentials_unchanged`, `error_messages_expose_sensitive_data`, `uses_deprecated_ciphers`, `malware_protection`; at SL 2 and above `application_whitelisting`, `sensitive_data_transmitted`, `uses_shared_platform`. Per zone `general_purpose_comms_unrestricted` and a numeric `security_level`; `network.direct_internet_connectivity_to_ics`; `conduits` a non-empty array.
- [ ] TSA pipeline: the applicability booleans; `hours_to_report` on every reported incident (a reported incident with none is an II.C.3 finding, not "0 hours"); `supplemental_hours_after_available` when the first report was incomplete; `days_since_information_change` (0 when nothing changed); `months_since_last_review`, `months_since_plan_approval`, `months_since_previous_approval`, `months_since_last_exercise`, `objectives_tested`, `packet_capture_max_hours`; `duration_days` on every pending change.
- [ ] Digital sovereignty, CMMC audit, FISMA, NERC CIP, corporate, FinOps, CI/CD, SLSA, Terraform plan, Dockerfile: fields that a row read through a negation and so dropped when absent now count against the row. Send, among others: `cloud_providers[].hq_country` and `.data_processed_pct` (number), `concentration_limits.max_single_provider_pct` (number), `hardware_components[].manufacturer_country`, `personnel[].location_country`, `encrypted_resources[].algorithm`; CMMC `audit.privileged_command_rules`, `audit.ntp_servers`, `audit.audit_admins` (lists), `scp.tls_min_version`; NERC CIP `bes_cyber_systems[].impact_level`, `recovery_plans.<system_id>`; `users[].roles`, `roles[].name`; FinOps `resources[].name`, `current_spend`; SLSA `sbom.format`, `provenance.predicate_type`; Terraform `from_port` and `to_port` as numbers; the Dockerfile `FROM` value. The per-package input schemas under `schemas/input/` list every path.


**Benchmarks: Linux and databases**
- [ ] CIS RHEL 9, RHEL 8, Rocky 9, Rocky 8, SUSE 16, Ubuntu 22.04, 24.04 and 26.04, Debian 12 and 13, Amazon Linux 2023: send `input.profile` (one of the four profile names, or `level1` / `level2`). There is no default any more. An absent, null, non-string or unknown profile evaluates every recommendation, reports `"profile": "unrecognised"` and one `PROFILE NOT SELECTED` violation, and is never compliant; `compliance_percentage` (and `score`) is then null with `compliance_percentage_reason` (the 99.999 cap of an earlier pass is gone). At Level 1 `auditd` is not needed; at Level 2 and with no profile it is evidence missing. Public `aac` sends the profile for RHEL 9; the private compliance mapper (read 2026-10-22) sends none.
- [ ] Same trees, numbers: `chronyd.servers_configured`, `chronyd.pools_configured` (whole, 0 or more), `initial_setup.gdm_idle_delay`, `gdm_lock_delay`, `pam.pass_max_days`, `pass_warn_age`, `inactive_days`, `tmout`, and `user_group.shadow_entries[].max_days`, `warn_days`, `inactive`, `last_change` are whole JSON numbers (decimal strings and fractions fail). `shadow_entries[].has_password` is a boolean on every row; `world_writable.truncated`, `unowned_files.truncated`, `ungrouped_files.truncated` are absent or boolean; `sudo.logfile_exists`, `ssh.banner_contains_sensitive_info`, `mta.has_mta` are absent, null or boolean; `mta.inet_interfaces` a string; `services.<unit>.state` a non-empty string for units that must be off; `authorized_keys.files[].mode`, `ssh_dirs[].mode`, `keys[].fingerprint` (RHEL 9) are required. A section key sent as null is not collected.
- [ ] CIS Ubuntu 20.04 and Debian 11: 59 yes/no facts per tree as booleans, and the facts a host used to answer by omission must be stated: `initial_setup.gdm_installed`, `autofs.installed`, `ipv6.disabled`, `require_remote_logging`, `require_ipv6_disabled`, `cron.cron_deny_exists`, `cron.at_deny_exists`, `sudo.sudoers_world_readable`, `initial_setup.motd_contains_sensitive_info` (and the `issue` copies), `process_hardening.core_dumps_enabled`, `prelink_installed`, `webserver.any_installed`, `client_packages.any_installed`, `x11.any_installed`, `wireless_interfaces.has_wireless`, `time_synchronization.active_service`, and the lists `unnecessary_services.analysis` and `.non_compliant`, `pam.users_with_future_password_change`, `pam.system_accounts_with_login_shell`, `sudo.nopasswd_entries`, `sudo.noauthenticate_entries` (empty is an answer). The local compliance mapper does not send several of these.
- [ ] DISA STIG RHEL 9, RHEL 10, Oracle Linux 9 and 8, RHEL 8 (the "Fix the STIG" ruling): numeric facts are JSON numbers only; a decimal string is an evidence-invalid finding (round 2 had accepted decimal strings; that is withdrawn). Affected: `auditd_config.freq`, `crypto_policy_state.min_rsa_size`, `faillock_conf.{deny, fail_interval, unlock_time}`, `login_defs.FAIL_DELAY`, `password_policy.{dcredit, dictcheck, difok, inactive_days, lcredit, maxclassrepeat, maxdays, maxrepeat, minclass, mindays, minlen, ocredit, retry, ucredit}`, `ssh_config.ClientAliveCountMax` and `ClientAliveInterval` (RHEL 9, OL9), `kernel_info.uek_release` (OL8), `pwquality_values.<opt>[]` (OL8), `interactive_users[].home_gid` and `primary_gid`, `file_permissions.*[].gid`, `chrony_conf.sources[].maxpoll`, `profile_tmout[].value`, `limits_maxlogins[].value`. The public `aac` collector sends `auditd_config.freq` and the two `ssh_config` values as text today; convert them before moving the pin. `disk_encryption.filesystems[].mount` is required on every entry (RHEL 9). RHEL 10 and OL8 sshd `ClientAliveInterval` and `ClientAliveCountMax` are read from digits-only text. Text facts compared by equality stay text (the list is in `benchmarks/stig/LINUX_COLLECTOR_CONTRACT.md`).
- [ ] STIG Oracle Database 19c and Oracle MySQL 8: profile limits (`SESSIONS_PER_USER`, `FAILED_LOGIN_ATTEMPTS`, `max_idle_time`) and MySQL `max_user_connections`, `validate_password.length`, `audit_log_rotate_on_size` are whole numbers; the day limits accept a number. The row-list facts (`unauthorized_object_owners` and 13 more, MySQL `unauthorized_audit_admins`, `sample_schemas_present`, `unused_plugins_installed`, `unauthorized_ddl_grantees` and the like) are arrays, `control_files`, `redo_log_groups[].members`, `unified_audit_policies_enabled` arrays of non-empty strings, `parameters.audit_trail` a string, `instance_name` a non-empty string, `version` a string starting with digits, `users_with_10g_password_verifier` an empty array when clean. MySQL `audit.filters` an array of non-empty strings and `users` an array of rows.
- [ ] CIS MySQL: every `mysql.users[]` row needs `host`, `user`, `privileges` (an object with the eight `*_priv` / `all_privileges` flags as text), `sql_mode`, `password_strength`, `password`, `roles` (array), `user_type`, `default_roles` (array) and the key `password_lifetime` (null allowed); also `database_privileges.mysql_db[].user`, `database_grants[].db`, `databases[].name`, `user_profiles[].content`, `replication.users[].privileges.{super, file, process}_priv`.
- [ ] CIS PostgreSQL 16, 17, 18: `security_definer_functions[].prosecdef` a boolean on every row (`"t"` and `"f"` are rejected), `security_definer_functions[]` rows carry string `schema` and `name`, `roles[].name` a string, `roles[].connection_limit` a number except on `pg_` roles, `authentication.pg_hba_entries[].connection_type` a string (17), `ssl.ssl_tls13_ciphers` a string (18). A non-array list fact is a failed control in the counts. PostgreSQL 13 to 15: `name` on extension rows.
- [ ] CIS SQL Server 2022 and 2025: `sql.configurations[<name>].value_configured` and `.value_in_use`, and `sql.asymmetric_keys[].key_length`, are numbers (a null used to read as "disabled" and `true` as "enabled").
- [ ] CIS Oracle Database 23ai and 26ai: `authorized_grantees` as a list (without it every grant to a non-Oracle-maintained grantee is a finding) and `grantee` on every grant row. Oracle 19c: `status` on default accounts. Legacy Oracle: `network_encryption.crypto_checksumming` when encryption is on; `account_name` and `profile_name` on rows.


**Benchmarks: Windows**
- [ ] CIS Windows 10, 11 and Server 2016 to 2025 (and the 2019 and 2022 key bridges), CIS Intune Defender Antivirus: send each registry value in its own type. A REG_DWORD or REG_QWORD is a JSON number; a REG_SZ or REG_EXPAND_SZ is a string, including one that holds a number; a REG_MULTI_SZ is a list of strings; numeric `secedit.system_access.<key>` and `audit_policy[<guid>]` are numbers; `secedit.privilege_rights.<right>` is a list of SID strings (omit a right nobody holds); Intune CSP integers are numbers. `Winlogon\CachedLogonsCount` is a string; `CloudContent\DisableSpotlightCollectionOnDesktop` and Windows 10 `PreviewBuilds\AllowBuildPreview` are numbers.
- [ ] Same trees, selectors: state `cis_profile.level`, `cis_profile.bitlocker` (Windows 10 and 11) and `cis_profile.next_generation` (every version except Windows 11) as booleans or the level as a number. A selector that is absent or not a boolean puts its tier's recommendations in scope as not assessed (round 2 treated an absent selector as opt-out; that is withdrawn); the profile block lists `<selector>_defaulted` and `selectors_not_stated`.
- [ ] DISA STIG Windows 11 and Server 2016, 2019, 2022, 2025: `LegalNoticeText` must equal the DoD Notice and Consent Banner printed in the check (any white-space layout); `LegalNoticeCaption` (2016, 2019) is one of the two titles the check names, or `attest.<id>_organization_defined_title: true`; `input.device_guard` (the Win32_DeviceGuard properties) feeds the VBS, Credential Guard and HVCI rules; `attest.<id>_transcript_directory_acl` for the PowerShell transcript rule; REG_SZ numbers as digit strings. A missing registry value is a finding unless the rule's own check text says a missing value is not a finding (the ids are in `benchmarks/stig/*/tests/`); a null is always a finding; a missing `registry` section opens every registry rule.

**Benchmarks: network, SaaS, mobile**
- [ ] CIS Palo Alto Firewall 11, `input.panos_config`: password-complexity and expiry numbers, `idle_timeout`, lockout, zone-protection flood and scan rates, `alert_threshold` are numbers (numeric strings were accepted); yes/no facts are `"yes"` or `"no"` in any case, or booleans; rulebase `from`, `to`, `source`, `destination`, `application`, `service` and the url-filtering action lists are arrays; `rulebase.security[].action` and `licenses[].feature` strings; `licenses[]` entries need `feature` and `expired`; `url_filtering[].log_container_page_only` must be sent as `"no"` (the PAN-OS default is yes).
- [ ] CIS VMware ESXi 8 and 9, `input.esxi`: the listed `advanced_settings` timeouts and lockout numbers, `sshd_config.clientalivecountmax` and `clientaliveinterval` are numbers; `firewall.rulesets[].enabled` and `allowed_ip_all` are booleans on every ruleset; port-group security flags booleans; `kernel_settings.disableHwrng` TRUE or FALSE.
- [ ] `cis_profile.level` is the number 1 or 2 (or absent) in Palo Alto, ESXi, iOS, Cisco IOS XE 17, Docker, AWS and Azure; any other value (including `"1"`, `"level1"`) is an evidence finding, the report is scoped at Level 2 and every Level 2 recommendation fails. iOS: `cis_profile.ownership` is `end_user` or `institutional` (or absent). CIS Docker and Azure with no level: `PROFILE NOT SELECTED`, never compliant.
- [ ] SCuBA M365: the 49 yes/no facts under `input.scuba.{exo, powerbi, powerplatform, sharepoint, teams}` must be boolean `true` (the string `"false"` used to clear 49 policies). CIS M365 v7: `entra.device_registration.user_device_quota` a number; `exchange.mailbox_audit.sampled` and `sample_limit` required numbers; `implementation_status` on Secure Score rows. CIS OPNsense: `input.filter` an object; pfSense and OPNsense `system.dnsserver` and `hasync.synchronizetoip` are IP addresses; OPNsense MVC booleans are `"1"`, `1` or `true` (`"true"` no longer counts).
- [ ] CIS VyOS is rewritten on the shapes `show configuration json` produces: `service` an object, valueless nodes `{}` or null, `system.name-server` a list, `system.ntp.server`, `system.syslog.host`, `firewall.name`, `system.login.user` objects, `encrypted-password` a crypt hash or `!` / `*`. CIS FortiGate: `minimum_length`, `admin_lockout_threshold`, `admin_lockout_duration`, `trap_free_memory_threshold`, `trap_freeable_memory_threshold`, `admintimeout`, `ha.group_id` as numbers (a collector that parses CLI text sends strings and fails these seven). Juniper: `junos_config.protocols` and `external_interfaces` must be collected.

**Benchmarks: cloud, containers, gates**
- [ ] CIS OCI: all 20 lists sent (empty when none): `iam.users`, `iam.policies`, `iam.dynamic_groups`, `iam.compartments`, `iam.root_compartment_resources`, `network.security_lists`, `network.security_groups`, `network.subnets`, `integration_instances`, `analytics_instances`, `autonomous_databases`, `compute.instances`, `tagging.default_tags`, `notifications.topics`, `events.rules`, `kms.keys`, `object_storage.buckets`, `block_storage.volumes`, `block_storage.boot_volumes`, `file_storage.file_systems`; per item the boolean flags (`console_password`, `mfa_enabled`, `is_tenancy_admin`, `active`, `root`, `is_default`, `flow_logs_enabled`, `customer_managed`, `write_logging_enabled`); `network_access` on integration, analytics and database instances; `ingress` on every security list and group with text `source` and `protocol`.
- [ ] CIS Azure and AWS: API booleans are booleans (the strings `"true"` and `"false"` are rejected); fields the APIs return as strings are unchanged. Azure: `bastion_hosts[].enableShareableLink` present and false on Standard and Premium; role names, SKU names, NAT gateway ids and role-assignment scopes and conditions real values; `logs[].enabled` boolean. AWS: `type` on every guardrail content filter; credential-report `password_enabled` and `mfa_active` as `true`, `false` or `not_supported`; `bedrock_api_keys[].Status` Active, Inactive or Expired; security-group rule protocols tcp, udp, icmp, icmpv6, `-1`, `all` or a number 0 to 255.
- [ ] CIS Docker: `docker.info.RegistryConfig.IndexConfigs.<name>.Secure` present and true. CIS OpenShift: every `scc.items[]` entry carries `allowPrivilegedContainer`, `allowHostPID`, `allowHostIPC`, `allowHostNetwork`; endpoint and container ports are numbers. STIG OpenShift 4: `rhcos.nodes[].sshd_enabled` and `sshd_active` are the raw words from `systemctl is-enabled` and `is-active`; an SCC `allow*` field may be absent (the check's jq reads it as false) but a string or number counts as set (CNTR-OS-000660; round 2 had read a missing field as an offender, that is withdrawn); a missing `runAsUser.type` selects the SCC.
- [ ] k8s_pss (Pod Security Standards): switches are booleans, `runAsUser` a number, `spec.containers` a non-empty list of objects; `input.pod.metadata` is not required (an earlier pass required it, withdrawn); sysctls carry `name`. nsa_cisa_k8s, CIS GKE, EKS, AKS, AKS Automatic, GCP, MCP server: yes/no facts as booleans, listed in `evidence_problems`. GCP `flowSampling` a number.
- [ ] crypto_miner_detection: all six lists (`running_processes`, `installed_packages`, `network_connections`, `systemd_services`, `cron_jobs`, `suspicious_files`), and per item `name`, `remote_host`, `remote_port`, `command` or `path` with no null fields.
- [ ] `kubernetes.admission`: a workload that leaves `allowPrivilegeEscalation`, `readOnlyRootFilesystem` or `automountServiceAccountToken` unset, sends a switch as a string, a null label or limit, an unnamed container, or has no readable containers is now denied; a blank `request.kind.kind` is denied; `policy.approved_registries`, when sent, is a list of host-name strings. Run the webhook in warn or audit mode first and read what it would deny before enforcing.
- [ ] `sentinel_kubernetes` (the pre-deployment gate) now denies a manifest whose `kind` is missing, empty, not a string or not recognised (SENTINEL-K8S-000); the 2026-10-19 exception that let it through is withdrawn. Recognised and judged: Deployment, StatefulSet, DaemonSet, Job, CronJob, Pod, Namespace, ClusterRole, ClusterRoleBinding, ConfigMap, Secret, Service, ServiceAccount, NetworkPolicy, Ingress, Role, RoleBinding, PersistentVolumeClaim. Recognised and not judged: the other stable built-in kinds of the core, apps, batch, networking.k8s.io, rbac.authorization.k8s.io, policy, autoscaling, storage.k8s.io, scheduling.k8s.io, coordination.k8s.io, discovery.k8s.io, admissionregistration.k8s.io, apiextensions.k8s.io, node.k8s.io, certificates.k8s.io and flowcontrol.apiserver.k8s.io groups (and events.k8s.io), read from the Kubernetes API reference (kubernetes.io/docs/reference/kubernetes-api/, 2026-11-24). A custom resource is denied with a finding that says how to allow it: list its kind in `input.policy.additional_kinds` (a list of non-empty strings; any other type is an evidence finding and denies). ReplicaSet and ReplicationController manifests are judged like a Deployment (they carry a pod template), as `kubernetes.admission` already did. Also denied now: a manifest that is not an object, a workload with no readable containers, a container with no name; `input.kind` and `input.manifest` must be sent. Run the gate in warn or audit mode in CI before enforcing, and list your custom kinds first. The Terraform and Ansible gates deny input they cannot read (SENTINEL-TF-000, SENTINEL-ANS-000).


### Changed — report counts and shapes (breaking for consumers of the reports) (2026-11-24)
- `total_controls` is a property of the standard, not of the input. Totals now: HITRUST 63 (was 59; `total_checks` 63, `failed_checks`), SEC cyber 23 (was 22), NYDFS 45 (was 44), GLBA 34 (was 33), NCSC CAF 23, TSA pipeline 12 sections (`total_requirements_evaluated` 112 directive subparagraphs, `total_checks` 175; was 175 raised to the finding count), IEC 62443 55 (51 requirements plus one per process module; was 58 raised to the finding count, 108 on empty input), NERC CIP 14 standards (was 48 raised), NIST SP 800-53 544 (was 542). `failed_controls` counts distinct failed controls, not findings and is no longer clamped; `violation_count` stays the finding count; passed + failed + not applicable = total.
- CSA CCM `failed_controls` is at most 150 (was 197); the report adds `controls_checked` (150), `controls_not_checked` (47), `passed_controls`, `failed_control_ids` and `checks_total` (549) beside `total_controls` 197.
- NIST SP 800-53 reports `release: "5.2.0"`, `coverage.catalog_release_date` and `coverage.release_5_2_0_additions_evaluated`. ISO 27001 and SP 800-171 add `advisory_evidence_findings` and `retired_rev2_input_findings`. `sox.itgc` and `sox.application_controls` add `evidence_problems`; `sox.main` findings add `detail`.
- CIS RHEL, Rocky, SUSE 16, Ubuntu, Debian, Amazon Linux, Docker: `compliance_percentage` and the scores derived from it are null with a reason when no profile is selected. The control-results roll-up and the Windows profile blocks gain keys (see schemas).
- CIS Windows Server 2016 and 2025 empty-input totals are 422 and 428 (were 415 and 420), because a recommendation whose tier selector is not stated is now counted.

### Fixed — by family (2026-11-24)
- **CCPA, NYDFS, SWIFT CSP, EU CRA.** Sending every fact as `"false"` cleared NYDFS from 45 findings to 2, SWIFT from 39 mandatory findings to 2, and made four CCPA modules and eleven CRA modules report compliant; all 28 packages now require boolean `true`. A null CCPA section no longer makes the report undefined; CRA `authorised_representative` and `oss_steward` no longer report compliant with no input.
- **HITRUST and CSA CCM.** Every check read its fact with a bare `not input…`, so every fact sent as `"false"` or null cleared it and both modules reported compliant; 63 and 549 checks now need boolean `true`.
- **HIPAA, GLBA, FERPA, COPPA, ITAR, COBIT, NIST SSDF, EU AI Act.** Bare `not input.x` let strings clear findings; bad-input failures for these eight entrypoints fell from 183 to 0 known. HIPAA rejects sections sent as null and mistyped attestations; fact-decided rows take no attestation (round 3 reversed round 1, which had accepted one).
- **ISO 27001, ISO 42001, CISA CPG, NIST CSF 2.0, SP 800-171, ACA 155.260, CPS 234, CERT-In, DPDP, PQC, AS9100D.** Boolean-only facts; a missing `production_data_used` is no longer "production data was not used" (A.8.33); attestations that did not count say why; the facts container missing or null leaves the report defined and failing. AS9100D 10.2.2 names a status that is not `open` or `closed`.
- **FedRAMP.** Selectors and evidence for CA-6, SA-9(5), RA-5, SC-13, PS-3 and PS-3(3) no longer pass on a number sent as a string, an empty list, a non-object entry or an unparsable date; an absent selector no longer switches a control off.
- **CMMC, IEC 62443, TSA.** Mutating an all-pass fixture (4,683 mutations) passed 2,479 times before and never now. A reported TSA incident with no `hours_to_report` is a finding. `iec_62443` is defined with no input document; the same no-input test was added to TSA, NERC CIP, NCSC CAF, HITRUST, SEC cyber and NYDFS.
- **SOX.** All three modules read the same document; sending the facts as input used to fail 31 of 31 checks with the facts present. `sox.simplified` no longer reports compliant with no input.
- **CIS Linux (RHEL, Rocky, Ubuntu, Debian, SUSE, Amazon Linux).** A wrong-typed or null fact no longer passes; audit rules (6.2.3.x) must be in both the on-disk and the running rules; the sudo log file check reads the `Defaults logfile` line only; a Level 1 host that loses its profile is scored against all 352 RHEL 9 recommendations (81 failed) instead of passing at Level 1; a pam_faillock argument without a number (`deny` for `deny=5`) fails 5.3.3.1.1.
- **CIS and STIG databases.** SQL Server `to_number(null)` read as 0; PostgreSQL rows without a name, schema or connection type dropped out of 5.5, 4.5 and 6.8 and a failed recommendation counted as passed; Oracle 19c, MySQL 8 and legacy Oracle lost rows without `account_name`; all closed.
- **CIS Windows and Windows STIG.** `"1"` passed where the benchmark requires the REG_DWORD 1; text or null read as "No One" for a user right; STIG ordering comparisons passed on any string (`>=`) and on null (`<=`). The legal-notice STIG rules now require the full banner rather than a fragment.
- **Network and SaaS benchmarks.** 49 SCuBA policies that cleared on the string `"false"`; CIS M365 5.2.2.11 now requires the sign-in frequency control to be on; Palo Alto empty security-profile lists on a collected configuration are a failed recommendation; VyOS no longer passes telnet, HTTP and SNMP checks when `service` is missing; Arista vetoes a control whose fact has the wrong type.
- **Cloud and Kubernetes.** nsa_cisa_k8s and CIS GKE cleared on a string in a yes/no fact; Azure and AWS accepted `"true"` and `"false"`; the Kubernetes gate dropped a finding when a container had no name; the Terraform gate failed to evaluate a change with several shape problems and now reports them; crypto_miner_detection reported a clean host on null or mistyped facts; CIS Azure 5.12, 5.3.3, 8.3.1.3, 8.4.2, 8.5 and 6.1.1.x read placeholders as real values; CIS AWS 2.14 cleared an administrative policy on a null attachment count.
- **Undefined negation.** Fail-open reads where a missing field made `not f(x.y)` undefined and dropped a finding (digital sovereignty, CMMC TLS, SLSA, corporate, FinOps, NERC CIP rows, Terraform port ranges, Dockerfile `FROM`, owner scope, Debian and Ubuntu pam_faillock, MySQL, Oracle legacy) now fail.
- **NIST SP 800-53 text.** The converters' OSCAL pin moves from v1.5.0 to v1.6.0 (usnistgov/oscal-content `f0de6d8d`, catalog sha256 `64ca6b41…`) because v1.5.0 repeated the SA-15(12) statement under SA-15(13); the policy module was written from the corrected text.


### Added — GovRAMP (formerly StateRAMP): one result per baseline control (2026-11-26)
- **`govramp.main.compliance_report`** (framework key `govramp`, `frameworks/federal/govramp/`). StateRAMP has been GovRAMP since 2025 (the publisher's bylaws read "StateRAMP dba GovRAMP"); there is one key and no alias. The module selects the controls of the declared impact level (`input.impact_level`: low, moderate, high) and verified status (`input.verification_status`: core, ready, authorized, provisionally_authorized) and reports one row per control, with `total_controls`, `passed_controls`, `failed_controls`, `not_applicable_controls` (always 0 until the 800-53 module can state "not applicable") adding up. Each control takes its result from the NIST SP 800-53 module, so no rule body is copied; benchmark results (`input.reports` / `input.findings`) go through the same STIG to 800-53 crosswalk as FedRAMP.
- **The control lists are GovRAMP's, not FedRAMP's.** The publisher's Controls Matrices select 153 (Low, V1.05), 319 (Moderate, V1.06) and 406 (High, V1.1) controls; FedRAMP Rev 5 selects 156 / 323 / 410. GovRAMP leaves out IA-2(12), IA-8(1) and SA-4(10) at every level and CA-8(2) at Moderate and High, and adds nothing. Ready selects 29 / 80 / 90 controls and Core 60 (Moderate only). `scripts/gen_govramp_framework_maps.py` writes the ids from `scripts/govramp_baselines.json` (ids, versions, URLs and sha256 of the source workbooks; no GovRAMP text) into `govramp_index.rego` and the new `govramp_*` maps of `crosswalk/framework_maps/data.json`; `--from-xlsx <dir>` refreshes the list from the workbooks.
- **Attestations a collector must send** (boolean or number; only boolean `true` passes): `verification.pmo_assessment_completed` (Core), `verification.third_party_assessment_completed` (Ready, Authorized, Provisionally Authorized), `verification.sponsoring_body_approved` (Authorized, Provisionally Authorized), `verification.status_valid_days_remaining` (number, negative means expired) and `continuous_monitoring.reports_submitted_on_schedule` (quarterly for Core, monthly otherwise), each cited to the Security Assessment Framework v4.2 or the Continuous Monitoring Guide v2.0 in the module header. An undeclared level assesses High, an undeclared or impossible status (Core outside Moderate) assesses Authorized, each with a finding.
- **Not applied:** GovRAMP's own parameter values. Where the Federal Overlay v1.0 lists a difference from FedRAMP (AU-11, CA-6, CP-9(8), IA-2(6), MP-5, SC-8(1), SC-13, SI-4(10)) the row says so (`federal_overlay_differs_from_fedramp`) and the control is checked with the 800-53 module's parameter.

### Added — NIST SP 800-53: AC-17(9) and SA-10(1) evaluated, 546 of 1,014 ids (2026-11-26)
- **`nist_800_53` and the AC and SA family modules** now evaluate AC-17(9) Disconnect or Disable Access and SA-10(1) Software and Firmware Integrity Verification, the two controls TX-RAMP Level 2 selects that were not among the 544 ids. Both are evidence-based, one finding each, only boolean `true` passes, numbers must be JSON numbers; neither is in an SP 800-53B or FedRAMP baseline (checked against the pinned OSCAL catalog v1.6.0, sha256 `64ca6b41...`; titles and the single organization-defined parameter, AC-17(9)'s time period, read from it). The stated evaluated-id count moves 544 to 546 (246 enhancements).
- **New facts a collector must send** (until it does both ids report `evidence_missing`, so an input that passed all 544 has 544 of 546 passing and `compliant: false`): `ac_controls.remote_access.disconnect.capability_provided` (boolean), `.measured_minutes` (number, minutes a test took to disconnect or disable remote access), `.odp.time_period_minutes` (number greater than 0; measured may not exceed it); `sa_controls.developer_cm.integrity_verification.required` (boolean), `.enabled` (boolean), `.components_unverified` (whole number, 0 passes).

### Added — TX-RAMP (Texas Risk and Authorization Management Program): one result per baseline control (2026-11-26)
- **`txramp.main.compliance_report`** (framework key `txramp`, `frameworks/federal/txramp/`). The module selects the controls of the declared certification level (`input.certification_level`: `level_1`, `level_2`) and reports one row per control, with `total_controls` (117 at Level 1, 223 at Level 2, the counts of Program Manual 4.0 Appendix A), `passed_controls`, `failed_controls`, `not_applicable_controls` (always 0) adding up. Each control takes its result from the NIST SP 800-53 module, so no rule body is copied; benchmark results go through the same STIG to 800-53 crosswalk as FedRAMP. A missing, unknown or `provisional` level is a finding and the Level 2 baseline is assessed; Provisional has no control list and is never compliant.
- **The control lists are TX-RAMP's own** (TX-RAMP Control Baselines 2.0, DIR, last updated 2022-11-14), not FedRAMP's. `scripts/gen_txramp_framework_maps.py` writes the ids from `scripts/txramp_baselines.json` (ids, URLs, sha256 and the published counts; no TX-RAMP text or parameter values) into `txramp_index.rego` and the `txramp_level_1` / `txramp_level_2` maps of `crosswalk/framework_maps/data.json`; `--from-xlsx <dir>` refreshes the list and refuses a workbook that does not reproduce the published counts per family.
- **Every control has a check:** all 117 and 223 controls are among the 546 ids the NIST SP 800-53 module evaluates (AC-17(9) and SA-10(1) were added for this). A control the 800-53 module has no row for would be reported `not_evaluated`, counted failed and listed in `not_evaluated_control_ids`.
- **Equivalence** (Program Manual 9.2): `input.equivalence` with `program` (fedramp, govramp), `status`, `impact_level` (FedRAMP), and the booleans `status_current` and `reciprocal_certification_granted`. FedRAMP Authorized earns Level 1 (Low) or Level 2 (Moderate, High); GovRAMP Core, Ready, Provisionally Authorized and Authorized earn Level 2; In Process, Ready (FedRAMP), Snapshot and Low-impact SaaS earn none. An accepted equivalence reports `certification_basis: "equivalence"`, every row `basis: "equivalence"` with the 800-53 verdict kept in `evidence_status`, and does not ask for control facts; a benchmark gap still fails its row. A claim that is not accepted lists each reason and the assessment applies in full.
- **Attestations a collector must send** (boolean or number; only boolean `true` passes): `certification.acknowledgment_inventory_approved`, `continuous_monitoring.breach_notices_within_48_hours`, `continuous_monitoring.significant_changes_reported_within_30_days` (both bases); on the assessment path also `certification.assessment_questionnaire_approved`, `certification.security_plan_workbook_submitted`, `certification.poam_current`, `certification.valid_days_remaining` (number, negative is expired) and `continuous_monitoring.vulnerability_reports_on_schedule` (quarterly Level 2, annual Level 1). TX-RAMP's own parameter values are not applied.

### Added — bad-input harness, undefined-negation check, crosswalk maps, NIST 800-53 Release 5.2.0, locked acceptance tests (2026-11-24)
- **Bad-input harness** (`make check-bad-input`, part of `make check-coverage`). `scripts/input_refs.py` reads each module's sources through OPA's parser and collects every input path; the harness sends one document with every path set to `"false"`, `"true"`, `"no"` or null, tries boolean fixture leaves as the opposite string, `"no"`, null and removed, and runs several all-pass fixtures per entrypoint. A report that passes fails the check, and so does one with fewer findings than the same document with boolean `false` (kind `fewer-findings`). It covers the 69 entrypoints that have no all-pass fixture. `scripts/bad_input_accepted.txt` holds 291 lines covering 361 accepted cases, one line each with a reason that cites a rule id, a standard's procedure or a collector contract; `--lint-accepted` rejects a line without one and a line whose case no longer fails. The unit tests of the check scripts run first.
- **Undefined-negation check** (`scripts/check_undefined_negation.py --check`, in `make check-coverage`). It parses every policy with `opa parse` and reports where a missing field makes a negated call, `not x.y in S`, a comparison or `object.get` with a passing default undefined inside a violation rule, so a finding silently disappears. It is gated for `enforcement/`, `frameworks/`, `governance/` and `threat_detection/` against a baseline in `scripts/undefined_negation_baseline/` where every entry has a reason. `benchmarks/` is not gated yet: a seeded sample of 40 detector hits found 14 real holes and 25 false positives (a false-positive rate of about 62%), so its 505 current hits need a reviewed baseline (about 366 entries were drafted) before it can gate.
- **Crosswalk maps.** `crosswalk/framework_maps/data.json` carries NIST CSF 2.0 (106 subcategories, 736 pairs, NIST OLIR reference 186), SP 800-171 Rev 3 (97 ids, 157 pairs, NIST CPRT export) and ISO/IEC 27001:2022 (121 ids, 643 pairs, OLIR reference 155, inverted, identifiers only) onto SP 800-53 Rev 5, generated by `scripts/gen_nist_framework_maps.py` from NIST files verified against a pinned sha256; `make check-generated` fails on a hand edit. The file also carries the 800-53 Rev 5.2.0 catalog ids and every mapped id is checked against them. `crosswalk.framework_overlay` gains `inherited_by` and `map_info`. The CIS Controls v8.1 map is not shipped (the CIS workbook is CC BY-NC-ND 4.0; the generator builds it locally from a workbook you download) and PCI DSS v4 is not shipped (no source whose licence allows it); both stay pending and empty. The CSF 2.0 and SP 800-171 modules do not read the maps yet.
- **NIST SP 800-53 Rev 5 Release 5.2.0** (27 August 2025): 544 of 1,014 active ids evaluated; SA-15(13) Logging Syntax and SI-2(7) Root Cause Analysis added (evidence-based and fail-closed), SA-24 already present. The catalog was diffed 5.1.1 to 5.2.0: three new ids, none withdrawn, no title or baseline change, no FedRAMP Rev 5 change.
- **Locked acceptance tests**: `tests/test_acceptance_r3.rego` in 32 trees: the Linux and Windows STIGs and Oracle STIGs, the CIS Linux, Docker and SUSE benchmarks (report arithmetic, profile selection), and the frameworks HIPAA, FedRAMP, CMMC, CCPA, GLBA, SEC cyber, NYDFS, HITRUST, CSA CCM, NCSC CAF, NERC CIP, IEC 62443 and TSA (count arithmetic and fact removal). 581 tests (160 requirements; the long sweeps are split into slices); `opa test . -r acceptance_r3` must stay at 581 of 581 and a locked file is not edited to make a change pass.
- `make check-standards` compares `STANDARDS_UPDATE_REGISTRY.md` with `standards.yaml` (`registry_rows`) and checks the counts stated in `docs/FRAMEWORKS.md`; `make check-no-library-tests` rejects a `test_*` rule in a policy file. New registry row: TSA Pipeline Security Directives.

### Known limits (2026-11-24)
- SWIFT CSP stays on CSCF v2024.
- ISO/IEC 27701 stays on the 2019 edition.
- The published GHCR bundle omits `crosswalk/` until a separate workflow change lands (tracked as its own pull request).
- `enforcement/git` (the repository's own change-governance gates) is exempt from the metadata check, with the reason recorded in `scripts/check_metadata.py`.
- Several CIS generators were edited by hand in step with their generated output and not re-run, because the licensed workbooks are not in the repository: `gen_aws.py` (closed vocabularies, `aws_lib.rego.tmpl`), the Windows selector template (`windows_lib_selector.rego.tmpl`, `gen_windows_10.py`), `gen_rhel_9.py` and its Rocky and RHEL 8 users (null percentage), `gen_suse_16.py`, `gen_ubuntu_26_04.py`, `gen_amazon_linux_2023.py`, `gen_docker.py`, the Debian and Ubuntu 22.04 and 24.04 trees (generated Rego patched from the SUSE pattern), STIG RHEL 10 and Oracle Linux 8 sshd numbers, and `gen_openshift_stig.py`. The 123 `is_number(x)` lines added before comparisons in the CIS Linux and Docker mains and the STIG RHEL 9, RHEL 10 and Oracle Linux account, ssh and configuration rules (so that `make check-coverage` sees the guard) are in the generated output only. A plain regeneration will revert these edits; diff it against the tree before committing it.
- Trees read for the missing-field idiom but not proven (the detector's hits there are baselined by reading, not by a test): AKS Automatic, GKE, Kubernetes, OpenShift, GCP, VMware ESXi 8 and 9, Cisco IOS XE 17, Fortinet, Arista, pfSense, OPNsense, VyOS, Juniper, Android and iOS, Intune Defender, MCP server, SAP ABAP, Windows 10, 11 and Server 2016 to 2025 modular, Apache, nginx, SQL Server 2022 and 2025, `cis/os` legacy, RHEL 10. Sibling `x.y == "v"` selectors inside comprehensions are outside the detector, and Oracle 19c still has row comprehensions that select with `p.user == "root"`.
- Accepted cases whose reason rests on a document that was not read (UNVERIFIED): CIS AKS 5.3.1 (`securityProfile.azureKeyVaultKms.enabled` and service-managed `infrastructureEncryption` as an alternative to KMS, 4 lines); CIS AWS 7.4.2 (`embedding` and `image` data delivery needed only for modalities in use, 4 lines); AS9100D 7.1.5.2, 9.3.1, 9.3.3 (`outputs_recorded`, `measuring_equipment[].traceable`, 4 lines) and the identifier and free-text presence tests of 8.5.2, 8.7.2 and 10.2.2 (3 lines); SAP ABAP baseline template v2.6 conditions (3 lines); ISO 42001 `organization_role` as free text (3 lines, the value gates nothing).
- CIS RHEL 10 declares 312 controls and its directory holds 25 checks (recorded in `scripts/coverage_stamp.py` as a known gap).
- STIG RHEL 10 and Oracle Linux 8 sshd line lists, exact-match sysctl and chrony text facts stay text; they are candidates for a follow-up. STIG Oracle 19c day limits (`PASSWORD_LIFE_TIME`, `PASSWORD_GRACE_TIME` and the like) still accept a fraction.

### Fixed — weekly audit 2026-11-23: counts, missing-evidence gates, citations and standard versions
Breaking for collectors of the frameworks below: facts must be JSON booleans, and several report totals change.
- **DORA**: `total_controls` and `failed_controls` are sums of the parts evaluated (300–320 for Title II, 172
  for Title III; was a fixed 399 with `failed_controls` clamped). Level-1 checks need boolean `true`. Citations
  corrected against Regulation (EU) 2022/2554 (Art. 9(4)(f), Art. 24(5)/(6), Art. 11(6)) and Delegated
  Regulation (EU) 2025/301 for the reporting time limits.
- **GDPR**: the Art. 9, Art. 37 and Chapter V gates, and six more conditional gates, exempt only on boolean
  `false`. Absent, null or wrong-typed is listed under `evidence_missing`. `failed_controls` is counted.
- **21 CFR Part 11**: 50 declared and 50 implemented (was 43 declared, 42 found). IQ/OQ/PQ is a non-scoring
  advisory; §11.200(a) and §11.300(c)–(e) citations corrected; four paragraphs gained a check; the string
  `"no"` no longer passes; five typed `in_use` scope declarations.
- **FISMA / RMF**: an empty POA&M, tailoring list, compensating-control list, network-connection list or
  external-dependency list passes only with an explicit typed "there are none" fact (SP 800-53 Rev 5 CA-5,
  PL-2, PL-11, RA-5).
- **NERC CIP**: CIP-003-9, CIP-004-7 and CIP-012-2 with their new parts; CIP-015-1 dates corrected (US
  effective 2028-10-01); requirement and part labels corrected in eleven modules; log review is Part 4.4 at 15
  calendar days; a future date is a finding and a missing date is evidence missing. `nerc_cip.main` now checks
  CIP-003-9 Attachment 1 Section 6 and CIP-012-2 Parts 1.2/1.3.
- **NIS2**: Art. 21(2)(j) is MFA or continuous authentication plus secured communications, with an explicit
  "not appropriate" statement; training cites Art. 20(2); log retention is a defined period (library
  criterion). 37 controls (was 35).
- **SOX**: one check list feeds score, findings, verdict and counts; Section 409 gates on the Form 8-K
  four-business-day deadline and automation is an advisory; four stray `.rego.fix*` files removed.
- **Docs and tooling**: `docs/FRAMEWORKS.md` is checked against `standards.yaml` and the coverage labels;
  NIST 800-53 header says 542; the coverage stamp requires equality for `full` and labels a count above the
  declared total `over`; the site catalog has a section for every tree (sums to the headline); the bundle
  manifest declares the `crosswalk` root.

### Fixed — FedRAMP Rev 5: three malformed inputs no longer pass (2026-11-22)
- `input.cryptography: null` (and any section sent as null or a non-object: `authorization`,
  `continuous_monitoring`, `data_residency`, `cloud_service`) reads as an empty section, so each check on it
  reports missing evidence. Before, `object.get` on the null section was undefined and the whole section
  raised nothing.
- `authorization.fedramp_authorized` and `authorization.in_process` must be the booleans true or false. The
  string `"true"` was truthy and passed CA-6; it is now `evidence invalid`.
- `personnel[].admin_access` must be a boolean. The string `"true"` skipped the PS-3 screening checks for
  that person; a missing or non-boolean value is now `evidence invalid`.
- Three entries leave `scripts/bad_input_known_failures.txt`. Collectors that send these fields as strings
  will see new findings: send booleans.

### Added — FedRAMP Rev 5 takes technical verdicts from benchmark results through the crosswalk (2026-11-22)
- `crosswalk/framework_maps/data.json` gains `fedramp_rev5_low`, `fedramp_rev5_moderate`, `fedramp_rev5_high`
  and `fedramp_rev5_li_saas`: identity maps (FedRAMP control id to the same NIST SP 800-53 Rev 5 id) for the
  156 / 323 / 410 / 156 controls and enhancements each baseline selects, status `authoritative`. Generated by
  `scripts/gen_fedramp_framework_maps.py` from the FedRAMP OSCAL baseline profiles this repository already pins
  (`converters/exports/oscal/dist/profiles`); each map cites the source URL, commit and sha256.
  `make check-generated` fails when they are stale. `crosswalk.framework_overlay` now reports these four
  baselines beside the three 800-53B ones.
- `fedramp.main.compliance_report` and `fedramp.fedramp_compliance_report` read benchmark results from the
  same input, in the two shapes `crosswalk.correlation` accepts and no other (`input.reports`,
  `input.findings`), for the baseline at the declared impact level (High until one is declared). The
  combination rule is the NIST SP 800-53 module's: a mapped Open rule fails the baseline control whatever the
  module's own check, declared evidence or attestation says; satisfied, not reviewed and not applicable are
  recorded and change nothing; benchmark results never turn a control into a pass. A verdict on a control the
  baseline does not select is listed (`controls_not_in_baseline`, `gap_not_in_baseline`) and is not a finding.
- Fail closed: a report with `facts_supplied: false` counts every rule as Open and adds a finding; results
  that cannot be read, results with no rule id the crosswalk knows, and results supplied when the crosswalk
  packages, the STIG map or the baseline map are not loaded are `FAIL-CLOSED` findings.
- With benchmark results the reports gain `benchmark_evidence`, `control_results` (one row per baseline
  control and per check of the module: `{id, status, checked, findings, benchmark}`, status pass / fail /
  not_evaluated) and `control_result_counts`; `failed_control_ids` also names the baseline controls a
  benchmark gap fails. `total_controls`, `failed_controls`, `area_summary` and `compliance_score` keep their
  meaning (the module's own checks and areas). With neither key in the input both reports are byte-identical
  to the previous release.
- Measured reach of the RHEL 9 STIG V2R10 module (445 rules, 47 base controls of 800-53): 27 of the 135 base
  controls of FedRAMP Low and LI-SaaS, 41 of 181 of Moderate, 45 of 191 of High. No enhancement is reached.
- Tests: 15 for the combination rule (`frameworks/federal/fedramp/tests/test_fedramp_benchmark.rego`, crosswalk
  supplied with `with`) and 8 on the shipped data from the RHEL 9 STIG module's report
  (`tests/crosswalk_fedramp`, repository root). No scoring, weighting or ranking was added.

### Fixed — crosswalk data lands at `data.crosswalk.*` in the wasm bundles (2026-11-22)
- `converters/packaging/wasm/build.py` passed each top-level directory to `opa build` as a bare path, so
  `crosswalk/stig_800_53/data.json` was in the opa-compliance bundle at `data.stig_800_53` and the modules,
  which read `data.crosswalk.stig_800_53`, saw no map there (`spine_loaded` false, so benchmark results could
  only end in the `FAIL-CLOSED` finding). Directories are now passed as `<dir>:<path>`, so every data file is at its
  path from the repository root (`data.crosswalk.stig_800_53`, `data.crosswalk.framework_maps`,
  `data.crosswalk.attack_800_53`).
- Every wasm build checks its own `data.json` and fails when a data file is not at that path.
  `build.py --check-data-paths` runs the check on a plain bundle without the wasm compile, and
  `make check-converters` runs it.
- Sample and fixture JSON in the policy trees, which opa also loads as data, moves with it from `data.<path
  below the top-level directory>` to `data.<top-level directory>.<path>`; no module reads it.
- Not changed: the bundle published to GHCR excludes `crosswalk/` and every `*.json`
  (`.github/workflows/publish-ghcr.yml`), so it carries neither the crosswalk packages nor their data.
### Added — generated JSON Schemas for framework input facts, with a validator (2026-11-22)
- `schemas/input/<framework key>/schema.json`: one JSON Schema (draft 2020-12) per `data.<key>.main.compliance_report`
  entrypoint for the facts the module reads, with `schemas/index.json` listing every key, its derivation and its
  sources. Generated by `scripts/gen_input_schemas.py` (`make schemas`); nothing is written by hand.
- Each schema records its derivation in `x-derivation`: `table` (the four Linux STIG rule tables, through the
  collector contract's extraction: types, the rules that read each path, and `required` from each rule's evidence
  list), `manifest` (the Windows CIS `collector_manifest.json` files), `static-scan+fixture` (input references in
  the module sources plus the shape of its all-pass test fixture) and `paths-only` (the scan alone, no types).
  Only the `table` schemas state required paths.
- `scripts/validate_input.py <framework key> <input.json>` (Python standard library only) reports missing required
  paths, type mismatches and misnamed keys (a key the module does not read that is close to one it does read and
  that is absent), with exit status 1. It checks a document; it collects nothing.
- `make check-generated` now runs `gen_input_schemas.py --check`: a stale schema fails, and so does a self-test
  (each key's all-pass fixture validates; a re-spelled key and a wrong-typed value are flagged).
- Docs: `docs/INPUT_SCHEMAS.md`. No policy, entrypoint or report changes.
### Added — SOC 2: checks for the 12 optional criteria that had none (2026-11-22)
- `soc2.criteria` now covers every one of the 61 criteria: all 28 criteria of the optional categories are
  evaluated for the categories in scope (was 16). `coverage.optional_criteria_not_mapped` is now empty.
- From evidence (5): PI1.4 (`data_processing.transmission.delivery_confirmation`,
  `data_processing.transactions.reconciliation.enabled`, `...reconciliation.frequency_hours` <=
  `input.soc2.commitments.reconciliation_interval_hours`), PI1.5 (`data_processing.integrity_checks.checksums.enabled`,
  `databases.integrity_constraints.enforced`, `databases.transactions.rollback_capability`), P4.3
  (`privacy.retention.automated_deletion`, `data_disposal.verification.completion_verified`), P6.2
  (`privacy.third_party_sharing.disclosure_logging.enabled`, a new path) and P6.7
  (`privacy.gdpr.records_of_processing`, `privacy.data_subject_requests.request_logging`,
  `privacy.data_subject_requests.response_timeline` <= `input.soc2.commitments.data_subject_response_days`).
- By signed attestation at `input.soc2.attestations[id]` (7): PI1.1, P1.1, P2.1, P6.3, P6.4, P6.5, P8.1.
- Titles are short paraphrases written for this library; no AICPA text. Numbers are compared only with the
  entity's own commitments.
- Behaviour change: with processing integrity or privacy in scope, `total_controls` rises by up to 12 (61
  with all four optional categories). An input that was compliant before also needs the five new evidence
  sets, the two new commitments and the seven new attestations; missing evidence is `evidence_missing`.
- Tests: pass, fail and evidence-missing for each new criterion, from the all-pass fixture, plus commitment,
  type, unsigned-attestation and scope tests.

### Changed — SOC 2 and ISO 27701 per-control status values match NIST SP 800-53 and TISAX (breaking) (2026-11-22)
- **Breaking change to the status values** in `control_results` of `soc2.main` (and `soc2.criteria`) and
  `iso27701.main`. Both now use the vocabulary of `nist_800_53.main` and `tisax.main`: `pass`, `fail`,
  `evidence_missing`, `not_attested`. The status `not_assessed` is gone from both, and so is the per-row
  `reason` field: every value it carried is now the status itself, or (`reason: pass` / `fail` in SOC 2) was
  the status already.

  | module | old status / reason | new status |
  |---|---|---|
  | SOC 2 | `not_assessed` / `evidence_missing` | `evidence_missing` |
  | SOC 2 | `not_assessed` / `attestation_missing` (no attestation) | `evidence_missing` |
  | SOC 2 | `fail` / `fail` (attestation present, not signed) | `not_attested` |
  | SOC 2 | `fail` / `fail` (attestation says `attested: false`) | `fail` (unchanged) |
  | ISO 27701 | `not_assessed` / `evidence_missing` | `evidence_missing` |
  | ISO 27701 | `not_assessed` / `not_attested` | `not_attested` |

- `control_result_counts` keys are now `pass`, `fail`, `evidence_missing`, `not_attested` in both modules
  (was `pass`, `fail`, `not_assessed`). Finding text changes with them (`evidence missing - ...`,
  `not attested - ...`; no more `not assessed`).
- Precedence in SOC 2 is that of NIST: fail > not_attested > evidence_missing > pass. Missing evidence and an
  unsigned attestation never pass; `total_controls`, `failed_controls` and `compliant` are unchanged.
- Out of scope is not a status in any of the four: rows outside the scope are left out and the scope is shown
  in `categories_in_scope` (SOC 2), `group_results` (ISO 27701), `part_results` (TISAX) or `baseline_results`
  (NIST). TISAX's top-level `not_assessed` list (superseded 3.1.2) and NIST's `withdrawn_not_assessed` are
  catalogue notes, not statuses, and are unchanged.
- One difference is kept on purpose: in SOC 2 and ISO 27701 an attestation that says `attested: false` is a
  `fail` (an explicit refusal), where TISAX and NIST report it as `not_attested`.

### Added — SOC 2: all 33 common criteria with per-criterion results (2026-11-22)
- `frameworks/management/soc2` now evaluates every common criterion of the 2017 Trust Services Criteria
  (points of focus revised 2022), CC1.1 to CC9.2 (was 12 of 33). New module `soc2.criteria`
  (`criteria/soc2_criteria.rego`) lists each criterion with a short paraphrased title (no AICPA text), its
  basis, the input paths it reads and the test each must meet.
- 10 criteria are decided from evidence (CC6.1, CC6.2, CC6.3, CC6.5, CC6.6, CC6.7, CC6.8, CC7.1, CC7.2,
  CC8.1) and 23 by a signed attestation at `input.soc2.attestations["<id>"]` = `{attested: true, by, date}`.
  CC1.2, CC1.4, CC3.2, CC7.4, CC9.1 and CC9.2 still need the records they read before as well, so an
  attestation never passes a criterion whose record says otherwise. The 16 mapped optional-category criteria
  move onto the same fact tests.
- `compliance_report` gains `control_results` (one row per criterion in scope: status pass / fail /
  not_assessed, reason pass / fail / evidence_missing / attestation_missing, basis, evidence paths, findings),
  `control_result_counts`, `basis_counts` and `coverage`. Missing evidence or a missing attestation is
  `not_assessed` and never passes; a supplied fact that fails outranks a missing one.
- Behaviour change: `total_controls` rises from 12 to 33 (plus the optional criteria in scope),
  `failed_criteria` lists every criterion that did not pass, and `violations` carry one message per unmet part
  (`SOC 2 <id>: <title> - ...`). Inputs that were compliant before now also need the attestations and the
  new CC6.5, CC6.7, CC6.8 and CC7.1 facts (`data_disposal`, `encryption.in_transit`, `dlp.monitoring`,
  `security.edr`, `security.vulnerability_management`). `soc2.main`, `soc2.soc2_assessment`, the submodules
  and every existing input path are unchanged; `compliance_report.criteria` keeps the earlier mapped checks
  and decides nothing.
- Tests: pass, fail and evidence-missing for each of the 49 criteria, plus record-versus-attestation,
  unsigned attestation, unknown key and type tests.
- Not mapped (no check): PI1.1, PI1.4, PI1.5, P1.1, P2.1, P4.3, P6.2-P6.5, P6.7, P8.1.

### Changed — ISO/IEC 27701:2019: one result for each of 108 controls (breaking ids) (2026-11-22)
- `frameworks/privacy/iso27701` now evaluates 108 controls of the 2019 edition: clause 5 (23 requirements
  extending ISO/IEC 27001), clause 6 (36 subclauses extending ISO/IEC 27002), Annex A controllers (31) and
  Annex B processors (18). 8 are decided from system facts (`input.iso27701.evidence`), 100 by signed
  attestation (`input.iso27701.attestations[id]`). Statuses are pass, fail and not_assessed; missing or
  mistyped evidence is never a pass. Annex A / B drop out only on `scope.pii_controller` /
  `scope.pii_processor` set to the boolean false.
- The control list was compiled from public secondary sources (publisher preview table of contents, two NQA
  analyses, the NIST Privacy Framework crosswalk by Microsoft) and has not been checked against the purchased
  standard; sources, inclusion rule and the five unconfirmed clause 6 ids (6.3.2.2, 6.12.1.1, 6.14.2.1,
  6.15.2.2, 6.15.2.3) are in the module header and in the report (`unconfirmed_ids`, `id_source`). It should be
  verified against the purchased standard when one is bought. The old declared total of 134 had no source.
- Per-control results: `control_results`, `control_result_counts`, `group_results`, `failed_control_ids`.
  `iso27701.main`, `compliance_report` and `overall_compliant` are unchanged in name; the four area packages
  (`pims_requirements`, `pii_controller`, `pii_processor`, `data_subject_rights`) are now views over the same
  results.
- Input paths: the old boolean fields are still read, mapped by meaning to the control each one evidences
  (`legacy_inputs`); a control passes on them only when every mapped field is true, and any false one fails
  it. Not read any more: `pii_processor.privacy_by_design.controls_throughout_lifecycle` (no 2019 control) and
  `pii_controller.privacy_by_design.transmission_controls` (7.4.9 is now decided from evidence).
- Breaking for anyone parsing violation prefixes: the old ids were misnumbered against the 2019 edition. Old
  prefix -> new id: 5.2 -> 5.2.1; 5.3 -> 5.2.2; 5.4 -> 5.2.3; 5.5 -> 5.3.1 / 5.5.1; 5.6 -> 5.3.2; 6.1 ->
  5.4.1.2 / 5.4.1.3 / 7.2.5; 6.2 -> 5.4.2; 6.3 -> 5.6.1; 7.2.5 -> 7.3.3; 7.3.2 -> 7.3.3; 7.3.3 -> 7.3.4;
  7.3.4 / 7.3.5 -> 7.3.6; 7.3.6 -> 7.3.8; 7.3.7 -> 7.3.9; 7.3.8 -> 7.3.10; 7.4.8 -> 7.4.9; 7.5.3 -> 7.5.4;
  8.2.3 -> 8.5.7; 8.2.4 -> 8.2.3; 8.3.2 -> 8.2.6; 8.4.1 -> retired; 8.4.2 -> 8.4.1; 8.4.3 -> 8.4.2;
  8.5.1 -> 8.5.5; 8.5.2 -> 8.5.4; 8.5.3 -> 8.5.6; 8.5.4 -> 8.5.1; "Annex B / GDPR Art. 15-22" -> 7.3.5,
  7.3.6, 7.3.7, 7.3.8, 7.3.9, 7.3.10. Unchanged: 7.2.1-7.2.4, 7.2.6, 7.2.7, 7.3.1, 7.4.1-7.4.7, 7.5.1, 7.5.2,
  8.2.1, 8.2.2, 8.3.1.
- 324 per-control tests (pass, fail and evidence-missing for each control) plus contract, scope, attestation
  and legacy-input tests. `coverage_stamp.py` known gap for iso27701 removed; label stays experimental.

### Added — NIST SP 800-53 takes technical verdicts from benchmark results through the crosswalk (2026-11-22)
- `nist.sp800_53.main` / `nist_800_53` now read benchmark results from the same input, in the two shapes
  `crosswalk.correlation` already accepts (`input.reports`: STIG compliance reports; `input.findings`: a flat
  `stig_id` + `status` list). For each 800-53 control the DISA map reaches, the row in `control_results` gains
  `benchmark: {status, rules, open_rules, not_reviewed_rules}` and the report gains a `benchmark_evidence` block.
- Combination rule: a benchmark gap fails the control, whatever its declared evidence or attestation says (the
  finding names the Open rules; `family_summary` counts it). A satisfied verdict is recorded and changes no
  status, so benchmark results never turn a control into a pass. Controls no rule maps to, and every enhancement
  (the map is at base-control granularity), are `not_evaluated`.
- Fail closed: a report with `facts_supplied: false` counts its rules as Open; rule ids the map does not know
  are listed under `unmapped_rules` and speak to no control; unreadable benchmark results, results with no known
  rule id, and results supplied while the crosswalk is not loaded each add a `FAIL-CLOSED` finding.
- No change without benchmark results: with neither key in the input the report is identical to before.
- New in `crosswalk`: `correlation.control_evidence`, `evidence_supplied`, `spine_loaded`,
  `reports_without_facts`, and `framework_overlay.control_evidence[<map key>][<control id>]` for the frameworks
  that will follow through `framework_maps`. No mapping was added; nothing is scored or ranked.
- Fixed: `framework_overlay.coverage` listed a framework control once per mapped 800-53 control, so
  `controls_satisfied` over-counted any control mapped to more than one (the shipped maps are one to one, so no
  published number changes).
- The RHEL 9 STIG module's 445 rules reach 47 base controls in 7 families (SC 11, AC 10, AU 9, IA 6, CM 5, SI 4,
  MA 2). The RHEL 9 slice of `crosswalk/stig_800_53/data.json` was regenerated from the V2R10 XCCDF, so all 445
  rule ids are in the map (three V2R10 ids were missing and three retired ids remained).
- Loading: to use benchmark results, `crosswalk/correlation.rego` and the map at `data.crosswalk.stig_800_53`
  must be in the same OPA as the 800-53 module. See `crosswalk/README.md` and `examples/nist_800_53/README.md`.

### Added — DISA STIG RHEL 9 V2R10: all 445 rules (2026-11-22)
- `benchmarks/stig/rhel_9` now implements every rule of the V2R10 STIG (was 104 of 445). The 341 new rules are
  reviewed table entries written against DISA's full check text (`tools/stig_generators/rhel9_rules_part1.py`
  to `rhel9_rules_part5.py`), each with pass, fail and evidence-missing tests. 366 rules are decided from
  facts, 77 from facts plus an attestation the check text asks for, 2 are attestation only.
- Input contract: the module now reads 484 fact paths and 98 attestation keys (was 133 and 24), all listed in
  `benchmarks/stig/LINUX_COLLECTOR_CONTRACT.md`. A rule whose facts are not supplied reports `evidence missing`
  (Open), so an older collector sees more Open findings, never a false pass. `total_controls` for `stig.rhel_9`
  and `stig_rhel9` rises to 445.
- The coverage label stays `partial`: the new rules are unit-tested and have not run on a real host.
- Oracle Linux 9, Oracle Linux 8 and RHEL 10 STIG modules regenerated (shared mount and audit-rule test
  fixtures grew); their rule sets are unchanged (114, 95 and 100 rules).
- `stig.rhel_9` score: `compliance_percentage` is 100 only when every control passed. With 445 controls one Open
  finding is 99.78 %, which rounded to 100 beside `compliant == false`; it now reports 99.
- `test_gate_transparent_when_facts_supplied` no longer requires a non-zero percentage from one supplied fact
  (1 of 445 rounds to 0); it requires a passed control and fewer failures than controls.
### Changed — CISA SCuBA M365 follows ScubaGear v2.0.0: Defender baseline replaced by Security Suite, Defender kept as a deprecated shim (2026-11-21, issue #341)

- `benchmarks/scuba/m365` now implements every active policy of the ScubaGear v2.0.0 baselines (2026-10-22): 109
  policies, 59 SHALL / 50 SHOULD, id and criticality checked one by one against `baselines/*.md`. The 85 Entra ID,
  EXO, Power BI, Power Platform, SharePoint and Teams ids were unchanged.
- v2.0.0 removed the Defender baseline. New module `scuba_m365.securitysuite` (`securitysuite_validation.rego`, 24
  MS.SECURITYSUITE policies in 8 groups: malware, impersonation, DLP, alerts, audit logging, inbound anti-spam,
  link protection, IP allow lists), input `scuba.securitysuite.*`. Where the rework is one to one the field names
  are kept (impersonation, `safe_attachments`, DLP, `alerts.routed_to_monitored_target`,
  `audit.unified_logging_enabled`); new facts: `malware.*`, `impersonation.user_warnings`, `alerts.enabled` (list
  of alert names; 4.1 names the seven it requires and reports the missing ones), `audit.searchable_retention_days`
  (>= 90) and `audit.retrievable_retention_days` (>= 365) for 5.2, `antispam.*`, `links.*`, `allow_lists.*`.
  MS.DEFENDER.4.5 and 6.2 have no successor.
- The orchestrator `scuba_m365.main` totals 109 and counts the Security Suite baseline only (its product summary
  carries `MS.SECURITYSUITE`, never `MS.DEFENDER`).
- **Not breaking in this release — deprecation shim.** `scuba_m365.defender` stays as a deprecated compatibility
  layer: `/v1/data/scuba_m365/defender/compliance_report` and input `scuba.defender.*` keep working with the same
  19 MS.DEFENDER ids, and the report gains `deprecated`, `successor` and `successor_ids`. The 11 policies with a
  one-to-one successor (2.1-2.3, 3.1, 4.1-4.4, 4.6, 5.2, 6.1) are evaluated by the Security Suite rule on the
  translated fact; the other 8 (1.1-1.5, 4.5, 5.1, 6.3) keep their original rule. When input arrives only as
  `scuba.defender.*`, `scuba_m365.main` evaluates the Security Suite baseline from the one-to-one facts (the 13
  policies with no legacy fact fail closed) and reports `securitysuite_input_path` and an `input_note`;
  `scuba.securitysuite.*` always wins when present. **The shim and the `scuba.defender.*` input path are removed in
  the next minor release** — move collectors to `scuba.securitysuite.*`.
- `standards.yaml` pins ScubaGear v2.0.0 (was unknown).
- `benchmarks/scuba/m365/aad_validation.rego`: the 30 checks written `not input.scuba.aad.<fact>` now require the
  boolean `true` (`not ... == true`), so a string such as `"true"` no longer passes (found by `make check-bad-input`
  once the Security Suite fixture let `scuba_m365.main` reach a pass).

### Changed — SAP ABAP baseline re-pinned to frun-csa-policies-best-practices cb687307 (2026-11-21, issue #341)

- `benchmarks/sap/abap` re-imported at `cb687307` (2026-11-12, upstream HEAD). The five commits since `888f3c53`
  carry the November Patch Day only (`NotesPolicies/` ABAP and HANA security notes, FRUN 3.0 FP01 `NO_PD`
  containers); `BaselinePolicies/SOS/v2.6/ABAP_ALL` is unchanged, so `scripts/import_sap_baseline.py` produces the
  same 355 registry rows and 127 translated checks, and only the source-commit stamp moves.

### Changed — TISAX rebuilt on VDA ISA2027.1 (2026-11-22) — BREAKING: control ids and input contract

- `frameworks/management/tisax` (package `tisax.main`, entrypoint unchanged) now evaluates every active control
  number of VDA ISA2027.1 (English workbook 2026-09-30; applies to TISAX assessments ordered from 2027-01-01):
  Information Security 45 (chapters 1–7), Prototype Protection 20 (8.1.1–8.1.13, 8.2.1–8.2.7), Data Protection 12
  (9.1.1–9.8.1) = 77. 3.1.2 is superseded in the catalogue and is listed under `not_assessed`.
- 13 Information Security controls (1.3.4, 3.1.4, 4.1.2, 4.1.3, 4.2.1, 5.1.1, 5.1.2, 5.2.3, 5.2.4, 5.2.5, 5.2.6,
  5.2.7, 5.2.9) are evaluated from system facts at `input.tisax.evidence.*` (facts and limits in `evidence_spec`;
  the limits are library defaults). The other 64 are organisational and pass only on a signed attestation
  `input.tisax.attestations["<id>"] = {attested: true, by, date}`, with an optional `maturity_level` that must be at
  least 3. Absent evidence or attestation is `evidence_missing`, never a pass.
- Prototype Protection and Data Protection are evaluated unless `input.tisax.scope.<part>` is the boolean false
  (replaces the old `assessment_level`-based gating of the three "TISAX PD AL2" checks).
- Report: `total_controls` = controls in scope, `failed_controls`, `failed_control_ids`, `control_results` (id, title,
  part, chapter, basis, status pass / fail / evidence_missing / not_attested, findings) and
  `control_result_counts`, `part_results`; `domain_summary` is gone. Violations read `TISAX ISA2027 <id> (<label>): ...`.
- **Breaking:** the previous ids were the module's own numbering under an ISA 6.0.3 heading (most on another topic
  than the catalogue control of the same number) and the old `input.isms.*` / `input.it_security.*` / ... facts are no
  longer read. Any consumer keyed on the old ids, the old "TISAX VDA ISA" / "TISAX PD" message prefixes or the old
  input paths must move. `technical_debt.scoring` now keys TISAX effort on the ISA2027 chapter (PD key removed).
- Not approved by ENX. VDA ISA © ENX Association, used under CC BY-ND 4.0 with the ENX additional grant; checks
  written independently. Only control numbers and paraphrased short labels are used; no catalogue text is carried.
  NOTICE gains a "Third-party notices" section with that credit. `standards.yaml`, STANDARDS_UPDATE_REGISTRY.md,
  docs/SCF_GAP.md, counts and the OSCAL / crosswalk exports updated.

### Reviewed — COBIT 7 blocked by vendor (2026-11-22, issue #194)

- ISACA requires a paid commercial licence to embed COBIT 7 content, objectives or derived material in software, with
  no free or open-source exception. The library takes no licence that costs money, so `frameworks/management/cobit`
  stays on COBIT 2019 and COBIT 7 is not planned; the module header, STANDARDS_UPDATE_REGISTRY.md and
  `standards.yaml` say "blocked by vendor", and the monthly watch no longer reports COBIT 7 as newer.

### Changed — DISA STIG VMware vSphere 8.0 ESXi V2R5, MS SQL Server 2016 bundle 2026-04 (2026-11-21, issue #341)

- `benchmarks/stig/vmware_vsphere_8` follows DISA's V2R5 (30 Sep 2026, bundle `U_VMW_vSphere_8-0_Y26M10`): 76 rules,
  none added or removed, no CCI changes. Of the eight rules DISA revised, only ESXI-80-000124 is implemented and its
  change is DoD → DoW wording, so no rule logic changed; version strings and `standards.yaml` move to V2R5 / 2026-10.
  Not implemented here: ESXI-80-000227 `Security.PasswordMaxDays` check now 365 (was 90) while the fix text says 180;
  ESXI-80-000193 adds an SSH scanning note; 000006/191/192/229/247 are DoD → DoW wording.
- `benchmarks/stig/ms_sql_2016`: the 2026-04 bundle `U_MS_SQL_Server_2016_Y26M04` carries the Instance STIG V3R6
  byte-identical to the 2026-01 bundle; only the Database STIG moves V3R4 → V3R5 (SQL6-D0-003300 TDE check query
  rewritten), which this Instance module does not cover. No rule change; `standards.yaml` released → 2026-04.

### Changed — SLSA re-pinned to v1.2 (build track unchanged) (2026-11-21, issue #341)

- `benchmarks/supply_chain/slsa` and `enforcement/supply_chain/slsa_governance.rego` now state SLSA v1.2 (2025-11-24;
  v1.0 is retired on slsa.dev). The Build track's three levels and requirements are the same as in v1.0 — v1.1 and
  v1.2 reworded them and added a RECOMMENDED signing method (transparency logs or time stamping) — so no level logic
  changed. v1.2's new Source track (L1-L4) is not implemented. The `slsa_governance` header now records that its
  gates keep the v0.1 shape (version-controlled source and verified history counted toward build levels; under v1.2
  they are Source L1/L2). Report strings "SLSA v1.2 (build track)" and "SLSA v1.2 + Supply Chain Governance".

### Changed — OpenSSF S2C2F pinned to v1.1 (2026-11-21, issue #341)

- `benchmarks/supply_chain/s2c2f` now states S2C2F v1.1 (ossf/s2c2f release, 2022-10-19, still the latest): the
  header maps all 25 v1.1 requirement ids with their maturity levels to the four substrate themes the overlay reuses
  (AUD-1 and REB-1 have no consumption-side theme). Report string "OpenSSF S2C2F v1.1 (consumption)";
  `reuses_substrate` and the collapse metrics are unchanged. `standards.yaml` pins v1.1 (was unknown).

### Reviewed — NIST Privacy Framework 1.1 still a draft (2026-11-21, issue #341)

- NIST Privacy Framework 1.1 remains the Initial Public Draft (NIST CSWP 40 ipd, 2025-04-14; comments closed
  2025-06-13; no second draft or final on CSRC). `frameworks/privacy/nist_privacy_framework` stays on 1.0; no rule
  changed. The `standards.yaml` page check now reads the final-document link ("Version 1.0 (PDF)") instead of any
  "Privacy Framework 1.1" text, so the draft no longer reports as a newer release; a final 1.1 link will. New
  STANDARDS_UPDATE_REGISTRY.md row.

### Changed — OWASP LLM MITRE ATLAS crosswalk re-pinned to atlas-data v2026.10 (2026-11-21, issue #341)

- `governance/owasp_llm` crosswalk metadata now cites atlas-data v2026.10 (2026-10-28, 44 mitigations
  AML.M0000-M0043; v2026.09 had 40). All 19 cited mitigation ids still exist with the same intent; three were renamed
  upstream (AML.M0023 "Maintain an AI Bill of Materials", AML.M0026 "Manage AI Agent Service Access", AML.M0028
  "Enforce Access Controls for AI Agent Tools"). The crosswalk table and the 30 checks are unchanged; the new
  mitigations AML.M0040-M0043 are not mapped.

### Changed — DISA STIG RHEL 8 V2R9 (2026-11-21, issue #341)

- `benchmarks/stig/rhel_8` follows DISA's standalone V2R9 (30 Sep 2026): 56 of 371 rules. Added RHEL-08-010287
  (sshd CRYPTO_POLICY commented), RHEL-08-010293 (openssl.cnf includes opensslcnf.config) and RHEL-08-030565
  (useradd audit rule), each fail-closed with an "evidence missing" detail. RHEL-08-020200 is 180 days (was 60);
  RHEL-08-010020 now checks the FIPS crypto policy without subpolicies, the CURRENT.pol hashes and min_rsa_size (it
  checked FIPS mode); the crossed banner ids are corrected (010040 sshd Banner file, 010060 /etc/issue, exact text);
  DoD → DoW titles. Crosswalk re-joined (V2R9 CCIs; RHEL-08-040221/040222 now have no Rev 5 mapping).
- `benchmarks/stig/ubuntu_20_04` (sunset) follows DISA's final V2R4 (01 Oct 2025; the module said V2R1): the five
  stub checks carried invented ids and non-DISA thresholds. Now 4 of 173 rules against the V2R4 check text —
  UBTU-20-010001 (vendor-supported release, attested), -010443 (DoD root CA), -010054 (minlen 15, was 14) and
  -010070 (remember 5, was 24); guest account and antivirus had no Ubuntu 20.04 rule and are removed. Every rule
  fails closed with an "evidence missing" detail; `stig_assessment` carries `rule_results`. UBTU-20 joins the
  800-53 crosswalk (173 of 173).

### Reviewed — HITRUST CSF and TISAX, licensed rows (2026-11-21, issue #341)

- `frameworks/management/hitrust` still names CSF v11.3.0 (released 2024-04-16); upstream is v11.9.0 (HAA 2026-005,
  2026-09-24) and v11.0–11.3 are decommissioned (HAA 2026-007: new r2 objects from 2026-12-23 must use v11.4+, no
  v11.0–11.3 submissions after 2027-03-31). The header now says so and that its ids are the module's own numbering in CSF reference style
  (the CSF has 14 categories, 00–13), not CSF control references; `published` corrected from 2023 to 2024-04-16. No
  rule logic changed. A rebuild needs HITRUST's written consent: the CSF licence is free but excludes IT security
  vendors and consultants and forbids derivative software without consent.
- `frameworks/management/tisax` still names VDA ISA 6.0.3; ISA2027 (published 2026-07-01, English ISA2027.1 dated
  2026-09-30) applies to assessments ordered from 2027-01-01. The header records that, the public id changes (1.2.4 →
  6.1.3, Prototype Protection renumbered) and that the module's ids are its own numbering (30 of 49 exist in ISA 6,
  nearly all on another topic); the objectives line now names the catalogue's Information Security, Prototype
  Protection and Data Protection modules. No rule logic changed. The catalogue is a free CC BY-ND 4.0 download with
  ENX's grant for marked derivatives, so a rebuild with catalogue ids and
  checks in our own words needs no permission.
- `standards.yaml`: notes on both rows (versions unchanged); the HITRUST watch pattern now matches "CSF Version
  11.9.0" (it stopped at 11.8). `STANDARDS_UPDATE_REGISTRY.md` rows rewritten.

### Reviewed — HIPAA amendment of 2026-11-19

- 45 CFR Part 164 amendment of 2026-11-19 (HIPAA Privacy Rule final rule, 91 FR 74848, FR doc 2026-23429; effective
  2027-01-19, compliance 2027-07-19) reviewed: it amends Subpart E (164.501-.525, .532) and 160.103 only, not the
  Security Rule (Subpart C). No rule logic changed; `standards.yaml` hipaa checked_through 2026-11-19. The
  `hipaa.privacy_rule` changes owed before 2027-07-19 are listed in STANDARDS_UPDATE_REGISTRY.md.
- 45 CFR Part 160 amendment of 2026-03-24 / 2026-05-26 (claims attachments final rule, 91 FR 14350, FR doc
  2026-05676; compliance 2028-05-26) reviewed: it changes only the 160.103 "Transaction" definition, which
  `hipaa.part160` does not evaluate.
- 45 CFR Part 162 amendments of 2025-04-14 and 2025-08-21 (NCPDP F6 retail pharmacy rule and its date
  corrections, 90 FR 9289, 90 FR 40746) reviewed: `hipaa.part162` already carries the August 14, 2027 /
  April 14, 2028 dates. The standards watch now covers 45 CFR Parts 160, 162 and 164.

### Changed — decisions of 2026-11-21

- NIST 800-53 PT-6(1) and PT-6(2) are attestation-based
  (`input.pt_controls.system_of_records_notice.{routine_uses,exemptions}.attestation`): a system with no system
  of records cannot produce review evidence. Attestation-based ids: 64 → 66.
- The AC family aggregate `nist_sp800_53_ac_compliant` (the AC report's `overall_compliant`) is true exactly when
  no AC id has a finding; it used to check 34 of the 60 evaluated ids.
- STIG RHEL 9 / RHEL 10 / Oracle Linux 8 / 9 follow DISA's check text: the pwquality ucredit, lcredit, dcredit and
  ocredit rules pass at 0 or any negative value (only a positive or commented-out value is a finding), and
  ClientAliveInterval "600 or less" no longer treats 0 as a finding. Fixed in the generator tables; modules,
  tests, golden cases and the Linux collector contract regenerated.
- STIG OpenShift 4 CNTR-OS-000400 follows DISA's V2R7 check text: only a ClientAliveInterval "> 600" (or missing)
  is a finding, so 0 now passes. The module has no pwquality credit rules. Generator fixed, module regenerated, golden cases added.
- CI runs every `examples/*/check.sh`; a monthly standards-watch workflow opens a "standards watch: YYYY-MM" issue
  when an upstream release is newer than `standards.yaml` or a source cannot be read.
- examples/nist_800_53 supplies the AC-3(14) facts again; its pins match the 542-id module.
- PCI DSS v4.0.1: findings tell a real failure (`status: fail`) from missing evidence (`status: evidence_missing`,
  whose title says "evidence missing" and names the input paths); new `requirement_results` and
  `requirement_result_counts` report all 12 requirements, passes included. Scope flags pass only on boolean `true`.
  `scripts/gen_pci_dss_evidence_spec.py --check` runs in `make check-generated`. Violation titles changed.
- PCI DSS 6.4.2: public-facing web apps need an implemented WAF that blocks, or alerts for immediate
  investigation, with audit logging; `automated_detection.waf_or_vapt` alone no longer satisfies it.

### Fixed — the last unguarded numeric comparisons (#300)

- STIG: the last 26 unguarded numeric comparisons (Kubernetes version gates and group ranges, RHEL 8 account_auth,
  Oracle Linux 8 pwquality, Ubuntu 20.04/22.04/24.04) now require `is_number`; a string or null value is Open,
  never Not_a_Finding. The numeric-guard baseline is empty, so any new unguarded comparison fails CI.
- The generator tables (gen_k8s.py, gen_linux.py, ol8_rules.py) carry the guards; type-trap tests per module.

### Added — coverage labels on the published site (#313)

- Every standard page and homepage card shows its validated / partial / experimental badge with the evidence; the
  new coverage-labels.html explains the three labels and lists every framework key.
- `scripts/coverage_labels.json` is the single source: `coverage_report.py --check` (CI) fails when a framework key
  has no label, a label names no key, or a module's METADATA carries its own label.

### Added — OSCAL assessment-results and SARIF for any framework key (#312)

- `converters/exports/oscal/build_assessment_results.py` and `converters/exports/sarif/build.py` take a
  compliance_report (opa eval, REST or bare) and `--key`, read `control_results` statuses (only `pass` is
  satisfied), fall back to violations, and `--validate` against the shipped schemas.
- SARIF works with GitHub code scanning: physical locations, severity-based levels and `security-severity`,
  per-finding fingerprints, categories, optional pass rows.
- `<key>.main` entrypoints resolve to their framework in every results export (about 40 keys did not, including
  `nist_800_53`, every `stig_*` key and `cis_windows_2022`). New all-keys roundtrip in `make check-converters`.
- CIS id exports include ids a module lists in `CONTROL_INDEX` (CIS M365 v7: 160 of 160, was 111); the XCCDF table
  keeps one row per benchmark, not per platform directory (#322).

### Fixed — numeric comparisons in benchmarks/ require a number (#300)

- 442 comparisons in benchmarks/ (outside STIG and Ubuntu 22.04, handled separately) now need `is_number`: pass
  rules no longer pass on "1", null or text; violation rules report "<id>: evidence missing — <field> is not a
  number". Type-trap tests across PostgreSQL, MySQL, Oracle, vCenter, Debian 11, Ubuntu 20.04, RHEL 9, M365, MCP and
  others. Library-wide, 26 scanner-detected comparisons remain in the baseline.

### Added — bad input never passes (#301)

- `make check-bad-input` (run by `check-coverage`) evaluates every compliance_report entrypoint on empty, absent,
  null and string-typed input, and mutates each module's all-pass test fixture (fields dropped or nulled, number and
  boolean leaves as strings). Current failures are listed in `scripts/bad_input_known_failures.txt`; the gate fails
  only on new ones and reports entries that now pass as stale.

### Added — mutation testing and golden cases (#305, #306)

- `scripts/mutation_test.py` / `make mutation MODULE=<dir>` (on demand, not CI) reports surviving mutants by
  file:line; docs/testing/MUTATION_AND_GOLDEN.md.
- Golden cases from public-domain text: 70 for NIST SP 800-53 AC (OSCAL statements), 87 for 32 DISA STIG RHEL 9
  rules. New tests raise mutation scores: PCI DSS Req 7/8 31.7%→95.9%, NIST AC 78.8%→98.1%, SCuBA M365 96.3%→100%.

### Added — NIST SP 800-53: the full Privacy baseline (542 ids); stricter counts and booleans

- All 96 Privacy-baseline ids are evaluated (19 added; 542 ids in total).
- A count that is negative or fractional is evidence missing in every 800-53 family.
- CP and IA: a non-boolean fact is evidence missing; `false` keeps the failure message.
- PT, SA, RA and SR attestation findings now say "not attested" and are counted as attestation-based.

### Added — Linux STIG collector contract

- `benchmarks/stig/LINUX_COLLECTOR_CONTRACT.md` lists every input fact path the RHEL 9, RHEL 10 and Oracle Linux
  8/9 STIG rules read, with type, accepted forms, a pass example and the rules that read it (for example
  `fips.fips_enabled` must be the string "1"; `fips_mode` is not read). Generated from the rule tables;
  `make check-generated` fails when it is stale. The RHEL 9 rule table imports without the DISA catalog.

### Fixed — CIS Ubuntu 22.04: five gaps found with real host evidence (#332)

- 2.4.1.7 passes when `/etc/cron.yearly` is absent (`cron.cron_yearly_exists: false`).
- 2.3.3.2, 5.4.3.3 and 6.3.2 take a `collected: true` marker on `chronyd`, `pam` and `aide`, so collected-and-empty
  is "not met" rather than "evidence missing"; 5.4.3.3 requires a umask line in `/etc/profile.d/*.sh`.
- The module README holds the full input contract; its numeric comparisons are guarded.

### Added — standards registry and release check (#308)

- `standards.yaml`: every framework key with the standard, the implemented version tied to module text, the
  publisher and a release-check method. `make check-standards` (run by `check-generated`) fails on drift.
- `scripts/check_standard_releases.py` network mode checks OSCAL, GitHub, DISA, eCFR, CIS and publisher pages;
  an unreadable source reports `failed`, never `current`.
- STANDARDS_UPDATE_REGISTRY.md v1.2: stale rows fixed; COBIT 7 publication (2026-11-19) recorded (#194).

### Added — coverage labels and quick starts beyond RHEL 9 (#313, #302, #311)

- Every framework key is labelled validated, partial or experimental (`scripts/coverage_labels.json`); COVERAGE.md
  prints the label with its evidence. 4 validated, 5 partial, 186 experimental.
- STIG RHEL 9 V2R10 is partial (about 45 fact paths not collected); ISO/IEC 27701 is experimental, not validated.
- `examples/` quick starts for CIS Windows Server 2022, CIS M365 v7, NIST 800-53, PCI DSS 4.0.1, CIS Kubernetes and
  CIS AWS, each with a `check.sh` that asserts the result; walkthrough in docs/QUICKSTARTS.md.

### Fixed — numeric comparisons outside benchmarks/ require a number (#300, part)

- 390 comparisons across IEC 62443, NERC CIP, AMI, CMMC, NCSC CAF, CRA, FISMA, NIST 800-171, SSDF, SOX, PCI DSS,
  SOC 2, ISO 27001, privacy, sovereignty, SLSA, FinOps and others now require `is_number`; violation rules report a
  non-number as evidence missing. Type-trap tests in every changed module; the baseline shrinks to 468.

### Added — per-control findings for CIS M365 v7, RHEL 9 and Windows Server 2022 (#309)

- Every `control_results` row now carries `findings`: the messages that cite that recommendation (Windows
  includes the observed value). It is empty for passes and for out-of-profile rows.
- #310: no CIS benchmark → other-framework crosswalk ships yet, so rows carry no `mappings` field.

### Added — NIST SP 800-53 Rev 5: all 300 base controls and every High-baseline control (523 ids)

The module evaluates 523 ids (was 370): all 300 active base controls and 223 enhancements, which is every control
the 800-53B Low, Moderate and High baselines and the FedRAMP Rev 5 Low, Moderate and High baselines select
(`baseline_results`: 149, 287, 370, 156, 323, 410 evaluated, none missing). Privacy baseline: 77 of 96.

- 153 ids added in 16 families (45 base controls, 108 enhancements), from NIST's OSCAL catalog 5.2.0. Each fails
  closed, compares organization-defined values under `odp.`, guards every number; 145 are evidence-based and 8 take
  an attestation (AU-14 in part, CA-8(1), IR-9(3), SC-31, SC-37, SC-38, SC-48, SI-23).
- **Strict booleans:** 62 older rules in AU (10), CM (11), IA (10), IR (6), SC (13) and SI (12) passed on any
  truthy value (`"yes"`, `1`, `"false"`, an object). They now pass only on `true`; any other value is "evidence
  missing" and `false` keeps the rule's message. Collectors that send booleans as strings will see findings.
- `control_results` on `{}`: 475 evidence missing, 48 not attested, 0 fail. 1,216 tests in the module.
- Report lookups read the grouped findings and baseline membership once (whole-object `object.get`).

### Changed — STIG → 800-53 map: RHEL 10 and Ubuntu 24.04

- `crosswalk/stig_800_53/data.json` gains RHEL 10 V1R3 (435 rules) and Ubuntu 24.04 V1R7 (195 rules), joined from
  DISA's October 2026 compilation and CCI list (2025-01-23) with `tools/stig_generators/parse_xccdf.py` +
  `gen_crosswalk.py`; 4,437 rules (was 3,807). Every rule of the library's RHEL 10 and Ubuntu 24.04 modules now
  reaches its 800-53 controls in `crosswalk.correlation` and the OSCAL baseline coverage.
- Windows Server 2016 / 2019 stay unmapped: DISA retired both in July 2026 and their XCCDF is not in the
  compilation.
### Added — waivers: required fields, maximum time to live, expiring soon

- `governance/exceptions/waivers.rego` reads optional site settings at `data.waivers.settings`:
  `required_fields` (for example `["reason", "approver", "mitigation"]`), `max_ttl_days` and
  `expiring_within_days` (default 14). Entries may carry `mitigation` and `evidence_ref`.
- An unexpired entry that matches a finding but breaks a setting is not applied: the finding stays active and
  the entry is listed in the new `rejected` set with the reasons (`rejected_count` alongside). A malformed
  setting rejects every entry. `expiring_soon` lists applied waivers that run out inside the window.
- No settings loaded: the decision is unchanged apart from the three new, empty keys.

### Added — STIG results roll up onto NIST SP 800-53 (crosswalk.correlation)

- Every STIG report (24 platforms) gains `rule_results`: each rule's DISA status, passes included. Additive;
  `violations`, totals and percentages do not change.
- `crosswalk.correlation` reads `input.reports` (one or more STIG `compliance_report`s) as well as the older
  `input.findings`, and rolls them onto 800-53 controls: `gap`, `not_reviewed`, `satisfied`, `not_applicable`;
  unassessed controls stay absent. `summary` reports `rules_supplied` and `rules_unmapped`.
- Fixed: a `Not_Reviewed` rule (an unresolved manual review) left its 800-53 control `satisfied`; it is now
  `not_reviewed`. An unrecognised status counts as Open, and a report without facts contributes Open rules.
- Known gap: the crosswalk map predates the rule ids of the current RHEL 10, Ubuntu 24.04 and Windows Server
  2016 / 2019 modules; those rules are reported as unmapped until the map is regenerated.
### Added — NIST SP 800-53 Rev 5: every Low and Moderate baseline control

The module evaluates 370 ids (was 266): 255 base controls and 115 enhancements, which is every control the
NIST SP 800-53B Low (149) and Moderate (287) baselines select. 104 ids added in 16 families (6 base controls:
CM-12, IA-11, IA-12, SC-4, SC-22, SC-39; 98 enhancements), ids and titles from NIST's OSCAL catalog 5.2.0.
FedRAMP Moderate is now 292 of 323 evaluated, FedRAMP High 300 of 410 (`baseline_results`).

- Each new id fails closed (absent or mistyped evidence is "evidence missing"), compares organization-defined
  values under `odp.`, guards every number; 102 are evidence-based, 2 (CA-2(1), CA-7(1)) need an attestation.
  Enhancement facts nest under the base control's object; an enhancement never fails its base control.
- Existing rules in AC, AT, AU, CA, CM, IA, IR, MA, PE, SC and SI now say "evidence missing" when their facts are
  absent or the wrong type, so `control_results` no longer reports absent evidence as `fail` (on `{}`: 330
  evidence missing, 40 not attested, 0 fail). Pass conditions are unchanged; IA-7 no longer passes silently on a
  non-object fact. An absent attestation reads `not_attested`.
- Tests for AC, AU, IA, IR and SC no longer wrap `with input as` in helper functions, so those families build
  to wasm again; SI and CM gain full test files. 881 tests in the module.
- Known gap, unchanged here: about 50 older AU, CM, IR, SC and SI rules still pass on a truthy non-boolean
  (`"yes"`, `1`); making them strict changes pass conditions and is a separate change.

### Added — NIST SP 800-53 Rev 5: per-control and per-baseline results

`nist_800_53.main.compliance_report` gains three fields. Additive: no existing field, total or finding changes.

- `control_results`: one row per evaluated id (370), passes included, in natural id order (AC-2 before AC-2(1)
  before AC-10): `id`, `status` (`pass`, `fail`, `evidence_missing`, `not_attested`), `basis` (`evidence` or
  `attestation`), `baselines` (the baseline keys that select the id) and `findings`. Every family check fails
  closed, so `pass` means the evidence was supplied and met the requirement.
- `control_result_counts`: rows per status.
- `baseline_results`: for NIST SP 800-53B Low, Moderate, High and Privacy and FedRAMP Rev 5 Low, Moderate and
  High: `in_scope`, `evaluated`, `passed`, `not_passed` (+ ids) and `not_evaluated` (+ ids). Controls the module
  does not evaluate are listed as not evaluated, never assumed met; the report is still not a baseline
  authorization.
- The static half (attestation basis, natural order, baseline membership) is generated into
  `nist_800_53_index.rego` by `scripts/gen_nist_800_53_index.py` from the module itself and the committed OSCAL
  baseline profiles (`--check` reports a stale file). 11 tests in `tests/test_nist_800_53_results.rego`.
- OSCAL assessment-results asserts a control `satisfied` only from a `control_results` pass row. NIST findings now
  target their catalog statements (the orchestrator package resolves to the framework of its family packages).

### Added — NIST SP 800-53 Rev 5: all 20 control families

The NIST 800-53 module evaluated 7 of the 20 Rev 5 families. It now aggregates all 20. Thirteen new family
modules (AT, CA, CP, MA, MP, PE, PL, PM, PS, PT, RA, SA, SR) cover every active base control in their family,
157 controls, with ids and titles checked against NIST's OSCAL catalog (release 5.2.0, the same catalog the
OSCAL export uses). The module now evaluates 266 ids: 249 of the 300 base controls plus 17 enhancements. The
51 base controls still missing are in the original families (AC, AU, CM, IA, SC, SI).

- Every new control fails closed: absent evidence, null, or the wrong type is "evidence missing", never a pass.
  Booleans pass only on `true`; every numeric comparison is guarded with `is_number`.
- Organization-defined frequencies and periods compare the observed value with the organisation's ODP, as
  IR-2 and IR-3 already did.
- Organizational controls with no machine-checkable evidence (much of PM, PE and PS) require an attestation
  `{attested: true, by, date}` at `input.<fam>_controls.<name>.attestation`.
- New fact roots for collectors: `input.{at,ca,cp,ma,mp,pe,pl,pm,ps,pt,ra,sa,sr}_controls`. Each control's fact
  paths are documented above its rule. Until a collector supplies them, those controls report evidence missing.
- `compliance_report.coverage` reports 20 families, 266 ids and 249 base controls; the label "partial: 7 of 20
  families" is gone.

### Fixed — CIS Microsoft 365 v7: a control no longer passes on a missing field or a wrong shape

Nine defects found while checking the collector against the policy. Each let a control pass, or stay silent, when it should not.

- **Fail closed per field and per shape.** A collected value that is not a list, or a compared field that is absent or of the wrong type, is evidence missing for the controls that read it. Every control that is not a pass now has its own message naming its id; on empty input the module reports 160 violations (was 31) and `failed_controls == total_controls == 160`. A compliant tenant still reports 0.
- **`total_controls` and `failed_controls`** added to the main report. `controls_evaluated` and `evaluated_control_ids` now reflect the input; the static list moved to `implemented_control_ids`.
- **Attestations:** `observed` must be a boolean and `false` is a failure; only ledger ids can be attested (an attestation for any other id is a finding and changes nothing); `attested_on` must be a date that is not in the future.
- **Semantics corrected from Microsoft's documentation:** 2.1.2 / 2.1.11 read `FileTypes`; 6.3.2 reads the default OWA policy's personal-account settings; 5.1.5.1 counts only self-service permission-grant policies as user consent; 2.1.9 needs the DKIM signing configuration enabled, not only the published CNAMEs; 1.3.2 compares the timeout value; 2.4.2 needs enabled strict-preset rules; 5.1.3.4 treats an absent group setting as the permissive default; 8.2.1 reads the allow-list object Teams returns; 2.1.15 checks limits, action and notification.
- An unrecognised `unavailable` key is its own finding and is no longer attributed to a control.

**Breaking:** new fact paths (`defender.dkim_signing_configs`, `defender.atp_protection_rules`, malware-filter `FileTypes`, outbound-spam limits, timeout-policy `definition`, OWA `IsDefault` and personal-account fields) and `attestations[].observed` as a boolean; see the module README. Violation counts rise on tenants whose collector does not yet supply them.

**Count:** control-level checks fall by 76: 67 lookup-table rows had been counted as checks, 29 literal gap messages went, 20 checks were added.

### Fixed — CIS RHEL 9 / Rocky 9 / RHEL 8 / Rocky 8 / Amazon Linux 2023: audit-rule and file-sweep evidence

- A collected but empty audit-rules list fails the audit-rule controls (it was evidence missing).
- World-writable and unowned-file sweeps: files found fail whether or not the sweep finished; only "nothing found, sweep truncated" is evidence missing. An unfinished empty sweep no longer passes.

### Fixed — DISA STIG RHEL 9 V2R10: rules test what the check text tests

The external audit found `benchmarks/stig/rhel_9` id-accurate but check-inaccurate. All 104 rules were reviewed against
their full V2R10 check text: 73 changed (17 read the wrong fact, 11 were collector booleans, 13 had a wrong value or
direction, 18 were incomplete, 11 failed open, 3 mishandled Not Applicable), 31 matched. The module is now generated by
`tools/stig_generators/gen_rhel9.py` from the reviewed table `rhel9_rules.py`, with pass / fail / evidence-missing tests
per rule (621 tests). The input contract changed (new fact paths and `input.attest.<key>` attestations, listed in the
generator table); the collector must follow. `stamp_catalog.py rhel_9` is refused. The derived rhel_10 / Oracle Linux
modules are unchanged until they are regenerated.
### Added — per-control results: every control's outcome, passes included

Auditors asked for a record of what passed, not only what failed. `compliance_report` now carries `control_results`:
one object per recommendation, in id order, with `id`, `status`, `basis` (`evidence` or `attestation`), `in_scope`,
`profile` and `evidence` (the input paths the decision reads), plus `control_result_counts`.

| Status | Meaning |
|---|---|
| `pass` | evaluated from evidence and met, or attested |
| `fail` | evaluated and not met |
| `evidence_missing` | a fact the control needs was not collected |
| `not_attested` | a Manual recommendation with no attestation |
| `not_applicable` | outside the selected profile, level or role |

- **Modules:** CIS Windows Server 2016, 2019, 2022 and 2025, Windows 10 and 11; RHEL 9, Rocky Linux 9, RHEL 8 and Rocky
  Linux 8; Microsoft 365 Foundations v7. Generated at the source for the Windows and RHEL families.
- **Additive:** no existing report field or total changes. Generated tests hold the list to the benchmark's own
  enumeration (no id missing or duplicated), to `total_controls` and `failed_controls`, and to the violations; on empty
  input no control is a pass.
- **Microsoft 365:** `input.cis_profile {licence: "E3"|"E5", level: 1|2}` scopes the list (default E5 Level 2, all 160).
  The 16 controls the module does not evaluate from facts are `not_attested` until attested. Building the list showed
  that 93 controls raise no violation of their own when one of their facts is missing (the section-level message was
  the only signal); they are `evidence_missing` in the list. Five gates that let a control pass with its fact missing
  were closed (1.1.4, 1.2.2, 1.3.1, 1.3.3, 5.1.3.4).
- **Count unchanged:** the control counter skips the reporting constructs, so the headline stays at 29,297.

### Fixed — DISA STIG OpenShift 4 V2R7: every rule decided from its check text

The six controls that always reported Open (CNTR-OS-000010, 000030, 000320, 000560, 000720, 000860) are all decidable
from collectable facts and are now implemented: insecure registries in `openshift.image_config`, LDAP / OpenID identity
providers, `--loginuid-immutable`, `page_poison=1` plus the OpenShift Virtualization sharing settings, the execpriv audit
rules and NX protection, per node under `rhcos.nodes[]`. The other eight rules read collector booleans and now read what
their checks read (kernel arguments, per-node sshd and FIPS values, SCC subjects in `scc.items`, the 70 audit rules of
CNTR-OS-000930, sshd.service state). CNTR-OS-000090 is an organizational review: an attestation, Not_Reviewed until
attested, and Not_Reviewed counts as failed. Module V2R6 → V2R7, generated by `gen_openshift_stig.py`, 76 tests.

### Fixed — DISA STIG RHEL 10: V1R3, rebuilt from its own check text

`benchmarks/stig/rhel_10` moves from V1R2 to V1R3 and is generated by `gen_rhel9.py rhel_10` from `rhel10_rules.py`,
built against the V1R3 check text. 86 rules reuse reviewed RHEL 9 / OL 9 logic where the check is the same; 14 are
written from the RHEL 10 text: sshd keywords must be set first in a drop-in that sorts before 50-redhat.conf and agree
with `sshd -T` (`input.sshd_config_files`, `input.sshd_runtime`); the server MAC list must equal the check's list in
its order; fchmodat2 is audited with the chmod family; release key 4 joins the Red Hat keys; AIDE hash lines use
sha512 only; library ownership and mode cover every file the check's find lists. RHEL-10-200050, a V1R2 id absent from
V1R3, is dropped. 100 of 435 rules (was 98), 612 generated tests.

### Fixed — DISA STIG Oracle Linux 8 V2R10: rebuilt from its own check text

`benchmarks/stig/oracle_linux_8` had been derived by title from the derived Oracle Linux 9 module. Every rule was
matched against the OL 8 V2R10 check text: 62 rules reuse reviewed RHEL 9 or OL 9 logic where the check is the same,
33 have OL 8 logic written from its text. OL 8 reads audit rules from `/etc/audit/audit.rules` (new path
`input.audit_rules_file`), mounts from `/etc/fstab` (`input.fstab`, `input.home_dir_mount_points`), sshd and pwquality
settings from every file with conflicting values a finding (`input.sshd_config_lines`, `input.pwquality_values`);
the faillock rules apply to 8.2 and above (`input.os_release.version_id`) and fail_interval must be 900 or more as OL 8
words it; OCSP uses ocsp_dgst=sha1; the vendor key is the Oracle OSS group key. Six ids the derivation had attached
to another setting now read their own (sendmail package, sshd active, IPv6 source routing, OCSP status checking,
faillock fail_interval, sshd PermitEmptyPasswords). 95 of 378 rules (was 68), 587 generated tests.

### Fixed — DISA STIG Oracle Linux 9 V1R7: rebuilt from its own check text

`benchmarks/stig/oracle_linux_9` had been derived from the RHEL 9 modules by rule title and still carried the
pre-review RHEL 9 logic. Every rule the module implemented, and every reviewed RHEL 9 rule it could inherit, was
matched against the OL 9 V1R7 check text. 92 rules reuse the reviewed RHEL 9 logic where the OL check is the same
check; 22 have OL-specific logic written from the OL text (Oracle `release key 1` / `backup key 1` and their
fingerprints, `fips-mode-setup --check`, `install firewire-core /bin/true`, FIPS subpolicies and the "below 256"
hash clause, `update-crypto-policies --check && echo PASS`, gpgcheck / localpkg_gpgcheck equal to 1 only, the
sssd.conf-only smart-card and certmap facts, the dconf `removal-action` line, AIDE initialised, `systemctl cat tftp`,
banner file present, IPv6 rules with their Not Applicable clause). Eight ids the derivation had attached to
another setting now read their own (tuned package, firewalld package, sshd active, /etc/shadow and /etc/gshadow
owner, IPv6 source routing, OCSP certificate status checking, faillock fail_interval). 114 of 450 rules (was 93),
654 generated tests. The module is generated by `gen_rhel9.py oracle_linux_9` from `ol9_rules.py`; the input
contract follows the RHEL 9 one plus the OL paths listed in the table. `gen_oracle_linux.py` is retired (exits 1).

### Fixed — external audit of 2026-11-17: standards accuracy in the hand-written frameworks

An external read-only audit of `main` at `ea38b446` listed twenty findings. Each was reproduced before it was changed, and
every requirement, threshold, count or id changed here was checked against a public primary source (cited in the module).
Where a standard is licensed and its text could not be read, the module now claims less.

- **Post-quantum readiness (Critical).** The module reported compliant when the cryptographic inventory was omitted, and
  an asset whose algorithm matched neither list (`Dilithium3`) passed unseen. A missing, malformed or empty inventory is
  now a finding; every asset is classified (quantum-vulnerable, post-quantum, hybrid, symmetric or hash, known but not
  NIST-approved, unrecognised) by whole-name matching; an unrecognised name is a finding. RSA, DSA and DH below 2048 bits
  and ECC below 224 fail in every profile whatever the migration plan says (SP 800-131A Rev. 2). Algorithms that are not
  NIST-approved fail the `federal` and `nss` profiles only. The report gains `total_controls` and `failed_controls`.
- **NIST SP 800-53 Rev 5.** Withdrawn AC-15 and SC-19 no longer produce findings. AC-3 passes on any one evidenced
  access-control model. Organisation-defined parameters (AC-7, AC-11, AC-14, AU-11, IR-2, IR-3) are compared with the
  organisation's own values. Enhancements are evaluated as their own ids (SC-8(1), SC-28(1), ten AC enhancements, SC-45
  and SC-45(1)), so a base control cannot fail on an enhancement. FIPS validation is no longer hard-required here. The
  report declares what it evaluates: 109 ids (92 base controls and 17 enhancements of 1,014) in 7 of 20 families, and
  failed controls can no longer exceed the total. The label no longer says "all control families".
- **FedRAMP.** Baseline sizes corrected from the Rev 4 figures to Rev 5 (Low 156, Moderate 323, High 410). The report
  separates the baseline size from the 10 to 12 checks the module evaluates, and was undefined whenever the result was
  non-compliant. Citations and impact-level gating follow the Rev 5 profiles; RA-5 has the 30 / 90 / 180-day parameters
  and an optional known-exploited-vulnerabilities input; SHA-1 is judged by usage. Five evidence fields that passed when
  absent are now findings.
- **PCI DSS, relabelled v4.0.1.** 8.3.4 lockout is not more than 10 attempts (was 6). 8.3.9 applies only where a password
  is the sole factor and accepts dynamic analysis. Rules stricter than the standard no longer gate (a 30-day scan
  cadence, SAST/DAST, WAF rule sets, EDR, SIEM features and others); three frequencies come from the entity's targeted
  risk analysis; anti-malware log retention of 360 days no longer passes for 12 months. 8.2.8, 8.3.10.1 and 11.3.1.2 are
  added. Every numeric threshold in the family is type-checked: a string used to pass.
- **HIPAA.** Addressable implementation specifications can be met by implementing them or by a documented decision with
  an equivalent alternative (45 CFR 164.306(d)(3)). Periods, frequencies and mechanisms the regulation does not state
  (key rotation, password and session rules, TLS versions, backup cadences and many more) moved to a non-scoring
  `advisories` output that is not cited to the regulation.
- **CMMC.** Access control, configuration management and incident response fail closed when their inventories are
  missing. Practices are scored once each against one registry: 15 at Level 1 (FAR 52.204-21 ids per 32 CFR 170.14),
  110 at Level 2; Level 3 is reported as not evaluated. Eighteen hard-coded values became organisation-defined.
- **ISO/IEC 27001.** A.8.24 no longer requires a post-quantum plan or specific mechanisms (HSM storage, pinning, key
  escrow); those are advisories. Library-chosen numbers in eleven controls are compared with the organisation's values.
- **SOC 2.** The report scores Trust Services Criteria by id (12 common criteria, plus 16 for in-scope categories) and
  compares idle timeout, log retention and similar values with the entity's own commitments.
- **Tests and tooling.** Four tests that asserted `count(...) >= 0` now assert something that can fail; the smoke-test
  generator no longer treats a missing `compliant` field as fail-closed; the coverage stamp's `as_of` changes only when
  a module's numbers change and is checked; the repo-hygiene control takes its address denylist from input or data.
- **Removed.** The deprecated `cis.rhel_9` v1.0.0 module (six controls); use `cis_rhel9`.
- **Documentation.** Stale figures and versions in `docs/COMPARISON.md`, `COVERAGE.md`, `FRAMEWORKS.md`, `SCF_GAP.md` and
  `TEST_GENERATION.md` corrected. `docs/COMPARISON.md` states what the check count is and is not: a per-file measure,
  not a count of distinct requirements (CIS RHEL 9 contributes 746 and cites 352 recommendation ids).

### Breaking — inputs and report shapes changed by the audit fixes

PQC, NIST 800-53, FedRAMP, PCI DSS, HIPAA, CMMC, ISO 27001 and SOC 2 each read new inputs (organisation-defined values
and commitments, alternative-measure decisions, evidence that used to be optional) and report different totals. FedRAMP
`total_controls` now means checks evaluated, not baseline size. HIPAA, PCI DSS requirement 6 and SOC 2 report fewer
violations than before, because rules the standards do not contain no longer score. `data.cis.rhel_9` no longer
resolves. The repo-hygiene control fails when no address denylist is supplied. Each module's header lists its inputs.

### Added — Regal in CI, bugs category only

- `.regal/ci.yaml` turns every Regal category off except `bugs` and CI lints the library with it on the OPA 1.22.0 leg
  (Regal 0.36.1, pinned by checksum). The tree starts clean, so a new bug-class finding fails the pull request. The
  default `.regal/config.yaml` is unchanged and still reports every category for local use (about 28,000 findings,
  almost all style). Four hygiene rules with hundreds of existing instances are off in CI and named in the file with
  the reason; two generated patterns are excluded by path.

### Fixed — CI: the OPA 1.10.0 leg was killed before it ran the tests

- After batch 2 the runner was shut down during the per-class wasm build on the OPA 1.10.0 leg (main at `ea38b446` and
  the following pull request), so that leg's `opa test` never ran and the required check went red. The bundle build
  now runs on the 1.22.0 leg only; the round-trip and `dist/` staleness checks still run on both.

### Fixed — findings from the first full Regal run (2026-11-17)

- **SAP ABAP baseline, AUDIT-A_c.3b:** the check title carries a log-file pattern with literal percent signs, which
  `sprintf` read as verbs: the message printed `%!d(...)` fragments and lost the collected state. The importer
  (`scripts/import_sap_baseline.py`) now escapes percent signs in titles; a test fails if any message carries a
  broken verb.
- Removed two branches that only restated their rule's default (FedRAMP `total_controls` for moderate, the corporate
  90-day password age), and reworded a comment in the RHEL 9 and RHEL 10 STIG services modules that Regal read as a
  stray metadata annotation. No result changes.

### Added — sixteen CIS benchmarks rebuilt or added from their workbooks (batch 2, 2026-11-17)

Each module is generated from the benchmark's own workbook by a generator under `tools/cis_generators/` that aborts on any
count, id, status, profile or title-keyword mismatch. Every recommendation has a rule; Automated recommendations are decided
from collected facts and fail closed ("evidence missing") when a fact is absent; Manual ones are attestations unless their
audit procedure names an exact value. No benchmark text is copied.

| Benchmark | Version | Recommendations | Key / entrypoint | Was |
|---|---|---:|---|---|
| Red Hat Enterprise Linux 8 | v4.0.0 | 322 | `cis_rhel8` | hand-copied module |
| Rocky Linux 8 | v3.0.0 | 322 | `cis_rocky_linux_8` | hand-copied module (workbook identical to RHEL 8 v4.0.0) |
| Ubuntu Linux 22.04 LTS | v3.0.0 | 306 | `cis_ubuntu_2204` | hand-copied module |
| Windows Server 2025 | v2.1.1 | 428 | `cis_windows_server_2025` | new |
| SQL Server 2022 | v1.3.0 | 48 | `cis.sql_server_2022` | new |
| PostgreSQL 16 | v1.1.0 | 71 | `cis_postgresql_16` | new |
| PostgreSQL 18 | v1.0.0 | 72 | `cis_postgresql_18` | new |
| AWS Foundations | v7.1.0 | 94 | `cis_aws` | 19 hand-written controls |
| Azure Kubernetes Service | v2.1.0 | 50 | `cis_aks` | v1.8.0, 56 controls on a boolean contract |
| AKS Automatic | v1.0.0 | 33 | `cis_aks_automatic` | new |
| OpenShift Container Platform | v2.0.0 | 115 | `cis_openshift` | declared 156 controls |
| VMware ESXi 8.0 | v1.4.0 | 134 | `cis_vmware_esxi` | `cis_esxi_8`, 96 hand-written checks, no entrypoint |
| VMware ESXi 9.0 | v1.0.0 | 134 | `cis_vmware_esxi_9` | new (workbook identical to ESXi 8.0 v1.4.0) |
| Cisco IOS XE 17.x | v2.2.2 | 84 | `cis_cisco_ios_xe_17` | new |
| Apple iOS 27 | v1.0.0 | 105 | `cis.mobile.ios` | unversioned module, 24 checks |

PostgreSQL 17 was checked against its v1.1.0 workbook and already matched; the `cis_postgresql` key stays on 17. The
PostgreSQL generators now share one core (`gen_postgresql.py`).

Library size after this batch: 1,052 policies (2,388 `.rego` files including tests), 29,157 control-level checks,
36,142 tests, 190 OSCAL catalogs / 22,258 controls, XCCDF id export for 42 platforms.

### Breaking — input contract changes for collectors (batch 2)

- **`cis_aks`**: the `input.cis_aks.*` booleans are gone; the module reads `aks.cluster` (the `az aks show` object),
  `pod_security.*`, `service_accounts.unneeded_token_mounts` and the Kubernetes module's kubelet and file facts.
- **`cis_aws`**: there was no shared AWS fact contract; every path is new and is listed in the header of
  `cis_aws_foundations.rego`.
- **`cis_openshift`**: reads parsed operator configmaps and cluster resources under `openshift.*`, per-member etcd flags and
  per-node kubelet config; the old `input.openshift.master_node…` shape is gone.
- **`cis_rhel8`, `cis_rocky_linux_8`, `cis_ubuntu_2204`**: the audit-rule recommendations require the rule in both the
  on-disk rules (`auditd.rules`) and the running rules; RHEL 8 also needs `sshd -T` output evaluated with the crypto-policy
  options. New paths are listed in each module's README.
- **ESXi**: package `cis_esxi_8` is replaced by `cis_vmware_esxi` with a `.main` entrypoint and facts under `input.esxi`.
- **iOS**: `input.device_config` is replaced by `input.ios_profile` (configuration-profile payload keys, checked against
  Apple's device-management schema).
- **Cisco IOS XE**: `input.ios_xe_config` carries top-level lines, sections and banner text.

### Fixed — defects found while building batch 2

- **OpenShift**: the module reported the larger of 156 and the finding count; it now reports the 115 recommendations of
  v2.0.0. The default namespace allows exactly the two platform Services the audit names. Component flags match either
  the hyphen or the underscore spelling, so `--bind_address` no longer slips past a check written for `--bind-address`.
- **AWS Foundations**: 4.2 and 4.5 fail when the account has no CloudTrail trail (they passed with nothing to check).
- **Apple iOS**: the Safari cookie recommendation accepted the unrestricted setting and rejected "websites visited"; the
  lock-screen notifications check read a key Apple does not define.
- **Windows Server 2016, 2019, 2022 — deny rights (fail-open).** The member-server control "Deny log on through Remote
  Desktop Services" (2016 2.2.27; 2019 and 2022 2.2.26) is stated as an exact list, and the shared derivation read that as
  "only these principals", so a host that denied no one passed. Every named principal must now be denied; denying more is
  allowed. Each generator pins the ids this rule may affect and aborts on any other.
- **Windows Server 2016, 2019, 2022 — zero passed two thresholds.** The security log warning threshold (2016 18.5.12;
  2019 and 2022 18.5.11) accepted 0, which generates no warning. The LAPS password age (2016 18.3.6; 2019 and 2022
  18.9.26.6) accepted 0, which is outside the configurable range.
- **RHEL 9, Rocky 9 — audit log group (6.2.4.4)** accepted group `audit` and an unset `log_group`; both the file group and
  `log_group` must be root or adm.
- **RHEL 9, Rocky 9 — log file access (6.1.3.1)** lacked the service-account and package-manager classes of the v3.0.0
  table (a 0644 `dnf.log` failed wrongly; a service-account log was not classed). README, SSSD and gdm logs are no
  longer special cases.
- **Audit rules were checked in the running rule set only** on RHEL 9, Rocky 9, Amazon Linux 2023, Ubuntu 24.04 and 26.04,
  Debian 12 and 13 and SUSE 16, and several syscall checks ignored architecture. Each rule is now required on disk and
  running where the audit procedure reads both, and for b32 and b64 exactly where the procedure names both.
  RHEL 9 6.2.3.10 requires an execution rule with both auid filters for every privileged command.

### Breaking — audit-rule facts (RHEL 9 family, Ubuntu, Debian, SUSE, Amazon Linux 2023)

`auditd.rules` (the lines of `/etc/audit/rules.d/*.rules`) must be collected separately from `auditd.active_rules`
(`auditctl -l`). A collector that supplies only the running rules now gets "evidence missing" on the audit-rule
recommendations; one that fills both from the same text passes without proving the on-disk state. RHEL 9 and Rocky 9
6.1.3.1 also read `log_file_permissions.analysis[].owner_has_login_shell` and `.owner_primary_group`.
`examples/rhel9/facts.json` carries on-disk and 32-bit rules to match and still reports 25 of 352 controls failing.

### Added — ten CIS benchmarks rebuilt or added from their workbooks (batch 1, 2026-11-14)

Every module below is generated from the CIS workbook by a script in `tools/cis_generators/`. Each generator aborts on
any mismatch with the workbook in recommendation count, id, Automated/Manual status, profile or title keyword, writes
only files it generated, and carries no CIS text (ids and status only; our own wording). Automated recommendations are
decided from collected facts and fail closed with an "evidence missing" finding; judgement items are attestations.

| Module | Benchmark | Recommendations | Replaces |
|---|---|---|---|
| `benchmarks/cis/rocky_linux_9/` | CIS Rocky Linux 9 v3.0.0 | 352 | a copy of the Rocky 8 module |
| `benchmarks/cis/ubuntu_24_04/` | CIS Ubuntu Linux 24.04 LTS v2.0.1 | 332 | a copy of the Ubuntu 22.04 module |
| `benchmarks/cis/debian_12/` | CIS Debian Linux 12 v2.0.1 | 331 | new (`cis_debian_12`) |
| `benchmarks/cis/debian_13/` | CIS Debian Linux 13 v1.1.1 | 350 | new (`cis_debian_13`) |
| `benchmarks/cis/amazon_linux_2023/` | CIS Amazon Linux 2023 v1.0.0 | 243 | a six-control sample |
| `benchmarks/cis/kubernetes/` | CIS Kubernetes v2.1.0 | 134 | v1.10.0 label, under ten rules |
| `benchmarks/cis/docker/` | CIS Docker v1.9.0 | 117 | v1.8.0 label, a handful of rules |
| `benchmarks/cis/azure/` | CIS Microsoft Azure Foundations v7.0.0 | 128 | v3.0.0, far fewer rules than declared |
| `benchmarks/cis/network_devices/palo_alto/` | CIS Palo Alto Firewall 11 v1.2.1 | 79 | a handful of rules |
| `benchmarks/cis/windows_server_2016_modular/` | CIS Microsoft Windows Server 2016 v4.0.0 | 422 | `benchmarks/cis/windows_server_2016/` (about 45 checks), removed |

Framework keys and `.main.compliance_report` entrypoints are unchanged for every replaced module. Rocky Linux 9 and
RHEL 9 v3.0.0 are identical benchmarks, so `gen_rocky_linux_9.py` configures `gen_rhel_9.py` and aborts if the two
workbooks ever diverge. Debian 13 v1.1.1 and Ubuntu 26.04 v1.0.0 have the same 350 ids and titles and differ in one
audit procedure (6.2.3.2), so `gen_debian_13.py` overrides only that rule.

### Breaking — input contract changes for collectors

Replaced modules read new facts. Until a collector supplies them, those controls report "evidence missing" (they fail
closed; they never pass). New fact paths per module:

- **Ubuntu 24.04, Debian 12** (on top of the Ubuntu 26.04 contract): `initial_setup.motd_extra_files[]`,
  `ssh.openssh_version`, `packages.sudo-ldap`, `sudo.default_timestamp_timeout`, `netplan.dir_exists` (Ubuntu) /
  `auditd.netplan_dir_exists` (Debian); `auditd.tools` must include all six tools, `autrace` among them.
- **Amazon Linux 2023** (on top of the RHEL 9 contract): `firewall.nft_ruleset_raw`, `firewall.default_zone`,
  `ssh.crypto_policy_override_raw`, `pam.su_config_raw`, `pam.libuser_conf_raw`, `user_group.group_members`,
  `user_group.shadow_entries[].min_days`, `user_group.home_dotfiles[]`, `cron.{cron,at}_{allow,deny}_*`,
  `boot_security.kernel_args`, and `services["rpcbind.socket"]` / `services["systemd-journal-remote.socket"]` (Ansible's
  `service_facts` does not list socket units). The legacy `cis.amazon_linux_2023.compliance_summary` view the product's
  assessment playbook calls is kept and agrees with `.main`.
- **Kubernetes** (on top of the Kubernetes STIG contract): `api_server.authentication_config`, `etcd.member_count`,
  `kube_proxy.{flags,config}`, `files.{cni,kubelet_service,kubelet_config_dir}`, `service_accounts.default[]`,
  `network_policies.namespaces_without_policy[]`, `collection_status.{default_service_accounts,network_policies}`.
  Profile: `input.cis_profile.{level,role}`.
- **Docker**: everything under `input.docker` (docker info and version, effective daemon settings, inspect lists for
  networks, containers and images, daemon file ownership and modes, swarm state, `docker.policy`), plus the shared
  `auditd.active_rules[]`. Profile: `input.cis_profile.{level,swarm}`.
- **Azure**: per-service resource lists (identity and role assignments, diagnostic settings and alerts, NSGs,
  application gateways, Front Door, network watchers and flow logs, Defender pricings and contacts, VMs, Key Vaults with
  keys/secrets/certificates, Managed HSMs, Bastion, public IPs, storage accounts). None of the v3 paths is read.
- **Palo Alto**: `input.panos_config` is `show config running` converted to JSON, plus `licenses[]` and the operator
  lists `site.{untrusted_zones,internet_zones,url_block_categories}`. The old `mgt_config.users.entry` shape is not read.
- **Windows Server 2016**: the 2019/2022 modular contract (`registry`, `registry_users`, `audit_policy`, `secedit`,
  `attestations`, `cis_profile`). The product names the old directory in three places, which must point at
  `benchmarks/cis/windows_server_2016_modular` in the PR that bumps the library pin: `ansible/vars/framework_catalog.yml`,
  `ansible/playbooks/seed_framework_catalog.yml` and `ansible/playbooks/load_opa_policies.yml`. The framework key
  `cis_windows_server_2016` and its entrypoint are unchanged. No other product file reads a removed package; the
  Amazon Linux 2023 playbook's legacy `cis.amazon_linux_2023.violations` and `compliance_summary` paths still resolve.
- **Known naming drift, to settle before the collector is written:** Ubuntu 24.04 reads `netplan.dir_exists` and
  Debian 12 reads `auditd.netplan_dir_exists` for the same fact.

### Fixed — generators no longer delete files they did not write

- The CIS Windows generators removed every `.rego` in their directory before writing, which would have deleted the
  framework-key bridges `cis_windows_2019_key_main.rego` and `cis_windows_2022_key_main.rego`. They now delete and
  overwrite only files whose header names the generating script, and abort rather than touch anything else
  (`gen_windows_server_2022.py`, `_2019.py`, `_2016.py`, `gen_windows_10.py`, which Windows 11 reuses). Every generator
  in this batch follows the same rule.
- CIS Azure 9.2.4 accepts a TLS 1.3 storage minimum (it required exactly TLS 1.2).
- The XCCDF section export accepted bare recommendation numbers only from modules on a workbook-verified list,
  so five replaced platforms dropped out of it; the ten workbook-generated directories are now on the list (33
  platforms, 7,047 sections, was 29).
- `cis_debian_12` and `cis_debian_13` are in `tests/framework_keys/test_keys.rego`, so the per-key report contract
  covers them.

### Added — a first run that scans something real

- `examples/rhel9/facts.json`: facts for one fictional RHEL 9 web server that the CIS RHEL 9 benchmark evaluates
  to a mixed result (352 controls, 327 pass, 25 fail for ordinary reasons such as root SSH login, a short
  password length and an unscheduled AIDE check). The README's first command now evaluates it; the no-facts
  fail-closed run comes second. `examples/rhel9/check.sh` asserts the exact result so the sample cannot rot.

### Fixed — site figures, search metadata, FedRAMP page

- The homepage said 864+ policies because nothing ran its generator; `build_site.py` now runs it and takes every
  figure from the counted metrics. Every page carries a canonical link, Open Graph and Twitter tags; the
  homepage carries SoftwareSourceCode structured data; the sitemap has a date per page; FedRAMP has a standard
  page; the footer links the public AAC repository and `llms.txt`. `llms.txt` gains a quickstart, the
  entrypoint convention, the report fields and the bundle reference. Gatekeeper package metadata restamped to
  2.5.0.

### Fixed — metadata vocabulary covers SUSE 16, OPNsense and Intune Defender Antivirus

- `scripts/metadata_vocabulary.json` gains the domains `suse`, `opnsense`, `endpoint`, `intune` and `antivirus`,
  which 28 modules already used; `make metadata` now fails only on the two `enforcement/git/` files that have
  no METADATA block (a protected path, left for an approved commit).

## [2.5.0] - 2026-11-13

The November 2026 freshen-up: formatting sweep, every framework key resolves fail-closed and reports `total_controls` and `failed_controls`, a line-by-line semantic review of the 690 modules never reviewed (172 defects fixed, generators corrected at the source), DISA STIGs on the October 2026 library (RHEL 8/9/10, Ubuntu 22.04/24.04, Amazon Linux 2023, SLES 15, Windows 11, Server 2016/2019/2022/2025), CIS Windows 10/11 Enterprise, CIS Apache 2.4 v2.4.0, CIS MCP Server complete, SAP Security Baseline, AS9100D, the standards-registry sweep, regenerated exports. Entries below were collected under Unreleased since 2.4.2.

### Fixed — line-by-line semantic review of the 690 modules never reviewed (2026-11-13)

Seventeen reviewers read every policy module outside the October review (691 files, about 206,000 lines); 518
were clean. Of 186 findings, 172 were reproduced with a probe and fixed, each with a regression test (463 new
tests); the rest are recorded as decisions. Rules now fail closed: a control whose evidence is missing raises
an "evidence missing" finding. Counted checks rise from 23,776 to 24,009, almost all of it those rules.

- **CIS Linux.** SSH timeouts no longer accept 0 (RHEL 8, Rocky 8/9, Amazon Linux 2023, Ubuntu 20.04 to 24.04,
  Debian 11); the mail-agent local-only check treats 127.0.0.1 as loopback and 0.0.0.0 as open, and the rsyslog
  remote-receive check matches `imtcp` loaded with parameters (RHEL 9, SUSE 16, Ubuntu 26.04); the RHEL 8
  sudoers include-directory check can match; Ubuntu 22.04/24.04 and RHEL 8 apply the Level 2 profile;
  `failed_controls` counts distinct control ids in nine legacy mains.
- **CIS other.** Kubernetes 2.1, Docker 3.1 and PAN-OS 3.1 fire on either wrong value; Kubernetes file modes are
  compared as octal bits; Azure, AWS and Microsoft 365 checks fail closed on missing fields; Entra 5.2.2.3 and
  5.2.2.8, SharePoint sharing and Teams 8.5.8 corrected; Windows 10/11 "Disabled or Not Installed" service rows
  accept an absent service; Windows Server 2016 and the legacy 2022 module fail closed.
- **DISA STIG, Windows.** Legal-notice rules require a non-empty banner instead of comparing to placeholder text;
  polluted registry paths cleaned (four Windows 11 rules, one Server 2016 rule); multi-line values parsed, which
  corrects AllowTelemetry, DODownloadMode and ConsentPromptBehaviorAdmin. Fixed in `gen_windows.py`.
- **DISA STIG, Linux and databases.** RHEL 8/9/10 CAT I rules fail closed on missing facts; RHEL 10 `compliant`
  means no open finding at any category (`cat_i_compliant` is separate); ClientAliveCountMax 0 no longer passes;
  RHEL 8 ciphers and MACs must all be in the approved set. Oracle Linux 8/9: seven rules that decided on an
  unrelated setting now read the setting their title names. Provisional until rebuilt from DISA's XCCDF; twelve
  more rules there are flagged. OpenShift 4: six controls with no matching fact report Open.
- **Federal.** FedRAMP treats a missing impact level as a finding and runs the Moderate/High checks; eight CMMC
  domain files can no longer be compliant while a practice fails; NIST 800-53 AC-15/16/21/23/24/25 have
  violation rules; NIST 800-171 `failed_controls` counts distinct requirements.
- **Privacy, management, financial.** GDPR `compliant` covers all computed controls; HIPAA audit retention is
  2,190 days, TLS below 1.2 fails, numeric thresholds fail closed; SOC 2 produces its report on a failing run;
  PCI DSS `compliant` agrees with the overall flag; CIS Controls 15.3/15.4 are IG2; ISO 27001 weak-algorithm
  matching is normalised.
- **Critical infrastructure.** NERC CIP: a high- or medium-impact system with no ESP, PSP, access-point,
  physical-control or personnel records is not compliant, CIP-002/014/015 findings are listed, and records
  without an id keep their violation. IEC 62443: empty input scores 0 of 51 SRs (was 32). AMI, CRA, digital
  sovereignty and CFR Part 11 corrections.
- **Governance and enforcement.** A disabled AI system is denied; GEISA API checks fail closed; waiver matching
  respects control-id boundaries; provider sources must be https; crypto-miner and Ansible findings are no
  longer dropped when a name is missing.

### Fixed — generators reproduce the fixes (root cause)

- The defects above that sat in generated modules came from the generators' logic tables and templates, and a
  patched output is undone by the next regeneration. `gen_rhel_9.py`, `gen_suse_16.py`, `gen_ubuntu_26_04.py`,
  `gen_windows_10.py`, `gen_windows_11.py` (with `windows_lib.rego.tmpl`) and `tools/stig_generators/gen_windows.py`
  were fixed and re-run against their sources: each now reproduces the committed module. `import_sap_baseline.py`
  gains a per-check override table that aborts if SAP's upstream condition changes; both Oracle generators emit
  the corrected 6.1.2. Regression tests the generators would have deleted are emitted by the generators.
- Known and not yet fixed: the CIS Windows Server 2019/2022 generators delete every `.rego` in their directory,
  including the framework-key bridges, and `gen_oracle_linux.py` still derives rules by title.

### Fixed — six framework-key bridges dropped every finding (semantic review 2026-11-13)

- `cis_rhel10`, `cis_ubuntu_2004`, `cis_ubuntu_2204`, `cis_ubuntu_2404`, `cis_windows_2019` and `cis_windows_2022`
  read `compliant` and `violations` from their target package, which only defines them inside
  `compliance_report`. With facts supplied the bridged report showed `violations: []`, `violation_count: 0` and
  `compliant: false`, whatever the host looked like. They now read the target report's fields, and
  `tests/framework_keys/test_keys.rego` asserts each one carries its target's findings.

### Fixed — checks that passed silently when their evidence was missing

- In Rego `not f(input.missing)` is undefined, not true, so the rule never fires. All 164 such sites were
  classified by whether their control raises a finding on empty input: 59 were guarded by an evidence-missing
  rule, 39 sit in pass predicates that already fail closed, and 68 were silent. Those 68 now read the fact with
  `object.get` and fail closed: the auditd boot-parameter and log-retention checks (4.1.1.3, 4.1.1.4, 4.1.2.1,
  4.1.2.3) in CIS RHEL 8, Rocky 8/9, Amazon Linux 2023 and Ubuntu 20.04/22.04/24.04; rsyslog file-create mode
  and sudoers mode in Debian 11, RHEL 8 and Ubuntu 24.04; CIS OCI 1.4 and 1.5; five CIS Windows Server 2016
  advanced-audit entries; and the SLSA gate, where a verified signature with no signing identity, or
  provenance with no builder id, raised nothing.
- `csa_ccm` and `ncsc_caf` carried a hardcoded empty `violations` list, so a failing run stored no findings.
  csa_ccm now lists the sixteen domain modules' findings and ncsc_caf one finding per contributing outcome
  that is not achieved.

### Fixed — every framework key reports failed_controls, never above total_controls

- `total_controls` stays the control count. Findings can outnumber controls (fail-closed and input-contract
  notices are findings, not controls), which is why 32 keys showed more findings than controls on empty input.
  The 55 keys that had no `failed_controls` now report one, capped at `total_controls`; the other 35 already did.
  Consumers derive passed = `total_controls` - `failed_controls`, not total minus the finding count.
- `tests/framework_keys/test_keys.rego` asserts a numeric `failed_controls` between 0 and `total_controls` for
  all 90 keys. This closes the item left open under the `total_controls` entry below.

### Fixed — every framework key reports total_controls and a violations list

- The product's generic assessment playbook refuses a report without `total_controls` and derives
  passed = total - failed from it. Nineteen of the 90 framework keys returned a report without it (the ten
  `#275` bridges plus as9100d, digital_sovereignty, fisma, gdpr, hipaa, pci_dss, soc2, sox and tsa_pipeline),
  and gdpr, pci_dss and sox had no `violations` list at all, so a failing run stored zero findings. Every key
  now carries a numeric `total_controls` (the module's control universe, never below the finding count, the
  pattern #286 set for the AMI keys), a `violations` array and `violation_count`; the fail-closed default
  reports count as one control with one finding. gdpr and pci_dss name the failing module or requirement;
  hipaa lists every part's findings against the sum of the parts' control totals; sox lists the six sections'
  findings against its 35 attested checks; tsa_pipeline's `total_requirements_evaluated` is now the real
  rule count (153; the literal 112 was below the 129 findings an empty run raises).
- `tests/framework_keys/test_keys.rego` asserts the contract for every key on empty input, so a key that
  drops `total_controls` or `violations` fails CI by name. Still open: 32 keys (every STIG key, by its two
  input-contract notices; ccpa, eu_ai_act, iso27001, nist_800_171, swift_csp and others by more) raise more
  findings than their declared `total_controls` on empty input, so passed = total - failed goes negative
  there; flooring those modules at the finding count is the next change, after which the test gates it.

### Fixed — AMI framework-key bridges (#286)

- `ami_device`, `ami_headend` and `ami_nist_ir7628` carry `total_controls` (16 per device, 19, 32; floored at the finding
  count) and `ami_device.main` reads the module's `all_violations`, so a tampered meter no longer reports
  `compliant: false` with an empty findings list.

### Changed — README rewritten for people

- The front page is now 120 lines: what the library is, a two-minute try-out that shows the fail-closed result,
  how the entrypoint and report work, the eight-row inventory, a "find your way in" table and the links out. The
  framework coverage table and the CIS, IEC 62443, TSA and NERC-CIP sections moved unchanged to
  `docs/FRAMEWORKS.md`; the directory tree and loading options to `docs/TAXONOMY.md`; the list of other
  Rego projects to `docs/COMMUNITY.md`. Every figure CI checks stays on the page.

### Changed — generated site pages and converter exports caught up with main

- `scripts/build_site.py`, `make oscal`, `make crosswalk`, `make xccdf` and the Gatekeeper `build.py` were re-run so
  the committed site (new STIG and AS9100D pages, sitemap, llms.txt), the OSCAL/crosswalk dists and the Gatekeeper
  template match the modules on main; `make check-converters` passes again.

### Fixed — AS9100D evidence validation (external review, 2026-11-11)

- **Malformed, empty or incomplete evidence never counts as a pass** in `frameworks/management/as9100d/`. The
  review found four defects, all reproduced before the fix: (1) calibration and corrective-action rows passed with
  missing or unparseable dates (`{"id": "x"}` alone, `calibration_due: "bad"`, an open corrective action with no
  `due_on` all gave 70/70); (2) KPIs with no target were skipped (value 0, no target: 70/70); (3) empty records
  counted as evidence (blank traceability ids/serials, `validated: true` with no id or date, a baseline with an
  empty `approved_by`); (4) empty lists passed the sibling rows (no suppliers still passed 8.4.2/8.4.3, no
  measuring equipment 7.1.5.2, no nonconformances 8.7.2, no corrective actions 10.2.2). Now every required field
  is tested through `object.get`: absent, null, blank, wrong-typed or (for dates) unparseable values are evidence
  missing and the row fails naming the field; ids must be non-blank and unique within their list; dates parse and
  compare numerically; KPI targets are required and numeric; list rows need at least one record. A period with no
  nonconformances or corrective actions is declared, not implied: `nonconformance.none_occurred: true` /
  `corrective_actions.none_occurred: true` plus the row's attestation (`8.7.1`/`8.7.2`, `10.2.1`/`10.2.2`);
  the declaration alongside records is a contradiction. Suppliers and measuring equipment have no such case.
- **Coverage and wording.** 8.3.4.1 (design and development verification and validation testing, aerospace
  addition) is its own attested row; clause 9.1.2 keeps its single clause id and is decided two ways — on-time delivery
  and conformity KPIs from evidence, and customer feedback, complaints and corrective-action requests attested
  under `attestations["9.1.2"]` (a `9.1.2-feedback` companion id was tried and dropped: consumers expect real
  clause numbers). "Within the past year" is the twelve months ending on `as_of` via `time.add_date` (the same
  calendar date one year earlier counts; a 365-day count failed the exact anniversary across a leap day).
  The module header states the grouped model (7.5.3.1/.2 under 7.5.3, 8.2.3.1/.2 under 8.2.3), the past-year
  rule, the `none_occurred` keys, and that the exports' 88 controls are the 71 rows plus 17 template controls. `attestations: false` (or any non-object) now carries the contract violation
  in the report; an `as_of` that does not parse is a contract violation. 71 rows (18 fact, 53 attested);
  258 tests (43 new, one per finding and sub-case, each asserting the row fails and the message names the path).

### Added — SAE AS9100D aerospace quality management (`frameworks/management/as9100d/`)

- **First industry QMS standard in the library.** SAE AS9100 Rev D (IAQG 9100:2016, built on ISO 9001:2015) at
  clause granularity: **71 rows** across clauses 4–10 in seven self-contained clause packages (`as9100d.context`,
  `.leadership`, `.planning`, `.support`, `.operation`, `.performance`, `.improvement`) rolled up by `as9100d.main`
  at `/v1/data/as9100d/main/compliance_report`. Every aerospace addition is a row: 8.1.1 operational risk
  management, 8.1.2 configuration management, 8.1.3 product safety, 8.1.4 counterfeit parts, 8.3.4.1 verification and validation testing, 8.4.1–8.4.3 external
  providers and flow-down, 8.5.1.1 equipment/tools/software, 8.5.1.2 special processes, 8.5.1.3 first article
  inspection, 8.5.2 traceability, 8.5.3 customer property, 8.5.6 control of changes, 8.6 release, 8.7 nonconforming
  outputs, 9.1.2 on-time delivery and conformity, 9.2 internal audit, 9.3 management review, 10.2 root cause and
  human factors, 10.3 continual improvement. **18 rows are decided from evidence** AAC already collects
  (configuration baselines and drift dispositions, approved change records, SBOM/provenance against approved
  sources, supplier register with status, past-year performance review and flow-down acknowledgement, lot/serial
  traceability, validated tooling and software, calibration register with no overdue due dates, nonconformance
  dispositions incl. customer authorization for use-as-is/repair, corrective actions with root cause, human factors
  and overdue tracking, audit and management-review dates within the past year, OTD/conformity KPIs against
  targets); **53 are attested** (`input.as9100d.attestations["<clause>"] == true`; `input.as9100d.as_of` pins the
  date). Fail-closed: empty input fails all 72 rows with an explicit reason (`not attested` / `FAIL-CLOSED: no
  evidence at input.as9100d.<path>`), unknown clause ids and a non-object attestations container are flagged, and a
  clause module missing from the store is itself a violation. Clause numbers and short titles only — AS9100D and
  ISO 9001 are licensed and no requirement text is reproduced; sources in the module header. 258 tests (one pass
  and one fail case per row, evidence-missing and failing-evidence cases per fact row, full fixture, empty input,
  report shape, roll-up, framework key). Vocabulary: source `sae`, domains `aerospace` and `quality`. Registry row
  added: the successor is renamed IA9100 and follows ISO 9001:2026 (published 2026-09-16), no publication date yet.

### Changed — CIS Apache HTTP Server 2.4 Benchmark v2.4.0 (`benchmarks/cis/apache/`)

- **Rebuilt from the CIS workbook.** v2.3.0 is deprecated upstream (v2.4.0, October 2026). The previous module was
  hand-written with its own numbering: 142 checks over 8 invented sections (1.1 "installed from source", a section 1
  that duplicated section 3, ids such as 5.22 / 6.16 / 7.14 that the benchmark does not have). The module is now
  generated by `tools/cis_generators/gen_apache.py` (the `gen_nginx.py` pattern, shared `cis_genlib.py` emitter) from
  `dump_workbook.py` output: all **86 recommendations** (57 Level 1, 29 Level 2), ids, levels and Automated/Manual
  status read from the workbook, titles rewritten by `neutralize.py`. 6 judgement recommendations (1.1, 1.2, 1.3, 2.1,
  4.2, 5.13) are attestation booleans under `input.apache.attest`; the other 80 (43 Automated plus 37 Manual whose
  audit is a directive, permission or probe comparison) are decided from collected facts and fail closed with an
  evidence-missing message. Sections 11 (SELinux) and 12 (AppArmor) are selected by `input.apache.platform.mac`;
  absent means both apply. The package `cis.apache_2_4` and its entrypoints (`compliant`, `violations`,
  `compliance_report`, `findings`) are unchanged; the input contract is new and documented in the module header
  (directives as `{name: [values]}`, one entry per `<Directory>`, `httpd -M` module list, permission and probe facts).
- Tests: 292 (265 generated: pass, fail and evidence-missing per recommendation, plus applicability, proxy exception
  and 25 helper tests re-pointed from the 2026-10-17 regression file), up from 30 across two files.
- `STANDARDS_UPDATE_REGISTRY.md` gains a CIS Apache row; `tools/cis_generators/README.md` documents the generator.

### Added — CIS MCP Server Benchmark v1.0.0 sections 6, 8 and 9 completed

- The three sections were written from a partial PDF with bare `true` attestations. Checked against the CIS workbook
  (55/55 ids, levels and Automated/Manual status match), the seven Manual recommendations whose audit procedure
  confirms several components separately now take the structured attestation the other sections use
  (`_parts`, every part true, a bare `true` is rejected): 6.1 (4 parts), 6.3 (4), 8.1 (3), 8.2 (4), 8.3 (4),
  9.1 (5), 9.3 (5). The Automated checks 6.2 (secret scan, inline manifest secrets) and 9.2 (sentinel probes,
  MAC profile, denial logging) already matched the workbook audit and are unchanged. 21 new tests
  (bare-true rejected, each part required, pass per recommendation). `STANDARDS_UPDATE_REGISTRY.md`: the CIS MCP
  row is no longer PARTIAL.

### Removed

- `benchmarks/cis/web_servers/apache/` (`cis.server.apache`, `cis_web_servers`): a legacy hand-written Apache module
  that duplicated `benchmarks/cis/apache/` with 37 checks and no benchmark ids. Nothing in the repository referenced
  its package. `benchmarks/cis/web_servers/mysql/` stays.

### Changed — standards registry November 2026 sweep; CIS Controls citations harmonised to v8.1

- `STANDARDS_UPDATE_REGISTRY.md` v1.1 (2026-11-11): every row checked against its watch source. All eight
  "verify" flags cleared with the confirmed cadence (800-53 patch releases, ISO 27001, SOC 2 points of focus,
  IEC 62443 per-part, AI RMF profiles, HITRUST, TISAX ×2). Six "pending" rows had already shipped in 2.3.x–2.4.x
  and now say so (CISA CPG #179, EU AI Act #175, DORA #177, NY DFS #176, ITAR #178, FedRAMP 20x #180). Rows
  that moved: **CMMC** — Phase II (was 2026-11-10) suspended by DoW on 2026-07-13, no outcome yet; **COBIT 7**
  launch slipped from 2026-10-27 to "November 2026" (#194 stays open); **SWIFT CSP** — module pins CSCF v2024,
  upstream v2026 (attestation due 2026-12-31) and v2027 published; **HITRUST** — module v11.3.0, upstream v11.9.0
  (2026-09-24), v11.0–11.3 decommissioned; **TISAX** — module ISA 6, upstream VDA ISA2027 (applies to orders from
  2027-01-01); **MITRE ATLAS** v2026.10; **SCuBA** ScubaGear v2.0.0; **NERC CIP** CIP-003-9 / CIP-012-2 effective,
  CIP-015-2 approved 2026-08-10; **CIS** Sep/Nov 2026 releases (Kubernetes v2.1.0, Docker v1.9.0, AWS v7.1.0,
  AKS v2.1.0, ESXi 9, IOS XE) against the directory pins; **CIS EKS** row corrected to the v2.0.0 the module
  carries; **NIST SP 800-53** r5.2.0 (2025-08-27) additions noted as not yet in the module; **DPDP** Rule 4 in
  force 2026-11-13; **UK DCC** ISN 2026/01–02 and the 2026-12-31 L0 ask; **NIS2** CJEU referrals (2026-07-08);
  **EU AI Act** new Art. 5 prohibitions apply 2026-12-02. Rows added for **CIS Controls v8.1** and the **SAP
  Security Baseline v2.6**. None of the modules named above changed in this PR; the behind-upstream ones have no
  issue yet. The CIS MCP §6/8/9 PDF and the Cyber AI Profile public draft remain pending upstream.
- **CIS Controls citations harmonised to v8.1** (June 2024, the current release; v9 has no date). The 18
  `frameworks/management/cis_controls_v8/c*.rego` violation messages read "CIS Controls v8 %s (IG%d)" while the
  METADATA titles, the orchestrator's `framework` string and the safeguard tables were already v8.1; the four
  `governance/estate_continuity` messages that cite safeguards 1.1/1.2 and three docs
  (`docs/CONTROL_CORRELATION_PATTERN.md`, `docs/FRAMEWORK_ROADMAP.md`, `converters/exports/oscal/README.md`)
  likewise. Package names (`cis_controls_v8`) and directory names are unchanged; OSCAL `dist/` regenerated (which also
  picks up four "turned on on" → "turned on for" message fixes from #269 that the committed dist had missed:
  CIS Azure, FortiGate, OCI ×2 — and, after merging main, the seven `compliance_report` exposures from #275).

### Added — CIS Windows 10 Enterprise v5.0.0 and Windows 11 Enterprise v5.1.0, rebuilt from the CIS workbooks

- `benchmarks/cis/windows_10_modular/` (package `cis_windows_10`): all **501** recommendations of the Windows 10
  Enterprise v5.0.0 benchmark -- 499 evaluated from facts, 2 Manual (1.2.3, 2.3.11.6) by attestation; 337 Level 1,
  102 Level 2, 49 BitLocker and 13 Next Generation Windows Security (the last two opt-in through
  `input.cis_profile`). `benchmarks/cis/windows_11_modular/` (package `cis_windows_11`): all **535** recommendations
  of Windows 11 Enterprise v5.1.0 -- 533 evaluated, 2 Manual (1.2.3, 2.3.11.5); 373 Level 1, 117 Level 2, 45
  BitLocker. Both are generated by `tools/cis_generators/gen_windows_10.py` / `gen_windows_11.py`, the Windows
  Server 2022 generator with the workstation profile model (level, bitlocker, next_generation; no server role),
  on the same fact contract as the Windows Server modules (`registry`, `registry_users`, `audit_policy`,
  `secedit`, `attestations`). Per recommendation: registry checks derived from the audit procedure with the
  operator from the title (Windows 10: 396 single, 9 multi-value, 4 must-not-exist, 11 per-user, 1 numbered-values
  key; Windows 11: 430 / 9 / 4 / 11 / 1), 38 user rights, 27 audit subcategories, 13 secedit account-policy and
  security-option keys per benchmark. Fail-closed `main.compliance_report` entrypoint; a recommendation whose input
  was not collected is not assessed and counted as failed. 1,544 and 1,645 generated tests (a compliant
  workstation per benchmark, every recommendation broken in turn, every input removed in turn, profile scopes
  against the workbook counts). `check_cis_ids.py` and `check_cis_coverage.py` pass against the two new
  keyword-digest enumerations.

### Removed — the superseded single-file Windows 10 (v4.0.0, 11 checks) and Windows 11 (v5.0.1, 210 of 267) modules

- `benchmarks/cis/windows_10/` and `benchmarks/cis/windows_11/` (packages `cis_windows_10` -- the name is reused by
  the new module with a different contract -- and `cis.windows_11`). Nothing in this repository or in the
  compliance repo's playbooks referenced either package; the OSCAL, crosswalk and XCCDF exports, the site index,
  the coverage scan and the README counts are regenerated. Consumers of the old `cis_windows_10` package move to
  `cis_windows_10.main.compliance_report` with the Windows Server fact shape.

### Changed — Windows STIGs refreshed to the October 2026 DISA library

- `benchmarks/stig/windows_11` V2R8 → **V2R11** (30 Sep 2026): 117 of 257 rules generated (was 102 of 256; WN11-SO-000080
  left the catalog, 16 rules are new or newly derivable). `windows_server_2022` V2R9 → **V2R11**: 103 of 277 (was 104 of 279;
  WN22-SO-000140 left). `windows_server_2025` V1R2 → **V1R4**: 94 of 291 (was 95 of 292; WN25-SO-000140 left; WN25-DC-000320
  moved under an unchanged title — the check now reads `LDAPServerEnforceIntegrity = 1`, not `LDAPServerIntegrity = 2`).
  Rule titles are unchanged for every id kept on all three platforms.
- `windows_server_2016` **V2R10** (103 of 273) and `windows_server_2019` **V3R9** (104 of 282) are generated platforms again:
  both were marked sunset against the July 2026 compilation, but the October 2026 library ships them. Each replaces a
  5-finding hand-written stub that carried Windows Server 2022 rule ids. Package names (`stig.windows_server_2016`,
  `stig.windows_server_2019`, their `.main` aliases) are unchanged.
- `windows_10` removed: DISA's final release is V3R6 and the platform is absent from the library. Recorded in
  `benchmarks/stig/SUNSET.md` (new); the stub stays in git history. 23 STIG platforms, 182 OSCAL catalogs.
- `tools/stig_generators/gen_windows.py` reads the `parse_xccdf.py` catalogs (version/release/date fields, DISA's
  `high/medium/low` mapped to CAT I/II/III), emits the `# METADATA` block itself, drives every platform from one table,
  and stamps "October 2026 library, verified 2026-11-10" in the headers.

### Fixed — Windows registry derivation reads the whole Value line

- The generator took the first number of a DISA Value line and ignored the rest, which PR #248 had fixed by hand for one
  rule (WN22/WN25-CC-000130). It now reads the line as written, on all five platforms: `in {…}` for "X, Y, or Z"
  (DriverLoadPolicy 1/3/8, AllowTelemetry, HypervisorEnforcedCodeIntegrity 1/2, RequirePlatformSecurityFeatures 1/3);
  `<=` / `>=` for "(or less)" / "or greater" where it read `==` (MaximumPasswordAge 30, InactivityTimeoutSecs 900,
  BitLocker MinimumPIN 6) with `> 0` for "excluding 0"; a second rule body for "(or if the Value Name does not exist)"
  (7 rules per server platform, 8 on Windows 11) so an absent value is not a finding once registry facts exist; and
  `to_number(...)` for numeric REG_SZ values, which were compared to the literal prose (`== "10 (or less)"`,
  `== "1 (Lock Workstation) or 2 (Force Logoff)"`) and could never pass. Two-value rules under one registry path
  (Hardened UNC Paths NETLOGON + SYSVOL, VBS EnableVirtualizationBasedSecurity + RequirePlatformSecurityFeatures) now
  check both values; a rule whose Value Name count the parser does not fully read is refused rather than half-derived.
  The #248 tests are kept and copied to Server 2016/2019.

### Changed — Linux DISA STIGs refreshed to the October 2026 library (verified 2026-11-10)

- **Generated platforms regenerated** (`tools/stig_generators/gen_linux.py`, catalog id hard-gate green, no pin
  retired or renumbered): Ubuntu 22.04 V2R9 → **V2R10** (22 of 191 rules, was 22 of 188), Amazon Linux 2023
  V1R4 → **V1R5** (23 of 187), SLES 15 V2R8 → **V2R9** (27 of 220, was 27 of 218). Title drift is editorial
  (DoD → DoW, hyphenation). The generator now reads the current `parse_xccdf.py` catalog shape, emits each
  module's METADATA block itself and names the library and verification date in one place.
- **RHEL 9 re-stamped by what each rule checks** (`tools/stig_generators/stamp_catalog.py`, new): the modules
  carried ids that named a different DISA rule than the logic next to them (the defect recorded 2026-10-13).
  Every one of the 143 findings was reviewed against the V2R10 check text and keyed on its fact: 104 are kept
  with the V2R10 stig_id, vuln_id, severity and title (99 of them re-pointed to a different id than they
  carried), **39 are removed** because V2R10 has no rule for what they check or another block already covers
  it (rsh-server, ypserv, xinetd, cups, bind, dhcp-server, httpd, samba, squid, rsync-daemon, net-snmp, avahi;
  pwhistory, PASS_WARN_AGE, audit `-e 2`, audit log directory mode, SUID inventory, cron.allow mode,
  unsigned packages, MaxAuthTries, Compression, Protocol; six duplicates of the FIPS / crypto-policy /
  smart-card rules). RHEL 9 V2R2 → **V2R10: 104 of 445** (was 143 findings against V2R2, 108 mis-keyed).
  Rules a module checks only half of (`conf.all` without `conf.default`) are stamped on the `all` rule; the
  `default` rule is uncovered, not invented.
- **RHEL 8 the same way**: V1R13 → **V2R8: 53 of 369** (was 73 findings; 20 removed, among them the
  `/etc/passwd`, `/etc/shadow` and `/etc/group` mode rules and the sshd IgnoreRhosts / HostbasedAuthentication /
  UsePAM rules, which the RHEL 8 STIG does not carry). The firewall block's header and identifiers, which
  disagreed with each other, are normalised.
- Tests follow the ids: the seeded-violation tests name the V2R10 / V2R8 rule, retired-rule tests are gone,
  `test_audit_logging_fixes.rego` (RHEL 9, all about the retired log-directory rule) is deleted.
- `gen_oracle_linux.py` overrides are re-keyed to the stamped RHEL 9 ids (53 keys moved, 8 removed with their
  source blocks); the Oracle modules themselves are unchanged in this release.

### Added — RHEL 10 V1R2 and Ubuntu 24.04 LTS V1R7 STIGs

- **`benchmarks/stig/rhel_10/`** (98 of 434 rules): derived from the re-stamped RHEL 9 modules by DISA rule
  title (`gen_oracle_linux.py rhel_10`, 45 reviewed overrides for RHEL 10's rewording, 1 look-alike refused —
  RHEL 10 has no OpenSSL crypto-policy rule). The six RHEL 9 rules with no RHEL 10 counterpart (two auditd
  actions, the grub password, FireWire, smart-card removal lock, OpenSSL) are not emitted.
- **`benchmarks/stig/ubuntu_24_04/`** (22 of 195 rules, 15 CAT I): the Ubuntu 22.04 logic table re-keyed by
  title (`gen_linux.py`, `UBTU_22_TO_24`); only the sshd Ciphers and MACs values differ and are taken from the
  24.04 check text. Both platforms carry the fail-closed `.main` alias and smoke tests.

### Added — every framework key resolves at `/v1/data/<key>/main/compliance_report`

- 38 framework-key bridge modules, one per product key whose package was named differently (every
  `stig_*` key onto `stig.<platform>.main`, `cis_rhel10`, `cis_ubuntu_2004/2204/2404`,
  `cis_windows_2019/2022`, `cis_openshift`, `nist_800_53`, `nist_csf`, `nist_ai_rmf`, `iso27001`, `cmmc`,
  `nerc_cip`, `iec_62443`, `ami_device`, `ami_headend`, `ami_nist_ir7628`, `crypto_miner_detection`,
  `sentinel_*`, `ai_governance`). Each lives in its framework's own directory so it ships in that bundle,
  and fails closed: no facts → non-compliant with an explicit finding, and the report object is always
  defined. Seven mains that named their report differently (`hipaa`, `gdpr`, `digital_sovereignty`, `sox`,
  `fisma`, `pci_dss`, `soc2`) now also expose `compliance_report` with an explicit `compliant`.
- `tests/framework_keys/test_keys.rego`: one test per product key (89) asserting the entrypoint resolves
  on empty input, is an object and is not compliant. Keys with no library counterpart are not bridged and
  are left for the product map to drop: `cis_cloud`, `cis_vmware`, `corporate`.
- README counts restamped by `scripts/count_controls.py --check-readme` (22,661 checks, 922 policy files).

### Changed — PQC Readiness cites the final NIST IR 8547

- `frameworks/federal/pqc/pqc_main.rego`: NIST finalized IR 8547, "Transition to Post-Quantum Cryptography
  Standards", on 2026-10-27. The header and the report's `sources` list cited the November 2024 initial public
  draft; both now cite the final. No rule changes: the deprecate-after-2030 / disallow-after-2035 schedule the
  checks quote is the one the final carries. `STANDARDS_UPDATE_REGISTRY.md` row updated; what is left to watch
  is the CNSA 2.0 FAQ, the FAR proposed rule and CISA's CBOM minimum elements.

### Added — SAP Security Baseline Template v2.6, ABAP stack (`benchmarks/sap/abap/`)

- **First application-suite baseline.** SAP publishes its Baseline Template checks as Focused Run CSA policies
  (`SAP-samples/frun-csa-policies-best-practices`, Apache-2.0); `scripts/import_sap_baseline.py` reads the
  v2.6 ABAP set (43 policies, 355 distinct check ids, pinned to commit `888f3c53`) and writes the registry
  (`sap_abap_baseline_registry.rego`, every check with level, requirement and whether this library assesses
  it) and one translated rule per host-decidable check (`sap_abap_baseline_checks.rego`): 127 profile,
  transport, kernel and CommonCryptoLib parameter conditions compiled from SAP's own expressions (equality,
  case-folded equality, numeric and between, enumerations, SQL LIKE and regex, wildcard parameter names,
  dotted versions). 11 more are hand-written (`sap_abap_baseline_manual.rego`): the three gateway ACL files
  and the message-server ACL, kernel and CommonCryptoLib age, kernel patch level per release (Note 2083594).
  The other 217 checks need user tables, authorizations, audit slots or RFC destinations and are listed as
  not assessable with the store named — the report's coverage is the registry's, never implied.
- **Canonical id = SAP's check id.** `PWDPOL-A_a.1`, `RFCGW-A_a secinfo.2` ... are public, stable and what
  an SAP auditor recognises. Profiles `critical` / `standard` / `extended` follow SAP's p1/p2/p3 priorities.
  An absent parameter fails its check ("not set in the collected facts"): the kernel default is not evidence.
- **One catalog, three views.** `compliance_report.projections` derives per-framework views from the same
  results through data-only mapping tables: the Baseline's own requirements (from the registry), the DSAG
  S/4HANA audit guide (section numbers only — the guide is all-rights-reserved; 26 parameters placed by
  where the guide names them, 11 requirements by subject) and NIST CSF 2.0 (all 106 subcategories listed;
  the assignment is this library's reading). A reference with nothing assessable is listed as
  `not_assessable`, never dropped.
- Input contract (`input.sap.abap.*`) and regeneration steps in `benchmarks/sap/abap/README.md`; 62 tests;
  vocabulary gains source `sap` and domains `sap`, `erp`.

### Changed

- **No verbatim CIS Benchmark text in `benchmarks/cis`.** Violation messages and comments keep the control id and now use the library's own wording for what the Rego evaluates (`tools/cis_generators/neutralize.py` rewrites generator titles; `scripts/check_cis_verbatim.py` fails CI on a copied recommendation sentence, with `scripts/cis_verbatim_allowlist.txt` for the exceptions). Packages, rule names, input shapes and results are unchanged.
- **CI compiles and tests on OPA 1.10.0 and 1.22.0.** The validate job is a matrix over both releases; a `validate-all` job keeps the required check name "Check and Test Rego Policies" and passes only when every leg passed. `docs/ENGINE_COMPATIBILITY.md` records the floor and the newest release tested.
- **Engine portability, step 1: no `some k, v in` inside set or array comprehensions.** rego-cpp (regopy) rejects that form with "Invalid collection" and refuses to load the whole module; 87 policy modules were affected; 85 are rewritten here (the other two, `enforcement/aap/extra_vars_control.rego` and `frameworks/financial/mas_trm/mas_trm_main.rego`, fail the per-file pre-commit check on main because they use definitions from sibling files, and follow separately). 244 comprehensions now use equivalent forms: `some v in X` when the key is unused, `some k; _ = X[k]` when the value is unused, `some k; v := X[k]` otherwise. Each form was checked on both engines (objects, arrays, sets, destructured values, indexed call results). The Windows Server 2022 generator and template emit the new forms, and regenerating reproduces the committed files. OPA results are unchanged: 991 evaluations of every affected directory's packages, on 721 inputs harvested from the test files plus empty input, are identical before and after (live timestamps masked), and 4,713/4,713 tests pass. Under regopy 1.5.2, 781 of 797 modules load with this change (was 701). Test files are unchanged; rego-cpp cannot compile the test suite anyway (see docs/ENGINE_COMPATIBILITY.md).

### Fixed

- **Every module now loads on its own, and the library compiles on OPA 1.22.** The product loads this library
  with one `PUT /v1/policies` per non-test file into an empty OPA server (`docker.io/openpolicyagent/opa:latest`,
  1.22.0 today). OPA 1.22 types a literal empty `{}`, `set()` or `[]` as having no members and rejects every
  index or iteration over it as `rego_type_error: undefined ref`, so 22 modules were rejected on upload and
  their frameworks were silently absent from the product's OPA while CI (OPA 1.10, `opa check <dir>`) stayed
  green: HIPAA Part 160 and Part 162 (`fact_basis := {}` / `_fact_pass := set()`), the eight CIS MCP Server
  sections with no multi-part attestation (`_parts := {}`; two of them also `_evidence_key := {}` /
  `fail := set()`), CIS FortiGate (`_v_wireless := set()`), CIS M365 v7 attestation (`NOT_IMPLEMENTED := {}`),
  the Kubernetes and RKE2 STIG cores (`some p in []` in 12 attestation-only rules) and eight Oracle Linux 8/9
  STIG modules with no CAT I rule (`cat_i_findings := []`). Each empty table is now built with a builtin
  (`object.union({}, {})`, `set() | set()`, `array.concat([], [])`), or the dead iteration is replaced by the
  literal it always produced; values, rule names, report shapes and all 15,132 tests are unchanged. The
  Oracle Linux generator emits the new form. One more module failed for the other reason a per-file upload
  can fail: `enforcement/aap/extra_vars_control.rego` called `_aap_team_name` from `owner_scope.rego`, which
  sorts after it, so it was rejected until its sibling arrived; it now carries the two-line helper itself.
  `scripts/check_per_file_load.py` (`make check-per-file-load`, and a CI step) starts a throwaway OPA server,
  uploads every policy file one at a time in sorted order, as the product does, and lists every module
  that is rejected. It does not prove every `find` order: `frameworks/financial/mas_trm/mas_trm_main.rego`
  still depends on `mas_trm_controls_a.rego`, which happens to sort first.

- **Fix decisions (2026-10-19): the 84 judgment items left open by the 2026-10-17 validation, decided by the maintainer and implemented.** 90 policy modules change, each fix with a test that fails on the old code; 6,919/6,919 tests pass on OPA 1.10.
  - **STIG `compliant` means no open finding at any category** (34 modules: Oracle Linux 8/9, RHEL 8/9). The old CAT-I-only meaning is kept as `cat_i_compliant`, also in each `compliance_report`. Modules without CAT I rules no longer report compliant with CAT II/III findings open. **Behaviour change for consumers that gate on `compliant`.**
  - **Undeclared applicability fails closed** (CRA authorised representative, FOSS exclusion, online marketplace, OSS steward; NERC CIP-002, CIP-008; EU AI Act Art. 50; GDPR joint controllers and SCC+TIA): an absent deciding fact raises "applicability not determined"; an explicit `false` is still not applicable.
  - **Every required rule now feeds `compliant` and `violations`.** NERC CIP-003–CIP-014 gain the violations that were missing for rules `compliant` already required (43 in CIP-004–013, plus CIP-003 R3/R4 and CIP-006); GDPR cookies and Art. 26, sovereignty and Amazon Linux 2023 log permissions are wired in. Dead helpers with no input source are removed (Arista and others). New control ids: IS-018 (proprietary API, was a reused IS-013), IS-019, SS-017, SS-018.
  - **Totals are computed, not quoted:** CIS AWS Foundations (19 evaluated, was 69) and pfSense (16, was 22), in the modules and their `*_main` roll-ups. `cis_rhel_9.rego` and the Amazon Linux 2023 roll-up are marked `custom.deprecated` with `superseded_by` the `*_main` package; they stay loadable because consumers still query them.
  - **Data contracts follow the docs:** CIP-004 reads `risk_assessment_completed` / `risk_assessment_date` (the nested form still works); CIP-013 and CIP-014 accept ISO-8601 and nanosecond dates; `corporate/backup_policy` policy rules no longer start with `test_` (opa test was running them); `soc2_main` imports the infrastructure packages the files declare, so `infrastructure_scores` resolves.
  - **Security gates:** OIDC `token_valid` checks `iss`, `aud`, `exp`, `nbf`, and the signature when a JWKS is supplied; Kubernetes admission denies bare image names (they resolve to Docker Hub) unless `docker.io` is allowed; a `${{ env.X }}` in a CI/CD run script exempts only the secret it wraps; SENTINEL-TF-002 says `::/0` for IPv6 findings.
  - **Interpretation:** FISMA RMF-R requires an authorization, not just a documented decision; CMMC Level 1 uses Level-1 practice flags; Kubernetes 4.2.9 accepts 0 or at least 5; an absent `--insecure-port` passes; an absent sudo `timestamp_timeout` passes (default 5 minutes); Ubuntu 22.04 logrotate is its own count; Oracle 19c modes use octal comparison; Windows 11 reports evaluation time in `assessed_at` only.
  - **CIS RHEL 9, found while building the compliance collectors:** `inactive_days: -1` (lock disabled) now fails CIS 5.5.1.4 instead of passing; absent `certificates.ca_bundle_intact` is reported as evidence missing instead of "CA bundle modified" (every host without the field got that false finding); the network section counts the `ipv6` input (was misspelled `ipv`).
  - Still open for a decision: OL9 package-absent semantics, RHEL 9 cups/nfs package checks, SOX scope and `sox_main` input contract, SOC 2 overall flag. Apache and VyOS items wait for the benchmark text.
- **Git playbook documentation audit (`enforcement/git/playbook_documentation.rego`), seven defects from the 2026-10-17 library validation.**
  - The upper-case placeholders (TODO, FIXME, TBD) were compared against the lower-cased value, so they never matched.
  - `audit_passed` used `every` over `input.playbooks`. It was true for an empty or missing list, and it ignored the DOC-021 short-task and DOC-030 staleness violations that `non_compliant_playbooks` counts. It is now false without playbooks and agrees with the per-playbook reports.
  - Staleness was measured from a fixed 2026-03 reference date. It now uses today unless the input pins `audit_year` / `audit_month`.
  - An empty play name returned `true` instead of the DOC-010 message (`else if` without `:= msg`).
  - The DOC-020 coverage percentage printed as `%!d(float64=…)`.
  - Empty or blank metadata strings counted as present for DOC-001, DOC-004 and the metadata score.
  - Ten regression tests are added; eight of them fail on the old module.
  - The module is now strict-clean, so CI's strict step covers all of `enforcement/` again.
- **Library-wide validation and fixes (2026-10-17): 755 defects fixed in 286 policy files, each with a test that fails on the old code.**
  - **How the defects were found:**
    - Every package was evaluated against empty input. 45 packages reported compliant with no evidence, and 18 were wholly undefined.
    - Agents reviewed 269 files (everything flagged by that evaluation, plus every file under 50 % test coverage) and found 788 defects.
    - A random sample of 30 high-severity findings was re-verified: 24 real, 6 real but overstated, 0 false.
    - The existing unit tests could not catch these. Most were generated smoke tests that only assert that a package loads or returns an object.
  - **The recurring defects, now fixed wherever they appeared:**
    - **Missing evidence passed.** A section with no facts, or with `{}`, produced no violations. Each check now emits a `CIS x.y: evidence missing — … not collected` violation, in line with the documented contract that empty facts fail closed.
    - **Rules without defaults inside object or array literals.** A failing control made its section, score or findings object undefined, so the failure removed its own violation. Affected: OpenShift 4, PCI DSS (all 12 requirements), SOC 2, SOX ITGC, nginx, ESXi and vCenter.
    - **File modes and umasks compared as decimal numbers or exact strings.** umask `022` passed the `027` check, and `0604` key and log modes passed. There is now a shared, tested octal helper with bitwise "no more permissive than" checks.
    - **Config text matched by substring, comments included.** For example, `#PermitRootLogin no` masked `PermitRootLogin yes`, and `contains("TLSv1")` matched TLSv1.2. Only active directives are parsed now.
    - **`contains()` applied to array-shaped facts.** These checks never fired. Affected: Cisco, MySQL, Apache modules, and RHEL access_control and filesystem.
    - **Values used as keys.** AWS IAM CIS 1.2 and 1.3 always passed.
    - **Applicability filters inside `every`.** In NERC CIP-005, 006, 007, 010, 014 and 015, one low-impact system failed the rule.
    - **Inflated roll-ups.** RHEL 9, RHEL 10 and Amazon Linux 2023 reported 99.28 % on empty input from a hard-coded 278-control denominator. Totals are now computed from the controls actually evaluated.
    - **Runtime errors.** Two `eval_conflict_error`s (FISMA ATO and corporate backup retention), plus divisions by zero.
  - **Notable single fixes:**
    - The Terraform gate now flags protocol `-1` and IPv6 `::/0` open to the world, and it no longer allows `{}`.
    - The Kubernetes gates now cover initContainers, CronJob templates and Pod-level host namespaces.
    - SOX no longer reports FULLY_COMPLIANT when ITGC fails.
    - GDPR transfers: US recipients qualify only through a verified EU-US Data Privacy Framework (DPF) certification, not by country name.
    - The CRA `foss_exclusion` module's `compliant` can be false again.
  - **Changes to existing behaviour that consumers will see:**
    - **Many CIS Linux and STIG sections now report "evidence missing".** No collector in the compliance repository sends these facts yet; the per-key list is in the fix reports.
    - **PCI DSS scope flags.** A requirement now counts as not applicable only when `in_scope == false` is explicit.
    - **Two existing tests changed.** The `test_soc2_main.rego` assertions pinned the undefined-score bug and were updated. The `eu_ai_act_main` `clean_minimal` fixture now declares all ten Article 5 sections. No test was deleted.
    - **Placeholder control IDs.** Newly wired Cisco, Juniper and RHEL 10 checks carry `UNMAPPED-<platform>-N` IDs until they are mapped to the CIS benchmark.
  - **Counts:**
    - The control-level count rises from 19,173 to 19,735. Most of the +562 are the new evidence-missing checks (about 410 new message lines), not new standard coverage.
    - The OSCAL catalogs grow by 195 controls.
    - The test suite grows from 4,713 to 6,669 tests.
  - **84 judgment calls were left unchanged for the maintainer.** Examples: whether STIG `compliant` should count only CAT I findings, whether undeclared applicability means not applicable, and the OIDC token checks.
- **CIS M365 v7 attestations no longer accept null or blank evidence.** `attestation_validation.rego` tested `attested_by`, `attested_on` and `evidence_ref` by truthiness, which fails only on `false` or undefined, so an attestation with `"evidence_ref": null` (or `""`, or a number) counted as attested and the control left the violation list. Each field must now be a non-empty string, the rule the Windows Server 2022 module already uses. Two regression tests (null evidence; blank, whitespace and non-string provenance) fail on the old rule and pass now.
- **STIG Windows Server 2022 / 2025: boot-start driver policy (WN22-CC-000130, WN25-CC-000130).** The rules passed only on `DriverLoadPolicy == 1`. The DISA check text (V-254344, V-278091) accepts 1, 3 or 8, treats an absent value as not a finding (the default enforces 3) and flags 7 ("All"). A host on the default or on CIS 18.9.13.1's value 3 was reported Open. Now 1/3/8 pass, 7 and any other value stay open, and an absent value passes only when registry facts were collected. Five tests per platform. The CIS Windows Server 2022 README's STIG cross-check now reads 88 of 92.

### Added
- **Provider change gate (`enforcement/provider/`, package `provider_change.main`): the OPA decision behind the `aac.tfprovider` `resource` module, 21 control-level checks (22,507).** Input is the planned-diff document of aac-tfprovider `docs/CONTRACTS.md` §4: one planned change to one resource, as the provider planned it, with sensitive values already masked as `__SENSITIVE__`. Output is `decision = {allow, reasons, policy_version, evaluated_rules}`. `allow` defaults to false and is true only when the `deny` set is empty; a document without `kind`, `version`, `action` or `resource_type` is denied with a PC-000 reason, so an empty or wrong document never passes. Seven rules, each with a rule-scoped METADATA title and the resource types it applies to: PC-001 public S3 ACLs (a canned public ACL or a grant to AllUsers / AuthenticatedUsers on `aws_s3_bucket`, `aws_s3_bucket_acl`); PC-002 `aws_s3_bucket_public_access_block` with any of the four protections false or unset; PC-003 ingress from `0.0.0.0/0` or `::/0` (`aws_security_group` inline ingress, `aws_security_group_rule`, `aws_vpc_security_group_ingress_rule`, `azurerm_network_security_rule` inbound Allow from `*` / `Internet`, `google_compute_firewall` with a world source range and an `allow` block); PC-004 replace or delete of a resource whose prior `tags` / `tags_all` / `labels` carry `protected = "true"`; PC-005 `owner` and `environment` on create / update / replace of the taggable AWS, Azure and GCP types in the package's `taggable_resource_types` data set (overridable with `with data.provider_change.main.taggable_resource_types as ...`); PC-006 create of `aws_iam_user_login_profile`, or of an `aws_iam_user` whose config declares a login profile. A masked value is never compared with an expectation (a masked tag counts as present; a masked `protected` value does not protect) and never appears in a reason. `compliance_report` is exposed as well, so the compliance repository's framework-map validator and generic assessment read the package like any other. 49 §4 fixture documents under `tests/fixtures/<name>/input.json` (allow and deny cases for every rule, loadable as-is with `opa eval -i`) and 78 tests. Routing: the compliance repository adds `provider_change: compliance` to `opa_framework_map` and a `provider_change` loader key.
  - **Review fixes (CONTRACTS.md v1.2).** A rule whose governing attribute is listed in `unknown_paths` fails closed with `cannot evaluate: <attribute> unknown at plan time` (PC-001 `acl` / `access_control_policy`; PC-003 `ingress`, the rule CIDR fields, Azure direction / access / sources, GCP direction / disabled / allow / sources), while a null or absent attribute not listed as unknown is the provider default and is judged as before; a masked (`__SENSITIVE__`) `protected` tag on replace or delete now denies (`protected tag is masked; cannot prove the resource is unprotected`); `google_compute_firewall` INGRESS with an `allow` block and none of `source_ranges` / `source_tags` / `source_service_accounts` denies (GCP defaults the source to `0.0.0.0/0`); the `taggable_resource_types` override accepts a set or an array; the unused `well_formed` rule is removed; the test helper that decides each fixture is a partial object rule instead of a function so `opa build -t wasm` (`make wasm`) compiles the test file. 54 fixtures, 99 tests.
- **DISA Kubernetes STIG V2R6 (all 92 rules) and RGS RKE2 STIG V2R7 (all 21 rules), 24 STIG platforms (22,486 control-level checks):** `benchmarks/stig/kubernetes/` regenerated from 23 rules to every catalog rule, new `benchmarks/stig/rke2/` (package `stig.rke2`, `stig.rke2.main` bridge with the same fail-closed gate as `stig_kubernetes_main.rego`). `tools/stig_generators/gen_k8s.py` rewritten with a two-way catalog gate.
  - **Fail closed rule by rule.** Every finding lists the evidence it reads; if any is absent it is Open with `detail` "<STIG-ID>: evidence missing — <field> not collected". Absence checks (`--basic-auth-file` not set, etc.) require the collection itself — the old `not input.x.flags["y"]` passed when kubelet or API server facts were never collected. Organizational checks are `input.attest.<key> == true`. Findings gain `check_type` and `detail`.
  - Kubernetes: 84 machine-checked, 1 machine + attestation, 7 attestation-only. RKE2: 15 / 1 / 5. RKE2 has its own input contract (`input.rke2.config`, the component args RKE2 renders, audit and PSA files, the `/etc/rancher/rke2` and `/var/lib/rancher/rke2` file table).
  - **Fixed meaning of existing rules (same ids and titles):** CNTR-K8-002640 tested `--tls-cert-file`/`--tls-private-key-file` (CNTR-K8-001440's check); it now tests `--kubelet-client-certificate`/`--kubelet-client-key`. CNTR-K8-002001 read the admission plugin list; DISA checks the PodSecurity feature gate on the manifests and kubelet. CNTR-K8-001162 is now read from the encryption config (secrets covered, identity not first) instead of a boolean. CNTR-K8-000290, 002010, 003110 are machine-checked instead of booleans; 001161 and 002011 use named attestations.
  - **Parser differentials closed (security review):** a flag is read only when exactly one key normalises to its name (components treat `a_b`, `--a-b` and `a-b` alike), so duplicated, repeated (list) or non-string values fail instead of passing on one spelling; absence checks see every spelling; `--feature-gates` entries are parsed like Go's `ParseBool` (`AllAlpha=1` is on) and unparseable or conflicting entries fail; kubelet `featureGates` values must be typed booleans; the legacy flattened kubelet keys are read only when the real key is absent; the encryption config and the RKE2 audit policy are evaluated first-match, as the API server does; `--request-timeout`/`--secure-port` zero in any form (`0s`, `00`) fails; ValidatingAdmissionWebhook is read from `--enable-admission-plugins` itself. Second review round: version-gated passes need a parseable 1.x `cluster.version` (absent, list, `latest`, `v2` fail; `1.30.2+rke2r1` parses); an absent PodSecurity gate is accepted only on 1.25+, older clusters must set `PodSecurity=true` everywhere; KubeletConfiguration values and defaults count only when the kubelet runs with `--config`; file modes must be strings, duplicate entries are all checked, and named paths (control-plane manifests and confs, kubelet.conf, PKI ca/apiserver crt+key, etcd member, the RKE2 entries DISA lists) must be present; empty cluster lists count only with `collection_status.<query> == "ok"`; RKE2 `*-arg` entries in config.yaml (and `+` drop-in keys) must match the running value. 80 probe tests cover these inputs.
  - **Input contract change for consumers:** `namespaces.user_resources_in_dedicated`, `secrets.sensitive_data_in_secrets_only`, `etcd.encryption_provider_configured`, `pod_security.policy_enforced`, `pod_security.admission_config_file_set` and `manifests.owned_by_root` and `api_server.admission_plugins` are no longer read; see the `gen_k8s.py` docstring for their replacements. The flattened kubelet keys `authentication_anonymous_enabled` / `authorization_mode` are still accepted.
  - `gen_crosswalk.py` replaced every `CNTR-*` mapping when joining one CNTR platform (it keyed on the first id segment); it now replaces only that platform's family. 800-53 spine: CNTR-K8 92 of 92, CNTR-R2 20 of 21, CNTR-OS unchanged (3,807 rules).
- **Estate continuity (`governance/estate_continuity`, package `estate_continuity.main`).** Tells an asset retired on purpose from one that went quiet or disappeared. Each host record (inventory presence, provider state, hours since last evaluation, last attempt outcome, any decommission record or removal event) is classified into one of 16 states. Nine are findings: unexplained disappearance (`missing`, NIST CM-8 / CIS Controls 1.1), a machine the provider shows running that is in no inventory (`unmanaged_running`, CIS 1.1), removal by a named actor without a decommission record (`removed_unrecorded`), a retired asset that still answers (`zombie`, CIS 1.2), four kinds of stale evaluation (unreachable, failing, no evidence stored, never targeted; NIST CA-7), and a malformed record. Silence is never treated as retirement: a decommission record counts only when it names the reference, the person and the time. Powered-off hosts are flagged, not failed, unless configured out of scope. The provider is the authority on existence: an inventory sync that drops stopped instances does not turn them into disappearances. All ages arrive in hours, so the policy does no clock arithmetic. Empty, missing or malformed input reports non-compliant. 31 tests. While writing the input guard: in OPA 1.8, `not is_array(input.hosts)` is not true when `input.hosts` is undefined (a built-in on an undefined argument), so the guard uses a helper rule, and a test pins the no-input case.
- **CIS Microsoft Windows Server 2022 Benchmark v5.1.0, every recommendation, 171 net new control-level checks (19,166):** `benchmarks/cis/windows_server_2022_modular/` regenerated from the CIS workbook by `tools/cis_generators/gen_windows_server_2022.py`. All 408 recommendations: 406 evaluated (287 single registry values, 9 multi-value, 4 must-not-exist, 11 per-user, 13 account-policy / secedit, 48 user rights, 34 audit subcategories), the 2 Manual ones by attestation. Member server and domain controller, Level 1/2 and Next Generation profiles selected by `input.cis_profile`; a role-specific recommendation with no role supplied is not assessed and counted as failed. Fact contract shared with the Windows STIG modules (`input.registry[<path>][<value>]`); audit policy keyed by subcategory GUID with the `auditpol /backup` bitmask; `data/collector_manifest.json` lists every value read. Registry values cross-checked against the repository's Windows Server 2022 STIG: 87 of 92 shared settings agree, the five differences explained in the module README. Windows is now under `check_cis_ids.py` and `check_cis_coverage.py` in CI. 441 tests.
  - **Found:** the previous module claimed v5.0.0 but cited 179 ids, of which 87 do not exist in the benchmark and 22 named a different recommendation (section 5 cited 26 services where the benchmark has 2; the user-rights ids 2.2.x were offset from their titles). Its input shape (semantic booleans under `input.registry`) is replaced: the compliance repo's collector changes in step.
  - `benchmarks/cis/windows_server_2019_modular/` carries the same citations and is labelled **IDs unverified** in the README until it is rebuilt from the CIS Windows Server 2019 benchmark.
  - README, COMPARISON, SCF_GAP, COVERAGE_SCAN, COVERAGE.md, TEST_GENERATION, OSCAL / crosswalk / XCCDF dists and site pages restamped.
- **SCF parity, Phase 3 batch 1 (US federal remainder), 1,917 new control-level checks (18,995):** NISPOM 32 CFR 117 (599 rows, 18 gates), FAR 52.204-21 / -25 / -27, CISA TIC 3.0 catalog v3.3 (116 capabilities), DOE C2M2 v2.1 (356 practices, MIL gate), NRC 10 CFR 73.54 (34), USCG 33 CFR 101 Subpart F (105), CERT-RMM v1.2 (248 practices; ids, titles and own summaries under the SEI licence), CMS MARS-E 2.0 (352 controls; superseded by ARC-AMPE; 224 rows carry partial text because the catalogue renders list items as images), 45 CFR 155.260 (35), FTC Red Flags 16 CFR 681 + disposal 682 (12). Regulation text verbatim from GovInfo's CFR XML.
- Converters: 800-53 overlay catalogs (`OVERLAY_CATALOGS`, currently CMS MARS-E) are excluded from the `label-is-800-53` mapping in the crosswalk spine and the OSCAL baseline coverage, so an overlay that restates 800-53 cannot inflate what the library is said to evaluate (FedRAMP Moderate stays 109/181 base controls).

### Added
- **SCF parity, Phase 2 batch 1 (NIST risk and AI, resilience, OWASP), 388 new control-level checks (17,078):**
  - `frameworks/federal/nist/risk_management_framework/`: **SP 800-37 Rev 2**, all 47 RMF tasks (P-1 … M-7) with role, outputs, references and Outcomes-column CSF items as data; the 12 Categorize rules folded into C-1 … C-3 via a `legacy` table (consumer paths under `nist.rmf.categorize` unchanged); new entrypoint `nist.rmf.main`.
  - `frameworks/federal/nist/sp_800_39/`: **SP 800-39**, the 12 numbered risk-management tasks (frame / assess / respond / monitor).
  - `frameworks/federal/nist/ai_rmf/`: **AI RMF 1.0** completed to all 72 Core subcategories from NIST AI 100-1 (14 fact-decided, 58 attested; 22 old checks moved to `legacy`), and the **AI 600-1 Generative AI Profile** as `nist.ai_600_1.main`, 212 suggested actions on their parent subcategories with the 12 GAI risks, gated by `scope.generative_ai`.
  - `frameworks/federal/nist/sp_800_160v2/`: **SP 800-160 Vol 2 Rev 1**, 50 cyber-resiliency implementation approaches (14 techniques), Table E-1 mapping to 265 SP 800-53 controls as data only.
  - `governance/owasp_top10/`: **OWASP Top 10:2025**, 10 categories, 249 mapped CWEs; no OWASP prose (site licence CC BY 3.0).
  - `crosswalk/attack_800_53/data.json`: **MITRE ATT&CK 16.1 → SP 800-53 Rev 5** from the Center for Threat-Informed Defense (Apache 2.0): 109 controls, 470 techniques, 5,264 mitigates pairs. Data only: no checks, and it does not feed the OSCAL baseline coverage.

### Changed
- `scripts/count_controls.py --check-readme` (run by CI on every PR) now also verifies the README's policy-file counts, the seven What's-in-the-box category rows (measured per directory from the same file set as the count), the DISA STIG platform count and the OSCAL catalog / control figures against `dist/catalogs/index.json`, and names each drifted number. The category rows had drifted by up to 40 files across the Phase 1 batches before #239 corrected them by hand.

### Added
- **SCF parity, Phase 1 batch 4 (DORA RTS, UK DPA 2018, ISO 27002 numbering, CSWP 39), 644 new control-level checks (16,690):**
  - `frameworks/financial/dora/dora_rts_ict_risk.rego`: **Commission Delegated Regulation (EU) 2024/1774** (the DORA RTS on the ICT risk management framework), 308 rows from the EUR-Lex text (Title II 228, Title III simplified framework 80), one row per lettered point, gates for the simplified framework and for the duties the act addresses only to central counterparties, central securities depositories, trading venues and non-microenterprises; aggregated by `dora.main` (`total_controls` 91 → 399).
  - `frameworks/privacy/uk_dpa_2018/`: **UK Data Protection Act 2018** as at 2026-09-30 from the legislation.gov.uk XML, 151 duty subsections beyond the UK GDPR (Part 2 Chapter 2–3 and Schedules 1–3 gated by scope flags, Part 3 law-enforcement processing gated by `competent_authority`, s.164A); repealed sections excluded, Parts 4–7 listed out of scope with citations. New vocabulary source `uk-parliament`.
  - `frameworks/management/iso27001/`: every one of the **93 ISO/IEC 27001:2022 Annex A controls** under the 2022 numbering with an `iso27002` view, titles and the five 27002 attribute families as data (no standard text); 54 existing checks re-keyed from their 2013 ids via the 27002 Annex B correspondence (35 controls fact-decided, 58 attested); a `compliance_report` with per-theme rollups; the `iso27001_assessment` endpoint keeps its keys.
  - `frameworks/federal/pqc/cswp39_crypto_agility.rego`: **NIST CSWP 39-upd1** (June 2026 update) crypto-agility practices, 67 rows keyed by section with implementer and cloud gates; the December 2025 edition is recorded as superseded (Appendix C changed one history paragraph).
  - `docs/SCF_GAP.md` v1.5: 65 covered, 8 partial, 161 gap. Site pages regenerated.
- **SCF parity, Phase 1 batch 3 (C5:2026, 800-171A Rev 2, HIPAA Administrative Simplification), 669 new control-level checks (16,046):**
  - `frameworks/regional/bsi_c5/` re-keyed from C5:2020 to **BSI C5:2026** (v1.0.1, 2026-04-07): all 168 criteria in 17 subject areas under BSI's own ids (OIS-01 …), with each criterion's basic / sharpening / complementing subcriteria ids as data (623 subcriteria), the six General Conditions as disclosures, effective-date rules (§3.5) in the report; the 61 made-up ids of the old module are a `legacy` table whose attestation names the 2026 candidate.
  - `frameworks/federal/nist/sp_800_171a_r2/`: **SP 800-171A (June 2018)**, all 320 assessment objectives under the 110 Rev 2 requirements, two extraction modes cross-checked, zero unreadable; methods as data.
  - `frameworks/privacy/hipaa/` re-keyed to **45 CFR citations** from GovInfo's 2025 CFR XML: Security Rule 68 rows (22 standards, 24 required, 22 addressable; 48 fact-decided), Privacy Rule 110 rows, Breach Notification 17 rows, new Part 160 (8) and Part 162 (43) modules; every Security Rule row carries its **SP 800-66 Rev 2** section and key-activity numbers (the 800-53 mapping is no longer in the PDF and CPRT has no 800-66 export, so it is not carried). Scope roles (`input.hipaa.scope`) gate applicability; the old report sub-objects and input shape are gone (nothing in the product repos read them).
  - Converters: the 800-53 id pattern used by the crosswalk spine and the baseline coverage bridge now rejects zero-padded ids, so C5's `PS-01` can no longer masquerade as 800-53 `PS-1`.
  - Site pages under `standard/` regenerated (they had not been since batch 1). `docs/SCF_GAP.md` v1.4: 61 covered, 12 partial, 161 gap.
- **SCF parity, Phase 1 batch 2 (NIST, from NIST's own exports and PDFs), 150 new control-level checks (15,377):**
  - `frameworks/federal/nist/cybersecurity_framework_2.0/` completed to **all 106 CSF 2.0 subcategories** from the CPRT export (ids, text, 22 current categories, 363 implementation examples as data, 79 withdrawn CSF 1.1 subcategories listed with CPRT's destination); 29 subcategories decided by the existing fact checks (7 of them carried across a CSF 1.1 `moved_to`), 77 attested; the 72 legacy checks that no longer decide a 2.0 outcome are removed from the count and kept as a `legacy` lineage table (46 retired, 26 unmapped). Package paths and `compliance_report` unchanged; facts alone can no longer pass.
  - `frameworks/privacy/nist_privacy_framework/`: **NIST Privacy Framework 1.0**, all 100 subcategories (5 functions, 18 categories) with each row's CSF relationship tag.
  - `frameworks/critical_infrastructure/nist_800_82/`: the **SP 800-82 Rev 3 OT overlay** (Appendix F, Table 22) as a data table and impact gate: 424 SP 800-53 controls with Low / Moderate / High membership, 24 additions and 3 removals, PM controls marked org-wide; transcription verified against the 800-53B baseline sizes (149 / 287 / 370) with zero unreadable rows.
  - `benchmarks/supply_chain/scrm_800_161/`: the **SP 800-161 Rev 1 upd 1 C-SCRM control summary** (Appendix B, Table 6) as a data table and level gate: 297 controls with Baseline / Flow Down / Level 1 / 2 / 3 membership; the three places Appendix A disagrees with Table 6 are recorded in the header.
  - Counting note: a subcategory decided by facts contributes its row in the main module and its violation rule in the function module, so the CSF directory counts 150 for 106 controls; the overlay and tailoring tables are stored as row arrays so they add no checks. `docs/SCF_GAP.md` v1.3: 57 covered, 16 partial, 161 gap.
- **SCF parity, Phase 1 batch 1 (NIST CUI series and the federal split-outs), 909 new control-level checks (15,227):**
  - `frameworks/federal/nist/sp_800_171/` re-keyed to **SP 800-171 Rev 3** exactly as NIST's CPRT export spells it: all 97 requirements (17 families) with their 349 statements, 79 decided by the existing fact checks (22 of them folded into the Rev 3 slot that absorbed their Rev 2 requirement), 18 attested; the 33 withdrawn requirements listed with NIST's reason; 11 retired Rev 2 checks kept for lineage but no longer decide anything. Package path unchanged.
  - `frameworks/federal/nist/sp_800_171a/`: **SP 800-171A Rev 3**, all 422 determination statements as attested rows, rolled up per requirement; examine / interview / test methods carried as data.
  - `frameworks/federal/nist/sp_800_171_r2/`: **SP 800-171 Rev 2**, the 110 requirements DFARS 252.204-7012 and CMMC 2.0 Level 2 still assess, with CPRT's basic / derived classification.
  - `frameworks/federal/nist/sp_800_172/`: **SP 800-172 Rev 3 + 172A**, 137 enhanced-security-requirement statements and all 199 determinations; a statement is satisfied only when attested and every determination holds; 12 withdrawn listed.
  - `frameworks/federal/dfars_7012/`: **DFARS 252.204-7012** (clause of May 2024, DFARS change of 2026-05-07), 25 contractor obligations by paragraph behind 7 declared applicability flags, dated windows in the report.
  - `frameworks/federal/eo_14028/`: **EO 14028**, 43 directive rows from Secs. 2, 3, 4, 6, 7 and 8 by role (agency, FCEB agency, supplier), with the 15 Sec. 4(e) supplier practices; derived duties marked.
  - `frameworks/federal/cisa_ssdaf/`: **CISA Secure Software Development Attestation Form v1.0**, the 15 attestation items with the form's scope gates; each item carries its EO 4(e) subsection and SSDF tasks.
  - NIST text and identifiers come from the CPRT JSON exports (URL, sha256 and date in every header); DFARS from acquisition.gov; EO 14028 from the Federal Register record; the form from CISA's PDF. Nothing paraphrased, nothing typed by hand.
  - `docs/SCF_GAP.md` v1.2: 56 covered, 16 partial, 162 gap. README claim line now states the catalog count CI can verify (156 framework catalogs) instead of a hand-maintained "tracked standards" figure. CONTRIBUTING.md gains the three rules CI enforces and a "Where help is wanted" section. Vocabulary: domains `cui`, `assessment`.
- OSCAL baseline **profiles** (`converters/exports/oscal/dist/profiles/`): NIST SP 800-53 Rev 5 Low / Moderate / High / Privacy and FedRAMP Rev 5 Low / Moderate / High / LI-SaaS as OSCAL 1.2.3 profile documents importing the pinned NIST catalog with the source baseline's control selection copied verbatim (1,947 selections); sources pinned by commit and sha256 (NIST oscal-content; FedRAMP from the OSCAL Compass mirror, the GSA repository having been removed); profile schema vendored, validated and round-tripped in CI. Closes the 800-53B row of `docs/SCF_GAP.md` (49 covered, 22 partial).
- OSCAL **baseline coverage** (`dist/profiles/coverage.csv`, `coverage_summary.json`): for each imported baseline, which 800-53 controls at least one library check evaluates, from three authoritative mapping sources only (DISA CCI map per STIG rule, modules whose control ids are 800-53 ids, the 800-53 module's labelled checks; 24 topic rows excluded). FedRAMP Moderate: 109 of 181 base controls, 4 of 142 enhancements. The component-definition gains one control-implementation per baseline (730 implemented-requirements) with the checks and mapping source on each. README gains a "Continuous ATO" section and the fail-closed sentence on the claim line.
- `docs/SCF_GAP.md`: document-by-document comparison against the Secure Controls Framework 2026.3 (234 distinct documents: 48 covered, 23 partial, 163 gap) and the six-phase plan to close it; `docs/COMPARISON.md` SCF row refreshed to 2026.3 figures.

## [2.4.2] - 2026-10-13

### Fixed — exports map object-shaped findings to their controls

- `converters/exports/_lib/findings.py`: a violation that is an object (every STIG module emits
  `{vuln_id, stig_id, severity, rule_title, status}`) is rendered as `<id>: <title>` before the control lookup,
  so SARIF results, OSCAL assessment findings and OCSF events for the 23 STIG platforms now name the catalog
  control (`stig_oracle_linux_9-OL09-00-002413`) instead of `<framework>-unmapped` with a JSON blob as the
  message. Oracle Linux 9 on empty input: 77 of 78 results mapped; the one unmapped is the fail-closed notice.
- SARIF results carry the finding's own severity (`properties.severity`: `CAT I` / `CAT II` / `CAT III`) when the
  module states one.
- `scripts/rego_ast.py`: `rule_title` is a text key, so the OSCAL catalog statement of a STIG control is the DISA
  rule title (was "Implemented by a Rego rule in … see the rule body"). 23 STIG catalogs regenerated; control ids,
  uuids and counts unchanged (14,318).
- The SARIF and OSCAL round-trip tests evaluate a STIG module and assert the mapping, the severity and the title.

## [2.4.1] - 2026-10-13

### Added — CIS Oracle Cloud Infrastructure Foundations v3.1 and CIS Oracle Database 23ai

- `benchmarks/cis/oci/cis_oci_foundations.rego` (`cis_oci.main`): all 54 recommendations of the CIS OCI Foundations
  Benchmark v3.1 (ids and titles from the public Prowler mapping of v3.1.0; CIS lists 3.1.1 as current), each reading
  the OCI resource the audit procedure inspects — IAM policies and users, security lists and NSGs, compute
  instance options, Events rules and Notifications topics, Cloud Guard, KMS, Object/Block/File Storage,
  compartments. Level 2 recommendations are marked in the report. Green-tenancy, probe and all-54-fire tests.
- `benchmarks/cis/oracle/cis_oracle_23ai.rego` (`cis.oracle_23ai`): all 87 recommendations of the CIS Oracle
  Database 23ai Benchmark v1.0.0, generated from the benchmark's own audit SQL by
  `tools/cis_generators/gen_oracle_db_23ai.py` (78 Automated read the queried value or rows, 9 Manual are
  attestations). Input contract shared with the Oracle Database 19c STIG module.
- Count 14,175 → **14,318**; 770 policy files; suite 3,658 tests.
- Two findings for the owner: the existing `cis_oracle_19c.rego` cites recommendation ids and titles that are not the
  CIS 19c benchmark's (its "2.3 ADMIN_RESTRICTIONS" is the benchmark's 2.1.4, and sections 3.x–8.x are invented);
  the 23ai generator is the template for re-stamping it from the 19c PDF. And the OCI module's Events rule
  event-type lists are written from the benchmark text's intent; verify against a tenancy before quoting them.

## [2.4.0] - 2026-10-13

### Added — DISA STIGs for the Oracle platforms (October 2026 library)

- `benchmarks/stig/oracle_linux_9` (OL09 V1R7, 93 rules), `oracle_linux_8` (OL08 V2R10, 68 rules),
  `oracle_database_19c` (O19C V1R6, all 96 rules), `oracle_mysql_8` (MYS8 V2R3, all 100 rules). The Linux
  modules are derived from the RHEL 9 modules by DISA rule title with reviewed overrides; the database modules
  read the value DISA's check queries where there is one and carry a named attestation where the check is a
  review. Each platform has the fail-closed `main` alias, a green-fixture test that closes every finding, and
  a probe test that opens one. All four join the 800-53 spine (3,787 STIG rules mapped, was 2,767).
- Count 13,778 → **14,175** control-level checks; 768 policy files (was 740); suite 3,645 tests.
- `tools/stig_generators/parse_xccdf.py`, `gen_oracle_linux.py`, `gen_oracle_db.py`, `gen_crosswalk.py`.
- **Found on the way:** the RHEL 9 STIG modules' ids disagree with the current catalog for 108 of 143 findings
  (the title beside the logic names a different rule than the id). Documented in `benchmarks/stig/README.md`;
  re-stamping by title is the next STIG item. The October 2026 library no longer ships RHEL 8, WebLogic 12c or
  Oracle HTTP Server (RHEL 10 V1R3 appears); noted, not yet acted on.

## [2.3.7] - 2026-10-13

### Fixed — no module in the library is fail-open on empty input

- The coverage scan's unguarded list goes from 9 to **0** (`docs/COVERAGE_SCAN.md`: 577 self, 25 by
  orchestrator, 0 none, 138 n/a). Array-style benchmarks (nginx, OpenShift, ESXi, vCenter) take their facts as a
  precondition of `compliant`; set-style modules (RHEL 9 legacy PAM section, m365 Exchange section, crypto-miner
  detection) raise a `FAIL-CLOSED` notice when no facts are supplied. Crypto-miner detection keeps
  `default compliant := true` for a host whose facts show no indicator; a host with no facts at all is no longer
  reported clean. Each module has a hand-written regression test.
- **`not is_object(input.x)` never fired.** When `input.x` is missing, a builtin call on it is undefined and `not`
  of an undefined call stays undefined, so the GEISA "missing or not an object" notices (adm ×2, vee, lee, api ×2)
  were silent exactly when they mattered; `geisa_api` reported compliant on `{}`. They now test
  `object.get(input, ..., null)`. The same shape in mas_trm, meti_csm, dcc, fedramp_20x and pqc is guarded by a
  presence check first and means "present but wrong type", so it is left as is.
- The stamper reads a report's own `violations` / `violation_count` when the module publishes no top-level
  `violations` (the m365 v7 orchestrator, which deliberately carries no `compliant` key, now scores `self` on
  its 31 empty-input violations). `scripts/gen_tests.py` emits the fail-closed test for modules with a bare
  `compliant` rule and no report, so future generated suites measure what the scan measures.
- Count 13,775 → **13,778** (the three new notices are checks like the eighteen added in 2.3.5).

### Security — Kubernetes admission registry allowlist anchored on the host (#228)

- `kubernetes.admission.from_approved_registry` matched `startswith(image, registry)`, so an image from
  `quay.io.evil.example/...` satisfied the `quay.io` entry. The match is now anchored on the host component
  (`registry + "/"`, a trailing slash in the policy's own list is tolerated). Images with no registry prefix
  are still admitted as cluster-local, as documented in the module. Regression tests in
  `enforcement/kubernetes/tests/test_registry_allowlist.rego`; the Gatekeeper `k8saacadmission` template is
  rebuilt from the module.

### Changed — CIS GCP lives in one directory; the guard reads bare `compliant` rules (#227)

- `cis_gcp_main.rego` (57 checks, `cis_gcp.main`) moves from the legacy `benchmarks/cis/cloud/gcp/` tree to
  `benchmarks/cis/gcp/`, next to the foundations and Level 2 modules it belongs with, mirroring the AWS and Azure
  layout. Its smoke test moves with it; package, endpoint and count are unchanged. `benchmarks/cis/gcp` now
  reads as one benchmark (3 modules, 109 checks) and `cis_gcp_foundations` is judged as a section of it rather
  than as a sparse module on its own.
- `cis_gcp_foundations` fails closed: `default compliant := false` and `input.iam_users` as a precondition, the
  pattern the other array-style modules received in 2.3.5.
- The coverage stamper read `compliant` only from a report object, so a module with a bare `compliant` rule
  and no report was scored on its `violations` count alone. It now falls back to the bare rule. Effect on
  the scan: `cis_gcp_foundations` and the Amazon Linux 2023 user/group section (caught by its orchestrator,
  whose bare `compliant` is false on empty input) leave the unguarded list, which goes from 11 to 9. The nine
  that remain report `compliant` true, or nothing, on empty input with no orchestrator above them, and are
  the next fail-closed work item: nginx, OpenShift, the RHEL 9 legacy PAM module, m365 exchange, m365 v7
  complete, ESXi, vCenter, GEISA api, crypto-miner detection. (`docs/TEST_GENERATION.md` reported zero
  because its fail-closed test is only generated for modules with a report object.)
- `COVERAGE.md` regenerated: 732 of 740 policy files have tests (it still said 235 from before the generated
  suite). OSCAL and crosswalk dists rebuilt for the new path.
- Makefile: the generator targets are declared `.PHONY`; `make crosswalk` was a no-op because the `crosswalk/`
  policy directory satisfied the target.

## [2.3.6] - 2026-10-12

### Changed — citations read from every message shape; the last six fail-open modules

- The control-id reader now sees `sprintf` built messages in a rule head (`violations contains sprintf("CIS
  4.1.3.x: ...", [x]) if`) and object-valued violations (`v := {"standard": "CIP-002", "requirement": ...}`,
  `{"control_id": ..., "finding": ...}`), citing them from the id the module already carries. Uncited violation
  rules fall from 1,272 to 803 with no policy edited; cited controls rise from 8,966 to 9,354. The 803 left either
  build their message from data at evaluation time or carry no standard reference by design (GEISA, OWASP LLM,
  admission gates). Count: 13,775.
- Six modules whose reports were undefined until 2.3.5 turned out to be fail-open once they evaluated (the Amazon
  Linux filesystem and network sections, the RHEL 8 and Rocky 8 and 9 network sections, the Oracle legacy
  user-account module). Each now carries the fail-closed notice; `docs/TEST_GENERATION.md`: undefined reports 1,
  unguarded fail-open 0; suite 3520 tests.
- **Declared totals from the standards' own text** (`standard_total` in the report literal, compared in control
  ids, cited to where the number was counted): CIS Controls v8.1 **153 safeguards** — 153 of 153 cited, full;
  NIST CSF 2.0 **106 subcategories** (NIST CSWP 29: GV 31, ID 21, PR 22, DE 11, RS 13, RC 8) — 87 cited, partial,
  19 to write; NIST SP 800-171 **Rev 2, 110 requirements** (the numbering the module cites; Rev 3 has 97 active
  `03.xx.yy` ids, 130 in the text with 33 withdrawn, migration pending) — 88 cited, partial. Both NIST gaps are
  named in `KNOWN_GAPS` so CI keeps judging them; 45 of 49 declaring modules are within 10 %.

## [2.3.5] - 2026-10-12

### Fixed — the fail-closed contract, module by module

- **58 reports that were undefined on empty input now evaluate.** Three causes, each fixed at the source: CIS
  section reports echoed raw `input.x.y` facts (any missing fact voided the whole report) — every echo inside a
  report or summary literal is now `object.get(input, [...], null)`, `[]` where it is counted or iterated; NERC CIP
  reports embedded boolean rules that were undefined rather than false — each gets `default := false`; counted
  collections assigned from input get `default := []`. The one left is `enforcement/git/playbook_documentation.rego`,
  a protected path for its owner.
- **The 18 unguarded fail-open modules fail closed.** Modules with a `violations` set gain a `FAIL-CLOSED` notice
  when the facts they key on are absent; modules that aggregate arrays make those facts a precondition of
  `compliant` with a `false` default; CMMC's `compliant` gains the default it lacked; GEISA VEE's "not required"
  answer now needs a discovery response to say so. The test generator now asserts fail-closed for them
  (`docs/TEST_GENERATION.md`: undefined reports 1, unguarded fail-open 6; suite 3514 tests).
- **Strict mode is clean.** 31 `opa check --strict` errors fixed (unused imports, arguments, assignments; FinOps
  `is_past_date` now compares the date instead of `year < 2025`); every tree except `enforcement/git` (pending its
  owner) passes `opa check --strict`. The CI step that enforces it follows in its own PR.
- Control-level checks: 13,758 → 13,771 (the fail-closed notices are cited checks).


## [2.3.4] - 2026-10-12

### Added — a smoke test for every module, roles and a measured fail-closed guard in the coverage scan

- `scripts/gen_tests.py` wrote a smoke test for every module that had none (554 files under `tests/`). Each
  asserts only what its module was proven to do on empty input: it evaluates without a runtime error; its report
  is an object; its report is not compliant (fail-closed); its violations are non-empty. The suite grows from
  1,954 to 3375 tests; the CI discovery floor is ratcheted to 3,000.
- The coverage scan stamps roles — `section` (a small module an orchestrator in the same tree aggregates),
  `orchestrator`, `overlay` (supply-chain scoring, crosswalk), `gate` (enforcement and governance decisions) —
  and a measured **`guard`**: one evaluation of the whole tree on empty input says, per module, whether
  fail-closed is enforced by the module itself (`self`, 543), by a fail-closed orchestrator that references it
  (`orchestrator`, 24), by nothing (`none`, 35) or does not apply (`n/a`). Of the 165 modules that looked sparse
  by size, 147 are one of those roles by design; 18 are genuinely thin and `docs/COVERAGE_SCAN.md` names them.
- `docs/TEST_GENERATION.md` lists what the generator could **not** assert, classified by guard. The findings
  worth acting on: **60 modules whose report is undefined on empty input** (the `{}` collapse the contract
  forbids: a member of the report literal is undefined without facts, so a consumer gets nothing); **18
  modules that report compliant on empty input with no orchestrator guarding them** (fail-open); 19 that are
  compliant alone but guarded by their orchestrator (by design); 2 whose report says compliant while the
  module emits violations (the report's `compliant` is computed from a subset of the checks).

## [2.3.3] - 2026-10-12

### Changed — a check is a distinct check, not a distinct citation: 13,758, validated against 47 declared totals

Trying to fill the "sparse" modules showed they were not sparse. NIS2 holds 35 checks and declares 34; the SEC
rule module holds 23 and declares 22; FDA Part 11 holds 42 and declares 43; GLBA 34 and declares 33. The 2.3.2
rule reported 14, 8, 30 and 26 because it folded every check citing the same article paragraph into one
("Art.21(2)(c): BCP not documented" and "Art.21(2)(c): BCP not tested annually" became one control). A check is
now a distinct (control id, text) pair per module; a row re-listed with identical text is still one.

The rule is now validated by evidence outside itself: 47 modules declare their own total in their report
literal, and 45 are within 10 % of it under this rule (NSA/CISA Kubernetes 43/43, PostgreSQL 15 172/172, CSA CCM
185/197 across its domain modules ...). The two below are licensed texts we could only partly transcribe
(ISO/IEC 27701 67/134, CIS Windows 11 210/267) and are named in `scripts/coverage_stamp.py`; `make
check-coverage` fails if any other declaring module falls below 90 %, so a counter regression cannot pass CI.

| | checks |
|---|---|
| 2.2.0 regex | 7,867 |
| 2.3.0 AST, one shape | 7,560 |
| 2.3.1 AST, six shapes | 11,645 |
| 2.3.2 exclusion fix | 11,693 |
| **2.3.3 distinct checks, validated** | **13,758** |

11,693 module-level controls and 11,124 distinct controls across 143 frameworks are unchanged; the OSCAL
catalogs, crosswalk CSV and XCCDF table are keyed on controls and do not move.


## [2.3.2] - 2026-10-12

### Changed — verification pass on the 2.3.1 count: 11,693

Re-checking 2.3.1 by hand against seven modules of different shapes found one defect: the check-map shape dropped
names that merely *contained* a plumbing word (`shared_accounts_managed` matched `count`). The exclusion list is
now anchored on whole words; 48 checks return. 2.3.1's stamping also left a second, misplaced `coverage:` block at
the end of every stamped module (harmless to OPA, wrong all the same); the stamper now removes every existing
block before writing one, and `make check-coverage` fails unless exactly one sits inside `custom:`.

Reproducibility, on today's tree: the 2.2.0 counter says 7,912, the 2.3.0 counter says 7,560, the 2.3.1 counter
says 11,645, this one says 11,693. Each earlier number is what its rule could see, not a different library.


## [2.3.1] - 2026-10-12

### Changed — the count reads every policy shape: 11,645 control-level checks

2.3.0 fixed *how* the counter read a line; this release fixes *what* it looks for. The 2.3.0 rule saw only
violation sets named `violations`/`deny` and top-level control tables, so 233 real modules counted as zero:
every STIG core module (`findings := [finding_r_<id>, ...]`), the PostgreSQL / MySQL / Oracle / Windows 11
benchmarks (`<section>_violations := [v | arrays := [["1.1: ..." | not check], ...]]`), the sectioned CIS host
modules (`config_violations contains "CIS 4.1.1: ..." if`), the SOC 2 and CAF modules (check maps
`findings := {"mfa_for_privileged_access": mfa_for_privileged_access, ...}`), the CMMC practice tables and the
Sentinel gates (`violation_df_003 contains msg if`). `scripts/rego_ast.py` now reads all six shapes from OPA's AST
and counts, per module, every distinct control id it evaluates plus each check that carries no id. Report
plumbing (`compliance_summary`, `total_controls`, section aggregates) is excluded by name.

| | 2.2.0 | 2.3.0 | 2.3.1 |
|---|---|---|---|
| control-level checks | 7,867 (regex, over- and under-counted) | 7,560 (AST, one shape) | **11,645 (AST, every shape)** |
| modules counted as zero | 233 | 233 | 55 (42 orchestrators, 13 pure-boolean modules) |

### Added — coverage stamped into every module's METADATA

`make coverage` (`scripts/coverage_stamp.py`) scans every module and writes `custom.coverage` into its
`# METADATA` block: checks, cited ids, the total the module itself declares, density (`full` / `partial` /
`sparse` against a declared total; `sized` / `sparse` / `stub` by size; `orchestrator`; `unrecognised`),
whether a test file exists, the entrypoint, and the library version of the scan. `make check-coverage` (in CI)
fails when a stamp is stale, so density and gaps are validated on every change instead of rediscovered.
`docs/COVERAGE_SCAN.md` is the human report: distribution, per-family totals, modules below their own declared
total (the provable missing controls), sparse modules without a declared total, unrecognised shapes, untested
modules.


## [2.3.0] - 2026-10-12

### Changed — the control-level count is now exact, and lower

**7,560 control-level checks** (was 7,867 at 2.2.0). No policy changed; the counter did. The old `make count`
read source lines with regular expressions and had two faults that partly cancelled: it counted the fields inside
multi-line table rows (`"text": "..."`) and the rows of report scaffolding (`report := Ellipsis`) as checks (+945),
and it missed every violation rule whose set element is a string literal or an object rather than a bare
variable (`violations contains "CIS L2 1.5: ..." if`, `deny contains {"msg": m} if`) (−638). The count now comes
from OPA's own parser (`scripts/rego_ast.py`, `opa parse --format json`): a multi-value violation rule, a leaf
object row of a top-level table, or a string row of a check table is one check; fields and scaffolding never are.
`scripts/inventory_controls.py` reads the same AST under the same rule, so the exports and the published number
cannot drift (7,560 checks → 6,076 distinct controls across 121 frameworks with controls).

We say "largest executable compliance library anyone can verify" and that claim must be exact; the next largest
public rule set we measured, Azure Policy built-ins, holds 5,130 definitions.

### Added
- **OSCAL 1.2.3 catalog export** (`converters/exports/oscal`): one catalog per framework (121) built from the new shared control inventory `scripts/inventory_controls.py` (7,560 checks → 6,076 distinct controls); committed under `dist/catalogs/`, combined `all.json` attached to releases, every catalog validated against the NIST schema in CI with a round-trip test proving no control is lost or invented.
- **SARIF 2.1.0 and OCSF 1.9.0 exports** (`converters/exports/sarif`, `converters/exports/ocsf`): convert any `compliance_report` output (an `opa eval -f json` file) into SARIF results for GitHub code scanning and every SARIF viewer, and into OCSF `compliance_finding` events for Security Lake, Splunk and Sentinel. Both use the OSCAL control id as the rule / finding uid, read one shared findings reader (`converters/exports/_lib/findings.py`), and are schema-validated with round-trip tests in CI.
- **Crosswalk CSVs** (`converters/exports/crosswalk_csv/dist`): `controls.csv` (every control with its OSCAL id), `stig_to_800_53.csv` (2,767 STIG rules), `framework_to_800_53.csv`, and `spine_800_53.csv`, the SCF-style pivot on the 800-53 spine (baseline membership, STIG rules per platform, library controls). **CIS-CAT / XCCDF join table** (`converters/exports/xccdf_ids/dist/cis_xccdf_ids.csv`): 1,126 CIS sections on 15 platforms with the XCCDF rule-id prefix to join CIS-CAT results on. Both committed, round-trip tested, kept fresh by CI.
- **OSCAL component-definition and assessment-results** (`converters/exports/oscal`): `dist/component-definition.json` (one implemented-requirement per catalog control) and `build_assessment_results.py` (from `compliance_report` output: one finding and observation per distinct violation targeting the catalog statement; controls without a finding are not asserted satisfied). Schema-validated and round-trip tested with the catalogs.

_Nothing yet._

---

## [2.2.0] - 2026-10-12

The Asia-Pacific release. **740 policy files** (996 including tests, counted at main 2026-10-12),
**7,867 control-level checks** (`make count`, new in this release; 7,104 at 2.1.1). 1,945 tests pass. No policy is removed or renamed; `enforcement/aap` is unchanged. Eleven new
frameworks in one day: the CCPA 2025 regulations (three modules) and seven Asia-Pacific regimes —
Singapore, India (two), Japan, Australia, Hong Kong, Malaysia — each written from the regulator's own
text, each an attestation module that fails closed and reports gaps by chapter or section.
Metadata vocabulary gains sources `mas`, `cert-in`, `meity`, `meti`, `apra`, `hkma`, `bnm` and domains
`singapore`, `india`, `japan`, `hong-kong`, `malaysia`.

### Added
- **Bank Negara Malaysia — Risk Management in Technology (RMiT), 25 September 2026** —
  `frameworks/financial/bnm_rmit/`, `bnm_rmit.main`, written from BNM/RH/PD 028-98 as published: one control
  per mandatory **S paragraph of Part B §§8–15 (99 standards)** — governance, technology risk management,
  technology operations, cybersecurity management, digital services, technology audits, external party
  assurance, awareness. Cloud, third-party, NCII and digital-services paragraphs are gated by flags that must
  be declared true or false. The report carries the 2027 dated obligations and the 4-hour / 120-minute
  availability targets. 11 tests. Vocabulary gains source `bnm` and domain `malaysia`.
- **HKMA Supervisory Policy Manual TM-G-1 General Principles for Technology Risk Management + TM-C-1
  Supervisory Approach on Cyber Risk Management (Hong Kong)** — `frameworks/financial/hkma_trm/`,
  `hkma_trm.main`, written from the HKMA texts: one control per TM-G-1 paragraph that sets an expectation
  across IT governance, security management, system development and change, information processing,
  communications networks and service providers (62), plus the five duties TM-C-1 (29 Nov 2024, statutory)
  places on AIs: proportionate framework, prompt incident reporting to the HKMA, regular C-RAF assessments,
  Secure Tertiary Data Backup, CISP intelligence sharing. WLAN, technology outsourcing and overseas-IT
  paragraphs are gated by flags that must be declared true or false. 9 tests. Vocabulary gains source
  `hkma` and domain `hong-kong`.
- **APRA Prudential Standard CPS 234 Information Security (Australia, July 2019)** —
  `frameworks/financial/apra_cps234/`, `apra_cps234.main`, written from the APRA text: one control per
  requirement paragraph 13–36 (24 controls) across roles, capability, policy framework, classification,
  controls, incident management, testing, internal audit and APRA notification. The four paragraphs that
  condition on related-party or third-party management of information assets (16, 22, 28, 34) are gated by
  `third_party_managed_assets`, which must be declared true or false. The 72-hour incident and
  10-business-day control-weakness notification clocks are in the report. 8 tests. Vocabulary gains source `apra`.
- **METI Cybersecurity Management Guidelines Ver. 3.0 (Japan, 2023)** — `frameworks/regional/meti_csm/`,
  `meti_csm.main`, written from the METI/IPA English text: Appendix A-1 (the three principles
  management must recognise, 9 items) and A-2 (the ten directions, 40 items), **49 items** each carrying
  the NIST CSF subcategory references the Guidelines print beside it. Attestation shape with a
  per-principle / per-direction gap report. Fail-closed; nothing can be scoped out. 10 tests.
  Vocabulary gains source `meti` and domain `japan`.
- **India — Digital Personal Data Protection Act, 2023 + DPDP Rules, 2025** — `frameworks/privacy/dpdp_india/`,
  `dpdp.main`, written from the Act and the Rules as gazetted (G.S.R. 846(E), 13 November 2025):
  s.4 lawful basis, s.5/Rule 3 notice, s.6 consent, s.8 general obligations, **Rule 6 reasonable security
  safeguards** (encryption/masking/tokens, access control, access logs, backups, one-year log retention,
  processor contracts), **Rule 7 breach intimation** (Data Principals without delay; Board without delay and
  the detailed report within 72 hours), Rule 8 retention and Third Schedule three-year erasure with the
  48-hour notice, s.9/Rules 10–12 children (verifiable parental consent with identity due diligence, no
  tracking or targeted ads), s.10/Rule 13 Significant Data Fiduciary (DPO in India, independent auditor,
  annual DPIA and audit, algorithmic due diligence, data-localisation of notified data), ss.11–14/Rule 14
  rights, s.16/Rule 15 transfers, Rule 23 Government requests. Four scope flags must be declared true or
  false. The report carries the phased commencement dates (substantive duties 2027-05-13) and the Schedule
  penalty tiers. 10 tests. Vocabulary gains source `meity`.
- **CERT-In Directions under s.70B(6) of the IT Act (India, 28 April 2022)** — `frameworks/regional/cert_in/`,
  `cert_in.main`. Directions (i)–(vi) and Annexures I–III from the CERT-In text: NIC/NPL time
  synchronisation, **6-hour incident reporting** with all **twenty Annexure I incident types** as
  individual checks, CERT-In orders and the Annexure II Point of Contact, **180-day rolling logs kept
  within India**, subscriber registration (7 fields, 5-year retention) for data centre / VPS / cloud /
  VPN providers, and KYC + reconstructable transaction records for virtual asset service providers.
  The two sector flags must be declared true or false; undeclared is a violation. 12 tests. Vocabulary
  gains source `cert-in` and domain `india`.
- **MAS Technology Risk Management Guidelines (Singapore, January 2021)** — `frameworks/financial/mas_trm/`,
  `mas_trm.main`. One control per Guidelines paragraph that states a "should": **237 controls across
  chapters 3–15** (governance, TRM framework, project management and security-by-design, software
  development, IT service management, IT resilience, access control, cryptography, data and
  infrastructure security, cyber security operations, cyber security assessment, online financial
  services, IT audit), attested from the FI's evidence as `input.mas_trm.controls["<paragraph>"]`.
  Per-chapter report with gaps; chapter 14 is scoped out by `online_financial_services=false` and
  nothing else can be excluded. Fail-closed on absent/non-true attestations, unknown ids and a
  malformed container. 14 tests. First Asia-Pacific framework beyond ACSC Essential Eight; metadata
  vocabulary gains source `mas` and domain `singapore`.
- **CCPA — the 2025 CPPA regulations (effective 2026-01-01)** as three new modules under
  `frameworks/privacy/ccpa/`, written from the OAL-approved text (approved 2025-09-22):
  - `ccpa.cybersecurity_audits` — Article 9, §§7120–7124: §7120 applicability thresholds
    (with a contradiction check when a business declares itself out of scope), §7121 first-report
    deadlines by revenue tier (2028/2029/2030-04-01, date-gated), §7122 auditor qualification and
    independence (internal-auditor reporting line), all **18 §7123(c) components** (each may be
    recorded not-applicable by the auditor), the §7123(e) report contents, and §7124 certification
    to the Agency. 44 checks.
  - `ccpa.risk_assessments` — Article 10, §§7150–7157: the six §7150(b) triggering activities
    (each must be declared in_use true/false — undeclared is a violation), §7151 stakeholder
    involvement, the nine §7152(a) report requirements plus the ADMT logic/output requirement,
    §7153 provider duties, §7155 timing (three-year review, 45-day material-change update, legacy
    processing by 2027-12-31, five-year retention) and §7157 submission to the Agency. 26 checks.
  - `ccpa.admt` — Article 11, §§7200–7222: Pre-use Notice contents (§7220), the opt-out right
    with the three §7221(b) exceptions and their conditions, sixteen §7221 opt-out mechanics
    (two methods, named link, no cookie-banner-only, no verification, 15-business-day cessation,
    service-provider notification), and the §7222 access right. Compliance date 2027-01-01 is
    reported, and gaps are reported before it. 36 checks.
  - `ccpa.main` now orchestrates 7 modules (was 4). 27 new tests in
    `frameworks/privacy/ccpa/tests/test_ccpa_2026_regulations.rego`.

### Changed
- `STANDARDS_UPDATE_REGISTRY.md`: CCPA row moved from "rulemaking ongoing" to implemented;
  COBIT row records COBIT 7's publication (ISACA, Foundation cutover 2026-10-27) and that the
  module stays COBIT 2019 until the COBIT 7 content is published and regenerated.

---

## [2.1.1] - 2026-10-10

Two days after 2.1.0, for the first consumer's second finding. **729 policy files**
(977 including tests, counted at main 2026-10-10). 1,845 tests pass. No policy is
removed or renamed; `enforcement/aap` is unchanged.


### Added
- **Package-scoped `# METADATA` on every policy.** All 729 policy files now resolve to an OPA
  annotation block carrying `title` and `custom.{class, framework, source, domains}`, so a
  consumer classifies a policy from `opa inspect -a` instead of parsing directory names. `class`
  is a closed set (`security`, `compliance`, `ot`, `governance`, `enforcement`,
  `threat-detection`) that maps to the OPA container; `source` and `domains` come from the
  controlled vocabulary in `scripts/metadata_vocabulary.json`. `scripts/check_metadata.py`
  (`make metadata`, now part of `make check`) fails when a block is missing or off-vocabulary.
  `scripts/backfill_metadata.py` is the directory-driven bootstrap for new trees. OPA permits one
  package-scoped block per package, so the two multi-file packages (`aac.aap.policy`,
  `supply_chain.slsa`) have one owning file and pointer comments in the rest.

### Fixed
- **`eu_ai_act` reported compliant on empty input (fail-open, #186).** A missing classification
  was given the strictest tier and then judged on the absence of evidence: no prohibited-practice
  fact is `true`, so the module has zero violations and `overall_compliant` was `true` on `{}`.
  `eu_ai_act.main` now carries the same fail-closed gate as `cis_rhel9.main`: `input.eu_ai_act`
  must be a non-empty object and `system_classification.risk_tier` one of the five tiers before
  anything can pass; each failure is an explicit `FAIL-CLOSED:` violation. The report gains a
  `compliant` key (one key across frameworks), `facts_supplied` and `classified`; `violations`,
  `violation_count` and `total_violations` now carry the real aggregate instead of the literal
  `[]` / `0` they were hard-coded to. Tests: `governance/eu_ai_act/tests/test_eu_ai_act_main.rego`.
- **DISA STIG RHEL 8 / RHEL 9 were unreachable from the uniform entrypoint.** Both bundles
  exposed only `stig_assessment` and had no `stig.<platform>.main` alias, so a caller using the
  library-wide `data.<package>.main.compliance_report` contract got `undefined` back. Added the
  uniform `compliance_report` contract to `stig_rhel8_complete.rego` / `stig_rhel9_complete.rego`
  and the fail-closed `stig.rhel_8.main` / `stig.rhel_9.main` aliases
  (`benchmarks/stig/rhel_8/stig_rhel_8_main.rego`, `benchmarks/stig/rhel_9/stig_rhel_9_main.rego`),
  matching the other 13 STIG platforms: empty input reports `compliant=false`,
  `facts_supplied=false`, 0% with an explicit FAIL-CLOSED CAT I finding. `total_controls` is derived
  from the module finding arrays (73 for RHEL 8 V1R13, 143 for RHEL 9 V2R2), not hard-coded.
  Tests: `tests/test_stig_rhel_8_main.rego`, `tests/test_stig_rhel_9_main.rego`.

---

## [2.1.0] - 2026-10-08

Seventeen days of additions since 2.0.0, and the first release consumed by Red Hat's AAP
Policy as Code in a live environment (ericcames/sales.demos#841). The library grew from 638 to
**729 policy files** (976 including tests, counted at main 2026-10-08). 1,837 tests pass.

### Fixed — fail closed, everywhere it was not
- **CIS RHEL 9 sections fail closed on missing facts** (#183). `filesystem`, `network` and
  `user_group` reported compliant with no facts at all, so `cis_rhel9/compliance_assessment`
  scored 21.4% with 3/14 sections compliant on empty input. Each now emits a `FAIL-CLOSED`
  violation per missing required fact object; `{}` reports `compliant=false, score=0, 0/14`.
  The guard clears when the fact objects are supplied and names each missing key. Reported by
  Eric Ames while attaching the policy to AAP.
- **STIG RHEL 8 / RHEL 9 gain `.main` aggregators** (#182), so `stig.rhel_8.main` (73 rules)
  and `stig.rhel_9.main` (143 rules) answer the uniform `compliance_report` entrypoint and fail
  closed on `{}` (every rule failed, 0%). They were previously unreachable by key.
- **AAP Policy as Code: AAP 2.7's team objects accepted** (#161), with a real AAP 2.7 input
  document captured from a live decision log as a test fixture.
- `is_object` guard on `_attest` in the CJIS, Zero Trust and Essential Eight orchestrators (#143);
  governance time-box clamp, approval expiry enforced, registry shape guard (#138).

### Added — new frameworks
- **AI governance:** ISO/IEC 42005:2025 AI impact assessment and the OWASP LLM Top 10 (2026)
  with a MITRE ATLAS crosswalk (#181); governance self-protecting MCP gate, load-bearing agent
  identity, crown-jewels tier (#136); group-membership read tools approved for agent inventory
  lookups (#146).
- **Federal:** FedRAMP 20x Key Security Indicators, 46 KSIs with Class B/C profiles (#180);
  PQC Readiness — FIPS 203/204/205, EO 14412, CNSA 2.0 (#165); FBI CJIS Security Policy, 13
  policy areas (#135); Zero Trust — CISA ZTMM v2.0 + NIST SP 800-207 (#132); IRS Publication
  1075, 8 safeguard areas (#140).
- **Regional:** UK MoD DCC — DEF STAN 05-138 Issue 4, all 148 controls (#166); BSI C5:2020
  (#142); UK Cyber Essentials (Willow) (#141); ACSC Essential Eight Maturity Model (#133).
- **Benchmarks:** CIS MCP Server Benchmark v1.0.0, 46/55 recommendations (#145).
- **Supply chain:** SSDF-GenAI, NIST SP 800-161 and S2C2F on a shared spine with a measured
  collapse metric (#111).
- **DORA level-2 RTS modules:** subcontracting (2025/532) and TLPT (2025/1190) (#177).

### Changed — reconciled with the standards as published
- EU AI Act: Digital Omnibus Reg. (EU) 2026/1744 dates and new Art. 5 prohibitions (#175).
- CRA: reconciled with the final Regulation (EU) 2024/2847 text (#167). ITAR: 2025–2026 final
  rules, §120.54 cites, AUKUS §126.7 (#178). NY DFS second amendment final tranche: universal
  MFA, 500.13(a) asset inventory (#176). CISA CPG titles aligned to the 2025-12-11 publication
  (#179). Standards registry 2026-10 sweep triage (#174).

### Changed — distribution and CI
- The bundle declares explicit roots so a consumer can compose site config beside it (#164).
- CI tests on OPA 1.10.0, the version the bundle publishes for (#163), and `opa check` runs
  package-aware per directory (#162). `actions/checkout` v7 (#134).
- A pre-merge Rego review skill tuned to this library's failure classes (#137, #139).

### Known limitations
- Seven `.main` entrypoints still answer `{}` on empty input: `digital_sovereignty`, `fisma`,
  `gdpr`, `hipaa`, `pci_dss`, `soc2`, `sox`. A consumer must treat an empty report as a failed
  assessment, never as a pass.
- The CIS RHEL 9 input is a custom document (about 60 top-level keys), not raw Ansible facts
  or OpenSCAP output; no shipped collector produces all of it yet. The section-level guards
  above make a partial input report what it did not evaluate.

---

## [2.0.0] - 2026-09-21

Six months of additions since the initial extraction. The library grew from 327 to
**638 policy files** (796 including tests), roughly doubling framework coverage and adding a
production distribution path, Level 2 hardening profiles, and a standards-update registry.

### Added — new frameworks
- **AI governance:** EU AI Act (Regulation 2024/1689) suite (`governance/eu_ai_act/`) and
  ISO/IEC 42001:2023 AIMS (`governance/iso_42001/`), completing the AI trio with NIST AI RMF.
- **Privacy:** ISO/IEC 27701:2019 PIMS; CCPA / CPRA; FERPA (20 U.S.C. §1232g) and
  COPPA (16 CFR Part 312) — 53 controls across the two education/children's-privacy rules.
- **Federal:** NIST SP 800-171 Rev 3 (14 families, 110 CUI requirements); CISA CPG 2.0
  (34 goals across the six CSF-2.0 functions incl. GOVERN).
- **Management:** CSA CCM v4.0 (16 domains, 197 controls); COBIT 2019 governance-system attestation.
- **Security program:** **CIS Controls v8.1** — the 18 Critical Security Controls / 153 safeguards,
  Implementation-Group tiered (cumulative IG1 ⊆ IG2 ⊆ IG3 scoring) with a fail-closed report
  (`frameworks/management/cis_controls_v8/`). Distinct from the CIS *Benchmarks* the library already ships.
- **SaaS security posture:** CISA SCuBA Microsoft 365 Secure Configuration Baselines — 104 policies
  across 7 products (Entra ID, Exchange Online, SharePoint/OneDrive, Teams, Defender, Power Platform,
  Power BI).
- **Financial:** GLBA Safeguards Rule (16 CFR 314).
- **Regulatory:** ITAR (22 CFR 120–130) data-safeguarding slice; DORA; NIS2.
- **Critical infrastructure:** NERC-CIP **CIP-015 INSM**; TSA Pipeline Security Directives
  (SD Pipeline-2021-01G/02G, 112 requirements); NCSC CAF 4.0 (23 Cyber Outcomes).

### Added — platform coverage
- **DISA STIGs expanded from 8 to 19 current platforms** — RHEL 8/9, Ubuntu 20.04/22.04,
  Amazon Linux 2023, SLES 15, Windows 10/11, Windows Server 2016/2019/2022/2025, SQL Server 2016,
  PostgreSQL 16, Apache 2.4, Cisco IOS-XE Router, Kubernetes, OpenShift 4, and VMware vSphere 8 —
  with XCCDF-verified rule IDs and fail-closed entrypoints.
- **Kubernetes hardening** — CIS managed-Kubernetes benchmarks (EKS v1.8.0, AKS v1.8.0,
  GKE v1.9.0; 145 controls), the NSA/CISA Kubernetes Hardening Guide v1.2 (43 controls), and
  Pod Security Standards (baseline + restricted profiles).
- **CIS Level 2 hardening profiles** for RHEL 9, Ubuntu 22.04, and Windows Server 2022.
- CIS benchmark content refreshed to May 2026 releases; added CIS Microsoft 365 (SaaS),
  PostgreSQL, and additional network devices.

### Added — distribution & governance
- **OCI bundle distribution** via GitHub Container Registry
  (`ghcr.io/ynotbhatc/rego_policy_libraries`) — pull and load without cloning.
- **`STANDARDS_UPDATE_REGISTRY.md`** — pinned version, upstream revision cadence, and watch URL
  per standard, so modules regenerate when a standard changes instead of drifting silently.
- Enforcement: CI/CD pipeline gating, SLSA supply-chain governance, and a broad Terraform plan
  **pre-apply** ruleset (`enforcement/terraform/`) that blocks non-compliant plans before apply.
- Governance: OIDC token validation, FinOps tagging, GEISA (API / ADM / LEE / VEE).
- Waiver / exceptions handling across frameworks.

### Changed
- Documented the uniform entrypoint convention: `data.<package>.main.compliance_report` for every
  framework, so a caller evaluates one by name without learning its internal layout.
- README rewritten with per-standard coverage tables, reproducible count commands, and fail-closed
  documentation.

### Corrected
- **CIS RHEL 9 coverage claim corrected** from the 1.0.0 "338/338 (100%)" to the reproducible,
  defensible figure: **224+ distinct CIS control IDs**, counted from the violation messages the
  modules emit (a floor — one rule can satisfy multiple controls). The library now publishes the
  number it can prove rather than a headline percentage.

### Notes
- All policies remain Rego v1 (`import rego.v1`), vendor-neutral, Apache 2.0.

---

## [1.0.0] - 2026-03-26

### Added
- Initial extraction from [ynotbhatc/compliance](https://github.com/ynotbhatc/compliance) AAC project
- 327 Rego policy files reorganized into a three-axis taxonomy:
  - `benchmarks/` — CIS Benchmarks (200+ files) and DISA STIGs (8 files)
  - `frameworks/` — Regulatory frameworks (NIST, FISMA, FedRAMP, CMMC, ISO 27001,
    SOC 2, PCI-DSS, SOX, GDPR, HIPAA, NERC-CIP, IEC 62443, AMI/NIST IR 7628,
    Digital Sovereignty)
  - `enforcement/` — Gate-style enforcement (Ansible, Terraform, Dockerfile,
    Kubernetes, Git)
  - `governance/` — AI governance and MCP tool-call enforcement
  - `threat_detection/` — Crypto miner detection
- README with taxonomy explanation and OPA usage examples
- Makefile with `test`, `lint`, `check` targets
- GitHub Actions CI: `opa check` on every PR and push to main

### CIS Coverage at v1.0.0
| Platform | Controls |
|----------|----------|
| RHEL 9 | 338/338 (100%) |
| RHEL 8 | Full |
| Ubuntu 22.04 | Full |
| Ubuntu 20.04 | Full |
| Ubuntu 24.04 | Full |
| Debian 11 | Full |
| Rocky Linux 8 | Full |
| Rocky Linux 9 | Full |
| Amazon Linux 2023 | Full |
| Windows Server 2016/2019/2022 | Full (modular) |
| Windows 10/11 | Full |
| AWS/Azure/GCP Foundations | Full |
| Docker, Kubernetes, OpenShift | Full |
| MySQL, Oracle, PostgreSQL | Full |
| Apache, Nginx | Full |
| Cisco, Juniper, Palo Alto, Fortinet, Arista | Full |
