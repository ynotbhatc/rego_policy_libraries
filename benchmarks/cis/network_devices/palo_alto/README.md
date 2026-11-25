# CIS Palo Alto Firewall 11 Benchmark v1.2.1

**Version:** v1.1 · generated 2026-11-14, typed-evidence rules 2026-11-24, by `tools/cis_generators/gen_palo_alto.py` from the CIS workbook

All 79 recommendations (62 Automated, 17 Manual; 69 Level 1, 10 Level 2). 66 are decided from the collected
configuration and fail closed with an "evidence missing" message when the fact was not collected; 13 judgement
items are attestation booleans. Messages carry the control id and our own wording, not CIS text.

Query: `POST /v1/data/cis_palo_alto_panos/main/compliance_report` (roll-up package `cis_palo_alto_panos`).

## Profile

`input.cis_profile.level` is the number `1` or `2` (Level 2 includes Level 1). Absent, it is `2`. `total_controls` is the
number in scope: 69 at Level 1, 79 at Level 2. On empty input every one of them fails.

Any other level (the string `"2"`, `3`, `null`, or a `cis_profile` that is not an object) is not read as a default. The
report is scoped at Level 2, carries `cis_profile.level: evidence invalid — cis_profile.level must be the number 1 or 2,
got …`, and the ten Level 2 recommendations fail with the same finding, because the profile that decides them could not
be read.

## Sections

| Section | Recommendations | Attested |
|---|---|---|
| 1 Device setup | 26 | 1.2.1, 1.2.2, 1.2.5, 1.6.3, 1.7.1 |
| 2 User identification | 8 | 2.1, 2.5, 2.6, 2.7 |
| 3 High availability | 3 | |
| 4 Dynamic updates | 2 | |
| 5 WildFire | 8 | 5.1, 5.7 |
| 6 Security profiles | 25 | |
| 7 Security policies | 4 | |
| 8 Decryption | 3 | 8.2, 8.3 |

2.1, 2.6 and 5.1 are Automated in the workbook but attested here: 2.1 is read from traffic logs, 2.6 is an
Active Directory setting, and the 5.1 defaults differ by PAN-OS release. Manual recommendations with a decidable
setting (1.2.4, 5.8, 6.2, 6.20, 6.24, 6.25, 7.4) are checked like Automated ones. 6.22-6.25 apply only while the
named license is active.

## Facts

`input.panos_config` is the running configuration (`show config running`) converted from XML to JSON: `-` in
element names becomes `_`, every `<entry>` list is an array of objects keyed by `name`, every `<member>` list is an
array of strings, booleans stay `"yes"`/`"no"` (JSON `true`/`false` read the same), and numbers are JSON numbers.
The full path list is in the header of `cis_palo_alto_panos.rego`.

| Input | Source |
|---|---|
| `deviceconfig.system`, `deviceconfig.setting`, `deviceconfig.high_availability` | device setup, services, update schedules, HA |
| `mgt_config.password_complexity`, `mgt_config.password_profile[]` | admin password rules |
| `shared.*` | server profiles, log settings, authentication and log forwarding profiles |
| `network.profiles.{interface_management,zone_protection}[]`, `zone[]`, `user_id.{setting,include_exclude_network[]}` | interfaces, zones, User-ID |
| `profiles.<kind>[]`, `profile_group[]` | antivirus, anti-spyware, vulnerability, URL filtering, data filtering, WildFire |
| `rulebase.{security,default_security_rules,decryption}[]` | policies |
| `licenses[]` | `request license info` |
| `site.{untrusted_zones,internet_zones,url_block_categories}` | the operator's zone classification and URL block list |
| `attest.*` | attestation booleans |

An absent list is evidence missing. An empty rule list or an empty `site` list also counts as evidence missing.
A `profiles.<kind>` list that was collected and is empty is not missing evidence: the recommendations that need a
profile of that kind fail with `(no <kind> profile configured)`. 6.22-6.25 still do not apply without their license.

## Typed facts

A value of the wrong type never passes and is never read as a default. The recommendation that reads it fails with
`<id>: evidence invalid — panos_config.<path> must be <type>, got <value>`:

| Type | Accepted | Facts |
|---|---|---|
| number | a JSON number (`"14"` is a string) | password complexity counts and expiry, password-profile expiry, `idle_timeout`, lockout `failed_attempts` / `lockout_time`, zone-protection flood rates and scan `interval` / `threshold` / `duration`, data-filtering `alert_threshold` |
| yes/no | `"yes"` / `"no"` in any case, or JSON `true` / `false` | every yes/no setting a recommendation reads, licence `expired`, rule `disabled` |
| list | a JSON array | security-rule `from`, `to`, `source`, `destination`, `application`, `service`, profile lists and `group`; decryption-rule `to`; URL-filtering `allow`, `alert`, `block`, `continue` |
| string | a JSON string | security-rule `action`, licence `feature` |

An absent yes/no in a collected section is the device default (see "Absent yes/no settings" below); an absent number fails the recommendation that needs it. `null` is a
wrong type.

Regenerate: see `tools/cis_generators/README.md`.

### Absent yes/no settings

The running configuration leaves out a setting that is at its default, and the collector does not invent values. So a
yes/no key that is absent from a collected section is read as the PAN-OS default, and it passes only where that default
is the state the recommendation asks for. When the section itself is absent the recommendation reports evidence missing.

| Fact | Recommendation | Passing state | PAN-OS default | Absent in a collected section |
|---|---|---|---|---|
| `user_id.setting.enable_probing` | 2.2 | no | no (CIS lists the default as not configured) | passes |
| `deviceconfig.high_availability.election_option.preemptive` | 3.3 | no | no ([preemption is disabled by default](https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-admin/high-availability/ha-concepts/device-priority-and-preemption)) | passes |
| `network.profiles.interface_management[].{http,telnet}` | 1.2.4 | no | no | passes |
| `deviceconfig.setting.wildfire.session_info_select.exclude_*` | 5.4 | no | no | passes |
| `profiles.url_filtering[].log_container_page_only` | 6.11 | no | **yes** ([Default: Enabled](https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-web-interface-help/objects/objects-security-profiles-url-filtering/url-filtering-settings)) | **fails**: the profile must state `no` |
| `licenses[].expired` | 6.8, 6.22-6.25 | no | none: `request license info` states it on every entry | evidence invalid (so is an entry without `feature`) |
| `rulebase.security[].disabled`, `rulebase.decryption[].disabled` | scope | - | no (the rule is active) | the rule is assessed |
| every setting whose passing state is yes | - | yes | - | fails |
