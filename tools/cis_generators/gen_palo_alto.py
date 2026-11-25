"""CIS Palo Alto Firewall 11 Benchmark v1.2.1 -> benchmarks/cis/network_devices/palo_alto/.

    python3 tools/cis_generators/dump_workbook.py <workbook.xlsx> /tmp/pa.json
    python3 tools/cis_generators/gen_palo_alto.py /tmp/pa.json benchmarks/cis/network_devices/palo_alto
    opa fmt -w benchmarks/cis/network_devices/palo_alto

Typed facts (2026-11-24): fact(typed=[T(...)]) names the numbers, yes/no values, lists and strings a check reads; a
wrong type is an "evidence invalid" finding (helpers _bad, _n, _yes). fact(nonempty=<kind>) makes a collected, empty
profiles.<kind> list a failed recommendation ("no <kind> profile configured") instead of missing evidence.

Every recommendation in the workbook gets a rule. Each logic entry carries a keyword that must occur in the
workbook title of its id; the run aborts on any count, id, status, profile or keyword mismatch. Titles are
replaced by our own wording (OWN below, else neutralize.py) before anything is written. Writes only the files
it owns (roll-up, .main bridge, generated recommendation tests).
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cis_genlib import LEVEL_HELPERS, LEVEL_VIOLATIONS, load_workbook_json, emit_control, emit_tests, table  # noqa: E402

WB = load_workbook_json(sys.argv[1])  # JSON from dump_workbook.py
OUT = sys.argv[2]
BENCH = "CIS Palo Alto Firewall 11 Benchmark v1.2.1"
PKG = "cis_palo_alto_panos"
P = "input.panos_config"
N_TOTAL, N_AUTO, N_L1, N_L2 = 79, 62, 69, 10

KW = {}


def add(path, value):
    return [{"op": "add", "path": "/panos_config" + path, "value": value}]


def rm(path):
    return [{"op": "remove", "path": "/panos_config" + path}]


KIND_LABEL = {"virus": "antivirus", "spyware": "anti-spyware", "vulnerability": "vulnerability protection",
              "url_filtering": "URL filtering", "data_filtering": "data filtering", "wildfire_analysis": "WildFire analysis"}
YN, NUM, LST, STR = "yes/no", "number", "list", "string"


def T(root, keys, via=()):
    """Rego: the wrong-typed facts under panos_config.<root>. keys: key name -> type ("*" = every key directly under
    the root); via: when given, the fact must sit under one of these path segments."""
    v = "{" + ", ".join(json.dumps(x) for x in via) + "}" if via else "set()"
    return f"_bad({json.dumps(root.split('.'))}, {v}, {json.dumps(keys)})"


def fact(cid, kw, ev, label, ok, fail, miss, ok2=None, typed=None, nonempty=None):
    """typed: T(...) expressions for the yes/no, number, list and string facts the check reads (a wrong type is an
    "evidence invalid" finding). nonempty: a profiles.<kind> list the check needs at least one entry of; a collected
    empty list fails the recommendation as "no <kind> profile configured" (an absent key is still missing evidence)."""
    KW[cid] = kw
    c = {"id": cid, "kind": "fact", "ev": ev, "label": "panos_config." + label, "ok": [ok] + ([ok2] if ok2 else []),
         "fail": fail, "miss": miss}
    if typed:
        c["typed"] = typed
    if nonempty:
        expr = f"{P}.profiles.{nonempty}"
        c["ok"] = [o if o[0].startswith("not _licensed") else [f"count({expr}) > 0"] + o for o in c["ok"]]
        c["empty"] = (expr, f"no {KIND_LABEL[nonempty]} profile configured")
    return c


def att(cid, kw, key):
    KW[cid] = kw
    return {"id": cid, "kind": "attest", "attest": key, "attest_root": P}


# Our own short wording for every recommendation (no CIS title text). Replaces the workbook title after the
# keyword check, so messages, tests and the recommendations table all carry it.
OWN = {}

C = []

# ── section 1: device setup ────────────────────────────────────────────────────
SYS = f"{P}.deviceconfig.system"
MGMT = f"{P}.deviceconfig.setting.management"
PWC = f"{P}.mgt_config.password_complexity"
LOGS = [f"is_object({P}.shared.log_settings)", f"count({P}.shared.log_settings) > 0"]
OWN.update({
    "1.1.1.1": "system, config, User-ID, HIP-match and IP-tag logs must all forward to a valid syslog server profile",
    "1.1.1.2": "system, config, User-ID, HIP-match and IP-tag logs must all send traps to an SNMP v3 trap profile",
    "1.1.2": "a login banner must be configured",
    "1.1.3": "logging under high dataplane load must be turned on",
    "1.2.1": "management interface permitted IPs must be limited to the management hosts",
    "1.2.2": "interface management profiles offering SSH, HTTPS or SNMP must restrict permitted IPs",
    "1.2.3": "the management interface must not offer HTTP or Telnet",
    "1.2.4": "interface management profiles must not offer HTTP or Telnet",
    "1.2.5": "the web admin interface certificate must be valid and trusted",
    "1.3.1": "admin password complexity must be enforced with username inclusion blocked",
    "1.3.2": "admin passwords must be at least 12 characters long",
    "1.3.3": "admin passwords must contain at least 1 upper-case letter",
    "1.3.4": "admin passwords must contain at least 1 lower-case letter",
    "1.3.5": "admin passwords must contain at least 1 digit",
    "1.3.6": "admin passwords must contain at least 1 special character",
    "1.3.7": "admin passwords must expire within 1 to 90 days",
    "1.3.8": "a new admin password must differ from the old one by at least 3 characters",
    "1.3.9": "admin passwords must not repeat any of the last 24",
    "1.3.10": "password profiles must not be weaker than the global rules (expiry 1 to 90 days)",
    "1.4.1": "management idle timeout must be 1 to 10 minutes",
    "1.4.2": "authentication profiles must lock out after failed attempts for a non-zero time",
    "1.5.1": "SNMP polling must use version 3",
    "1.6.1": "the update server identity must be verified",
    "1.6.2": "two distinct NTP servers must be configured",
    "1.6.3": "the remote access VPN certificate and its TLS minimum must be valid",
    "1.7.1": "IKEv2 VPN gateways must use a post-quantum pre-shared key",
})


def pwc(cid, kw, key, op, n, bad):
    return fact(cid, kw, [f"is_object({PWC})"], "mgt_config.password_complexity",
                [f'_n({PWC}, "{key}") {op} {n}'], add(f"/mgt_config/password_complexity/{key}", bad),
                rm("/mgt_config/password_complexity"), typed=[T("mgt_config.password_complexity", {key: NUM})])


C += [
    fact("1.1.1.1", "syslog", [f"is_array({P}.shared.server_profile.syslog)"] + LOGS,
         "shared.{server_profile.syslog,log_settings}", ['_log_dest_ok("send_syslog", _syslog_profiles)'],
         add("/shared/log_settings/system/match_list/0/send_syslog", ["no-such-profile"]), rm("/shared/server_profile/syslog")),
    fact("1.1.1.2", "snmpv3 traps", [f"is_array({P}.shared.server_profile.snmptrap)"] + LOGS,
         "shared.{server_profile.snmptrap,log_settings}", ['_log_dest_ok("send_snmptrap", _snmpv3_profiles)'],
         add("/shared/server_profile/snmptrap/0/version", "v2c"), rm("/shared/server_profile/snmptrap")),
    fact("1.1.2", "login banner", [f"is_object({SYS})"], "deviceconfig.system",
         [f"is_string({SYS}.login_banner)", f'trim_space({SYS}.login_banner) != ""'],
         add("/deviceconfig/system/login_banner", " "), rm("/deviceconfig/system")),
    fact("1.1.3", "high dp load", [f"is_object({MGMT})"], "deviceconfig.setting.management",
         [f'_yes({MGMT}, "enable_log_high_dp_load")'],
         add("/deviceconfig/setting/management/enable_log_high_dp_load", "no"), rm("/deviceconfig/setting/management"),
         typed=[T("deviceconfig.setting.management", {"enable_log_high_dp_load": YN})]),
    att("1.2.1", "permitted ip addresses", "management_permitted_ips_reviewed"),
    att("1.2.2", "management profiles where", "management_profile_permitted_ips_reviewed"),
    fact("1.2.3", "management interface", [f"is_object({SYS}.service)"], "deviceconfig.system.service",
         [f'_yes({SYS}.service, "disable_http")', f'_yes({SYS}.service, "disable_telnet")'],
         add("/deviceconfig/system/service/disable_telnet", "no"), rm("/deviceconfig/system/service"),
         typed=[T("deviceconfig.system.service", {"disable_http": YN, "disable_telnet": YN})]),
    fact("1.2.4", "all management profiles", [f"is_array({P}.network.profiles.interface_management)"],
         "network.profiles.interface_management",
         [f'every p in {P}.network.profiles.interface_management {{ not _yes(p, "http"); not _yes(p, "telnet") }}'],
         add("/network/profiles/interface_management/0/http", "yes"), rm("/network/profiles/interface_management"),
         typed=[T("network.profiles.interface_management", {"http": YN, "telnet": YN})]),
    att("1.2.5", "certificate", "admin_web_certificate_valid"),
    fact("1.3.1", "password complexity", [f"is_object({PWC})"], "mgt_config.password_complexity",
         [f'_yes({PWC}, "enabled")', f'_yes({PWC}, "block_username_inclusion")'],
         add("/mgt_config/password_complexity/enabled", "no"), rm("/mgt_config/password_complexity"),
         typed=[T("mgt_config.password_complexity", {"enabled": YN, "block_username_inclusion": YN})]),
    pwc("1.3.2", "minimum length", "minimum_length", ">=", 12, 8),
    pwc("1.3.3", "uppercase", "minimum_uppercase_letters", ">=", 1, 0),
    pwc("1.3.4", "lowercase", "minimum_lowercase_letters", ">=", 1, 0),
    pwc("1.3.5", "numeric", "minimum_numeric_letters", ">=", 1, 0),
    pwc("1.3.6", "special characters", "minimum_special_characters", ">=", 1, 0),
    fact("1.3.7", "change period", [f"is_object({PWC})"], "mgt_config.password_complexity",
         [f'n := _n(object.get({PWC}, "password_change", {{}}), "expiration_period")', "n > 0", "n <= 90"],
         add("/mgt_config/password_complexity/password_change/expiration_period", 0), rm("/mgt_config/password_complexity"),
         typed=[T("mgt_config.password_complexity.password_change", {"expiration_period": NUM})]),
    pwc("1.3.8", "differs by characters", "new_password_differs_by_characters", ">=", 3, 2),
    pwc("1.3.9", "reuse limit", "password_history_count", ">=", 24, 10),
    fact("1.3.10", "password profiles", [f"is_array({P}.mgt_config.password_profile)"], "mgt_config.password_profile",
         [f"every pp in {P}.mgt_config.password_profile {{ _expiry_ok(pp) }}"],
         add("/mgt_config/password_profile/0/password_change/expiration_period", 0), rm("/mgt_config/password_profile"),
         typed=[T("mgt_config.password_profile", {"expiration_period": NUM})]),
    fact("1.4.1", "idle timeout", [f"is_object({MGMT})"], "deviceconfig.setting.management",
         [f'n := _n({MGMT}, "idle_timeout")', "n > 0", "n <= 10"],
         add("/deviceconfig/setting/management/idle_timeout", 0), rm("/deviceconfig/setting/management"),
         typed=[T("deviceconfig.setting.management", {"idle_timeout": NUM})]),
    fact("1.4.2", "lockout time", [f"is_array({P}.shared.authentication_profile)", f"count({P}.shared.authentication_profile) > 0"],
         "shared.authentication_profile", [f"every a in {P}.shared.authentication_profile {{ _lockout_ok(a) }}"],
         add("/shared/authentication_profile/0/lockout/lockout_time", 0), rm("/shared/authentication_profile"),
         typed=[T("shared.authentication_profile", {"failed_attempts": NUM, "lockout_time": NUM})]),
    fact("1.5.1", "v3", [f"is_object({SYS}.snmp_setting)"], "deviceconfig.system.snmp_setting",
         [f'lower({SYS}.snmp_setting.access_setting.version) == "v3"'],
         add("/deviceconfig/system/snmp_setting/access_setting/version", "v2c"), rm("/deviceconfig/system/snmp_setting")),
    fact("1.6.1", "update server identity", [f"is_object({SYS})"], "deviceconfig.system",
         [f'_yes({SYS}, "server_verification")'], add("/deviceconfig/system/server_verification", "no"), rm("/deviceconfig/system"),
         typed=[T("deviceconfig.system", {"server_verification": YN})]),
    fact("1.6.2", "ntp", [f"is_object({SYS}.ntp_servers)"], "deviceconfig.system.ntp_servers",
         ["_ntp_ok"], add("/deviceconfig/system/ntp_servers/secondary_ntp_server/ntp_server_address", "10.0.0.123"),
         rm("/deviceconfig/system/ntp_servers")),
    att("1.6.3", "remote access vpns", "vpn_certificate_valid"),
    att("1.7.1", "post-quantum", "ikev2_post_quantum_ppk_enabled"),
]

# ── sections 2-4: User-ID, high availability, dynamic updates ────────────────────
ZONES = [f"is_array({P}.zone)", f"count({P}.zone) > 0"]
RULES = [f"is_array({P}.rulebase.security)", f"count({P}.rulebase.security) > 0"]
UNTR = [f"is_array({P}.site.untrusted_zones)", f"count({P}.site.untrusted_zones) > 0"]
INET = [f"is_array({P}.site.internet_zones)", f"count({P}.site.internet_zones) > 0"]
HA = f"{P}.deviceconfig.high_availability"
# shape of a security rule: a wrong type here would drop the rule from the allow / Internet-bound sets unnoticed
RULE_T = T("rulebase.security", dict({"disabled": YN, "action": STR, "group": LST},
                                     **{k: LST for k in ["from", "to", "source", "destination", "application", "service"]},
                                     **{k: LST for k in KIND_LABEL}))
ZONE_T = T("zone", {"enable_user_identification": YN})
# `request license info` returns <feature> and <expired> on every entry: an entry without either is not a valid
# licence statement (wrong types and incomplete entries are both "evidence invalid")
LIC_T = T("licenses", {"expired": YN, "feature": STR}) + " | _lic_incomplete"
US = f"{SYS}.update_schedule"
OWN.update({
    "2.1": "traffic from trusted zones must carry a mapped user name",
    "2.2": "User-ID client (WMI) probing must be off",
    "2.3": "User-ID must be on only for trusted internal zones",
    "2.4": "with User-ID on, the user mapping must name its trusted networks as include entries",
    "2.5": "the User-ID agent account must hold only the minimal group memberships",
    "2.6": "the User-ID service account must be denied interactive logon",
    "2.7": "the User-ID service account must have no remote access rights",
    "2.8": "a rule must block msrpc from the User-ID agent toward every untrusted zone",
    "3.1": "HA must be on with an HA2 data link and session synchronization",
    "3.2": "HA must fail over on link or path monitoring (failure condition any)",
    "3.3": "HA passive link state must be auto and preemption must be off",
    "4.1": "antivirus content must download and install hourly",
    "4.2": "application and threat content must download and install at least daily",
})

C += [
    att("2.1", "mapped to usernames", "user_mapping_verified_in_logs"),
    fact("2.2", "wmi probing", [f"is_object({P}.user_id.setting)"], "user_id.setting",
         [f'not _yes({P}.user_id.setting, "enable_probing")'], add("/user_id/setting/enable_probing", "yes"), rm("/user_id/setting"),
         typed=[T("user_id.setting", {"enable_probing": YN})]),
    fact("2.3", "internal trusted", ZONES + UNTR, "{zone,site.untrusted_zones}",
         ["count({lower(z.name) | some z in _uid_zones} & _untrusted) == 0"],
         add("/zone/1/enable_user_identification", "yes"), rm("/site/untrusted_zones"), typed=[ZONE_T]),
    fact("2.4", "include/exclude", ZONES + [f"is_array({P}.user_id.include_exclude_network)"],
         "{zone,user_id.include_exclude_network}", ["count(_uid_zones) == 0"],
         add("/user_id/include_exclude_network/0/discovery", "exclude"), rm("/user_id/include_exclude_network"),
         ok2=[f'some e in {P}.user_id.include_exclude_network', 'lower(object.get(e, "discovery", "")) == "include"',
              '_nonempty(object.get(e, "network_address", ""))'], typed=[ZONE_T]),
    att("2.5", "minimal permissions", "userid_account_minimal_groups"),
    att("2.6", "interactive logon", "userid_account_no_interactive_logon"),
    att("2.7", "remote access", "userid_account_no_remote_access"),
    fact("2.8", "untrusted zones", RULES + UNTR, "{rulebase.security,site.untrusted_zones}",
         ["some r in _rules", "_deny(r)", '"msrpc" in _ls(r, "application")', "_to_all_untrusted(r)"],
         add("/rulebase/security/2/application", ["dns"]), rm("/rulebase/security"), typed=[RULE_T]),
    fact("3.1", "fully-synchronized", [f"is_object({HA})"], "deviceconfig.high_availability",
         [f'_yes({HA}, "enabled")', f"is_string({HA}.interface.ha2.port)", f'{HA}.interface.ha2.port != ""',
          f'_yes({HA}.state_synchronization, "enabled")'],
         add("/deviceconfig/high_availability/state_synchronization/enabled", "no"), rm("/deviceconfig/high_availability"),
         typed=[T("deviceconfig.high_availability", {"enabled": YN})]),
    fact("3.2", "link monitoring", [f"is_object({HA})"], "deviceconfig.high_availability",
         [f'_monitor_ok(object.get({HA}, "link_monitoring", {{}}), "link_group", "interface")'],
         add("/deviceconfig/high_availability/link_monitoring/enabled", "no"), rm("/deviceconfig/high_availability"),
         ok2=[f'_monitor_ok(object.get({HA}, "path_monitoring", {{}}), "path_group", "destination_ip")'],
         typed=[T("deviceconfig.high_availability", {"enabled": YN})]),
    fact("3.3", "preemptive", [f"is_object({HA})"], "deviceconfig.high_availability",
         [f'{HA}.active_passive.passive_link_state == "auto"', f'not _yes(object.get({HA}, "election_option", {{}}), "preemptive")'],
         add("/deviceconfig/high_availability/election_option/preemptive", "yes"), rm("/deviceconfig/high_availability"),
         typed=[T("deviceconfig.high_availability", {"preemptive": YN})]),
    fact("4.1", "antivirus update", [f"is_object({US})"], "deviceconfig.system.update_schedule",
         [f'{US}.anti_virus.action == "download-and-install"', f'{US}.anti_virus.recurrence == "hourly"'],
         add("/deviceconfig/system/update_schedule/anti_virus/recurrence", "daily"), rm("/deviceconfig/system/update_schedule")),
    fact("4.2", "applications and threats", [f"is_object({US})"], "deviceconfig.system.update_schedule",
         [f'{US}.threats.action == "download-and-install"',
          f'{US}.threats.recurrence in {{"daily", "hourly", "every-30-mins", "every-15-mins", "every-5-mins", "every-min"}}'],
         add("/deviceconfig/system/update_schedule/threats/recurrence", "weekly"), rm("/deviceconfig/system/update_schedule")),
]

# ── section 5: WildFire ──────────────────────────────────────────────────────────
WF = f"{P}.deviceconfig.setting.wildfire"
PR = f"{P}.profiles"


def plist(kind):
    """evidence for a profile list: the key was collected. An empty list is a finding (fact(nonempty=kind)), not missing evidence."""
    return [f"is_array({PR}.{kind})"]


OWN.update({
    "5.1": "WildFire upload size limits must be at or above the defaults",
    "5.2": "every allow rule must carry a WildFire analysis profile",
    "5.3": "decrypted content must be forwarded to WildFire",
    "5.4": "WildFire session information must include every field",
    "5.5": "WildFire logs must be forwarded to an alerting destination",
    "5.6": "WildFire content must update in real time",
    "5.7": "the WildFire public cloud region must be the approved one",
    "5.8": "WildFire profiles must block PE files through inline cloud analysis",
})

C += [
    att("5.1", "file size", "wildfire_file_size_limits_reviewed"),
    fact("5.2", "wildfire analysis profile", RULES + plist("wildfire_analysis"), "{rulebase.security,profiles.wildfire_analysis}",
         ['every r in _allow_rules { _has_profile(r, "wildfire_analysis") }'],
         rm("/rulebase/security/0/profile_setting/profiles/wildfire_analysis"), rm("/profiles/wildfire_analysis"),
         typed=[RULE_T], nonempty="wildfire_analysis"),
    fact("5.3", "decrypted content", [f"is_object({P}.deviceconfig.setting.ssl_decrypt)"], "deviceconfig.setting.ssl_decrypt",
         [f'_yes({P}.deviceconfig.setting.ssl_decrypt, "allow_forward_decrypted_content")'],
         add("/deviceconfig/setting/ssl_decrypt/allow_forward_decrypted_content", "no"), rm("/deviceconfig/setting/ssl_decrypt"),
         typed=[T("deviceconfig.setting.ssl_decrypt", {"allow_forward_decrypted_content": YN})]),
    fact("5.4", "session information", [f"is_object({WF})"], "deviceconfig.setting.wildfire",
         [f'sis := object.get({WF}, "session_info_select", {{}})', "is_object(sis)", "every k, _ in sis { not _yes(sis, k) }"],
         add("/deviceconfig/setting/wildfire/session_info_select/exclude_username", "yes"), rm("/deviceconfig/setting/wildfire"),
         typed=[T("deviceconfig.setting.wildfire.session_info_select", {"*": YN})]),
    fact("5.5", "alerts", [f"is_array({P}.shared.log_forwarding_profile)"], "shared.log_forwarding_profile",
         [f"some lf in {P}.shared.log_forwarding_profile", 'some m in _l(lf, "match_list")',
          'lower(object.get(m, "log_type", "")) == "wildfire"', "_sends(m)"],
         add("/shared/log_forwarding_profile/0/match_list/0/log_type", "traffic"), rm("/shared/log_forwarding_profile")),
    fact("5.6", "real-time", [f"is_object({US})"], "deviceconfig.system.update_schedule",
         [f'{US}.wildfire.recurrence == "real-time"'],
         add("/deviceconfig/system/update_schedule/wildfire/recurrence", "every-min"), rm("/deviceconfig/system/update_schedule")),
    att("5.7", "cloud region", "wildfire_cloud_region_approved"),
    fact("5.8", "inline cloud analysis", plist("wildfire_analysis"), "profiles.wildfire_analysis",
         [f"every p in {PR}.wildfire_analysis {{ _wf_inline_ok(p) }}"],
         add("/profiles/wildfire_analysis/0/cloud_inline_analysis", "no"), rm("/profiles/wildfire_analysis"),
         typed=[T("profiles.wildfire_analysis", {"cloud_inline_analysis": YN})], nonempty="wildfire_analysis"),
]

# ── section 6 (6.1-6.14): security profiles ─────────────────────────────────────────
LIC = [f"is_array({P}.licenses)"]
URLC = [f"is_array({P}.site.url_block_categories)", f"count({P}.site.url_block_categories) > 0"]
R0 = "/rulebase/security/0/profile_setting/profiles"
OWN.update({
    "6.1": "antivirus decoders must reset both ends for signature and WildFire actions (imap and pop3 may alert)",
    "6.2": "every allow rule must carry an antivirus profile",
    "6.3": "an anti-spyware profile must reset critical, high and medium threats of any category",
    "6.4": "anti-spyware profiles in use must sinkhole the Palo Alto DNS list with IPv4 and IPv6 sinkhole addresses",
    "6.5": "every allow rule toward the Internet must carry an anti-spyware profile",
    "6.6": "a vulnerability profile must block critical and high threats and keep at least the default action below",
    "6.7": "every allow rule must carry a vulnerability protection profile",
    "6.8": "a PAN-DB URL filtering license must be active",
    "6.9": "URL filtering profiles must block or override every organisation-designated category",
    "6.10": "URL filtering profiles must log (alert) every category they let through",
    "6.11": "URL filtering profiles must log User-Agent, Referer and X-Forwarded-For on every page",
    "6.12": "every allow rule toward the Internet must carry a URL filtering profile",
    "6.13": "a data filtering profile must alert on sensitive data patterns above a threshold",
    "6.14": "every allow rule to or from the Internet must carry a data filtering profile",
})


def rule_prof(cid, kw, kind, rules_var, ev, label, miss, nonempty=None):
    return fact(cid, kw, ev, label, [f'every r in {rules_var} {{ _has_profile(r, "{kind}") }}'], rm(f"{R0}/{kind}"), miss,
                typed=[RULE_T], nonempty=nonempty)


C += [
    fact("6.1", "reset-both", plist("virus"), "profiles.virus",
         [f'every p in {PR}.virus {{ _av_decoders_ok(p, "action"); _av_decoders_ok(p, "wildfire_action") }}'],
         add("/profiles/virus/0/decoder/0/wildfire_action", "alert"), rm("/profiles/virus"), nonempty="virus"),
    rule_prof("6.2", "antivirus profile", "virus", "_allow_rules", RULES + plist("virus"),
              "{rulebase.security,profiles.virus}", rm("/profiles/virus"), nonempty="virus"),
    fact("6.3", "anti-spyware profile is configured", plist("spyware"), "profiles.spyware",
         [f"some p in {PR}.spyware", "_spyware_block_rule(p)"],
         add("/profiles/spyware/0/rules/0/action", "alert"), rm("/profiles/spyware"), nonempty="spyware"),
    fact("6.4", "sinkholing", RULES + plist("spyware"), "{rulebase.security,profiles.spyware}",
         ['count(_inuse("spyware")) > 0', f'every n in _inuse("spyware") {{ some p in {PR}.spyware; p.name == n; _sinkhole_ok(p) }}'],
         add("/profiles/spyware/0/botnet_domains/lists/0/action", "alert"), rm("/profiles/spyware"),
         typed=[RULE_T], nonempty="spyware"),
    rule_prof("6.5", "permitting traffic to the internet", "spyware", "_inet_out_rules", RULES + INET + plist("spyware"),
              "{rulebase.security,site.internet_zones,profiles.spyware}", rm("/site/internet_zones"), nonempty="spyware"),
    fact("6.6", "critical and high", plist("vulnerability"), "profiles.vulnerability",
         [f"some p in {PR}.vulnerability", "_vuln_ok(p)"],
         add("/profiles/vulnerability/0/rules/0/action", "alert"), rm("/profiles/vulnerability"), nonempty="vulnerability"),
    rule_prof("6.7", "security rules allowing", "vulnerability", "_allow_rules", RULES, "rulebase.security", rm("/rulebase/security")),
    fact("6.8", "pan-db", LIC, "licenses", ['_licensed({"pan-db url filtering", "advanced url filtering"})'],
         add("/licenses/0/expired", "yes"), rm("/licenses"), typed=[LIC_T]),
    fact("6.9", "override", plist("url_filtering") + URLC, "{profiles.url_filtering,site.url_block_categories}",
         [f'every p in {PR}.url_filtering {{ count(_ls({P}.site, "url_block_categories") - (_ls(p, "block") | _ls(p, "override"))) == 0 }}'],
         add("/profiles/url_filtering/0/block", ["malware"]), rm("/site/url_block_categories"), nonempty="url_filtering"),
    fact("6.10", "logged", plist("url_filtering"), "profiles.url_filtering",
         [f'every p in {PR}.url_filtering {{ count(_l(p, "allow")) == 0 }}'],
         add("/profiles/url_filtering/0/allow", ["news"]), rm("/profiles/url_filtering"),
         typed=[T("profiles.url_filtering", {"allow": LST})], nonempty="url_filtering"),
    fact("6.11", "http header", plist("url_filtering"), "profiles.url_filtering",
         [f"every p in {PR}.url_filtering {{ _url_header_logging(p) }}"],
         add("/profiles/url_filtering/0/log_http_hdr_xff", "no"), rm("/profiles/url_filtering"),
         typed=[T("profiles.url_filtering", {k: YN for k in ["log_container_page_only", "log_http_hdr_user_agent",
                                                              "log_http_hdr_referer", "log_http_hdr_xff"]})],
         nonempty="url_filtering"),
    rule_prof("6.12", "secure url filtering", "url_filtering", "_inet_out_rules", RULES + INET,
              "{rulebase.security,site.internet_zones}", rm("/site/internet_zones")),
    fact("6.13", "credit card", plist("data_filtering"), "profiles.data_filtering",
         [f'some p in {PR}.data_filtering', 'some x in _l(p, "rules")', 'count(_l(x, "data_object")) > 0',
          '_n(x, "alert_threshold") > 0'],
         add("/profiles/data_filtering/0/rules/0/alert_threshold", 0), rm("/profiles/data_filtering"),
         typed=[T("profiles.data_filtering", {"alert_threshold": NUM})], nonempty="data_filtering"),
    rule_prof("6.14", "data filtering", "data_filtering", "_inet_rules", RULES + INET,
              "{rulebase.security,site.internet_zones}", rm("/site/internet_zones")),
]

# ── section 6 (6.15-6.25): zone protection, credential, inline ML / cloud ─────────
ZP = f"{P}.network.profiles.zone_protection"
ZPE = [f"is_array({ZP})"]
ZPATH = "/network/profiles/zone_protection/0"
ATP = '{"advanced threat prevention"}'
DISCARDS = ["discard_ip_spoof", "discard_overlapping_tcp_segment_mismatch", "discard_strict_source_routing",
            "discard_loose_source_routing", "discard_malformed_option"]
OWN.update({
    "6.15": "untrusted zones must have a zone protection profile answering SYN floods with SYN cookies",
    "6.16": "untrusted zones must have zone protection flood limits on for every flood type",
    "6.17": "every zone must have zone protection with TCP and UDP port scan and host sweep detection on",
    "6.18": "every zone must have zone protection dropping spoofed, mismatched-overlap, source-routed and malformed packets",
    "6.19": "URL filtering profiles must block or continue credential submission and keep credential detection on",
    "6.20": "the antivirus WildFire inline ML action must reset both ends (imap and pop3 may alert)",
    "6.21": "antivirus WildFire inline ML must be on for every file model",
    "6.22": "with Advanced Threat Prevention, vulnerability profiles must run inline cloud analysis (models alert)",
    "6.23": "with an advanced license, URL filtering profiles must run local and cloud inline categorization",
    "6.24": "with Advanced Threat Prevention, anti-spyware profiles must run inline cloud analysis (models reset both)",
    "6.25": "with DNS Security, anti-spyware profiles must sinkhole every DNS Security category (C2 with extended capture)",
})

C += [
    fact("6.15", "syn cookies", ZONES + UNTR + ZPE, "{zone,site.untrusted_zones,network.profiles.zone_protection}",
         ["_untrusted_known", "every z in _untrusted_zone_objs { _syn_cookies(_zpp(z)) }"],
         add(f"{ZPATH}/flood/tcp_syn/action", "red"), rm("/network/profiles/zone_protection"),
         typed=[T("network.profiles.zone_protection", {"enable": YN, "alarm_rate": NUM, "activate_rate": NUM, "maximal_rate": NUM}, via=["tcp_syn"])]),
    fact("6.16", "flood protection", ZONES + UNTR + ZPE, "{zone,site.untrusted_zones,network.profiles.zone_protection}",
         ["_untrusted_known", "every z in _untrusted_zone_objs { _floods_ok(_zpp(z)) }"],
         add(f"{ZPATH}/flood/udp/enable", "no"), rm("/network/profiles/zone_protection"),
         typed=[T("network.profiles.zone_protection", {"enable": YN, "alarm_rate": NUM, "activate_rate": NUM, "maximal_rate": NUM}, via=["flood"])]),
    fact("6.17", "reconnaissance", ZONES + ZPE, "{zone,network.profiles.zone_protection}",
         [f"every z in {P}.zone {{ _recon_ok(_zpp(z)) }}"],
         add(f"{ZPATH}/scan/host_sweep/action", "allow"), rm("/network/profiles/zone_protection"),
         typed=[T("network.profiles.zone_protection", {"enable": YN, "interval": NUM, "threshold": NUM, "duration": NUM},
                  via=["scan"])]),
    fact("6.18", "specially crafted", ZONES + ZPE, "{zone,network.profiles.zone_protection}",
         [f"every z in {P}.zone {{ _drops_ok(_zpp(z)) }}"],
         add(f"{ZPATH}/discard_ip_spoof", "no"), rm("/network/profiles/zone_protection"),
         typed=[T("network.profiles.zone_protection", {k: YN for k in DISCARDS})]),
    fact("6.19", "credential submission", plist("url_filtering"), "profiles.url_filtering",
         [f"every p in {PR}.url_filtering {{ _cred_ok(p) }}"],
         add("/profiles/url_filtering/0/credential_enforcement/mode", "disabled"), rm("/profiles/url_filtering"),
         typed=[T("profiles.url_filtering", {k: LST for k in ["allow", "alert", "block", "continue"]})],
         nonempty="url_filtering"),
    fact("6.20", "inline ml action", plist("virus"), "profiles.virus",
         [f'every p in {PR}.virus {{ _av_decoders_ok(p, "mlav_action") }}'],
         add("/profiles/virus/0/decoder/0/mlav_action", "alert"), rm("/profiles/virus"), nonempty="virus"),
    fact("6.21", "all file types", plist("virus"), "profiles.virus",
         [f"every p in {PR}.virus {{ _mlav_ok(p) }}"],
         add("/profiles/virus/0/mlav_engine_filebased_enabled/0/mlav_policy_action", "disable"), rm("/profiles/virus"),
         nonempty="virus"),
    fact("6.22", "vulnerability protection profiles", LIC + plist("vulnerability"), "{licenses,profiles.vulnerability}",
         [f"not _licensed({ATP})"], add("/profiles/vulnerability/0/cloud_inline_analysis", "no"), rm("/licenses"),
         ok2=[f'every p in {PR}.vulnerability {{ _inline_cloud_ok(p, "mica_engine_vulnerability_enabled", "alert") }}'],
         typed=[LIC_T, T("profiles.vulnerability", {"cloud_inline_analysis": YN})], nonempty="vulnerability"),
    fact("6.23", "cloud inline categorization", LIC + plist("url_filtering"), "{licenses,profiles.url_filtering}",
         ['not _licensed({"advanced threat prevention", "advanced url filtering"})'],
         add("/profiles/url_filtering/0/cloud_inline_cat", "no"), rm("/licenses"),
         ok2=[f'every p in {PR}.url_filtering {{ _yes(p, "local_inline_cat"); _yes(p, "cloud_inline_cat") }}'],
         typed=[LIC_T, T("profiles.url_filtering", {"local_inline_cat": YN, "cloud_inline_cat": YN})], nonempty="url_filtering"),
    fact("6.24", "anti-spyware profiles are enabled", LIC + plist("spyware"), "{licenses,profiles.spyware}",
         [f"not _licensed({ATP})"], add("/profiles/spyware/0/mica_engine_spyware_enabled/0/inline_policy_action", "alert"),
         rm("/licenses"),
         ok2=[f'every p in {PR}.spyware {{ _inline_cloud_ok(p, "mica_engine_spyware_enabled", "reset-both") }}'],
         typed=[LIC_T, T("profiles.spyware", {"cloud_inline_analysis": YN})], nonempty="spyware"),
    fact("6.25", "dns security", LIC + plist("spyware"), "{licenses,profiles.spyware}",
         ['not _licensed({"dns security", "advanced dns security"})'],
         add("/profiles/spyware/0/botnet_domains/dns_security_categories/0/packet_capture", "disable"), rm("/licenses"),
         ok2=[f"every p in {PR}.spyware {{ _dns_security_ok(p) }}"], typed=[LIC_T], nonempty="spyware"),
]

# ── sections 7-8: security policies, decryption ─────────────────────────────────────
DEC = [f"is_array({P}.rulebase.decryption)"]
OWN.update({
    "7.1": "allow rules from an untrusted to a more trusted zone must name the application and the service",
    "7.2": "allow rules must not use service any",
    "7.3": "deny rules must block traffic to and from the Palo Alto malicious, high-risk, Tor-exit and bulletproof IP lists",
    "7.4": "the intrazone and interzone default rules must log at session end",
    "8.1": "an SSL forward proxy decryption rule must cover traffic toward the Internet",
    "8.2": "inbound TLS to published servers must pass through SSL inbound inspection",
    "8.3": "the decryption certificate must be trusted and valid",
})

C += [
    fact("7.1", "more trusted zone", RULES + UNTR, "{rulebase.security,site.untrusted_zones}",
         ["every r in _untrusted_inbound { _app_named(r); _service_named(r) }"],
         add("/rulebase/security/3/application", ["any"]), rm("/site/untrusted_zones"), typed=[RULE_T]),
    fact("7.2", "service setting of any", RULES, "rulebase.security", ["every r in _allow_rules { _service_named(r) }"],
         add("/rulebase/security/0/service", ["any"]), rm("/rulebase/security"), typed=[RULE_T]),
    fact("7.3", "threat intelligence", RULES, "rulebase.security", ['_edl_deny("destination")', '_edl_deny("source")'],
         add("/rulebase/security/4/destination", ["any"]), rm("/rulebase/security"), typed=[RULE_T]),
    fact("7.4", "built-in default", [f"is_array({P}.rulebase.default_security_rules)"], "rulebase.default_security_rules",
         [f'every n in {{"intrazone-default", "interzone-default"}} {{ some d in {P}.rulebase.default_security_rules; d.name == n; _yes(d, "log_end") }}'],
         add("/rulebase/default_security_rules/0/log_end", "no"), rm("/rulebase/default_security_rules"),
         typed=[T("rulebase.default_security_rules", {"log_end": YN})]),
    fact("8.1", "ssl forward proxy", DEC + INET, "{rulebase.decryption,site.internet_zones}",
         [f"some d in {P}.rulebase.decryption", "_forward_proxy_inet(d)"],
         add("/rulebase/decryption/0/type", "ssl-inbound-inspection"), rm("/rulebase/decryption"),
         typed=[T("rulebase.decryption", {"disabled": YN, "to": LST})]),
    att("8.2", "inbound inspection", "ssl_inbound_inspection_reviewed"),
    att("8.3", "decryption", "decryption_certificate_trusted"),
]

# ── abort on any mismatch with the workbook ───────────────────────────────────────
ids = [c["id"] for c in C]
assert len(ids) == len(set(ids)) == len(WB) == N_TOTAL, (len(ids), len(WB), sorted(set(WB) - set(ids)), sorted(set(ids) - set(WB)))
assert set(ids) == set(WB) == set(OWN) == set(KW), (sorted(set(WB) ^ set(ids)), sorted(set(WB) ^ set(OWN)))
assert sum(1 for w in WB.values() if w["assessment"] == "Automated") == N_AUTO
assert sum(1 for w in WB.values() if w["level"] == 1) == N_L1 and sum(1 for w in WB.values() if w["level"] == 2) == N_L2
for cid in ids:
    assert WB[cid]["assessment"] in ("Automated", "Manual"), cid
    assert len(WB[cid]["profiles"]) == 1, (cid, WB[cid]["profiles"])
    assert KW[cid].lower() in WB[cid]["title"].lower(), (cid, KW[cid])
AUTO_ATTESTED = {c["id"] for c in C if c["kind"] == "attest" and WB[c["id"]]["assessment"] == "Automated"}
assert AUTO_ATTESTED == {"2.1", "2.6", "5.1"}, AUTO_ATTESTED

from neutralize import neutralize_title  # noqa: E402

for cid in ids:  # our wording replaces the workbook title from here on
    assert neutralize_title(OWN[cid]) == OWN[cid], cid
    WB[cid]["title"] = OWN[cid]

SECTION_OF = {"1": "device_setup", "2": "user_identification", "3": "high_availability", "4": "dynamic_updates",
              "5": "wildfire", "6": "security_profiles", "7": "security_policies", "8": "decryption"}
SECTIONS = list(SECTION_OF.values())
STITLE = {"device_setup": "1 Device setup", "user_identification": "2 User identification",
          "high_availability": "3 High availability", "dynamic_updates": "4 Dynamic updates", "wildfire": "5 WildFire",
          "security_profiles": "6 Security profiles", "security_policies": "7 Security policies", "decryption": "8 Decryption"}


def section(cid):
    return SECTION_OF[cid.split(".")[0]]


attest_ids = [c["id"] for c in C if c["kind"] == "attest"]
manual_fact = [c["id"] for c in C if c["kind"] == "fact" and WB[c["id"]]["assessment"] == "Manual"]

# ── a compliant configuration (test fixture) ───────────────────────────────────────
ALL_PROF = {"virus": ["av-strict"], "spyware": ["as-strict"], "vulnerability": ["vp-strict"],
            "url_filtering": ["url-strict"], "data_filtering": ["df-strict"], "wildfire_analysis": ["wf-strict"]}
EDLS = ["panw-known-ip-list", "panw-highrisk-ip-list", "panw-torexit-ip-list", "panw-bulletproof-ip-list"]
LOGM = {"name": "all", "filter": "All Logs", "send_syslog": ["syslog-siem"], "send_snmptrap": ["trap-v3"]}
FLOOD = {"enable": "yes", "alarm_rate": 10000, "activate_rate": 10000, "maximal_rate": 40000}


def rule(name, frm, to, app, action, src=None, dst=None, svc=None, prof=None):
    r = {"name": name, "from": frm, "to": to, "source": src or ["any"], "destination": dst or ["any"],
         "application": app, "service": svc or ["application-default"], "action": action}
    if prof is not None:
        r["profile_setting"] = prof
    return r


GREEN = {"panos_config": {
    "deviceconfig": {
        "system": {
            "login_banner": "Authorised use only.", "server_verification": "yes",
            "service": {"disable_http": "yes", "disable_telnet": "yes"},
            "snmp_setting": {"access_setting": {"version": "v3"}},
            "ntp_servers": {"primary_ntp_server": {"ntp_server_address": "10.0.0.123"},
                            "secondary_ntp_server": {"ntp_server_address": "10.0.1.123"}},
            "update_schedule": {"anti_virus": {"action": "download-and-install", "recurrence": "hourly"},
                                "threats": {"action": "download-and-install", "recurrence": "every-30-mins"},
                                "wildfire": {"action": "download-and-install", "recurrence": "real-time"}},
        },
        "setting": {
            "management": {"enable_log_high_dp_load": "yes", "idle_timeout": 10},
            "ssl_decrypt": {"allow_forward_decrypted_content": "yes"},
            "wildfire": {"session_info_select": {"exclude_src_ip": "no"}},
        },
        "high_availability": {
            "enabled": "yes", "interface": {"ha2": {"port": "ethernet1/5"}}, "state_synchronization": {"enabled": "yes"},
            "link_monitoring": {"enabled": "yes", "failure_condition": "any",
                                "link_group": [{"name": "uplinks", "enabled": "yes", "failure_condition": "any",
                                                "interface": ["ethernet1/1", "ethernet1/2"]}]},
            "active_passive": {"passive_link_state": "auto"}, "election_option": {"preemptive": "no"},
        },
    },
    "mgt_config": {
        "password_complexity": {"enabled": "yes", "block_username_inclusion": "yes", "minimum_length": 14,
                                "minimum_uppercase_letters": 1, "minimum_lowercase_letters": 1, "minimum_numeric_letters": 1,
                                "minimum_special_characters": 1, "new_password_differs_by_characters": 3,
                                "password_history_count": 24, "password_change": {"expiration_period": 90}},
        "password_profile": [{"name": "svc", "password_change": {"expiration_period": 60}}],
    },
    "shared": {
        "server_profile": {
            "syslog": [{"name": "syslog-siem", "server": [{"name": "siem", "server": "10.0.0.30"}]}],
            "snmptrap": [{"name": "trap-v3", "version": "v3",
                          "server": [{"name": "nms", "manager": "10.0.0.20", "user": "trapper", "engineid": "0x80001f88",
                                      "authpwd": "-AQ==hashed"}]}],
        },
        "log_settings": {t: {"match_list": [dict(LOGM)]} for t in ["system", "config", "userid", "hipmatch", "iptag"]},
        "authentication_profile": [{"name": "admin-auth", "lockout": {"failed_attempts": 5, "lockout_time": 15}}],
        "log_forwarding_profile": [{"name": "lf-default",
                                    "match_list": [{"name": "wf", "log_type": "wildfire", "send_syslog": ["syslog-siem"]}]}],
    },
    "network": {"profiles": {
        "interface_management": [{"name": "mgmt-ping", "ping": "yes", "https": "yes", "permitted_ip": ["10.0.0.0/24"]}],
        "zone_protection": [{
            "name": "zp-strict",
            "flood": {t: dict(FLOOD, **({"action": "syn-cookies"} if t == "tcp_syn" else {}))
                      for t in ["tcp_syn", "udp", "icmp", "icmpv6", "other_ip"]},
            "scan": {"tcp_port_scan": {"enable": "yes", "action": "block-ip", "track_by": "source", "duration": 600,
                                       "interval": 5, "threshold": 20},
                     "host_sweep": {"enable": "yes", "action": "block", "interval": 10, "threshold": 30},
                     "udp_port_scan": {"enable": "yes", "action": "alert", "interval": 10, "threshold": 20}},
            "discard_ip_spoof": "yes", "discard_overlapping_tcp_segment_mismatch": "yes",
            "discard_strict_source_routing": "yes", "discard_loose_source_routing": "yes", "discard_malformed_option": "yes",
        }],
    }},
    "user_id": {"setting": {"enable_probing": "no"},
                "include_exclude_network": [{"name": "corp", "discovery": "include", "network_address": "10.0.0.0/8"},
                                            {"name": "guest-wifi", "discovery": "exclude", "network_address": "172.16.0.0/16"}]},
    "zone": [
        {"name": "trust", "zone_protection_profile": "zp-strict", "enable_user_identification": "yes"},
        {"name": "untrust", "zone_protection_profile": "zp-strict"},
        {"name": "guest", "zone_protection_profile": "zp-strict"},
        {"name": "dmz", "zone_protection_profile": "zp-strict"},
    ],
    "site": {"untrusted_zones": ["untrust", "guest"], "internet_zones": ["untrust"],
             "url_block_categories": ["malware", "phishing", "command-and-control"]},
    "profile_group": [dict({"name": "pg-strict"}, **ALL_PROF)],
    "profiles": {
        "virus": [{"name": "av-strict",
                   "decoder": [{"name": n, "action": a, "wildfire_action": a, "mlav_action": a}
                               for n, a in [("http", "reset-both"), ("smtp", "reset-both"), ("imap", "alert"), ("pop3", "alert")]],
                   "mlav_engine_filebased_enabled": [{"name": n, "mlav_policy_action": "enable"}
                                                     for n in ["Windows Executables", "PowerShell Script 1", "Executable Linked Format"]]}],
        "spyware": [{"name": "as-strict",
                     "rules": [{"name": "block-chm", "severity": ["critical", "high", "medium"], "category": "any",
                                "threat_name": "any", "action": {"reset-both": {}}}],
                     "botnet_domains": {"lists": [{"name": "default-paloalto-dns", "action": {"sinkhole": {}}}],
                                        "sinkhole": {"ipv4_address": "sinkhole.paloaltonetworks.com", "ipv6_address": "::1"},
                                        "dns_security_categories": [{"name": "pan-dns-sec-cc", "action": "sinkhole",
                                                                     "packet_capture": "extended-capture"},
                                                                    {"name": "pan-dns-sec-malware", "action": "sinkhole"}]},
                     "cloud_inline_analysis": "yes",
                     "mica_engine_spyware_enabled": [{"name": "HTTP Command and Control detector", "inline_policy_action": "reset-both"}]}],
        "vulnerability": [{"name": "vp-strict",
                           "rules": [{"name": "block-ch", "severity": ["critical", "high"], "action": {"reset-both": {}}},
                                     {"name": "default-mli", "severity": ["medium", "low", "informational"], "action": {"default": {}}}],
                           "cloud_inline_analysis": "yes",
                           "mica_engine_vulnerability_enabled": [{"name": "SQL Injection", "inline_policy_action": "alert"}]}],
        "url_filtering": [{"name": "url-strict", "block": ["malware", "phishing"], "override": ["command-and-control"],
                           "alert": ["news", "business-and-economy"],
                           "log_container_page_only": "no",
                           "log_http_hdr_user_agent": "yes", "log_http_hdr_referer": "yes", "log_http_hdr_xff": "yes",
                           "local_inline_cat": "yes", "cloud_inline_cat": "yes",
                           "credential_enforcement": {"mode": "ip-user", "log_severity": "medium",
                                                      "block": ["malware", "phishing", "command-and-control"],
                                                      "continue": ["news", "business-and-economy"]}}],
        "data_filtering": [{"name": "df-strict", "rules": [{"name": "cc", "data_object": ["credit-card-numbers"],
                                                            "alert_threshold": 20, "block_threshold": 0}]}],
        "wildfire_analysis": [{"name": "wf-strict", "rules": [{"name": "all", "application": ["any"], "file_type": ["any"]}],
                               "cloud_inline_analysis": "yes",
                               "inline_cloud_rules": [{"name": "pe", "application": ["any"], "file_type": ["pe"],
                                                       "direction": "both", "action": "block"}]}],
    },
    "rulebase": {
        "security": [
            rule("outbound-web", ["trust"], ["untrust"], ["web-browsing", "ssl"], "allow", prof={"profiles": ALL_PROF}),
            rule("outbound-dns", ["trust"], ["untrust"], ["dns"], "allow", prof={"group": ["pg-strict"]}),
            rule("deny-msrpc-untrusted", ["trust"], ["untrust", "guest"], ["msrpc"], "deny", src=["uid-agent"]),
            rule("dmz-web-in", ["untrust"], ["dmz"], ["web-browsing"], "allow", dst=["web01"], prof={"group": ["pg-strict"]}),
            rule("deny-to-malicious", ["any"], ["any"], ["any"], "deny", dst=EDLS, svc=["any"]),
            rule("deny-from-malicious", ["any"], ["any"], ["any"], "drop", src=EDLS, svc=["any"]),
        ],
        "default_security_rules": [{"name": "intrazone-default", "action": "allow", "log_end": "yes"},
                                   {"name": "interzone-default", "action": "deny", "log_end": "yes"}],
        "decryption": [{"name": "decrypt-outbound", "from": ["trust"], "to": ["untrust"], "action": "decrypt",
                        "type": {"ssl-forward-proxy": {}}, "category": ["any"]}],
    },
    "licenses": [{"feature": "PAN-DB URL Filtering", "expired": "no"},
                 {"feature": "Advanced Threat Prevention", "expired": "no"},
                 {"feature": "DNS Security", "expired": "no"}],
    "attest": {c["attest"]: True for c in C if c["kind"] == "attest"},
}}

# ── Rego helpers ───────────────────────────────────────────────────────────────────────
HELPERS = r'''# ── helpers ──────────────────────────────────────────────────────────────────
'''
HELPERS += LEVEL_HELPERS + r'''
# PAN-OS yes/no facts: the string "yes" / "no" (any case) or a JSON boolean. The running configuration leaves out a
# setting that is at its default, so an absent key in a collected section is the device default. _yes reads absent as
# "no", which is right only where the PAN-OS default is "no" (every fact read with _yes: see the README table).
# Where the default is "yes" (URL filtering "log container page only") the check uses _no, which absent does not meet.
# Any other value is not read as either: the recommendation that reads it reports "evidence invalid" (_bad).
_yes(o, k) if object.get(o, k, "no") == true

_yes(o, k) if {
	v := object.get(o, k, "no")
	is_string(v)
	lower(v) == "yes"
}

# stated as "no" (or false): an absent key is not "no"
_no(o, k) if object.get(o, k, null) == false

_no(o, k) if {
	v := object.get(o, k, null)
	is_string(v)
	lower(v) == "no"
}

# a number fact: only a JSON number counts ("14" is a string); absent or any other type is undefined
_n(o, k) := v if {
	v := object.get(o, k, null)
	is_number(v)
}

_type_ok("yes/no", v) if is_boolean(v)

_type_ok("yes/no", v) if {
	is_string(v)
	lower(v) in {"yes", "no"}
}

_type_ok("number", v) if is_number(v)

_type_ok("list", v) if is_array(v)

_type_ok("string", v) if is_string(v)

_type_want := {"yes/no": "\"yes\" or \"no\"", "number": "a number", "list": "a list", "string": "a string"}

# wrong-typed facts under input.panos_config.<root>. keys maps a key name to the type its value must have ("*": every
# key directly under the root); via, when not empty, names path segments one of which the fact must sit under.
# A fact that is absent is not reported here (absent has its own meaning per check); null is a wrong type.
_bad(root, via, keys) := {msg |
	sub := object.get(input.panos_config, root, null)
	walk(sub, [path, v])
	count(path) > 0
	k := path[count(path) - 1]
	is_string(k)
	t := _key_type(keys, k, count(path))
	_via_ok(via, path)
	not _type_ok(t, v)
	full := array.concat(root, [sprintf("%v", [s]) | some s in path])
	msg := sprintf("panos_config.%s must be %s, got %s", [concat(".", full), _type_want[t], json.marshal(v)])
}

_key_type(keys, k, _) := keys[k]

_key_type(keys, k, depth) := keys["*"] if {
	not keys[k]
	depth == 1
}

_via_ok(via, _) if count(via) == 0

_via_ok(via, path) if {
	some s in path
	s in via
}

_nonempty(v) if {
	is_string(v)
	trim_space(v) != ""
}

# an entry list (always an array in the contract); anything else reads as empty
_l(o, k) := v if {
	v := object.get(o, k, [])
	is_array(v)
}

_l(o, k) := [] if not is_array(object.get(o, k, []))

_ls(o, k) := {lower(sprintf("%v", [x])) | some x in _l(o, k)}

# an action written as a string ("reset-both") or as converted XML ({"reset-both": {}})
_act(a) := lower(a) if is_string(a)

_act(a) := lower(k) if {
	is_object(a)
	count(a) == 1
	some k, _ in a
}

# ── security rules (disabled rules are skipped) ──
_rules := [r | some r in input.panos_config.rulebase.security; not _yes(r, "disabled")]

_allow_rules := [r | some r in _rules; lower(object.get(r, "action", "")) == "allow"]

_deny(r) if lower(object.get(r, "action", "")) in {"deny", "drop", "reset-client", "reset-server", "reset-both"}

_untrusted := {lower(z) | some z in input.panos_config.site.untrusted_zones}

# a rule zone of "any" reaches the Internet
_inet := {lower(z) | some z in input.panos_config.site.internet_zones} | {"any"}

_to_inet(r) if {
	some z in _ls(r, "to")
	z in _inet
}

_from_inet(r) if {
	some z in _ls(r, "from")
	z in _inet
}

_inet_either(r) if _to_inet(r)

_inet_either(r) if _from_inet(r)

_inet_out_rules := [r | some r in _allow_rules; _to_inet(r)]

_inet_rules := [r | some r in _allow_rules; _inet_either(r)]

_to_all_untrusted(r) if "any" in _ls(r, "to")

_to_all_untrusted(r) if count(_untrusted - _ls(r, "to")) == 0

_from_untrusted(r) if {
	some z in _ls(r, "from")
	z in (_untrusted | {"any"})
}

_to_trusted(r) if {
	some z in _ls(r, "to")
	not z in _untrusted
}

_untrusted_inbound := [r | some r in _allow_rules; _from_untrusted(r); _to_trusted(r)]

_app_named(r) if {
	count(_ls(r, "application")) > 0
	not "any" in _ls(r, "application")
}

_service_named(r) if {
	count(_ls(r, "service")) > 0
	not "any" in _ls(r, "service")
}

# Palo Alto Networks predefined external dynamic lists (malicious, high-risk, Tor exit, bulletproof)
_edls := {"panw-known-ip-list", "panw-highrisk-ip-list", "panw-torexit-ip-list", "panw-bulletproof-ip-list"}

_edl_deny(field) if {
	some r in _rules
	_deny(r)
	count(_edls - _ls(r, field)) == 0
}

# security profiles a rule applies, directly or through a profile group
_ps(r) := object.get(r, "profile_setting", {})

_group_profiles(r, kind) := {n |
	some g in _l(_ps(r), "group")
	some pg in _l(input.panos_config, "profile_group")
	pg.name == g
	some n in _l(pg, kind)
}

_rule_profiles(r, kind) := {n | some n in _l(object.get(_ps(r), "profiles", {}), kind)} | _group_profiles(r, kind)

_has_profile(r, kind) if count(_rule_profiles(r, kind)) > 0

_inuse(kind) := {n | some r in _allow_rules; some n in _rule_profiles(r, kind)}

_licensed(names) if {
	some l in input.panos_config.licenses
	lower(object.get(l, "feature", "")) in names
	not _yes(l, "expired")
}

# a licence entry that is not an object, or lacks feature or expired: it states nothing about the licence
_lic_incomplete contains msg if {
	some i, l in input.panos_config.licenses
	not is_object(l)
	msg := sprintf("panos_config.licenses.%d must be a licence entry {feature, expired}, got %s", [i, json.marshal(l)])
}

_lic_incomplete contains msg if {
	some i, l in input.panos_config.licenses
	is_object(l)
	some k in ["feature", "expired"]
	not k in object.keys(l)
	msg := sprintf("panos_config.licenses.%d.%s must be %s, got nothing (the entry does not state it)", [i, k, _type_want[_lic_keys[k]]])
}

_lic_keys := {"feature": "string", "expired": "yes/no"}

_uid_zones := [z | some z in input.panos_config.zone; _yes(z, "enable_user_identification")]

'''
HELPERS += r'''# ── device setup ──
_log_types := ["system", "config", "userid", "hipmatch", "iptag"]

_syslog_profiles := {p.name |
	some p in input.panos_config.shared.server_profile.syslog
	srv := _l(p, "server")
	count(srv) > 0
	every s in srv { _nonempty(object.get(s, "server", "")) }
}

_snmpv3_profiles := {p.name |
	some p in input.panos_config.shared.server_profile.snmptrap
	lower(object.get(p, "version", "")) == "v3"
	srv := _l(p, "server")
	count(srv) > 0
	every s in srv {
		every k in ["manager", "user", "engineid", "authpwd"] { _nonempty(object.get(s, k, "")) }
	}
}

# every log type has an "All Logs" match sending to the destination, and every destination named is a valid profile
_log_dest_ok(field, profs) if {
	count(profs) > 0
	every t in _log_types {
		ms := _l(object.get(input.panos_config.shared.log_settings, t, {}), "match_list")
		some m in ms
		lower(object.get(m, "filter", "")) == "all logs"
		count(_l(m, field)) > 0
		every m2 in ms {
			every s in _l(m2, field) { s in profs }
		}
	}
}

_expiry_ok(pp) if {
	n := _n(object.get(pp, "password_change", {}), "expiration_period")
	n > 0
	n <= 90
}

# 0 failed attempts or 0 lockout time means lockout is off
_lockout_ok(a) if {
	lo := object.get(a, "lockout", {})
	_n(lo, "failed_attempts") > 0
	_n(lo, "lockout_time") > 0
}

default _ntp_ok := false

_ntp_ok if {
	s := input.panos_config.deviceconfig.system.ntp_servers
	p := object.get(object.get(s, "primary_ntp_server", {}), "ntp_server_address", "")
	q := object.get(object.get(s, "secondary_ntp_server", {}), "ntp_server_address", "")
	_nonempty(p)
	_nonempty(q)
	lower(p) != lower(q)
}

# ── high availability ──
_monitor_ok(m, groups, members) if {
	_yes(m, "enabled")
	lower(object.get(m, "failure_condition", "")) == "any"
	some g in _l(m, groups)
	_yes(g, "enabled")
	count(_l(g, members)) > 0
}

# ── WildFire ──
_sends(m) if {
	some k in ["send_syslog", "send_snmptrap", "send_email", "send_http"]
	count(_l(m, k)) > 0
}

_wf_inline_ok(p) if {
	_yes(p, "cloud_inline_analysis")
	some x in _l(p, "inline_cloud_rules")
	"any" in _ls(x, "application")
	"pe" in _ls(x, "file_type")
	lower(object.get(x, "direction", "")) == "both"
	_act(object.get(x, "action", "")) == "block"
}

# ── security profiles ──
_av_decoders_ok(p, k) if {
	ds := _l(p, "decoder")
	count(ds) > 0
	every d in ds { _decoder_ok(d, k) }
}

_decoder_ok(d, k) if _act(object.get(d, k, "")) == "reset-both"

_decoder_ok(d, k) if {
	lower(object.get(d, "name", "")) in {"imap", "pop3"}
	_act(object.get(d, k, "")) == "alert"
}

_mlav_ok(p) if {
	ms := _l(p, "mlav_engine_filebased_enabled")
	count(ms) > 0
	every m in ms { lower(object.get(m, "mlav_policy_action", "")) == "enable" }
}

_spyware_block_rule(p) if {
	some x in _l(p, "rules")
	_act(object.get(x, "action", "")) == "reset-both"
	count({"critical", "high", "medium"} - _ls(x, "severity")) == 0
	lower(object.get(x, "category", "any")) == "any"
	lower(object.get(x, "threat_name", "any")) == "any"
}

_sinkhole_ok(p) if {
	bd := object.get(p, "botnet_domains", {})
	some l in _l(bd, "lists")
	lower(object.get(l, "name", "")) == "default-paloalto-dns"
	_act(object.get(l, "action", "")) == "sinkhole"
	sh := object.get(bd, "sinkhole", {})
	_nonempty(object.get(sh, "ipv4_address", ""))
	_nonempty(object.get(sh, "ipv6_address", ""))
}

_dns_security_ok(p) if {
	cats := _l(object.get(p, "botnet_domains", {}), "dns_security_categories")
	count(cats) > 0
	every c in cats { _act(object.get(c, "action", "")) == "sinkhole" }
	some c in cats
	lower(object.get(c, "name", "")) == "pan-dns-sec-cc"
	lower(object.get(c, "packet_capture", "")) == "extended-capture"
}

_inline_cloud_ok(p, k, want) if {
	_yes(p, "cloud_inline_analysis")
	ms := _l(p, k)
	count(ms) > 0
	every m in ms { _act(object.get(m, "inline_policy_action", "")) == want }
}

_block_acts := {"block-ip", "drop", "reset-both", "reset-client", "reset-server", "block"}

# every rule matching the severity (or "any") takes one of the actions, and at least one rule matches
_vuln_sev(p, s, acts) if {
	xs := [x | some x in _l(p, "rules"); count({s, "any"} & _ls(x, "severity")) > 0]
	count(xs) > 0
	every x in xs { _act(object.get(x, "action", "")) in acts }
}

_vuln_ok(p) if {
	every s in ["critical", "high"] { _vuln_sev(p, s, _block_acts) }
	every s in ["medium", "low", "informational"] { _vuln_sev(p, s, _block_acts | {"default"}) }
}

_url_header_logging(p) if {
	_no(p, "log_container_page_only")
	_yes(p, "log_http_hdr_user_agent")
	_yes(p, "log_http_hdr_referer")
	_yes(p, "log_http_hdr_xff")
}

# credential detection on; every category the profile lets through blocks or continues credential submission
_cred_ok(p) if {
	ce := object.get(p, "credential_enforcement", {})
	lower(object.get(ce, "mode", "disabled")) != "disabled"
	_nonempty(object.get(ce, "log_severity", ""))
	count(_l(ce, "allow")) == 0
	count(_l(ce, "alert")) == 0
	count((_ls(p, "alert") | _ls(p, "allow")) - (_ls(ce, "block") | _ls(ce, "continue"))) == 0
}

# ── zone protection ──
_zpp(z) := p if {
	some p in input.panos_config.network.profiles.zone_protection
	p.name == object.get(z, "zone_protection_profile", "")
}

_untrusted_zone_objs := [z | some z in input.panos_config.zone; lower(z.name) in _untrusted]

# every zone the site lists as untrusted exists in the collected zone list
default _untrusted_known := false

_untrusted_known if count(_untrusted - {lower(z.name) | some z in input.panos_config.zone}) == 0

_rate_ok(f) if {
	every k in ["alarm_rate", "activate_rate", "maximal_rate"] { _n(f, k) > 0 }
}

_syn_cookies(p) if {
	f := object.get(object.get(p, "flood", {}), "tcp_syn", {})
	_yes(f, "enable")
	lower(object.get(f, "action", "")) == "syn-cookies"
	_rate_ok(f)
}

_floods_ok(p) if {
	fl := object.get(p, "flood", {})
	every t in ["tcp_syn", "udp", "icmp", "icmpv6", "other_ip"] {
		f := object.get(fl, t, {})
		_yes(f, "enable")
		_rate_ok(f)
	}
}

_scan_ok(s, k, acts) if {
	x := object.get(s, k, {})
	_yes(x, "enable")
	lower(object.get(x, "action", "")) in acts
	_n(x, "interval") > 0
	_n(x, "threshold") > 0
}

_recon_ok(p) if {
	s := object.get(p, "scan", {})
	_scan_ok(s, "tcp_port_scan", {"block-ip"})
	lower(object.get(s.tcp_port_scan, "track_by", "")) == "source"
	_n(s.tcp_port_scan, "duration") > 0
	_scan_ok(s, "host_sweep", {"block", "block-ip"})
	_scan_ok(s, "udp_port_scan", {"alert", "block", "block-ip"})
}

_drops_ok(p) if {
	every k in [
		"discard_ip_spoof", "discard_overlapping_tcp_segment_mismatch", "discard_strict_source_routing",
		"discard_loose_source_routing", "discard_malformed_option",
	] { _yes(p, k) }
}

# ── decryption ──
_forward_proxy_inet(d) if {
	not _yes(d, "disabled")
	_act(object.get(d, "action", "")) == "decrypt"
	_act(object.get(d, "type", "")) == "ssl-forward-proxy"
	_to_inet(d)
}

'''

# ── emission: roll-up module ───────────────────────────────────────────────────────
META = '''# METADATA
# title: "{title}"
# custom:
#   class: security
#   framework: cis_network_devices
#   source: cis
#   domains: [network, palo-alto]
#   coverage:
#     checks: {checks}
#     cited: {checks}
#     density: {density}
#     basis: {basis}
#     tested: true
#     entrypoint: {entry}
#     guard: self
#     as_of: v2.4.2
'''

HEADER = META.format(title=BENCH, checks=N_TOTAL, density="sized", basis="size", entry="compliance_report") + f'''package {PKG}

# {BENCH}
# Rewritten 2026-11-14 from the CIS workbook by tools/cis_generators/gen_palo_alto.py. The previous module claimed
# "CIS Palo Alto PAN-OS Benchmark v1.2.0" and implemented a handful of rules; it is replaced in place.
# {N_TOTAL} recommendations ({N_AUTO} Automated, {N_TOTAL - N_AUTO} Manual; {N_L1} Level 1, {N_L2} Level 2), every one in the
# benchmark; ids, levels and assessment status read from the workbook. Messages use our own wording, not CIS text.
# Profile: input.cis_profile.level, the number 1 or 2 (Level 2 includes Level 1); absent => 2; any other value (the
# string "2" included) => "evidence invalid", scoped at Level 2. total_controls counts the recommendations in the
# selected profile.
# Automated checks fail closed: facts not collected => "<id>: evidence missing — <field> not collected".
# Typed facts: a number must be a JSON number and a yes/no must be "yes" / "no" or a JSON boolean; a list the check
# counts must be a list. Anything else => "<id>: evidence invalid — <field> must be <type>, got <value>".
# A profiles.<kind> list that was collected and is empty fails its recommendations as "(no <kind> profile configured)";
# only an absent key is missing evidence.
# Manual recommendations with a decidable configuration fact are checked like Automated ones:
#   {", ".join(manual_fact)}.
# Attestation booleans under input.panos_config.attest (false or absent => violation): {", ".join(attest_ids)}.
#   Automated in the workbook but attested here: 2.1 (read from traffic/URL logs, not configuration), 2.6 (an
#   Active Directory setting), 5.1 (the per-file-type defaults differ by PAN-OS release; sizing is a judgement).
# 6.22-6.25 apply only when the named license is active; licenses not collected => evidence missing.
#
# Input contract (input.panos_config): the running configuration (`show config running`, XML converted to JSON)
# with "-" in element names written as "_", every <entry> list written as an array of objects keyed by "name",
# every <member> list as an array of strings, booleans as "yes"/"no" (JSON true/false read the same) and numbers
# as JSON numbers. Paths are flattened as follows:
#   deviceconfig.system            : login_banner, server_verification, service{{disable_http, disable_telnet}},
#                                    snmp_setting.access_setting.version ("v3"), ntp_servers.{{primary,secondary}}_ntp_server
#                                    .ntp_server_address, update_schedule.{{anti_virus,threats,wildfire}}{{action, recurrence}}
#   deviceconfig.setting           : management{{enable_log_high_dp_load, idle_timeout}}, ssl_decrypt
#                                    .allow_forward_decrypted_content, wildfire.session_info_select{{exclude_*}}
#   deviceconfig.high_availability : enabled, interface.ha2.port, state_synchronization.enabled, link_monitoring /
#                                    path_monitoring {{enabled, failure_condition, link_group[] / path_group[]}},
#                                    active_passive.passive_link_state, election_option.preemptive
#   mgt_config                     : password_complexity{{...}}, password_profile[]{{name, password_change.expiration_period}}
#   shared                         : server_profile.{{syslog[], snmptrap[]}}, log_settings.<type>.match_list[]{{filter,
#                                    send_syslog[], send_snmptrap[]}}, authentication_profile[]{{lockout}},
#                                    log_forwarding_profile[]{{match_list[]{{log_type, send_*[]}}}}
#   network.profiles               : interface_management[]{{http, telnet, ...}}, zone_protection[]{{flood, scan, discard_*}}
#   zone[]                         : {{name, zone_protection_profile, enable_user_identification}}
#   user_id                        : setting.enable_probing, include_exclude_network[]{{name, discovery, network_address}}
#   profiles.<kind>[]              : virus, spyware, vulnerability, url_filtering, data_filtering, wildfire_analysis
#   profile_group[]                : {{name, <kind>[]}}
#   rulebase.security[]            : {{name, from[], to[], source[], destination[], application[], service[], action,
#                                    disabled, profile_setting{{profiles{{<kind>[]}}, group[]}}}}
#   rulebase.default_security_rules[], rulebase.decryption[]{{action, type, from[], to[]}}
#   licenses[]                     : `request license info` {{feature, expired}}
#   site                           : operator classification, not device config: untrusted_zones[], internet_zones[],
#                                    url_block_categories[] (an empty or absent list is evidence missing)
#   attest.*                       : attestation booleans for the judgement recommendations

import rego.v1

# Main compliance rule - every recommendation in the selected profile must pass; no facts, no compliance
default compliant := false

compliant if {{
	input.panos_config
	count(violations) == 0
}}

# Aggregate all violations across sections
violations := [v |
	arrays := [
{chr(10).join(f"		{s}_violations," for s in SECTIONS)}
		profile_violations,
	]
	some a in arrays
	some v in a
]

'''

parts = [HEADER]
parts.append(LEVEL_VIOLATIONS)
for s in SECTIONS:
    parts.append(f"# {STITLE[s]}\n{s}_violations := sort([m | some m in _v_{s}])\n")
parts.append(HELPERS)
for c in C:
    parts.append(emit_control(c, WB, f"_v_{section(c['id'])}", applies=True))
parts.append("# Every recommendation in the benchmark: title, level, assessment status, how it is checked, report section.\n"
             "recommendations := " + table(C, WB, lambda c, w: {"section": section(c["id"])}) + "\n")
sec_tot = {s: sum(1 for c in C if section(c["id"]) == s) for s in SECTIONS}
assert sum(sec_tot.values()) == N_TOTAL
sec_lines = ",\n".join(
    f'\t\t"{s}": {{\n\t\t\t"total": count({{id | some id, r in recommendations; r.section == "{s}"; _applies(id)}}),\n'
    f'\t\t\t"violations": count({s}_violations),\n\t\t}}' for s in SECTIONS)
parts.append(f'''
# recommendations in the selected profile
in_scope := {{id | some id, _ in recommendations; _applies(id)}}

_failed_ids := {{id | some v in violations; id := split(v, ":")[0]; id in in_scope}}

# Compliance summary for reporting (counts are recommendations; a recommendation fails once however many messages it emits)
compliance_summary := {{
	"total_controls": count(in_scope),
	"passing_controls": count(in_scope) - count(_failed_ids),
	"failing_controls": count(_failed_ids),
	"compliance_percentage": ((count(in_scope) - count(_failed_ids)) * 100) / count(in_scope),
	"sections": {{
{sec_lines},
	}},
}}

compliance_report := {{
	"benchmark": "{BENCH}",
	"level": _level,
	"total_controls": count(in_scope),
	"standard_total": {N_TOTAL},
	"standard_total_source": "{BENCH}, recommendations counted from the CIS workbook",
	"failed_controls": count(_failed_ids),
	"passed_controls": count(in_scope) - count(_failed_ids),
	"compliant": compliant,
	"violation_count": count(violations),
	"violations": violations,
}}
''')
open(f"{OUT}/{PKG}.rego", "w").write("\n".join(parts))

# ── emission: .main bridge ────────────────────────────────────────────────────────
MAIN = META.format(title=f"{BENCH} - compliance_report entrypoint", checks=0, density="orchestrator", basis="role",
                   entry="compliance_report") + f'''package {PKG}.main

# OPA query path: /v1/data/{PKG}/main/compliance_report
# Thin bridge over data.{PKG} (generated by tools/cis_generators/gen_palo_alto.py). That package already fails
# closed per recommendation; this adds the fields every cis_*.main report carries and an explicit notice on empty input.

import data.{PKG} as bench
import rego.v1

default _facts_supplied := false

_facts_supplied if count(object.keys(input)) > 0

# distinct failing in-scope recommendations, parsed from the "<id>: ..." message prefix
_failed_ids := {{id |
	some v in bench.violations
	id := split(v, ":")[0]
	id in bench.in_scope
}}

_total := count(bench.in_scope)

default _pct := 0

_pct := round(((_total - count(_failed_ids)) * 100) / _total) if _total > 0

_no_facts_msg := sprintf(
	"FAIL-CLOSED: no facts supplied for %s — the assessment could not be evaluated. This is NOT a passing result; check that fact collection ran and produced input.",
	["{PKG}"],
)

_report_violations := array.concat(sort([v | some v in bench.violations]), [_no_facts_msg]) if not _facts_supplied

_report_violations := sort([v | some v in bench.violations]) if _facts_supplied

compliant := bench.compliant

violations := bench.violations

compliance_report := object.union(bench.compliance_report, {{
	"framework": "{PKG}",
	"version": "v1.2.1",
	"facts_supplied": _facts_supplied,
	"controls_basis": "recommendations of {BENCH} in the selected profile (input.cis_profile.level)",
	"total_controls": _total,
	"passed_controls": _total - count(_failed_ids),
	"failed_controls": count(_failed_ids),
	"compliance_percentage": _pct,
	"violations": _report_violations,
	"violation_count": count(_report_violations),
}})
'''
open(f"{OUT}/{PKG}_main.rego", "w").write(MAIN)

# ── emission: generated tests ─────────────────────────────────────────────────────────
tests = f'''package {PKG}_test

import rego.v1

import data.{PKG} as b

# Generated per-recommendation tests for {BENCH} (tools/cis_generators/gen_palo_alto.py): every recommendation
# has a pass test (green input) and a fail test; configuration checks also have an evidence-missing test;
# attestations fail when false or absent. Hand-written tests live in test_{PKG}_controls.rego.

green := {json.dumps(GREEN, indent=chr(9), ensure_ascii=False)}

_has_id(vs, id) if {{
	some v in vs
	startswith(v, concat("", [id, ":"]))
}}

test_green_input_is_compliant if {{
	vs := b.violations with input as green
	count(vs) == 0
	b.compliant with input as green
	s := b.compliance_summary with input as green
	s.passing_controls == {N_TOTAL}
	s.compliance_percentage == 100
}}

test_recommendation_count_matches_workbook if {{
	count(b.recommendations) == {N_TOTAL}
	count([id | some id, r in b.recommendations; r.level == 2]) == {N_L2}
	count([id | some id, r in b.recommendations; r.assessment == "Automated"]) == {N_AUTO}
	count([id | some id, r in b.recommendations; r.check == "attestation"]) == {len(attest_ids)}
}}

test_empty_input_fails_every_recommendation if {{
	r := b.compliance_report with input as {{}}
	r.total_controls == {N_TOTAL}
	r.failed_controls == {N_TOTAL}
	r.compliant == false
}}

test_level_1_profile_scopes_the_report if {{
	inp := json.patch(green, [{{"op": "add", "path": "/cis_profile", "value": {{"level": 1}}}}])
	r := b.compliance_report with input as inp
	r.total_controls == {N_L1}
	r.failed_controls == 0
	e := b.compliance_report with input as {{"cis_profile": {{"level": 1}}}}
	e.total_controls == {N_L1}
	e.failed_controls == {N_L1}
}}

test_level_2_only_recommendation_skipped_at_level_1 if {{
	inp := json.patch(green, [
		{{"op": "add", "path": "/cis_profile", "value": {{"level": 1}}}},
		{{"op": "add", "path": "/panos_config/user_id/setting/enable_probing", "value": "yes"}},
	])
	vs := b.violations with input as inp
	not _has_id(vs, "2.2")
}}

{emit_tests(PKG, C, WB, GREEN, "/panos_config/attest")}'''
open(f"{OUT}/tests/test_{PKG}_recommendations.rego", "w").write(tests)
print("ok", len(C), sec_tot, "attested", len(attest_ids), "manual-as-fact", len(manual_fact))
