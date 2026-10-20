import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cis_genlib import load_workbook_json, emit_control, emit_tests, table  # noqa: E402

WB = load_workbook_json(sys.argv[1])  # JSON from dump_workbook.py
OUT = sys.argv[2]
BENCH = "CIS FortiGate 7.4.x Benchmark v1.0.1"
F = "input.fortigate_config"
G = f"{F}.system.global"


def add(path, value):
    return [{"op": "add", "path": "/fortigate_config" + path, "value": value}]


def rm(path):
    return [{"op": "remove", "path": "/fortigate_config" + path}]


def fact(cid, ev, label, ok, fail, miss, ok2=None):
    return {"id": cid, "kind": "fact", "ev": ev, "label": "fortigate_config." + label, "ok": [ok] + ([ok2] if ok2 else []),
            "fail": fail, "miss": miss}


def glob(cid, ok, fail):
    return fact(cid, ["_global_collected"], "system.global", ok, add(f"/system/global/{fail[0]}", fail[1]), rm("/system/global"))


def att(cid, key):
    return {"id": cid, "kind": "attest", "attest": key, "attest_root": F}


POL = [f"is_array({F}.firewall.policy)", f"count({F}.firewall.policy) > 0"]
POL_IF = POL + [f"is_array({F}.system.interface)", "count(_wan_interfaces) > 0"]
AVP = [f"is_array({F}.antivirus.profile)", f"count({F}.antivirus.profile) > 0"]
DNSP = [f"is_array({F}.dnsfilter.profile)", f"count({F}.dnsfilter.profile) > 0"]
APPL = [f"is_array({F}.application.list)", f"count({F}.application.list) > 0"]
IFACE = [f"is_array({F}.system.interface)", f"count({F}.system.interface) > 0"]
ADM = [f"is_array({F}.system.admin)", f"count({F}.system.admin) > 0"]
SNMPU = [f"is_array({F}.system.snmp.user)", f"count({F}.system.snmp.user) > 0"]
HA = [f"is_object({F}.system.ha)", f"is_string({F}.system.ha.mode)"]
SYSLOG = [f"is_object({F}.log.syslogd.setting)", f"count({F}.log.syslogd.setting) > 0"]

C = [
    fact("1.1", [f"is_object({F}.system.dns)"], "system.dns",
         [f"is_string({F}.system.dns.primary)", f'not {F}.system.dns.primary in {{"", "0.0.0.0"}}'],
         add("/system/dns/primary", "0.0.0.0"), rm("/system/dns")),
    fact("1.2", [f"is_array({F}.system.zone)"], "system.zone",
         [f'every z in {F}.system.zone {{ lower(object.get(z, "intrazone", "allow")) == "deny" }}'],
         add("/system/zone/0/intrazone", "allow"), rm("/system/zone")),
    fact("1.3", IFACE + ["count(_wan_interfaces) > 0"], "system.interface (a WAN-role interface)",
         ['every i in _wan_interfaces { count(_access(i) & {"ping", "https", "http", "ssh", "snmp", "radius-acct"}) == 0 }'],
         add("/system/interface/0/allowaccess", "ping https"), rm("/system/interface/0/role")),
    glob("2.1.1", [f'{G}.pre_login_banner == "enable"'], ("pre_login_banner", "disable")),
    glob("2.1.2", [f'{G}.post_login_banner == "enable"'], ("post_login_banner", "disable")),
    glob("2.1.3", [f"_ = {G}.timezone", f'sprintf("%v", [{G}.timezone]) != ""'], ("timezone", "")),
    fact("2.1.4", [f"is_object({F}.system.ntp)"], "system.ntp", [f'{F}.system.ntp.ntpsync == "enable"'],
         add("/system/ntp/ntpsync", "disable"), rm("/system/ntp")),
    glob("2.1.5", [f"is_string({G}.hostname)", f'{G}.hostname != ""'], ("hostname", "")),
    att("2.1.6", "latest_firmware_installed"),
    fact("2.1.7", [f"is_object({F}.system.auto_install)"], "system.auto_install",
         [f'{F}.system.auto_install.auto_install_config == "disable"', f'{F}.system.auto_install.auto_install_image == "disable"'],
         add("/system/auto_install/auto_install_image", "enable"), rm("/system/auto_install")),
    glob("2.1.8", [f'{G}.ssl_static_key_ciphers == "disable"'], ("ssl_static_key_ciphers", "enable")),
    glob("2.1.9", [f'{G}.strong_crypto == "enable"'], ("strong_crypto", "disable")),
    glob("2.1.10", [f'_words({G}.admin_https_ssl_versions) == {{"tlsv1-3"}}'], ("admin_https_ssl_versions", "tlsv1-2 tlsv1-3")),
    glob("2.1.11", [f'{G}.gui_cdn_usage == "enable"'], ("gui_cdn_usage", "disable")),
    glob("2.1.12", [f'{G}.log_single_cpu_high == "enable"'], ("log_single_cpu_high", "disable")),
    glob("2.1.13", [f'{G}.gui_display_hostname == "disable"'], ("gui_display_hostname", "enable")),
    fact("2.2.1", [f"is_object({F}.system.password_policy)"], "system.password_policy",
         [f'{F}.system.password_policy.status == "enable"', f"to_number({F}.system.password_policy.minimum_length) >= 14",
          f'{{"admin-password", "ipsec-preshared-key"}} - _words({F}.system.password_policy.apply_to) == set()'],
         add("/system/password_policy/minimum_length", 8), rm("/system/password_policy")),
    glob("2.2.2", [f"n := to_number({G}.admin_lockout_threshold)", "n > 0", "n <= 3",
                   f"t := to_number({G}.admin_lockout_duration)", "t > 0", "t <= 900"], ("admin_lockout_threshold", 5)),
    fact("2.3.1", [f"is_object({F}.system.snmp.sysinfo)", f"is_array({F}.system.snmp.community)", f"is_array({F}.system.snmp.user)"],
         "system.snmp.{sysinfo,community,user}",
         [f'{F}.system.snmp.sysinfo.status == "enable"', f"count({F}.system.snmp.community) == 0", f"count({F}.system.snmp.user) > 0"],
         add("/system/snmp/community", [{"name": "public"}]), rm("/system/snmp/community")),
    fact("2.3.2", SNMPU, "system.snmp.user",
         [f'every u in {F}.system.snmp.user {{ hs := _names(object.get(u, "notify_hosts", [])); count(hs) > 0; not "0.0.0.0" in hs }}'],
         add("/system/snmp/user/0/notify_hosts", ["0.0.0.0"]), rm("/system/snmp/user")),
    fact("2.3.3", SNMPU, "system.snmp.user",
         [f'every u in {F}.system.snmp.user {{ object.get(u, "queries", "enable") == "disable" }}'],
         add("/system/snmp/user/0/queries", "enable"), rm("/system/snmp/user")),
    fact("2.3.4", [f"is_object({F}.system.snmp.sysinfo)"], "system.snmp.sysinfo",
         [f'{F}.system.snmp.sysinfo.status == "enable"', f"to_number({F}.system.snmp.sysinfo.trap_free_memory_threshold) >= 20",
          f"to_number({F}.system.snmp.sysinfo.trap_freeable_memory_threshold) <= 50"],
         add("/system/snmp/sysinfo/trap_free_memory_threshold", 5), rm("/system/snmp/sysinfo")),
    fact("2.4.1", ADM, "system.admin", [f'every a in {F}.system.admin {{ lower(a.name) != "admin" }}'],
         add("/system/admin/0/name", "admin"), rm("/system/admin")),
    fact("2.4.2", ADM, "system.admin", [f"every a in {F}.system.admin {{ _restricted_trusthosts(a) }}"],
         add("/system/admin/0/trusthosts", []), rm("/system/admin")),
    att("2.4.3", "admin_profiles_reviewed"),
    glob("2.4.4", [f"n := to_number({G}.admintimeout)", "n > 0", "n <= 5"], ("admintimeout", 30)),
    fact("2.4.5", IFACE, "system.interface",
         [f'every i in {F}.system.interface {{ count(_access(i) & {{"http", "telnet"}}) == 0 }}'],
         add("/system/interface/1/allowaccess", "https ssh http"), rm("/system/interface")),
    fact("2.4.6", [f"is_array({F}.firewall.local_in_policy)"], "firewall.local_in_policy",
         [f"count({F}.firewall.local_in_policy) > 0"], add("/firewall/local_in_policy", []), rm("/firewall/local_in_policy")),
    glob("2.4.7", [f'object.get({G}, "admin_port", 80) != 80', f'object.get({G}, "admin_sport", 443) != 443',
                   f'object.get({G}, "admin_https_redirect", "enable") == "disable"'], ("admin_sport", 443)),
    fact("2.4.8", [f"is_array({F}.firewall.local_in_policy)"], "firewall.local_in_policy",
         [f'every p in {F}.firewall.local_in_policy {{ _local_in_patched(p) }}'],
         add("/firewall/local_in_policy/0/virtual_patch", "disable"), rm("/firewall/local_in_policy")),
    fact("2.5.1", HA, "system.ha",
         [f'lower({F}.system.ha.mode) in {{"a-p", "a-a"}}', f'is_string({F}.system.ha.group_name)', f'{F}.system.ha.group_name != ""',
          f'count(_names(object.get({F}.system.ha, "hbdev", []))) > 0'],
         add("/system/ha/mode", "standalone"), rm("/system/ha")),
    fact("2.5.2", HA, "system.ha", [f'count(_names(object.get({F}.system.ha, "monitor", []))) > 0'],
         add("/system/ha/monitor", []), rm("/system/ha"), ok2=["_ha_standalone"]),
    fact("2.5.3", HA, "system.ha",
         [f'{F}.system.ha.ha_mgmt_status == "enable"', f'count(object.get({F}.system.ha, "ha_mgmt_interfaces", [])) > 0'],
         add("/system/ha/ha_mgmt_status", "disable"), rm("/system/ha"), ok2=["_ha_standalone"]),
    fact("2.5.4", HA, "system.ha", [f'to_number(object.get({F}.system.ha, "group_id", 0)) > 0'],
         add("/system/ha/group_id", 0), rm("/system/ha")),
    att("3.1", "unused_policies_reviewed"),
    fact("3.2", POL, "firewall.policy",
         ['every p in _accept_policies { not "all" in {lower(s) | some s in _names(object.get(p, "service", []))} }'],
         add("/firewall/policy/0/service", ["ALL"]), rm("/firewall/policy")),
    fact("3.3", POL, "firewall.policy",
         ["count(_isdb_inbound - _denied_isdb_src) == 0", "count(_isdb_outbound - _denied_isdb_dst) == 0"],
         add("/firewall/policy/1/internet_service_src_name", ["Tor-Exit.Node"]), rm("/firewall/policy")),
    fact("3.4", POL, "firewall.policy",
         [f'every p in {F}.firewall.policy {{ lower(object.get(p, "logtraffic", "")) in {{"all", "utm"}} }}'],
         add("/firewall/policy/0/logtraffic", "disable"), rm("/firewall/policy")),
    fact("4.1.1", POL_IF + [f"is_array({F}.ips.sensor)"], "{ips.sensor,firewall.policy,system.interface WAN role}",
         ["count(_botnet_block_sensors) > 0", 'every p in _wan_accept_policies { object.get(p, "ips_sensor", "") in _botnet_block_sensors }'],
         add("/ips/sensor/0/scan_botnet_connections", "monitor"), rm("/system/interface/0/role")),
    fact("4.1.2", POL, "firewall.policy", ['every p in _accept_policies { _set(p, "ips_sensor") }'],
         rm("/firewall/policy/0/ips_sensor"), rm("/firewall/policy")),
    fact("4.2.1", [f"is_object({F}.system.autoupdate.schedule)"], "system.autoupdate.schedule",
         [f'{F}.system.autoupdate.schedule.frequency == "automatic"'],
         add("/system/autoupdate/schedule/frequency", "daily"), rm("/system/autoupdate/schedule")),
    fact("4.2.2", POL, "firewall.policy", ['every p in _accept_policies { _set(p, "av_profile") }'],
         rm("/firewall/policy/0/av_profile"), rm("/firewall/policy")),
    fact("4.2.3", AVP, "antivirus.profile", [f"every prof in {F}.antivirus.profile {{ _outbreak_blocked(prof) }}"],
         add("/antivirus/profile/0/http/outbreak_prevention", "disabled"), rm("/antivirus/profile")),
    fact("4.2.4", [f"is_object({F}.antivirus.settings)"], "antivirus.settings",
         [f'{F}.antivirus.settings.machine_learning_detection == "enable"'],
         add("/antivirus/settings/machine_learning_detection", "monitor"), rm("/antivirus/settings")),
    fact("4.2.5", [f"is_object({F}.antivirus.settings)"], "antivirus.settings", [f'{F}.antivirus.settings.grayware == "enable"'],
         add("/antivirus/settings/grayware", "disable"), rm("/antivirus/settings")),
    fact("4.2.6", [f"is_object({F}.system.fortiguard)"] + AVP, "{system.fortiguard,antivirus.profile}",
         [f'{F}.system.fortiguard.sandbox_inline_scan == "enable"',
          f'every prof in {F}.antivirus.profile {{ object.get(prof, "fortisandbox_mode", "") == "inline" }}'],
         add("/system/fortiguard/sandbox_inline_scan", "disable"), rm("/system/fortiguard")),
    fact("4.2.7", AVP, "antivirus.profile", [f"some prof in {F}.antivirus.profile", "_proxy_cdr(prof)"],
         add("/antivirus/profile/0/feature_set", "flow"), rm("/antivirus/profile")),
    fact("4.3.1", DNSP, "dnsfilter.profile", [f'every p in {F}.dnsfilter.profile {{ object.get(p, "block_botnet", "") == "enable" }}'],
         add("/dnsfilter/profile/0/block_botnet", "disable"), rm("/dnsfilter/profile")),
    fact("4.3.2", DNSP, "dnsfilter.profile", [f'every p in {F}.dnsfilter.profile {{ object.get(p, "log_all_domain", "") == "enable" }}'],
         add("/dnsfilter/profile/0/log_all_domain", "disable"), rm("/dnsfilter/profile")),
    fact("4.3.3", POL_IF, "{firewall.policy,system.interface WAN role}", ['every p in _wan_accept_policies { _set(p, "dnsfilter_profile") }'],
         rm("/firewall/policy/0/dnsfilter_profile"), rm("/system/interface/0/role")),
    fact("4.4.1", [f"is_array({F}.webfilter.profile)", f"count({F}.webfilter.profile) > 0"], "webfilter.profile",
         [f"some prof in {F}.webfilter.profile", 'count({"26", "61", "86"} - _webfilter_blocked(prof)) == 0'],
         add("/webfilter/profile/0/ftgd_wf/filters/0/action", "monitor"), rm("/webfilter/profile")),
    fact("4.5.1", APPL, "application.list", [f"some l in {F}.application.list", 'count({"2", "6"} - _app_blocked_categories(l)) == 0'],
         add("/application/list/0/entries/0/action", "monitor"), rm("/application/list")),
    fact("4.5.2", APPL, "application.list",
         [f'every l in {F}.application.list {{ object.get(l, "enforce_default_app_port", "") == "enable" }}'],
         add("/application/list/0/enforce_default_app_port", "disable"), rm("/application/list")),
    fact("4.5.3", APPL, "application.list",
         [f'every l in {F}.application.list {{ every e in object.get(l, "entries", []) {{ object.get(e, "action", "") != "pass" }} }}'],
         add("/application/list/0/entries/1/action", "pass"), rm("/application/list")),
    fact("4.5.4", POL, "firewall.policy", ['every p in _accept_policies { _set(p, "application_list") }'],
         rm("/firewall/policy/0/application_list"), rm("/firewall/policy")),
    fact("5.1.1", [f"is_array({F}.system.automation_stitch)"], "system.automation_stitch",
         [f"some s in {F}.system.automation_stitch", "_quarantine_stitch(s)"],
         add("/system/automation_stitch/0/status", "disable"), rm("/system/automation_stitch")),
    fact("5.2.1.1", [f"is_object({F}.system.csf)"], "system.csf",
         [f'{F}.system.csf.status == "enable"', f"is_string({F}.system.csf.group_name)", f'{F}.system.csf.group_name != ""'],
         add("/system/csf/status", "disable"), rm("/system/csf")),
    fact("6.1.1", [f"is_object({F}.vpn.ssl.settings)"], "vpn.ssl.settings",
         [f"is_string({F}.vpn.ssl.settings.servercert)",
          f'not lower({F}.vpn.ssl.settings.servercert) in {{"", "fortinet_factory", "self-sign"}}'],
         add("/vpn/ssl/settings/servercert", "Fortinet_Factory"), rm("/vpn/ssl/settings")),
    fact("6.1.2", [f"is_object({F}.vpn.ssl.settings)"], "vpn.ssl.settings",
         [f'{F}.vpn.ssl.settings.ssl_max_proto_ver == "tls1-3"', f'{F}.vpn.ssl.settings.ssl_min_proto_ver == "tls1-2"',
          f'{F}.vpn.ssl.settings.algorithm == "high"'],
         add("/vpn/ssl/settings/ssl_min_proto_ver", "tls1-1"), rm("/vpn/ssl/settings")),
    fact("7.1.1", [f"is_object({F}.log.eventfilter)", f"count({F}.log.eventfilter) > 0"], "log.eventfilter",
         [f'every _, v in {F}.log.eventfilter {{ v == "enable" }}'],
         add("/log/eventfilter/vpn", "disable"), rm("/log/eventfilter")),
    fact("7.2.1", SYSLOG, "log.syslogd.setting",
         [f'{F}.log.syslogd.setting.status == "enable"', f"is_string({F}.log.syslogd.setting.server)",
          f'{F}.log.syslogd.setting.server != ""'],
         add("/log/syslogd/setting/status", "disable"), rm("/log/syslogd/setting")),
    fact("7.3.1", [f"is_object({F}.log.fortianalyzer.setting)", f"count({F}.log.fortianalyzer.setting) > 0"],
         "log.fortianalyzer.setting",
         [f'{F}.log.fortianalyzer.setting.enc_algorithm == "high"', f'{F}.log.fortianalyzer.setting.reliable == "enable"'],
         add("/log/fortianalyzer/setting/enc_algorithm", "low"), rm("/log/fortianalyzer/setting")),
    fact("7.3.2", SYSLOG, "log.syslogd.setting",
         [f'{F}.log.syslogd.setting.enc_algorithm == "high"', f'{F}.log.syslogd.setting.reliable == "enable"'],
         add("/log/syslogd/setting/enc_algorithm", "disable"), rm("/log/syslogd/setting")),
    fact("7.3.3", SYSLOG, "log.syslogd.setting",
         [f'{F}.log.syslogd.setting.enc_algorithm == "high"', f'{F}.log.syslogd.setting.reliable == "enable"'],
         add("/log/syslogd/setting/reliable", "disable"), rm("/log/syslogd/setting")),
]

SECTION_OF = {"1": "network", "2.1": "system_settings", "2.3": "system_settings", "2.5": "system_settings",
              "2.2": "administration", "2.4": "administration", "3": "firewall", "4": "security_profiles",
              "5": "security_fabric", "6": "vpn", "7": "logging"}


def section(cid):
    p = cid.split(".")
    return SECTION_OF.get(".".join(p[:2])) or SECTION_OF[p[0]]


SECTIONS = ["system_settings", "administration", "logging", "network", "firewall", "vpn", "wireless", "security_fabric",
            "security_profiles"]
STITLE = {"system_settings": "2.1 / 2.3 / 2.5 System settings, SNMP, high availability",
          "administration": "2.2 / 2.4 Password policy and administrators", "logging": "7 Logs and reports",
          "network": "1 Network settings", "firewall": "3 Policy and objects", "vpn": "6 VPN",
          "wireless": "no wireless recommendations in the 7.4.x benchmark (kept so the report shape is unchanged)",
          "security_fabric": "5 Security fabric", "security_profiles": "4 Security profiles"}

ids = [c["id"] for c in C]
assert len(ids) == len(set(ids)) == len(WB) == 64, (len(ids), len(WB), set(WB) - set(ids))
assert set(ids) == set(WB)

INB = ["Tor-Exit.Node", "Tor-Relay.Node", "Censys-Scanner", "Shodan-Scanner", "Botnet-C&C.Server", "Phishing-Phishing.Server",
       "Proxy-Proxy.Server", "Spam-Spamming.Server", "VPN-Anonymous.VPN", "Malicious-Malicious.Server"]
OUTB = ["Tor-Relay.Node", "Botnet-C&C.Server", "Phishing-Phishing.Server", "Proxy-Proxy.Server", "Spam-Spamming.Server",
        "VPN-Anonymous.VPN", "Malicious-Malicious.Server"]

GREEN = {"fortigate_config": {
    "system": {
        "dns": {"primary": "10.0.0.53", "secondary": "10.0.1.53"},
        "zone": [{"name": "DMZ", "intrazone": "deny"}],
        "interface": [{"name": "wan1", "role": "wan", "allowaccess": ""},
                      {"name": "mgmt", "role": "lan", "allowaccess": "https ssh"}],
        "global": {"pre_login_banner": "enable", "post_login_banner": "enable", "timezone": "US/Eastern",
                   "hostname": "fw-edge-01", "ssl_static_key_ciphers": "disable", "strong_crypto": "enable",
                   "admin_https_ssl_versions": "tlsv1-3", "gui_cdn_usage": "enable", "log_single_cpu_high": "enable",
                   "gui_display_hostname": "disable", "admin_lockout_threshold": 3, "admin_lockout_duration": 900,
                   "admintimeout": 5, "admin_port": 8082, "admin_sport": 4343, "admin_https_redirect": "disable"},
        "ntp": {"ntpsync": "enable"},
        "auto_install": {"auto_install_config": "disable", "auto_install_image": "disable"},
        "password_policy": {"status": "enable", "minimum_length": 14, "apply_to": "admin-password ipsec-preshared-key"},
        "snmp": {"sysinfo": {"status": "enable", "trap_free_memory_threshold": 20, "trap_freeable_memory_threshold": 50},
                 "community": [],
                 "user": [{"name": "snmp_ops", "notify_hosts": ["10.0.0.20"], "queries": "disable"}]},
        "admin": [{"name": "fw_ops", "trusthosts": ["10.0.0.0 255.255.255.0"]}],
        "ha": {"mode": "a-p", "group_name": "FGT-HA", "group_id": 10, "hbdev": ["port10"], "monitor": ["port6", "port7"],
               "ha_mgmt_status": "enable", "ha_mgmt_interfaces": [{"interface": "port8", "gateway": "10.10.10.1"}]},
        "autoupdate": {"schedule": {"frequency": "automatic"}},
        "fortiguard": {"sandbox_inline_scan": "enable"},
        "automation_stitch": [{"name": "Compromised Host Quarantine", "status": "enable", "trigger": "Compromised Host - High",
                               "actions": ["Quarantine on FortiSwitch + FortiAP", "Quarantine FortiClient EMS Endpoint"]}],
        "csf": {"status": "enable", "group_name": "fabric-01"},
    },
    "firewall": {
        "local_in_policy": [{"policyid": 1, "action": "accept", "virtual_patch": "enable"}, {"policyid": 2, "action": "deny"}],
        "policy": [
            {"policyid": 1, "srcintf": ["mgmt"], "dstintf": ["wan1"], "action": "accept", "service": ["HTTPS", "DNS"],
             "logtraffic": "all", "ips_sensor": "botnet-block", "av_profile": "av-default", "dnsfilter_profile": "dns-default",
             "application_list": "app-default"},
            {"policyid": 2, "srcintf": ["wan1"], "dstintf": ["mgmt"], "action": "deny", "service": ["ALL_TCP"],
             "logtraffic": "all", "internet_service_src": "enable", "internet_service_src_name": INB},
            {"policyid": 3, "srcintf": ["mgmt"], "dstintf": ["wan1"], "action": "deny", "service": ["HTTPS"],
             "logtraffic": "all", "internet_service": "enable", "internet_service_name": OUTB},
        ],
    },
    "ips": {"sensor": [{"name": "botnet-block", "scan_botnet_connections": "block"}]},
    "antivirus": {
        "settings": {"machine_learning_detection": "enable", "grayware": "enable"},
        "profile": [{"name": "av-default", "feature_set": "proxy", "fortisandbox_mode": "inline",
                     "http": {"outbreak_prevention": "block", "content_disarm": "enable"},
                     "smtp": {"outbreak_prevention": "block", "content_disarm": "enable"}}],
    },
    "dnsfilter": {"profile": [{"name": "dns-default", "block_botnet": "enable", "log_all_domain": "enable"}]},
    "webfilter": {"profile": [{"name": "web-default", "ftgd_wf": {"filters": [
        {"category": 26, "action": "block"}, {"category": 61, "action": "block"}, {"category": 86, "action": "block"}]}}]},
    "application": {"list": [{"name": "app-default", "enforce_default_app_port": "enable",
                              "entries": [{"category": [2, 6], "action": "block"}, {"category": [5], "action": "monitor"}]}]},
    "vpn": {"ssl": {"settings": {"servercert": "vpn.example.com", "ssl_max_proto_ver": "tls1-3",
                                 "ssl_min_proto_ver": "tls1-2", "algorithm": "high"}}},
    "log": {
        "eventfilter": {"event": "enable", "system": "enable", "vpn": "enable", "user": "enable", "router": "enable",
                        "wireless_activity": "enable", "wan_opt": "enable", "endpoint": "enable", "ha": "enable",
                        "security_rating": "enable", "fortiextender": "enable", "connector": "enable", "sdwan": "enable",
                        "cifs": "enable", "switch_controller": "enable", "rest_api": "enable", "webproxy": "enable"},
        "syslogd": {"setting": {"status": "enable", "server": "10.0.0.30", "enc_algorithm": "high", "reliable": "enable"}},
        "fortianalyzer": {"setting": {"status": "enable", "server": "10.0.0.31", "enc_algorithm": "high", "reliable": "enable"}},
    },
    "attest": {"latest_firmware_installed": True, "admin_profiles_reviewed": True, "unused_policies_reviewed": True},
}}

attest_ids = [c["id"] for c in C if c["kind"] == "attest"]
manual_fact = [c["id"] for c in C if c["kind"] == "fact" and WB[c["id"]]["assessment"] == "Manual"]
n_auto = sum(1 for w in WB.values() if w["assessment"] == "Automated")

HEADER = f'''# METADATA
# title: "{BENCH}"
# custom:
#   class: security
#   framework: cis_network_devices
#   source: cis
#   domains: [network, fortinet]
#   coverage:
#     checks: 8
#     cited: 8
#     density: sparse
#     basis: size
#     tested: true
#     entrypoint: none
#     guard: self
#     as_of: v2.4.2
package cis_fortinet_fortigate

# {BENCH}
# Rewritten 2026-10-20 from the CIS workbook. The previous module claimed "Fortinet FortiGate Benchmark v1.3.0"; its 8
# control ids do not match the FortiGate 7.4.x numbering (e.g. its 1.1 checked the admin GUI TLS version, which is
# 7.4.x 2.1.10; 7.4.x 1.1 is the DNS server).
# {len(C)} recommendations ({n_auto} Automated, {len(C) - n_auto} Manual), every one in the benchmark; ids, titles, levels
# and assessment status read from the workbook. All levels are evaluated; `recommendations` lists each id's level.
# Automated checks fail closed: facts not collected => "<id>: evidence missing — <field> not collected".
# Manual recommendations with a decidable configuration fact are checked like Automated ones:
#   {", ".join(manual_fact)}.
# Manual recommendations that need a human judgement carry an attestation boolean under
#   input.fortigate_config.attest (not attested => violation): {", ".join(attest_ids)}.
# 7.3.2 and 7.3.3 carry the same title and audit in the workbook; both are kept as separate ids with the same check.
# 3.2 applies to accept policies (3.3 itself asks for deny policies on all services).
# 1.3, 4.1.1 and 4.3.3 need at least one interface with role "wan"; without one the evidence is missing.
# 2.5.2 and 2.5.3 apply to HA clusters; a standalone unit (system.ha.mode == "standalone") passes them.
#
# Input contract (input.fortigate_config, FortiOS CLI names with "-" written as "_"):
#   system.global.*                 : `get system global` (pre_login_banner, admin_https_ssl_versions, admintimeout, ...)
#   system.{{dns,ntp,auto_install,password_policy,ha,csf,fortiguard}} : the matching `config system ...` objects
#   system.autoupdate.schedule      : `config system autoupdate schedule`
#   system.interface[]              : {{name, role, allowaccess}} (allowaccess a space-separated string or a list)
#   system.zone[]                   : {{name, intrazone}}
#   system.admin[]                  : {{name, trusthosts[]}} (trusthost1..10 values, "0.0.0.0 0.0.0.0" = any)
#   system.snmp.{{sysinfo, community[], user[]}} : user {{name, notify_hosts[], queries}}
#   system.automation_stitch[]      : {{name, status, trigger, actions[]}}
#   firewall.policy[]               : {{policyid, srcintf, dstintf, action, service, logtraffic, ips_sensor, av_profile,
#                                      dnsfilter_profile, application_list, internet_service_name, internet_service_src_name}}
#   firewall.local_in_policy[]      : {{policyid, action, virtual_patch}}
#   ips.sensor[]                    : {{name, scan_botnet_connections}}
#   antivirus.settings / antivirus.profile[] : profile {{name, feature_set, fortisandbox_mode, <protocol>: {{outbreak_prevention, content_disarm}}}}
#   dnsfilter.profile[]             : {{name, block_botnet, log_all_domain}}
#   webfilter.profile[]             : {{name, ftgd_wf.filters[] {{category (FortiGuard id), action}}}}
#   application.list[]              : {{name, enforce_default_app_port, entries[] {{category[] (FortiGuard ids), action}}}}
#   vpn.ssl.settings                : {{servercert, ssl_min_proto_ver, ssl_max_proto_ver, algorithm}}
#   log.eventfilter / log.syslogd.setting / log.fortianalyzer.setting
#   attest.*                        : attestation booleans for the judgement recommendations

import rego.v1

# Main compliance rule - every recommendation must pass; no facts, no compliance
default compliant := false

compliant if {{
	input.fortigate_config
	count(violations) == 0
}}

# Aggregate all violations across sections
violations := [v |
	arrays := [
		system_settings_violations,
		administration_violations,
		logging_violations,
		network_violations,
		firewall_violations,
		vpn_violations,
		wireless_violations,
		security_fabric_violations,
		security_profiles_violations,
	]
	some a in arrays
	some v in a
]

'''

HELPERS = r'''# ── helpers ──────────────────────────────────────────────────────────────────
default _global_collected := false

_global_collected if {
	is_object(input.fortigate_config.system.global)
	count(input.fortigate_config.system.global) > 0
}

# a FortiOS multi-value field: a list, or a space-separated string
_names(v) := {sprintf("%v", [x]) | some x in v} if is_array(v)

_names(v) := {t | some t in regex.split(`\s+`, trim_space(v)); t != ""} if is_string(v)

_words(v) := {lower(t) | some t in _names(v)}

_access(i) := _words(object.get(i, "allowaccess", ""))

_set(obj, key) if {
	v := object.get(obj, key, "")
	is_string(v)
	v != ""
}

_wan_interfaces := [i | some i in input.fortigate_config.system.interface; lower(object.get(i, "role", "")) == "wan"]

_wan_names := {i.name | some i in _wan_interfaces}

_accept_policies := [p | some p in input.fortigate_config.firewall.policy; lower(object.get(p, "action", "deny")) == "accept"]

# accept policies whose destination includes a WAN-role interface (traffic outbound to the Internet)
_wan_accept_policies := [p |
	some p in _accept_policies
	count(_names(object.get(p, "dstintf", [])) & _wan_names) > 0
]

_restricted_trusthosts(a) if {
	hs := {h | some h in object.get(a, "trusthosts", []); not h in {"0.0.0.0 0.0.0.0", "0.0.0.0/0"}}
	count(hs) > 0
}

_local_in_patched(p) if lower(object.get(p, "action", "deny")) != "accept"

_local_in_patched(p) if object.get(p, "virtual_patch", "") == "enable"

default _ha_standalone := false

_ha_standalone if lower(input.fortigate_config.system.ha.mode) == "standalone"

# 3.3: Internet Service Database objects the benchmark names (inbound sources / outbound destinations)
_isdb_inbound := {
	"Tor-Exit.Node", "Tor-Relay.Node", "Censys-Scanner", "Shodan-Scanner", "Botnet-C&C.Server",
	"Phishing-Phishing.Server", "Proxy-Proxy.Server", "Spam-Spamming.Server", "VPN-Anonymous.VPN",
	"Malicious-Malicious.Server",
}

_isdb_outbound := {
	"Tor-Relay.Node", "Botnet-C&C.Server", "Phishing-Phishing.Server", "Proxy-Proxy.Server",
	"Spam-Spamming.Server", "VPN-Anonymous.VPN", "Malicious-Malicious.Server",
}

_deny_policies := [p | some p in input.fortigate_config.firewall.policy; lower(object.get(p, "action", "deny")) == "deny"]

_denied_isdb_src := {n | some p in _deny_policies; some n in _names(object.get(p, "internet_service_src_name", []))}

_denied_isdb_dst := {n | some p in _deny_policies; some n in _names(object.get(p, "internet_service_name", []))}

_botnet_block_sensors := {s.name | some s in input.fortigate_config.ips.sensor; object.get(s, "scan_botnet_connections", "") == "block"}

_av_protocols := {"http", "ftp", "imap", "pop3", "smtp", "mapi", "nntp", "cifs", "ssh"}

_outbreak_blocked(prof) if {
	protos := [v | some k, v in prof; k in _av_protocols]
	count(protos) > 0
	every v in protos { object.get(v, "outbreak_prevention", "") == "block" }
}

_proxy_cdr(prof) if {
	object.get(prof, "feature_set", "") == "proxy"
	some k, v in prof
	k in _av_protocols
	object.get(v, "content_disarm", "") == "enable"
}

# FortiGuard web filter category ids blocked by a profile (26 Malicious Websites, 61 Phishing, 86 Spam URLs)
_webfilter_blocked(prof) := {sprintf("%v", [f.category]) |
	wf := object.get(prof, "ftgd_wf", {})
	some f in object.get(wf, "filters", [])
	object.get(f, "action", "") == "block"
}

# FortiGuard application category ids blocked by a list (2 P2P, 6 Proxy)
_app_blocked_categories(l) := {c |
	some e in object.get(l, "entries", [])
	object.get(e, "action", "") == "block"
	some c in _names(object.get(e, "category", []))
}

_quarantine_stitch(s) if {
	object.get(s, "status", "") == "enable"
	contains(lower(sprintf("%v", [object.get(s, "trigger", "")])), "compromised host")
	some a in _names(object.get(s, "actions", []))
	contains(lower(a), "quarantine")
}

'''

parts = [HEADER]
for s in SECTIONS:
    parts.append(f"# {STITLE[s]}\n{s}_violations := sort([m | some m in _v_{s}])\n")
parts.append("_v_wireless := set()\n")
parts.append(HELPERS)
for c in C:
    parts.append(emit_control(c, WB, f"_v_{section(c['id'])}"))
parts.append("# Every recommendation in the benchmark: title, level, assessment status, how it is checked, report section.\n"
             "recommendations := " + table(C, WB, lambda c, w: {"section": section(c["id"])}) + "\n")
sec_tot = {s: sum(1 for c in C if section(c["id"]) == s) for s in SECTIONS}
assert sum(sec_tot.values()) == 64
sec_lines = ",\n".join(f'\t\t"{s}": {{\n\t\t\t"total": {sec_tot[s]},\n\t\t\t"violations": count({s}_violations),\n\t\t}}' for s in SECTIONS)
parts.append(f'''
_failed_ids := {{id | some v in violations; id := split(v, ":")[0]}}

# Compliance summary for reporting (counts are recommendations; a recommendation fails once however many messages it emits)
compliance_summary := {{
	"total_controls": 64,
	"passing_controls": 64 - count(_failed_ids),
	"failing_controls": count(_failed_ids),
	"compliance_percentage": ((64 - count(_failed_ids)) * 100) / 64,
	"sections": {{
{sec_lines},
	}},
}}

# Detailed findings for remediation
detailed_findings := {{
{chr(10).join(f'	"{s}_violations": {s}_violations,' for s in SECTIONS)}
}}

compliance_report := {{
	"benchmark": "{BENCH}",
	"total_controls": count(recommendations),
	"standard_total": 64,
	"standard_total_source": "{BENCH}, recommendations counted from the CIS workbook",
	"failed_controls": count(_failed_ids),
	"passed_controls": count(recommendations) - count(_failed_ids),
	"compliant": compliant,
	"violation_count": count(violations),
	"violations": violations,
}}
''')
open(f"{OUT}/cis_fortinet_fortigate.rego", "w").write("\n".join(parts))

tests = f'''package cis_fortinet_fortigate_test

import rego.v1

import data.cis_fortinet_fortigate as b

# Generated per-recommendation tests for {BENCH}: every recommendation has a pass test (green input) and a
# fail test; configuration checks also have an evidence-missing test; attestations fail when false or absent.

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
	s.passing_controls == 64
	s.compliance_percentage == 100
}}

test_recommendation_count_matches_workbook if {{
	count(b.recommendations) == 64
	count([id | some id, r in b.recommendations; r.level == 2]) == {sum(1 for w in WB.values() if w["level"] == 2)}
	count([id | some id, r in b.recommendations; r.assessment == "Automated"]) == {n_auto}
}}

test_summary_counts_recommendations_not_messages if {{
	s := b.compliance_summary with input as {{}}
	s.failing_controls == 64
	s.passing_controls == 0
	s.compliance_percentage == 0
	r := b.compliance_report with input as {{}}
	r.failed_controls == 64
	r.compliant == false
}}

test_3_2_deny_all_service_allowed_accept_all_flagged if {{
	inp := json.patch(green, [{{"op": "add", "path": "/fortigate_config/firewall/policy/1/service", "value": ["ALL"]}}])
	vs := b.violations with input as inp
	not _has_id(vs, "3.2")
	inp2 := json.patch(green, [{{"op": "add", "path": "/fortigate_config/firewall/policy/0/service", "value": ["ALL"]}}])
	vs2 := b.violations with input as inp2
	_has_id(vs2, "3.2")
}}

test_empty_policy_list_is_not_evidence if {{
	inp := json.patch(green, [{{"op": "add", "path": "/fortigate_config/firewall/policy", "value": []}}])
	vs := b.violations with input as inp
	"3.4: evidence missing — fortigate_config.firewall.policy not collected" in vs
}}

test_standalone_unit_passes_ha_cluster_checks if {{
	inp := json.patch(green, [{{"op": "add", "path": "/fortigate_config/system/ha", "value": {{"mode": "standalone"}}}}])
	vs := b.violations with input as inp
	not _has_id(vs, "2.5.2")
	not _has_id(vs, "2.5.3")
	_has_id(vs, "2.5.1")
}}

{emit_tests("cis_fortinet_fortigate", C, WB, GREEN, "/fortigate_config/attest")}'''
open(f"{OUT}/tests/test_cis_fortinet_fortigate_recommendations.rego", "w").write(tests)
print("ok", len(C), sec_tot)
