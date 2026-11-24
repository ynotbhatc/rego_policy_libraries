"""CIS Cisco IOS XE 17.x Benchmark v2.2.2 -> benchmarks/cis/network_devices/cisco_ios_xe_17/.

    /usr/bin/python3 tools/cis_generators/dump_workbook.py <workbook.xlsx> /tmp/xe.json
    /usr/bin/python3 tools/cis_generators/gen_cisco_ios_xe_17.py /tmp/xe.json benchmarks/cis/network_devices/cisco_ios_xe_17

Every recommendation in the workbook gets a rule. Each logic entry carries a keyword that must occur in the
workbook title of its id; the run aborts on any count, id, status, profile or keyword mismatch. Titles are
replaced by our own wording (OWN) before anything is written. Writes only the files it owns (roll-up, .main
bridge, generated recommendation tests, README is hand-kept beside them).
"""
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cis_genlib import LEVEL_HELPERS, LEVEL_VIOLATIONS, load_workbook_json, emit_control, emit_tests, table  # noqa: E402
from neutralize import neutralize_title  # noqa: E402

WB = load_workbook_json(sys.argv[1])
OUT = sys.argv[2]
BENCH = "CIS Cisco IOS XE 17.x Benchmark v2.2.2"
PKG = "cis_cisco_ios_xe_17"
P = "input.ios_xe_config"
N_TOTAL, N_AUTO, N_L1, N_L2 = 84, 0, 75, 9  # N_AUTO checked below against the workbook
KW = {}
OWN = {}
C = []

# ── a compliant configuration (test fixture) and JSON-patch helpers built from it ───────────────
GL = [
    "hostname edge-r1", "aaa new-model",
    "aaa authentication login default group tacacs+ local",
    "aaa authentication enable default group tacacs+ enable",
    "aaa accounting commands 15 default start-stop group tacacs+",
    "aaa accounting connection default start-stop group tacacs+",
    "aaa accounting exec default start-stop group tacacs+",
    "aaa accounting network default start-stop group tacacs+",
    "aaa accounting system default start-stop group tacacs+",
    "enable secret 9 $9$abcdef", "service password-encryption",
    "username admin privilege 1 secret 9 $9$ghijkl",
    "ip domain name example.net", "ip ssh time-out 60", "ip ssh authentication-retries 3", "ip ssh version 2",
    "no cdp run", "no ip bootp server", "no service dhcp", "service tcp-keepalives-in", "service tcp-keepalives-out",
    "no service pad", "login on-failure log", "login on-success log",
    "logging buffered 64000", "logging console critical", "logging host 10.20.30.40", "logging trap informational",
    "service timestamps debug datetime msec show-timezone", "logging source-interface Loopback0",
    "ntp authenticate", "ntp authentication-key 1 md5 0a1b2c", "ntp trusted-key 1", "ntp server 10.20.30.41 key 1",
    "ntp source Loopback0", "ip tftp source-interface Loopback0", "ip radius source-interface Loopback0",
    "no ip source-route",
    "ip http secure-server", "ip http max-connections 2", "ip http authentication aaa",
    "ip http timeout-policy idle 600 life 86400 requests 3",
    "ip admission auth-proxy-banner http ^Cauthorised use only^C",
    "snmp-server community s3cr3t RO 10", "snmp-server host 10.20.30.42 version 2c s3cr3t",
    "snmp-server enable traps snmp authentication linkup linkdown coldstart", "snmp-server group NMS v3 priv",
    "archive", "interface Loopback0", "interface GigabitEthernet0/0/0", "line con 0", "line aux 0",
    "line vty 0 4", "line vty 5 15",
]
VTYB = ["exec-timeout 10 0", "access-class 10 in", "login authentication default", "transport input ssh"]
GS = [
    {"header": "archive", "lines": ["log config", "logging enable"]},
    {"header": "interface Loopback0", "lines": ["ip address 10.255.255.1 255.255.255.255"]},
    {"header": "interface GigabitEthernet0/0/0", "lines": ["ip address 192.0.2.1 255.255.255.0", "no ip proxy-arp"]},
    {"header": "line con 0", "lines": ["exec-timeout 5 0"]},
    {"header": "line aux 0", "lines": ["no exec", "exec-timeout 5 0"]},
    {"header": "line vty 0 4", "lines": list(VTYB)},
    {"header": "line vty 5 15", "lines": list(VTYB)},
]
GREEN = {"ios_xe_config": {
    "lines": GL, "sections": GS,
    "banners": {"exec": "Authorised use only.", "login": "Authorised use only.", "motd": "Authorised use only."},
    "attest": {},
}}


def _idx(pat):
    return [i for i, l in enumerate(GL) if re.search(pat, l)]


def L_rm(pat):
    ix = _idx(pat)
    assert ix, pat
    return [{"op": "remove", "path": f"/ios_xe_config/lines/{i}"} for i in sorted(ix, reverse=True)]


def L_rep(pat, new):
    ix = _idx(pat)
    assert ix, pat
    return [{"op": "replace", "path": f"/ios_xe_config/lines/{ix[0]}", "value": new}]


def L_add(line):
    return [{"op": "add", "path": "/ios_xe_config/lines/-", "value": line}]


def _sec(hpat):
    ix = [i for i, s in enumerate(GS) if re.search(hpat, s["header"])]
    assert ix, hpat
    return ix


def S_rm(hpat, cpat, all_=True):
    ops = []
    for i in (_sec(hpat) if all_ else _sec(hpat)[:1]):
        for j, l in enumerate(GS[i]["lines"]):
            if re.search(cpat, l):
                ops.append({"op": "remove", "path": f"/ios_xe_config/sections/{i}/lines/{j}"})
    assert ops, (hpat, cpat)
    return sorted(ops, key=lambda o: (int(o['path'].split('/')[3]), int(o['path'].split('/')[5])), reverse=True)


def S_rep(hpat, cpat, new):
    i = _sec(hpat)[0]
    for j, l in enumerate(GS[i]["lines"]):
        if re.search(cpat, l):
            return [{"op": "replace", "path": f"/ios_xe_config/sections/{i}/lines/{j}", "value": new}]
    raise AssertionError((hpat, cpat))


def S_add(hpat, line):
    return [{"op": "add", "path": f"/ios_xe_config/sections/{_sec(hpat)[0]}/lines/-", "value": line}]


def rm(path):
    return [{"op": "remove", "path": "/ios_xe_config" + path}]


def R(x):
    return "`" + x + "`"


LN_EV = [f"is_array({P}.lines)", f"count({P}.lines) > 0"]
SEC_EV = [f"is_array({P}.sections)"]
VTY_EV = SEC_EV + ["count(_vty) > 0"]
LN, SEC = "ios_xe_config.lines", "ios_xe_config.sections"


def entry(cid, kw, own, ev, label, oks, fail, miss):
    KW[cid] = kw
    OWN[cid] = own
    C.append({"id": cid, "kind": "fact", "ev": ev, "label": label, "ok": oks, "fail": fail, "miss": miss})


def lp(cid, kw, own, pat, pat_py=None):
    """a top-level running-config line must be present"""
    entry(cid, kw, own, LN_EV, LN, [[f"_has({R(pat)})"]], L_rm(pat_py or pat), rm("/lines"))


def att(cid, kw, own, key):
    KW[cid] = kw
    OWN[cid] = own
    C.append({"id": cid, "kind": "attest", "attest": key, "attest_root": P})
    GREEN["ios_xe_config"]["attest"][key] = True

# ── section 1: management plane ───────────────────────────────────────────────────────────────
lp("1.1.1", "aaa new-model", "AAA must be turned on globally (aaa new-model)", r"^aaa new-model\s*$")
lp("1.1.2", "aaa authentication login", "a login authentication method list must be configured",
   r"^aaa authentication login\s+\S+")
lp("1.1.3", "enable default", "enable-mode authentication must use an AAA default method list",
   r"^aaa authentication enable default\s+\S+")
entry("1.1.4", "line vty", "every vty line block must set login authentication", VTY_EV, SEC,
      [["every s in _vty { _sec_has(s, " + R(r'^login authentication\s+\S+') + ") }"]],
      S_rm(r"^line vty", r"^login authentication"), rm("/sections"))
entry("1.1.5", "ip http", "when the HTTP server is on, ip http authentication must be set", LN_EV, LN,
      [["not _http_on"], ["_has(" + R(r'^ip http authentication\s+\S+') + ")"]],
      L_rm(r"^ip http authentication"), rm("/lines"))
for cid, kw, w, own in [
    ("1.1.6", "commands 15", r"commands 15", "privilege 15 command accounting must be configured"),
    ("1.1.7", "connection", r"connection", "connection accounting must be configured"),
    ("1.1.8", "exec", r"exec", "EXEC session accounting must be configured"),
    ("1.1.9", "network", r"network", "network accounting must be configured"),
    ("1.1.10", "system", r"system", "system accounting must be configured"),
]:
    lp(cid, kw, own, rf"^aaa accounting {w}\s+\S+")
entry("1.2.1", "privilege 1", "every local username must be at privilege level 1 (none above)", LN_EV, LN,
      [["every l in _user_lines { not _bad_priv(l) }"]], L_add("username ops privilege 15 secret 9 $9$zzzzzz"), rm("/lines"))
entry("1.2.2", "transport input ssh", "every vty line block must allow only ssh for transport input", VTY_EV, SEC,
      [["every s in _vty { _ssh_only(s) }"]], S_rep(r"^line vty", r"^transport input", "transport input ssh telnet"),
      rm("/sections"))
AUXEV = SEC_EV + ["count(_vty) > 0"]
entry("1.2.3", "no exec", "the aux line must have no exec (a device with no aux line passes)", AUXEV, SEC,
      [["count(_aux) == 0"], ["count(_aux) > 0", "every s in _aux { _sec_has(s, " + R(r'^no exec\s*$') + ") }"]],
      S_rm(r"^line aux", r"^no exec"), rm("/sections"))
att("1.2.4", "access-list", "an access list for the vty lines must exist and be appropriate", "vty_acl_defined")
entry("1.2.5", "access-class", "every vty line block must set an inbound access-class",
      VTY_EV, SEC, [["every s in _vty { _sec_has(s, " + R(r'^access-class\s+\S+\s+in(\s|$)') + ") }"]],
      S_rm(r"^line vty", r"^access-class"), rm("/sections"))
entry("1.2.6", "line aux 0", "the aux line exec-timeout must be 1 to 10 minutes (a device with no aux line passes)",
      AUXEV, SEC, [["count(_aux) == 0"], ["count(_aux) > 0", "every s in _aux { _exec_ok(s) }"]],
      S_rep(r"^line aux", r"^exec-timeout", "exec-timeout 0 0"), rm("/sections"))
entry("1.2.7", "line console 0", "the console line exec-timeout must be 1 to 10 minutes", SEC_EV + ["count(_con) > 0"], SEC,
      [["every s in _con { _exec_ok(s) }"]], S_rep(r"^line con", r"^exec-timeout", "exec-timeout 30 0"), rm("/sections"))
entry("1.2.8", "line vty", "every vty line block must have an exec-timeout of 1 to 10 minutes", VTY_EV, SEC,
      [["every s in _vty { _exec_ok(s) }"]], S_rep(r"^line vty", r"^exec-timeout", "exec-timeout 0 0"), rm("/sections"))
entry("1.2.9", "secure-server", "when the HTTP server is on, ip http max-connections must be 1 or 2", LN_EV, LN,
      [["not _http_on"], ["some n in _nums(" + R(r'^ip http max-connections\s+(\d+)') + ")", "is_number(n)", "n >= 1", "n <= 2"]],
      L_rep(r"^ip http max-connections", "ip http max-connections 10"), rm("/lines"))
entry("1.2.10", "ip http", "when the HTTP server is on, the ip http idle timeout must be 1 to 600 seconds", LN_EV, LN,
      [["not _http_on"], ["some n in _nums(" + R(r'^ip http timeout-policy idle\s+(\d+)') + ")", "is_number(n)", "n >= 1", "n <= 600"]],
      L_rep(r"^ip http timeout-policy", "ip http timeout-policy idle 0 life 86400 requests 3"), rm("/lines"))
BAN = [f"is_object({P}.banners)"]
for cid, kw, b in [("1.3.1", "banner exec", "exec"), ("1.3.2", "banner login", "login"), ("1.3.3", "banner motd", "motd")]:
    entry(cid, kw, f"a {b} banner with text must be configured", BAN, "ios_xe_config.banners",
          [[f"_nonblank({P}.banners.{b})"]], [{"op": "replace", "path": f"/ios_xe_config/banners/{b}", "value": " "}],
          rm("/banners"))
lp("1.3.4", "webauth banner", "a webauth (auth-proxy) banner must be configured",
   r"^ip admission auth-proxy-banner http\s+\S")
lp("1.4.1", "enable secret", "an enable secret of hash type 5, 8 or 9 must be set", r"^enable secret\s+(5|8|9)\s+\S+")
lp("1.4.2", "password-encryption", "service password-encryption must be on", r"^service password-encryption\s*$")
entry("1.4.3", "username secret", "every local user must have a type 5, 8 or 9 secret", LN_EV, LN,
      [["every l in _user_lines { _has_secret(l) }"]], L_add("username bob password 7 0822455D0A16"), rm("/lines"))
att("1.5.1", "no snmp-server", "SNMP must be off when unused", "snmp_disabled_when_unused")
entry("1.5.2", "private", "an snmp-server community named private must not exist", LN_EV, LN,
      [["not _has(" + R(r'^snmp-server community\s+private(\s|$)') + ")"]], L_add("snmp-server community private RO"), rm("/lines"))
entry("1.5.3", "public", "an snmp-server community named public must not exist", LN_EV, LN,
      [["not _has(" + R(r'^snmp-server community\s+public(\s|$)') + ")"]], L_add("snmp-server community public RO"), rm("/lines"))
entry("1.5.4", "rw", "no snmp-server community must grant RW access", LN_EV, LN,
      [["every l in _comm_lines { not _comm_rw(l) }"]], L_add("snmp-server community s3cr3t2 RW 10"), rm("/lines"))
entry("1.5.5", "acl", "every snmp-server community must carry an ACL", LN_EV, LN,
      [["every l in _comm_lines { _comm_acl(l) }"]], L_add("snmp-server community s3cr3t2 RO"), rm("/lines"))
att("1.5.6", "access-list", "an access list for SNMP must exist and be appropriate", "snmp_acl_defined")
entry("1.5.7", "snmp-server host", "when SNMP is in use, an snmp-server host must be set", LN_EV, LN,
      [["not _snmp_used"], ["_has(" + R(r'^snmp-server host\s+\S+') + ")"]], L_rm(r"^snmp-server host"), rm("/lines"))
entry("1.5.8", "traps snmp", "when SNMP is in use, snmp-server enable traps snmp must be set", LN_EV, LN,
      [["not _snmp_used"], ["_has(" + R(r'^snmp-server enable traps snmp(\s|$)') + ")"]],
      L_rm(r"^snmp-server enable traps snmp"), rm("/lines"))
entry("1.5.9", "priv", "every SNMPv3 group must use the priv security level", LN_EV, LN,
      [["every l in _matches(" + R(r'^snmp-server group\s+\S+\s+v3\s+\S+') + ") { regex.match(" + R(r'^snmp-server group\s+\S+\s+v3\s+priv(\s|$)') + ", l) }"]],
      L_add("snmp-server group OPS v3 auth"), rm("/lines"))
att("1.5.10", "aes 128", "SNMPv3 users must use at least AES-128 privacy", "snmpv3_user_aes128_minimum")

# ── section 2: control plane ──────────────────────────────────────────────────────────────────
entry("2.1.1.1.1", "hostname", "a hostname other than the factory default must be set", LN_EV, LN,
      [["some h in _cap(" + R(r'^hostname\s+(\S+)\s*$') + ")", 'not lower(h) in {"router", "switch"}']],
      L_rep(r"^hostname", "hostname Router"), rm("/lines"))
entry("2.1.1.1.2", "ip domain-name", "a global ip domain name must be set", LN_EV, LN,
      [["some d in _cap(" + R(r'^ip domain[ -]name\s+(\S+)') + ")", 'd != "vrf"']],
      L_rep(r"^ip domain name", "ip domain name vrf MGMT example.net"), rm("/lines"))
att("2.1.1.1.3", "modulus", "the RSA key modulus must be at least 2048 bits", "rsa_modulus_2048_or_more")
entry("2.1.1.1.4", "ip ssh timeout", "ip ssh time-out must be 1 to 60 seconds", LN_EV, LN,
      [["some n in _nums(" + R(r'^ip ssh time-out\s+(\d+)') + ")", "is_number(n)", "n >= 1", "n <= 60"]],
      L_rep(r"^ip ssh time-out", "ip ssh time-out 120"), rm("/lines"))
entry("2.1.1.1.5", "authentication-retries", "ip ssh authentication-retries must be at most 3 (unset is the default 3)",
      LN_EV, LN, [["every n in _nums(" + R(r'^ip ssh authentication-retries\s+(\d+)') + ") { n >= 1; n <= 3 }"]],
      L_rep(r"^ip ssh authentication-retries", "ip ssh authentication-retries 5"), rm("/lines"))
lp("2.1.1.2", "ip ssh version", "ip ssh version 2 must be set", r"^ip ssh version 2\s*$")
lp("2.1.2", "cdp", "CDP must be turned off globally (no cdp run)", r"^no cdp run\s*$")
lp("2.1.3", "bootp", "the BOOTP server must be off", r"^(no ip bootp server|ip dhcp bootp ignore)\s*$")
lp("2.1.4", "service dhcp", "the DHCP service must be off (no service dhcp)", r"^no service dhcp\s*$")
lp("2.1.5", "keepalives-in", "service tcp-keepalives-in must be on", r"^service tcp-keepalives-in\s*$")
lp("2.1.6", "keepalives-out", "service tcp-keepalives-out must be on", r"^service tcp-keepalives-out\s*$")
lp("2.1.7", "service pad", "the PAD service must be off (no service pad)", r"^no service pad\s*$")
entry("2.2.1", "logging enable", "archive configuration-change logging must be enabled", SEC_EV, SEC,
      [["some s in _secs(" + R(r'^archive\s*$') + ")", "_sec_has(s, " + R(r'^logging enable\s*$') + ")"]],
      S_rm(r"^archive", r"^logging enable"), rm("/sections"))
entry("2.2.2", "logging buffered", "logging buffered must set a size of at least 64000 bytes", LN_EV, LN,
      [["some n in _nums(" + R(r'^logging buffered\s+(\d+)') + ")", "is_number(n)", "n >= 64000"]],
      L_rep(r"^logging buffered", "logging buffered 4096"), rm("/lines"))
lp("2.2.3", "logging console", "console logging must be limited to level critical", r"^logging console critical\s*$")
lp("2.2.4", "logging host", "a syslog host must be set by IP address",
   r"^logging\s+(host\s+)?(\d{1,3}(\.\d{1,3}){3}|ipv6\s+\S+)(\s|$)")
lp("2.2.5", "logging trap", "logging trap must be at level informational", r"^logging trap\s+(informational|6)\s*$")
lp("2.2.6", "timestamps debug", "debug timestamps must carry the date and time", r"^service timestamps debug datetime(\s|$)")
lp("2.2.7", "logging source", "a logging source-interface must be set", r"^logging source-interface\s+\S+")
entry("2.2.8", "login success", "login success and failure logging must both be on", LN_EV, LN,
      [["_has(" + R(r'^login on-failure\s+log(\s|$)') + ")", "_has(" + R(r'^login on-success\s+log(\s|$)') + ")"]],
      L_rm(r"^login on-success"), rm("/lines"))
lp("2.3.1.1", "ntp authenticate", "ntp authenticate must be on", r"^ntp authenticate\s*$")
lp("2.3.1.2", "ntp authentication-key", "an ntp authentication-key must be defined", r"^ntp authentication-key\s+\d+\s+\S+\s+\S+")
lp("2.3.1.3", "trusted-key", "an ntp trusted-key must be defined", r"^ntp trusted-key\s+\d+")
entry("2.3.1.4", "ntp server", "every ntp server must name an authentication key (at least one server)", LN_EV, LN,
      [["count(_ntp_srv) > 0", "every l in _ntp_srv { regex.match(" + R(r'\skey\s+\d+(\s|$)') + ", l) }"]],
      L_rep(r"^ntp server", "ntp server 10.20.30.41"), rm("/lines"))
lp("2.3.2", "ntp server", "an ntp server must be set by IP address",
   r"^ntp server\s+(vrf\s+\S+\s+)?(\d{1,3}(\.\d{1,3}){3}|ipv6\s+\S+)(\s|$)")
entry("2.4.1", "loopback", "exactly one loopback interface must exist and carry an IP address", LN_EV + SEC_EV, "ios_xe_config.{lines,sections}",
      [["count(_matches(" + R(r'(?i)^interface\s+loopback\s*\d+\s*$') + ")) == 1",
        "some s in _secs(" + R(r'(?i)^interface\s+loopback\s*\d+\s*$') + ")",
        "_sec_has(s, " + R(r'^ip(v6)? address\s+\S+') + ")"]],
      L_add("interface Loopback1"), rm("/sections"))
entry("2.4.2", "source-interface", "AAA (radius or tacacs) must have a source-interface", LN_EV + SEC_EV, "ios_xe_config.{lines,sections}",
      [["_has(" + R(r'^ip (radius|tacacs) source-interface\s+\S+') + ")"],
       ["some s in " + P + ".sections", "_sec_has(s, " + R(r'^ip (radius|tacacs) source-interface\s+\S+') + ")"]],
      L_rm(r"^ip radius source-interface"), rm("/sections"))
lp("2.4.3", "ntp source", "ntp source must be a loopback interface", r"(?i)^ntp source\s+loopback\s*\d+\s*$", r"^ntp source")
lp("2.4.4", "tftp", "the tftp source-interface must be a loopback interface",
   r"(?i)^ip tftp source-interface\s+loopback\s*\d+\s*$", r"^ip tftp source-interface")

# ── section 3: data plane ─────────────────────────────────────────────────────────────────────
lp("3.1.1", "source-route", "IP source routing must be off (no ip source-route)", r"^no ip source-route\s*$")
entry("3.1.2", "proxy-arp", "every routed non-loopback interface must have no ip proxy-arp", SEC_EV + ["count(_l3_ifs) > 0"], SEC,
      [["every s in _l3_ifs { _sec_has(s, " + R(r'^no ip proxy-arp\s*$') + ") }"]],
      S_rm(r"^interface GigabitEthernet0/0/0", r"^no ip proxy-arp"), rm("/sections"))
entry("3.1.3", "tunnel", "tunnel interfaces must not be defined", LN_EV, LN,
      [["not _has(" + R(r'(?i)^interface\s+tunnel') + ")"]], L_add("interface Tunnel0"), rm("/lines"))
att("3.1.4", "unicast", "uRPF must be set on the appropriate interfaces", "urpf_on_untrusted_interfaces")
att("3.2.1", "access-list", "an ACL must forbid private source addresses from external networks", "private_source_acl_defined")
att("3.2.2", "access-group", "an inbound ACL must be applied on the external interface", "external_interface_acl_inbound")
for cid, kw, own, key in [
    ("3.3.1.1", "key chain", "an EIGRP key chain must be defined", "eigrp_key_chain_defined"),
    ("3.3.1.2", "key", "the EIGRP key chain must define keys", "eigrp_key_defined"),
    ("3.3.1.3", "key-string", "each EIGRP key must have a key-string", "eigrp_key_string_set"),
    ("3.3.1.4", "address-family ipv4", "the EIGRP address family must be configured", "eigrp_address_family_set"),
    ("3.3.1.5", "af-interface default", "the EIGRP af-interface default must be configured", "eigrp_af_interface_default"),
    ("3.3.1.6", "authentication key-chain", "EIGRP af-interfaces must authenticate with a key chain", "eigrp_af_key_chain"),
    ("3.3.1.7", "authentication mode md5", "EIGRP af-interfaces must use authentication mode md5", "eigrp_af_auth_md5"),
    ("3.3.1.8", "ip authentication key-chain eigrp", "EIGRP interfaces must set an authentication key-chain", "eigrp_interface_key_chain"),
    ("3.3.1.9", "ip authentication mode eigrp", "EIGRP interfaces must set an authentication mode", "eigrp_interface_auth_mode"),
    ("3.3.2.1", "message-digest", "OSPF areas must use message-digest authentication", "ospf_area_message_digest"),
    ("3.3.2.2", "message-digest-key", "OSPF interfaces must set an md5 message-digest key", "ospf_interface_md5_key"),
    ("3.3.3.1", "neighbor password", "BGP neighbors must have a password", "bgp_neighbor_password"),
]:
    att(cid, kw, own, key)

# ── abort on any mismatch with the workbook ───────────────────────────────────────────────────
N_AUTO = sum(1 for w in WB.values() if w["assessment"] == "Automated")
ids = [c["id"] for c in C]
assert len(ids) == len(set(ids)) == len(WB) == N_TOTAL, (len(ids), len(WB), sorted(set(WB) - set(ids)), sorted(set(ids) - set(WB)))
assert set(ids) == set(WB) == set(OWN) == set(KW), (sorted(set(WB) ^ set(ids)), sorted(set(WB) ^ set(OWN)))
assert sum(1 for w in WB.values() if w["level"] == 1) == N_L1 and sum(1 for w in WB.values() if w["level"] == 2) == N_L2
EXPECT_AUTO = 51
assert N_AUTO == EXPECT_AUTO, N_AUTO
for cid in ids:
    assert WB[cid]["assessment"] in ("Automated", "Manual"), cid
    assert len(WB[cid]["profiles"]) == 1, (cid, WB[cid]["profiles"])
    assert KW[cid].lower() in WB[cid]["title"].lower(), (cid, KW[cid])
AUTO_ATTESTED = {c["id"] for c in C if c["kind"] == "attest" and WB[c["id"]]["assessment"] == "Automated"}
assert not AUTO_ATTESTED, AUTO_ATTESTED
for cid in ids:  # our wording replaces the workbook title from here on
    if neutralize_title(OWN[cid]) != OWN[cid]: print("NEUT", cid, "|", OWN[cid], "|", neutralize_title(OWN[cid]))
    WB[cid]["title"] = OWN[cid]

SECTION_OF = {"1": "management_plane", "2": "control_plane", "3": "data_plane"}
SECTIONS = list(SECTION_OF.values())
STITLE = {"management_plane": "1 Management plane", "control_plane": "2 Control plane", "data_plane": "3 Data plane"}


def section(cid):
    return SECTION_OF[cid.split(".")[0]]


attest_ids = [c["id"] for c in C if c["kind"] == "attest"]
manual_fact = [c["id"] for c in C if c["kind"] == "fact" and WB[c["id"]]["assessment"] == "Manual"]

# ── Rego helpers ──────────────────────────────────────────────────────────────────────────────
HELPERS = "# ── helpers ──────────────────────────────────────────────────────────────────\n" + LEVEL_HELPERS + r'''
# Top-level running-config lines never start with whitespace and a comment starts with "!", so every pattern is
# anchored at ^ on a command word and cannot hit a commented line, an indented child line or a longer command
# (no aaa new-model does not match ^aaa new-model).
_matches(re) := [l | some l in input.ios_xe_config.lines; is_string(l); regex.match(re, l)]

_has(re) if count(_matches(re)) > 0

# first capture group of every matching top-level line
_cap(re) := [m[0][1] |
	some l in input.ios_xe_config.lines
	is_string(l)
	m := regex.find_all_string_submatch_n(re, l, 1)
	count(m) > 0
]

_nums(re) := [to_number(c) | some c in _cap(re)]

_secs(re) := [s | some s in input.ios_xe_config.sections; is_string(s.header); regex.match(re, s.header)]

_sec_has(s, re) if {
	some l in s.lines
	is_string(l)
	regex.match(re, l)
}

_sec_lines(s, re) := [l | some l in s.lines; is_string(l); regex.match(re, l)]

_nonblank(v) if {
	is_string(v)
	trim_space(v) != ""
}

# ── line sections ──
_vty := _secs(`^line vty(\s|$)`)

_aux := _secs(`^line aux\s+0\s*$`)

_con := _secs(`^line con\s+0\s*$`)

_ssh_only(s) if {
	ls := _sec_lines(s, `^transport input(\s|$)`)
	count(ls) > 0
	every l in ls { regex.match(`^transport input\s+ssh\s*$`, l) }
}

# exec-timeout minutes [seconds]: 1 to 600 seconds in total; "0 0" is never-time-out and fails
_timeout_secs(g) := (to_number(g[1]) * 60) + to_number(g[2]) if g[2] != ""

_timeout_secs(g) := to_number(g[1]) * 60 if g[2] == ""

_exec_ok(s) if {
	some l in s.lines
	is_string(l)
	m := regex.find_all_string_submatch_n(`^exec-timeout\s+(\d+)(?:\s+(\d+))?\s*$`, l, 1)
	count(m) > 0
	t := _timeout_secs(m[0])
	t > 0
	t <= 600
}

# ── HTTP server ──
_http_on if _has(`^ip http (secure-)?server\s*$`)

# ── local users ──
_user_lines := _matches(`^username\s+\S+`)

_bad_priv(l) if {
	m := regex.find_all_string_submatch_n(`\sprivilege\s+(\d+)`, l, 1)
	count(m) > 0
	m[0][1] != "1"
}

_has_secret(l) if regex.match(`\ssecret\s+(5|8|9)\s+\S+`, l)

# ── SNMP ──
_snmp_used if _has(`^snmp-server (community|group|user)\s`)

_comm_lines := _matches(`^snmp-server community\s+\S+`)

# arguments after the community string and an optional "view <name>"
_comm_rest(l) := array.slice(t, 3, count(t)) if t := regex.split(`\s+`, trim_space(l))

_comm_args(l) := [] if count(_comm_rest(l)) == 0

_comm_args(l) := r if {
	r := _comm_rest(l)
	count(r) > 0
	lower(r[0]) != "view"
}

_comm_args(l) := array.slice(r, 2, count(r)) if {
	r := _comm_rest(l)
	count(r) > 0
	lower(r[0]) == "view"
}

_comm_rw(l) if {
	a := _comm_args(l)
	count(a) > 0
	lower(a[0]) == "rw"
}

# an ACL follows the access mode, or is the first argument when the mode is left out
_comm_acl(l) if {
	a := _comm_args(l)
	count(a) >= 2
	lower(a[0]) in {"ro", "rw"}
}

_comm_acl(l) if {
	a := _comm_args(l)
	count(a) >= 1
	not lower(a[0]) in {"ro", "rw", "ipv6"}
}

# ── NTP / interfaces ──
_ntp_srv := _matches(`^ntp server\s+\S+`)

_l3_ifs := [s |
	some s in input.ios_xe_config.sections
	is_string(s.header)
	regex.match(`^interface\s+\S+`, s.header)
	not regex.match(`(?i)^interface\s+loopback`, s.header)
	_sec_has(s, `^ip address\s+\d`)
]

'''

# ── emission: roll-up module ──────────────────────────────────────────────────────────────────
NL = "\n"
META = '''# METADATA
# title: "{title}"
# custom:
#   class: security
#   framework: cis_network_devices
#   source: cis
#   domains: [network, cisco]
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

SECLIST = NL.join(f"\t\t{s}_violations," for s in SECTIONS)
HEADER = META.format(title=BENCH, checks=N_TOTAL, density="sized", basis="size", entry="compliance_report") + f'''package {PKG}

# {BENCH}
# Generated from the CIS workbook by tools/cis_generators/gen_cisco_ios_xe_17.py. This module is new: the older
# hand-written Cisco modules (cis_cisco_ios, cis.network.cisco) are generic IOS and do not claim IOS XE.
# {N_TOTAL} recommendations ({N_AUTO} Automated, {N_TOTAL - N_AUTO} Manual; {N_L1} Level 1, {N_L2} Level 2), every one in the
# benchmark; ids, levels and assessment status read from the workbook. Messages use our own wording, not CIS text.
# Profile: input.cis_profile.level, the number 1 or 2 (Level 2 includes Level 1); absent => 2; any other value (the
# string "2", 3, null) is invalid evidence, reported as such, with the report scoped at Level 2 and the Level 2
# recommendations failed. total_controls counts the recommendations in the selected profile.
# Automated checks fail closed: facts not collected => "<id>: evidence missing — <field> not collected".
# Manual recommendations with a decidable configuration fact are checked like Automated ones:
#   {", ".join(manual_fact)}.
# Attestation booleans under input.ios_xe_config.attest (false or absent => violation): {", ".join(attest_ids)}.
#
# Input contract (input.ios_xe_config), the parsed running configuration of `show running-config all`
# (cisco.ios facts ansible_net_config, split by the collector):
#   lines     : array of strings, every top-level (unindented) line verbatim, section headers included
#               ("line vty 0 4", "interface Loopback0"); comment lines ("!") may be present and are ignored
#   sections  : array of {{header, lines[]}}, one per top-level line that has an indented body; lines[] are the
#               body lines with the indentation removed (nested blocks flattened)
#   banners   : {{exec, login, motd}} the banner texts without delimiters (banner bodies are not top-level lines)
#   attest.*  : attestation booleans for the judgement recommendations
# The "all" form matters: exec-timeout, ip ssh time-out and "no exec" only show up there when left at default.
# Absent lines/sections/banners are evidence missing, never a pass.

import rego.v1

# Main compliance rule - every recommendation in the selected profile must pass; no facts, no compliance
default compliant := false

compliant if {{
	input.ios_xe_config
	count(violations) == 0
}}

# Aggregate all violations across sections
violations := [v |
	arrays := [
{SECLIST}
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
os.makedirs(f"{OUT}/tests", exist_ok=True)
open(f"{OUT}/{PKG}.rego", "w").write("\n".join(parts))
# ── emission: .main bridge ────────────────────────────────────────────────────────
MAIN = META.format(title=f"{BENCH} - compliance_report entrypoint", checks=0, density="orchestrator", basis="role",
                   entry="compliance_report") + f'''package {PKG}.main

# OPA query path: /v1/data/{PKG}/main/compliance_report
# Thin bridge over data.{PKG} (generated by tools/cis_generators/gen_cisco_ios_xe_17.py). That package already fails
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
	"version": "v2.2.2",
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

# Generated per-recommendation tests for {BENCH} (tools/cis_generators/gen_cisco_ios_xe_17.py): every recommendation
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

# cis_profile.level must be the number 1 or 2: anything else is reported, the report is scoped at Level 2 and
# the Level 2 recommendations fail, so a mistyped level can never shrink the assessment into a pass
test_level_must_be_the_number_1_or_2 if {{
	every lv in ["1", "2", "high", 0, 3, 1.5, true, false, null, [1], {{"level": 1}}] {{
		r := b.compliance_report with input as json.patch(green, [{{"op": "add", "path": "/cis_profile", "value": {{"level": lv}}}}])
		r.compliant == false
		r.level == 2
		r.total_controls == {N_TOTAL}
		r.failed_controls == {N_L2}
		r.passed_controls + r.failed_controls == r.total_controls
		some v in r.violations
		startswith(v, "cis_profile.level: evidence invalid — cis_profile.level must be the number 1 or 2, got ")
	}}
	every cp in ["1", 1, null, [1], true] {{
		r := b.compliance_report with input as json.patch(green, [{{"op": "add", "path": "/cis_profile", "value": cp}}])
		r.compliant == false
		r.failed_controls == {N_L2}
	}}
}}

test_level_numbers_and_absent_level_are_valid if {{
	l2 := b.compliance_report with input as json.patch(green, [{{"op": "add", "path": "/cis_profile", "value": {{"level": 2}}}}])
	l2.compliant == true
	l2.total_controls == {N_TOTAL}
	none := b.compliance_report with input as json.patch(green, [{{"op": "add", "path": "/cis_profile", "value": {{}}}}])
	none.compliant == true
	none.total_controls == {N_TOTAL}
}}

test_level_2_only_recommendation_skipped_at_level_1 if {{
	inp := json.patch(green, [
		{{"op": "add", "path": "/cis_profile", "value": {{"level": 1}}}},
		{{"op": "replace", "path": "/ios_xe_config/sections/2/lines/1", "value": "ip proxy-arp"}},
	])
	vs := b.violations with input as inp
	not _has_id(vs, "3.1.2")
}}

{emit_tests(PKG, C, WB, GREEN, "/ios_xe_config/attest")}'''
open(f"{OUT}/tests/test_{PKG}_recommendations.rego", "w").write(tests)
print("ok", len(C), sec_tot, "attested", len(attest_ids), "manual-as-fact", len(manual_fact))
