"""CIS VMware ESXi 8.0 v1.4.0 and ESXi 9.0 v1.0.0 -> benchmarks/cis/vmware/esxi and benchmarks/cis/vmware/esxi_9.

    python3 tools/cis_generators/dump_workbook.py <workbook.xlsx> /tmp/esxi8.json
    python3 tools/cis_generators/gen_esxi.py 8 /tmp/esxi8.json benchmarks/cis/vmware/esxi
    python3 tools/cis_generators/dump_workbook.py <workbook9.xlsx> /tmp/esxi9.json
    python3 tools/cis_generators/gen_esxi.py 9 /tmp/esxi9.json benchmarks/cis/vmware/esxi_9
    opa fmt -w benchmarks/cis/vmware/esxi benchmarks/cis/vmware/esxi_9

One logic table serves both releases: the two workbooks list the same 134 recommendations with the same
ids, status and profiles and the same audit procedures, so only the key, package and benchmark label differ
(VARIANTS below). Each logic entry carries a keyword that must occur in the workbook title of its id; the run
aborts on any count, id, status, profile or keyword mismatch. Titles are replaced by our own wording (OWN)
before anything is written. Writes only the files it owns (roll-up, .main bridge, generated tests, README).
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cis_genlib import load_workbook_json, emit_control, emit_tests, table  # noqa: E402
from neutralize import neutralize_title  # noqa: E402

VARIANT = sys.argv[1]
WB = load_workbook_json(sys.argv[2])
OUT = sys.argv[3]
VARIANTS = {
    "8": {"bench": "CIS VMware ESXi 8.0 Benchmark v1.4.0", "pkg": "cis_vmware_esxi", "ver": "v1.4.0", "esxi": "8.0"},
    "9": {"bench": "CIS VMware ESXi 9.0 Benchmark v1.0.0", "pkg": "cis_vmware_esxi_9", "ver": "v1.0.0", "esxi": "9.0"},
}
V = VARIANTS[VARIANT]
BENCH, PKG = V["bench"], V["pkg"]
P = "input.esxi"
N_TOTAL, N_AUTO, N_L1, N_L2 = 134, 38, 116, 18

KW = {}
C = []
OWN = {}


def add(path, value):
    return [{"op": "add", "path": "/esxi" + path, "value": value}]


def rm(path):
    return [{"op": "remove", "path": "/esxi" + path}]


def fact(cid, kw, ev, label, ok, fail, miss, ok2=None):
    KW[cid] = kw
    C.append({"id": cid, "kind": "fact", "ev": ev, "label": "esxi." + label, "ok": [ok] + ([ok2] if ok2 else []),
              "fail": fail, "miss": miss})


def att(cid, kw, key):
    KW[cid] = kw
    C.append({"id": cid, "kind": "attest", "attest": key, "attest_root": P})


def adv(cid, kw, name, ok, bad):
    """Host advanced setting `name` (input.esxi.advanced_settings[name]); ok lines may use the value `v`."""
    fact(cid, kw, [f'_has_adv("{name}")'], f"advanced_settings.{name}", [f'v := _adv("{name}")'] + ok,
         add(f"/advanced_settings/{name}", bad), rm(f"/advanced_settings/{name}"))


def advn(cid, kw, name, cond, bad):
    adv(cid, kw, name, ["n := _num(v)"] + cond, bad)


VMEV = ["_vm_adv_ev"]


def vadv(cid, kw, ok_expr, key, bad):
    """Every VM must satisfy ok_expr (uses `vm`); fail patch writes `bad` to VM 1's setting `key`."""
    fact(cid, kw, VMEV, "vms[].advanced_settings", [f"every vm in {P}.vms {{ {ok_expr} }}"],
         add(f"/vms/1/advanced_settings/{key}", bad), rm("/vms"))


def vtrue(cid, kw, key):
    vadv(cid, kw, f'_vtrue(vm, "{key}")', key, "FALSE")


def vtrue_or_absent(cid, kw, key):
    vadv(cid, kw, f'_vtrue_or_absent(vm, "{key}")', key, "FALSE")


def vclear(cid, kw, regex, key):
    vadv(cid, kw, f'not _vkey_bad(vm, "{regex}")', key, "TRUE")


def vtools(cid, kw, key, cond, bad):
    fact(cid, kw, [f"is_array({P}.vms)", f'every vm in {P}.vms {{ vm.tools_config["{key}"] != null }}'],
         "vms[].tools_config", [f'every vm in {P}.vms {{ {cond} }}'],
         add(f"/vms/1/tools_config/{key}", bad), rm("/vms"))


def sshd(cid, kw, key, val):
    fact(cid, kw, [f'_has_sshd("{key}")'], f"sshd_config.{key}", [f'_sshd("{key}") == "{val}"'],
         add(f"/sshd_config/{key}", "yes" if val == "no" else "no"), rm("/sshd_config"))


def svc_off(cid, kw, svc):
    fact(cid, kw, [f'is_object({P}.services["{svc}"])'], f"services.{svc}",
         [f'{P}.services["{svc}"].running == false', f'lower({P}.services["{svc}"].policy) == "off"'],
         add(f"/services/{svc}/running", True), rm("/services"))

# Our own short wording for every recommendation (no CIS title text); replaces the workbook title after the
# keyword check, so messages, tests and the recommendations table all carry it.
OWN.update({
    "1.1": "firmware on the system and its devices must be inventoried against a supported baseline",
    "1.2": "UEFI Secure Boot must be on in the host firmware",
    "1.3": "Intel TXT must be on where the CPU supports it",
    "1.4": "a TPM 2.0 must be present and configured",
    "1.5": "the baseboard management controller must be hardened",
    "1.6": "the management controller clock must be synchronized",
    "1.7": "the management controller must forward its events to a remote collector",
    "1.8": "management controller logins must be individual, strong and locked down",
    "1.9": "AMD SEV-ES must be on where the CPU supports it",
    "1.10": "Intel SGX must be on where the CPU supports it",
    "1.11": "unused external hardware ports must be secured",
    "1.12": "Net.BMCNetworkEnable must be 0 so the controller has no internal network path",
    "2.1": "the ESXi release must still be in general support",
    "2.2": "all available patches must be installed",
    "2.3": "the host must refuse to run with Secure Boot enforcement off",
    "2.4": "the image profile acceptance level must be PartnerSupported or stricter",
    "2.5": "the host must run only binaries from installed signed VIBs",
    "2.6": "NTP must run on the host with at least one server configured",
    "2.7": "a time service must be enabled, configured and running",
    "2.8": "configuration encryption must be anchored in the TPM",
    "2.9": "UserVars.SuppressHyperthreadWarning must be 0",
    "2.10": "Mem.ShareForceSalting must be 2 to stop inter-VM page sharing",
    "2.11": "the disableHwrng kernel option must not be TRUE",
    "2.12": "Mem.MemEagerZero must be 1 so freed memory is zeroed",
    "3.1": "the SSH service must be stopped and set to start manually",
    "3.2": "the ESXi shell service must be stopped and set to start manually",
    "3.3": "Config.HostAgent.plugins.solo.enableMob must be false",
    "3.4": "the SLP service must not be running",
    "3.5": "CIM/WBEM must be off",
    "3.6": "SNMP must be off unless needed",
    "3.7": "UserVars.DcuiTimeOut must be 1 to 600 seconds",
    "3.8": "UserVars.ESXiShellInteractiveTimeOut must be 1 to 300 seconds",
    "3.9": "UserVars.ESXiShellTimeOut must be 1 to 3600 seconds",
    "3.10": "UserVars.SuppressShellWarning must be 0",
    "3.11": "Security.PasswordQualityControl must demand 15 or more characters from four classes",
    "3.12": "Security.AccountLockFailures must be 5",
    "3.13": "Security.AccountUnlockTime must be 900",
    "3.14": "Security.PasswordHistory must be 5",
    "3.15": "Security.PasswordMaxDays must match the approved rotation policy",
    "3.16": "the API session timeout must be a finite approved value",
    "3.17": "UserVars.HostClientSessionTimeout must be a finite positive value",
    "3.18": "DCUI.Access must list only the approved override users",
    "3.19": "the lockdown Exception Users list must be reviewed and accurate",
    "3.20": "lockdown mode must be normal or strict",
    "3.21": "lockdown mode must be strict",
    "3.22": "the dcui account must have a non-interactive shell",
    "3.23": "the vpxuser account must have a non-interactive shell",
    "3.24": "the DCUI and Host Client welcome banner must carry the approved text",
    "3.25": "the SSH banner file must carry the approved text",
    "3.26": "legacy TLS versions must be off and the highest supported version on",
    "4.1": "system logs must be written to a persistent location",
    "4.2": "Syslog.global.logHost must name a remote collector",
    "4.3": "logging detail and local log files must be reviewed as sufficient",
    "4.4": "the syslog log level must be info",
    "4.5": "syslog log filtering must be off",
    "4.6": "audit record storage must be active",
    "4.7": "audit records must be stored in a persistent location",
    "4.8": "local audit storage must hold at least seven days",
    "4.9": "audit records must be sent to a remote collector",
    "4.10": "remote syslog over TLS must check the endpoint certificate",
    "4.11": "remote syslog over TLS must use strict x509 checks",
    "5.1": "an enabled firewall ruleset must not allow all IP addresses",
    "5.2": "the host firewall must be on and drop by default",
    "5.3": "Net.DVFilterBindIpAddress must be empty",
    "5.4": "Net.BlockGuestBPDU must be 1",
    "5.5": "VMkernel interfaces for virtual hardware management must be absent",
    "5.6": "standard switches and port groups must reject forged transmits",
    "5.7": "standard switches and port groups must reject MAC address changes",
    "5.8": "standard switches and port groups must reject promiscuous mode",
    "5.9": "a standard port group must not use the native VLAN",
    "5.10": "a standard port group must not use VLAN 4095",
    "5.11": "management traffic must stay on dedicated VMkernel interfaces and VLANs",
    "6.1.1": "CIM access, if used, must go through a least-privilege account",
    "6.2.1": "storage traffic must be isolated from other networks",
    "6.2.2": "datastore names must be unique",
    "6.3.1": "iSCSI adapters must use mutual CHAP",
    "6.3.2": "iSCSI CHAP secrets must be unique per adapter",
    "6.4.1": "SNMP, if used, must restrict who can poll",
    "6.5.1": "sshd ciphers must be limited to approved FIPS-validated ones",
    "6.5.2": "sshd must run on the platform FIPS-validated crypto modules",
    "6.5.3": "sshd GatewayPorts must be no",
    "6.5.4": "sshd HostbasedAuthentication must be no",
    "6.5.5": "sshd ClientAliveCountMax must be a positive value",
    "6.5.6": "sshd ClientAliveInterval must be a positive value",
    "6.5.7": "sshd must show a banner before login",
    "6.5.8": "sshd IgnoreRhosts must be yes",
    "6.5.9": "sshd AllowStreamLocalForwarding must be no",
    "6.5.10": "sshd AllowTcpForwarding must be no",
    "6.5.11": "sshd PermitTunnel must be no",
    "6.5.12": "sshd PermitUserEnvironment must be no",
    "7.1": "every VM must boot with EFI Secure Boot",
    "7.2": "every VM must require encrypted vMotion",
    "7.3": "every VM must require encrypted Fault Tolerance traffic",
    "7.4": "mks.enable3d must not be on for VMs",
    "7.5": "tools.guest.desktop.autolock must be TRUE",
    "7.6": "RemoteDisplay.maxConnections must be 1",
    "7.7": "a VM must not have a pciPassthru device present",
    "7.8": "isolation.device.edit.disable must be TRUE",
    "7.9": "isolation.device.connectable.disable must be TRUE",
    "7.10": "VMs must have no sound device",
    "7.11": "VMs must have no AHCI controller that backs nothing needed",
    "7.12": "VMs must have no USB or XHCI controller",
    "7.13": "VMs must have no serial port",
    "7.14": "VMs must have no parallel port",
    "7.15": "VMs must have no CD/DVD drive",
    "7.16": "VMs must have no floppy drive",
    "7.17": "isolation.tools.dnd.disable must be TRUE or absent",
    "7.18": "isolation.tools.copy.disable must be TRUE or absent",
    "7.19": "isolation.tools.paste.disable must be TRUE or absent",
    "7.20": "VMs must not be bound to a dvfilter",
    "7.21": "isolation.tools.diskShrink.disable must be TRUE",
    "7.22": "isolation.tools.diskWiper.disable must be TRUE",
    "7.23": "two VMs must not share a sched.mem.pshare.salt value",
    "7.24": "tools.guestlib.enableHostInfo must be FALSE",
    "7.25": "VM logging must be TRUE or left at its default",
    "7.26": "log.keepOld must be 10",
    "7.27": "log.rotateSize must be 1024000",
    "7.28": "tools.setInfo.sizeLimit must be a finite approved value",
    "7.29": "VM hardware version must be 19 or newer",
    "8.1": "VMware Tools must be a release still in general support",
    "8.2": "VMware Tools must carry all security updates",
    "8.3": "the Tools upgrade policy must match the approved change model",
    "8.4": "deployed VMs must not be re-customizable through Tools",
    "8.5": "Tools must not add features automatically",
    "8.6": "Tools must not remove features automatically",
    "8.7": "Tools globalconf must be off",
    "8.8": "Tools containerinfo poll-interval must be 0",
    "8.9": "Tools appinfo must be disabled",
    "8.10": "Tools gueststoreupgrade policy must be off",
    "8.11": "Tools servicediscovery must be disabled",
    "8.12": "Tools must not allow MSI transforms on upgrade",
    "8.13": "Tools logging must be on",
    "8.14": "Tools logs must go to the guest system logger",
    "8.15": "Tools guestoperations must be disabled",
})

# ── section 1: hardware ──────────────────────────────────────────────────────────
att("1.1", "firmware", "hardware_firmware_inventoried")
fact("1.2", "secure boot", [f"is_boolean({P}.secure_boot.enabled)"], "secure_boot.enabled", [f"{P}.secure_boot.enabled == true"],
     add("/secure_boot/enabled", False), rm("/secure_boot"))
att("1.3", "intel txt", "intel_txt_enabled_where_supported")
att("1.4", "tpm 2.0", "tpm_2_0_configured")
att("1.5", "management controller", "bmc_hardened")
att("1.6", "time synchronization", "bmc_time_synchronized")
att("1.7", "remote logging", "bmc_remote_logging")
att("1.8", "secure authentication", "bmc_authentication_secure")
att("1.9", "amd sev-es", "amd_sev_es_enabled_where_supported")
att("1.10", "intel sgx", "intel_sgx_enabled_where_supported")
att("1.11", "unused external hardware ports", "unused_ports_secured")
advn("1.12", "internal networking", "Net.BMCNetworkEnable", ["n == 0"], 1)

# ── section 2: software and boot ─────────────────────────────────────────────────
att("2.1", "general support", "esxi_release_in_general_support")
att("2.2", "updates installed", "esxi_patches_current")
fact("2.3", "secure boot enforcement", [f"is_boolean({P}.encryption.require_secure_boot)"], "encryption.require_secure_boot",
     [f"{P}.encryption.require_secure_boot == true"], add("/encryption/require_secure_boot", False), rm("/encryption"))
fact("2.4", "acceptance level", [f"is_string({P}.software.acceptance_level)"], "software.acceptance_level",
     [f'lower({P}.software.acceptance_level) in {{"vmwarecertified", "vmwareaccepted", "partnersupported"}}'],
     add("/software/acceptance_level", "CommunitySupported"), rm("/software"))
fact("2.5", "signed vib", [f"is_object({P}.kernel_settings)", f"{P}.kernel_settings.execInstalledOnly != null"],
     "kernel_settings.execInstalledOnly", [f"_istrue({P}.kernel_settings.execInstalledOnly)"],
     add("/kernel_settings/execInstalledOnly", "FALSE"), rm("/kernel_settings"))
NTP_EV = [f'is_object({P}.services.ntpd)', f"is_array({P}.ntp.servers)"]
NTP_OK = [f"{P}.services.ntpd.running == true", f'lower({P}.services.ntpd.policy) in {{"on", "automatic"}}',
          f"count({P}.ntp.servers) > 0"]
fact("2.6", "time synchronization", NTP_EV, "{services.ntpd,ntp.servers}", NTP_OK, add("/services/ntpd/running", False), rm("/ntp"))
fact("2.7", "time synchronization services", NTP_EV, "{services.ntpd,ntp.servers}", NTP_OK,
     add("/services/ntpd/policy", "off"), rm("/services"))
fact("2.8", "tpm-based", [f"is_string({P}.encryption.mode)"], "encryption.mode", [f'lower({P}.encryption.mode) == "tpm"'],
     add("/encryption/mode", "NONE"), rm("/encryption"))
advn("2.9", "hyperthreading", "UserVars.SuppressHyperthreadWarning", ["n == 0"], 1)
advn("2.10", "transparent page sharing", "Mem.ShareForceSalting", ["n == 2"], 1)
fact("2.11", "entropy", [f"is_object({P}.kernel_settings)"], "kernel_settings", [f"not _istrue({P}.kernel_settings.disableHwrng)"],
     add("/kernel_settings/disableHwrng", "TRUE"), rm("/kernel_settings"))
advn("2.12", "volatile key", "Mem.MemEagerZero", ["n == 1"], 0)

# ── section 3: access and shell ──────────────────────────────────────────────────
svc_off("3.1", "ssh", "TSM-SSH")
svc_off("3.2", "esxi shell", "TSM")
adv("3.3", "managed object browser", "Config.HostAgent.plugins.solo.enableMob", ["_isfalse(v)"], "true")
fact("3.4", "slp", [f"is_object({P}.services)"], "services", [f'not {P}.services["slpd"]'], add("/services/slpd/running", True),
     rm("/services"), ok2=[f'{P}.services["slpd"].running == false'])
fact("3.5", "cim", [f"is_boolean({P}.wbem.enabled)"], "wbem.enabled", [f"{P}.wbem.enabled == false"], add("/wbem/enabled", True), rm("/wbem"))
fact("3.6", "snmp", [f"is_boolean({P}.snmp.enabled)"], "snmp.enabled", [f"{P}.snmp.enabled == false"], add("/snmp/enabled", True), rm("/snmp"))
advn("3.7", "dcui sessions", "UserVars.DcuiTimeOut", ["n > 0", "n <= 600"], 0)
advn("3.8", "idle shells", "UserVars.ESXiShellInteractiveTimeOut", ["n > 0", "n <= 300"], 0)
advn("3.9", "deactivate shell services", "UserVars.ESXiShellTimeOut", ["n > 0", "n <= 3600"], 7200)
advn("3.10", "warnings that the shell", "UserVars.SuppressShellWarning", ["n == 0"], 1)
fact("3.11", "password complexity", ["is_string(_adv(\"Security.PasswordQualityControl\"))"], "advanced_settings.Security.PasswordQualityControl",
     ["_pwq_ok"], add("/advanced_settings/Security.PasswordQualityControl", "retry=3 min=disabled,disabled,disabled,disabled,8"),
     rm("/advanced_settings/Security.PasswordQualityControl"))
advn("3.12", "failed login attempts", "Security.AccountLockFailures", ["n == 5"], 10)
advn("3.13", "unlock accounts", "Security.AccountUnlockTime", ["n == 900"], 60)
advn("3.14", "password history", "Security.PasswordHistory", ["n == 5"], 1)
att("3.15", "maximum password age", "password_max_days_approved")
advn("3.16", "session timeout for the api", "Config.HostAgent.vmacore.soap.sessionTimeout", ["n > 0"], 0)
advn("3.17", "idle host client sessions", "UserVars.HostClientSessionTimeout", ["n > 0"], 0)
att("3.18", "dcui.access", "dcui_access_list_accurate")
att("3.19", "exception users", "lockdown_exception_users_accurate")
fact("3.20", "enable lockdown mode", ["is_string(" + P + ".lockdown_mode)"], "lockdown_mode", ['_lockdown in {"normal", "strict"}'],
     add("/lockdown_mode", "disabled"), rm("/lockdown_mode"))
fact("3.21", "strict lockdown mode", ["is_string(" + P + ".lockdown_mode)"], "lockdown_mode", ['_lockdown == "strict"'],
     add("/lockdown_mode", "normal"), rm("/lockdown_mode"))
SHELL_OK = '{"/bin/false", "/sbin/nologin", "/usr/sbin/nologin", "/bin/nologin"}'
for cid, kw, acct in [("3.22", "dcui account", "dcui"), ("3.23", "vpxuser account", "vpxuser")]:
    fact(cid, kw, [f"is_string({P}.passwd.{acct}.shell)"], f"passwd.{acct}.shell", [f"lower({P}.passwd.{acct}.shell) in {SHELL_OK}"],
         add(f"/passwd/{acct}/shell", "/bin/sh"), rm("/passwd"))
att("3.24", "login banner for the dcui", "dcui_host_client_banner_approved")
att("3.25", "login banner for ssh", "ssh_banner_file_approved")
att("3.26", "version of tls", "tls_highest_version_only")

# ── section 4: logging ───────────────────────────────────────────────────────────
SL, AR = f"{P}.syslog", f"{P}.audit_records"
att("4.1", "persistent log location for all locally stored system logs", "system_log_location_persistent")
LOGHOST = '_nonempty(_adv("Syslog.global.logHost"))'
fact("4.2", "remote log collector", ['_has_adv("Syslog.global.logHost")'], "advanced_settings.Syslog.global.logHost", [LOGHOST],
     add("/advanced_settings/Syslog.global.logHost", ""), rm("/advanced_settings/Syslog.global.logHost"))
att("4.3", "sufficient information", "log_detail_sufficient")
fact("4.4", "informational level", [f"is_string({SL}.log_level)"], "syslog.log_level", [f'lower({SL}.log_level) == "info"'],
     add("/syslog/log_level", "warning"), rm("/syslog"))
fact("4.5", "log filtering", [f"is_boolean({SL}.log_filtering_enabled)"], "syslog.log_filtering_enabled",
     [f"{SL}.log_filtering_enabled == false"], add("/syslog/log_filtering_enabled", True), rm("/syslog"))
fact("4.6", "audit record logging", [f"is_boolean({AR}.storage_active)"], "audit_records.storage_active",
     [f"{AR}.storage_active == true"], add("/audit_records/storage_active", False), rm("/audit_records"))
att("4.7", "persistent log location for all locally stored audit", "audit_record_location_persistent")
att("4.8", "one week of audit", "audit_storage_seven_days")
fact("4.9", "audit records to a remote", ['_has_adv("Syslog.global.logHost")', f"is_boolean({AR}.remote_host_enabled)"],
     "{advanced_settings.Syslog.global.logHost,audit_records.remote_host_enabled}", [LOGHOST, f"{AR}.remote_host_enabled == true"],
     add("/audit_records/remote_host_enabled", False), rm("/audit_records"))
fact("4.10", "verify certificates", [f"is_boolean({SL}.check_ssl_certs)"], "syslog.check_ssl_certs", [f"{SL}.check_ssl_certs == true"],
     add("/syslog/check_ssl_certs", False), rm("/syslog"))
fact("4.11", "strict x509", [f"is_boolean({SL}.strict_x509_compliance)"], "syslog.strict_x509_compliance",
     [f"{SL}.strict_x509_compliance == true"], add("/syslog/strict_x509_compliance", False), rm("/syslog"))

# ── section 5: host networking ───────────────────────────────────────────────────
FW = f"{P}.firewall"
fact("5.1", "authorized networks", [f"is_array({FW}.rulesets)"], "firewall.rulesets", [f"count([1 | some r in {FW}.rulesets; _ruleset_open(r)]) == 0"],
     add("/firewall/rulesets/1/allowed_ip_all", True), rm("/firewall"))
fact("5.2", "block network traffic by default", [f"is_boolean({FW}.enabled)", f"is_string({FW}.default_action)"],
     "firewall.{enabled,default_action}", [f"{FW}.enabled == true", f'lower({FW}.default_action) == "drop"'],
     add("/firewall/default_action", "PASS"), rm("/firewall"))
adv("5.3", "dvfilter", "Net.DVFilterBindIpAddress", ['v == ""'], "10.0.0.5")
advn("5.4", "bridge protocol data unit", "Net.BlockGuestBPDU", ["n == 1"], 0)
att("5.5", "virtual hardware management", "virtual_hardware_mgmt_interfaces_absent")
VS = f"{P}.vswitches"
for cid, kw, key in [("5.6", "forged transmits", "forged_transmits"), ("5.7", "mac address changes", "mac_changes"),
                     ("5.8", "promiscuous mode", "promiscuous_mode")]:
    fact(cid, kw, [f"is_array({VS})", f"every sw in {VS} {{ is_boolean(sw.security.{key}) }}"], "vswitches[].security",
         [f"every sw in {VS} {{ sw.security.{key} == false; count([1 | some pg in object.get(sw, \"portgroups\", []); pg.security.{key} == true]) == 0 }}"],
         add(f"/vswitches/0/security/{key}", True), rm("/vswitches"))
PGEV = [f"is_array({VS})", f"every sw in {VS} {{ every pg in sw.portgroups {{ is_number(pg.vlan_id) }} }}"]
fact("5.9", "native vlan", PGEV, "vswitches[].portgroups[].vlan_id",
     [f"count([1 | some sw in {VS}; some pg in sw.portgroups; pg.vlan_id == _native_vlan]) == 0"],
     add("/vswitches/0/portgroups/0/vlan_id", 1), rm("/vswitches"))
fact("5.10", "virtual guest tagging", PGEV, "vswitches[].portgroups[].vlan_id",
     [f"count([1 | some sw in {VS}; some pg in sw.portgroups; pg.vlan_id == 4095]) == 0"],
     add("/vswitches/0/portgroups/0/vlan_id", 4095), rm("/vswitches"))
att("5.11", "isolate management", "management_traffic_isolated")

# ── section 6: services ─────────────────────────────────────────────────────────
att("6.1.1", "cim services", "cim_access_limited")
att("6.2.1", "isolate storage", "storage_traffic_isolated")
fact("6.2.2", "unique names", [f"is_array({P}.datastores)", f"every d in {P}.datastores {{ is_string(d.name) }}"], "datastores[].name",
     [f"count({{d.name | some d in {P}.datastores}}) == count({P}.datastores)"], add("/datastores/1/name", "ds-a"), rm("/datastores"))
IS = f"{P}.iscsi_adapters"
fact("6.3.1", "mutual chap", [f"is_array({IS})"], "iscsi_adapters", [f'every a in {IS} {{ a.mutual_chap_enabled == true; lower(a.chap_type) == "required" }}'],
     add("/iscsi_adapters/0/mutual_chap_enabled", False), rm("/iscsi_adapters"))
att("6.3.2", "unique chap", "iscsi_chap_secrets_unique")
att("6.4.1", "snmp services", "snmp_access_limited")
att("6.5.1", "validated ciphers", "sshd_ciphers_fips")
att("6.5.2", "validated cryptographic modules", "sshd_crypto_modules_fips")
sshd("6.5.3", "gateway ports", "gatewayports", "no")
sshd("6.5.4", "host-based", "hostbasedauthentication", "no")
for cid, kw, key in [("6.5.5", "timeout count", "clientalivecountmax"), ("6.5.6", "timeout interval", "clientaliveinterval")]:
    fact(cid, kw, [f'_has_sshd("{key}")'], f"sshd_config.{key}", [f'{P}.sshd_config["{key}"] != null', f'_num({P}.sshd_config["{key}"]) > 0'],
         add(f"/sshd_config/{key}", 0), rm("/sshd_config"))
fact("6.5.7", "login banner", ['_has_sshd("banner")'], "sshd_config.banner", ['_sshd("banner") != "none"', '_sshd("banner") != ""'],
     add("/sshd_config/banner", "none"), rm("/sshd_config"))
sshd("6.5.8", ".rhosts", "ignorerhosts", "yes")
sshd("6.5.9", "stream local forwarding", "allowstreamlocalforwarding", "no")
sshd("6.5.10", "tcp forwarding", "allowtcpforwarding", "no")
sshd("6.5.11", "tunnels", "permittunnel", "no")
sshd("6.5.12", "user environment", "permituserenvironment", "no")

# ── section 7: virtual machines ───────────────────────────────────────────────────
VMS = f"{P}.vms"


def vcfg(cid, kw, field, cond, bad, desc):
    fact(cid, kw, [f"is_array({VMS})", f"every vm in {VMS} {{ is_string(vm.config.{field}) }}"], f"vms[].config.{field}",
         [f"every vm in {VMS} {{ {cond} }}"], add(f"/vms/1/config/{field}", bad), rm("/vms"))


fact("7.1", "secure boot", [f"is_array({VMS})", f"every vm in {VMS} {{ is_boolean(vm.config.efi_secure_boot_enabled) }}"],
     "vms[].config.efi_secure_boot_enabled", [f"every vm in {VMS} {{ vm.config.efi_secure_boot_enabled == true }}"],
     add("/vms/1/config/efi_secure_boot_enabled", False), rm("/vms"))
vcfg("7.2", "vmotion", "migrate_encryption", 'lower(vm.config.migrate_encryption) == "required"', "opportunistic", "")
vcfg("7.3", "fault tolerance", "ft_encryption_mode", 'lower(vm.config.ft_encryption_mode) == "ftencryptionrequired"',
     "ftEncryptionOpportunistic", "")
vadv("7.4", "3d graphics", '_vfalse_or_absent(vm, "mks.enable3d")', "mks.enable3d", "TRUE")
vtrue("7.5", "lock when the last console", "tools.guest.desktop.autolock")
vadv("7.6", "console sharing", '_num(vm.advanced_settings["RemoteDisplay.maxConnections"]) == 1', "RemoteDisplay.maxConnections", "4")
vclear("7.7", "passthrough", "(?i)^pcipassthru[0-9]*\\\\.present$", "pciPassthru0.present")
vtrue("7.8", "modification and disconnection", "isolation.device.edit.disable")
vtrue("7.9", "unauthorized connection of devices", "isolation.device.connectable.disable")
DEVEV = [f"is_array({VMS})", f"every vm in {VMS} {{ is_array(vm.device_types) }}"]


def vdev(cid, kw, kind):
    fact(cid, kw, DEVEV, "vms[].device_types", [f'every vm in {VMS} {{ not "{kind}" in {{lower(t) | some t in vm.device_types}} }}'],
         add("/vms/1/device_types", [kind]), rm("/vms"))


vdev("7.10", "audio devices", "sound")
att("7.11", "ahci", "unneeded_ahci_controllers_removed")
vclear("7.12", "usb/xhci", "(?i)^(usb|usb_xhci)\\\\.present$", "usb.present")
vclear("7.13", "serial port", "(?i)^serial[0-9]+\\\\.present$", "serial0.present")
vclear("7.14", "parallel port", "(?i)^parallel[0-9]+\\\\.present$", "parallel0.present")
vdev("7.15", "cd/dvd", "cdrom")
vclear("7.16", "floppy", "(?i)^floppy[0-9]+\\\\.present$", "floppy0.present")
vtrue_or_absent("7.17", "drag and drop", "isolation.tools.dnd.disable")
vtrue_or_absent("7.18", "copy operations", "isolation.tools.copy.disable")
vtrue_or_absent("7.19", "paste operations", "isolation.tools.paste.disable")
vadv("7.20", "dvfilter", 'not _vkey_any(vm, "(?i)^ethernet[0-9]+\\\\.filter[0-9]+\\\\.name$")', "ethernet0.filter1.name", "dvfilter-example")
vtrue("7.21", "disk shrinking", "isolation.tools.diskShrink.disable")
vtrue("7.22", "disk wiping", "isolation.tools.diskWiper.disable")
fact("7.23", "sharing of memory pages", VMEV, "vms[].advanced_settings",
     [f'salts := [s | some vm in {VMS}; s := vm.advanced_settings["sched.mem.pshare.salt"]]', "count(salts) == count({s | some s in salts})"],
     add("/vms/0/advanced_settings/sched.mem.pshare.salt", "shared") + [
         {"op": "add", "path": "/esxi/vms/1/advanced_settings/sched.mem.pshare.salt", "value": "shared"}], rm("/vms"))
vadv("7.24", "host information", '_vfalse("tools.guestlib.enableHostInfo", vm)'.replace('("tools.guestlib.enableHostInfo", vm)', '(vm, "tools.guestlib.enableHostInfo")'),
     "tools.guestlib.enableHostInfo", "TRUE")
vadv("7.25", "diagnostic logging", '_vtrue_or_absent(vm, "logging")', "logging", "FALSE")
vadv("7.26", "retained diagnostic logs", '_num(vm.advanced_settings["log.keepOld"]) == 10', "log.keepOld", "3")
vadv("7.27", "size of diagnostic logs", '_num(vm.advanced_settings["log.rotateSize"]) == 1024000', "log.rotateSize", "0")
att("7.28", "informational messages", "tools_setinfo_size_limit_approved")
fact("7.29", "hardware version", [f"is_array({VMS})", f"every vm in {VMS} {{ _hw(vm) }}".replace("{ _hw(vm) }", "{ is_number(_hw(vm)) }")],
     "vms[].config.version", [f"every vm in {VMS} {{ _hw(vm) >= 19 }}"], add("/vms/1/config/version", "vmx-13"), rm("/vms"))

# ── section 8: VMware Tools ──────────────────────────────────────────────────────
att("8.1", "end of general support", "tools_version_supported")
att("8.2", "all software updates", "tools_updates_current")
att("8.3", "automatic upgrades", "tools_upgrade_policy_approved")
att("8.4", "recustomized", "tools_recustomize_blocked")
att("8.5", "automatic addition", "tools_auto_add_features_limited")
att("8.6", "automatic removal", "tools_auto_remove_features_limited")
vtools("8.7", "globalconf", "globalconf.enabled", '_isfalse(vm.tools_config["globalconf.enabled"])', "true")
vtools("8.8", "containerinfo", "containerinfo.poll-interval", '_num(vm.tools_config["containerinfo.poll-interval"]) == 0', "30")
vtools("8.9", "appinfo", "appinfo.disabled", '_istrue(vm.tools_config["appinfo.disabled"])', "false")
vtools("8.10", "guest store upgrade", "gueststoreupgrade.policy", '_str(vm.tools_config["gueststoreupgrade.policy"]) == "off"', "on")
vtools("8.11", "service discovery", "servicediscovery.disabled", '_istrue(vm.tools_config["servicediscovery.disabled"])', "false")
att("8.12", "msi transforms", "tools_msi_transforms_limited")
vtools("8.13", "tools logging", "logging.log", '_istrue(vm.tools_config["logging.log"])', "false")
att("8.14", "system log service", "tools_logs_to_system_logger")
vtools("8.15", "guest operations", "guestoperations.disabled", '_istrue(vm.tools_config["guestoperations.disabled"])', "false")

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
assert not AUTO_ATTESTED, AUTO_ATTESTED
for cid in ids:  # our wording replaces the workbook title from here on
    assert neutralize_title(OWN[cid]) == OWN[cid], cid
    WB[cid]["title"] = OWN[cid]

SECTION_OF = {"1": "hardware", "2": "software_and_boot", "3": "access_and_shell", "4": "logging", "5": "host_network",
              "6": "host_services", "7": "virtual_machines", "8": "vmware_tools"}
SECTIONS = list(SECTION_OF.values())
STITLE = {"hardware": "1 Hardware", "software_and_boot": "2 Software and boot", "access_and_shell": "3 Access and shell",
          "logging": "4 Logging", "host_network": "5 Host networking", "host_services": "6 Host services",
          "virtual_machines": "7 Virtual machines", "vmware_tools": "8 VMware Tools"}


def section(cid):
    return SECTION_OF[cid.split(".")[0]]


attest_ids = [c["id"] for c in C if c["kind"] == "attest"]
manual_fact = [c["id"] for c in C if c["kind"] == "fact" and WB[c["id"]]["assessment"] == "Manual"]

# ── a compliant host (test fixture) ────────────────────────────────────────────────
VM_ADV = {"mks.enable3d": "FALSE", "tools.guest.desktop.autolock": "TRUE", "RemoteDisplay.maxConnections": "1",
          "pciPassthru0.present": "FALSE", "isolation.device.edit.disable": "TRUE", "isolation.device.connectable.disable": "TRUE",
          "usb.present": "FALSE", "isolation.tools.dnd.disable": "TRUE", "isolation.tools.copy.disable": "TRUE",
          "isolation.tools.paste.disable": "TRUE", "isolation.tools.diskShrink.disable": "TRUE",
          "isolation.tools.diskWiper.disable": "TRUE", "tools.guestlib.enableHostInfo": "FALSE", "logging": "TRUE",
          "log.keepOld": "10", "log.rotateSize": "1024000"}
VM_TOOLS = {"globalconf.enabled": "false", "containerinfo.poll-interval": "0", "appinfo.disabled": "true",
            "gueststoreupgrade.policy": "off", "servicediscovery.disabled": "true", "logging.log": "true",
            "guestoperations.disabled": "true"}


def vm(name):
    return {"name": name, "config": {"efi_secure_boot_enabled": True, "migrate_encryption": "required",
                                      "ft_encryption_mode": "ftEncryptionRequired", "version": "vmx-21"},
            "advanced_settings": dict(VM_ADV), "device_types": [], "tools_config": dict(VM_TOOLS)}


SECG = {"promiscuous_mode": False, "mac_changes": False, "forged_transmits": False}
GREEN = {"esxi": {
    "advanced_settings": {
        "Net.BMCNetworkEnable": 0, "UserVars.SuppressHyperthreadWarning": 0, "Mem.ShareForceSalting": 2, "Mem.MemEagerZero": 1,
        "Config.HostAgent.plugins.solo.enableMob": "false", "UserVars.DcuiTimeOut": 600,
        "UserVars.ESXiShellInteractiveTimeOut": 300, "UserVars.ESXiShellTimeOut": 3600, "UserVars.SuppressShellWarning": 0,
        "Security.PasswordQualityControl": "retry=3 min=disabled,disabled,disabled,disabled,15",
        "Security.AccountLockFailures": 5, "Security.AccountUnlockTime": 900, "Security.PasswordHistory": 5,
        "Config.HostAgent.vmacore.soap.sessionTimeout": 30, "UserVars.HostClientSessionTimeout": 900,
        "Syslog.global.logHost": "udp://10.0.0.30:514", "Net.DVFilterBindIpAddress": "", "Net.BlockGuestBPDU": 1,
    },
    "secure_boot": {"enabled": True},
    "encryption": {"mode": "TPM", "require_secure_boot": True},
    "software": {"acceptance_level": "PartnerSupported"},
    "kernel_settings": {"execInstalledOnly": "TRUE", "disableHwrng": "FALSE"},
    "services": {"TSM-SSH": {"running": False, "policy": "off"}, "TSM": {"running": False, "policy": "off"},
                 "slpd": {"running": False, "policy": "off"}, "ntpd": {"running": True, "policy": "on"}},
    "ntp": {"servers": ["10.0.0.123", "10.0.1.123"]},
    "wbem": {"enabled": False}, "snmp": {"enabled": False},
    "lockdown_mode": "strict",
    "passwd": {"dcui": {"shell": "/sbin/nologin"}, "vpxuser": {"shell": "/sbin/nologin"}},
    "syslog": {"log_level": "info", "log_filtering_enabled": False, "check_ssl_certs": True, "strict_x509_compliance": True},
    "audit_records": {"storage_active": True, "remote_host_enabled": True},
    "firewall": {"enabled": True, "default_action": "DROP",
                 "rulesets": [{"name": "sshServer", "enabled": False, "allowed_ip_all": True},
                              {"name": "ntpClient", "enabled": True, "allowed_ip_all": False}]},
    "vswitches": [{"name": "vSwitch0", "security": dict(SECG),
                   "portgroups": [{"name": "VM Network", "vlan_id": 20, "security": {"forged_transmits": False}},
                                  {"name": "Mgmt", "vlan_id": 30}]}],
    "datastores": [{"name": "ds-a"}, {"name": "ds-b"}],
    "iscsi_adapters": [{"device": "vmhba64", "chap_type": "Required", "mutual_chap_enabled": True}],
    "sshd_config": {"gatewayports": "no", "hostbasedauthentication": "no", "clientalivecountmax": 3, "clientaliveinterval": 200,
                    "banner": "/etc/issue", "ignorerhosts": "yes", "allowstreamlocalforwarding": "no",
                    "allowtcpforwarding": "no", "permittunnel": "no", "permituserenvironment": "no"},
    "vms": [vm("vm-a"), vm("vm-b")],
    "attest": {c["attest"]: True for c in C if c["kind"] == "attest"},
}}

# ── Rego helpers ──────────────────────────────────────────────────────────────────
HELPERS = r'''# ── helpers ──────────────────────────────────────────────────────────────────
# profile selection: input.cis_profile.level 1 or 2 (Level 2 includes Level 1); absent or other => 2, the stricter
default _level := 2

_level := 1 if input.cis_profile.level == 1

_applies(id) if recommendations[id].level <= _level

_nonempty(v) if {
	is_string(v)
	trim_space(v) != ""
}

# comparable text of a setting: "TRUE", true and " true " all read as "true"
_str(v) := lower(trim_space(sprintf("%v", [v])))

_istrue(v) if _str(v) == "true"

_isfalse(v) if _str(v) == "false"

# advanced settings come back as strings or numbers depending on the collector
_num(v) := v if is_number(v)

_num(v) := to_number(trim_space(v)) if {
	is_string(v)
	regex.match(`^\s*-?[0-9]+(\.[0-9]+)?\s*$`, v)
}

# ── host facts ──
_adv(k) := v if {
	v := input.esxi.advanced_settings[k]
	v != null
}

_has_adv(k) if input.esxi.advanced_settings[k] != null

_lockdown := trim_prefix(_str(input.esxi.lockdown_mode), "lockdown")

# Security.PasswordQualityControl: "min=N0,N1,N2,N3,N4" with the first four disabled and N4 >= 15
_pwq_ok if {
	m := regex.find_all_string_submatch_n(`(?:^|\s)min=([^\s]+)`, _adv("Security.PasswordQualityControl"), 1)
	parts := split(m[0][1], ",")
	count(parts) == 5
	every i in [0, 1, 2, 3] {
		lower(parts[i]) == "disabled"
	}
	regex.match(`^[0-9]+$`, parts[4])
	to_number(parts[4]) >= 15
}

# sshd effective settings (directive names lower-case); never a text search of the file
_has_sshd(k) if input.esxi.sshd_config[k] != null

_sshd(k) := _str(input.esxi.sshd_config[k]) if input.esxi.sshd_config[k] != null

# an enabled ruleset that does not name its allowed addresses is open to every address
_ruleset_open(r) if {
	r.enabled == true
	not r.allowed_ip_all == false
}

# VLAN the operator treats as native (default 1)
_native_vlan := object.get(input.esxi, "native_vlan_id", 1)

# ── VM facts ──
_vm_adv_ev if {
	is_array(input.esxi.vms)
	every vm in input.esxi.vms {
		is_object(vm.advanced_settings)
	}
}

_vhas(vm, k) if vm.advanced_settings[k] != null

_vtrue(vm, k) if _istrue(vm.advanced_settings[k])

_vfalse(vm, k) if _isfalse(vm.advanced_settings[k])

_vtrue_or_absent(vm, k) if not _vhas(vm, k)

_vtrue_or_absent(vm, k) if _vtrue(vm, k)

_vfalse_or_absent(vm, k) if not _vhas(vm, k)

_vfalse_or_absent(vm, k) if _vfalse(vm, k)

# a setting whose name matches the pattern with any value other than false
_vkey_bad(vm, re) if {
	some k, v in vm.advanced_settings
	regex.match(re, k)
	not _isfalse(v)
}

_vkey_any(vm, re) if {
	some k, _ in vm.advanced_settings
	regex.match(re, k)
}

# virtual hardware version as a number ("vmx-21" => 21)
_hw(vm) := to_number(trim_prefix(vm.config.version, "vmx-")) if regex.match(`^vmx-[0-9]+$`, vm.config.version)

'''

# ── emission: roll-up module ───────────────────────────────────────────────────────
META = '''# METADATA
# title: "{title}"
# custom:
#   class: security
#   framework: cis_vmware
#   source: cis
#   domains: [virtualization, vmware]
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
ATTLIST = ", ".join(attest_ids)
HEADER = META.format(title=BENCH, checks=N_TOTAL, density="sized", basis="size", entry="compliance_report") + f'''package {PKG}

# {BENCH}
# Generated from the CIS workbook by tools/cis_generators/gen_esxi.py (one logic table for ESXi 8.0 and 9.0).
# {N_TOTAL} recommendations ({N_AUTO} Automated, {N_TOTAL - N_AUTO} Manual; {N_L1} Level 1, {N_L2} Level 2), every one in the
# benchmark; ids, levels and assessment status read from the workbook. Messages use our own wording, not CIS text.
# Profile: input.cis_profile.level 1 or 2 (Level 2 includes Level 1); absent => 2. total_controls counts the
# recommendations in the selected profile.
# Facts missing => "<id>: evidence missing — <field> not collected". Manual recommendations whose audit names an
# exact value are checked like Automated ones: {", ".join(manual_fact)}.
# Attestation booleans under input.esxi.attest (false or absent => violation): {ATTLIST}.
#
# Input contract (input.esxi, one host; every name is what the audit procedure reads):
#   advanced_settings{{<name>: value}}  Get-AdvancedSetting on the host (the STIG ESXi module reads the same map)
#   lockdown_mode                      "disabled" | "normal" | "strict" (lockdownNormal etc. accepted)
#   services{{<key>: {{running, policy}}}} Get-VMHostService: TSM-SSH, TSM, slpd, ntpd; policy "on"|"off"|"automatic"
#   wbem.enabled, snmp.enabled         esxcli system wbem get / snmp get
#   software.acceptance_level          esxcli software acceptance get
#   kernel_settings{{<option>: value}}   esxcli system settings kernel list (execInstalledOnly, disableHwrng)
#   secure_boot.enabled                secureBoot.py -s ("Enabled" => true)
#   encryption{{mode, require_secure_boot}} esxcli system settings encryption get
#   ntp.servers[]                      esxcli system ntp config get
#   passwd.<dcui|vpxuser>.shell        login shell from the passwd entry
#   syslog{{log_level, log_filtering_enabled, check_ssl_certs, strict_x509_compliance}}  esxcli system syslog config get
#   audit_records{{storage_active, remote_host_enabled}}  esxcli system auditrecords get
#   firewall{{enabled, default_action, rulesets[]{{name, enabled, allowed_ip_all}}}}
#   vswitches[]{{name, security{{promiscuous_mode, mac_changes, forged_transmits}}, portgroups[]{{name, vlan_id,
#                security{{...optional overrides}}}}}}; native_vlan_id (optional, default 1)
#   datastores[]{{name}}, iscsi_adapters[]{{device, chap_type, mutual_chap_enabled}}
#   sshd_config{{<directive>: value}}    effective sshd settings, directive names lower-case
#   vms[]{{config{{efi_secure_boot_enabled, migrate_encryption, ft_encryption_mode, version}}, advanced_settings{{}},
#          device_types[], tools_config{{"<section>.<key>": value}}}}
#   attest.*                           attestation booleans for the judgement recommendations
# A setting that a VM does not carry is absent from advanced_settings; the "TRUE or absent" and "FALSE or absent"
# checks accept that, the others read it as not configured.

import rego.v1

# Main compliance rule - every recommendation in the selected profile must pass; no facts, no compliance
default compliant := false

compliant if {{
	input.esxi
	count(violations) == 0
}}

# Aggregate all violations across sections
violations := [v |
	arrays := [
{chr(10).join(f"		{s}_violations," for s in SECTIONS)}
	]
	some a in arrays
	some v in a
]

'''

parts = [HEADER]
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
# Thin bridge over data.{PKG} (generated by tools/cis_generators/gen_esxi.py). That package already fails
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
	"version": "{V['ver']}",
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

# Generated per-recommendation tests for {BENCH} (tools/cis_generators/gen_esxi.py): every recommendation
# has a pass test (green input) and a fail test; configuration checks also have an evidence-missing test;
# attestations fail when false or absent.

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
		{{"op": "add", "path": "/esxi/lockdown_mode", "value": "normal"}},
	])
	vs := b.violations with input as inp
	not _has_id(vs, "3.21")
}}

test_password_quality_needs_every_class_disabled if {{
	inp := json.patch(green, [{{"op": "add", "path": "/esxi/advanced_settings/Security.PasswordQualityControl",
		"value": "retry=3 min=disabled,disabled,12,disabled,15"}}])
	vs := b.violations with input as inp
	_has_id(vs, "3.11")
}}

test_zero_timeout_is_disabled_not_compliant if {{
	inp := json.patch(green, [{{"op": "add", "path": "/esxi/advanced_settings/UserVars.DcuiTimeOut", "value": "0"}}])
	vs := b.violations with input as inp
	_has_id(vs, "3.7")
}}

test_absent_slp_service_is_compliant if {{
	inp := json.patch(green, [{{"op": "remove", "path": "/esxi/services/slpd"}}])
	vs := b.violations with input as inp
	not _has_id(vs, "3.4")
}}

test_port_group_override_accepting_promiscuous_fails if {{
	inp := json.patch(green, [{{"op": "add", "path": "/esxi/vswitches/0/portgroups/1/security", "value": {{"promiscuous_mode": true}}}}])
	vs := b.violations with input as inp
	_has_id(vs, "5.8")
}}

{emit_tests(PKG, C, WB, GREEN, "/esxi/attest")}'''
open(f"{OUT}/tests/test_{PKG}_recommendations.rego", "w").write(tests)

# ── emission: README ─────────────────────────────────────────────────────────────────
sec_rows = []
for s in SECTIONS:
    ids_s = [c["id"] for c in C if section(c["id"]) == s]
    at = [i for i in ids_s if i in attest_ids]
    sec_rows.append(f"| {STITLE[s]} | {len(ids_s)} | {len(at)} |")
README = f'''# {BENCH}

**Version:** v1.0 · generated by `tools/cis_generators/gen_esxi.py` from the CIS workbook

All {N_TOTAL} recommendations ({N_AUTO} Automated, {N_TOTAL - N_AUTO} Manual; {N_L1} Level 1, {N_L2} Level 2). {N_TOTAL - len(attest_ids)} are decided
from collected facts and fail closed with an "evidence missing" message when the fact was not collected;
{len(attest_ids)} judgement items (hardware, vendor lifecycle, organisation-approved values) are attestation booleans.
Every Automated recommendation is decided from facts. Messages carry the control id and our own wording, not CIS text.
The ESXi 8.0 and 9.0 workbooks list the same recommendations and audit procedures, so both modules come from one logic table.

Query: `POST /v1/data/{PKG}/main/compliance_report` (roll-up package `{PKG}`).

## Profile

`input.cis_profile.level` is `1` or `2` (Level 2 includes Level 1). Absent, it is `2`. `total_controls` is the number in
scope: {N_L1} at Level 1, {N_TOTAL} at Level 2. On empty input every one of them fails.

## Sections

| Section | Recommendations | Attested |
|---|---|---|
{chr(10).join(sec_rows)}

Attested: {ATTLIST}.

## Facts

`input.esxi` describes one host and its virtual machines. The full path list is in the header of `{PKG}.rego`. Host
advanced settings are the same `input.esxi.advanced_settings` map the DISA STIG module for ESXi reads. Settings that the
audit says may be absent on a VM ("TRUE or absent", "FALSE or absent", device-presence keys) accept an absent key; every
other VM check reads an absent key as not configured. Values that the benchmark leaves to the organisation (password
maximum age, API session timeout, SSH idle count, size limits) are checked only for being finite and positive, or attested.

Regenerate: see `tools/cis_generators/README.md`.
'''
open(f"{OUT}/README.md", "w").write(README)
print("ok", VARIANT, len(C), sec_tot, "attested", len(attest_ids), "manual-as-fact", len(manual_fact))
