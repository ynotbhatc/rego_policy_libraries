"""Reviewed logic table for gen_rhel9.py oracle_linux_8 (DISA STIG for Oracle Linux 8, V2R10).

Built 2026-11-18 rule by rule against the OL 8 V2R10 check text (catalogs/oracle_linux_8.json). OL 8 is RHEL 8 era
tooling: audit rules are read from /etc/audit/audit.rules (not auditctl -l), mounts from /etc/fstab, sshd and
pwquality settings from every file with "conflicting results" a finding, faillock rules apply to 8.2 and above.
`T.reuse` only where the OL 8 check is the same check as a reviewed RHEL 9 (or OL 9) rule; see linux_stig_table.py.
"""
import json

import ol9_rules
import rhel9_rules
from linux_stig_table import Table

T = Table(sources=(rhel9_rules, ol9_rules))

# ── same check as the reviewed RHEL 9 / OL 9 rule ─────────────────────────────────────────────────────────────
for ol, src in [
    ("OL08-00-040170", "RHEL-09-211050"), ("OL08-00-010293", "RHEL-09-672055"), ("OL08-00-010291", "RHEL-09-255065"),
    ("OL08-00-010290", "RHEL-09-255075"), ("OL08-00-010110", "RHEL-09-611140"), ("OL08-00-020190", "RHEL-09-611075"),
    ("OL08-00-020200", "RHEL-09-411010"), ("OL08-00-020240", "RHEL-09-411030"), ("OL08-00-010121", "RHEL-09-611155"),
    ("OL08-00-030181", "RHEL-09-653015"), ("OL08-00-030731", "RHEL-09-653040"), ("OL08-00-010060", "RHEL-09-211020"),
    ("OL08-00-010430", "RHEL-09-213070"), ("OL08-00-010375", "RHEL-09-213010"), ("OL08-00-010376", "RHEL-09-213015"),
    ("OL08-00-040286", "RHEL-09-251045"), ("OL08-00-040281", "RHEL-09-213075"), ("OL08-00-040285", "RHEL-09-253035"),
    ("OL08-00-040080", "RHEL-09-291010"), ("OL08-00-040026", "RHEL-09-213055"), ("OL08-00-010360", "RHEL-09-651015"),
    ("OL08-00-010780", "RHEL-09-232255"), ("OL08-00-010790", "RHEL-09-232250"), ("OL08-00-010330", "RHEL-09-232020"),
    ("OL08-00-010340", "RHEL-09-232200"), ("OL08-00-040259", "RHEL-09-253075"), ("OL08-00-040279", "RHEL-09-253015"),
    ("OL08-00-040220", "RHEL-09-253065"), ("OL08-00-040239", "RHEL-09-253020"), ("OL08-00-040110", "RHEL-09-291040"),
    ("OL08-00-040330", "RHEL-09-251040"), ("OL08-00-010090", "RHEL-09-631010"), ("OL08-00-040000", "RHEL-09-215040"),
    ("OL08-00-020050", "OL09-00-002160"), ("OL08-00-040282", "OL09-00-002410"), ("OL08-00-040280", "OL09-00-006041"),
    ("OL08-00-040240", "OL09-00-006042"), ("OL08-00-040160", "OL09-00-000251"),
]:
    T.reuse(ol, src)

# ── same check, one clause different ──────────────────────────────────────────────────────────────────────────
s = T.src["RHEL-09-653025"]   # OL 8 has no ask-the-SA clause
T.reuse("OL08-00-030060", "RHEL-09-653025", attest_alts=[], pass_cases=[],
        expect="disk_full_action in /etc/audit/auditd.conf must be SYSLOG, SINGLE or HALT")
s = T.src["RHEL-09-214020"]   # OL 8: 1 / True / yes, no ask-the-SA clause
T.reuse("OL08-00-010371", "RHEL-09-214020", attest_alts=[], pass_cases=[],
        expect="localpkg_gpgcheck in /etc/dnf/dnf.conf must be 1, True or yes")
s = T.src["RHEL-09-652010"]   # OL 8: rsyslog, or the SA shows how audit logs are offloaded
T.reuse("OL08-00-030670", "RHEL-09-652010", attest_alts=[['_attested("ol08_00_030670_offload")']],
        expect="the rsyslog package must be installed, or the SA must show how audit logs are offloaded "
               "(input.attest.ol08_00_030670_offload)",
        pass_cases=[{"packages": {"rsyslog": False}, "attest": {"ol08_00_030670_offload": True}}])
s = T.src["RHEL-09-251015"]   # OL 8: firewalld active, or the SA shows another firewall installed and active
T.reuse("OL08-00-040101", "RHEL-09-251015", attest_alts=[['_attested("ol08_00_040101_other_firewall")']],
        expect="firewalld must be active, or the SA must show another firewall is installed and active "
               "(input.attest.ol08_00_040101_other_firewall)",
        pass_cases=[{"services": {"firewalld": "inactive"}, "attest": {"ol08_00_040101_other_firewall": True}}])
s = T.src["RHEL-09-231040"]   # OL 8: autofs not installed is Not Applicable
T.reuse("OL08-00-040070", "RHEL-09-231040", na=[["input.packages.autofs == false"]],
        na_expect="the autofs service is not installed", na_cases=[{"unit_enabled": {"autofs": None}, "packages": {"autofs": False}}])
s = T.src["RHEL-09-291035"]   # OL 8: no Bluetooth adapter is Not Applicable
T.reuse("OL08-00-040111", "RHEL-09-291035", na=[["input.bluetooth_adapter_present == false"]],
        na_expect="the system has no Bluetooth adapter",
        na_cases=[{"modprobe": {"bluetooth": None}, "bluetooth_adapter_present": False}])
s = T.src["RHEL-09-213020"]   # OL 8: UEK R6+ with Secure Boot is Not Applicable
T.reuse("OL08-00-010372", "RHEL-09-213020",
        na=[['_num(["kernel_info", "uek_release"]) >= 6', "input.secureboot_enabled == true"]],
        na_expect="the Unbreakable Enterprise Kernel release 6 or above runs with Secure Boot enabled",
        na_cases=[{"kernel_params": {"kernel.kexec_load_disabled": None}, "kernel_info": {"uek_release": 7},
                   "secureboot_enabled": True}],
        comment="kernel.kexec_load_disabled must be 1; UEK R6+ with Secure Boot is Not Applicable "
                "(input.kernel_info.uek_release, input.secureboot_enabled)")
s = T.src["RHEL-09-215060"]   # same check; its green state is N/A beside OL08-00-040190 (tftp-server not installed)
T.reuse("OL08-00-040350", "RHEL-09-215060", green_na={"packages": {"tftp-server": False}})
s = T.src["RHEL-09-212010"]   # OL 8 BIOS variant: /boot/grub2/user.cfg; UEFI systems are Not Applicable
T.reuse("OL08-00-010150", "RHEL-09-212010", na=[['_kw(["boot_firmware"]) == "uefi"']],
        na_expect="the system boots with UEFI", na_cases=[{"grub": {"user_cfg_password": None}, "boot_firmware": "uefi"}],
        expect="GRUB2_PASSWORD in /boot/grub2/user.cfg must begin with grub.pbkdf2.sha512",
        comment="GRUB2_PASSWORD in /boot/grub2/user.cfg (BIOS); input.boot_firmware \"uefi\" is Not Applicable")
s = T.src["RHEL-09-631015"]
o9 = T.src["OL09-00-000910"]  # OL 8 reads /etc/sssd/sssd.conf only, no ask-the-SA clause, alternate-MFA N/A kept
T.reuse("OL08-00-020090", "OL09-00-000910", attest_alts=[], pass_cases=[],
        na=[['_attested("ol08_00_020090_alternate_mfa")']],
        na_expect="the SA demonstrated an approved alternate multifactor authentication method",
        na_cases=[{"sssd_conf_file": {"certmap_rules": None}, "attest": {"ol08_00_020090_alternate_mfa": True}}],
        expect="/etc/sssd/sssd.conf must have a [certmap/...] section with a maprule")
s = T.src["RHEL-09-611170"]   # OL 8 requires ocsp_dgst=sha1 and has no alternate-MFA note
T.reuse("OL08-00-010400", "RHEL-09-611170",
        alts=[[a.replace("ocsp_dgst=sha512", "ocsp_dgst=sha1") for a in s["alts"][0]]],
        green={"sssd": {"certificate_verification": "ocsp_dgst=sha1"}},
        bad=[{"sssd": {"certificate_verification": "ocsp_dgst=sha512"}},
             {"sssd": {"certificate_verification": "ocsp_dgst=sha1,no_ocsp"}}],
        pass_cases=[{"sssd": {"certificate_verification": None}, "attest": {"ol08_00_010400_status_checking": True}}],
        na=[], na_expect="", na_cases=[],
        expect="certificate_verification in the [sssd] section must carry ocsp_dgst=sha1 (as the OL 8 check prints it) and "
               "neither no_ocsp nor no_verification, or the SA must show how certificate status checking is implemented "
               "(input.attest.ol08_00_010400_status_checking)")

# ── audit rules: same rule text, but OL 8 reads the rules file /etc/audit/audit.rules (input.audit_rules_file) ──
T.helpers("audit_logging", r'''
# input.audit_rules_file: the uncommented lines of /etc/audit/audit.rules (OL 8 greps the rules file, not auditctl -l)
_audit_lines := [l | some l in input.audit_rules_file; is_string(l)]''', replace=True)


def rules_file(spec):
    def sub(o):
        if isinstance(o, str):
            return o.replace("input.audit_rules", "input.audit_rules_file").replace("loaded audit rule", "rule in /etc/audit/audit.rules")
        if isinstance(o, tuple):
            return tuple("audit_rules_file" if x == "audit_rules" else x for x in o)
        if isinstance(o, list):
            return [sub(x) for x in o]
        if isinstance(o, dict):
            return {("audit_rules_file" if k == "audit_rules" else k): sub(v) for k, v in o.items()}
        return o
    return {k: sub(spec[k]) for k in ("ev", "alts", "green", "bad", "pass_cases", "expect", "comment")}


for ol, r9 in [("OL08-00-030000", "RHEL-09-654010"), ("OL08-00-030480", "RHEL-09-654020"), ("OL08-00-030490", "RHEL-09-654015"),
               ("OL08-00-030200", "RHEL-09-654025"), ("OL08-00-030420", "RHEL-09-654070"), ("OL08-00-030360", "RHEL-09-654080"),
               ("OL08-00-030171", "RHEL-09-654215"), ("OL08-00-030150", "RHEL-09-654240"), ("OL08-00-030550", "RHEL-09-654150")]:
    T.reuse(ol, r9, **rules_file(T.src[r9]))

# ── OL 8's own check ───────────────────────────────────────────────────────────────────────────────────────────
T.R("configuration_management", "OL08-00-010170", "selinux_enforcing", [("selinux", "getenforce")],
    [['_kw(["selinux", "getenforce"]) == "enforcing"']],
    {"selinux": {"getenforce": "Enforcing"}}, [{"selinux": {"getenforce": "Permissive"}}],
    "getenforce must return Enforcing", "Set SELINUX=enforcing in /etc/selinux/config and run setenforce 1",
    comment="getenforce (OL 8 checks the runtime mode only)")

T.R("configuration_management", "OL08-00-010450", "selinux_targeted", [("selinux", "policy"), ("selinux", "config_selinuxtype")],
    [['_str(["selinux", "policy"]) == "targeted"', '_str(["selinux", "config_selinuxtype"]) == "targeted"']],
    {"selinux": {"policy": "targeted", "config_selinuxtype": "targeted"}},
    [{"selinux": {"policy": "mls"}}, {"selinux": {"config_selinuxtype": "mls"}}],
    "sestatus Loaded policy name must be targeted and /etc/selinux/config must set SELINUXTYPE=targeted",
    "Set SELINUXTYPE=targeted in /etc/selinux/config and reboot",
    comment="Loaded policy name (sestatus) and the uncommented SELINUXTYPE in /etc/selinux/config")

T.R("configuration_management", "OL08-00-010020", "fips_mode_enabled",
    [("fips", "mode_setup_check"), ("grub", "kernelopts"), ("fips", "fips_enabled")],
    [['out := _str(["fips", "mode_setup_check"])', 'ls := split(out, "\\n")', 'some l in ls',
      'regex.match(`^FIPS mode is enabled\\.?$`, trim_space(l))',
      'opts := split(_str(["grub", "kernelopts"]), " ")', '"fips=1" in opts', '_str(["fips", "fips_enabled"]) == "1"']],
    {"fips": {"mode_setup_check": "FIPS mode is enabled.", "fips_enabled": "1"},
     "grub": {"kernelopts": "root=/dev/mapper/ol-root ro crashkernel=auto fips=1 boot=UUID=1a2b"}},
    [{"fips": {"mode_setup_check": "FIPS mode is disabled."}}, {"grub": {"kernelopts": "root=/dev/mapper/ol-root ro fips=0"}},
     {"fips": {"fips_enabled": "0"}}],
    "fips-mode-setup --check must report FIPS mode is enabled, grub2-editenv kernelopts must carry fips=1 and "
    "/proc/sys/crypto/fips_enabled must be 1",
    "Enable FIPS mode: fips-mode-setup --enable, then reboot",
    comment="fips-mode-setup --check, the kernelopts of grub2-editenv list, and /proc/sys/crypto/fips_enabled")

FIPS7 = ["SHA2-256", "SHA2-384", "SHA2-512", "SHA2-224", "SHA3-256", "SHA3-384", "SHA3-512"]
T.helpers("configuration_management", r'''
# the OL 8 crypto-policy hash set (OL 8 lists seven; SHAKE-256 is not required)
ol8_fips_policy_hashes := ''' + "{" + ", ".join(f'"{h}"' for h in FIPS7) + "}")
s = T.src["RHEL-09-215105"]
T.reuse("OL08-00-010182", "RHEL-09-215105",
        alts=[[a.replace("every h in fips_policy_hashes", "every h in ol8_fips_policy_hashes") for a in s["alts"][0]]],
        green={"crypto_policy": "FIPS", "crypto_policy_state": {"hash": FIPS7, "min_rsa_size": 2048}},
        bad=[{"crypto_policy": "FIPS:OSPP"}, {"crypto_policy_state": {"hash": FIPS7 + ["SHA1"]}},
             {"crypto_policy_state": {"hash": FIPS7[:-1]}}, {"crypto_policy_state": {"min_rsa_size": 1024}}],
        pass_cases=[{"crypto_policy_state": {"hash": FIPS7 + ["SHAKE-256"]}}],
        expect="update-crypto-policies --show must be FIPS; CURRENT.pol hash must include " + " ".join(FIPS7)
               + ", nothing with SHA1 or below 224 bits; min_rsa_size must be at least 2048")

T.R("pki_crypto", "OL08-00-010183", "crypto_policy_not_overridden", [("crypto_policy_check", "is_applied")],
    [['out := _str(["crypto_policy_check", "is_applied"])', 'ls := split(out, "\\n")', 'some l in ls',
      'trim_space(l) == "The configured policy is applied"']],
    {"crypto_policy_check": {"is_applied": "The configured policy is applied"}},
    [{"crypto_policy_check": {"is_applied": "The configured policy is NOT applied"}}],
    "update-crypto-policies --is-applied must report: The configured policy is applied",
    "Remove the overrides and run update-crypto-policies --set FIPS, then reboot",
    comment="output of update-crypto-policies --is-applied (OL 8; RHEL 9 runs --check and lists the back-ends)")

T.helpers("software_integrity", r'''
_ol8_str_val(v) := trim_space(v) if is_string(v)

_ol8_str_val(v) := format_int(v, 10) if {
	is_number(v)
	v == floor(v)
}''')
T.R("software_integrity", "OL08-00-010370", "all_repos_gpgcheck", [("yum_repos",)],
    [["repos := input.yum_repos", "is_array(repos)", "count(repos) > 0",
      'every r in repos {\n\t_ol8_str_val(object.get(r, "gpgcheck", null)) == "1"\n}']],
    {"yum_repos": [{"name": "ol8_baseos_latest", "gpgcheck": "1"}, {"name": "ol8_appstream", "gpgcheck": 1}]},
    [{"yum_repos": [{"name": "ol8_baseos_latest", "gpgcheck": "0"}]}, {"yum_repos": [{"name": "ol8_baseos_latest", "gpgcheck": "true"}]},
     {"yum_repos": [{"name": "ol8_baseos_latest"}]}, {"yum_repos": []}],
    "every repository in /etc/yum.repos.d/*.repo must set gpgcheck=1, or the SA must show an approved certificate "
    "validation process (input.attest.ol08_00_010370_gpg_process)",
    "Set gpgcheck=1 in every repository definition under /etc/yum.repos.d/",
    comment="input.yum_repos[{name, gpgcheck}]; OL 8 accepts only \"1\"; the ask-the-SA clause is an attestation",
    attest_alts=[['_attested("ol08_00_010370_gpg_process")']],
    pass_cases=[{"yum_repos": [{"name": "x", "gpgcheck": "0"}], "attest": {"ol08_00_010370_gpg_process": True}}])

T.helpers("software_integrity", r'''
_ol8_fpr(s) := upper(replace(s, " ", "")) if is_string(s)''')
T.R("software_integrity", "OL08-00-010019", "oracle_gpg_key",
    [("rpm_gpg_pubkeys",), ("oracle_release_key_file", "fingerprints")],
    [['"gpg(Oracle OSS group (Open Source Software group) <build@oss.oracle.com>)" in {trim_space(s) | some s in input.rpm_gpg_pubkeys; is_string(s)}',
      "fps := input.oracle_release_key_file.fingerprints", "is_array(fps)",
      '"76FD3DB13AB67410B89DB10E82562EA9AD986DA3" in {f | some x in fps; f := _ol8_fpr(x)}']],
    {"rpm_gpg_pubkeys": ["gpg(Oracle OSS group (Open Source Software group) <build@oss.oracle.com>)"],
     "oracle_release_key_file": {"fingerprints": ["76FD 3DB1 3AB6 7410 B89D  B10E 8256 2EA9 AD98 6DA3"]}},
    [{"rpm_gpg_pubkeys": ["gpg(Not Oracle OSS group (Open Source Software group) <build@oss.oracle.com>)"]},
     {"oracle_release_key_file": {"fingerprints": ["76FD 3DB1 3AB6 7410 B89D  B10E 8256 2EA9 AD98 6DA4"]}}],
    "the Oracle OSS group GPG key must be installed and /etc/pki/rpm-gpg/RPM-GPG-KEY-oracle must carry fingerprint "
    "76FD3DB13AB67410B89DB10E82562EA9AD986DA3",
    "Install the Oracle signing key: rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY-oracle (verify the fingerprint first)",
    comment="rpm -q --queryformat \"%{SUMMARY}\" gpg-pubkey and gpg --with-fingerprint /etc/pki/rpm-gpg/RPM-GPG-KEY-oracle")

# ── faillock (OL 8.2 and above; 8.0 / 8.1 are Not Applicable) ────────────────────────────────────────────────
T.helpers("account_auth", r'''
# OL 8.0 or 8.1 (input.os_release.version_id, e.g. "8.1"): the faillock.conf checks do not apply
_ol8_before_8_2 if {
	v := _str(["os_release", "version_id"])
	m := regex.find_all_string_submatch_n(`^8\.([0-9]+)$`, v, 1)
	minor := to_number(m[0][1])
	minor < 2
}

# every value of an option in /etc/security/pwquality.conf and pwquality.conf.d/*.conf (input.pwquality_values[<opt>],
# one entry per uncommented line), as numbers; undefined unless every entry is a decimal integer
_pwq(opt) := ns if {
	vs := input.pwquality_values[opt]
	is_array(vs)
	ns := [n | some v in vs; n := _num_val(v)]
	count(ns) == count(vs)
}

_num_val(v) := v if {
	is_number(v)
	v == floor(v)
}

_num_val(v) := to_number(trim_space(v)) if {
	is_string(v)
	regex.match(`^\s*-?[0-9]+\s*$`, v)
}''')
NA82 = dict(na=[["_ol8_before_8_2"]], na_expect="the system is OL 8.0 or 8.1 (this check applies to 8.2 and above)")
T.reuse("OL08-00-020011", "RHEL-09-411075", na_cases=[{"faillock_conf": {"deny": None}, "os_release": {"version_id": "8.1"}}], **NA82)
s = T.src["RHEL-09-411085"]
T.reuse("OL08-00-020013", "RHEL-09-411085",
        alts=[['n := _num(["faillock_conf", "fail_interval"])', "n >= 900"]],
        bad=[{"faillock_conf": {"fail_interval": 600}}, {"faillock_conf": {"fail_interval": "900s"}}],
        pass_cases=[{"faillock_conf": {"fail_interval": 1800}}],
        na_cases=[{"faillock_conf": {"fail_interval": None}, "os_release": {"version_id": "8.0"}}],
        expect="fail_interval in /etc/security/faillock.conf must be 900 or more (OL 8's finding: not set to 900 or more)",
        comment="fail_interval in /etc/security/faillock.conf; OL 8 requires 900 or MORE (RHEL 9: 900 or less); 8.0/8.1 N/A",
        **NA82)

# V2R10 check text for the credits: only "a positive number or is commented out" is a finding, so the limit is 0
# (0 and negative values pass) while the fix and the green fixture stay at -1
for sid, opt, name, op, want, limit, bad in [
    ("OL08-00-020230", "minlen", "password_min_length", ">=", 15, 15, 8),
    ("OL08-00-020110", "ucredit", "password_ucredit", "<=", -1, 0, 1),
    ("OL08-00-020120", "lcredit", "password_lcredit", "<=", -1, 0, 1),
    ("OL08-00-020130", "dcredit", "password_dcredit", "<=", -1, 0, 1),
    ("OL08-00-020280", "ocredit", "password_ocredit", "<=", -1, 0, 1),
]:
    T.R("account_auth", sid, name, [("pwquality_values", opt)],
        [[f'ns := _pwq("{opt}")', "count(ns) > 0", f"every n in ns {{\n\tis_number(n)\n\tn {op} {limit}\n}}", "count({n | some n in ns}) == 1"]],
        {"pwquality_values": {opt: [str(want)]}},
        [{"pwquality_values": {opt: [str(bad)]}}, {"pwquality_values": {opt: []}},
         {"pwquality_values": {opt: [str(want), str(want - 1 if op == ">=" else want - 1)]}} if op == "<=" else
         {"pwquality_values": {opt: [str(want), str(want + 1)]}},
         {"pwquality_values": {opt: ["x"]}}],
        f"{opt} must be {op} {limit} on every uncommented {opt} line of /etc/security/pwquality.conf*, with no conflicting values",
        f"Set {opt} = {want} in /etc/security/pwquality.conf and remove other {opt} lines",
        comment=f"every {opt} = value line found by grep -r {opt} /etc/security/pwquality.conf* (conflicting results are a finding)",
        **({"pass_cases": [{"pwquality_values": {opt: ["0"]}}]} if op == "<=" else {}))

# ── sshd settings: every uncommented line in the files sshd reads; conflicting results are a finding ──────────
T.helpers("ssh_config", r'''
# input.sshd_config_lines[<Keyword>]: the value of every uncommented <Keyword> line in the files sshd reads
# (sshd -dd ... | xargs grep -iH), lower-cased; [] when the keyword is not set
_ssh_vals(kw) := [lower(trim_space(v)) | some v in input.sshd_config_lines[kw]; is_string(v)]''')


def ssh(sid, kw, name, cond, green, bads, expect, fix, comment, allow_absent=False, **kw2):
    alt = [f'vals := _ssh_vals("{kw}")', f'count(vals) == count(input.sshd_config_lines["{kw}"])']
    if not allow_absent:
        alt.append("count(vals) > 0")
    alt += [f"every v in vals {{\n\t{cond}\n}}", "count({v | some v in vals}) <= 1"]
    T.R("ssh_config", sid, name, [("sshd_config_lines", kw)], [alt],
        {"sshd_config_lines": {kw: green}}, [{"sshd_config_lines": {kw: b}} for b in bads],
        expect, fix, comment=comment, **kw2)


ssh("OL08-00-010550", "PermitRootLogin", "ssh_no_root_login", 'v == "no"', ["no"], [["yes"], [], ["no", "yes"], ["prohibit-password"]],
    "PermitRootLogin must be no on every line sshd reads (none conflicting)", "Set PermitRootLogin no in /etc/ssh/sshd_config",
    "OL 8's finding names yes / missing / commented out and conflicting results; expected output and fix are 'no'")
ssh("OL08-00-010500", "StrictModes", "ssh_strict_modes", 'v == "yes"', ["yes"], [["no"], [], ["yes", "no"]],
    "StrictModes must be yes (set, not no, none conflicting)", "Set StrictModes yes in /etc/ssh/sshd_config",
    "StrictModes lines sshd reads")
ssh("OL08-00-010520", "IgnoreUserKnownHosts", "ssh_ignore_user_known_hosts", 'v == "yes"', ["yes"], [["no"], [], ["yes", "no"]],
    "IgnoreUserKnownHosts must be yes (none conflicting)", "Set IgnoreUserKnownHosts yes in /etc/ssh/sshd_config",
    "IgnoreUserKnownHosts lines sshd reads")
ssh("OL08-00-020350", "PrintLastLog", "ssh_print_last_log", 'v == "yes"', ["yes"], [["no"], [], ["yes", "no"]],
    "PrintLastLog must be yes (set, not no, none conflicting)", "Set PrintLastLog yes in /etc/ssh/sshd_config",
    "PrintLastLog lines sshd reads")
ssh("OL08-00-020330", "PermitEmptyPasswords", "ssh_no_empty_passwords", 'v == "no"', ["no"], [["yes"], ["no", "yes"]],
    "PermitEmptyPasswords must not be yes (none conflicting)", "Set PermitEmptyPasswords no in /etc/ssh/sshd_config",
    "OL 8's finding is only 'set to yes' or conflicting results: an unset keyword (sshd default no) passes",
    allow_absent=True, pass_cases=[{"sshd_config_lines": {"PermitEmptyPasswords": []}}])
ssh("OL08-00-040340", "X11Forwarding", "ssh_x11_disabled", 'v == "no"', ["no"], [["yes"], [], ["no", "yes"]],
    "X11Forwarding must be no (set, none conflicting), or its use documented with the ISSO (input.attest.ol08_00_040340_x11_documented)",
    "Set X11Forwarding no in /etc/ssh/sshd_config", "X11Forwarding lines sshd reads",
    attest_alts=[['_attested("ol08_00_040340_x11_documented")']],
    pass_cases=[{"sshd_config_lines": {"X11Forwarding": ["yes"]}, "attest": {"ol08_00_040340_x11_documented": True}}])
# V2R10 check text: "600" or less (0 is not excluded); digits only, so a negative value stays a finding
ssh("OL08-00-010201", "ClientAliveInterval", "ssh_client_alive_interval_ok",
    'regex.match(`^[0-9]+$`, v)\n\tto_number(v) <= 600', ["600"], [["601"], ["-1"], [], ["300", "600"], ["10m"]],
    "ClientAliveInterval must be 600 or less on every line sshd reads, none conflicting",
    "Set ClientAliveInterval 600 in /etc/ssh/sshd_config", "ClientAliveInterval lines sshd reads",
    pass_cases=[{"sshd_config_lines": {"ClientAliveInterval": ["0"]}}])
ssh("OL08-00-010200", "ClientAliveCountMax", "ssh_client_alive_count_ok", 'v == "1"', ["1"], [["0"], ["3"], [], ["1", "3"]],
    "ClientAliveCountMax must be 1 (none conflicting)", "Set ClientAliveCountMax 1 in /etc/ssh/sshd_config",
    "ClientAliveCountMax lines sshd reads")

# the SSH banner: Banner names one file (no conflicting lines) whose text is the DoW banner
T.R("configuration_management", "OL08-00-010040", "ssh_banner_set", [("sshd_config_lines", "Banner"), ("ssh_banner_file", "text")],
    ['vals := [trim_space(v) | some v in input.sshd_config_lines.Banner; is_string(v)]'.split("\n") +
     ["count(vals) > 0", "count({v | some v in vals}) == 1", 'not lower(vals[0]) == "none"',
      's := _str(["ssh_banner_file", "text"])', "_squash(s) == dod_banner"]],
    {"sshd_config_lines": {"Banner": ["/etc/issue"]}, "ssh_banner_file": {"text": rhel9_rules.RULES["RHEL-09-211020"]["green"]["login_banner"]["issue"]}},
    [{"sshd_config_lines": {"Banner": []}}, {"sshd_config_lines": {"Banner": ["/etc/issue", "/etc/issue.net"]}},
     {"ssh_banner_file": {"text": "Authorized users only."}}],
    "sshd must name one banner file (Banner, no conflicting lines) whose text is the Standard Mandatory DoW Notice and Consent Banner",
    "Set Banner /etc/issue in /etc/ssh/sshd_config and put the DoW banner text in that file",
    comment="input.sshd_config_lines.Banner (every Banner line sshd reads) and input.ssh_banner_file.text (the file it names)")

# ── file systems: OL 8 reads /etc/fstab (input.fstab[{mount_point, fs_type, options}], uncommented entries) ─────
T.helpers("configuration_management", r'''
_fstab_entry(mp) := e if {
	entries := input.fstab
	is_array(entries)
	some e in entries
	e.mount_point == mp
}

# the fstab entry's options as exact tokens
_fstab_opts(e) := {o | some x in parts; o := trim_space(x)} if {
	is_string(e.options)
	parts := split(e.options, ",")
}''')
FSTAB = [{"mount_point": "/", "fs_type": "xfs", "options": "defaults"},
         {"mount_point": "/tmp", "fs_type": "xfs", "options": "defaults,nodev,nosuid,noexec"},
         {"mount_point": "/var/log", "fs_type": "xfs", "options": "defaults,nodev,nosuid,noexec"},
         {"mount_point": "/var/log/audit", "fs_type": "ext4", "options": "defaults"},
         {"mount_point": "/home", "fs_type": "ext4", "options": "rw,relatime,discard,data=ordered,nosuid,nodev,noexec"}]
for sid, mp, name in [("OL08-00-010543", "/tmp", "tmp_separate_partition"), ("OL08-00-010541", "/var/log", "var_log_separate")]:
    T.R("configuration_management", sid, name, [("fstab",)], [[f'_fstab_entry("{mp}")']],
        {"fstab": FSTAB}, [{"fstab": [e for e in FSTAB if e["mount_point"] != mp]}],
        f"/etc/fstab must have a separate entry for {mp}", f"Create a separate file system for {mp} and add it to /etc/fstab",
        comment=f"an uncommented /etc/fstab entry mounting {mp} (grep {mp} /etc/fstab)")
T.R("configuration_management", "OL08-00-010542", "var_log_audit_separate", [("fstab",), ("auditd_config", "log_file")],
    [['f := _str(["auditd_config", "log_file"])', 'dir := regex.replace(f, `/[^/]*$`, "")', "_fstab_entry(dir)"]],
    {"fstab": FSTAB, "auditd_config": {"log_file": "/var/log/audit/audit.log"}},
    [{"fstab": [e for e in FSTAB if e["mount_point"] != "/var/log/audit"]}],
    "/etc/fstab must have an entry for the audit data path (the directory of auditd log_file), or the SA must show the "
    "audit logs are written to another file system (input.attest.ol08_00_010542_other_partition)",
    "Create a separate file system for the audit data path and add it to /etc/fstab",
    comment="the directory of auditd log_file must have its own /etc/fstab entry; the ask-the-SA clause is an attestation",
    attest_alts=[['_attested("ol08_00_010542_other_partition")']],
    pass_cases=[{"fstab": FSTAB[:3], "attest": {"ol08_00_010542_other_partition": True}}])
for sid, opt, name in [("OL08-00-010570", "nosuid", "home_nosuid"), ("OL08-00-010590", "noexec", "home_noexec")]:
    T.R("configuration_management", sid, name, [("fstab",), ("home_dir_mount_points",)],
        [["mps := input.home_dir_mount_points", "is_array(mps)", "count(mps) > 0",
          f'every mp in mps {{\n\te := _fstab_entry(mp)\n\t"{opt}" in _fstab_opts(e)\n}}']],
        {"fstab": FSTAB, "home_dir_mount_points": ["/home"]},
        [{"fstab": FSTAB[:4] + [{"mount_point": "/home", "fs_type": "ext4", "options": "rw,nodev"}]},
         {"fstab": FSTAB[:4] + [{"mount_point": "/home", "fs_type": "ext4", "options": f"rw,no{opt}x"}]},
         {"home_dir_mount_points": ["/"]}, {"home_dir_mount_points": []}],
        f"every /etc/fstab file system holding interactive users' home directories must carry the {opt} option",
        f"Add {opt} to the /etc/fstab options of the file system holding /home",
        comment="input.home_dir_mount_points: the fstab mount points holding the home directories of users with UID >= 1000 "
                "(not nobody); each entry's options must include the option")

# ── services / packages / misc ────────────────────────────────────────────────────────────────────────────────
T.R("services", "OL08-00-040190", "tftp_server_absent", [("packages", "tftp-server")],
    [['input.packages["tftp-server"] == false']],
    {"packages": {"tftp-server": False}}, [{"packages": {"tftp-server": True}}],
    "the tftp-server package must not be installed, or its requirement documented with the ISSO "
    "(input.attest.ol08_00_040190_tftp_documented)", "Remove the TFTP server: yum remove tftp-server",
    comment="yum list installed tftp-server",
    attest_alts=[['_attested("ol08_00_040190_tftp_documented")']],
    pass_cases=[{"packages": {"tftp-server": True}, "attest": {"ol08_00_040190_tftp_documented": True}}])
T.R("services", "OL08-00-040360", "ftp_server_absent", [("ftpd_packages",)],
    [["pk := input.ftpd_packages", "is_array(pk)", "count(pk) == 0"]],
    {"ftpd_packages": []}, [{"ftpd_packages": ["vsftpd"]}],
    "no FTP server package may be installed (yum list installed | grep ftpd), unless documented with the ISSO "
    "(input.attest.ol08_00_040360_ftp_documented)", "Remove the FTP server: yum remove vsftpd",
    comment="input.ftpd_packages: installed package names matching ftpd",
    attest_alts=[['_attested("ol08_00_040360_ftp_documented")']],
    pass_cases=[{"ftpd_packages": ["vsftpd"], "attest": {"ol08_00_040360_ftp_documented": True}}])
T.R("services", "OL08-00-040002", "sendmail_absent", [("packages", "sendmail")], [["input.packages.sendmail == false"]],
    {"packages": {"sendmail": False}}, [{"packages": {"sendmail": True}}],
    "the sendmail package must not be installed", "Remove sendmail: yum remove sendmail",
    comment="yum list installed sendmail")
T.R("software_integrity", "OL08-00-010561", "rsyslog_active", [("services", "rsyslog"), ("unit_enabled", "rsyslog")],
    [['_kw(["services", "rsyslog"]) == "active"', '_kw(["unit_enabled", "rsyslog"]) == "enabled"']],
    {"services": {"rsyslog": "active"}, "unit_enabled": {"rsyslog": "enabled"}},
    [{"services": {"rsyslog": "inactive"}}, {"unit_enabled": {"rsyslog": "disabled"}}],
    "rsyslog must be enabled and active (systemctl is-enabled / is-active rsyslog)", "systemctl enable --now rsyslog",
    comment="systemctl is-enabled rsyslog and systemctl is-active rsyslog")
T.R("audit_logging", "OL08-00-030040", "disk_error_action_ok", [("auditd_config", "disk_error_action")],
    [['_kw(["auditd_config", "disk_error_action"]) in {"syslog", "single", "halt"}']],
    {"auditd_config": {"disk_error_action": "HALT"}}, [{"auditd_config": {"disk_error_action": "IGNORE"}}],
    "disk_error_action in /etc/audit/auditd.conf must be SYSLOG, SINGLE or HALT",
    "Set disk_error_action = HALT in /etc/audit/auditd.conf", comment="grep disk_error_action /etc/audit/auditd.conf")
T.R("configuration_management", "OL08-00-010140", "grub_uefi_password_set", [("grub", "efi_user_cfg_password")],
    [['s := _str(["grub", "efi_user_cfg_password"])', 'startswith(s, "grub.pbkdf2.sha512")']],
    {"grub": {"efi_user_cfg_password": "grub.pbkdf2.sha512.10000.ABCD"}}, [{"grub": {"efi_user_cfg_password": "plaintext"}}],
    "GRUB2_PASSWORD in /boot/efi/EFI/redhat/user.cfg must begin with grub.pbkdf2.sha512",
    "Set a grub superuser password with grub2-setpassword", comment="GRUB2_PASSWORD in /boot/efi/EFI/redhat/user.cfg (UEFI)",
    na=[['_kw(["boot_firmware"]) == "bios"']], na_expect="the system boots with a BIOS",
    na_cases=[{"grub": {"efi_user_cfg_password": None}, "boot_firmware": "bios"}])
T.R("configuration_management", "OL08-00-040171", "ctrl_alt_del_graphical_disabled", [("dconf_local", "logout")],
    [["vals := input.dconf_local.logout", "is_array(vals)", "count(vals) > 0",
      "every v in vals {\n\tis_string(v)\n\ttrim_space(v) == \"''\"\n}"]],
    {"dconf_local": {"logout": ["''"]}}, [{"dconf_local": {"logout": []}}, {"dconf_local": {"logout": ["'<Control><Alt>Delete'"]}}],
    "logout='' must be set (uncommented) in /etc/dconf/db/local.d/* (no key bound)",
    "Set logout='' under [org/gnome/settings-daemon/plugins/media-keys] in /etc/dconf/db/local.d/ and run dconf update",
    comment="input.dconf_local.logout: values of uncommented logout= lines in /etc/dconf/db/local.d/*; the rule title "
            "applies it only when a GUI is installed (input.gui_installed == false is Not Applicable)",
    na=[["input.gui_installed == false"]], na_expect="no graphical user interface is installed",
    na_cases=[{"dconf_local": {"logout": None}, "gui_installed": False}])
s = T.src["RHEL-09-232010"]   # OL 8's find omits /usr/libexec
T.R("file_permissions", "OL08-00-010300", "sys_commands_permissions_ok", [("file_permissions", "system_commands_group_or_world_writable")],
    [['xs := object.get(input, ["file_permissions", "system_commands_group_or_world_writable"], null)', "is_array(xs)",
      "count([x | some x in xs; not _in_libexec(x)]) == 0"]],
    {"file_permissions": {"system_commands_group_or_world_writable": []}},
    [{"file_permissions": {"system_commands_group_or_world_writable": ["-rwxrwxr-x 1 root root 1024 Jan 1 /usr/bin/foo"]}}],
    "no system command in /bin, /sbin, /usr/bin, /usr/sbin, /usr/local/bin, /usr/local/sbin may be group- or world-writable",
    "chmod go-w on each file the find command lists",
    comment="the RHEL 9 offender list (find -perm /022 incl. /usr/libexec); OL 8 does not search /usr/libexec, so those entries are ignored",
    pass_cases=[{"file_permissions": {"system_commands_group_or_world_writable": ["/usr/libexec/foo"]}}])
T.helpers("file_permissions", r'''
# an offender under /usr/libexec (a path, or an ls -l line ending in one)
_in_libexec(x) if {
	is_string(x)
	regex.match(`(^|\s)/usr/libexec/`, x)
}''')
s = T.src["RHEL-09-232050"]   # OL 8 selects UID >= 1000 except nobody (RHEL 9: UID >= 1000 without a nologin shell)
_h = {k: json.loads(json.dumps(s[k]).replace("interactive_home_dirs", "home_dirs_uid_1000")) for k in ("alts", "green", "bad", "pass_cases")}
T.reuse("OL08-00-010730", "RHEL-09-232050", **_h,
        ev=[("file_permissions", "home_dirs_uid_1000")],
        expect="the home directory of every UID >= 1000 user except nobody must have mode 0750 or less permissive",
        comment="input.file_permissions.home_dirs_uid_1000 [{path, mode}]: users with UID >= 1000 other than nobody "
                "(OL 8's awk; RHEL 9 excludes nologin shells instead)")

RULES, SECTION_HELPERS = T.finish()
OWN_HELPERS = T.extra
