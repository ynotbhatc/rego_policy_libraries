"""Reviewed logic table for gen_rhel9.py (DISA STIG for RHEL 9, V2R10).

A spec (see R below):
  sec     : section module          name  : the rule's boolean (kept from the hand-maintained module)
  ev      : evidence paths that must be collected (else Open "evidence missing")
  alts    : alternative bodies (OR), each a list of Rego lines (AND), evaluated only with all evidence present
  attest_alts : bodies that pass on an attestation alone (the check's "ask the SA ..." clause)
  na / na_expect / na_cases : the check text's Not Applicable clause, as explicit evidence
  green   : fixture patch that passes      bad : list of patches (object.union onto green) that fail
  expect  : what the check requires (the Open detail)      fix : fix text      kind : machine | machine+attestation
Every rule the hand-maintained module implemented (104 of 445) is here; the block order in each module follows this file.
"""

SECTION_HELPERS = {"file_permissions": r'''# Parse an octal permission string ("644", "0644", "0o644") to an integer; undefined if not octal.
octal(s) := n if {
	t := trim_prefix(lower(trim_space(sprintf("%v", [s]))), "0o")
	regex.match(`^[0-7]{1,4}$`, t)
	p := concat("", [substring("0000", 0, 4 - count(t)), t])
	ds := [to_number(substring(p, i, 1)) | some i in numbers.range(0, 3)]
	n := ((ds[0] * 512) + (ds[1] * 64)) + ((ds[2] * 8) + ds[3])
}

# true when mode grants nothing beyond max (both octal strings)
mode_within(mode, max) if bits.and(octal(mode), bits.and(bits.negate(octal(max)), 4095)) == 0'''}
RULES = {}


def helpers(sec, text):
    SECTION_HELPERS[sec] = (SECTION_HELPERS.get(sec, "").strip() + "\n\n" + text.strip()).strip()


def R(sec, sid, name, ev, alts, green, bad, expect, fix, comment="", kind="machine", attest_alts=(), na=(),
      na_expect="", na_cases=(), pass_cases=(), num_items=()):
    assert sid not in RULES, f"{sid} defined twice"
    if attest_alts and kind == "machine":
        kind = "machine+attestation"
    RULES[sid] = dict(sec=sec, name=name, ev=[tuple(e) for e in ev], alts=alts, green=green, bad=list(bad),
                      expect=expect, fix=fix, comment=comment, kind=kind,
                      attest_alts=list(attest_alts), na=list(na), na_expect=na_expect, na_cases=list(na_cases),
                      pass_cases=list(pass_cases), num_items=list(num_items))


# ═════════════════════════════════════════════════════════════════════════════════════════════════
# CAT I (reviewed 2026-11-18 against the V2R10 check text)
# ═════════════════════════════════════════════════════════════════════════════════════════════════

FIPS_HASHES = ["SHA2-256", "SHA2-384", "SHA2-512", "SHA2-224", "SHA3-256", "SHA3-384", "SHA3-512", "SHAKE-256"]

R("configuration_management", "RHEL-09-211050", "ctrl_alt_del_disabled",
  [("systemd_units", "ctrl-alt-del.target", "load_state")],
  [['_kw(["systemd_units", "ctrl-alt-del.target", "load_state"]) == "masked"']],
  {"systemd_units": {"ctrl-alt-del.target": {"load_state": "masked"}}},
  [{"systemd_units": {"ctrl-alt-del.target": {"load_state": "loaded"}}}],
  "ctrl-alt-del.target must be masked (systemctl status: Loaded: masked)",
  "Mask the target: systemctl disable --now ctrl-alt-del.target && systemctl mask ctrl-alt-del.target",
  comment="ctrl-alt-del.target load state (systemctl show -p LoadState) must be masked")

R("configuration_management", "RHEL-09-431010", "selinux_enforcing",
  [("selinux", "getenforce"), ("selinux", "config_selinux")],
  [['_kw(["selinux", "getenforce"]) == "enforcing"', '_kw(["selinux", "config_selinux"]) == "enforcing"']],
  {"selinux": {"getenforce": "Enforcing", "config_selinux": "enforcing"}},
  [{"selinux": {"getenforce": "Permissive"}}, {"selinux": {"config_selinux": "permissive"}}],
  "getenforce must return Enforcing and /etc/selinux/config must set SELINUX=enforcing",
  "Set SELINUX=enforcing in /etc/selinux/config and run setenforce 1",
  comment="SELinux enforcing at runtime (getenforce) and at boot (SELINUX= in /etc/selinux/config)")

R("configuration_management", "RHEL-09-671010", "fips_mode_enabled",
  [("fips", "fips_enabled")],
  [['_str(["fips", "fips_enabled"]) == "1"']],
  {"fips": {"fips_enabled": "1"}},
  [{"fips": {"fips_enabled": "0"}}],
  "/proc/sys/crypto/fips_enabled must contain 1",
  "Enable FIPS mode: fips-mode-setup --enable, then reboot",
  comment="content of /proc/sys/crypto/fips_enabled must be 1")

helpers("configuration_management", r'''
# FIPS 140-3 hash set the crypto-policy check requires in /etc/crypto-policies/state/CURRENT.pol
fips_policy_hashes := ''' + "{" + ", ".join(f'"{h}"' for h in FIPS_HASHES) + "}" + r'''

# a hash the crypto-policy check rejects: SHA1 (or MD5), or a digest size below 224
_weak_hash(h) if not is_string(h)

_weak_hash(h) if {
	is_string(h)
	u := upper(h)
	contains(u, "SHA1")
}

_weak_hash(h) if {
	is_string(h)
	u := upper(h)
	contains(u, "MD5")
}

_weak_hash(h) if {
	is_string(h)
	m := regex.find_all_string_submatch_n(`-([0-9]+)$`, h, 1)
	bits := to_number(m[0][1])
	bits < 224
}''')

R("configuration_management", "RHEL-09-215105", "crypto_policy_fips",
  [("crypto_policy",), ("crypto_policy_state", "hash"), ("crypto_policy_state", "min_rsa_size")],
  [['_str(["crypto_policy"]) == "FIPS"',
    "hashes := input.crypto_policy_state.hash",
    "is_array(hashes)",
    "every h in fips_policy_hashes {\n\th in hashes\n}",
    "count([h | some h in hashes; _weak_hash(h)]) == 0",
    '_num(["crypto_policy_state", "min_rsa_size"]) >= 2048']],
  {"crypto_policy": "FIPS", "crypto_policy_state": {"hash": FIPS_HASHES, "min_rsa_size": 2048}},
  [{"crypto_policy": "FIPS:OSPP"}, {"crypto_policy": "DEFAULT"},
   {"crypto_policy_state": {"hash": FIPS_HASHES + ["SHA1"]}},
   {"crypto_policy_state": {"hash": FIPS_HASHES[:-1]}},
   {"crypto_policy_state": {"hash": FIPS_HASHES + ["SHAKE-128"]}},
   {"crypto_policy_state": {"min_rsa_size": 1024}}, {"crypto_policy_state": {"min_rsa_size": "2048 bits"}},
   {"crypto_policy_state": {"min_rsa_size": "3072"}}],
  "update-crypto-policies --show must be FIPS; CURRENT.pol hash must include " + " ".join(FIPS_HASHES)
  + ", nothing with SHA1 or below 224 bits; min_rsa_size must be at least 2048",
  "Set the FIPS policy: update-crypto-policies --set FIPS, then reboot",
  comment="systemwide crypto policy FIPS; CURRENT.pol hash list and min_rsa_size",
  pass_cases=[{"crypto_policy_state": {"min_rsa_size": 3072}}])

helpers("pki_crypto", r'''
# a crypto back-end in /etc/crypto-policies/back-ends/: nss.config is a regular file; every other one is a
# symlink to its own file under /usr/share/crypto-policies/FIPS/ (bind.config -> FIPS/bind.txt)
_backend_ok(b) if {
	b.name == "nss.config"
	b.is_symlink == false
}

_backend_ok(b) if {
	is_string(b.name)
	b.name != "nss.config"
	b.is_symlink == true
	base := trim_suffix(b.name, ".config")
	b.target == concat("", ["/usr/share/crypto-policies/FIPS/", base, ".txt"])
}''')

R("pki_crypto", "RHEL-09-672020", "crypto_policy_not_overridden",
  [("crypto_policy_check", "output"), ("crypto_backends",)],
  [['out := _str(["crypto_policy_check", "output"])',
    'contains(out, "The configured policy matches the generated policy")',
    'not contains(out, "does NOT match")',
    "backends := input.crypto_backends",
    "is_array(backends)",
    "count(backends) > 0",
    "count([b | some b in backends; not _backend_ok(b)]) == 0"]],
  {"crypto_policy_check": {"output": "The configured policy matches the generated policy"},
   "crypto_backends": [{"name": "openssh.config", "is_symlink": True, "target": "/usr/share/crypto-policies/FIPS/openssh.txt"},
                       {"name": "opensslcnf.config", "is_symlink": True, "target": "/usr/share/crypto-policies/FIPS/opensslcnf.txt"},
                       {"name": "nss.config", "is_symlink": False, "target": None}]},
  [{"crypto_policy_check": {"output": "The configured policy does NOT match the generated policy"}},
   {"crypto_backends": [{"name": "openssh.config", "is_symlink": True, "target": "/usr/share/crypto-policies/DEFAULT/openssh.txt"}]},
   {"crypto_backends": [{"name": "openssh.config", "is_symlink": False, "target": None}]},
   {"crypto_backends": [{"name": "nss.config", "is_symlink": True, "target": "/usr/share/crypto-policies/FIPS/nss.txt"}]},
   {"crypto_backends": []}],
  "update-crypto-policies --check must report the configured policy matches the generated policy, and every "
  "back-end in /etc/crypto-policies/back-ends/ except nss.config must link to its file under /usr/share/crypto-policies/FIPS/",
  "Remove overrides and regenerate: update-crypto-policies --set FIPS",
  comment="update-crypto-policies --check output and the back-end symlinks (input.crypto_backends[{name, is_symlink, target}])")

R("pki_crypto", "RHEL-09-672055", "openssl_system_policy",
  [("openssl_cnf", "lines")],
  [["lines := input.openssl_cnf.lines", "is_array(lines)", "some l in lines",
    r"regex.match(`^\s*\.include\s*=?\s*/etc/crypto-policies/back-ends/opensslcnf\.config\s*$`, l)"]],
  {"openssl_cnf": {"lines": ["[ crypto_policy ]", ".include = /etc/crypto-policies/back-ends/opensslcnf.config"]}},
  [{"openssl_cnf": {"lines": ["# .include = /etc/crypto-policies/back-ends/opensslcnf.config"]}},
   {"openssl_cnf": {"lines": [".include = /etc/pki/tls/other.cnf"]}}],
  "/etc/pki/tls/openssl.cnf must include /etc/crypto-policies/back-ends/opensslcnf.config (uncommented)",
  "Add .include = /etc/crypto-policies/back-ends/opensslcnf.config to /etc/pki/tls/openssl.cnf",
  comment="the lines of /etc/pki/tls/openssl.cnf must include the crypto-policy opensslcnf.config back-end")

R("services", "RHEL-09-215060", "tftp_secure_mode",
  [("packages", "tftp-server")],
  [['input.packages["tftp-server"] == true', 's := _str(["tftp", "execstart"])', r"regex.match(`(^|\s)-s(\s|$)`, s)"]],
  {"packages": {"tftp-server": True}, "tftp": {"execstart": "/usr/sbin/in.tftpd -s /var/lib/tftpboot"}},
  [{"tftp": {"execstart": "/usr/sbin/in.tftpd /var/lib/tftpboot"}}, {"tftp": {"execstart": None}}],
  "tftp-server is installed: the ExecStart of tftp.service (input.tftp.execstart) must run in.tftpd with -s",
  "Remove tftp-server (dnf remove tftp-server) or set ExecStart=/usr/sbin/in.tftpd -s /var/lib/tftpboot",
  comment="if tftp-server is installed, tftp.service ExecStart must carry -s; not installed is Not Applicable",
  na=[['input.packages["tftp-server"] == false']],
  na_expect="tftp-server is not installed",
  na_cases=[{"packages": {"tftp-server": False}}])

R("services", "RHEL-09-215015", "ftp_server_disabled",
  [("packages", "vsftpd")],
  [["input.packages.vsftpd == false"]],
  {"packages": {"vsftpd": False}},
  [{"packages": {"vsftpd": True}}],
  "the vsftpd package must not be installed",
  "Remove the FTP server: dnf remove vsftpd",
  comment="the vsftpd package must not be installed (input.packages.vsftpd == false)")

GPG_ATTEST = "a process to verify the GPG signatures of software packages is approved by the organization"
R("software_integrity", "RHEL-09-214025", "all_repos_gpgcheck",
  [("yum_repos",)],
  [["repos := input.yum_repos", "is_array(repos)", "count(repos) > 0",
    'every r in repos {\n\t_truthy(object.get(r, "gpgcheck", null))\n}']],
  {"yum_repos": [{"file": "/etc/yum.repos.d/redhat.repo", "name": "rhel-9-for-x86_64-baseos-rpms", "gpgcheck": "1"}]},
  [{"yum_repos": [{"file": "/etc/yum.repos.d/redhat.repo", "name": "rhel-9-for-x86_64-baseos-rpms", "gpgcheck": "0"}]},
   {"yum_repos": [{"file": "/etc/yum.repos.d/local.repo", "name": "local"}]},
   {"yum_repos": []}],
  "every repository in /etc/yum.repos.d/*.repo must set gpgcheck to 1, true or yes, or an approved GPG "
  "verification process must be attested (input.attest.rhel_09_214025_gpg_process)",
  "Set gpgcheck=1 in every repository definition under /etc/yum.repos.d/",
  comment="gpgcheck as written in each /etc/yum.repos.d/*.repo section (input.yum_repos[{file, name, gpgcheck}])",
  attest_alts=[['_attested("rhel_09_214025_gpg_process")']],
  pass_cases=[{"yum_repos": [{"name": "a", "gpgcheck": "Yes"}, {"name": "b", "gpgcheck": "TRUE"}]},
              {"yum_repos": [{"name": "a", "gpgcheck": "0"}], "attest": {"rhel_09_214025_gpg_process": True}}])

R("software_integrity", "RHEL-09-214020", "localpkg_gpgcheck",
  [("dnf_config", "localpkg_gpgcheck")],
  [["_truthy(input.dnf_config.localpkg_gpgcheck)"]],
  {"dnf_config": {"localpkg_gpgcheck": "1"}},
  [{"dnf_config": {"localpkg_gpgcheck": "0"}}, {"dnf_config": {"localpkg_gpgcheck": "False"}}],
  "localpkg_gpgcheck in /etc/dnf/dnf.conf must be 1, true or yes, or an approved GPG verification process must "
  "be attested (input.attest.rhel_09_214020_gpg_process)",
  "Set localpkg_gpgcheck=1 in /etc/dnf/dnf.conf",
  comment="localpkg_gpgcheck as written in /etc/dnf/dnf.conf",
  attest_alts=[['_attested("rhel_09_214020_gpg_process")']],
  pass_cases=[{"dnf_config": {"localpkg_gpgcheck": "True"}}])

SSH_CIPHERS = "aes256-gcm@openssh.com,aes256-ctr,aes128-gcm@openssh.com,aes128-ctr"
SSH_MACS = "hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512"
helpers("ssh_config", r'''
# DISA's lists for the opensshserver crypto-policy back-end (RHEL-09-255065 / RHEL-09-255075)
fips_ssh_ciphers := ''' + "{" + ", ".join(f'"{c}"' for c in SSH_CIPHERS.split(",")) + "}" + r'''

fips_ssh_macs := ''' + "{" + ", ".join(f'"{c}"' for c in SSH_MACS.split(",")) + "}" + r'''

# the comma-separated list at path, each entry trimmed; undefined unless a string
_csv(path) := [trim_space(x) | some x in parts] if {
	s := _str(path)
	parts := split(s, ",")
}''')

for sid, key, allowed, setname, extra in (("RHEL-09-255065", "Ciphers", SSH_CIPHERS, "fips_ssh_ciphers", "aes192-ctr"),
                                          ("RHEL-09-255075", "MACs", SSH_MACS, "fips_ssh_macs", "hmac-sha1")):
    R("ssh_config", sid, "ssh_fips_ciphers" if key == "Ciphers" else "ssh_fips_macs",
      [("opensshserver_config", key)],
      [[f'vals := _csv(["opensshserver_config", "{key}"])', "count(vals) > 0",
        f"every v in vals {{\n\tv in {setname}\n}}"]],
      {"opensshserver_config": {key: allowed}},
      [{"opensshserver_config": {key: allowed + "," + extra}}, {"opensshserver_config": {key: ""}}],
      f"{key} in /etc/crypto-policies/back-ends/opensshserver.config must list only {allowed}",
      "Apply the FIPS crypto policy (update-crypto-policies --set FIPS) so opensshserver.config carries the DISA list",
      comment=f"{key} line of /etc/crypto-policies/back-ends/opensshserver.config (not sshd_config)",
      pass_cases=[{"opensshserver_config": {key: allowed.split(",")[1]}}])

for sid, key, name, want, bad in (("RHEL-09-255040", "PermitEmptyPasswords", "ssh_no_empty_passwords", "no", "yes"),
                                  ("RHEL-09-255050", "UsePAM", "ssh_use_pam", "yes", "no")):
    R("ssh_config", sid, name, [("ssh_config", key)],
      [[f'_kw(["ssh_config", "{key}"]) == "{want}"']],
      {"ssh_config": {key: want}}, [{"ssh_config": {key: bad}}],
      f"sshd {key} must be {want}", f"Set {key} {want} in /etc/ssh/sshd_config (or a drop-in) and restart sshd",
      comment=f"effective sshd {key} (case-insensitive) must be {want}")


# ═════════════════════════════════════════════════════════════════════════════════════════════════
# CAT II (reviewed 2026-11-18 against the V2R10 check text)
# ═════════════════════════════════════════════════════════════════════════════════════════════════

def num_rule(sec, sid, name, path, lo, hi, green, bads, expect, fix, comment, **kw):
    """a numeric setting within [lo, hi] (None = unbounded), read through _num: a JSON whole number only (the
    generator adds a number-as-text test per _num path, so a decimal string is never a pass case)"""
    p = '["' + '", "'.join(path) + '"]'
    lines = [f"n := _num({p})"] + ([f"n >= {lo}"] if lo is not None else []) + ([f"n <= {hi}"] if hi is not None else [])
    patch = lambda v: nest(path, v)
    R(sec, sid, name, [tuple(path)], [lines], patch(green), [patch(b) for b in bads], expect, fix, comment=comment,
      pass_cases=kw.pop("pass_cases", []), **kw)


def nest(path, v):
    for k in reversed(path):
        v = {k: v}
    return v


# ── account_auth ────────────────────────────────────────────────────────────────────────────────
R("account_auth", "RHEL-09-611165", "mfa_enabled",
  [("sssd", "pam_cert_auth")],
  [['_kw(["sssd", "pam_cert_auth"]) == "true"']],
  {"sssd": {"pam_cert_auth": "True"}},
  [{"sssd": {"pam_cert_auth": "False"}}],
  "pam_cert_auth = True must be set (uncommented) in /etc/sssd/sssd.conf or /etc/sssd/conf.d/",
  "Set pam_cert_auth = True in the [pam] section of /etc/sssd/sssd.conf (or a conf.d drop-in) and restart sssd",
  comment="pam_cert_auth as configured in /etc/sssd/sssd.conf or /etc/sssd/conf.d/ (null when missing or commented out)",
  na=[['_attested("rhel_09_611165_alternate_mfa")']],
  na_expect="the SA demonstrated an approved alternate multifactor authentication method",
  na_cases=[{"sssd": {"pam_cert_auth": None}, "attest": {"rhel_09_611165_alternate_mfa": True}}])

R("account_auth", "RHEL-09-611140", "password_sha512",
  [("login_defs", "ENCRYPT_METHOD")],
  [['_str(["login_defs", "ENCRYPT_METHOD"]) == "SHA512"']],
  {"login_defs": {"ENCRYPT_METHOD": "SHA512"}},
  [{"login_defs": {"ENCRYPT_METHOD": "MD5"}}, {"login_defs": {"ENCRYPT_METHOD": "YESCRYPT"}}],
  "ENCRYPT_METHOD in /etc/login.defs must be SHA512",
  "Set ENCRYPT_METHOD SHA512 in /etc/login.defs",
  comment="ENCRYPT_METHOD as configured in /etc/login.defs (null when missing or commented out)")

num_rule("account_auth", "RHEL-09-411075", "account_lockout_enabled", ["faillock_conf", "deny"], 1, 3, 3, [4, 0, "three"],
         "deny in /etc/security/faillock.conf must be 1 to 3 (not 0)",
         "Set deny = 3 in /etc/security/faillock.conf",
         "deny as configured in /etc/security/faillock.conf")

R("account_auth", "RHEL-09-611155", "no_empty_password_hashes",
  [("local_accounts_with_empty_passwords",)],
  [["accts := input.local_accounts_with_empty_passwords", "is_array(accts)", "count(accts) == 0"]],
  {"local_accounts_with_empty_passwords": []},
  [{"local_accounts_with_empty_passwords": ["guest"]}],
  "no /etc/shadow entry may have an empty password field",
  "Lock or set a password for each listed account: passwd -l <username>",
  comment="accounts whose /etc/shadow password field is empty (awk -F: '!$2 {print $1}' /etc/shadow)")

num_rule("account_auth", "RHEL-09-611090", "password_minlen", ["password_policy", "minlen"], 15, None, 15, [8, "8"],
         "minlen in /etc/security/pwquality.conf(.d) must be 15 or greater",
         "Set minlen = 15 in /etc/security/pwquality.conf",
         "effective minlen from /etc/security/pwquality.conf and pwquality.conf.d/*.conf")

for sid, name, key, what in (("RHEL-09-611110", "password_uppercase", "ucredit", "uppercase"),
                             ("RHEL-09-611065", "password_lowercase", "lcredit", "lowercase"),
                             ("RHEL-09-611070", "password_numeric", "dcredit", "numeric"),
                             ("RHEL-09-611100", "password_special", "ocredit", "special")):
    # V2R10 check text: only "a positive number or is commented out" is a finding, so 0 and negative values pass
    num_rule("account_auth", sid, name, ["password_policy", key], None, 0, -1, [1, "1", 2, "-1", "0"],
             f"{key} in /etc/security/pwquality.conf(.d) must be set and not positive (-1: at least one {what} character)",
             f"Set {key} = -1 in /etc/security/pwquality.conf",
             f"effective {key} from /etc/security/pwquality.conf and pwquality.conf.d/*.conf",
             pass_cases=[{"password_policy": {key: 0}}, {"password_policy": {key: -2}}])

num_rule("account_auth", "RHEL-09-411010", "password_maxage", ["password_policy", "maxdays"], 1, 180, 180, [181, 365, -1, "99999", "180"],
         "PASS_MAX_DAYS in /etc/login.defs must be 180 or less (and set: -1 disables the limit)",
         "Set PASS_MAX_DAYS 180 in /etc/login.defs",
         "PASS_MAX_DAYS as configured in /etc/login.defs",
         pass_cases=[{"password_policy": {"maxdays": 60}}, {"password_policy": {"maxdays": 1}}])

num_rule("account_auth", "RHEL-09-611075", "password_minage", ["password_policy", "mindays"], 1, None, 1, [0, "0"],
         "PASS_MIN_DAYS in /etc/login.defs must be 1 or greater",
         "Set PASS_MIN_DAYS 1 in /etc/login.defs",
         "PASS_MIN_DAYS as configured in /etc/login.defs")

num_rule("account_auth", "RHEL-09-411085", "lockout_duration_ok", ["faillock_conf", "fail_interval"], 1, 900, 900, [901, 0, "900s"],
         "fail_interval in /etc/security/faillock.conf must be 900 or less (not 0)",
         "Set fail_interval = 900 in /etc/security/faillock.conf",
         "fail_interval as configured in /etc/security/faillock.conf",
         na=[['_attested("rhel_09_411085_central_lockout")']],
         na_expect="the SA demonstrated an approved centralized account management method that locks after three failures in 15 minutes",
         na_cases=[{"faillock_conf": {"fail_interval": None}, "attest": {"rhel_09_411085_central_lockout": True}}])

num_rule("account_auth", "RHEL-09-411050", "inactive_lock_ok", ["password_policy", "inactive_days"], 0, 35, 35, [-1, 36, "-1"],
         "INACTIVE in /etc/default/useradd must be 0 to 35 (not -1)",
         "Set INACTIVE=35 in /etc/default/useradd",
         "INACTIVE as configured in /etc/default/useradd")

R("account_auth", "RHEL-09-411030", "no_duplicate_uids",
  [("duplicate_uid_accounts",)],
  [["accts := input.duplicate_uid_accounts", "is_array(accts)",
    "count([a | some a in accts; not a.interactive == false]) == 0"]],
  {"duplicate_uid_accounts": []},
  [{"duplicate_uid_accounts": [{"name": "alice2", "uid": 1001, "interactive": True}]},
   {"duplicate_uid_accounts": [{"name": "alice2", "uid": 1001}]}],
  "no interactive account in /etc/passwd may share its UID with another account",
  "Give each interactive account a unique UID (usermod -u) and fix file ownership",
  comment="accounts printed by awk -F: 'list[$3]++{print $1, $3}' /etc/passwd, each {name, uid, interactive}",
  pass_cases=[{"duplicate_uid_accounts": [{"name": "toor", "uid": 0, "interactive": False}]}])

R("account_auth", "RHEL-09-411110", "no_duplicate_gids",
  [("duplicate_gids",)],
  [["gids := input.duplicate_gids", "is_array(gids)", "count(gids) == 0"]],
  {"duplicate_gids": []},
  [{"duplicate_gids": [1001]}],
  "no GID may appear twice in /etc/group",
  "Give each group a unique GID (groupmod -g)",
  comment="GIDs printed by cut -d : -f 3 /etc/group | uniq -d")


# ── audit_logging ───────────────────────────────────────────────────────────────────────────────
helpers("audit_logging", r'''
# input.audit_rules: the loaded rules, one string per line of `auditctl -l`
_audit_lines := [l | some l in input.audit_rules; is_string(l)]

_tokens(line) := [t | some t in parts; t != ""] if parts := split(line, " ")

_syscalls(toks) := {s | some i, t in toks; t == "-S"; v := toks[i + 1]; parts := split(v, ","); some s in parts}

_exit_rule(toks) if "always,exit" in toks

_exit_rule(toks) if "exit,always" in toks

# the -F / -C field tokens of a rule (arch=b64, auid>=1000, exit=-EPERM, path=..., uid!=euid, ...)
_fields(toks) := [v | some i, t in toks; t in {"-F", "-C"}; v := toks[i + 1]]

_field_ok(f, _) if startswith(f, "arch=")

_field_ok(f, _) if startswith(f, "key=")

_field_ok(f, allowed) if f in allowed

# auid != unset, as auditctl prints it (-1, 4294967295 or unset)
auid_unset := {"auid!=-1", "auid!=4294967295", "auid!=unset"}

# every syscall in `needed` is audited for `arch` by an always,exit rule that carries one value of every set in
# `required` and no other field (a rule narrowed by uid=, exe=, ... does not audit every user)
_syscalls_audited(arch, needed, required) if {
	a := concat("=", ["arch", arch])
	allowed := {f | some req in required; some f in req}
	every s in needed {
		some line in _audit_lines
		toks := _tokens(line)
		_exit_rule(toks)
		a in toks
		s in _syscalls(toks)
		fs := _fields(toks)
		every req in required {
			some f in fs
			f in req
		}
		every f in fs {
			_field_ok(f, allowed)
		}
	}
}

# a rule audits exactly `path` with at least the permission letters in `perms` (e.g. ["w", "a"]):
# `-w <path> -p <perm>`, or an always,exit rule with `-F path=<path> -F perm=<perm>` and no narrowing field
_path_audited(path, perms) if {
	some line in _audit_lines
	toks := _tokens(line)
	some i, t in toks
	t == "-w"
	toks[i + 1] == path
	some j, u in toks
	u == "-p"
	p := toks[j + 1]
	every c in perms {
		contains(p, c)
	}
}

_path_audited(path, perms) if {
	some line in _audit_lines
	toks := _tokens(line)
	_exit_rule(toks)
	fs := _fields(toks)
	concat("=", ["path", path]) in fs
	some f in fs
	startswith(f, "perm=")
	p := substring(f, 5, -1)
	every c in perms {
		contains(p, c)
	}
	every g in fs {
		_path_field_ok(g, path)
	}
}

_path_field_ok(f, path) if f == concat("=", ["path", path])

_path_field_ok(f, _) if startswith(f, "perm=")

_path_field_ok(f, _) if f in ({"auid>=1000"} | auid_unset)

_path_field_ok(f, _) if _field_ok(f, set())''')


def sc_line(arch, calls, extra="", auid=True):
    return f"-a always,exit -F arch={arch} -S {','.join(calls)}{extra}" + (" -F auid>=1000 -F auid!=-1" if auid else "") + " -F key=k"


AUID = [["auid>=1000"], ["auid!=-1", "auid!=4294967295", "auid!=unset"]]


def rego_set(xs):
    return "{" + ", ".join(chr(34) + x + chr(34) for x in xs) + "}"


def syscall_rule(sid, name, calls, required_sets, expect, comment, bad_drop):
    """required_sets: per arch, one list of alternative-groups per expected rule line (from the check's example)"""
    alts = [["is_array(input.audit_rules)"] + [
        f'_syscalls_audited("{arch}", {rego_set(calls)}, [{", ".join(rego_set(g) for g in req)}])'
        for arch in ("b32", "b64") for req in required_sets]]
    lines = [l for l in AUDIT_GREEN_FINAL if f" -S {','.join(calls)} " in l]
    narrowed = lines[-1].replace(" -F auid>=1000", " -F auid>=1000 -F uid=1000") if "auid>=1000" in lines[-1] else lines[-1] + " -F uid=1000"
    exe = lines[-1] + " -F exe=/usr/bin/true"
    others = [l for l in AUDIT_GREEN_FINAL if l != lines[-1]]
    bad = [{"audit_rules": [l for l in AUDIT_GREEN_FINAL if l not in bad_drop(lines)]},
           {"audit_rules": others + [narrowed]}, {"audit_rules": others + [exe]}]
    if any("auid>=1000" in g for req in required_sets for g in req):
        bad.append({"audit_rules": others + [lines[-1].replace(" -F auid>=1000 -F auid!=-1", "")]})
    R("audit_logging", sid, name, [("audit_rules",)], alts, {"audit_rules": "__AUDIT__"}, bad, expect,
      f"Add the rules to /etc/audit/rules.d/audit.rules and load them (augenrules --load): {lines[-1]}",
      comment=comment,
      pass_cases=[{"audit_rules": others + [lines[-1].replace("auid!=-1", "auid!=unset")]}] if "auid!=-1" in lines[-1] else [])


AUDIT_GREEN_FINAL = (
    [sc_line(a, ["execve"], f" -C {c} -F {e}", auid=False) for a in ("b32", "b64") for c, e in (("uid!=euid", "euid=0"), ("gid!=egid", "egid=0"))]
    + [sc_line(a, ["chown", "fchown", "fchownat", "lchown"]) for a in ("b32", "b64")]
    + [sc_line(a, ["chmod", "fchmod", "fchmodat"]) for a in ("b32", "b64")]
    + [sc_line(a, ["setxattr", "fsetxattr", "lsetxattr", "removexattr", "fremovexattr", "lremovexattr"]) for a in ("b32", "b64")]
    + [sc_line(a, ["truncate", "ftruncate", "creat", "open", "openat", "open_by_handle_at"], f" -F exit={e}")
       for a in ("b32", "b64") for e in ("-EPERM", "-EACCES")]
    + [sc_line(a, ["init_module", "finit_module"]) for a in ("b32", "b64")]
    + ["-a always,exit -F arch=b32 -F path=/etc/sudoers -F perm=wa -F key=identity",
       "-a always,exit -F arch=b64 -F path=/etc/sudoers -F perm=wa -F key=identity",
       "-w /etc/passwd -p wa -k identity",
       "-a always,exit -S all -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=-1 -F key=priv_cmd"])

syscall_rule("RHEL-09-654010", "audit_execve_b64", ["execve"], [[["uid!=euid"], ["euid=0"]], [["gid!=egid"], ["egid=0"]]],
             "execve must be audited for b32 and b64 with -C uid!=euid -F euid=0 and -C gid!=egid -F egid=0 (all four rules)",
             "execve rules (auditctl -l) for both arches and both setuid/setgid conditions", lambda ls: [ls[3]])
syscall_rule("RHEL-09-654020", "audit_chown", ["chown", "fchown", "fchownat", "lchown"], [AUID],
             "chown, fchown, fchownat and lchown must be audited for both b32 and b64",
             "always,exit rules for the chown family, both arches (auditctl -l)", lambda ls: [ls[0]])
syscall_rule("RHEL-09-654015", "audit_chmod", ["chmod", "fchmod", "fchmodat"], [AUID],
             "chmod, fchmod and fchmodat must be audited for both b32 and b64",
             "always,exit rules for the chmod family, both arches (auditctl -l)", lambda ls: [ls[0]])
syscall_rule("RHEL-09-654025", "audit_setxattr", ["setxattr", "fsetxattr", "lsetxattr", "removexattr", "fremovexattr", "lremovexattr"], [AUID],
             "setxattr, fsetxattr, lsetxattr, removexattr, fremovexattr and lremovexattr must be audited for both b32 and b64",
             "always,exit rules for the xattr family, both arches (auditctl -l)", lambda ls: [ls[1]])
syscall_rule("RHEL-09-654070", "audit_open_failure", ["truncate", "ftruncate", "creat", "open", "openat", "open_by_handle_at"],
             [[["exit=-EPERM"]] + AUID, [["exit=-EACCES"]] + AUID],
             "truncate, ftruncate, creat, open, openat and open_by_handle_at must be audited for both arches with -F exit=-EPERM and -F exit=-EACCES",
             "always,exit rules for the open/truncate family with exit=-EPERM and exit=-EACCES, both arches", lambda ls: [ls[3]])
syscall_rule("RHEL-09-654080", "audit_modules", ["init_module", "finit_module"], [AUID],
             "init_module and finit_module must be audited for both b32 and b64",
             "always,exit rules for init_module and finit_module, both arches (auditctl -l)", lambda ls: [ls[0]])

for sid, name, path, perms, expect in (
        ("RHEL-09-654215", "audit_sudoers", "/etc/sudoers", "wa",
         "a loaded audit rule must watch /etc/sudoers itself (not only /etc/sudoers.d/) for write and attribute change (perm wa)"),
        ("RHEL-09-654240", "audit_passwd_file", "/etc/passwd", "wa",
         "a loaded audit rule must watch /etc/passwd for write and attribute change (perm wa)"),
        ("RHEL-09-654150", "audit_privileged_cmds", "/usr/bin/sudo", "x",
         "a loaded audit rule must audit execution (perm x) of /usr/bin/sudo")):
    keep = [l for l in AUDIT_GREEN_FINAL if path + " " not in l and "=" + path + " " not in l]
    bads = [{"audit_rules": keep}, {"audit_rules": keep + [f"-w {path} -p r -k k"]},
            {"audit_rules": keep + [f"-a always,exit -F arch=b64 -F path={path} -F perm=r -F key=k"]},
            {"audit_rules": keep + [f"-a always,exit -F arch=b64 -F path={path} -F perm={perms} -F uid=0 -F key=k"]}]
    if path == "/etc/sudoers":
        bads.append({"audit_rules": keep + ["-w /etc/sudoers.d/ -p wa -k identity"]})
    if path == "/usr/bin/sudo":
        bads.append({"audit_rules": keep + ["-a always,exit -F path=/usr/bin/su -F perm=x -F key=privileged"]})
    R("audit_logging", sid, name, [("audit_rules",)],
      [["is_array(input.audit_rules)", f'_path_audited("{path}", [{", ".join(chr(34) + c + chr(34) for c in perms)}])']],
      {"audit_rules": "__AUDIT__"}, bads, expect,
      f"Add an audit rule for {path} to /etc/audit/rules.d/ and load it (augenrules --load)",
      comment=f"a loaded rule (auditctl -l) on exactly {path}: -w {path} or -F path={path}",
      pass_cases=[{"audit_rules": keep + [f"-w {path} -p {perms} -k k"]},
                  {"audit_rules": keep + [f"-a always,exit -F arch=b64 -F path={path} -F perm=rwxa -F auid>=1000 -F auid!=unset -F key=k"]}])

# the shared green list: every audit rule above passes on it
for _sid, _spec in RULES.items():
    if _spec.get("green") == {"audit_rules": "__AUDIT__"}:
        _spec["green"] = {"audit_rules": AUDIT_GREEN_FINAL}

R("audit_logging", "RHEL-09-653015", "auditd_active",
  [("services", "auditd")],
  [['_kw(["services", "auditd"]) == "active"']],
  {"services": {"auditd": "active"}}, [{"services": {"auditd": "inactive"}}, {"services": {"auditd": "failed"}}],
  "auditd.service must be active (running)", "Enable and start auditd: systemctl enable --now auditd",
  comment="systemctl is-active auditd")

for sid, name, key, allowed, att, what in (
        ("RHEL-09-653055", "audit_storage_ok", "max_log_file_action", ["rotate", "single"], "rhel_09_653055_storage_action",
         "the system takes appropriate action when the audit files reach maximum size"),
        ("RHEL-09-653025", "admin_space_left_action_ok", "disk_full_action", ["syslog", "single", "halt"], "rhel_09_653025_disk_full_action",
         "the system takes appropriate action when the audit storage volume is full"),
        ("RHEL-09-653040", "space_left_action_ok", "space_left_action", ["email"], "rhel_09_653040_realtime_alerts",
         "real-time alerts to the SA and ISSO are configured at 75 percent of audit storage")):
    R("audit_logging", sid, name, [("auditd_config", key)],
      [[f'_kw(["auditd_config", "{key}"]) in {{{", ".join(chr(34) + a + chr(34) for a in allowed)}}}']],
      {"auditd_config": {key: allowed[0].upper()}},
      [{"auditd_config": {key: "ignore"}}] + ([{"auditd_config": {key: "syslog"}}] if key == "space_left_action" else [])
      + ([{"auditd_config": {key: "keep_logs"}}] if key == "max_log_file_action" else []),
      f"{key} in /etc/audit/auditd.conf must be {' or '.join(a.upper() for a in allowed)}, or the SA must attest that {what} "
      f"(input.attest.{att})",
      f"Set {key} = {allowed[0].upper()} in /etc/audit/auditd.conf",
      comment=f"{key} as configured in /etc/audit/auditd.conf",
      attest_alts=[[f'_attested("{att}")']],
      pass_cases=[{"auditd_config": {key: a}} for a in allowed[1:]] + [{"auditd_config": {key: "ignore"}, "attest": {att: True}}])


# ── configuration_management ────────────────────────────────────────────────────────────────────
import json as _json, os as _os, re as _re

_HERE = _os.path.dirname(_os.path.abspath(__file__))
_CATALOG = _os.path.join(_HERE, "catalogs", "rhel_9.json")
if _os.path.exists(_CATALOG):
    _CAT = {r["stig_id"]: r for r in _json.load(open(_CATALOG))["rules"]}
    # the banner text is the value the check compares against, taken from the check itself (whitespace-normalised)
    DOD_BANNER = " ".join(_re.search(r'"(You are accessing.*?details\.)"', _CAT["RHEL-09-211020"]["check"], _re.S).group(1).split())
else:
    # no catalog (gitignored; CI and gen_collector_contract.py import the table without it): the banner as the
    # committed module carries it. gen_rhel9.py itself still requires the catalog and re-derives it from the check.
    _m = _re.search(r'(?m)^dod_banner := "((?:[^"\\]|\\.)*)"$',
                    open(_os.path.join(_HERE, "..", "..", "benchmarks", "stig", "rhel_9", "configuration_management.rego")).read())
    DOD_BANNER = _json.loads('"' + _m.group(1) + '"')

helpers("configuration_management", r'''
# the Standard Mandatory DoW Notice and Consent Banner, from the RHEL-09-211020 check text (whitespace-normalised)
dod_banner := "''' + DOD_BANNER.replace("\\", "\\\\").replace('"', '\\"') + r'''"

# text with every run of whitespace collapsed to one space and the ends trimmed
_squash(s) := regex.replace(trim_space(s), `\s+`, " ")

# the mount entry for a mount point; undefined unless the mount list was collected and the entry is there
_mount(point) := m if {
	mounts := input.filesystem_mounts
	is_array(mounts)
	some m in mounts
	m.mount == point
}''')

MODULE_HELPER = r'''
# a kernel module is disabled the way the check requires: an uncommented `install <mod> /bin/false` and
# `blacklist <mod>` in /etc/modprobe.conf or /etc/modprobe.d/* (input.modprobe[<mod>] = {install, blacklisted})
_module_disabled(mod) if {
	m := input.modprobe[mod]
	m.install == "/bin/false"
	m.blacklisted == true
}'''

R("configuration_management", "RHEL-09-271105", "ctrl_alt_del_graphical_disabled",
  [("gnome", "media_keys_logout")],
  [['_str(["gnome", "media_keys_logout"]) in {"[\'\']", "@as []"}']],
  {"gnome": {"media_keys_logout": "['']"}},
  [{"gnome": {"media_keys_logout": "['<Control><Alt>Delete']"}}],
  "gsettings get org.gnome.settings-daemon.plugins.media-keys logout must return [''] (no logout key sequence)",
  "Set logout='' under [org/gnome/settings-daemon/plugins/media-keys] in /etc/dconf/db/local.d/ and run dconf update",
  comment="gsettings get org.gnome.settings-daemon.plugins.media-keys logout; no GUI installed is Not Applicable",
  na=[["input.gui_installed == false"]], na_expect="no graphical user interface is installed",
  na_cases=[{"gnome": {"media_keys_logout": None}, "gui_installed": False}])

R("configuration_management", "RHEL-09-431015", "selinux_targeted",
  [("selinux", "policy")], [['_str(["selinux", "policy"]) == "targeted"']],
  {"selinux": {"policy": "targeted"}}, [{"selinux": {"policy": "mls"}}],
  "sestatus Loaded policy name must be targeted", "Set SELINUXTYPE=targeted in /etc/selinux/config and reboot",
  comment="Loaded policy name from sestatus")

R("configuration_management", "RHEL-09-212010", "grub_password_set",
  [("grub", "user_cfg_password")],
  [['s := _str(["grub", "user_cfg_password"])', 'startswith(s, "grub.pbkdf2.sha512")']],
  {"grub": {"user_cfg_password": "grub.pbkdf2.sha512.10000.ABCDEF"}},
  [{"grub": {"user_cfg_password": "plaintext"}}, {"grub": {"user_cfg_password": ""}}],
  "GRUB2_PASSWORD in /boot/grub2/user.cfg (or the legacy /boot/efi/EFI/redhat/user.cfg) must begin with grub.pbkdf2.sha512",
  "Set a bootloader password: grub2-setpassword",
  comment="the GRUB2_PASSWORD value from /boot/grub2/user.cfg, else /boot/efi/EFI/redhat/user.cfg (null if absent or commented)")

R("configuration_management", "RHEL-09-211020", "login_banner_set",
  [("login_banner", "issue")],
  [['s := _str(["login_banner", "issue"])', "_squash(s) == dod_banner"]],
  {"login_banner": {"issue": DOD_BANNER}},
  [{"login_banner": {"issue": "Authorized users only. All activity may be monitored."}},
   {"login_banner": {"issue": DOD_BANNER.replace("USG-authorized use only", "authorized use only")}}],
  "/etc/issue must contain exactly the Standard Mandatory DoW Notice and Consent Banner (whitespace aside)",
  "Replace /etc/issue with the Standard Mandatory DoW Notice and Consent Banner text",
  comment="content of /etc/issue, compared with the banner text in the check (whitespace runs collapsed)",
  pass_cases=[{"login_banner": {"issue": DOD_BANNER.replace(" -", "\n-") + "\n"}}])

R("configuration_management", "RHEL-09-255025", "ssh_banner_set",
  [("ssh_config", "Banner")],
  [['b := _kw(["ssh_config", "Banner"])', 'b != ""', 'b != "none"']],
  {"ssh_config": {"Banner": "/etc/issue"}}, [{"ssh_config": {"Banner": "none"}}],
  "sshd must have an uncommented Banner keyword naming the banner file",
  "Set Banner /etc/issue in /etc/ssh/sshd_config (or a drop-in) and restart sshd",
  comment="effective sshd Banner keyword (sshd -T or the config files sshd -dd reads)")

R("configuration_management", "RHEL-09-213070", "aslr_enabled",
  [("kernel_params", "kernel.randomize_va_space"), ("sysctl_config", "kernel.randomize_va_space")],
  [['_str(["kernel_params", "kernel.randomize_va_space"]) == "2"',
    'vals := input.sysctl_config["kernel.randomize_va_space"]', "is_array(vals)", "count(vals) > 0",
    'every v in vals {\n\tsprintf("%v", [v]) == "2"\n}']],
  {"kernel_params": {"kernel.randomize_va_space": "2"}, "sysctl_config": {"kernel.randomize_va_space": ["2"]}},
  [{"kernel_params": {"kernel.randomize_va_space": "1"}}, {"sysctl_config": {"kernel.randomize_va_space": []}},
   {"sysctl_config": {"kernel.randomize_va_space": ["2", "0"]}}],
  "kernel.randomize_va_space must be 2 at runtime and in every sysctl configuration file that sets it (none conflicting)",
  "Set kernel.randomize_va_space = 2 in /etc/sysctl.d/99-kernel_randomize_va_space.conf and run sysctl --system",
  comment="runtime value (sysctl) and every value configured in the sysctl.d / sysctl.conf files the check greps")


def sysctl_rule(sec, sid, name, key, want, bad, expect, fix, **kw):
    R(sec, sid, name, [("kernel_params", key)], [[f'_str(["kernel_params", "{key}"]) == "{want}"']],
      {"kernel_params": {key: want}}, [{"kernel_params": {key: b}} for b in bad],
      expect, fix, comment=f"runtime {key} (sysctl)", pass_cases=kw.pop("pass_cases", [{"kernel_params": {key: int(want)}}]), **kw)


sysctl_rule("configuration_management", "RHEL-09-213010", "dmesg_restricted", "kernel.dmesg_restrict", "1", ["0"],
            "kernel.dmesg_restrict must be 1", "Set kernel.dmesg_restrict = 1 in /etc/sysctl.d/ and run sysctl --system")
sysctl_rule("configuration_management", "RHEL-09-213015", "perf_event_restricted", "kernel.perf_event_paranoid", "2", ["1", "3"],
            "kernel.perf_event_paranoid must be 2", "Set kernel.perf_event_paranoid = 2 in /etc/sysctl.d/ and run sysctl --system")
sysctl_rule("configuration_management", "RHEL-09-213075", "bpf_restricted", "kernel.unprivileged_bpf_disabled", "1", ["0", "2"],
            "kernel.unprivileged_bpf_disabled must be 1", "Set kernel.unprivileged_bpf_disabled = 1 in /etc/sysctl.d/ and run sysctl --system")
sysctl_rule("configuration_management", "RHEL-09-251045", "bpf_jit_hardened", "net.core.bpf_jit_harden", "2", ["1"],
            "net.core.bpf_jit_harden must be 2", "Set net.core.bpf_jit_harden = 2 in /etc/sysctl.d/ and run sysctl --system")


def module_rule(sec, sid, name, mod, att):
    R(sec, sid, name, [("modprobe", mod)], [[f'_module_disabled("{mod}")']],
      {"modprobe": {mod: {"install": "/bin/false", "blacklisted": True}}},
      [{"modprobe": {mod: {"install": "/bin/false", "blacklisted": False}}}, {"modprobe": {mod: {"install": None, "blacklisted": True}}}],
      f"/etc/modprobe.conf or /etc/modprobe.d/* must carry uncommented 'install {mod} /bin/false' and 'blacklist {mod}', "
      f"or its use must be documented with the ISSO (input.attest.{att})",
      f"Add 'install {mod} /bin/false' and 'blacklist {mod}' to /etc/modprobe.d/{mod}.conf",
      comment=f"uncommented modprobe lines for {mod}: input.modprobe[\"{mod}\"] = {{install: <command>, blacklisted: bool}}",
      attest_alts=[[f'_attested("{att}")']],
      pass_cases=[{"modprobe": {mod: {"install": "/bin/true", "blacklisted": False}}, "attest": {att: True}}])
    if "_module_disabled(mod) if" not in SECTION_HELPERS.get(sec, ""):
        helpers(sec, MODULE_HELPER)


module_rule("configuration_management", "RHEL-09-291010", "usb_storage_disabled", "usb-storage", "rhel_09_291010_usb_storage_documented")
module_rule("configuration_management", "RHEL-09-213055", "firewire_disabled", "firewire-core", "rhel_09_213055_firewire_documented")

R("configuration_management", "RHEL-09-651015", "aide_cron_configured",
  [("packages", "aide"), ("aide", "schedule")],
  [["input.packages.aide == true", "lines := input.aide.schedule", "is_array(lines)",
    "some l in lines", "_aide_check_line(l)", "_aide_notifies"]],
  {"packages": {"aide": True}, "aide": {"schedule": ["/etc/cron.daily/aide: /usr/sbin/aide --check | /bin/mail -s \"aide integrity check\" root@sysname.mil"]}},
  [{"aide": {"schedule": []}}, {"aide": {"schedule": ["/etc/cron.daily/aide: /usr/sbin/aide --check"]}},
   {"aide": {"schedule": ["/etc/crontab: # 30 04 * * * root /usr/sbin/aide --check | /bin/mail root"]}},
   {"aide": {"schedule": ["/etc/cron.daily/aide: /usr/sbin/aide --checksum-report | /bin/mail root"]}},
   {"aide": {"schedule": ["/etc/cron.daily/aide: /usr/local/bin/notaide --check | /bin/mail root"]}},
   {"aide": {"schedule": ["/etc/cron.daily/aide: /usr/sbin/aide --check > /var/log/aide-mail.log"]}}],
  "a cron job (/etc/cron.*, /etc/crontab, /var/spool/cron/root) must run aide --check and notify designated personnel "
  "(mail in the job, or input.attest.rhel_09_651015_notification); another integrity tool must be attested (input.attest.rhel_09_651015_other_tool)",
  "Add /etc/cron.daily/aide running /usr/sbin/aide --check | /bin/mail -s \"$HOSTNAME - Daily aide integrity check run\" root@sysname.mil",
  comment="the cron lines that run AIDE (input.aide.schedule) and how their results reach the SA",
  attest_alts=[['_attested("rhel_09_651015_other_tool")']],
  pass_cases=[{"aide": {"schedule": ["/etc/crontab: 30 04 * * * root /usr/sbin/aide --check"]}, "attest": {"rhel_09_651015_notification": True}}])
helpers("configuration_management", r'''
# the AIDE job mails its result, or the SA attests to another notification path
_aide_notifies if {
	some l in input.aide.schedule
	_aide_check_line(l)
	regex.match(`\|\s*(\S*/)?(mail|mailx|sendmail)(\s|$)`, l)
}

# a cron line (as "<file>: <entry>") that runs the aide binary with --check, not commented out
_aide_check_line(l) if {
	is_string(l)
	not regex.match(`^[^:]*:\s*#`, l)
	regex.match(`(^|[\s:/])aide\s+(--check|-C)(\s|$)`, l)
}

_aide_notifies if _attested("rhel_09_651015_notification")''')

R("configuration_management", "RHEL-09-651010", "aide_installed",
  [("packages", "aide")], [["input.packages.aide == true"]],
  {"packages": {"aide": True}}, [{"packages": {"aide": False}}],
  "the aide package must be installed, or the SA must attest how file integrity checks are performed (input.attest.rhel_09_651010_alternate_fic)",
  "Install AIDE: dnf install aide, then initialise it (aide --init)",
  comment="aide package installed (dnf list installed aide)",
  attest_alts=[['_attested("rhel_09_651010_alternate_fic")']],
  pass_cases=[{"packages": {"aide": False}, "attest": {"rhel_09_651010_alternate_fic": True}}])

MOUNTS = [{"mount": "/tmp", "device": "/dev/mapper/rhel-tmp", "fstype": "xfs", "options": ["rw", "nodev", "nosuid", "noexec"]},
          {"mount": "/home", "device": "/dev/mapper/rhel-home", "fstype": "xfs", "options": ["rw", "nodev", "nosuid", "noexec"]},
          {"mount": "/var/log", "device": "/dev/mapper/rhel-var_log", "fstype": "xfs", "options": ["rw", "nodev", "nosuid", "noexec"]},
          {"mount": "/var/log/audit", "device": "/dev/mapper/rhel-var_log_audit", "fstype": "xfs", "options": ["rw", "nodev", "nosuid", "noexec"]}]


def without(point):
    return [m for m in MOUNTS if m["mount"] != point]


for sid, name, point in (("RHEL-09-231015", "tmp_separate_partition", "/tmp"),
                         ("RHEL-09-231025", "var_log_separate", "/var/log")):
    R("configuration_management", sid, name, [("filesystem_mounts",)], [[f'_mount("{point}")']],
      {"filesystem_mounts": MOUNTS}, [{"filesystem_mounts": without(point)}],
      f"a separate file system must be mounted on {point}", f"Create a separate file system for {point} and mount it in /etc/fstab",
      comment=f"the mount table (findmnt / mount): a separate entry for {point}",
      pass_cases=[{"filesystem_mounts": without(point) + [{"mount": point, "device": "tmpfs", "fstype": "tmpfs", "options": ["rw"]}]}]
      if point == "/tmp" else [])

for sid, name, opt in (("RHEL-09-231045", "tmp_nodev", "nodev"), ("RHEL-09-231050", "tmp_nosuid", "nosuid"),
                       ("RHEL-09-231055", "tmp_noexec", "noexec")):
    R("configuration_management", sid, name.replace("tmp_", "home_"), [("filesystem_mounts",)],
      [['m := _mount("/home")', f'"{opt}" in m.options']],
      {"filesystem_mounts": MOUNTS},
      [{"filesystem_mounts": without("/home") + [{"mount": "/home", "device": "/dev/mapper/rhel-home", "fstype": "xfs",
                                                  "options": [o for o in ["rw", "nodev", "nosuid", "noexec"] if o != opt]}]},
       {"filesystem_mounts": without("/home")}],
      f"/home must be a separate file system mounted with {opt} (home directories under / are a finding)",
      f"Mount /home with the {opt} option in /etc/fstab",
      comment=f"the /home entry of the mount table must carry {opt}; no separate /home is a finding")

R("configuration_management", "RHEL-09-231030", "var_log_audit_separate",
  [("filesystem_mounts",), ("auditd_config", "log_file")],
  [['f := _str(["auditd_config", "log_file"])', r'dir := regex.replace(f, `/[^/]*$`, "")', "_mount(dir)"]],
  {"filesystem_mounts": MOUNTS, "auditd_config": {"log_file": "/var/log/audit/audit.log"}},
  [{"filesystem_mounts": without("/var/log/audit")}, {"auditd_config": {"log_file": "/srv/audit/audit.log"}}],
  "the directory of auditd log_file (the audit data path) must be a separate mounted file system",
  "Create a separate file system for the audit data path (e.g. /var/log/audit) and mount it in /etc/fstab",
  comment="the audit data path is the directory of auditd.conf log_file; it must be its own mount")


# ── file_permissions ────────────────────────────────────────────────────────────────────────────
def empty_list_rule(sec, sid, name, path, sample, expect, fix, comment, **kw):
    p = '["' + '", "'.join(path) + '"]'
    R(sec, sid, name, [tuple(path)],
      [[f"xs := object.get(input, {p}, null)", "is_array(xs)", "count(xs) == 0"]],
      nest(path, []), [nest(path, [sample])], expect, fix, comment=comment, **kw)


empty_list_rule("file_permissions", "RHEL-09-232255", "no_unowned_files", ["file_permissions", "unowned_files"], "/srv/x",
                "no local file or directory may lack a valid owner", "Assign an owner to each listed file: chown <user> <file>",
                "files found by find <local mounts> -xdev -nouser")
empty_list_rule("file_permissions", "RHEL-09-232250", "no_ungrouped_files", ["file_permissions", "ungrouped_files"], "/srv/x",
                "no local file or directory may lack a valid group", "Assign a group to each listed file: chgrp <group> <file>",
                "files found by find <local mounts> -xdev -nogroup")

for sid, name, key, mx, bad in (("RHEL-09-232075", "passwd_permissions_ok", "etc_passwd", "0644", "0664"),
                                ("RHEL-09-232270", "shadow_permissions_ok", "etc_shadow", "0000", "0400"),
                                ("RHEL-09-232055", "group_permissions_ok", "etc_group", "0644", "0666"),
                                ("RHEL-09-232065", "gshadow_permissions_ok", "etc_gshadow", "0000", "0640")):
    f = "/etc/" + key[4:]
    R("file_permissions", sid, name, [("file_permissions", key, "mode")],
      [[f'mode_within(input.file_permissions.{key}.mode, "{mx}")']],
      {"file_permissions": {key: {"mode": mx}}}, [{"file_permissions": {key: {"mode": bad}}}, {"file_permissions": {key: {"mode": "rw-r--r--"}}}],
      f"{f} must have mode {mx}" + (" or less permissive" if mx != "0000" else ""), f"chmod {mx} {f}",
      comment=f"mode of {f} (stat -c %a) as an octal string",
      pass_cases=[{"file_permissions": {key: {"mode": "0" if mx == "0000" else "600"}}}])

empty_list_rule("file_permissions", "RHEL-09-232020", "lib_permissions_ok", ["file_permissions", "library_files_group_or_world_writable"],
                "/usr/lib64/libx.so.1 0775", "no shared library file (*.so*) in /lib, /lib64, /usr/lib, /usr/lib64 may be group- or world-writable",
                "chmod 755 each listed library file", "output of find /lib /lib64 /usr/lib /usr/lib64 -type f -name '*.so*' -perm /022")
empty_list_rule("file_permissions", "RHEL-09-232200", "lib_dirs_owned_root", ["file_permissions", "library_files_not_owned_by_root"],
                "/usr/lib64/libx.so.1 nobody", "every shared library file (*.so*) in /lib, /lib64, /usr/lib, /usr/lib64 must be owned by root",
                "chown root each listed library file", "output of find /lib /lib64 /usr/lib /usr/lib64 -type f -name '*.so*' ! -user root")
empty_list_rule("file_permissions", "RHEL-09-232010", "sys_commands_permissions_ok", ["file_permissions", "system_commands_group_or_world_writable"],
                "/usr/local/bin/tool", "no system command in /bin, /sbin, /usr/bin, /usr/sbin, /usr/libexec, /usr/local/bin, /usr/local/sbin may be group- or world-writable",
                "chmod 755 each listed command", "output of find -L /bin /sbin /usr/bin /usr/sbin /usr/libexec /usr/local/bin /usr/local/sbin -perm /022")

R("file_permissions", "RHEL-09-232050", "home_dir_permissions_ok", [("file_permissions", "interactive_home_dirs")],
  [["dirs := input.file_permissions.interactive_home_dirs", "is_array(dirs)",
    'every d in dirs {\n\tmode_within(d.mode, "0750")\n}']],
  {"file_permissions": {"interactive_home_dirs": [{"path": "/home/disauser", "mode": "700"}]}},
  [{"file_permissions": {"interactive_home_dirs": [{"path": "/home/disauser", "mode": "755"}]}},
   {"file_permissions": {"interactive_home_dirs": [{"path": "/home/disauser"}]}}],
  "the home directory of every local interactive user (UID >= 1000, login shell not nologin) must have mode 0750 or less permissive",
  "chmod 0750 each listed home directory",
  comment="stat -L -c '%a %n' of each interactive user's home directory: [{path, mode}]",
  pass_cases=[{"file_permissions": {"interactive_home_dirs": []}}])


# ── network ─────────────────────────────────────────────────────────────────────────────────────
R("network", "RHEL-09-251015", "firewall_active", [("services", "firewalld")],
  [['_kw(["services", "firewalld"]) == "active"']],
  {"services": {"firewalld": "active"}}, [{"services": {"firewalld": "inactive"}}, {"services": {"firewalld": "inactive", "nftables": "active"}}],
  "firewalld must be active (systemctl is-active firewalld)", "Enable firewalld: systemctl enable --now firewalld",
  comment="systemctl is-active firewalld")

for sid, name, key, want, att in (
        ("RHEL-09-253075", "ip_forwarding_disabled", "net.ipv4.conf.all.forwarding", "0", "rhel_09_253075_router_documented"),
        ("RHEL-09-253015", "icmp_redirect_accept_disabled", "net.ipv4.conf.all.accept_redirects", "0", None),
        ("RHEL-09-253065", "icmp_redirect_send_disabled", "net.ipv4.conf.all.send_redirects", "0", "rhel_09_253065_redirects_documented"),
        ("RHEL-09-253020", "source_routing_disabled", "net.ipv4.conf.all.accept_source_route", "0", None),
        ("RHEL-09-253060", "icmp_bogus_error_responses", "net.ipv4.icmp_ignore_bogus_error_responses", "1", None),
        ("RHEL-09-253010", "tcp_syncookies_enabled", "net.ipv4.tcp_syncookies", "1", None),
        ("RHEL-09-253035", "rp_filter_enabled", "net.ipv4.conf.all.rp_filter", "1", None)):
    bad = ["1"] if want == "0" else (["0", "2"] if key.endswith("rp_filter") else ["0"])
    extra = {}
    if att:
        extra = dict(attest_alts=[[f'_attested("{att}")']],
                     pass_cases=[{"kernel_params": {key: int(want)}}, {"kernel_params": {key: "1"}, "attest": {att: True}}])
    sysctl_rule("network", sid, name, key, want, bad,
                f"{key} must be {want}" + (f", or the setting must be documented with the ISSO as an operational requirement (input.attest.{att})" if att else ""),
                f"Set {key} = {want} in /etc/sysctl.d/ and run sysctl --system", **extra)

R("network", "RHEL-09-291040", "wireless_disabled", [("wireless_interfaces",)],
  [["ifs := input.wireless_interfaces", "is_array(ifs)", "count(ifs) == 0"]],
  {"wireless_interfaces": []}, [{"wireless_interfaces": ["wlp7s0"]}],
  "no wireless interface may be configured unless documented and approved by the ISSO (input.attest.rhel_09_291040_wireless_approved)",
  "Disable the wireless interfaces: nmcli radio all off",
  comment="configured wireless devices (nmcli device status, TYPE wifi); no physical radio is Not Applicable",
  attest_alts=[['_attested("rhel_09_291040_wireless_approved")']],
  na=[["input.wireless_radios_present == false"]], na_expect="the system has no physical wireless network radios",
  na_cases=[{"wireless_interfaces": None, "wireless_radios_present": False}],
  pass_cases=[{"wireless_interfaces": ["wlp7s0"], "attest": {"rhel_09_291040_wireless_approved": True}}])

module_rule("network", "RHEL-09-291035", "bluetooth_module_disabled", "bluetooth", "rhel_09_291035_bluetooth_documented")

R("network", "RHEL-09-251040", "no_promiscuous_interfaces", [("promiscuous_interfaces",)],
  [["ifs := input.promiscuous_interfaces", "is_array(ifs)", "count(ifs) == 0"]],
  {"promiscuous_interfaces": []}, [{"promiscuous_interfaces": ["eth0"]}],
  "no interface may be in promiscuous mode unless approved by the ISSO and documented (input.attest.rhel_09_251040_promisc_approved)",
  "Turn promiscuous mode off: ip link set dev <if> multicast off promisc off",
  comment="interfaces flagged PROMISC by ip link",
  attest_alts=[['_attested("rhel_09_251040_promisc_approved")']],
  pass_cases=[{"promiscuous_interfaces": ["eth0"], "attest": {"rhel_09_251040_promisc_approved": True}}])


# ── pki_crypto ──────────────────────────────────────────────────────────────────────────────────
def alt_mfa(sid):
    key = f"{ident_of(sid)}_alternate_mfa"
    return dict(na=[[f'_attested("{key}")']], na_expect="the SA demonstrated an approved alternate multifactor authentication method",
                na_key=key)


def ident_of(sid):
    return sid.lower().replace("-", "_")


m = alt_mfa("RHEL-09-611170")
R("pki_crypto", "RHEL-09-611170", "cert_revocation_check", [("sssd", "certificate_verification")],
  [['opts := {o | some o in _csv(["sssd", "certificate_verification"])}', '"ocsp_dgst=sha512" in opts',
    'not "no_ocsp" in opts', 'not "no_verification" in opts']],
  {"sssd": {"certificate_verification": "ocsp_dgst=sha512"}},
  [{"sssd": {"certificate_verification": "no_ocsp"}}, {"sssd": {"certificate_verification": "ocsp_dgst=sha1"}},
   {"sssd": {"certificate_verification": "no_ocsp,ocsp_dgst=sha512"}},
   {"sssd": {"certificate_verification": "no_verification, ocsp_dgst=sha512"}},
   {"sssd": {"certificate_verification": "ocsp_dgst=sha5120"}}],
  "certificate_verification in the [sssd] section must carry the option ocsp_dgst=sha512 and neither no_ocsp nor no_verification, or the SA must show how certificate status "
  "checking is implemented (input.attest.rhel_09_611170_status_checking)",
  "Set certificate_verification = ocsp_dgst=sha512 in the [sssd] section of /etc/sssd/sssd.conf",
  comment="certificate_verification from the [sssd] section of sssd.conf / conf.d (uncommented)",
  attest_alts=[['_attested("rhel_09_611170_status_checking")']], na=m["na"], na_expect=m["na_expect"],
  pass_cases=[{"sssd": {"certificate_verification": "soft_ocsp, ocsp_dgst=sha512"}}],
  na_cases=[{"sssd": {"certificate_verification": None}, "attest": {m["na_key"]: True}}])

helpers("pki_crypto", r'''
# the comma-separated option list at path, each entry trimmed; undefined unless a string
_csv(path) := [trim_space(x) | some x in parts] if {
	s := _str(path)
	parts := split(s, ",")
}

# a DoD root CA from /etc/sssd/pki/sssd_auth_ca_db.pem, as the RHEL-09-631010 check shows it: self-signed
# (Subject == Issuer), Issuer C = US, O = U.S. Government, OU = DoD (the check text prints DoW), OU = PKI,
# CN = DoD Root CA <n>, compared component by component; inside its validity dates.
# input.sssd_ca_db.certificates: [{issuer_rdns, subject_rdns, not_before, not_after}], RDNs as [type, value]
# pairs in certificate order, dates RFC 3339.
_dod_root_valid(c) if {
	rdns := c.issuer_rdns
	is_array(rdns)
	count(rdns) == 5
	rdns[0] == ["C", "US"]
	rdns[1] == ["O", "U.S. Government"]
	rdns[2] in {["OU", "DoD"], ["OU", "DoW"]}
	rdns[3] == ["OU", "PKI"]
	rdns[4][0] == "CN"
	is_string(rdns[4][1])
	regex.match(`^DoD Root CA [0-9]+$`, rdns[4][1])
	c.subject_rdns == rdns
	nb := time.parse_rfc3339_ns(c.not_before)
	na := time.parse_rfc3339_ns(c.not_after)
	now := time.now_ns()
	nb <= now
	now < na
}''')

m = alt_mfa("RHEL-09-631010")
DOD_RDNS = [["C", "US"], ["O", "U.S. Government"], ["OU", "DoD"], ["OU", "PKI"], ["CN", "DoD Root CA 3"]]
DOD_CA = {"issuer_rdns": DOD_RDNS, "subject_rdns": DOD_RDNS, "not_before": "2012-03-20T18:46:41Z", "not_after": "2099-12-30T18:46:41Z"}
LOOKALIKE = DOD_RDNS[:4] + [["CN", "DoD Root CA 3 Fake Intermediate"]]
EMBEDDED_O = [["C", "US"], ["O", "Evil Corp, O = U.S. Government"], ["OU", "DoD"], ["OU", "PKI"], ["CN", "DoD Root CA 3"]]
INTERMEDIATE = [["C", "US"], ["O", "U.S. Government"], ["OU", "DoD"], ["OU", "PKI"], ["CN", "DOD ID CA-70"]]
R("pki_crypto", "RHEL-09-631010", "dod_ca_trusted", [("sssd_ca_db", "certificates")],
  [["certs := input.sssd_ca_db.certificates", "is_array(certs)", "some c in certs", "_dod_root_valid(c)"]],
  {"sssd_ca_db": {"certificates": [DOD_CA]}},
  [{"sssd_ca_db": {"certificates": [dict(DOD_CA, not_after="2020-01-01T00:00:00Z")]}},
   {"sssd_ca_db": {"certificates": [dict(DOD_CA, issuer_rdns=[["CN", "Example Corp Root CA"]], subject_rdns=[["CN", "Example Corp Root CA"]])]}},
   {"sssd_ca_db": {"certificates": [dict(DOD_CA, issuer_rdns=LOOKALIKE, subject_rdns=LOOKALIKE)]}},
   {"sssd_ca_db": {"certificates": [dict(DOD_CA, issuer_rdns=EMBEDDED_O, subject_rdns=EMBEDDED_O)]}},
   {"sssd_ca_db": {"certificates": [dict(DOD_CA, subject_rdns=INTERMEDIATE)]}},
   {"sssd_ca_db": {"certificates": [dict(DOD_CA, not_before="2098-01-01T00:00:00Z")]}},
   {"sssd_ca_db": {"certificates": []}}],
  "/etc/sssd/pki/sssd_auth_ca_db.pem must hold a self-signed DoD root CA (Issuer = Subject = C=US, O=U.S. Government, "
  "OU=DoD, OU=PKI, CN=DoD Root CA <n>) within its validity dates",
  "Install the DoD root CA bundle as /etc/sssd/pki/sssd_auth_ca_db.pem",
  comment="certificates in /etc/sssd/pki/sssd_auth_ca_db.pem: issuer / subject RDNs and validity dates",
  pass_cases=[{"sssd_ca_db": {"certificates": [dict(DOD_CA, subject_rdns=INTERMEDIATE), dict(DOD_CA, issuer_rdns=[r if r[0] != "OU" or r[1] != "DoD" else ["OU", "DoW"] for r in DOD_RDNS],
                                                                                              subject_rdns=[r if r[0] != "OU" or r[1] != "DoD" else ["OU", "DoW"] for r in DOD_RDNS])]}}],
  na=m["na"], na_expect=m["na_expect"], na_cases=[{"sssd_ca_db": None, "attest": {m["na_key"]: True}}])

R("pki_crypto", "RHEL-09-271045", "smartcard_lock_on_removal", [("gnome", "smartcard_removal_action")],
  [['s := _str(["gnome", "smartcard_removal_action"])', "trim(s, \"'\") == \"lock-screen\""]],
  {"gnome": {"smartcard_removal_action": "'lock-screen'"}}, [{"gnome": {"smartcard_removal_action": "'none'"}}],
  "gsettings get org.gnome.settings-daemon.peripherals.smartcard removal-action must return 'lock-screen'",
  "Set removal-action='lock-screen' under [org/gnome/settings-daemon/peripherals/smartcard] in /etc/dconf/db/local.d/ and run dconf update",
  comment="gsettings get org.gnome.settings-daemon.peripherals.smartcard removal-action; no GUI is Not Applicable",
  na=[["input.gui_installed == false"]], na_expect="no graphical user interface is installed",
  na_cases=[{"gnome": {"smartcard_removal_action": None}, "gui_installed": False}])

m = alt_mfa("RHEL-09-631015")
R("pki_crypto", "RHEL-09-631015", "cert_user_mapping", [("sssd", "certmap_rules")],
  [["rules := input.sssd.certmap_rules", "is_array(rules)", "some r in rules",
    'is_string(r.maprule)', 'trim_space(r.maprule) != ""']],
  {"sssd": {"certmap_rules": [{"section": "certmap/testing.test/rule_name", "matchrule": "<SAN>.*EDIPI@mil",
                               "maprule": "(userCertificate;binary={cert!bin})", "domains": "testing.test"}]}},
  [{"sssd": {"certmap_rules": []}}],
  "sssd.conf / conf.d must have a [certmap/...] section mapping certificates to accounts, or the SA must show how certificates "
  "are mapped (input.attest.rhel_09_631015_certificate_mapping)",
  "Add a [certmap/<domain>/<rule>] section with matchrule and maprule to /etc/sssd/sssd.conf",
  comment="[certmap/...] sections of sssd.conf and conf.d: [{section, matchrule, maprule, domains}]",
  attest_alts=[['_attested("rhel_09_631015_certificate_mapping")']], na=m["na"], na_expect=m["na_expect"],
  na_cases=[{"sssd": {"certmap_rules": None}, "attest": {m["na_key"]: True}}])


# ── services ────────────────────────────────────────────────────────────────────────────────────
for sid, name, pkg in (("RHEL-09-215040", "telnet_server_absent", "telnet-server"), ("RHEL-09-215025", "nfs_disabled", "nfs-utils")):
    R("services", sid, name, [("packages", pkg)], [[f'input.packages["{pkg}"] == false']],
      {"packages": {pkg: False}}, [{"packages": {pkg: True}}],
      f"the {pkg} package must not be installed", f"Remove the package: dnf remove {pkg}",
      comment=f"the {pkg} package must not be installed (dnf list --installed {pkg})")

R("services", "RHEL-09-231040", "autofs_disabled", [("unit_enabled", "autofs")],
  [['_kw(["unit_enabled", "autofs"]) in {"masked", "disabled", "not-found"}']],
  {"unit_enabled": {"autofs": "masked"}}, [{"unit_enabled": {"autofs": "enabled"}}, {"unit_enabled": {"autofs": "static"}}],
  "systemctl is-enabled autofs must return masked, disabled or not-found",
  "Disable and mask the automounter: systemctl mask --now autofs.service",
  comment="systemctl is-enabled autofs (input.unit_enabled[<unit>] is that command's output)",
  pass_cases=[{"unit_enabled": {"autofs": "disabled"}}, {"unit_enabled": {"autofs": "not-found"}}])


# ── software_integrity ──────────────────────────────────────────────────────────────────────────
RH_KEYS = {"567E347AD0044ADE55BA8A5F199E2F91FD431D51": "release key 2", "7E4624258C406535D56D6F135054E4A45A6340B3": "auxiliary key 3"}
helpers("software_integrity", r'''
# Red Hat RHEL 9 package-signing key fingerprints, from the RHEL-09-214010 check text
redhat_key_fingerprints := ''' + "{" + ", ".join(f'"{k}"' for k in RH_KEYS) + "}" + r'''

_fpr(s) := upper(replace(s, " ", "")) if is_string(s)

# an installed gpg-pubkey whose summary is exactly Red Hat's for key `label` (as the check's rpm -q output shows it)
_rh_key_installed(label) if {
	some s in input.rpm_gpg_pubkeys
	is_string(s)
	trim_space(s) == concat("", ["Red Hat, Inc. ", label, " <security@redhat.com> public key"])
}

# an AIDE rule line (uncommented selection / group definition) that uses sha512
_aide_sha512(l) if {
	is_string(l)
	parts := regex.split(`[=+ ]+`, trim_space(l))
	"sha512" in parts
}''')

R("software_integrity", "RHEL-09-214010", "gpgcheck_global",
  [("rpm_gpg_pubkeys",), ("redhat_release_key_file", "fingerprints")],
  [['_rh_key_installed("(release key 2)")', '_rh_key_installed("(auxiliary key 3)")',
    "fps := input.redhat_release_key_file.fingerprints", "is_array(fps)",
    "installed := {f | some x in fps; f := _fpr(x)}",
    "every k in redhat_key_fingerprints {\n\tk in installed\n}"]],
  {"rpm_gpg_pubkeys": ["Red Hat, Inc. (release key 2) <security@redhat.com> public key",
                       "Red Hat, Inc. (auxiliary key 3) <security@redhat.com> public key"],
   "redhat_release_key_file": {"fingerprints": ["567E 347A D004 4ADE 55BA  8A5F 199E 2F91 FD43 1D51",
                                                "7E46 2425 8C40 6535 D56D  6F13 5054 E4A4 5A63 40B3"]}},
  [{"rpm_gpg_pubkeys": ["Red Hat, Inc. (release key 2) <security@redhat.com> public key"]},
   {"rpm_gpg_pubkeys": ["Red Hat, Inc. (release key 2) <security@redhat.com> public key",
                        "Not Red Hat, Inc. (auxiliary key 3) <security@redhat.com> public key"]},
   {"redhat_release_key_file": {"fingerprints": ["567E 347A D004 4ADE 55BA  8A5F 199E 2F91 FD43 1D51",
                                                 "0000 0000 0000 0000 0000  0000 0000 0000 0000 0000"]}}],
  "Red Hat GPG keys 'release key 2' and 'auxiliary key 3' must be installed and /etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release "
  "must carry fingerprints 567E347AD0044ADE55BA8A5F199E2F91FD431D51 and 7E4624258C406535D56D6F135054E4A45A6340B3",
  "Install the Red Hat keys: rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release (from a verified redhat-release package)",
  comment="installed gpg-pubkey summaries and the fingerprints in /etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release (null if the file is missing)")

R("software_integrity", "RHEL-09-651020", "aide_fips_hashes", [("aide", "rule_lines")],
  [["lines := input.aide.rule_lines", "is_array(lines)", "count(lines) > 0",
    "every l in lines {\n\t_aide_sha512(l)\n}"]],
  {"aide": {"rule_lines": ["All=p+i+n+u+g+s+m+S+sha512+acl+xattrs+selinux"]}},
  [{"aide": {"rule_lines": ["All=p+i+n+u+g+s+m+S+sha512+acl+xattrs+selinux", "NORMAL=p+i+n+u+g+s+m+sha256"]}},
   {"aide": {"rule_lines": []}}],
  "every uncommented selection line in /etc/aide.conf must use sha512, or another tool using FIPS 140-3 hashes must be attested "
  "(input.attest.rhel_09_651020_other_tool)",
  "Add sha512 to every uncommented selection line in /etc/aide.conf",
  comment="the uncommented rule / selection lines of /etc/aide.conf",
  attest_alts=[['_attested("rhel_09_651020_other_tool")']])

sysctl_rule("software_integrity", "RHEL-09-213020", "kexec_disabled", "kernel.kexec_load_disabled", "1", ["0"],
            "kernel.kexec_load_disabled must be 1", "Set kernel.kexec_load_disabled = 1 in /etc/sysctl.d/ and run sysctl --system")

R("software_integrity", "RHEL-09-652010", "rsyslog_installed", [("packages", "rsyslog")], [["input.packages.rsyslog == true"]],
  {"packages": {"rsyslog": True}}, [{"packages": {"rsyslog": False}}],
  "the rsyslog package must be installed", "Install rsyslog: dnf install rsyslog", comment="rsyslog package installed")

R("software_integrity", "RHEL-09-652020", "rsyslog_active", [("services", "rsyslog")], [['_kw(["services", "rsyslog"]) == "active"']],
  {"services": {"rsyslog": "active"}}, [{"services": {"rsyslog": "inactive"}}],
  "rsyslog must be active (systemctl is-active rsyslog)", "Enable rsyslog: systemctl enable --now rsyslog",
  comment="systemctl is-active rsyslog")


# ── ssh_config ──────────────────────────────────────────────────────────────────────────────────
for sid, key, name, want, bad in (("RHEL-09-255045", "PermitRootLogin", "ssh_no_root_login", "no", ["yes", "forced-commands-only", "prohibit-password"]),
                                  ("RHEL-09-255080", "HostbasedAuthentication", "ssh_no_hostbased_auth", "no", ["yes"]),
                                  ("RHEL-09-255160", "StrictModes", "ssh_strict_modes", "yes", ["no"]),
                                  ("RHEL-09-255145", "IgnoreRhosts", "ssh_ignore_rhosts", "yes", ["no"]),
                                  ("RHEL-09-255150", "IgnoreUserKnownHosts", "ssh_ignore_user_known_hosts", "yes", ["no"]),
                                  ("RHEL-09-255165", "PrintLastLog", "ssh_print_last_log", "yes", ["no"])):
    R("ssh_config", sid, name, [("ssh_config", key)], [[f'_kw(["ssh_config", "{key}"]) == "{want}"']],
      {"ssh_config": {key: want}}, [{"ssh_config": {key: b}} for b in bad],
      f"sshd {key} must be {want}", f"Set {key} {want} in /etc/ssh/sshd_config (or a drop-in) and restart sshd",
      comment=f"effective sshd {key} (case-insensitive) must be {want}",
      pass_cases=[{"ssh_config": {key: want.upper()}}])

R("ssh_config", "RHEL-09-255155", "ssh_no_x11", [("ssh_config", "X11Forwarding")], [['_kw(["ssh_config", "X11Forwarding"]) == "no"']],
  {"ssh_config": {"X11Forwarding": "no"}}, [{"ssh_config": {"X11Forwarding": "yes"}}],
  "sshd X11Forwarding must be no, unless X11 forwarding is documented with the ISSO (input.attest.rhel_09_255155_x11_documented)",
  "Set X11Forwarding no in /etc/ssh/sshd_config (or a drop-in) and restart sshd",
  comment="effective sshd X11Forwarding", attest_alts=[['_attested("rhel_09_255155_x11_documented")']],
  pass_cases=[{"ssh_config": {"X11Forwarding": "yes"}, "attest": {"rhel_09_255155_x11_documented": True}}])

# V2R10 check text: a finding only when it "does not have a value of "600" or less" (0 is not excluded); a negative
# value is not a time sshd accepts, so it stays a finding
num_rule("ssh_config", "RHEL-09-255100", "ssh_client_alive_interval_ok", ["ssh_config", "ClientAliveInterval"], 0, 600, 600, [601, -1, "10m", "600", "0"],
         "sshd ClientAliveInterval must be set to 600 or less",
         "Set ClientAliveInterval 600 in /etc/ssh/sshd_config (or a drop-in) and restart sshd",
         "effective sshd ClientAliveInterval (sshd -T)",
         pass_cases=[{"ssh_config": {"ClientAliveInterval": 300}}, {"ssh_config": {"ClientAliveInterval": 0}}])
num_rule("ssh_config", "RHEL-09-255095", "ssh_client_alive_count_ok", ["ssh_config", "ClientAliveCountMax"], 1, 1, 1, [0, 3],
         "sshd ClientAliveCountMax must be 1", "Set ClientAliveCountMax 1 in /etc/ssh/sshd_config (or a drop-in) and restart sshd",
         "effective sshd ClientAliveCountMax (sshd -T)")
import rhel9_rules_part1  # noqa: E402,F401  (part 1 of the full V2R10 table)
import rhel9_rules_part2  # noqa: E402,F401  (part 2 of the table: RHEL-09-231150 to RHEL-09-252060)
import rhel9_rules_part3  # noqa: E402,F401  (part 3 of the table: RHEL-09-252065 to RHEL-09-411070)
import rhel9_rules_part4  # noqa: E402,F401  (part 4 of the V2R10 table)
import rhel9_rules_part5  # noqa: E402,F401  (part 5 of the table; registers its rules through R)
