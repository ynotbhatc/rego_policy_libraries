"""Reviewed logic table for gen_rhel9.py (DISA STIG for RHEL 9, V2R10).

A spec (see R below):
  sec     : section module          name  : the rule's boolean (kept from the hand-maintained module)
  ev      : evidence paths that must be collected (else Open "evidence missing")
  alts    : alternative bodies (OR), each a list of Rego lines (AND), evaluated only with all evidence present
  attest_alts : bodies that pass on an attestation alone (the check's "ask the SA ..." clause)
  na / na_expect / na_cases : the check text's Not Applicable clause, as explicit evidence
  green   : fixture patch that passes      bad : list of patches (object.union onto green) that fail
  expect  : what the check requires (the Open detail)      fix : fix text      kind : machine | machine+attestation
Rules not yet moved here are carried verbatim from the hand-maintained module (rhel9_legacy.py).
"""
from rhel9_legacy import LEGACY, LEGACY_HELPERS

SECTION_HELPERS = dict(LEGACY_HELPERS)
RULES = {sid: dict(spec, legacy=True) for sid, spec in LEGACY.items()}


def helpers(sec, text):
    SECTION_HELPERS[sec] = (SECTION_HELPERS.get(sec, "").strip() + "\n\n" + text.strip()).strip()


def R(sec, sid, name, ev, alts, green, bad, expect, fix, comment="", kind="machine", attest_alts=(), na=(),
      na_expect="", na_cases=(), pass_cases=()):
    assert sid in RULES and RULES[sid]["sec"] == sec, sid
    if attest_alts and kind == "machine":
        kind = "machine+attestation"
    RULES[sid] = dict(sec=sec, name=name, ev=[tuple(e) for e in ev], alts=alts, green=green, bad=list(bad),
                      expect=expect, fix=fix, comment=comment or RULES[sid].get("comment", ""), kind=kind,
                      attest_alts=list(attest_alts), na=list(na), na_expect=na_expect, na_cases=list(na_cases),
                      pass_cases=list(pass_cases))


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
   {"crypto_policy_state": {"min_rsa_size": 1024}}, {"crypto_policy_state": {"min_rsa_size": "2048 bits"}}],
  "update-crypto-policies --show must be FIPS; CURRENT.pol hash must include " + " ".join(FIPS_HASHES)
  + ", nothing with SHA1 or below 224 bits; min_rsa_size must be at least 2048",
  "Set the FIPS policy: update-crypto-policies --set FIPS, then reboot",
  comment="systemwide crypto policy FIPS; CURRENT.pol hash list and min_rsa_size",
  pass_cases=[{"crypto_policy_state": {"min_rsa_size": "3072"}}])

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
