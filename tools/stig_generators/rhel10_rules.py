"""Reviewed logic table for gen_rhel9.py rhel_10 (DISA STIG for RHEL 10, V1R3).

Built 2026-11-18 rule by rule against the RHEL 10 V1R3 check text (catalogs/rhel_10.json), replacing the by-title
derivation. `T.reuse` only where the RHEL 10 check is the same check as a reviewed RHEL 9 (or OL 9) rule. RHEL 10
differences written here: sshd settings must sit in a drop-in that sorts before 50-redhat.conf (and the runtime value
must match), the server MAC list and its order, fchmodat2, release key 4, AIDE hash lines, library file sets.
"""
import json

import ol9_rules
import rhel9_rules
from linux_stig_table import Table

T = Table(sources=(rhel9_rules, ol9_rules))


def r10_audit(spec):
    """RHEL 10 audits fchmodat2 with chmod/fchmod/fchmodat: the shared audit fixture carries it for every rule."""
    def sub(o):
        return json.loads(json.dumps(o).replace("-S chmod,fchmod,fchmodat ", "-S chmod,fchmod,fchmodat,fchmodat2 "))
    return {k: sub(spec[k]) for k in ("green", "bad", "pass_cases")}


for r10, src in [
    ("RHEL-10-700960", "RHEL-09-211050"), ("RHEL-10-000500", "RHEL-09-671010"), ("RHEL-10-300010", "RHEL-09-215105"),
    ("RHEL-10-300090", "RHEL-09-672020"), ("RHEL-10-300085", "RHEL-09-672055"), ("RHEL-10-001050", "RHEL-09-214025"),
    ("RHEL-10-001040", "RHEL-09-214020"), ("RHEL-10-600640", "RHEL-09-255050"), ("RHEL-10-600100", "RHEL-09-411010"),
    ("RHEL-10-600210", "RHEL-09-611075"), ("RHEL-10-600130", "RHEL-09-411030"), ("RHEL-10-600470", "RHEL-09-411110"),
    ("RHEL-10-500205", "RHEL-09-653040"), ("RHEL-10-700040", "RHEL-09-211020"), ("RHEL-10-701030", "RHEL-09-213010"),
    ("RHEL-10-701040", "RHEL-09-213015"), ("RHEL-10-800030", "RHEL-09-213075"), ("RHEL-10-800050", "RHEL-09-251045"),
    ("RHEL-10-200633", "RHEL-09-651015"), ("RHEL-10-400355", "RHEL-09-231045"), ("RHEL-10-400360", "RHEL-09-231050"),
    ("RHEL-10-400365", "RHEL-09-231055"), ("RHEL-10-400265", "RHEL-09-232075"), ("RHEL-10-400245", "RHEL-09-232055"),
    ("RHEL-10-400205", "RHEL-09-232010"), ("RHEL-10-400240", "RHEL-09-232050"), ("RHEL-10-800210", "RHEL-09-253075"),
    ("RHEL-10-800090", "RHEL-09-253015"), ("RHEL-10-800190", "RHEL-09-253065"), ("RHEL-10-800100", "RHEL-09-253020"),
    ("RHEL-10-800130", "RHEL-09-253035"), ("RHEL-10-800020", "RHEL-09-251040"), ("RHEL-10-701270", "RHEL-09-631010"),
    ("RHEL-10-701050", "RHEL-09-213020"), ("RHEL-10-200090", "RHEL-09-215015"), ("RHEL-10-300040", "RHEL-09-255065"),
    ("RHEL-10-701220", "RHEL-09-611165"), ("RHEL-10-600410", "RHEL-09-411075"), ("RHEL-10-600460", "RHEL-09-611155"),
    ("RHEL-10-600220", "RHEL-09-611090"), ("RHEL-10-600250", "RHEL-09-611110"), ("RHEL-10-600310", "RHEL-09-611070"),
    ("RHEL-10-600230", "RHEL-09-611100"), ("RHEL-10-600240", "RHEL-09-611065"), ("RHEL-10-600160", "RHEL-09-411050"),
    ("RHEL-10-700400", "RHEL-09-431015"), ("RHEL-10-701130", "RHEL-09-213070"), ("RHEL-10-700850", "RHEL-09-291010"),
    ("RHEL-10-000560", "RHEL-09-231025"), ("RHEL-10-000520", "RHEL-09-231030"), ("RHEL-10-400290", "RHEL-09-232255"),
    ("RHEL-10-400285", "RHEL-09-232250"), ("RHEL-10-400295", "RHEL-09-232270"), ("RHEL-10-400255", "RHEL-09-232065"),
    ("RHEL-10-200531", "RHEL-09-251015"), ("RHEL-10-800180", "RHEL-09-253060"), ("RHEL-10-800080", "RHEL-09-253010"),
    ("RHEL-10-700860", "RHEL-09-291035"), ("RHEL-10-701230", "RHEL-09-611170"), ("RHEL-10-701280", "RHEL-09-631015"),
    ("RHEL-10-200641", "RHEL-09-652020"), ("RHEL-10-600740", "RHEL-09-611140"), ("RHEL-10-200661", "RHEL-09-653015"),
    ("RHEL-10-700420", "RHEL-09-431010"), ("RHEL-10-700830", "RHEL-09-271105"), ("RHEL-10-000540", "RHEL-09-231015"),
    ("RHEL-10-700870", "RHEL-09-291040"), ("RHEL-10-200640", "RHEL-09-652010"), ("RHEL-10-200020", "RHEL-09-215040"),
    ("RHEL-10-200010", "RHEL-09-215025"),
    # the banner file must exist, as in OL 9 (reviewed there); AIDE installed and initialised, as in OL 9
    ("RHEL-10-700010", "OL09-00-000256"), ("RHEL-10-200630", "OL09-00-000300"),
]:
    T.reuse(r10, src)

for r10, r9 in [("RHEL-10-500300", "RHEL-09-654010"), ("RHEL-10-500790", "RHEL-09-654020"), ("RHEL-10-500310", "RHEL-09-654025"),
                ("RHEL-10-500390", "RHEL-09-654070"), ("RHEL-10-500410", "RHEL-09-654080"), ("RHEL-10-500680", "RHEL-09-654215"),
                ("RHEL-10-500730", "RHEL-09-654240"), ("RHEL-10-500550", "RHEL-09-654150")]:
    T.reuse(r10, r9, **r10_audit(T.src[r9]))

# chmod family: RHEL 10 adds fchmodat2
s = T.src["RHEL-09-654015"]
p = r10_audit(s)
T.reuse("RHEL-10-500780", "RHEL-09-654015",
        alts=[[a.replace('{"chmod", "fchmod", "fchmodat"}', '{"chmod", "fchmod", "fchmodat", "fchmodat2"}') for a in s["alts"][0]]],
        green=p["green"], pass_cases=p["pass_cases"],
        bad=p["bad"] + [s["green"]],   # the RHEL 9 rule set (no fchmodat2) fails here
        expect="chmod, fchmod, fchmodat and fchmodat2 must be audited for both b32 and b64")

# no centralized-account-management Not Applicable note in RHEL 10
T.reuse("RHEL-10-600420", "RHEL-09-411085", na=[], na_expect="", na_cases=[])
# /boot/grub2/user.cfg only (no legacy EFI note)
T.reuse("RHEL-10-600000", "RHEL-09-212010", expect="GRUB2_PASSWORD in /boot/grub2/user.cfg must begin with grub.pbkdf2.sha512")
# autofs not installed is Not Applicable
T.reuse("RHEL-10-701210", "RHEL-09-231040", na=[["input.packages.autofs == false"]], na_expect="the autofs service is not installed",
        na_cases=[{"unit_enabled": {"autofs": None}, "packages": {"autofs": False}}])
# TFTP secure mode: systemctl cat tftp.service (as OL 9), plus "documented as critical to the mission with the ISSO"
T.reuse("RHEL-10-800310", "OL09-00-002426", attest_alts=[['_attested("rhel_10_800310_tftp_documented")']],
        expect="tftp-server is installed: the ExecStart line of `systemctl cat tftp.service` must carry -s, or TFTP must be "
               "documented as mission critical with the ISSO (input.attest.rhel_10_800310_tftp_documented)",
        pass_cases=[{"packages": {"tftp-server": True}, "tftp": {"unit_execstart": "ExecStart=/usr/sbin/in.tftpd"},
                     "attest": {"rhel_10_800310_tftp_documented": True}}])

# ── sshd: the keyword must be set in a drop-in that sorts before 50-redhat.conf, and the runtime value must match ──
T.helpers("ssh_config", r'''
# input.sshd_config_files[<Keyword>]: [{file, value}] for every uncommented <Keyword> line in the files sshd reads,
# in sshd's read order (sshd -dd ... | xargs grep -iH); sshd uses the first one. The first must come from a drop-in
# under /etc/ssh/sshd_config.d/ whose name sorts before 50-redhat.conf.
_r10_ssh_first(kw) := lower(trim_space(e.value)) if {
	es := input.sshd_config_files[kw]
	is_array(es)
	count(es) > 0
	e := es[0]
	is_string(e.file)
	is_string(e.value)
	startswith(e.file, "/etc/ssh/sshd_config.d/")
	name := substring(e.file, count("/etc/ssh/sshd_config.d/"), -1)
	not contains(name, "/")
	name < "50-redhat.conf"
}

# input.sshd_runtime[<keyword lower-case>]: the value sshd -T prints
_r10_ssh_runtime(kw) := lower(trim_space(v)) if {
	k := lower(kw)
	v := input.sshd_runtime[k]
	is_string(v)
}''')

DROP = "/etc/ssh/sshd_config.d/10-stig.conf"


def ssh(sid, kw, name, want, bad_value, attest=None, numeric=False):
    lk = kw.lower()
    if numeric:
        alt = [f'v := _r10_ssh_first("{kw}")', "regex.match(`^[0-9]+$`, v)", "to_number(v) >= 1", f"to_number(v) <= {want}",
               f'r := _r10_ssh_runtime("{kw}")', "regex.match(`^[0-9]+$`, r)", "to_number(r) >= 1", f"to_number(r) <= {want}"]
        expect = f"{kw} must be 1..{want} in a drop-in before 50-redhat.conf (the first value sshd reads) and at runtime (sshd -T)"
    else:
        alt = [f'_r10_ssh_first("{kw}") == "{want}"', f'_r10_ssh_runtime("{kw}") == "{want}"']
        expect = f"{kw} must be {want} in a drop-in before 50-redhat.conf (the first value sshd reads) and at runtime (sshd -T)"
    green = {"sshd_config_files": {kw: [{"file": DROP, "value": str(want)}]}, "sshd_runtime": {lk: str(want)}}
    bads = [{"sshd_config_files": {kw: [{"file": DROP, "value": bad_value}]}},
            {"sshd_config_files": {kw: [{"file": "/etc/ssh/sshd_config.d/60-local.conf", "value": str(want)}]}},
            {"sshd_config_files": {kw: [{"file": "/etc/ssh/sshd_config", "value": str(want)}]}},
            {"sshd_config_files": {kw: []}}, {"sshd_runtime": {lk: bad_value}}]
    kwargs = {}
    if attest:
        expect += f", or its use documented with the ISSO (input.attest.{attest})"
        kwargs = dict(attest_alts=[[f'_attested("{attest}")']],
                      pass_cases=[{"sshd_config_files": {kw: []}, "attest": {attest: True}}])
    T.R("ssh_config", sid, name, [("sshd_config_files", kw), ("sshd_runtime", lk)], [alt], green, bads, expect,
        f"Set {kw} {want} in {DROP} (sorting before 50-redhat.conf) and restart sshd",
        comment=f"{kw}: first value sshd reads must come from a drop-in before 50-redhat.conf; sshd -T must agree", **kwargs)


ssh("RHEL-10-700610", "PermitEmptyPasswords", "ssh_no_empty_passwords", "no", "yes")
ssh("RHEL-10-700620", "PermitRootLogin", "ssh_no_root_login", "no", "prohibit-password")
ssh("RHEL-10-700630", "HostbasedAuthentication", "ssh_no_hostbased_auth", "no", "yes")
ssh("RHEL-10-700530", "IgnoreRhosts", "ssh_ignore_rhosts", "yes", "no")
ssh("RHEL-10-700540", "IgnoreUserKnownHosts", "ssh_ignore_user_known_hosts", "yes", "no")
ssh("RHEL-10-700550", "X11Forwarding", "ssh_x11_disabled", "no", "yes", attest="rhel_10_700550_x11_documented")
ssh("RHEL-10-700560", "StrictModes", "ssh_strict_modes", "yes", "no")
ssh("RHEL-10-700570", "PrintLastLog", "ssh_print_last_log", "yes", "no")
ssh("RHEL-10-700660", "ClientAliveCountMax", "ssh_client_alive_count_ok", "1", "3")
ssh("RHEL-10-700930", "ClientAliveInterval", "ssh_client_alive_interval_ok", 600, "900", numeric=True)

# server MACs: the list in opensshserver.config, exactly the check's example and in its order
MACS = ["hmac-sha2-256-etm@openssh.com", "hmac-sha2-512-etm@openssh.com", "hmac-sha2-256", "hmac-sha2-512"]
T.R("ssh_config", "RHEL-10-300060", "ssh_fips_macs", [("opensshserver_config", "MACs")],
    [['vals := _csv(["opensshserver_config", "MACs"])', "vals == " + json.dumps(MACS)]],
    {"opensshserver_config": {"MACs": ",".join(MACS)}},
    [{"opensshserver_config": {"MACs": ",".join(reversed(MACS))}}, {"opensshserver_config": {"MACs": ",".join(MACS + ["hmac-sha1"])}},
     {"opensshserver_config": {"MACs": "hmac-sha2-512,hmac-sha2-256"}}],
    "MACs in /etc/crypto-policies/back-ends/opensshserver.config must be exactly " + ",".join(MACS) + " in that order",
    "Set the FIPS crypto policy (update-crypto-policies --set FIPS) and reboot",
    comment="RHEL 10 makes a different order a finding; the example list is the expected value (its 'other than "
            "hmac-sha2-512 and hmac-sha2-256' wording names the families of the four example entries)")

# ── Red Hat keys: release key 2, auxiliary key 3 and release key 4 (fingerprints from sq inspect) ──────────────
R10_KEYS = {"567E347AD0044ADE55BA8A5F199E2F91FD431D51": "(release key 2)", "7E4624258C406535D56D6F135054E4A45A6340B3": "(auxiliary key 3)",
            "FCD355B305707A62DA143AB6E422397E50FE8467A2A95343D246D6276AFEDF8F": "(release key 4)"}
T.helpers("software_integrity", r'''
# the RHEL 10 package-signing key fingerprints, from the RHEL-10-001020 check text (sq inspect output)
rhel10_key_fingerprints := ''' + "{" + ", ".join(f'"{k}"' for k in R10_KEYS) + "}")
s = T.src["RHEL-09-214010"]
T.reuse("RHEL-10-001020", "RHEL-09-214010",
        alts=[['_rh_key_installed("(release key 2)")', '_rh_key_installed("(auxiliary key 3)")', '_rh_key_installed("(release key 4)")',
               "fps := input.redhat_release_key_file.fingerprints", "is_array(fps)",
               "installed := {f | some x in fps; f := _fpr(x)}", "every k in rhel10_key_fingerprints {\n\tk in installed\n}"]],
        green={"rpm_gpg_pubkeys": [f"Red Hat, Inc. {v} <security@redhat.com> public key" for v in R10_KEYS.values()],
               "redhat_release_key_file": {"fingerprints": list(R10_KEYS)}},
        bad=[{"rpm_gpg_pubkeys": [f"Red Hat, Inc. {v} <security@redhat.com> public key" for v in list(R10_KEYS.values())[:2]]},
             {"redhat_release_key_file": {"fingerprints": list(R10_KEYS)[:2]}}],
        pass_cases=[],
        expect="Red Hat GPG keys release key 2, auxiliary key 3 and release key 4 must be installed and "
               "/etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release must carry fingerprints " + ", ".join(R10_KEYS),
        comment="input.rpm_gpg_pubkeys (rpm -q gpg-pubkey summaries); input.redhat_release_key_file.fingerprints (sq inspect)")

# ── AIDE: no hash other than sha512 on any uncommented line, and none of md5 / sha1 / whirlpool / tiger ──────────
T.helpers("configuration_management", r'''
# a hash name AIDE accepts in a rule definition (lower case)
aide_hash_names := {"md5", "sha1", "sha256", "sha512", "rmd160", "tiger", "haval", "gost", "crc32", "whirlpool", "crc32b", "stribog256", "stribog512", "sha512_256"}

# the hash names used on an uncommented aide.conf line (`NAME = a+b+sha512`, or a bare selection line)
_aide_line_hashes(l) := {h | some p in parts; h := trim_space(p); h in aide_hash_names} if {
	ll := lower(l)
	parts := regex.split(`[+=\s]+`, ll)
}''')
T.R("configuration_management", "RHEL-10-200632", "aide_sha512", [("aide", "rule_lines")],
    [["lines := input.aide.rule_lines", "is_array(lines)", "count(lines) > 0",
      'used := {h | some l in lines; is_string(l); hs := _aide_line_hashes(l); some h in hs}', '"sha512" in used', 'used == {"sha512"}']],
    {"aide": {"rule_lines": ["FIPSR = p+i+n+u+g+s+m+ftype+growing+acl+selinux+xattrs+sha512", "NORMAL = FIPSR+sha512"]}},
    [{"aide": {"rule_lines": ["FIPSR = p+i+n+u+g+s+m+acl+selinux+xattrs+sha512", "NORMAL = FIPSR+sha256"]}},
     {"aide": {"rule_lines": ["NORMAL = FIPSR+md5+sha512"]}}, {"aide": {"rule_lines": ["NORMAL = FIPSR"]}}],
    "the uncommented hash lines of /etc/aide.conf must use sha512 and no other hash (no md5, sha1, whirlpool, tiger ...), "
    "or another FIPS-validated file integrity tool must be attested (input.attest.rhel_10_200632_other_tool)",
    "Use sha512 as the only hash in the /etc/aide.conf rule definitions",
    comment="input.aide.rule_lines: uncommented /etc/aide.conf lines naming hashes (grep -iE 'sha|md5|rmd' /etc/aide.conf)",
    attest_alts=[['_attested("rhel_10_200632_other_tool")']],
    pass_cases=[{"aide": {"rule_lines": []}, "attest": {"rhel_10_200632_other_tool": True}}])

# ── library files: every file under the library directories (find -L ... -type f / ! -type d), not only *.so* ────
for sid, path, name, expect, fix in [
    ("RHEL-10-400215", "library_dir_files_group_or_world_writable", "library_files_mode_ok",
     "no file under /lib, /lib64, /usr/lib, /usr/lib64 may be group- or world-writable (find -L ... -perm /022 -type f)", "chmod go-w"),
    ("RHEL-10-400110", "library_dir_files_not_owned_by_root", "library_files_owned_root",
     "every non-directory under /lib, /lib64, /usr/lib, /usr/lib64 must be owned by root (find -L ... ! -user root ! -type d)", "chown root"),
]:
    T.R("file_permissions", sid, name, [("file_permissions", path)],
        [[f'xs := object.get(input, ["file_permissions", "{path}"], null)', "is_array(xs)", "count(xs) == 0"]],
        {"file_permissions": {path: []}}, [{"file_permissions": {path: ["/usr/lib/libexample.a"]}}],
        expect, f"{fix} on every file the find command lists",
        comment=f"input.file_permissions.{path}: the offender list of the RHEL 10 find command (every file, not only *.so*)")

RULES, SECTION_HELPERS = T.finish()
# the shared cipher/MAC helper paragraph cites the RHEL 9 MAC rule, which RHEL 10 does not reuse (RHEL-10-300060 is its own)
SECTION_HELPERS = {k: v.replace(" / RHEL-09-255075", "") for k, v in SECTION_HELPERS.items()}
OWN_HELPERS = T.extra
