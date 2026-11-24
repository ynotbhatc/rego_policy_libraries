"""Reviewed logic table, part 2, for gen_rhel9.py (DISA STIG for RHEL 9, V2R10): 69 rules, RHEL-09-231150 to
RHEL-09-252060 (mount options, disk encryption, file ownership and modes, firewalld, chrony, DNS, IPsec, postfix).

Same spec format as rhel9_rules.py (see R there); imported by the last lines of rhel9_rules.py, so every rule
lands in the same RULES / SECTION_HELPERS. Each entry was written against the full V2R10 check text.
"""
from rhel9_rules import MOUNTS, R, empty_list_rule, helpers, module_rule, without


def _ensure_mount(point, device):
    """The shared mount-table fixture (rhel9_rules.MOUNTS) must hold every mount point a rule reads: the green
    fixtures of all mount rules are one list. Idempotent, so another part adding the same mount point is harmless."""
    if not any(m["mount"] == point for m in MOUNTS):
        MOUNTS.append({"mount": point, "device": device, "fstype": "xfs", "options": ["rw", "nodev", "nosuid", "noexec"]})


_ensure_mount("/var/tmp", "/dev/mapper/rhel-var_tmp")


def _remount(point, options):
    old = next(m for m in MOUNTS if m["mount"] == point)
    return without(point) + [dict(old, options=options)]


# ── configuration_management: mount options (mount | grep <point>) ───────────────────────────────
for sid, point, opt in (("RHEL-09-231150", "/var/log", "noexec"), ("RHEL-09-231155", "/var/log", "nosuid"),
                        ("RHEL-09-231160", "/var/log/audit", "nodev"), ("RHEL-09-231165", "/var/log/audit", "noexec"),
                        ("RHEL-09-231170", "/var/log/audit", "nosuid"), ("RHEL-09-231175", "/var/tmp", "nodev"),
                        ("RHEL-09-231180", "/var/tmp", "noexec"), ("RHEL-09-231185", "/var/tmp", "nosuid")):
    R("configuration_management", sid, point.strip("/").replace("/", "_") + "_" + opt, [("filesystem_mounts",)],
      [[f'm := _mount("{point}")', f'"{opt}" in m.options']],
      {"filesystem_mounts": MOUNTS},
      [{"filesystem_mounts": _remount(point, [o for o in ["rw", "nodev", "nosuid", "noexec"] if o != opt])},
       {"filesystem_mounts": _remount(point, ["rw", "x" + opt + "x"])},
       {"filesystem_mounts": without(point)}],
      f"the {point} file system must be mounted with the {opt} option (mount | grep {point})",
      f"Add {opt} to the {point} options in /etc/fstab and remount",
      comment=f"the {point} entry of the mount table must carry {opt} (exact option token); no {point} mount entry "
              "cannot show the option and stays a finding")

R("configuration_management", "RHEL-09-231200", "nonroot_local_partitions_nodev", [("filesystem_mounts",)],
  [["mounts := input.filesystem_mounts", "is_array(mounts)",
    "count([m |\n\tsome m in mounts\n\t_nonroot_dev_mount(m)\n\tnot _mount_has_option(m, \"nodev\")\n]) == 0"]],
  {"filesystem_mounts": MOUNTS},
  [{"filesystem_mounts": _remount("/home", ["rw", "nosuid"])},
   {"filesystem_mounts": MOUNTS + [{"mount": "/data", "device": "/dev/sdb1", "fstype": "xfs"}]}],
  "every mount of a /dev device on a mount point other than / must carry the nodev option",
  "Add nodev to every non-root local partition in /etc/fstab and remount",
  comment="mount | grep '^/dev\\S* on /\\S' | grep --invert-match 'nodev': mount entries whose device starts with /dev "
          "and whose mount point is not /",
  pass_cases=[{"filesystem_mounts": MOUNTS + [{"mount": "/", "device": "/dev/mapper/rhel-root", "fstype": "xfs", "options": ["rw"]},
                                              {"mount": "/run", "device": "tmpfs", "fstype": "tmpfs", "options": ["rw"]}]}])
helpers("configuration_management", r'''
# a mount the RHEL-09-231200 grep selects: device under /dev, mount point below / (not / itself)
_nonroot_dev_mount(m) if {
	is_string(m.device)
	startswith(m.device, "/dev")
	is_string(m.mount)
	regex.match(`^/\S`, m.mount)
}

# the mount entry lists the option (an entry without an options list does not)
_mount_has_option(m, opt) if {
	is_array(m.options)
	opt in m.options
}

# /boot and /boot/efi are the two file systems the check leaves out. A helper on the whole entry, because
# `not f.mount in {...}` is undefined for an entry without a mount and would drop it from the checked list.
_boot_fs(f) if f.mount in {"/boot", "/boot/efi"}''')

# ── configuration_management: data at rest ───────────────────────────────────────────────────────
_FS = [{"mount": "/", "device": "/dev/mapper/rhel-root", "crypt": [{"name": "luks-b74f6910", "type": "LUKS2"}]},
       {"mount": "/home", "device": "/dev/mapper/rhel-home", "crypt": [{"name": "luks-b74f6910", "type": "LUKS2"}]},
       {"mount": "/boot", "device": "/dev/nvme0n1p2", "crypt": []},
       {"mount": "/boot/efi", "device": "/dev/nvme0n1p1", "crypt": []}]
R("configuration_management", "RHEL-09-231190", "persistent_filesystems_encrypted", [("disk_encryption", "filesystems")],
  [["fss := input.disk_encryption.filesystems", "is_array(fss)",
    'checked := [f | some f in fss; not _boot_fs(f)]', "count(checked) > 0",
    "every f in checked {\n\t_luks_parent(f)\n}"]],
  {"disk_encryption": {"filesystems": _FS}},
  [{"disk_encryption": {"filesystems": [dict(_FS[0], crypt=[])] + _FS[1:]}},
   {"disk_encryption": {"filesystems": [dict(_FS[0], crypt=[{"name": "plain0", "type": "PLAIN"}])] + _FS[1:]}},
   {"disk_encryption": {"filesystems": [{"mount": "/", "device": "/dev/sda3"}] + _FS[2:]}},
   {"disk_encryption": {"filesystems": _FS[2:]}},
   {"disk_encryption": {"filesystems": _FS[:2] + [{"device": "/dev/nvme0n1p2", "crypt": []}]}}],
  "every persistent file system except /boot and /boot/efi must sit on a crypt block device of type LUKS "
  "(lsblk --tree, cryptsetup status), or the administrator must show how the file systems are encrypted "
  "(input.attest.rhel_09_231190_encryption_evidence)",
  "Encrypt the partitions holding persistent file systems with LUKS (dedicate an encrypted partition in the layout)",
  comment="input.disk_encryption.filesystems[{mount, device, crypt: [{name, type}]}]: each persistent file system and the "
          "crypt-type parents in its lsblk tree with the cryptsetup status type; a documented and approved reason for no "
          "OS-level encryption is Not Applicable",
  attest_alts=[['_attested("rhel_09_231190_encryption_evidence")']],
  na=[['_attested("rhel_09_231190_no_os_encryption_approved")']],
  na_expect="a documented and approved reason for not having data-at-rest encryption at the operating system level",
  na_cases=[{"disk_encryption": {"filesystems": _FS[2:]}, "attest": {"rhel_09_231190_no_os_encryption_approved": True}}],
  pass_cases=[{"disk_encryption": {"filesystems": [dict(_FS[0], crypt=[{"name": "luks-1", "type": "LUKS1"}])] + _FS[1:]}},
              {"disk_encryption": {"filesystems": _FS[2:]}, "attest": {"rhel_09_231190_encryption_evidence": True}}])
helpers("configuration_management", r'''
# the file system has a crypt parent block device whose cryptsetup type is LUKS (LUKS1 / LUKS2)
_luks_parent(f) if {
	some c in f.crypt
	is_string(c.type)
	startswith(upper(c.type), "LUKS")
}''')

module_rule("configuration_management", "RHEL-09-231195", "cramfs_disabled", "cramfs", "rhel_09_231195_cramfs_documented")

# ── file_permissions ─────────────────────────────────────────────────────────────────────────────
FP = "file_permissions"

empty_list_rule(FP, "RHEL-09-232015", "library_dirs_permissions_ok", [FP, "library_dirs_group_or_world_writable"],
                "/usr/lib64/site 0775", "no directory under /lib, /lib64, /usr/lib, /usr/lib64 may be group- or world-writable",
                "chmod 755 each listed library directory",
                "output of find -L /lib /lib64 /usr/lib /usr/lib64 -perm /022 -type d")
empty_list_rule(FP, "RHEL-09-232040", "cron_permissions_default", [FP, "cron_rpm_verify_deviations"],
                ".M.......  c /etc/crontab",
                "rpm --verify cronie crontabs must report no owner, group or mode deviation for the cron files and directories",
                "Restore the defaults: dnf reinstall cronie crontabs; rpm --setugids cronie crontabs; rpm --setperms cronie crontabs",
                "lines of rpm --verify cronie crontabs | awk '! ($2 == \"c\" && $1 ~ /^.\\..\\.\\.\\.\\..\\./) {print $0}'")
empty_list_rule(FP, "RHEL-09-232045", "init_files_permissions_ok", [FP, "init_files_more_permissive_than_0740"],
                "/home/disauser/.somepermissivefile",
                "no local initialization file (dot file up to two levels under /home and /root) may have a mode more permissive than 0740",
                "chmod 0740 each listed initialization file",
                "output of find /home /root -maxdepth 2 -type f -name '.*' -perm /037")
empty_list_rule(FP, "RHEL-09-232190", "sys_commands_owned_root", [FP, "system_commands_not_owned_by_root"],
                "nobody /usr/local/bin/tool",
                "every system command in /bin, /sbin, /usr/bin, /usr/sbin, /usr/libexec, /usr/local/bin, /usr/local/sbin must be owned by root",
                "chown root each listed command",
                "output of find -L /bin /sbin /usr/bin /usr/sbin /usr/libexec /usr/local/bin /usr/local/sbin ! -user root")
empty_list_rule(FP, "RHEL-09-232205", "lib_files_group_root", [FP, "library_files_not_group_owned_by_root"],
                "/usr/lib64/libx.so.1 staff",
                "every shared library file (*.so*) in /lib, /lib64, /usr/lib, /usr/lib64 must be group-owned by root",
                "chown :root each listed library file",
                "output of find /lib /lib64 /usr/lib /usr/lib64 -type f -name '*.so*' ! -group root")
empty_list_rule(FP, "RHEL-09-232210", "library_dirs_owned_root", [FP, "library_dirs_not_owned_by_root"],
                "nobody /usr/lib64/site",
                "every directory under /lib, /lib64, /usr/lib, /usr/lib64 must be owned by root",
                "chown root each listed library directory",
                "output of find /lib /lib64 /usr/lib /usr/lib64 ! -user root -type d")
empty_list_rule(FP, "RHEL-09-232245", "public_dirs_sticky", [FP, "world_writable_dirs_without_sticky_bit"],
                "/srv/share",
                "every world-writable directory must have the sticky bit set",
                "chmod a+t each listed directory",
                "output of find / -type d \\( -perm -0002 -a ! -perm -1000 \\) -print")

# single files and directories: mode (stat -c %a), owner (%U), group (%G) under input.file_permissions.<key>
_FILES = {"etc_group": "/etc/group", "etc_group_backup": "/etc/group-", "etc_gshadow": "/etc/gshadow",
          "etc_gshadow_backup": "/etc/gshadow-", "etc_passwd": "/etc/passwd", "etc_passwd_backup": "/etc/passwd-",
          "etc_shadow": "/etc/shadow", "etc_shadow_backup": "/etc/shadow-", "etc_audit_dir": "/etc/audit/",
          "var_log": "/var/log", "var_log_messages": "/var/log/messages"}

for sid, key, mx, bad, ok in (("RHEL-09-232025", "var_log", "0755", "0775", "750"),
                              ("RHEL-09-232030", "var_log_messages", "0640", "0644", "600"),
                              ("RHEL-09-232060", "etc_group_backup", "0644", "0664", "600"),
                              ("RHEL-09-232070", "etc_gshadow_backup", "0000", "0600", "0"),
                              ("RHEL-09-232080", "etc_passwd_backup", "0644", "0646", "600"),
                              ("RHEL-09-232085", "etc_shadow_backup", "0000", "0400", "0")):
    f = _FILES[key]
    R(FP, sid, key.removeprefix("etc_") + "_mode_ok", [(FP, key, "mode")],
      [[f'mode_within(input.file_permissions.{key}.mode, "{mx}")']],
      {FP: {key: {"mode": mx}}}, [{FP: {key: {"mode": bad}}}, {FP: {key: {"mode": "rw-r--r--"}}}],
      f"{f} must have mode {mx}" + (" or less permissive" if mx != "0000" else ""), f"chmod {mx} {f}",
      comment=f"mode of {f} (stat -c %a) as an octal string", pass_cases=[{FP: {key: {"mode": ok}}}])

for sid, key, attr in (("RHEL-09-232090", "etc_group", "owner"), ("RHEL-09-232095", "etc_group", "group"),
                       ("RHEL-09-232100", "etc_group_backup", "owner"), ("RHEL-09-232105", "etc_group_backup", "group"),
                       ("RHEL-09-232103", "etc_audit_dir", "owner"), ("RHEL-09-232104", "etc_audit_dir", "group"),
                       ("RHEL-09-232110", "etc_gshadow", "owner"), ("RHEL-09-232115", "etc_gshadow", "group"),
                       ("RHEL-09-232120", "etc_gshadow_backup", "owner"), ("RHEL-09-232125", "etc_gshadow_backup", "group"),
                       ("RHEL-09-232130", "etc_passwd", "owner"), ("RHEL-09-232135", "etc_passwd", "group"),
                       ("RHEL-09-232140", "etc_passwd_backup", "owner"), ("RHEL-09-232145", "etc_passwd_backup", "group"),
                       ("RHEL-09-232150", "etc_shadow", "owner"), ("RHEL-09-232155", "etc_shadow", "group"),
                       ("RHEL-09-232160", "etc_shadow_backup", "owner"), ("RHEL-09-232165", "etc_shadow_backup", "group"),
                       ("RHEL-09-232170", "var_log", "owner"), ("RHEL-09-232175", "var_log", "group"),
                       ("RHEL-09-232180", "var_log_messages", "owner"), ("RHEL-09-232185", "var_log_messages", "group")):
    f = _FILES[key]
    what, fmt, cmd = ("be owned by root", "%U", "chown") if attr == "owner" else ("be group-owned by root", "%G", "chgrp")
    R(FP, sid, f"{key.removeprefix('etc_')}_{attr}_root", [(FP, key, attr)],
      [[f'_str(["{FP}", "{key}", "{attr}"]) == "root"']],
      {FP: {key: {attr: "root"}}}, [{FP: {key: {attr: "nobody"}}}, {FP: {key: {attr: "Root"}}}],
      f"{f} must {what}", f"{cmd} root {f}",
      comment=f"{attr} of {f} (stat -c \"{fmt} %n\" {f})")

# the seven audit tools the checks stat: input.file_permissions.audit_tools[{path, mode, owner, group}] (the ones that exist)
_TOOLS = ["/sbin/auditctl", "/sbin/aureport", "/sbin/ausearch", "/sbin/autrace", "/sbin/auditd", "/sbin/rsyslogd", "/sbin/augenrules"]
_TOOLS_GREEN = [{"path": p, "mode": "750" if p.endswith("autrace") else "755", "owner": "root", "group": "root"} for p in _TOOLS]


def _tools_with(**kw):
    return [dict(_TOOLS_GREEN[0], **kw)] + _TOOLS_GREEN[1:]


def _tools_without(k):
    return [{a: b for a, b in _TOOLS_GREEN[0].items() if a != k}] + _TOOLS_GREEN[1:]


_TOOLS_TXT = "auditctl, aureport, ausearch, autrace, auditd, rsyslogd and augenrules under /sbin"
for sid, name, attr, test, bads, expect, fix in (
        ("RHEL-09-232035", "audit_tools_mode_ok", "mode", 'mode_within(t.mode, "0755")', ["0775", "4755"],
         f"no audit tool ({_TOOLS_TXT}) may have a mode more permissive than 0755", "chmod 0755 each listed audit tool"),
        ("RHEL-09-232220", "audit_tools_owner_root", "owner", 't.owner == "root"', ["nobody"],
         f"every audit tool ({_TOOLS_TXT}) must be owned by root", "chown root each listed audit tool"),
        ("RHEL-09-232225", "audit_tools_group_root", "group", 't.group == "root"', ["wheel"],
         f"every audit tool ({_TOOLS_TXT}) must be group-owned by root", "chgrp root each listed audit tool")):
    R(FP, sid, name, [(FP, "audit_tools")],
      [["tools := input.file_permissions.audit_tools", "is_array(tools)", f"every t in tools {{\n\t{test}\n}}"]],
      {FP: {"audit_tools": _TOOLS_GREEN}},
      [{FP: {"audit_tools": _tools_with(**{attr: b})}} for b in bads] + [{FP: {"audit_tools": _tools_without(attr)}}],
      expect, fix,
      comment=f"{attr} of each audit tool (stat -c on {' '.join(_TOOLS)}): input.file_permissions.audit_tools[{{path, mode, owner, group}}]",
      pass_cases=[{FP: {"audit_tools": _TOOLS_GREEN[:5]}}])

_CRON = [{"path": p, "owner": "root", "group": "root"} for p in
         ("/etc/cron.d", "/etc/cron.daily", "/etc/cron.deny", "/etc/cron.hourly", "/etc/cron.monthly", "/etc/crontab", "/etc/cron.weekly")]
for sid, attr, fmt, cmd in (("RHEL-09-232230", "owner", "%U", "chown"), ("RHEL-09-232235", "group", "%G", "chgrp")):
    R(FP, sid, f"cron_config_{attr}_root", [(FP, "cron_config")],
      [["items := input.file_permissions.cron_config", "is_array(items)", f'every c in items {{\n\tc.{attr} == "root"\n}}']],
      {FP: {"cron_config": _CRON}},
      [{FP: {"cron_config": _CRON[:-1] + [dict(_CRON[-1], **{attr: "bin"})]}},
       {FP: {"cron_config": _CRON[:-1] + [{"path": "/etc/cron.weekly"}]}}],
      f"every /etc/cron* file and directory must be {'owned' if attr == 'owner' else 'group-owned'} by root",
      f"{cmd} root each listed cron configuration file or directory",
      comment=f"stat -c \"{fmt} %n\" /etc/cron*: input.file_permissions.cron_config[{{path, owner, group}}]")

# group ownership "by root or a required system account": the find lists what is not group root; a listed entry
# passes only when its group is a system group (GID below 1000)
helpers(FP, r'''
# an entry {path, group, gid} whose group is a system account group (GID below 1000, type-guarded)
_system_group(e) if {
	is_number(e.gid)
	e.gid < 1000
}

_system_group(e) if {
	is_string(e.gid)
	regex.match(`^\s*[0-9]+\s*$`, e.gid)
	to_number(trim_space(e.gid)) < 1000
}''')
for sid, name, key, what, find in (
        ("RHEL-09-232195", "sys_commands_group_root", "system_commands_not_group_owned_by_root",
         "system command in /bin, /sbin, /usr/bin, /usr/sbin, /usr/libexec, /usr/local/bin, /usr/local/sbin",
         "find -L /bin /sbin /usr/bin /usr/sbin /usr/libexec /usr/local/bin /usr/local/sbin ! -group root -exec stat -L -c \"%G %g %n\""),
        ("RHEL-09-232215", "library_dirs_group_root", "library_dirs_not_group_owned_by_root",
         "directory under /lib, /lib64, /usr/lib, /usr/lib64",
         "find /lib /lib64 /usr/lib /usr/lib64 ! -group root -type d -exec stat -c \"%G %g %n\"")):
    R(FP, sid, name, [(FP, key)],
      [[f"xs := input.file_permissions.{key}", "is_array(xs)", "every e in xs {\n\t_system_group(e)\n}"]],
      {FP: {key: []}},
      [{FP: {key: [{"path": "/usr/local/x", "group": "staff", "gid": 1001}]}},
       {FP: {key: [{"path": "/usr/local/x", "group": "staff", "gid": "users"}]}},
       {FP: {key: [{"path": "/usr/local/x", "group": "tty"}]}}],
      f"every {what} must be group-owned by root or a system account group (GID below 1000)",
      "chgrp root each listed entry whose group is not a required system account",
      comment=f"{find}: input.file_permissions.{key}[{{path, group, gid}}]",
      pass_cases=[{FP: {key: [{"path": "/usr/bin/write", "group": "tty", "gid": 5}, {"path": "/usr/x", "group": "utmp", "gid": "22"}]}}])

R(FP, "RHEL-09-232240", "world_writable_dirs_owner_ok", [(FP, "world_writable_dirs_owned_by_uid_1000_plus")],
  [[f"xs := input.file_permissions.world_writable_dirs_owned_by_uid_1000_plus", "is_array(xs)", "count(xs) == 0"]],
  {FP: {"world_writable_dirs_owned_by_uid_1000_plus": []}},
  [{FP: {"world_writable_dirs_owned_by_uid_1000_plus": ["disauser, 1001, drwxrwxrwt, /srv/share"]}}],
  "no world-writable directory may be owned by an account with UID 1000 or above, unless every listed owner is an "
  "approved system or application account (input.attest.rhel_09_232240_owners_approved)",
  "chown each listed directory to root or a system account",
  comment="output of find / -xdev -type d -perm -0002 -uid +999 -exec stat -c \"%U, %u, %A, %n\"",
  attest_alts=[['_attested("rhel_09_232240_owners_approved")']],
  pass_cases=[{FP: {"world_writable_dirs_owned_by_uid_1000_plus": ["appsvc, 1500, drwxrwxrwt, /opt/app/spool"]},
               "attest": {"rhel_09_232240_owners_approved": True}}])

R(FP, "RHEL-09-232260", "device_files_labeled", [("device_file_labels", "device_t"), ("device_file_labels", "unlabeled_t")],
  [["un := input.device_file_labels.unlabeled_t", "is_array(un)", "count(un) == 0",
    "dev := input.device_file_labels.device_t", "is_array(dev)", "_device_t_ok(dev)"]],
  {"device_file_labels": {"device_t": [], "unlabeled_t": []}},
  [{"device_file_labels": {"unlabeled_t": [{"path": "/dev/x", "context": "system_u:object_r:unlabeled_t:s0"}]}},
   {"device_file_labels": {"device_t": [{"path": "/dev/odd0", "context": "system_u:object_r:device_t:s0"}]}},
   {"device_file_labels": {"unlabeled_t": [{"path": "/dev/x", "context": "system_u:object_r:unlabeled_t:s0"}]},
    "attest": {"rhel_09_232260_vm_device_files": True}}],
  "no character or block device file may carry the device_t or unlabeled_t SELinux type; device_t files a virtual "
  "machine needs (such as /dev/vmci) are allowed when attested (input.attest.rhel_09_232260_vm_device_files)",
  "Restore the label of each listed device file: restorecon -v <device_path>",
  comment="find /dev -context *:device_t:* / *:unlabeled_t:* \\( -type c -o -type b \\) -printf \"%p %Z\\n\": "
          "input.device_file_labels.{device_t, unlabeled_t}[{path, context}]",
  kind="machine+attestation",
  pass_cases=[{"device_file_labels": {"device_t": [{"path": "/dev/vmci", "context": "system_u:object_r:device_t:s0"}]}},
              {"device_file_labels": {"device_t": [{"path": "/dev/vsock", "context": "system_u:object_r:device_t:s0"}]},
               "attest": {"rhel_09_232260_vm_device_files": True}}])
helpers(FP, r'''
# device_t device files: none, only the hypervisor device the check text names, or attested as virtual machine devices
_device_t_ok(dev) if {
	every d in dev {
		d.path == "/dev/vmci"
	}
}

_device_t_ok(_) if _attested("rhel_09_232260_vm_device_files")''')

# ── network: firewalld ───────────────────────────────────────────────────────────────────────────
R("network", "RHEL-09-251010", "firewalld_installed", [("packages", "firewalld")],
  [["input.packages.firewalld == true"]],
  {"packages": {"firewalld": True}}, [{"packages": {"firewalld": False}}],
  "the firewalld package must be installed", "Install firewalld: dnf install firewalld",
  comment="input.packages.firewalld (dnf list --installed firewalld)")

R("network", "RHEL-09-251020", "firewall_default_deny",
  [("firewalld", "active_zones"), ("firewalld", "default_zone", "target_runtime"), ("firewalld", "default_zone", "target_permanent")],
  [["zones := input.firewalld.active_zones", "is_array(zones)", "count(zones) > 0",
    '_str(["firewalld", "default_zone", "target_runtime"]) == "DROP"',
    '_str(["firewalld", "default_zone", "target_permanent"]) == "DROP"']],
  {"firewalld": {"active_zones": ["drop"], "default_zone": {"target_runtime": "DROP", "target_permanent": "DROP"}}},
  [{"firewalld": {"active_zones": []}},
   {"firewalld": {"default_zone": {"target_runtime": "default"}}},
   {"firewalld": {"default_zone": {"target_permanent": "ACCEPT"}}},
   {"firewalld": {"default_zone": {"target_runtime": "%%REJECT%%", "target_permanent": "%%REJECT%%"}}}],
  "at least one firewalld zone must be active and the default zone's runtime and permanent targets must both be DROP",
  "Add the required exceptions to the drop zone, then: firewall-cmd --reload; firewall-cmd --set-default-zone=drop; "
  "firewall-cmd --permanent --zone=drop --change-interface=<if>; firewall-cmd --reload",
  comment="firewall-cmd --get-active-zones (zone names; empty when none or firewalld is not running) and the target of the "
          "default zone: firewall-cmd --list-all --zone=$(firewall-cmd --get-default-zone), and the same with --permanent")

R("network", "RHEL-09-251030", "firewall_backend_nftables", [("firewalld_conf", "FirewallBackend")],
  [['_str(["firewalld_conf", "FirewallBackend"]) == "nftables"']],
  {"firewalld_conf": {"FirewallBackend": "nftables"}}, [{"firewalld_conf": {"FirewallBackend": "iptables"}}],
  "FirewallBackend in /etc/firewalld/firewalld.conf must be nftables",
  "Set FirewallBackend=nftables in /etc/firewalld/firewalld.conf and establish the rate-limiting rules",
  comment="FirewallBackend as configured in /etc/firewalld/firewalld.conf (null when missing or commented out)")

R("network", "RHEL-09-251035", "firewall_services_match_ppsm", [("firewalld", "zone_services")],
  [["is_array(input.firewalld.zone_services)", '_attested("rhel_09_251035_ppsm_clsa_match")']],
  {"firewalld": {"zone_services": ["drop (active)", "  services: ssh"]}, "attest": {"rhel_09_251035_ppsm_clsa_match": True}},
  [{"attest": {"rhel_09_251035_ppsm_clsa_match": False}}, {"firewalld": {"zone_services": "ssh"}}],
  "the services the firewall allows (input.firewalld.zone_services) must be reviewed against the site PPSM CLSA and the "
  "PPSM CAL, and the match attested (input.attest.rhel_09_251035_ppsm_clsa_match)",
  "Update the firewall settings and running services to comply with the PPSM CLSA and the PPSM CAL, then firewall-cmd --reload",
  comment="document review: the lines of firewall-cmd --list-all-zones | grep -e \"active\" -e \"services\" are collected for "
          "the reviewer; the comparison with the PPSM CLSA is the attestation, never decided from the facts",
  kind="machine+attestation")

# ── services: time synchronisation (chrony) ──────────────────────────────────────────────────────
R("services", "RHEL-09-252010", "chrony_installed", [("packages", "chrony")], [["input.packages.chrony == true"]],
  {"packages": {"chrony": True}}, [{"packages": {"chrony": False}}],
  "the chrony package must be installed", "Install chrony: dnf install chrony",
  comment="input.packages.chrony (dnf list --installed chrony)")

R("services", "RHEL-09-252015", "chronyd_active", [("services", "chronyd")], [['_kw(["services", "chronyd"]) == "active"']],
  {"services": {"chronyd": "active"}}, [{"services": {"chronyd": "inactive"}}, {"services": {"chronyd": "failed"}}],
  "chronyd must be active (systemctl is-active chronyd)", "Enable the service: systemctl enable --now chronyd",
  comment="systemctl is-active chronyd")

_SRC = [{"directive": "server", "address": "0.us.pool.ntp.mil", "maxpoll": "16"}]
R("services", "RHEL-09-252020", "chrony_maxpoll_and_source", [("chrony_conf", "sources")],
  [["srcs := input.chrony_conf.sources", "is_array(srcs)",
    'count([s | some s in srcs; s.directive == "server"]) > 0',
    'polls := [p | some s in srcs; p := object.get(s, "maxpoll", null); p != null]', "count(polls) > 0",
    "every p in polls {\n\t_maxpoll_ok(p)\n}",
    '_attested("rhel_09_252020_authoritative_time_source")']],
  {"chrony_conf": {"sources": _SRC}, "attest": {"rhel_09_252020_authoritative_time_source": True}},
  [{"chrony_conf": {"sources": [dict(_SRC[0], maxpoll=17)]}},
   {"chrony_conf": {"sources": [dict(_SRC[0], maxpoll="sixteen")]}},
   {"chrony_conf": {"sources": [{"directive": "server", "address": "0.us.pool.ntp.mil"}]}},
   {"chrony_conf": {"sources": [{"directive": "pool", "address": "2.rhel.pool.ntp.org", "maxpoll": 10}]}},
   {"chrony_conf": {"sources": []}},
   {"attest": {"rhel_09_252020_authoritative_time_source": False}}],
  "an uncommented time source line in /etc/chrony.conf must set maxpoll, no maxpoll may exceed 16, a server must be "
  "configured, and it must be attested as an authoritative DoW time source (input.attest.rhel_09_252020_authoritative_time_source)",
  "Set in /etc/chrony.conf: server [ntp.server.name] iburst maxpoll 16",
  comment="uncommented server / pool / peer lines of /etc/chrony.conf: input.chrony_conf.sources[{directive, address, maxpoll}] "
          "(maxpoll null when the line has none); whether the server is an authoritative DoW source is an attestation",
  kind="machine+attestation",
  pass_cases=[{"chrony_conf": {"sources": [dict(_SRC[0], maxpoll=10), {"directive": "server", "address": "1.us.pool.ntp.mil"}]}}])
helpers("services", r'''
# a maxpoll value the check accepts: a number (or decimal string) not greater than 16
_maxpoll_ok(p) if {
	is_number(p)
	p <= 16
}

_maxpoll_ok(p) if {
	is_string(p)
	regex.match(`^\s*-?[0-9]+\s*$`, p)
	to_number(trim_space(p)) <= 16
}''')

for sid, key, name, what in (("RHEL-09-252025", "port", "chrony_server_disabled", "disable the chrony daemon from acting as a server"),
                             ("RHEL-09-252030", "cmdport", "chrony_cmdport_disabled", "disable network management of the chrony daemon")):
    extra = {}
    if key == "port":
        extra = dict(na=[['_attested("rhel_09_252025_ntp_server")']], na_expect="the system is serving as an NTP server",
                     na_cases=[{"chrony_conf": {"port": "123"}, "attest": {"rhel_09_252025_ntp_server": True}}])
    R("services", sid, name, [("chrony_conf", key)], [[f'_str(["chrony_conf", "{key}"]) == "0"']],
      {"chrony_conf": {key: "0"}}, [{"chrony_conf": {key: "123"}}, {"chrony_conf": {key: "323"}}],
      f"{key} in /etc/chrony.conf must be 0 (uncommented) to {what}", f"Set {key} 0 in /etc/chrony.conf",
      comment=f"the {key} directive as configured in /etc/chrony.conf (grep -w {key}; null when missing or commented out)",
      pass_cases=[{"chrony_conf": {key: 0}}], **extra)

# ── network: DNS, tunnels ────────────────────────────────────────────────────────────────────────
R("network", "RHEL-09-252035", "two_nameservers", [("resolv_conf", "nameservers")],
  [["ns := input.resolv_conf.nameservers", "is_array(ns)", "count(ns) >= 2"]],
  {"resolv_conf": {"nameservers": ["ns1.example.mil", "ns2.example.mil"]}},
  [{"resolv_conf": {"nameservers": ["ns1.example.mil"]}}, {"resolv_conf": {"nameservers": []}}],
  "/etc/resolv.conf must carry at least two uncommented nameserver lines",
  "Configure two or more name servers (in /etc/resolv.conf when the NetworkManager DNS mode is none, else on the connection: nmcli connection modify <name> ipv4.dns <ip>)",
  comment="the value of each uncommented nameserver line of /etc/resolv.conf, in file order; a cloud platform whose provider "
          "gives a single highly available DNS address is Not Applicable (attested)",
  na=[['_attested("rhel_09_252035_cloud_single_dns")']],
  na_expect="the system runs in a cloud platform whose provider gives a single, highly available DNS address",
  na_cases=[{"resolv_conf": {"nameservers": ["ns1.example.mil"]}, "attest": {"rhel_09_252035_cloud_single_dns": True}}])

R("network", "RHEL-09-252040", "networkmanager_dns_mode", [("networkmanager", "main", "dns")],
  [['_str(["networkmanager", "main", "dns"]) in {"default", "none", "systemd-resolved"}']],
  {"networkmanager": {"main": {"dns": "none"}}},
  [{"networkmanager": {"main": {"dns": "dnsmasq"}}}, {"networkmanager": {"main": {"dns": ""}}}],
  "the dns key in the [main] section of NetworkManager --print-config must be default, none or systemd-resolved, or a DNS "
  "resolver other than NetworkManager must be documented and approved by the ISSO (input.attest.rhel_09_252040_other_resolver_approved)",
  "Set dns = default, none or systemd-resolved in the [main] section of /etc/NetworkManager/NetworkManager.conf and reload NetworkManager",
  comment="dns key under [main] in NetworkManager --print-config (null when the key does not exist)",
  attest_alts=[['_attested("rhel_09_252040_other_resolver_approved")']],
  pass_cases=[{"networkmanager": {"main": {"dns": "default"}}}, {"networkmanager": {"main": {"dns": "systemd-resolved"}}},
              {"networkmanager": {"main": {"dns": "dnsmasq"}}, "attest": {"rhel_09_252040_other_resolver_approved": True}}])

R("network", "RHEL-09-252045", "no_unauthorized_ip_tunnels", [("services", "ipsec")],
  [['s := _kw(["services", "ipsec"])', 's != "active"'],
   ['_kw(["services", "ipsec"]) == "active"', "conns := input.ipsec.conn_lines", "is_array(conns)", "count(conns) == 0"]],
  {"services": {"ipsec": "inactive"}},
  [{"services": {"ipsec": "active"}, "ipsec": {"conn_lines": ["/etc/ipsec.d/site.conf:1:conn site-to-site"]}},
   {"services": {"ipsec": "active"}}],
  "the ipsec service must not be active, or no IPsec connection (conn) may be configured, or the configured tunnels "
  "must be documented with the ISSO (input.attest.rhel_09_252045_tunnels_approved)",
  "Remove all unapproved tunnels from the system, or document them with the ISSO",
  comment="systemctl is-active ipsec; when active, the lines of grep -rni conn /etc/ipsec.conf /etc/ipsec.d/ (input.ipsec.conn_lines)",
  attest_alts=[['_attested("rhel_09_252045_tunnels_approved")']],
  pass_cases=[{"services": {"ipsec": "active"}, "ipsec": {"conn_lines": []}},
              {"services": {"ipsec": "active"}, "ipsec": {"conn_lines": ["/etc/ipsec.conf:3:conn hq"]},
               "attest": {"rhel_09_252045_tunnels_approved": True}}])

# ── services: mail ───────────────────────────────────────────────────────────────────────────────
R("services", "RHEL-09-252050", "postfix_relay_restricted", [("packages", "postfix")],
  [["input.packages.postfix == true", 's := _str(["postfix", "smtpd_client_restrictions"])',
    r'entries := [e | some e in regex.split(`[\s,]+`, s); e != ""]', "count(entries) > 0",
    'every e in entries {\n\te in {"permit_mynetworks", "reject"}\n}']],
  {"packages": {"postfix": True}, "postfix": {"smtpd_client_restrictions": "permit_mynetworks,reject"}},
  [{"postfix": {"smtpd_client_restrictions": "permit_mynetworks,permit_sasl_authenticated,reject"}},
   {"postfix": {"smtpd_client_restrictions": "permit"}}, {"postfix": {"smtpd_client_restrictions": ""}},
   {"postfix": {"smtpd_client_restrictions": None}}],
  "postfix is installed: postconf -n smtpd_client_restrictions must list only permit_mynetworks and reject, or the "
  "additional entries must be documented with the ISSO (input.attest.rhel_09_252050_restrictions_documented)",
  "Restrict client connections: postconf -e 'smtpd_client_restrictions = permit_mynetworks,reject'",
  comment="the value postconf -n smtpd_client_restrictions prints (input.postfix.smtpd_client_restrictions); postfix not "
          "installed is Not Applicable",
  attest_alts=[['_attested("rhel_09_252050_restrictions_documented")']],
  na=[["input.packages.postfix == false"]], na_expect="postfix is not installed",
  na_cases=[{"packages": {"postfix": False}}],
  pass_cases=[{"postfix": {"smtpd_client_restrictions": "permit_mynetworks, reject"}},
              {"postfix": {"smtpd_client_restrictions": "reject"}},
              {"postfix": {"smtpd_client_restrictions": "permit_sasl_authenticated,reject"},
               "attest": {"rhel_09_252050_restrictions_documented": True}}])

R("services", "RHEL-09-252060", "postmaster_alias_root", [("mail_aliases", "postmaster")],
  [['_str(["mail_aliases", "postmaster"]) == "root"']],
  {"mail_aliases": {"postmaster": "root"}}, [{"mail_aliases": {"postmaster": "admin@example.mil"}}],
  "/etc/aliases must carry an uncommented 'postmaster: root' line, or the SA must show how the SA and ISSO are notified of "
  "an audit processing failure (input.attest.rhel_09_252060_audit_failure_notification)",
  "Append 'postmaster: root' to /etc/aliases and run newaliases",
  comment="the value of the uncommented postmaster entry of /etc/aliases (grep \"postmaster:\\s*root$\"; null when there is none)",
  attest_alts=[['_attested("rhel_09_252060_audit_failure_notification")']],
  pass_cases=[{"mail_aliases": {"postmaster": "admin@example.mil"}, "attest": {"rhel_09_252060_audit_failure_notification": True}}])
