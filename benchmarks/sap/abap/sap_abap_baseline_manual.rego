# Hand-written checks for SAP Security Baseline Template v2.6 (ABAP) — the ones whose CSA condition is not a
# NAME/VALUE test the importer can translate: the gateway and message-server ACL files (line-shaped stores),
# the date-based currency checks, and the kernel patch level, which SAP joins on the kernel release.
# A `# MANUAL-CHECK: <id>` comment claims the id; scripts/import_sap_baseline.py reads these comments and marks
# the registry row `basis: hand_written` instead of generating or giving up on it.
# The package METADATA block is in sap_abap_baseline.rego (one block per package).
package sap_abap_baseline.main

import rego.v1

# ---------------------------------------------------------------------------------------------------------
# RFC gateway ACL files (RFCGW-A) — input.sap.abap.gateway.{secinfo,reginfo,prxyinfo} = {present, lines}
# SAP's rule: a permit line ("P ...") whose every selector is `*` (or absent) is fully generic and defeats the
# ACL. secinfo selectors: TP, HOST, USER, USER-HOST. reginfo: TP, HOST, ACCESS, CANCEL. prxyinfo: SOURCE, DEST.
# ---------------------------------------------------------------------------------------------------------
_acl(file) := input.sap.abap.gateway[file]

# A predicate, not a ref on the function result: `not _acl(f).present == true` is undefined (not true) when
# the file key is absent, because Rego hoists the call out of the negation.
_acl_present(file) if input.sap.abap.gateway[file].present == true

_permit_lines(file) := [l | some l in _acl(file).lines; regex.match(`^\s*P(\s|$)`, l)]

# A selector is generic when it is absent from the line or set to a bare `*`.
_selector_generic(line, key) if not regex.match(sprintf(`(^|\s)%s=`, [key]), line)

_selector_generic(line, key) if regex.match(sprintf(`(^|\s)%s=\*(\s|$)`, [key]), line)

_fully_generic(line, keys) if every k in keys {
	_selector_generic(line, k)
}

_generic_permits(file, keys) := [l | some l in _permit_lines(file); _fully_generic(l, keys)]

# MANUAL-CHECK: RFCGW-A_a secinfo.1
violations contains msg if {
	level_in_profile("critical")
	not _acl_present("secinfo")
	msg := "RFCGW-A_a secinfo.1: RFC Gateway ACL: gw/sec_info file not found (secinfo file absent or unreadable on the host)"
}

# MANUAL-CHECK: RFCGW-A_a secinfo.2
violations contains msg if {
	level_in_profile("critical")
	_acl_present("secinfo")
	g := _generic_permits("secinfo", ["TP", "HOST", "USER", "USER-HOST"])
	count(g) > 0
	msg := sprintf("RFCGW-A_a secinfo.2: RFC gateway ACL: secinfo file entries not fully generic (RFC Gateway hardening) (%d fully generic permit line(s): %v)", [count(g), g])
}

# MANUAL-CHECK: RFCGW-A_a reginfo.1
violations contains msg if {
	level_in_profile("critical")
	not _acl_present("reginfo")
	msg := "RFCGW-A_a reginfo.1: RFC Gateway ACL: gw/reg_info file not found (reginfo file absent or unreadable on the host)"
}

# MANUAL-CHECK: RFCGW-A_a reginfo.2
violations contains msg if {
	level_in_profile("critical")
	_acl_present("reginfo")
	g := _generic_permits("reginfo", ["TP", "HOST", "ACCESS", "CANCEL"])
	count(g) > 0
	msg := sprintf("RFCGW-A_a reginfo.2: RFC gateway ACL: reginfo file entries not fully generic (RFC Gateway hardening) (%d fully generic permit line(s): %v)", [count(g), g])
}

# MANUAL-CHECK: RFCGW-A_h prxinfo.1
violations contains msg if {
	level_in_profile("extended")
	not _acl_present("prxyinfo")
	msg := "RFCGW-A_h prxinfo.1: RFC Gateway ACL: gw/prxy_info file not found (prxyinfo file absent or unreadable on the host)"
}

# MANUAL-CHECK: RFCGW-A_h prxinfo.2
violations contains msg if {
	level_in_profile("extended")
	_acl_present("prxyinfo")
	g := _generic_permits("prxyinfo", ["SOURCE", "DEST"])
	count(g) > 0
	msg := sprintf("RFCGW-A_h prxinfo.2: RFC gateway ACL: prxyinfo file entries not fully generic (RFC Gateway hardening) (%d fully generic permit line(s): %v)", [count(g), g])
}

# ---------------------------------------------------------------------------------------------------------
# Message server ACL (MSGSRV-A) — input.sap.abap.message_server.acl = {present, lines}
# SAP's rule: no HOST entry may be a bare `*` (a `*.example.com` suffix pattern is fine).
# ---------------------------------------------------------------------------------------------------------
_ms_acl := input.sap.abap.message_server.acl

_ms_acl_present if input.sap.abap.message_server.acl.present == true

_ms_generic_hosts := [l |
	some l in _ms_acl.lines
	regex.match(`HOST=[ \t]*\*([ \t]|$)`, l)
]

# MANUAL-CHECK: MSGSRV-A_e.1
violations contains msg if {
	level_in_profile("critical")
	not _ms_acl_present
	msg := "MSGSRV-A_e.1: Message Server ACL should not contain generic entries, such as HOST=* (ACL file, Message Server Security) (ms_acl_info file absent or unreadable on the host)"
}

violations contains msg if {
	level_in_profile("critical")
	_ms_acl_present
	count(_ms_generic_hosts) > 0
	msg := sprintf("MSGSRV-A_e.1: Message Server ACL should not contain generic entries, such as HOST=* (ACL file, Message Server Security) (%d generic HOST entry(ies): %v)", [count(_ms_generic_hosts), _ms_generic_hosts])
}

# MANUAL-CHECK: MSGSRV-A_e.3
# SAP lists the same test again at the extended level (e.3): same evidence, same outcome, so the two never
# disagree; the registry keeps e.3 as hand-written so the Baseline projection shows it assessed.
violations contains msg if {
	level_in_profile("extended")
	not _ms_acl_present
	msg := "MSGSRV-A_e.3: Message Server ACL should not contain generic entries (ACL file, Message Server Security) (ms_acl_info file absent or unreadable on the host)"
}

violations contains msg if {
	level_in_profile("extended")
	_ms_acl_present
	count(_ms_generic_hosts) > 0
	msg := sprintf("MSGSRV-A_e.3: Message Server ACL should not contain generic entries (ACL file, Message Server Security) (%d generic HOST entry(ies))", [count(_ms_generic_hosts)])
}

# ---------------------------------------------------------------------------------------------------------
# Currency checks (SECUPD-A) — dates measured against input.sap.abap.collected_at (or OPA's clock)
# ---------------------------------------------------------------------------------------------------------
_now_ns := t if {
	d := input.sap.abap.collected_at
	t := time.parse_rfc3339_ns(_as_rfc3339(d))
} else := time.now_ns()

_as_rfc3339(d) := d if regex.match(`^\d{4}-\d{2}-\d{2}T`, d)

_as_rfc3339(d) := concat("", [d, "T00:00:00Z"]) if regex.match(`^\d{4}-\d{2}-\d{2}$`, d)

_months := {"Jan": "01", "Feb": "02", "Mar": "03", "Apr": "04", "May": "05", "Jun": "06", "Jul": "07", "Aug": "08", "Sep": "09", "Oct": "10", "Nov": "11", "Dec": "12"}

# "Jan 15 2026" / "Jan  5 2026" (the disp+work banner form) or an ISO date -> ns since epoch
_date_ns(s) := t if {
	m := regex.find_all_string_submatch_n(`([A-Za-z]{3})\s+(\d{1,2})\s+(\d{4})`, s, 1)
	count(m) == 1
	mon := _months[m[0][1]]
	day := sprintf("%02d", [to_number(m[0][2])])
	t := time.parse_rfc3339_ns(sprintf("%s-%s-%sT00:00:00Z", [m[0][3], mon, day]))
}

_date_ns(s) := t if {
	m := regex.find_n(`\d{4}-\d{2}-\d{2}`, s, 1)
	count(m) == 1
	t := time.parse_rfc3339_ns(concat("", [m[0], "T00:00:00Z"]))
}

_age_days(s) := d if {
	d := floor((_now_ns - _date_ns(s)) / (24 * 60 * 60 * 1000000000))
}

# MANUAL-CHECK: SECUPD-A_a.3
violations contains msg if {
	level_in_profile("critical")
	not _kernel_current
	msg := sprintf("SECUPD-A_a.3: SAP Kernel date not older than 365 days (%s)", [_kernel_date_state])
}

_kernel_current if {
	v := fact("kernel", "KERN_COMP_TIME")
	_age_days(v) < 365
}

_kernel_date_state := sprintf("kernel built %d days before the collection date", [_age_days(fact("kernel", "KERN_COMP_TIME"))]) if {
	_age_days(fact("kernel", "KERN_COMP_TIME"))
} else := sprintf("KERN_COMP_TIME %q carries no recognisable date", [fact("kernel", "KERN_COMP_TIME")]) if {
	fact("kernel", "KERN_COMP_TIME")
} else := "KERN_COMP_TIME not set in the collected facts"

# MANUAL-CHECK: SECUPD-A_a.4
violations contains msg if {
	level_in_profile("critical")
	not _ccl_current
	msg := sprintf("SECUPD-A_a.4: CRYPTOLIB date not older than 365 days (%s)", [_ccl_date_state])
}

_ccl_current if {
	v := fact("cryptolib", "CCL_DATE")
	_age_days(v) < 365
}

_ccl_date_state := sprintf("CommonCryptoLib built %d days before the collection date", [_age_days(fact("cryptolib", "CCL_DATE"))]) if {
	_age_days(fact("cryptolib", "CCL_DATE"))
} else := sprintf("CCL_DATE %q carries no recognisable date", [fact("cryptolib", "CCL_DATE")]) if {
	fact("cryptolib", "CCL_DATE")
} else := "CCL_DATE not set in the collected facts"

# ---------------------------------------------------------------------------------------------------------
# Kernel patch level (CHANGE-A_g.4) — SAP Note 2083594 minimum per kernel release, joined on KERN_REL
# ---------------------------------------------------------------------------------------------------------
_min_patch := {"722": 1600, "753": 1600, "754": 700, "777": 900, "793": 401, "916": 100}

_kernel_release := r if {
	v := fact("kernel", "KERN_REL")
	r := substring(trim_space(v), 0, 3)
}

# MANUAL-CHECK: CHANGE-A_g.4
violations contains msg if {
	level_in_profile("extended")
	not _kernel_patch_ok
	msg := sprintf("CHANGE-A_g.4: Minimum Kernel patchlevel which Note 2083594 recommends (%s)", [_kernel_patch_state])
}

_kernel_patch_ok if {
	minimum := _min_patch[_kernel_release]
	num_ge(fact("kernel", "KERN_PATCHLEVEL"), minimum)
}

_kernel_patch_state := sprintf("kernel %s patch level %s, Note 2083594 minimum %d", [_kernel_release, fact("kernel", "KERN_PATCHLEVEL"), _min_patch[_kernel_release]]) if {
	_min_patch[_kernel_release]
	fact("kernel", "KERN_PATCHLEVEL")
} else := sprintf("kernel release %q is not one Note 2083594 lists (722, 753, 754, 777, 793, 916)", [_kernel_release]) if {
	_kernel_release
} else := "KERN_REL / KERN_PATCHLEVEL not set in the collected facts"
