package cis_oracle.installation_patches_test

import rego.v1

# Validation fix 2026-10-17: permission regex allowed group/other write bits and rejected "0755";
# numeric version strings were flagged; missing oracle_home evidence passed.

base := {
	"oracle_version": {"supported": true, "version": "19c"},
	"critical_patches": {"days_since_last_patch": 10, "critical_missing": 0},
	"oracle_home": {"permissions": "755", "owner": "oracle", "group": "oinstall"},
	"oracle_inventory": {"exists": true, "permissions": "755"},
}

with_home(h) := object.union(object.remove(base, ["oracle_home"]), {"oracle_home": h})

test_base_compliant if {
	data.cis_oracle.installation_patches.compliant with input as base
}

test_group_write_mode_violates if {
	not data.cis_oracle.installation_patches.compliant with input as with_home({"permissions": "752", "owner": "oracle", "group": "dba"})
}

test_leading_zero_mode_ok if {
	data.cis_oracle.installation_patches.compliant with input as with_home({"permissions": "0755", "owner": "oracle", "group": "dba"})
}

test_stricter_mode_ok if {
	data.cis_oracle.installation_patches.compliant with input as with_home({"permissions": "750", "owner": "oracle", "group": "dba"})
}

test_inventory_group_write_violates if {
	inp := object.union(object.remove(base, ["oracle_inventory"]), {"oracle_inventory": {"exists": true, "permissions": "775"}})
	not data.cis_oracle.installation_patches.compliant with input as inp
}

test_numeric_version_ok if {
	inp := object.union(object.remove(base, ["oracle_version"]), {"oracle_version": {"supported": true, "version": "19.3.0.0.0"}})
	data.cis_oracle.installation_patches.compliant with input as inp
}

test_old_numeric_version_violates if {
	inp := object.union(object.remove(base, ["oracle_version"]), {"oracle_version": {"supported": true, "version": "12.2.0.1"}})
	not data.cis_oracle.installation_patches.compliant with input as inp
}

test_missing_oracle_home_violates if {
	not data.cis_oracle.installation_patches.compliant with input as object.remove(base, ["oracle_home"])
}
