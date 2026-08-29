package corporate.git_approval

# Git Change Approval Policy
# Ensures changes to critical paths require proper approval

import rego.v1

# Protected paths that require approval
protected_paths := {
	"policies/",
	"opa/",
	".github/workflows/",
	"aap-integration/",
	"ansible/",
}

# Users authorized to approve changes.
#
# EVERY ENTRY MUST BE A REAL, DELIVERABLE ADDRESS BELONGING TO SOMEONE
# ACCOUNTABLE FOR THE CHANGE.
#
# This set previously carried four example.com placeholders --
# tcoulter@example.com, john.doe@example.com, security-team@example.com,
# compliance-admin@example.com. example.com is RFC 2606 reserved: those
# addresses can never belong to anyone. Because approval is satisfied by any
# trailer matching this set, `Approved-By: john.doe@example.com` evaluated to
# `true` and passed the gate on protected paths. Verified against this policy
# on 2026-08-29 before removal.
#
# A placeholder in an allowlist is not a placeholder. It is a working key.
#
# To add an approver, add the address they actually receive mail at. Do not add
# a role address unless it resolves to people who will read it.
authorized_approvers := {"ynotbha@aisle-five.com"}

# Default: changes are not approved
default approved := false

# Changes are approved if:
# 1. Commit message contains "Approved-By:" with authorized approver
# 2. Changes don't affect protected paths, OR
# 3. Pull request has required approvals
approved if {
	input.commit_message
	some approver in extract_approvers(input.commit_message)
	approver in authorized_approvers
}

# Allow changes to non-protected paths without approval
approved if {
	not affects_protected_paths
}

# Check if changes affect protected paths
affects_protected_paths if {
	some file in input.changed_files
	some path in protected_paths
	startswith(file, path)
}

# Extract every approver email from the commit message.
#
# Returns a SET, not a single value. A function that yields more than one
# output for the same input is an eval_conflict_error, and a commit message can
# legitimately contain more than one line mentioning the trailer — a real
# trailer plus prose discussing it, or two co-approvers. The previous
# single-valued form aborted evaluation in that case; it only appeared to work
# because the calling workflow truncated the message to 20 lines first.
#
# Only a line that *starts with* the trailer counts, so prose that merely
# mentions "Approved-By:" mid-sentence is correctly ignored.
extract_approvers(msg) := {approver |
	some line in split(msg, "\n")
	trimmed := trim_space(line)
	startswith(trimmed, "Approved-By:")
	approver := trim_space(substring(trimmed, count("Approved-By:"), -1))
}

# Validation: Check if approval is required but missing
default requires_approval := false

requires_approval if {
	affects_protected_paths
	not approved
}

# Generate approval requirement message
approval_message := msg if {
	requires_approval
	affected := [file |
		some file in input.changed_files
		some path in protected_paths
		startswith(file, path)
	]
	msg := sprintf("Changes to protected paths require approval: %v", [affected])
}

# Policy decision
decision := {
	"approved": approved,
	"requires_approval": requires_approval,
	"affected_protected_paths": affected_protected_paths,
	"message": "Check complete",
}

# Helper: Get affected protected paths
default affected_protected_paths := []

affected_protected_paths := paths if {
	paths := [file |
		some file in input.changed_files
		some path in protected_paths
		startswith(file, path)
	]
}

# Test data helpers
test_approved_change if {
	approved with input as {
		"commit_message": "Update policies\n\nApproved-By: ynotbha@aisle-five.com",
		"changed_files": ["policies/cis_rhel9/test.rego"],
	}
}

# Regression. This exact input returned `true` until 2026-08-29, because the
# approver set carried example.com placeholders and any trailer matching the
# set was sufficient. A reserved address that can never belong to anyone was
# therefore a working approval key on every protected path.
test_placeholder_approver_is_rejected if {
	not approved with input as {
		"commit_message": "Update policies\n\nApproved-By: john.doe@example.com",
		"changed_files": ["policies/cis_rhel9/test.rego"],
	}
}

test_any_example_com_address_is_rejected if {
	not approved with input as {
		"commit_message": "Update policies\n\nApproved-By: security-team@example.com",
		"changed_files": [".github/workflows/ci.yml"],
	}
}

test_unapproved_change if {
	requires_approval with input as {
		"commit_message": "Update policies",
		"changed_files": ["policies/cis_rhel9/test.rego"],
	}
}

test_non_protected_change if {
	approved with input as {
		"commit_message": "Update documentation",
		"changed_files": ["docs/README.md"],
	}
}
