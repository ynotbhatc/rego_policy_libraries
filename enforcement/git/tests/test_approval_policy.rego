package corporate.git_approval_test

import data.corporate.git_approval
import rego.v1

_protected := [".github/workflows/approval-check.yml"]

_unprotected := ["README.md"]

# ansible/ was removed from protected_paths 2026-09-01 — an ordinary
# playbook change must no longer demand the trailer, and the gate on the
# gate itself (enforcement/git/) must hold.
_formerly_protected := ["ansible/playbooks/some_playbook.yml"]

_gate_itself := ["enforcement/git/approval_policy.rego"]

test_ansible_no_longer_protected if {
	d := git_approval.decision with input as {
		"commit_message": "feat: change a playbook with no trailer",
		"changed_files": _formerly_protected,
		"author": "ynotbhatc",
		"pr_number": 5,
	}
	d.approved
	d.requires_approval == false
}

test_gate_itself_is_protected if {
	d := git_approval.decision with input as {
		"commit_message": "feat: loosen the gate with no trailer",
		"changed_files": _gate_itself,
		"author": "ynotbhatc",
		"pr_number": 6,
	}
	d.requires_approval == true
	not d.approved
}

# The exact shape that broke evaluation: a real trailer PLUS prose that
# mentions the trailer. Previously produced eval_conflict_error.
_msg_trailer_and_prose := concat("\n", [
	"fix(ci): something",
	"",
	"Approved-By: ynotbha@aisle-five.com",
	"",
	"Body text explaining that a commit may lose `Approved-By:` when truncated.",
])

test_trailer_with_prose_mention_does_not_conflict if {
	d := git_approval.decision with input as {
		"commit_message": _msg_trailer_and_prose,
		"changed_files": _protected,
		"author": "ynotbhatc",
		"pr_number": 1,
	}
	d.approved
	d.requires_approval == false
}

# Two trailers, the authorized one SECOND. Under the old single-valued
# function this was an eval_conflict_error; a set-valued extractor must find
# both and approve on the authorized one regardless of order.
test_two_approver_trailers_both_extracted if {
	msg := concat("\n", [
		"chore: dual approval",
		"",
		"Approved-By: someone-else@example.com",
		"Approved-By: ynotbha@aisle-five.com",
	])
	d := git_approval.decision with input as {
		"commit_message": msg,
		"changed_files": _protected,
		"author": "ynotbhatc",
		"pr_number": 6,
	}
	d.approved
	d.requires_approval == false
}

test_prose_only_mention_is_not_an_approval if {
	msg := concat("\n", [
		"docs: describe the convention",
		"",
		"Protected paths need `Approved-By:` in the message.",
	])
	d := git_approval.decision with input as {
		"commit_message": msg,
		"changed_files": _protected,
		"author": "ynotbhatc",
		"pr_number": 2,
	}
	not d.approved
	d.requires_approval
}

test_unauthorized_approver_rejected if {
	msg := "chore: x\n\nApproved-By: stranger@example.com"
	d := git_approval.decision with input as {
		"commit_message": msg,
		"changed_files": _protected,
		"author": "ynotbhatc",
		"pr_number": 3,
	}
	not d.approved
}

test_unprotected_path_needs_no_approval if {
	d := git_approval.decision with input as {
		"commit_message": "docs: tweak",
		"changed_files": _unprotected,
		"author": "ynotbhatc",
		"pr_number": 4,
	}
	d.approved
	d.requires_approval == false
}

test_long_message_trailer_at_end_still_found if {
	body := [sprintf("line %d of a long explanation", [i]) | some i in numbers.range(1, 40)]
	msg := concat("\n", array.concat(
		array.concat(["feat: big change", ""], body),
		["", "Approved-By: ynotbha@aisle-five.com"],
	))
	d := git_approval.decision with input as {
		"commit_message": msg,
		"changed_files": _protected,
		"author": "ynotbhatc",
		"pr_number": 5,
	}
	d.approved
}
