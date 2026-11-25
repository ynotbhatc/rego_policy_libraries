#!/usr/bin/env python3
"""Unit tests for scripts/check_undefined_negation.py: what is a hit, which effect it gets, and how the baseline gate
behaves. Each case writes a small policy to a temp dir and scans it with OPA's parser ($OPA, else `opa`).

    python3 -m unittest discover -s scripts/tests        (run by `make check-bad-input`)
"""
import os, pathlib, shutil, sys, tempfile, unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import check_undefined_negation as un  # noqa: E402

HAVE_OPA = shutil.which(os.environ.get("OPA", "opa")) is not None


def scan(body, name="p.rego"):
    d = pathlib.Path(tempfile.mkdtemp())
    (d / "t").mkdir()
    (d / "t" / name).write_text("package t.main\nimport rego.v1\n" + body)
    return un.scan(d, ["t"]), d


@unittest.skipUnless(HAVE_OPA, "no opa")
class Detector(unittest.TestCase):
    def kinds(self, body):
        hits, _ = scan(body)
        return [(h["kind"], h["effect"]) for h in hits]

    def test_neg_call_in_violation_is_fail_open(self):
        self.assertEqual(self.kinds("""
violations contains msg if {
	some r in input.rows
	not is_string(r.name)
	msg := "x"
}"""), [("neg-call", "fail-open")])

    def test_neg_call_in_pass_rule_is_fail_closed(self):
        self.assertEqual(self.kinds("""
compliant if {
	not is_string(input.a.b)
}"""), [("neg-call", "fail-closed")])

    def test_neg_in(self):
        self.assertEqual(self.kinds("""
violations contains msg if {
	some r in input.rows
	not r.kind in {"a", "b"}
	msg := "x"
}"""), [("neg-in", "fail-open")])

    def test_plain_negation_and_negated_equality_are_true_on_missing(self):
        self.assertEqual(self.kinds("""
violations contains msg if {
	some r in input.rows
	not r.enabled
	not r.mode == "on"
	msg := "x"
}"""), [])

    def test_object_get_with_failing_default_is_a_guard(self):
        self.assertEqual(self.kinds("""
violations contains msg if {
	some r in input.rows
	not is_string(object.get(r, "name", null))
	msg := "x"
}"""), [])

    def test_comparison_and_count_zero_and_to_number(self):
        ks = self.kinds("""
violations contains msg if {
	some r in input.rows
	r.level < 3
	msg := "x"
}
violations contains msg if {
	some r in input.rows
	count(r.items) == 0
	msg := "y"
}
violations contains msg if {
	some r in input.rows
	to_number(r.n) > 1
	msg := "z"
}""")
        self.assertEqual(sorted(ks), [("cmp", "fail-open"), ("count-zero", "fail-open"), ("to-number", "fail-open")])

    def test_typed_comparison_with_an_evidence_rule_is_guarded(self):
        body = """
violations contains msg if {
	is_number(input.d.days)
	input.d.days > 90
	msg := "late"
}
violations contains msg if {
	not is_number(object.get(input, ["d", "days"], null))
	msg := "evidence missing: d.days not collected"
}"""
        self.assertEqual(self.kinds(body), [("cmp", "guarded")])
        self.assertEqual(self.kinds(body.split("violations contains msg if {\n\tnot")[0]), [("cmp", "fail-open")])

    def test_has_key_guard_makes_an_optional_field(self):
        self.assertEqual(self.kinds("""
has_key(obj, k) if k in object.keys(obj)
violations contains "m.name: must be a string" if {
	has_key(input.m, "name")
	not is_string(input.m.name)
}"""), [("neg-call", "guarded")])

    def test_not_equal_null_is_a_presence_test(self):
        self.assertEqual(self.kinds("""
violations contains msg if {
	some r in input.rows
	r.owner != null
	msg := "x"
}"""), [])

    def test_get_default_that_passes(self):
        ks = self.kinds("""
violations contains msg if {
	some r in input.rows
	object.get(r, "hours", 0) > 24
	msg := "x"
}""")
        self.assertIn(("get-default", "fail-open"), ks)

    def test_neg_var_split_over_two_lines(self):
        ks = self.kinds("""
violations contains msg if {
	v := input.cfg.mode
	not is_string(v)
	msg := "x"
}""")
        self.assertTrue(ks and all(k[1] == "fail-open" for k in ks), ks)

    def test_comprehension_inside_is_always_defined(self):
        self.assertEqual(self.kinds("""
violations contains msg if {
	some r in input.rows
	not is_string(object.get(r, "name", null))
	count([x | some x in r.items; x.a]) == 0
	msg := "x"
}"""), [])


@unittest.skipUnless(HAVE_OPA, "no opa")
class Baseline(unittest.TestCase):
    BODY = """
violations contains msg if {
	some r in input.rows
	not is_string(r.name)
	msg := "x"
}"""

    def run_check(self, baseline_text):
        _, d = scan(self.BODY)
        bd = d / "bl"
        bd.mkdir()
        if baseline_text is not None:
            (bd / "t.txt").write_text(baseline_text)
        return un.main(["--root", str(d), "--paths", "t", "--check", "--baseline-dir", str(bd)]), d, bd

    def entry(self):
        hits, _ = scan(self.BODY)
        return [h for h in hits if un.is_gated(h)][0].key

    def test_no_baseline_file_is_not_gated(self):
        rc, _, _ = self.run_check(None)
        self.assertEqual(rc, 0)

    def test_new_hit_fails(self):
        rc, _, _ = self.run_check("# empty\n")
        self.assertEqual(rc, 1)

    def test_baselined_with_reason_passes(self):
        rc, _, _ = self.run_check(f"# reason: optional per the standard\n{self.entry()}\n")
        self.assertEqual(rc, 0)

    def test_entry_without_reason_or_with_todo_fails(self):
        self.assertEqual(self.run_check(f"{self.entry()}\n")[0], 1)
        self.assertEqual(self.run_check(f"# reason: TODO\n{self.entry()}\n")[0], 1)

    def test_stale_entry_fails(self):
        rc, _, _ = self.run_check(f"# reason: r\n{self.entry()}\n# reason: r\nt/gone.rego\tx\tneg-call\tnot f(x.y)\n")
        self.assertEqual(rc, 1)


if __name__ == "__main__":
    unittest.main()
