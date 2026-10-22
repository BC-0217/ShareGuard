"""Result/policy serialization contract used by CLI and GUI."""

import copy
import json
import unittest

from tests import WorkDirTestCase, token
from shareguard.model import ISSUE_CODES, ScanResult
from shareguard.policy import CEILINGS, Policy, PolicyError
from shareguard.rules import RULES
from shareguard.scanner import scan_paths


class PolicyContract(unittest.TestCase):
    def test_defaults_equal_ceilings(self):
        self.assertEqual(Policy().to_dict(), {k: CEILINGS[k] for k in CEILINGS})

    def test_roundtrip_and_lowering(self):
        p = Policy(max_file_bytes=1024, file_timeout_seconds=1)
        self.assertEqual(Policy.from_dict(p.to_dict()), p)
        self.assertIsInstance(p.file_timeout_seconds, float)

    def test_rejects_bad_input(self):
        for bad in ({"max_depth": 0}, {"max_depth": -1}, {"max_depth": True},
                    {"max_depth": "3"}, {"unknown": 1}, {"file_timeout_seconds": float("nan")},
                    {"scan_timeout_seconds": float("inf")}, {"max_entries": 1.5}):
            with self.subTest(bad=bad):
                with self.assertRaises(PolicyError):
                    Policy.from_dict(bad)
        with self.assertRaises(PolicyError):
            Policy.from_dict(["not", "a", "dict"])


class ResultContract(WorkDirTestCase):
    def sample(self):
        self.write("d/a.txt", token("github") + "\n")
        self.write("d/b.bin", b"\x00\x01")
        return scan_paths([self.path("d")]).to_dict()

    def test_roundtrip_json_primitives(self):
        d = self.sample()
        text = json.dumps(d)
        self.assertEqual(ScanResult.from_dict(json.loads(text)).to_dict(), d)
        self.assertEqual(d["outcome"], "findings")
        self.assertEqual(d["completeness"], "incomplete")
        self.assertRegex(d["scan_id"], r"^[0-9a-f]{16}$")

    def test_from_dict_rejects_tampering(self):
        d = self.sample()
        mutations = [
            lambda x: x["findings"][0].update(rule_id="custom.rule"),
            lambda x: x["findings"][0].update(target_id="C:\\Users\\x"),
            lambda x: x["findings"][0].update(snippet="leak"),
            lambda x: x["findings"][0].update(severity="low"),
            lambda x: x["findings"][0].update(line=0),
            lambda x: x["issues"][0].update(code="Traceback: something"),
            lambda x: x["targets"][0].update(kind="path"),
            lambda x: x.update(completeness="safe"),
            lambda x: x.update(outcome="no_findings"),
            lambda x: x.update(extra="x"),
            lambda x: x["counts"].update(path=1),
            lambda x: x["policy"].update(max_file_bytes=10**12),
            lambda x: x.update(scan_id="../../etc"),
        ]
        for i, mutate in enumerate(mutations):
            with self.subTest(i=i):
                bad = copy.deepcopy(d)
                mutate(bad)
                with self.assertRaises(ValueError):
                    ScanResult.from_dict(bad)

    def test_cross_field_invariants_fail_closed(self):
        base = self.sample()
        mutations = []

        def complete_with_issues(x):
            x["completeness"] = "complete"
        mutations.append(complete_with_issues)

        def count_mismatch(x):
            x["counts"]["findings"] += 1
        mutations.append(count_mismatch)

        def orphan_finding(x):
            x["findings"][0]["target_id"] = "T999"
        mutations.append(orphan_finding)

        def duplicate_target(x):
            x["targets"][1]["target_id"] = x["targets"][0]["target_id"]
        mutations.append(duplicate_target)

        def orphan_parent(x):
            x["targets"][1]["parent_id"] = "T999"
        mutations.append(orphan_parent)

        def wrong_version(x):
            x["tool_version"] = "0.1.1"
        mutations.append(wrong_version)

        def trailing_newline_id(x):
            x["targets"][0]["target_id"] += "\n"
        mutations.append(trailing_newline_id)

        def unhashable_issue(x):
            x["issues"][0]["code"] = []
        mutations.append(unhashable_issue)

        for mutate in mutations:
            with self.subTest(mutate=mutate.__name__):
                bad = copy.deepcopy(base)
                mutate(bad)
                with self.assertRaises(ValueError):
                    ScanResult.from_dict(bad)

    def test_list_bounds_checked_before_item_parsing(self):
        data = self.sample()
        data["findings"] = [data["findings"][0]] * (CEILINGS["max_findings"] + 1)
        with self.assertRaises(ValueError):
            ScanResult.from_dict(data)

    def test_codes_and_rules_are_fixed_identifiers(self):
        for code in ISSUE_CODES:
            self.assertRegex(code, r"^[A-Z0-9_]+$")
        for rule in RULES:
            self.assertRegex(rule.rule_id, r"^[a-z0-9.\-]+$")
