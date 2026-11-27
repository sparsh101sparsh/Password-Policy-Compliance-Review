import json
import plistlib
import unittest
from pathlib import Path

import audit_password_policy as app


BASE_DIR = Path(__file__).resolve().parent.parent


class PasswordPolicyReviewTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = json.loads((BASE_DIR / "organization_policy.json").read_text(encoding="utf-8"))
        self.base_state = {
            "collected_at": "2026-11-27T20:00:00+05:30",
            "hostname": "Test-MacBook",
            "current_user": "testuser",
            "os_version": "macOS 27.2.1",
            "local_users": [{"username": "testuser", "uid": 501}],
            "pwpolicy_parsed": {
                "parsed": True,
                "categories": ["policyCategoryPasswordContent"],
                "identifiers": ["com.apple.defaultpasswordpolicy.fde"],
                "content_rules": ["policyAttributePassword matches '.{4,}+'"],
                "min_length": 4,
                "has_complexity": False,
                "history_depth": None,
                "max_failed_attempts": None,
                "max_age_days": None,
            },
            "screen_lock_seconds": 300,
            "autologin_disabled": True,
            "guest_enabled": False,
            "filevault_on": True,
            "ad_bound": False,
            "dep_enrolled": False,
            "mdm_enrolled": False,
            "hashing_schemes": "SALTED-SHA512-PBKDF2",
            "pam_files": {
                "passwd": ["password required pam_opendirectory.so"],
                "sudo": ["auth required pam_opendirectory.so"],
                "authorization": ["auth required pam_opendirectory.so"],
            },
            "raw_evidence": {},
        }

    def test_parse_default_fde_plist(self) -> None:
        sample_plist = (
            "Getting global account policies\n"
            + plistlib.dumps(
                {
                    "policyCategoryPasswordContent": [
                        {
                            "policyContent": "policyAttributePassword matches '.{4,}+'",
                            "policyIdentifier": "com.apple.defaultpasswordpolicy.fde",
                        }
                    ]
                }
            ).decode("utf-8")
        )
        parsed = app.parse_pwpolicy_plist(sample_plist)
        self.assertTrue(parsed["parsed"])
        self.assertEqual(parsed["min_length"], 4)
        self.assertFalse(parsed["has_complexity"])
        self.assertIsNone(parsed["history_depth"])

    def test_recommended_plist_simulates_91_7_percent_compliance(self) -> None:
        plist_xml = app.build_recommended_plist()
        parsed_obj = plistlib.loads(plist_xml.encode("utf-8"))
        self.assertIn("policyCategoryAuthentication", parsed_obj)
        self.assertIn("policyCategoryPasswordChange", parsed_obj)
        self.assertIn("policyCategoryPasswordContent", parsed_obj)

        sim_state = dict(self.base_state)
        sim_state["pwpolicy_parsed"] = app.parse_pwpolicy_plist(plist_xml)
        sim_eval = app.evaluate_compliance(self.policy, sim_state)
        self.assertEqual(sim_eval["summary"]["compliant"], 11)
        self.assertEqual(sim_eval["summary"]["non_compliant"], 1)
        self.assertEqual(sim_eval["summary"]["compliance_score_pct"], 91.7)

    def test_candidate_password_evaluation(self) -> None:
        results = app.evaluate_sample_passwords(
            ["1234", "admin123", "Pass2026", "Tr0ub4dor&3!"],
            self.base_state,
            self.policy,
        )
        by_pwd = {r["password"]: r for r in results}
        self.assertTrue(by_pwd["1234"]["local_policy_pass"])
        self.assertFalse(by_pwd["1234"]["org_policy_pass"])
        self.assertFalse(by_pwd["Pass2026"]["org_policy_pass"])
        self.assertTrue(by_pwd["Tr0ub4dor&3!"]["org_policy_pass"])

        sim_state = dict(self.base_state)
        sim_state["pwpolicy_parsed"] = app.parse_pwpolicy_plist(app.build_recommended_plist())
        sim_results = {r["password"]: r for r in app.evaluate_sample_passwords(["1234", "Pass2026", "Tr0ub4dor&3!"], sim_state, self.policy)}
        self.assertFalse(sim_results["1234"]["local_policy_pass"])
        self.assertFalse(sim_results["Pass2026"]["local_policy_pass"])
        self.assertTrue(sim_results["Tr0ub4dor&3!"]["local_policy_pass"])


if __name__ == "__main__":
    unittest.main()
