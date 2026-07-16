import unittest
from browser_agent_cookie_scope_risk_auditor_20260716.__main__ import audit


class T(unittest.TestCase):
    def test_risky(self):
        self.assertEqual(audit([{"name": "session", "domain": ".x.com", "secure": False}])["risky_count"], 1)

    def test_allowlist_and_expired_summary(self):
        result = audit(
            [
                {
                    "name": "auth_token",
                    "domain": ".tracker.test",
                    "secure": True,
                    "httpOnly": True,
                    "sameSite": "Lax",
                    "expirationDate": 1,
                }
            ],
            allowed_domains=["example.com"],
        )
        self.assertEqual(result["flag_counts"]["outside-allowlist"], 1)
        self.assertEqual(result["flag_counts"]["expired"], 1)
        self.assertEqual(result["risks"][0]["severity"], "high")

    def test_subdomain_allowlist_match(self):
        result = audit(
            [{"name": "prefs", "domain": "app.example.com", "secure": True, "httpOnly": True, "sameSite": "Strict"}],
            allowed_domains=["example.com"],
        )
        self.assertEqual(result["flag_counts"]["outside-allowlist"], 0)


if __name__ == "__main__":
    unittest.main()
