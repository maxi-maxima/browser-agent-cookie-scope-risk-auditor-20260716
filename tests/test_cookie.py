import io
import unittest
from contextlib import redirect_stdout
from browser_agent_cookie_scope_risk_auditor_20260716.__main__ import audit, main


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
        self.assertEqual(result["risks"][0]["index"], 0)

    def test_subdomain_allowlist_match(self):
        result = audit(
            [{"name": "prefs", "domain": "app.example.com", "secure": True, "httpOnly": True, "sameSite": "Strict"}],
            allowed_domains=["example.com"],
        )
        self.assertEqual(result["flag_counts"]["outside-allowlist"], 0)

    def test_github_annotations_format(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            main(["examples/cookies.json", "--format", "github-annotations"])
        output = buf.getvalue()
        self.assertIn("::error", output)
        self.assertIn("session_token", output)
        self.assertIn("cookie #0", output)

    def test_text_format(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            main(["examples/cookies.json", "--format", "text"])
        self.assertIn("risky cookies", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
