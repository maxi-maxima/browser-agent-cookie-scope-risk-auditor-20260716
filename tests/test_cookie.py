import unittest
from browser_agent_cookie_scope_risk_auditor_20260716.__main__ import audit
class T(unittest.TestCase):
 def test_risky(self):
  self.assertEqual(audit([{'name':'session','domain':'.x.com','secure':False}])['risky_count'],1)
if __name__=='__main__': unittest.main()
