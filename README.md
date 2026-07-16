# Browser Agent Cookie Scope Risk Auditor

## Pain point
Browser agents often need authenticated sessions, but exported cookies can be over-broad and unsafe to paste into automation.

## Why now
Browser-control agents and Stagehand-like automation are hot; cookie/session safety is a concrete blocker for real usage.

## Install and run
```bash
python -m browser_agent_cookie_scope_risk_auditor_20260716 --help
python -m browser_agent_cookie_scope_risk_auditor_20260716 examples/cookies.json
```

## Example
```bash
python -m browser_agent_cookie_scope_risk_auditor_20260716 examples/cookies.json
```

## Self-check
```bash
python -m unittest discover -s tests -v
```

## Roadmap
- HAR import.
- Domain allowlist policies.
- Expiration and third-party risk scoring.

## License
MIT
