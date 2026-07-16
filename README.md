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

## Policy mode
Use `--allow-domain` to flag cookies outside the domains you expect to share with the browser agent. Repeat it for multiple domains. Add `--strict` in CI to exit with code `2` when high-risk cookies are present.

```bash
python -m browser_agent_cookie_scope_risk_auditor_20260716 examples/cookies.json --allow-domain example.com --strict
```

The JSON report now includes `flag_counts`, including expired cookies and outside-allowlist cookies.

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
