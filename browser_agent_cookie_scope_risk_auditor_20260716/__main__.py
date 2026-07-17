import argparse
import datetime
import json
from typing import Any, Iterable


def _same_site_value(cookie: dict[str, Any]) -> str:
    return str(cookie.get("sameSite") or cookie.get("same_site") or "").lower()


def _is_expired(cookie: dict[str, Any], now: datetime.datetime | None = None) -> bool:
    raw = cookie.get("expirationDate", cookie.get("expires"))
    if raw in (None, "", -1):
        return False
    now = now or datetime.datetime.now(datetime.timezone.utc)
    try:
        expires_at = datetime.datetime.fromtimestamp(float(raw), tz=datetime.timezone.utc)
    except (TypeError, ValueError, OSError):
        return False
    return expires_at <= now


def _domain_matches_allowlist(domain: str, allowlist: Iterable[str]) -> bool:
    normalized = domain.lstrip(".").lower()
    for allowed in allowlist:
        allowed_normalized = allowed.strip().lstrip(".").lower()
        if allowed_normalized and (normalized == allowed_normalized or normalized.endswith("." + allowed_normalized)):
            return True
    return False


def audit(cookies, allowed_domains: Iterable[str] | None = None):
    allowed_domains = list(allowed_domains or [])
    risks = []
    summary = {
        "broad-domain": 0,
        "not-httpOnly": 0,
        "not-secure": 0,
        "weak-sameSite": 0,
        "auth-like-name": 0,
        "expired": 0,
        "outside-allowlist": 0,
    }
    for index, c in enumerate(cookies):
        name = c.get("name", "")
        dom = c.get("domain", "")
        flags = []
        if dom.startswith(".") or dom.count(".") <= 1:
            flags.append("broad-domain")
        if not c.get("httpOnly", False):
            flags.append("not-httpOnly")
        if not c.get("secure", False):
            flags.append("not-secure")
        if _same_site_value(c) in ("none", "no_restriction", ""):
            flags.append("weak-sameSite")
        if any(x in name.lower() for x in ["session", "token", "auth"]):
            flags.append("auth-like-name")
        if _is_expired(c):
            flags.append("expired")
        if allowed_domains and dom and not _domain_matches_allowlist(dom, allowed_domains):
            flags.append("outside-allowlist")
        for flag in flags:
            summary[flag] += 1
        if flags:
            severity = "high" if "auth-like-name" in flags and len(set(flags) - {"expired"}) > 1 else "medium"
            if "outside-allowlist" in flags or ("expired" in flags and "auth-like-name" in flags):
                severity = "high"
            risks.append({"index": index, "name": name, "domain": dom, "flags": flags, "severity": severity})
    return {"cookie_count": len(cookies), "risky_count": len(risks), "flag_counts": summary, "risks": risks}


def load_cookies(path: str):
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    return data if isinstance(data, list) else data.get("cookies", [])


def render_text(report: dict[str, Any]) -> str:
    lines = [f"{report['risky_count']} risky cookies out of {report['cookie_count']} checked"]
    for risk in report["risks"]:
        flags = ",".join(risk["flags"])
        lines.append(f"- #{risk['index']} {risk['severity'].upper()} {risk['name']}@{risk['domain']}: {flags}")
    return "\n".join(lines)


def render_github_annotations(report: dict[str, Any]) -> str:
    lines = []
    for risk in report["risks"]:
        command = "error" if risk["severity"] == "high" else "warning"
        title = f"{risk['severity']} cookie risk: {risk['name']}"
        message = f"cookie #{risk['index']} {risk['name']}@{risk['domain']} flags={','.join(risk['flags'])}"
        lines.append(f"::{command} title={title}::{message}")
    return "\n".join(lines) or "::notice title=Cookie audit::No risky cookies found"


def main(argv=None):
    ap = argparse.ArgumentParser(description="Audit browser-agent cookie exports before sharing them with automation or LLM agents.")
    ap.add_argument("cookies_json")
    ap.add_argument("--allow-domain", action="append", default=[], help="Allowed eTLD+1/domain; repeat to flag cookies outside policy")
    ap.add_argument("--strict", action="store_true", help="Exit 2 when high-risk cookies are found")
    ap.add_argument("--format", choices=("json", "text", "github-annotations"), default="json", help="Output format for local review or CI annotations")
    ns = ap.parse_args(argv)
    out = audit(load_cookies(ns.cookies_json), ns.allow_domain)
    if ns.format == "json":
        print(json.dumps(out, indent=2, ensure_ascii=False))
    elif ns.format == "text":
        print(render_text(out))
    else:
        print(render_github_annotations(out))
    if ns.strict and any(r["severity"] == "high" for r in out["risks"]):
        raise SystemExit(2)


if __name__ == "__main__":
    main()
