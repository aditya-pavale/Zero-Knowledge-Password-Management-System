"""Normalize Bandit, Semgrep and OWASP ZAP JSON reports into one finding shape.

Code snippets / matched source lines / HTTP evidence are deliberately dropped here:
they are the most likely place for real secrets to hide, and the AI does not need
them to explain a vulnerability class.
"""

import html
import re

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
_TAG = re.compile(r"<[^>]+>")


def _plain(text):
    """ZAP descriptions are HTML fragments; reduce them to plain text."""
    return " ".join(html.unescape(_TAG.sub(" ", text or "")).split())

_SEMGREP_SEVERITY = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}
_ZAP_RISK = {"3": "high", "2": "medium", "1": "low", "0": "info"}


def _finding(tool, rule_id, title, severity, location="", cwe="", description=""):
    severity = (severity or "info").lower()
    if severity not in SEVERITY_ORDER:
        severity = "info"
    return {
        "tool": tool,
        "rule_id": str(rule_id)[:200],
        "title": str(title)[:300],
        "severity": severity,
        "location": str(location)[:300],
        "cwe": str(cwe)[:40],
        "description": str(description)[:2000],
    }


def parse_bandit(report):
    findings = []
    for r in report.get("results", []):
        cwe = r.get("issue_cwe", {}) or {}
        findings.append(
            _finding(
                "bandit",
                r.get("test_id", ""),
                r.get("test_name", ""),
                r.get("issue_severity", "info"),
                f"{r.get('filename', '')}:{r.get('line_number', '')}",
                f"CWE-{cwe['id']}" if cwe.get("id") else "",
                r.get("issue_text", ""),
            )
        )
    return findings


def parse_semgrep(report):
    findings = []
    for r in report.get("results", []):
        extra = r.get("extra", {}) or {}
        meta = extra.get("metadata", {}) or {}
        cwe = meta.get("cwe", "")
        if isinstance(cwe, list):
            cwe = cwe[0] if cwe else ""
        findings.append(
            _finding(
                "semgrep",
                r.get("check_id", ""),
                r.get("check_id", "").rsplit(".", 1)[-1],
                _SEMGREP_SEVERITY.get(str(extra.get("severity", "")).upper(), "info"),
                f"{r.get('path', '')}:{(r.get('start') or {}).get('line', '')}",
                str(cwe).split(":")[0],
                extra.get("message", ""),
            )
        )
    return findings


def parse_zap(report):
    findings = []
    for site in report.get("site", []):
        for alert in site.get("alerts", []):
            instances = alert.get("instances", []) or []
            uri = instances[0].get("uri", "") if instances else ""
            findings.append(
                _finding(
                    "zap",
                    alert.get("pluginid", ""),
                    alert.get("name") or alert.get("alert", ""),
                    _ZAP_RISK.get(str(alert.get("riskcode", "0")), "info"),
                    uri,
                    f"CWE-{alert['cweid']}" if str(alert.get("cweid", "")) not in ("", "-1", "0") else "",
                    _plain(alert.get("desc", "")),
                )
            )
    return findings


PARSERS = {"bandit": parse_bandit, "semgrep": parse_semgrep, "zap": parse_zap}


def normalize(reports):
    """reports: {"bandit": {...}, "semgrep": {...}, "zap": {...}, "findings": [...]}"""
    findings = []
    for name, parser in PARSERS.items():
        if isinstance(reports.get(name), dict):
            findings.extend(parser(reports[name]))
    for raw in reports.get("findings", []) or []:
        if isinstance(raw, dict):
            findings.append(
                _finding(
                    raw.get("tool", "manual"), raw.get("rule_id", ""), raw.get("title", ""),
                    raw.get("severity", "info"), raw.get("location", ""), raw.get("cwe", ""),
                    raw.get("description", ""),
                )
            )
    # De-duplicate identical rule+location pairs (ZAP in particular repeats a lot).
    seen, unique = set(), []
    for f in findings:
        key = (f["tool"], f["rule_id"], f["location"])
        if key not in seen:
            seen.add(key)
            unique.append(f)
    unique.sort(key=lambda f: SEVERITY_ORDER.index(f["severity"]))
    return unique
