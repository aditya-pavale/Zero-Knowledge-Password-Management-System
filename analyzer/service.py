"""AI security analyzer: explain findings, rate severity, suggest remediation.

Only redacted, snippet-free finding metadata is ever sent to the LLM. No vault data,
passwords, keys or ciphertext exist in this code path at all.
"""
import json
import logging

from django.conf import settings

from . import knowledge
from .parsers import SEVERITY_ORDER, normalize
from .redact import redact_finding

logger = logging.getLogger(__name__)

OFFLINE_ENGINE = "offline-knowledge-base"
MAX_FINDINGS_PER_CALL = 40
FALLBACK_MODEL_PREFIXES = ("claude-opus-5", "claude-fable-5")

SYSTEM_PROMPT = (
    "You are an application-security reviewer for a zero-knowledge password vault built with "
    "Django REST Framework and browser-side WebCrypto (Argon2id, AES-256-GCM, RSA-OAEP, RSA-PSS). "
    "You receive scanner findings from Bandit, Semgrep and OWASP ZAP. Secrets and code snippets "
    "have been removed; never ask for them. For each finding, explain the vulnerability in two or "
    "three plain sentences for a student developer, give your own severity assessment for this "
    "specific application (it may differ from the scanner's, e.g. a test file or a false positive "
    "can be 'info'), say whether it is likely a false positive, and give concrete remediation steps "
    "that fit Django/DRF and vanilla JavaScript."
)

RESULT_SCHEMA = {
    "type": "object",
    "properties": {
        "results": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "index": {"type": "integer"},
                    "explanation": {"type": "string"},
                    "severity": {"type": "string", "enum": SEVERITY_ORDER},
                    "likely_false_positive": {"type": "boolean"},
                    "remediation": {"type": "string"},
                },
                "required": ["index", "explanation", "severity", "likely_false_positive", "remediation"],
                "additionalProperties": False,
            },
        },
        "overall_summary": {"type": "string"},
    },
    "required": ["results", "overall_summary"],
    "additionalProperties": False,
}


def _offline(findings):
    results = []
    for f in findings:
        cwe, (explanation, remediation) = knowledge.lookup(f)
        results.append(
            {
                **f,
                "cwe": f["cwe"] or cwe,
                "explanation": explanation,
                "ai_severity": f["severity"],
                "likely_false_positive": False,
                "remediation": remediation,
            }
        )
    return results, ""


def _call_claude(findings):
    import anthropic

    client = anthropic.Anthropic(api_key=settings.ANTHROPIC_API_KEY or None, timeout=120.0)
    payload = [{"index": i, **f} for i, f in enumerate(findings)]
    request = dict(
        model=settings.ANTHROPIC_MODEL,
        max_tokens=16000,
        system=SYSTEM_PROMPT,
        output_config={"effort": "medium", "format": {"type": "json_schema", "schema": RESULT_SCHEMA}},
        messages=[
            {
                "role": "user",
                "content": "Analyze these findings:\n" + json.dumps(payload, indent=1),
            }
        ],
    )
    if settings.ANTHROPIC_MODEL.startswith(FALLBACK_MODEL_PREFIXES):
        # Server-side refusal fallback is documented for these models only.
        response = client.beta.messages.create(
            betas=["server-side-fallback-2026-07-01"], fallbacks="default", **request
        )
    else:
        response = client.messages.create(**request)
    if response.stop_reason == "refusal":
        raise RuntimeError("model declined the request")
    if response.stop_reason == "max_tokens":
        raise RuntimeError("model output was truncated")
    text = next(b.text for b in response.content if b.type == "text")
    return json.loads(text)


def _llm(findings):
    merged, summaries = [], []
    for start in range(0, len(findings), MAX_FINDINGS_PER_CALL):
        batch = findings[start : start + MAX_FINDINGS_PER_CALL]
        data = _call_claude(batch)
        by_index = {r["index"]: r for r in data["results"]}
        for i, f in enumerate(batch):
            r = by_index.get(i)
            if r is None:  # model skipped one: fall back to the knowledge base for it
                merged.extend(_offline([f])[0])
                continue
            merged.append(
                {
                    **f,
                    "explanation": r["explanation"],
                    "ai_severity": r["severity"],
                    "likely_false_positive": r["likely_false_positive"],
                    "remediation": r["remediation"],
                }
            )
        summaries.append(data["overall_summary"])
    return merged, "\n\n".join(summaries)


def analyze(reports, *, use_llm=True):
    """Return (engine, results, summary_dict)."""
    findings = [redact_finding(f) for f in normalize(reports)]
    engine = OFFLINE_ENGINE
    results, overall = _offline(findings)
    if findings and use_llm and settings.ANTHROPIC_API_KEY:
        try:
            results, overall = _llm(findings)
            engine = settings.ANTHROPIC_MODEL
        except Exception as exc:  # any LLM failure degrades to the offline explanations
            logger.warning("LLM analysis failed, using offline knowledge base: %s", type(exc).__name__)
    counts = {s: 0 for s in SEVERITY_ORDER}
    for r in results:
        counts[r["ai_severity"]] += 1
    summary = {
        "total": len(results),
        "by_severity": counts,
        "overall": overall or _default_overall(counts),
    }
    return engine, results, summary


def _default_overall(counts):
    serious = counts["critical"] + counts["high"]
    if serious:
        return f"{serious} critical/high finding(s) need attention before release."
    if sum(counts.values()):
        return "No critical or high findings; review the medium/low items below."
    return "No findings reported by the scanners."


def to_markdown(engine, results, summary):
    lines = [
        "# AI Security Analysis",
        "",
        f"Engine: `{engine}`  ",
        f"Total findings: **{summary['total']}** - "
        + ", ".join(f"{k}: {v}" for k, v in summary["by_severity"].items() if v),
        "",
        summary["overall"],
        "",
    ]
    for i, r in enumerate(results, 1):
        fp = " _(likely false positive)_" if r.get("likely_false_positive") else ""
        lines += [
            f"## {i}. [{r['ai_severity'].upper()}] {r['title']}{fp}",
            "",
            f"- **Tool / rule:** {r['tool']} `{r['rule_id']}`" + (f" ({r['cwe']})" if r.get("cwe") else ""),
            f"- **Location:** `{r['location']}`",
            f"- **Scanner severity:** {r['severity']}",
            "",
            f"**What it means:** {r['explanation']}",
            "",
            f"**How to fix:** {r['remediation']}",
            "",
        ]
    return "\n".join(lines)
