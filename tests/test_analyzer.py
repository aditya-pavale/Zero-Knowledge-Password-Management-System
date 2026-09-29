import json

import pytest

from analyzer import service
from analyzer.parsers import normalize
from analyzer.redact import REDACTED, redact_text

BANDIT = {
    "results": [
        {
            "test_id": "B105", "test_name": "hardcoded_password_string", "issue_severity": "LOW",
            "filename": "app/settings.py", "line_number": 12, "issue_cwe": {"id": 259},
            "issue_text": "Possible hardcoded password: 'hunter2hunter2'",
            "code": "PASSWORD = 'hunter2hunter2'",
        },
        {
            "test_id": "B602", "test_name": "subprocess_popen_with_shell_equals_true", "issue_severity": "HIGH",
            "filename": "app/tools.py", "line_number": 3, "issue_cwe": {"id": 78}, "issue_text": "shell=True",
        },
    ]
}
SEMGREP = {
    "results": [
        {
            "check_id": "python.django.security.injection.sql.raw-query", "path": "app/views.py",
            "start": {"line": 40}, "extra": {"severity": "ERROR", "message": "Raw SQL", "lines": "cursor.execute(q)",
                                             "metadata": {"cwe": ["CWE-89: SQL Injection"]}},
        }
    ]
}
ZAP = {
    "site": [{"alerts": [{"pluginid": "10038", "name": "Content Security Policy (CSP) Header Not Set",
                          "riskcode": "2", "cweid": "693", "desc": "<p>CSP &amp; headers missing</p>",
                          "instances": [{"uri": "http://localhost/", "evidence": "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnop"}]}]}]
}


def test_normalize_merges_and_sorts_by_severity():
    findings = normalize({"bandit": BANDIT, "semgrep": SEMGREP, "zap": ZAP})
    assert [f["tool"] for f in findings][:2] == ["bandit", "semgrep"]  # both high
    assert {f["severity"] for f in findings} == {"high", "medium", "low"}
    sql = next(f for f in findings if f["tool"] == "semgrep")
    assert sql["cwe"] == "CWE-89"


def test_snippets_and_evidence_are_never_included():
    blob = json.dumps(normalize({"bandit": BANDIT, "semgrep": SEMGREP, "zap": ZAP}))
    assert "PASSWORD = " not in blob
    assert "cursor.execute(q)" not in blob
    assert "eyJhbGci" not in blob


@pytest.mark.parametrize(
    "text",
    [
        "password = 'hunter2hunter2'",
        "api_key: sk-ant-api03-abcdefghijklmnopqrstuvwxyz",
        "token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnop",
        "AKIAIOSFODNN7EXAMPLE",
        "postgres://vault:s3cretpw@db:5432/vault",
        "blob Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MEFCQ0RFRkdISUpLTE1O",
        "-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----",
    ],
)
def test_redaction(text):
    out = redact_text(text)
    assert REDACTED in out
    for secret in ["hunter2hunter2", "sk-ant-api03", "eyJhbGci", "AKIAIOSFODNN7", "s3cretpw", "Zm9vYmFy", "MIIE"]:
        assert secret not in out


def test_redaction_keeps_ordinary_text():
    text = "Use of insecure MD5 hash function in accounts/management/commands/set_role.py:12"
    assert redact_text(text) == text


def test_offline_analysis(settings):
    settings.ANTHROPIC_API_KEY = ""
    engine, results, summary = service.analyze({"bandit": BANDIT, "semgrep": SEMGREP, "zap": ZAP})
    assert engine == service.OFFLINE_ENGINE
    assert summary["total"] == 4
    sql = next(r for r in results if r["cwe"] == "CWE-89")
    assert "parameterized" in sql["remediation"]
    assert all(r["explanation"] and r["remediation"] for r in results)


def test_llm_receives_only_redacted_metadata(settings, monkeypatch):
    settings.ANTHROPIC_API_KEY = "test-key"
    captured = {}

    def fake_call(findings):
        captured["payload"] = json.dumps(findings)
        return {
            "results": [
                {"index": i, "explanation": "e", "severity": "low", "likely_false_positive": i == 0, "remediation": "r"}
                for i in range(len(findings))
            ],
            "overall_summary": "fine",
        }

    monkeypatch.setattr(service, "_call_claude", fake_call)
    engine, results, summary = service.analyze({"bandit": BANDIT, "zap": ZAP})
    assert engine == settings.ANTHROPIC_MODEL
    assert summary["overall"] == "fine"
    assert results[0]["likely_false_positive"] is True
    assert "hunter2hunter2" not in captured["payload"]
    assert "eyJhbGci" not in captured["payload"]


def test_llm_failure_falls_back_to_offline(settings, monkeypatch):
    settings.ANTHROPIC_API_KEY = "test-key"

    def boom(findings):
        raise RuntimeError("network down")

    monkeypatch.setattr(service, "_call_claude", boom)
    engine, results, _ = service.analyze({"semgrep": SEMGREP})
    assert engine == service.OFFLINE_ENGINE
    assert results[0]["remediation"]


@pytest.mark.django_db
def test_analyzer_api_admin_only(register, client_for, settings):
    settings.ANTHROPIC_API_KEY = ""
    admin = register("root", role="admin")
    c = client_for(admin)
    res = c.post("/api/analyzer/analyze/", {"bandit": BANDIT}, format="json")
    assert res.status_code == 201
    assert res.json()["findings_count"] == 2
    assert c.get("/api/analyzer/reports/").json()["count"] == 1
    assert c.post("/api/analyzer/analyze/", {}, format="json").status_code == 400


def test_zap_html_descriptions_are_flattened():
    zap = normalize({"zap": ZAP})[0]
    assert zap["description"] == "CSP & headers missing"


def test_cors_finding_gets_specific_advice(settings):
    settings.ANTHROPIC_API_KEY = ""
    report = {"site": [{"alerts": [{"pluginid": "10098", "name": "Cross-Domain Misconfiguration",
                                     "riskcode": "2", "cweid": "264", "desc": "<p>CORS</p>", "instances": []}]}]}
    _, results, _ = service.analyze({"zap": report})
    assert "WHITENOISE_ALLOW_ALL_ORIGINS" in results[0]["remediation"]


@pytest.mark.parametrize("model,uses_fallback", [("claude-sonnet-5", False), ("claude-opus-5", True)])
def test_request_shape_per_model(settings, monkeypatch, model, uses_fallback):
    import types

    import anthropic

    settings.ANTHROPIC_API_KEY = "test-key"
    settings.ANTHROPIC_MODEL = model
    calls = {}
    reply = types.SimpleNamespace(
        stop_reason="end_turn",
        content=[types.SimpleNamespace(type="text", text='{"results": [], "overall_summary": "ok"}')],
    )

    class FakeMessages:
        def __init__(self, kind):
            self.kind = kind

        def create(self, **kwargs):
            calls[self.kind] = kwargs
            return reply

    class FakeClient:
        def __init__(self, **_):
            self.messages = FakeMessages("stable")
            self.beta = types.SimpleNamespace(messages=FakeMessages("beta"))

    monkeypatch.setattr(anthropic, "Anthropic", FakeClient)
    service._call_claude([{"title": "t"}])
    (kind, kwargs), = calls.items()
    assert kwargs["model"] == model
    assert (kind == "beta") is uses_fallback
    assert ("fallbacks" in kwargs) is uses_fallback
    assert kwargs["output_config"]["format"]["type"] == "json_schema"
