"""CI entry point: python manage.py analyze_findings --bandit b.json --semgrep s.json --zap z.json"""
import json
from pathlib import Path

from django.core.management.base import BaseCommand, CommandError

from analyzer.service import analyze, to_markdown


class Command(BaseCommand):
    help = "Explain scanner findings (Bandit/Semgrep/ZAP JSON) with the AI analyzer and write a report."

    def add_arguments(self, parser):
        parser.add_argument("--bandit")
        parser.add_argument("--semgrep")
        parser.add_argument("--zap")
        parser.add_argument("--out", default="reports/ai-analysis.md")
        parser.add_argument("--json-out", default="reports/ai-analysis.json")
        parser.add_argument("--offline", action="store_true", help="Don't call the LLM")
        parser.add_argument(
            "--fail-on", choices=["critical", "high", "medium", "none"], default="none",
            help="Exit non-zero if any finding at or above this AI-assessed severity (and not a likely FP)",
        )

    def handle(self, *args, **opts):
        reports = {}
        for name in ("bandit", "semgrep", "zap"):
            path = opts.get(name)
            if not path:
                continue
            p = Path(path)
            if not p.exists():
                self.stderr.write(f"skipping {name}: {path} not found")
                continue
            try:
                reports[name] = json.loads(p.read_text())
            except json.JSONDecodeError as exc:
                raise CommandError(f"{path} is not valid JSON") from exc

        engine, results, summary = analyze(reports, use_llm=not opts["offline"])
        markdown = to_markdown(engine, results, summary)
        for key, content in (("out", markdown), ("json_out", json.dumps(
            {"engine": engine, "summary": summary, "results": results}, indent=2))):
            out = Path(opts[key])
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(content)
        self.stdout.write(markdown)

        if opts["fail_on"] != "none":
            levels = ["critical", "high", "medium"]
            blocking = levels[: levels.index(opts["fail_on"]) + 1]
            bad = [r for r in results if r["ai_severity"] in blocking and not r.get("likely_false_positive")]
            if bad:
                raise CommandError(f"{len(bad)} finding(s) at or above '{opts['fail_on']}'")
