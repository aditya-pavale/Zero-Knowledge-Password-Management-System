#!/usr/bin/env bash
# Run the same security scans as CI, locally, then explain them with the AI analyzer.
#   scripts/security_scan.sh              # Bandit + Semgrep (+ ZAP if a server is up and Docker exists)
#   ZAP_TARGET=http://localhost:8000 scripts/security_scan.sh
set -uo pipefail
cd "$(dirname "$0")/.."

PY=${PY:-.venv/bin/python}
BIN=$(dirname "$PY")
mkdir -p reports

echo "== Bandit"
"$BIN/bandit" -r accounts vault sharing audit analyzer vault_project -f json -o reports/bandit.json -q
"$BIN/bandit" -r accounts vault sharing audit analyzer vault_project -q -ll || true

echo "== Semgrep"
"$BIN/semgrep" scan --metrics=off --quiet \
  --config p/python --config p/django --config p/javascript --config p/secrets \
  --json -o reports/semgrep.json .
"$BIN/semgrep" scan --metrics=off --quiet \
  --config p/python --config p/django --config p/javascript --config p/secrets . || true

ZAP_ARGS=()
TARGET=${ZAP_TARGET:-http://localhost:8000}
if command -v docker >/dev/null && curl -fsS "$TARGET/api/health/" >/dev/null 2>&1; then
  echo "== OWASP ZAP baseline against $TARGET"
  docker run --rm --network host -v "$PWD/reports:/zap/wrk:rw" -v "$PWD/.zap:/zap/rules:ro" \
    ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t "$TARGET" -c /zap/rules/rules.tsv -J zap.json -r zap.html -I
  ZAP_ARGS=(--zap reports/zap.json)
else
  echo "== Skipping ZAP (needs Docker and a running server at $TARGET)"
fi

echo "== AI analyzer"
DJANGO_DEBUG=${DJANGO_DEBUG:-true} "$PY" manage.py analyze_findings \
  --bandit reports/bandit.json --semgrep reports/semgrep.json "${ZAP_ARGS[@]}" \
  --out reports/ai-analysis.md --json-out reports/ai-analysis.json
echo "Reports written to reports/"
