#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BACKEND_HOST="${SAUGRA_SMOKE_BACKEND_HOST:-127.0.0.1}"
BACKEND_PORT="${SAUGRA_SMOKE_BACKEND_PORT:-18080}"
SAUGRA_HOST="${SAUGRA_SMOKE_HOST:-127.0.0.1}"
SAUGRA_PORT="${SAUGRA_SMOKE_PORT:-18787}"
TIMEZONE="${SAUGRA_SMOKE_TIMEZONE:-Africa/Nairobi}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/saugra-waf-smoke.XXXXXX")"
CONFIG_PATH="${TMP_DIR}/saugra-waf.yml"
EVENT_LOG_PATH="${TMP_DIR}/saugra-waf-events.jsonl"
BACKEND_LOG_PATH="${TMP_DIR}/backend.log"
SAUGRA_LOG_PATH="${TMP_DIR}/saugra-waf.log"
BACKEND_PID=""
SAUGRA_PID=""
FAILED=0

cleanup() {
    local exit_code=$?
    if [[ "${exit_code}" -ne 0 ]]; then
        FAILED=1
    fi

    if [[ -n "${SAUGRA_PID}" ]] && kill -0 "${SAUGRA_PID}" 2>/dev/null; then
        kill "${SAUGRA_PID}" 2>/dev/null || true
        wait "${SAUGRA_PID}" 2>/dev/null || true
    fi

    if [[ -n "${BACKEND_PID}" ]] && kill -0 "${BACKEND_PID}" 2>/dev/null; then
        kill "${BACKEND_PID}" 2>/dev/null || true
        wait "${BACKEND_PID}" 2>/dev/null || true
    fi

    if [[ "${FAILED}" -eq 1 ]]; then
        echo "--- backend log ---" >&2
        sed -n '1,120p' "${BACKEND_LOG_PATH}" >&2 2>/dev/null || true
        echo "--- saugra-waf log ---" >&2
        sed -n '1,160p' "${SAUGRA_LOG_PATH}" >&2 2>/dev/null || true
        echo "--- event log ---" >&2
        sed -n '1,120p' "${EVENT_LOG_PATH}" >&2 2>/dev/null || true
    fi

    rm -rf "${TMP_DIR}"
    exit "${exit_code}"
}
trap cleanup EXIT

require_command() {
    local command_name="$1"
    if ! command -v "${command_name}" >/dev/null 2>&1; then
        echo "missing required command: ${command_name}" >&2
        exit 1
    fi
}

wait_for_url() {
    local url="$1"
    local attempts=40

    for _ in $(seq 1 "${attempts}"); do
        if curl -fsS "${url}" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.25
    done

    echo "timed out waiting for ${url}" >&2
    return 1
}

require_command cargo
require_command curl
require_command python3

cd "${ROOT_DIR}"

python3 -m http.server "${BACKEND_PORT}" --bind "${BACKEND_HOST}" >"${BACKEND_LOG_PATH}" 2>&1 &
BACKEND_PID="$!"
wait_for_url "http://${BACKEND_HOST}:${BACKEND_PORT}/"

cat >"${CONFIG_PATH}" <<YAML
server:
  listen: ${SAUGRA_HOST}:${SAUGRA_PORT}
  mode: block

upstreams:
  - name: smoke-backend
    host: smoke.local
    target: http://${BACKEND_HOST}:${BACKEND_PORT}

security:
  max_body_size: 2mb
  enable_rate_limiting: true
  block_suspicious_user_agents: true
  inspect_json_body: true

rate_limit:
  backend: memory
  requests_per_minute: 120
  burst: 30
  routes: []

rules:
  owasp_crs: true
  paranoia_level: 1
  inbound_anomaly_threshold: 5
  files:
    - configs/rules/REQUEST-913-SCANNER-DETECTION.yml
    - configs/rules/REQUEST-914-AUTHENTICATION-ABUSE.yml
    - configs/rules/REQUEST-916-INSECURE-DESIGN.yml
    - configs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.yml
    - configs/rules/REQUEST-921-CRYPTO-TRANSPORT.yml
    - configs/rules/REQUEST-932-APPLICATION-ATTACK-RCE.yml
    - configs/rules/REQUEST-930-APPLICATION-ATTACK-LFI.yml
    - configs/rules/REQUEST-941-APPLICATION-ATTACK-XSS.yml
    - configs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.yml
    - configs/rules/REQUEST-944-SUPPLY-CHAIN.yml
    - configs/rules/REQUEST-945-INTEGRITY.yml
    - configs/rules/REQUEST-949-LOGGING-ALERTING.yml
    - configs/rules/REQUEST-950-EXCEPTIONAL-CONDITIONS.yml
  exclusions: []

ai:
  enabled: true
  mode: explain_only

logging:
  format: json
  level: info
  event_log_path: ${EVENT_LOG_PATH}
  event_log_max_size: 10mb
  event_log_max_files: 3
  timezone: ${TIMEZONE}
YAML

cargo run --quiet -- test-config --config "${CONFIG_PATH}" >/dev/null
cargo run --quiet -- run --config "${CONFIG_PATH}" >"${SAUGRA_LOG_PATH}" 2>&1 &
SAUGRA_PID="$!"
wait_for_url "http://${SAUGRA_HOST}:${SAUGRA_PORT}/_saugra-waf/health"

clean_status="$(curl -sS -o /dev/null -w "%{http_code}" -H "Host: smoke.local" "http://${SAUGRA_HOST}:${SAUGRA_PORT}/")"
if [[ "${clean_status}" != "200" ]]; then
    echo "expected clean request to return 200, got ${clean_status}" >&2
    exit 1
fi

attack_status="$(
    curl -sS -o /dev/null -w "%{http_code}" \
        -H "Host: smoke.local" \
        --get \
        --data-urlencode "q=' OR 1=1--" \
        "http://${SAUGRA_HOST}:${SAUGRA_PORT}/search"
)"
if [[ "${attack_status}" != "403" ]]; then
    echo "expected SQL injection request to return 403, got ${attack_status}" >&2
    exit 1
fi

python3 - "${EVENT_LOG_PATH}" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, "r", encoding="utf-8") as handle:
    events = [json.loads(line) for line in handle if line.strip()]

if len(events) < 2:
    raise SystemExit(f"expected at least 2 security events, got {len(events)}")

latest = events[-1]
if "timestamp" not in latest:
    raise SystemExit("latest event is missing timestamp")
if "timestamp_unix_seconds" in latest:
    raise SystemExit("latest event still uses timestamp_unix_seconds")
if latest.get("client_ip") != "unknown":
    raise SystemExit(f"expected direct local client_ip to be unknown, got {latest.get('client_ip')!r}")
if latest["decision"]["action"] != "block":
    raise SystemExit(f"expected latest event action to be block, got {latest['decision']['action']!r}")
if not latest["decision"]["matched_rules"]:
    raise SystemExit("expected latest event to include matched rules")

print(f"verified {len(events)} events; latest request_id={latest['decision']['request_id']}")
PY

echo "Saugra local smoke test passed"
