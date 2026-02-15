#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

STACK_FILE="docker-compose.local.yml"
APP_HOST="${APP_HOST:-0.0.0.0}"
APP_PORT="${APP_PORT:-8000}"

choose_model_dir() {
  if [[ -n "${MODEL_DIR:-}" ]]; then
    echo "$MODEL_DIR"
    return
  fi

  if [[ -d "advanced_artifacts" ]]; then
    echo "advanced_artifacts"
    return
  fi

  if [[ -d "demo_artifacts" ]]; then
    echo "demo_artifacts"
    return
  fi

  echo "."
}

start_stack() {
  if ! command -v docker >/dev/null 2>&1; then
    echo "docker not found; skipping local stack startup"
    return
  fi
  docker compose -f "$STACK_FILE" up -d
}

stop_stack() {
  if ! command -v docker >/dev/null 2>&1; then
    return
  fi
  docker compose -f "$STACK_FILE" down
}

run_api() {
  if [[ ! -x ".venv/bin/uvicorn" ]]; then
    echo ".venv/bin/uvicorn not found. Run setup first:"
    echo "python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt"
    exit 1
  fi

  export API_KEYS="${API_KEYS:-dev-api-key}"
  export MODEL_DIR="$(choose_model_dir)"

  export MINIO_ENDPOINT="${MINIO_ENDPOINT:-127.0.0.1:9000}"
  export MINIO_ACCESS_KEY="${MINIO_ACCESS_KEY:-minioadmin}"
  export MINIO_SECRET_KEY="${MINIO_SECRET_KEY:-minioadmin}"
  export MINIO_SECURE="${MINIO_SECURE:-false}"
  export MINIO_BUCKET="${MINIO_BUCKET:-chunks}"

  echo "Starting API on ${APP_HOST}:${APP_PORT}"
  echo "MODEL_DIR=${MODEL_DIR}"
  echo "MINIO_ENDPOINT=${MINIO_ENDPOINT}"

  .venv/bin/uvicorn app:app --host "$APP_HOST" --port "$APP_PORT" --reload
}

run_smoke_test() {
  local base_url="${BASE_URL:-http://127.0.0.1:${APP_PORT}}"

  echo "Health check..."
  curl -fsS "${base_url}/health" && echo

  local sample_file
  sample_file="$(mktemp /tmp/secure-dedup-demo-XXXXXX.txt)"
  echo "hello dedup demo" > "$sample_file"

  echo "First upload..."
  curl -fsS -X POST "${base_url}/upload" \
    -H "X-API-Key: ${API_KEYS:-dev-api-key}" \
    -H "X-Client-ID: demo-client-1" \
    -F "file=@${sample_file}" && echo

  echo "Second upload (duplicate path)..."
  curl -sS -X POST "${base_url}/upload" \
    -H "X-API-Key: ${API_KEYS:-dev-api-key}" \
    -H "X-Client-ID: demo-client-1" \
    -F "file=@${sample_file}" && echo

  rm -f "$sample_file"
}

usage() {
  cat <<EOF
Usage: ./run_demo.sh <command>

Commands:
  start   Start local stack (Redis + MinIO) and run API
  stop    Stop local stack
  test    Run smoke test against running API
EOF
}

cmd="${1:-start}"

case "$cmd" in
  start)
    start_stack
    run_api
    ;;
  stop)
    stop_stack
    ;;
  test)
    run_smoke_test
    ;;
  *)
    usage
    exit 1
    ;;
esac
