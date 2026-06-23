#!/usr/bin/env bash
# =============================================================================
#  run_prowler.sh
#  Runs a Prowler scan against the ICT lab AWS environment.
#
#  Usage:
#    ./run_prowler.sh [--mock]        # --mock uses pre-generated findings
#    ./run_prowler.sh                 # real AWS scan (needs credentials)
#
#  Prerequisites (real mode):
#    pip install prowler
#    export AWS_ACCESS_KEY_ID=...
#    export AWS_SECRET_ACCESS_KEY=...
#    export AWS_DEFAULT_REGION=eu-west-1
# =============================================================================

set -euo pipefail

RESULTS_DIR="../results"
mkdir -p "$RESULTS_DIR"

if [[ "${1:-}" == "--mock" ]]; then
  echo "============================================================"
  echo "  MOCK MODE: using pre-generated findings"
  echo "============================================================"
  python3 ../mock_data/generate_mock_environment.py
  echo ""
  echo "[OK] Mock scan complete. Results in $RESULTS_DIR/"
  exit 0
fi

# ── REAL MODE ─────────────────────────────────────────────────────────────────
echo "============================================================"
echo "  PROWLER REAL AWS SCAN"
echo "============================================================"

# Check credentials
if [[ -z "${AWS_ACCESS_KEY_ID:-}" ]]; then
  echo "[ERROR] AWS credentials not set."
  echo "  Export AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_DEFAULT_REGION"
  echo "  or use: ./run_prowler.sh --mock"
  exit 1
fi

echo "[INFO] Running full account scan — this takes ~10-20 minutes..."
echo "[INFO] Region: ${AWS_DEFAULT_REGION:-eu-west-1}"

# Full scan — all services, three output formats
prowler aws \
  --region "${AWS_DEFAULT_REGION:-eu-west-1}" \
  --output-formats json csv html \
  --output-directory "$RESULTS_DIR" \
  --output-filename prowler_output \
  --log-level WARNING \
  --ignore-exit-code-3

# Rename main JSON to expected filename
find "$RESULTS_DIR" -name "prowler_output*.json" | head -1 | \
  xargs -I{} cp {} "$RESULTS_DIR/prowler_output.json"

echo ""
echo "[OK] Prowler scan complete."
echo "     JSON : $RESULTS_DIR/prowler_output.json"
echo "     HTML : $RESULTS_DIR/prowler_output.html"
echo "     CSV  : $RESULTS_DIR/prowler_output.csv"
