#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# Revula — Full Test Suite Runner
#
# Runs the complete quality pipeline:
#   1. ruff check (linting)
#   2. ruff format --check (formatting)
#   3. mypy (type checking)
#   4. pytest with coverage
#
# Usage:
#   ./run_tests.sh               # full suite
#   ./run_tests.sh --quick       # skip mypy + coverage
#   ./run_tests.sh --no-lint     # skip ruff + mypy
# =============================================================================

FLAG_QUICK=false
FLAG_NO_LINT=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --quick)    FLAG_QUICK=true ;;
        --no-lint)  FLAG_NO_LINT=true ;;
        --help|-h)
            echo "Usage: $0 [--quick] [--no-lint] [--help]"
            echo "  --quick    Skip mypy and coverage"
            echo "  --no-lint  Skip ruff and mypy"
            exit 0
            ;;
        *) echo "Unknown arg: $1"; exit 1 ;;
    esac
    shift
done

# ---------------------------------------------------------------------------
# Colors
# ---------------------------------------------------------------------------

if [[ -t 1 ]] && [[ "${TERM:-dumb}" != "dumb" ]]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
    BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'
else
    RED='' GREEN='' YELLOW='' BLUE='' BOLD='' NC=''
fi

step()    { echo -e "\n${BOLD}${BLUE}▶ $*${NC}"; }
pass()    { echo -e "${GREEN}  ✓ $*${NC}"; }
fail()    { echo -e "${RED}  ✗ $*${NC}"; }

# ---------------------------------------------------------------------------
# Project root detection
# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
cd "$PROJECT_ROOT"

echo -e "${BOLD}"
echo "╔══════════════════════════════════════════════════════╗"
echo "║         Revula — Test Suite Runner                   ║"
echo "╚══════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo "  Project root: ${PROJECT_ROOT}"
echo "  Python:       $(python3 --version 2>&1)"
echo ""

TOTAL=0
PASSED=0
FAILED=0

run_step() {
    local name="$1"
    shift
    ((TOTAL++)) || true
    step "$name"
    if "$@"; then
        pass "$name passed"
        ((PASSED++)) || true
        return 0
    else
        fail "$name FAILED"
        ((FAILED++)) || true
        return 1
    fi
}

# ---------------------------------------------------------------------------
# Steps
# ---------------------------------------------------------------------------

EXIT_CODE=0

if [[ "$FLAG_NO_LINT" == false ]]; then
    # 1. Ruff lint
    run_step "ruff check" python3 -m ruff check src/ tests/ || EXIT_CODE=1

    # 2. Ruff format check
    run_step "ruff format --check" python3 -m ruff format --check src/ tests/ || EXIT_CODE=1

    # 3. mypy (skip in quick mode)
    if [[ "$FLAG_QUICK" == false ]]; then
        run_step "mypy" python3 -m mypy src/revula/ --ignore-missing-imports || EXIT_CODE=1
    fi
fi

# 4. pytest
if [[ "$FLAG_QUICK" == true ]]; then
    run_step "pytest" python3 -m pytest tests/ -x -q --timeout=60 || EXIT_CODE=1
else
    run_step "pytest (with coverage)" python3 -m pytest tests/ \
        --timeout=120 \
        -q \
        --cov=revula \
        --cov-report=term-missing \
        --cov-report=html:htmlcov \
        --cov-fail-under=0 || EXIT_CODE=1
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

echo ""
echo "══════════════════════════════════════════════════════"
echo -e "  ${GREEN}Passed: ${PASSED}${NC}  /  ${BOLD}Total: ${TOTAL}${NC}  |  ${RED}Failed: ${FAILED}${NC}"
echo "══════════════════════════════════════════════════════"

if [[ "$FAILED" -gt 0 ]]; then
    echo -e "${RED}${BOLD}  Some checks failed!${NC}"
else
    echo -e "${GREEN}${BOLD}  All checks passed!${NC}"
fi

if [[ "$FLAG_QUICK" == false ]] && [[ "$FLAG_NO_LINT" == false ]]; then
    if [[ -d "htmlcov" ]]; then
        echo ""
        echo "  Coverage report: file://${PROJECT_ROOT}/htmlcov/index.html"
    fi
fi

echo ""
exit $EXIT_CODE
