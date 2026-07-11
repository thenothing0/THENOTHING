#!/usr/bin/env bash
set -euo pipefail

# HYDRA smoke test — build, install in temp venv, validate
VENV_DIR=$(mktemp -d)
trap 'rm -rf "$VENV_DIR"' EXIT

echo "=== HYDRA Smoke Test ==="
echo "Temp venv: $VENV_DIR"

# Build
echo ""
echo "--- Building ---"
python -m build --quiet 2>/dev/null || python -m build
WHEEL=$(ls dist/hydra_security-*.whl 2>/dev/null | head -1)
if [ -z "$WHEEL" ]; then
    echo "FAIL: no wheel found in dist/"
    exit 1
fi
echo "Built: $WHEEL"

# Install in clean venv
echo ""
echo "--- Installing in clean venv ---"
python -m venv "$VENV_DIR"
"$VENV_DIR/bin/pip" install --quiet "$WHEEL"

# Verify import
echo ""
echo "--- Verifying import ---"
VERSION=$("$VENV_DIR/bin/python" -c "from hydra import __version__; print(__version__)")
echo "Version: $VERSION"
if [ "$VERSION" != "1.0.0" ]; then
    echo "FAIL: expected version 1.0.0, got $VERSION"
    exit 1
fi

# Verify entry points
echo ""
echo "--- Verifying entry points ---"
"$VENV_DIR/bin/hydra-engine" --help >/dev/null 2>&1 && echo "hydra-engine --help: OK" || echo "hydra-engine --help: FAIL"
"$VENV_DIR/bin/python" -m hydra --help >/dev/null 2>&1 && echo "python -m hydra --help: OK" || echo "python -m hydra --help: FAIL"

echo ""
echo "=== Smoke test PASSED ==="
