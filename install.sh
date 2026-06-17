#!/usr/bin/env sh
# THENOTHING installer — sets up the platform + the `hydra-security` MCP server.
#
#   curl -fsSL .../install.sh | sh                 # install from a clone or PyPI
#   THENOTHING_DIR=/opt/thenothing sh install.sh   # install into a chosen dir
#   THENOTHING_WITH_BROWSER=1 sh install.sh         # also install Playwright + chromium
#
# Fail-closed: any missing prerequisite or failed step aborts (set -e). No step
# runs privileged; everything lands in a project-local venv unless pipx is used.
set -eu

info() { printf '\033[36m[thenothing]\033[0m %s\n' "$1"; }
err()  { printf '\033[31m[thenothing] error:\033[0m %s\n' "$1" >&2; exit 1; }

# --- prerequisites -------------------------------------------------------------
command -v python3 >/dev/null 2>&1 || err "python3 is required (>=3.10)"
PYV=$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')
case "$PYV" in
  3.1[0-9]|3.[2-9][0-9]) : ;;            # 3.10 .. 3.99
  *) err "python >=3.10 required, found $PYV" ;;
esac
info "python $PYV ok"

# --- locate the source tree ----------------------------------------------------
# Prefer the directory this script lives in (a clone); fall back to PyPI install.
SCRIPT_DIR=$(cd "$(dirname "$0")" 2>/dev/null && pwd || echo "")
SRC=""
if [ -n "$SCRIPT_DIR" ] && [ -f "$SCRIPT_DIR/mcp_server.py" ]; then
  SRC="$SCRIPT_DIR"
  info "installing from source tree: $SRC"
fi

# --- install -------------------------------------------------------------------
TARGET="${THENOTHING_DIR:-$HOME/.thenothing}"
if [ -n "$SRC" ]; then
  info "creating venv at $TARGET/venv"
  python3 -m venv "$TARGET/venv"
  # shellcheck disable=SC1091
  . "$TARGET/venv/bin/activate"
  python3 -m pip install --upgrade pip >/dev/null
  info "installing dependencies"
  pip install -r "$SRC/requirements.txt"
  pip install -e "$SRC"
else
  command -v pipx >/dev/null 2>&1 || err "no source tree found and pipx not installed (pip install pipx)"
  info "installing 'thenothing' from PyPI via pipx"
  pipx install thenothing
fi

# --- optional: browser engine --------------------------------------------------
if [ "${THENOTHING_WITH_BROWSER:-0}" = "1" ]; then
  info "installing Playwright + chromium (browser_crawl)"
  pip install playwright
  python3 -m playwright install chromium
fi

# --- verify --------------------------------------------------------------------
info "verifying the MCP server imports"
if [ -n "$SRC" ]; then
  ( cd "$SRC" && python3 -c "import mcp_server; print('hydra-security MCP server OK')" )
fi

info "done. Register the 'hydra-security' MCP server (cwd = repo root) in your client."
info "Operator mode: declare scope once (register_bounty_program) then run the harness skip-permissions."
