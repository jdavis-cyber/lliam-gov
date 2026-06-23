#!/bin/bash
# Launch Lliam-GOV (isolated home) with the Claude-Code bridge.
#
# Starts claude_bridge.py (routes Claude inference through `claude -p` on the
# Max subscription) if it isn't already up, then launches the desktop app
# pinned to the ~/.lliam-gov governance home.
set -e

export HERMES_HOME="$HOME/.lliam-gov"
BRIDGE_PY="$HOME/.lliam-gov/claude_bridge.py"
VENV_PY="$HOME/lliam-gov/venv/bin/python"
BRIDGE_URL="http://127.0.0.1:8765/health"

# 1. Ensure the bridge is running (idempotent).
if curl -s "$BRIDGE_URL" >/dev/null 2>&1; then
  echo "claude-bridge already running"
else
  echo "starting claude-bridge..."
  # Keep launch logs out of world-readable /tmp (they can echo prompt/project
  # details); match the bridge's own log dir under the isolated home.
  BRIDGE_LOG_DIR="$HOME/.lliam-gov/logs"
  mkdir -p "$BRIDGE_LOG_DIR" && chmod 700 "$BRIDGE_LOG_DIR"
  BRIDGE_LOG="$BRIDGE_LOG_DIR/claude_bridge.log"
  nohup "$VENV_PY" "$BRIDGE_PY" >> "$BRIDGE_LOG" 2>&1 &
  for _ in 1 2 3 4 5 6 7 8; do
    sleep 1
    curl -s "$BRIDGE_URL" >/dev/null 2>&1 && break
  done
  curl -s "$BRIDGE_URL" >/dev/null 2>&1 \
    && echo "claude-bridge up" \
    || { echo "ERROR: claude-bridge failed to start (see $BRIDGE_LOG)"; exit 1; }
fi

# 2. Launch the desktop app against the isolated home.
cd "$HOME/lliam-gov/apps/desktop"
exec env HERMES_HOME="$HOME/.lliam-gov" npm start
