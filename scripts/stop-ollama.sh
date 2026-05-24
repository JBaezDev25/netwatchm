#!/usr/bin/env bash
# Stop (and disable) the Ollama service.
#
# Context: as of Session 30 the NetWatchM agent uses the Anthropic API, not
# Ollama, so the local Ollama daemon is no longer queried by NetWatchM. The
# service was also pinned CPU-only (scripts/harden-ollama-cpu-only.sh), where
# inference timed out at 600s — see CHECKLIST Session 29/30.
#
# This stops the running daemon and disables it at boot so it stops consuming
# CPU/RAM. The downloaded models on disk are NOT removed.
#
# Rollback: sudo systemctl enable --now ollama
set -euo pipefail

echo "Current state:"
systemctl is-active ollama  || true
systemctl is-enabled ollama || true

echo
echo "Stopping ollama ..."
sudo systemctl stop ollama

echo "Disabling ollama at boot ..."
sudo systemctl disable ollama

echo
echo "New state:"
systemctl is-active ollama  || true
systemctl is-enabled ollama || true

echo
echo "Done. Models on disk are untouched. To bring it back:"
echo "    sudo systemctl enable --now ollama"
