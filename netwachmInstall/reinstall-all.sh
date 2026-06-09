#!/usr/bin/env bash
#
# NetWatchM — full-rebuild bootstrap (Linux)
#
# Installs, in order:
#   1. NetWatchM core (monitor + web dashboard)  — via netwachmInstall/install.sh
#   2. Local AI (optional, ON by default)        — Ollama + the models NetWatchM can use
#   3. nic-asst-ai (optional, ON by default)     — Claude/OpenRouter network assistant
#
# Usage: bash netwachmInstall/reinstall-all.sh [options]
#   --no-ai        skip Ollama + local model install
#   --no-nic       skip the nic-asst-ai helper
#   --owner NAME   GitHub owner for the nic-asst-ai clone (default: JBaezDev25)
#   --yes, -y      non-interactive (read OPENROUTER_API_KEY from the environment)
#   -h, --help     show this help
#
set -euo pipefail

# ---- defaults ----
WITH_AI=true
WITH_NIC=true
ASSUME_YES=false
GH_OWNER="JBaezDev25"
AI_MODELS=("mistral:latest" "nomic-embed-text:latest")
PROJECTS_DIR="${PROJECTS_DIR:-$HOME/ai-projects}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NETWATCHM_DIR="$(dirname "$SCRIPT_DIR")"      # repo root (parent of netwachmInstall/)

# ---- pretty output ----
c_g=$'\e[32m'; c_y=$'\e[33m'; c_r=$'\e[31m'; c_b=$'\e[36m'; c_0=$'\e[0m'
step(){ printf '\n%s==>%s %s\n' "$c_b" "$c_0" "$*"; }
ok(){   printf '%s  ok%s %s\n' "$c_g" "$c_0" "$*"; }
warn(){ printf '%s   !%s %s\n' "$c_y" "$c_0" "$*"; }
die(){  printf '%s   x%s %s\n' "$c_r" "$c_0" "$*" >&2; exit 1; }

# ---- args ----
while [ $# -gt 0 ]; do
  case "$1" in
    --no-ai)   WITH_AI=false ;;
    --no-nic)  WITH_NIC=false ;;
    --owner)   GH_OWNER="${2:?--owner needs a value}"; shift ;;
    --yes|-y)  ASSUME_YES=true ;;
    -h|--help) grep '^#' "$0" | grep -v '^#!' | sed 's/^#\s\{0,1\}//'; exit 0 ;;
    *) die "unknown option: $1 (try --help)" ;;
  esac
  shift
done

command -v git  >/dev/null || die "git is required."
command -v curl >/dev/null || die "curl is required."

# ---- 1. NetWatchM core ----
step "1/3 · NetWatchM core (monitor + web dashboard)"
[ -f "$NETWATCHM_DIR/netwachmInstall/install.sh" ] \
  || die "install.sh not found — run this from inside the netwatchm repo."
bash "$NETWATCHM_DIR/netwachmInstall/install.sh" --yes
ok "NetWatchM core installed."

# ---- 2. Local AI (Ollama + models) ----
if $WITH_AI; then
  step "2/3 · Local AI — Ollama + models: ${AI_MODELS[*]}"
  if ! command -v ollama >/dev/null; then
    warn "Ollama not found — installing via the official script (uses sudo)."
    curl -fsSL https://ollama.com/install.sh | sh
  else
    ok "Ollama already installed ($(command -v ollama))."
  fi
  # make sure the daemon is reachable
  if command -v systemctl >/dev/null && systemctl list-unit-files 2>/dev/null | grep -q '^ollama\.service'; then
    sudo systemctl enable --now ollama 2>/dev/null || true
  fi
  ollama list >/dev/null 2>&1 || { warn "starting ollama serve in the background"; (ollama serve >/dev/null 2>&1 &) ; sleep 3; }
  for m in "${AI_MODELS[@]}"; do
    if ollama list 2>/dev/null | awk '{print $1}' | grep -qx "$m"; then
      ok "model present: $m"
    else
      warn "pulling model: $m  (may be several GB)"
      ollama pull "$m" || warn "could not pull $m — retry later with: ollama pull $m"
    fi
  done
else
  step "2/3 · Local AI — skipped (--no-ai)"
fi

# ---- 3. nic-asst-ai ----
if $WITH_NIC; then
  step "3/3 · nic-asst-ai (Claude/OpenRouter network assistant)"
  if ! command -v uv >/dev/null; then
    warn "installing uv (per-user Python package manager)"
    curl -LsSf https://astral.sh/uv/install.sh | sh
    export PATH="$HOME/.local/bin:$PATH"
  fi
  NIC_DIR="$PROJECTS_DIR/nic-asst-ai"
  mkdir -p "$PROJECTS_DIR"
  if [ -d "$NIC_DIR/.git" ]; then
    ok "repo present — updating"
    git -C "$NIC_DIR" pull --ff-only || warn "pull skipped (local changes present)"
  else
    git clone "https://github.com/$GH_OWNER/nic-asst-ai.git" "$NIC_DIR"
  fi
  ( cd "$NIC_DIR" && uv sync )

  # OpenRouter key — nic-asst-ai reads it from ~/.env
  if grep -qsE '^OPENROUTER_API_KEY=' "$HOME/.env"; then
    ok "OPENROUTER_API_KEY already present in ~/.env"
  elif [ -n "${OPENROUTER_API_KEY:-}" ]; then
    printf 'OPENROUTER_API_KEY=%s\n' "$OPENROUTER_API_KEY" >> "$HOME/.env"
    chmod 600 "$HOME/.env"; ok "saved OPENROUTER_API_KEY to ~/.env"
  elif $ASSUME_YES; then
    warn "no OPENROUTER_API_KEY set — add it to ~/.env later for AI analysis."
  else
    printf 'Enter your OpenRouter API key (sk-or-v1-...), blank to skip: '
    read -r KEY || KEY=""
    if [ -n "$KEY" ]; then
      printf 'OPENROUTER_API_KEY=%s\n' "$KEY" >> "$HOME/.env"
      chmod 600 "$HOME/.env"; ok "saved to ~/.env"
    else
      warn "skipped — add OPENROUTER_API_KEY to ~/.env later."
    fi
  fi
  ok "nic-asst-ai ready."
else
  step "3/3 · nic-asst-ai — skipped (--no-nic)"
fi

# ---- summary ----
step "Done."
echo "  • NetWatchM dashboard:  https://localhost:8765/events.html  (or your host IP on the LAN)"
$WITH_AI  && echo "  • Local AI models:      ${AI_MODELS[*]}  (enable NetWatchM's agent in netwatchm.yaml -> ai.enabled: true)"
$WITH_NIC && echo "  • nic-asst-ai:          cd $PROJECTS_DIR/nic-asst-ai && uv run python main.py --list"
