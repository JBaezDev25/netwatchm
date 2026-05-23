#!/usr/bin/env bash
# harden-ollama-cpu-only.sh
#
# Pin Ollama to CPU-only mode so it skips GPU discovery on startup.
#
# Why: this host (Ryzen 5 5600G, no discrete GPU) has hit an intermittent
# Ollama deadlock where /api/chat hangs for 3+ minutes because of:
#   failure during GPU discovery — OLLAMA_LIBRARY_PATH=[…/cuda_v13]
#   error="failed to finish discovery before timeout"
# (see journalctl -u ollama on 2026-05-23 14:33 EDT).
#
# OLLAMA_NUM_GPU=0 alone does NOT prevent discovery — it only sets the
# layer count for inference. To actually skip discovery we hide CUDA and
# ROCm runtimes from Ollama via the standard env vars they themselves
# respect.
#
# Writes a systemd drop-in (additive, leaves the packaged unit untouched)
# at /etc/systemd/system/ollama.service.d/no-gpu.conf, reloads systemd,
# restarts ollama, and times one chat request to confirm health.
#
# Idempotent — safe to re-run. Rollback: delete the drop-in file and
# `sudo systemctl daemon-reload && sudo systemctl restart ollama`.
set -euo pipefail

DROPIN_DIR="/etc/systemd/system/ollama.service.d"
DROPIN_FILE="${DROPIN_DIR}/no-gpu.conf"

echo "==> Writing CPU-only drop-in at ${DROPIN_FILE}"
sudo mkdir -p "${DROPIN_DIR}"
sudo tee "${DROPIN_FILE}" > /dev/null <<'CONF'
# Managed by scripts/harden-ollama-cpu-only.sh — see that file for context.
[Service]
Environment=OLLAMA_NUM_GPU=0
Environment=CUDA_VISIBLE_DEVICES=
Environment=HIP_VISIBLE_DEVICES=
CONF

sudo chmod 644 "${DROPIN_FILE}"

echo "==> Reloading systemd + restarting ollama"
sudo systemctl daemon-reload
sudo systemctl restart ollama

echo "==> Confirming Environment is applied:"
systemctl show ollama --property=Environment --no-pager

echo
echo "==> Waiting 3s for ollama to come up…"
sleep 3
systemctl is-active ollama

echo
echo "==> Tail the last lines of the ollama log (should NOT show 'GPU discovery'):"
sudo journalctl -u ollama -n 20 --no-pager | grep -iE 'gpu|discovery|cuda|hip|started|listen' || \
  echo "  (no GPU-related lines — good)"

echo
echo "==> Timed sanity check: trivial chat to mistral:latest (~3s expected on this host)"
time curl -m 60 -fsS http://127.0.0.1:11434/api/chat \
  -H 'Content-Type: application/json' \
  -d '{"model":"mistral:latest","stream":false,"think":false,
       "messages":[{"role":"user","content":"say ok"}],
       "options":{"num_predict":8}}' \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print('reply :', repr(d.get('message',{}).get('content','')[:80])); print('load  :', d.get('load_duration',0)//1_000_000, 'ms'); print('eval  :', d.get('eval_count'), 'tok in', d.get('eval_duration',0)//1_000_000, 'ms'); print('total :', d.get('total_duration',0)//1_000_000, 'ms')"

echo
echo "Done. Ollama is pinned to CPU-only. The next netwatchm agent tick"
echo "(every 5 min) will use this same Ollama. To roll back:"
echo "  sudo rm ${DROPIN_FILE}"
echo "  sudo systemctl daemon-reload && sudo systemctl restart ollama"
