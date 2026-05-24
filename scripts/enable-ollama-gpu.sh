#!/usr/bin/env bash
# enable-ollama-gpu.sh
#
# Re-enable GPU inference for Ollama by removing the CPU-only drop-in written
# by scripts/harden-ollama-cpu-only.sh. This host actually has an NVIDIA
# RTX 3090 Ti (24 GB) that was being ignored — CUDA was hidden from Ollama via
# CUDA_VISIBLE_DEVICES="" in no-gpu.conf.
#
# This removes ONLY no-gpu.conf. override.conf (thread/affinity/KV tuning) is
# left in place — it does not block GPU offload.
#
# Idempotent. Rollback: re-run scripts/harden-ollama-cpu-only.sh
set -euo pipefail

DROPIN="/etc/systemd/system/ollama.service.d/no-gpu.conf"

echo "==> Before:"
systemctl show ollama --property=Environment --no-pager | tr ' ' '\n' | grep -iE 'GPU|CUDA|HIP' || true

if [[ -f "$DROPIN" ]]; then
  echo "==> Removing $DROPIN"
  sudo rm -f "$DROPIN"
else
  echo "==> $DROPIN already absent"
fi

echo "==> daemon-reload + restart ollama"
sudo systemctl daemon-reload
sudo systemctl restart ollama
sleep 3

echo "==> After (CUDA should no longer be blanked):"
systemctl show ollama --property=Environment --no-pager | tr ' ' '\n' | grep -iE 'GPU|CUDA|HIP' || echo "  (no GPU-blocking vars — good)"

echo "==> Ollama GPU discovery (from logs):"
sudo journalctl -u ollama -n 40 --no-pager | grep -iE 'gpu|cuda|inference compute|library' | tail -8 || echo "  (none yet)"

echo "==> Warming mistral so it loads onto the GPU, then checking nvidia-smi:"
curl -m 120 -fsS http://127.0.0.1:11434/api/generate \
  -H 'Content-Type: application/json' \
  -d '{"model":"mistral:latest","prompt":"hi","stream":false,"options":{"num_predict":4}}' >/dev/null
nvidia-smi --query-compute-apps=process_name,used_memory --format=csv

echo
echo "Done. If you see an ollama process holding GPU memory above, GPU offload"
echo "is live. Re-run:  python3 scripts/bench-ollama.py --model mistral:latest"
