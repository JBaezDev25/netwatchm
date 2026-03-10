#!/usr/bin/env bash
# reset-grafana-password.sh — Reset Grafana admin password
# Run with: bash scripts/reset-grafana-password.sh
set -e

read -rsp "New Grafana admin password: " NEW_PASS
echo

sudo grafana-cli admin reset-admin-password "$NEW_PASS"
echo "Done. Login at http://localhost:3000 with admin / <your password>"
