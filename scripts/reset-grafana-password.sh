#!/usr/bin/env bash
# reset-grafana-password.sh — Reset Grafana admin password
# Run with: bash scripts/reset-grafana-password.sh
set -e

NEW_PASS="BioIluvleeloo@5858"

sudo grafana-cli admin reset-admin-password "$NEW_PASS"
echo "Done. Login at http://localhost:3000 with admin / $NEW_PASS"
