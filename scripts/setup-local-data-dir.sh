#!/usr/bin/env bash
set -e

sudo mkdir -p /mnt/jbaez_data/netwatchm
sudo chown netwatchm:netwatchm /mnt/jbaez_data/netwatchm
sudo chmod 750 /mnt/jbaez_data/netwatchm

echo "Local data dir ready:"
ls -la /mnt/jbaez_data/ | grep netwatchm
