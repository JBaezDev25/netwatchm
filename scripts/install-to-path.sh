#!/usr/bin/env bash
# install-to-path.sh
#
# Make every NetWatchM script runnable by name from anywhere, for ALL users,
# by installing thin launcher wrappers in /usr/local/bin.
#
# Why wrappers and not raw symlinks: 17 of these scripts derive the repo path
# from their own location (`dirname "$0"` / `__file__`). A bare symlink in
# /usr/local/bin would make them resolve the repo as /usr/local and break.
# A wrapper execs the real script by its ABSOLUTE path, so $0 inside the
# script is the true repo path and resolution works — with zero edits to the
# scripts themselves. Edits to the repo scripts still take effect immediately
# (the wrapper always execs the live file).
#
#   Install:    sudo bash scripts/install-to-path.sh        (or run via !)
#   Uninstall:  sudo bash scripts/install-to-path.sh --uninstall
set -euo pipefail

# self-resolve so this works even when invoked through its own wrapper
SELF="$(readlink -f "$0")"
REPO="$(cd "$(dirname "$SELF")/.." && pwd)"
SCRIPTS="$REPO/scripts"
BIN="/usr/local/bin"
MARKER="# NetWatchM launcher"

if [[ "${1:-}" == "--uninstall" ]]; then
  removed=0
  for f in "$SCRIPTS"/*; do
    w="$BIN/$(basename "$f")"
    if [[ -f "$w" ]] && grep -q "$MARKER" "$w" 2>/dev/null; then
      sudo rm -f "$w" && removed=$((removed + 1))
    fi
  done
  echo "Removed $removed NetWatchM launchers from $BIN."
  exit 0
fi

installed=0
skipped=0
for f in "$SCRIPTS"/*; do
  name="$(basename "$f")"
  [[ -f "$f" ]] || continue
  case "$name" in
    *.ps1) skipped=$((skipped + 1)); continue ;;   # Windows-only, won't run here
  esac
  # only wrap real scripts (must start with a shebang)
  if ! head -1 "$f" | grep -q '^#!'; then
    echo "  skip $name (no shebang)"
    skipped=$((skipped + 1))
    continue
  fi
  chmod +x "$f"
  w="$BIN/$name"
  sudo tee "$w" >/dev/null <<EOF
#!/usr/bin/env bash
$MARKER — execs the repo script so its \$0-relative paths resolve correctly.
exec "$f" "\$@"
EOF
  sudo chmod 755 "$w"
  installed=$((installed + 1))
done

echo
echo "Installed $installed launchers into $BIN (skipped $skipped)."
echo "Run any script by name from any directory, e.g.:"
echo "    count-tokens.py --mode digest"
echo "    enable-ollama-gpu.sh"
echo "    bench-ollama.py --model mistral:latest"
echo
echo "Uninstall: sudo bash $SCRIPTS/install-to-path.sh --uninstall"
