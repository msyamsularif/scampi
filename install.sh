#!/usr/bin/env bash
#
# Scampi installer helper.
#
# Prefers the Hermes CLI. Falls back to printing precise manual steps instead
# of guessing — a plugin that decides how to install itself is a plugin that
# can silently install itself wrong.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ ! -f "$REPO_ROOT/plugin.yaml" ]]; then
  echo "This script must be run from the Scampi repository root." >&2
  exit 1
fi

echo "Scampi — ${REPO_ROOT}"

if command -v hermes >/dev/null 2>&1; then
  echo "Hermes CLI found. Installing from the local directory..."
  if hermes plugins install "$REPO_ROOT"; then
    echo
    echo "Installed. Next steps:"
    echo "  1. hermes plugins enable scampi"
    echo "  2. Set optional keys (docs/credentials.md), or skip them —"
    echo "     link checks degrade gracefully and say so."
    echo "  3. hermes scampi status   (or /scampi status in chat)"
    exit 0
  fi
  echo "Local-path install failed; try the repository form instead:" >&2
  echo "  hermes plugins install <owner>/<repo>" >&2
  exit 1
fi

cat <<'EOF'
Hermes CLI is not on PATH, so here are the manual steps:

  1. Copy this directory into your Hermes plugins folder, e.g.:
       cp -R . "${HERMES_HOME:-$HOME/.hermes}/plugins/scampi"

  2. Enable it in your Hermes config:
       plugins:
         entries:
           scampi:
             enabled: true
             # optional settings live under `settings:` — see docs/configuration.md

  3. Optional provider keys (docs/credentials.md):
       SAFE_BROWSING_API_KEY=...
       URLHAUS_AUTH_KEY=...

  4. Restart Hermes, then check with /scampi status or `hermes scampi status`.
EOF
