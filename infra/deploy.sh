#!/usr/bin/env bash
set -Eeuo pipefail

root_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

if [[ ! -f .env ]]; then
  echo "Missing .env; copy .env.example and configure production values." >&2
  exit 2
fi

infra/compose-prod.sh config -q
infra/compose-prod.sh pull api web agent
infra/compose-prod.sh up -d --wait
infra/compose-prod.sh ps
