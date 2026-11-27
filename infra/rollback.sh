#!/usr/bin/env bash
set -Eeuo pipefail

if [[ $# -ne 3 || ! "$1" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][A-Za-z0-9.-]+)?$ ]]; then
  echo "Usage: infra/rollback.sh vMAJOR.MINOR.PATCH API_DIGEST AGENT_DIGEST" >&2
  exit 2
fi
for digest in "${@:2}"; do
  if [[ ! "$digest" =~ ^sha256:[0-9a-f]{64}$ ]]; then
    echo "Image digests must use sha256 followed by 64 lowercase hexadecimal characters." >&2
    exit 2
  fi
done

root_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

if [[ ! -f .env ]]; then
  echo "Missing .env; copy .env.example and configure production values." >&2
  exit 2
fi

infra/compose-prod.sh config -q
IMAGE_TAG="$1" API_IMAGE_DIGEST="$2" AGENT_IMAGE_DIGEST="$3" infra/compose-prod.sh pull api agent
IMAGE_TAG="$1" API_IMAGE_DIGEST="$2" AGENT_IMAGE_DIGEST="$3" infra/compose-prod.sh up -d --wait
infra/compose-prod.sh ps
