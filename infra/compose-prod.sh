#!/usr/bin/env bash
set -Eeuo pipefail

root_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

if [[ ! -f .env ]]; then
  echo "Missing .env; copy .env.example and configure production values." >&2
  exit 2
fi

read_setting() {
  local name="$1"
  if printenv "$name" >/dev/null 2>&1; then
    printenv "$name"
  else
    awk -F= -v name="$name" '$1 == name { value = substr($0, length(name) + 2) } END { print value }' .env
  fi
}

image_tag="$(read_setting IMAGE_TAG)"
if [[ ! "$image_tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][A-Za-z0-9.-]+)?$ ]]; then
  echo "IMAGE_TAG must be a version tag such as v1.2.3." >&2
  exit 2
fi
for name in API_IMAGE_DIGEST WEB_IMAGE_DIGEST AGENT_IMAGE_DIGEST; do
  digest="$(read_setting "$name")"
  if [[ ! "$digest" =~ ^sha256:[0-9a-f]{64}$ ]]; then
    echo "$name must be a sha256 image digest from the tagged CI build." >&2
    exit 2
  fi
done

ssd_path="$(read_setting HOST_SSD_PATH)"
hdd_path="$(read_setting HOST_HDD_PATH)"
compose_files=(-f compose.prod.yaml)

if [[ -n "$ssd_path" || -n "$hdd_path" ]]; then
  if [[ -z "$ssd_path" || -z "$hdd_path" ]]; then
    echo "Set both HOST_SSD_PATH and HOST_HDD_PATH to enable storage metrics." >&2
    exit 2
  fi
  for path in "$ssd_path" "$hdd_path"; do
    if [[ ! "$path" =~ ^/[A-Za-z0-9._/-]+$ || "$path" == *"/../"* || "$path" == */.. || -L "$path" ]]; then
      echo "Storage probe paths must be absolute regular-file paths without whitespace or parent traversal." >&2
      exit 2
    fi
    if [[ ! -f "$path" ]]; then
      echo "Storage probe must be an existing file on the target filesystem: $path" >&2
      exit 2
    fi
  done
  if ! ssd_mount="$(findmnt --noheadings --raw --output TARGET --target "$ssd_path")" \
    || ! hdd_mount="$(findmnt --noheadings --raw --output TARGET --target "$hdd_path")" \
    || ! ssd_source="$(findmnt --noheadings --raw --output SOURCE --target "$ssd_path")" \
    || ! hdd_source="$(findmnt --noheadings --raw --output SOURCE --target "$hdd_path")"; then
    echo "Unable to identify the filesystems for the storage probes." >&2
    exit 2
  fi
  if [[ -z "$ssd_mount" || -z "$hdd_mount" || -z "$ssd_source" || -z "$hdd_source" || "$ssd_mount" == "$hdd_mount" || "$ssd_source" == "$hdd_source" ]]; then
    echo "HOST_SSD_PATH and HOST_HDD_PATH must be on different filesystems." >&2
    exit 2
  fi
  export HOST_SSD_PATH="$ssd_path" HOST_HDD_PATH="$hdd_path"
  export HOST_SSD_MOUNT_LABEL="$ssd_mount" HOST_HDD_MOUNT_LABEL="$hdd_mount"
  compose_files+=(-f compose.storage.prod.yaml)
fi

exec docker compose "${compose_files[@]}" "$@"
