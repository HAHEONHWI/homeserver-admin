#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

if [[ $# -ne 1 ]]; then
  echo "Usage: infra/backup.sh /private/path/audit.sqlite3" >&2
  exit 2
fi

root_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"
backup_file="$(realpath -m -- "$1")"
backup_dir="$(dirname -- "$backup_file")"
mkdir -p -- "$backup_dir"
python3 - "$backup_dir" <<'PY'
import os
import sys

if os.stat(sys.argv[1]).st_mode & 0o077:
    raise SystemExit("Backup directory must have mode 700 or stricter")
PY

if [[ -e "$backup_file" ]]; then
  echo "Refusing to overwrite existing backup: $backup_file" >&2
  exit 2
fi

infra/compose-prod.sh config -q
container_file="/tmp/hs-admin-audit-$$.sqlite3"
tmp_dir="$(mktemp -d "$backup_dir/.audit.XXXXXXXX")"
tmp_file="$tmp_dir/admin.sqlite3"
cleanup() {
  infra/compose-prod.sh exec -T api python -c 'import os,sys; os.path.exists(sys.argv[1]) and os.unlink(sys.argv[1])' "$container_file" >/dev/null 2>&1 || true
  rm -f -- "$tmp_file"
  rmdir -- "$tmp_dir" 2>/dev/null || true
}
trap cleanup EXIT

infra/compose-prod.sh exec -T -e "BACKUP_PATH=$container_file" api python -c 'import os,sqlite3; src=sqlite3.connect("file:/data/admin.sqlite3?mode=ro",uri=True); dst=sqlite3.connect(os.environ["BACKUP_PATH"]); src.backup(dst); dst.close(); src.close()'
infra/compose-prod.sh cp "api:$container_file" "$tmp_file"
python3 - "$tmp_file" <<'PY'
import sqlite3
import sys

with sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True) as db:
    if db.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
        raise SystemExit("Backup failed SQLite integrity_check")
    tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    if not {"jobs", "audit_events"} <= tables:
        raise SystemExit("Backup is missing the HomeServer Admin tables")
PY
chmod 600 "$tmp_file"
mv -- "$tmp_file" "$backup_file"
printf 'Backup saved: %s\n' "$backup_file"
