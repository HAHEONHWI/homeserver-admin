#!/usr/bin/env bash
set -Eeuo pipefail

if [[ $# -ne 2 || "$1" != "--confirm" || ! -f "$2" || -L "$2" ]]; then
  echo "Usage: infra/restore.sh --confirm /private/path/audit.sqlite3" >&2
  exit 2
fi

root_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"
backup_file="$(realpath -- "$2")"
backup_dir="$(dirname -- "$backup_file")"
python3 - "$backup_dir" "$backup_file" <<'PY'
import os
import sqlite3
import sys

if os.stat(sys.argv[1]).st_mode & 0o077:
    raise SystemExit("Backup directory must have mode 700 or stricter")
if os.stat(sys.argv[2]).st_mode & 0o077:
    raise SystemExit("Backup file must have mode 600 or stricter")
with sqlite3.connect(f"file:{sys.argv[2]}?mode=ro", uri=True) as db:
    if db.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
        raise SystemExit("Backup failed SQLite integrity_check")
    tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    if not {"jobs", "audit_events"} <= tables:
        raise SystemExit("Backup is missing the HomeServer Admin tables")
PY

if [[ ! -f .env ]]; then
  echo "Missing .env; configure production values before restoring." >&2
  exit 2
fi

infra/compose-prod.sh config -q
infra/compose-prod.sh ps --status running --services | grep -Fxq api || {
  echo "The API must be running so a pre-restore backup can be created." >&2
  exit 2
}

pre_restore="${backup_file%.sqlite3}.before-restore-$(date -u +%Y%m%dT%H%M%SZ).sqlite3"
infra/backup.sh "$pre_restore"
infra/compose-prod.sh stop api
api_stopped=1
restart_api() {
  if [[ ${api_stopped:-0} -eq 1 ]]; then
    infra/compose-prod.sh up -d --wait api || true
  fi
}
trap restart_api EXIT

# The one-shot runner needs to read the private backup and restore volume ownership.
infra/compose-prod.sh run --rm --no-deps --user 0 \
  --cap-add DAC_OVERRIDE --cap-add CHOWN --cap-add FOWNER \
  --volume "$backup_file:/tmp/audit-restore.sqlite3:ro" \
  api python -c '
import os, sqlite3
src = sqlite3.connect("file:/tmp/audit-restore.sqlite3?mode=ro", uri=True)
dst = sqlite3.connect("/data/admin.sqlite3")
src.backup(dst)
src.close()
for table in ("webauthn_credentials", "webauthn_challenges", "webauthn_grants"):
    if dst.execute("SELECT 1 FROM sqlite_master WHERE type=? AND name=?", ("table", table)).fetchone():
        dst.execute(f"DELETE FROM {table}")
dst.commit()
dst.execute("PRAGMA wal_checkpoint(TRUNCATE)")
dst.close()
[(os.chown(p, 10001, 10001), os.chmod(p, 0o600)) for p in ("/data/admin.sqlite3", "/data/admin.sqlite3-wal", "/data/admin.sqlite3-shm") if os.path.exists(p)]
'
infra/compose-prod.sh up -d --wait api
api_stopped=0
echo "Audit database restored. Verify the API and audit history before resuming operations."
