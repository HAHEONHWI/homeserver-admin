import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from time import time
from uuid import uuid4


def database_path(data_dir: Path) -> Path:
    return data_dir / "admin.sqlite3"


def initialize(data_dir: Path) -> None:
    data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = database_path(data_dir)
    with sqlite3.connect(path, timeout=5) as connection:
        connection.execute("PRAGMA journal_mode=WAL")
        connection.executescript("""
            CREATE TABLE IF NOT EXISTS jobs (
                id TEXT PRIMARY KEY,
                operation TEXT NOT NULL,
                target TEXT NOT NULL,
                state TEXT NOT NULL,
                simulation INTEGER NOT NULL,
                message TEXT NOT NULL,
                actor TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS audit_events (
                id TEXT PRIMARY KEY,
                actor TEXT NOT NULL,
                operation TEXT NOT NULL,
                target TEXT NOT NULL,
                result TEXT NOT NULL,
                created_at TEXT NOT NULL,
                details TEXT NOT NULL DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS notification_alerts (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS webauthn_credentials (
                credential_id TEXT PRIMARY KEY,
                subject TEXT NOT NULL,
                public_key BLOB NOT NULL,
                sign_count INTEGER NOT NULL,
                name TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS webauthn_credentials_subject
                ON webauthn_credentials(subject);
            CREATE TABLE IF NOT EXISTS webauthn_challenges (
                id TEXT PRIMARY KEY,
                subject TEXT NOT NULL,
                purpose TEXT NOT NULL,
                operation TEXT NOT NULL,
                target TEXT NOT NULL,
                challenge BLOB NOT NULL,
                bootstrap INTEGER NOT NULL,
                expires_at REAL NOT NULL,
                used INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS webauthn_grants (
                token_hash TEXT PRIMARY KEY,
                subject TEXT NOT NULL,
                operation TEXT NOT NULL,
                target TEXT NOT NULL,
                expires_at REAL NOT NULL,
                consumed INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS audit_events_created_at ON audit_events(created_at DESC);
            CREATE INDEX IF NOT EXISTS jobs_created_at ON jobs(created_at DESC);
        """)
        audit_columns = {
            row[1] for row in connection.execute("PRAGMA table_info(audit_events)")
        }
        if "details" not in audit_columns:
            connection.execute(
                "ALTER TABLE audit_events ADD COLUMN details TEXT NOT NULL DEFAULT ''"
            )
        connection.execute("DELETE FROM webauthn_challenges")
        connection.execute("DELETE FROM webauthn_grants")
        connection.execute(
            "UPDATE jobs SET state = 'unknown', message = 'API restarted before the result was confirmed; inspect the target before retrying' "
            "WHERE state = 'running' AND simulation = 0"
        )
        connection.execute(
            "UPDATE audit_events SET result = 'unknown' WHERE result = 'running' AND id IN "
            "(SELECT id FROM jobs WHERE state = 'unknown' AND simulation = 0)"
        )
    path.chmod(0o600)


def record_simulated_job(job: dict, actor: str, data_dir: Path, details: str = "") -> None:
    with sqlite3.connect(database_path(data_dir), timeout=5) as connection:
        connection.execute(
            "INSERT INTO jobs VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                job["id"],
                job["operation"],
                job["target"],
                job["state"],
                1,
                job["message"],
                actor,
                job["createdAt"],
            ),
        )
        connection.execute(
            "INSERT INTO audit_events (id, actor, operation, target, result, created_at, details) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                job["id"], actor, job["operation"], job["target"], "simulated",
                job["createdAt"], details,
            ),
        )


def begin_live_job(job: dict, actor: str, data_dir: Path, details: str = "") -> None:
    with sqlite3.connect(database_path(data_dir), timeout=5) as connection:
        connection.execute(
            "INSERT INTO jobs VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                job["id"],
                job["operation"],
                job["target"],
                "running",
                0,
                job["message"],
                actor,
                job["createdAt"],
            ),
        )
        connection.execute(
            "INSERT INTO audit_events (id, actor, operation, target, result, created_at, details) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                job["id"], actor, job["operation"], job["target"], "running",
                job["createdAt"], details,
            ),
        )


def finish_live_job(job: dict, data_dir: Path, details: str | None = None) -> None:
    with sqlite3.connect(database_path(data_dir), timeout=5) as connection:
        updated = connection.execute(
            "UPDATE jobs SET state = ?, message = ? WHERE id = ? AND simulation = 0",
            (job["state"], job["message"], job["id"]),
        ).rowcount
        audited = connection.execute(
            "UPDATE audit_events SET result = ? WHERE id = ? AND result = 'running'",
            (job["state"], job["id"]),
        ).rowcount
        if audited == 1 and details is not None:
            connection.execute(
                "UPDATE audit_events SET details = ? WHERE id = ?",
                (details, job["id"]),
            )
        if updated != 1 or audited != 1:
            raise ValueError("Live job audit record is missing")


def list_audit(data_dir: Path, limit: int = 50) -> list[dict]:
    with sqlite3.connect(database_path(data_dir), timeout=5) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            "SELECT id, actor, operation, target, result, created_at, details FROM audit_events ORDER BY created_at DESC LIMIT ?",
            (min(max(limit, 1), 100),),
        ).fetchall()
    return [dict(row) for row in rows]


def list_notification_alerts(data_dir: Path) -> dict[str, str]:
    with sqlite3.connect(database_path(data_dir), timeout=5) as connection:
        return dict(connection.execute("SELECT id, name FROM notification_alerts"))


def replace_notification_alerts(data_dir: Path, alerts: dict[str, str]) -> None:
    with sqlite3.connect(database_path(data_dir), timeout=5) as connection:
        connection.execute("DELETE FROM notification_alerts")
        connection.executemany(
            "INSERT INTO notification_alerts (id, name) VALUES (?, ?)", alerts.items()
        )


def list_passkeys(data_dir: Path, subject: str) -> list[dict]:
    with sqlite3.connect(database_path(data_dir), timeout=5) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            "SELECT credential_id, name, created_at FROM webauthn_credentials "
            "WHERE subject = ? ORDER BY created_at",
            (subject,),
        ).fetchall()
    return [dict(row) for row in rows]


def get_passkey(data_dir: Path, subject: str, credential_id: str) -> dict | None:
    with sqlite3.connect(database_path(data_dir), timeout=5) as connection:
        connection.row_factory = sqlite3.Row
        row = connection.execute(
            "SELECT public_key, sign_count FROM webauthn_credentials "
            "WHERE subject = ? AND credential_id = ?",
            (subject, credential_id),
        ).fetchone()
    return dict(row) if row else None


def add_passkey(
    data_dir: Path,
    subject: str,
    credential_id: str,
    public_key: bytes,
    sign_count: int,
    name: str,
    created_at: str,
    actor: str,
    registration_challenge_id: str | None = None,
) -> bool:
    try:
        with sqlite3.connect(database_path(data_dir), timeout=5) as connection:
            if registration_challenge_id:
                connection.execute("BEGIN IMMEDIATE")
                challenge = connection.execute(
                    "SELECT 1 FROM webauthn_challenges WHERE id = ? AND subject = ? "
                    "AND purpose = 'register' AND used = 1 AND expires_at > ?",
                    (registration_challenge_id, subject, time()),
                ).fetchone()
                if challenge is None:
                    return False
            connection.execute(
                "INSERT INTO webauthn_credentials "
                "(credential_id, subject, public_key, sign_count, name, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (credential_id, subject, public_key, sign_count, name, created_at),
            )
            connection.execute(
                "INSERT INTO audit_events (id, actor, operation, target, result, created_at, details) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (str(uuid4()), actor, "passkey.add", name, "succeeded", created_at, ""),
            )
            if registration_challenge_id:
                connection.execute(
                    "DELETE FROM webauthn_challenges WHERE id = ? AND subject = ?",
                    (registration_challenge_id, subject),
                )
        return True
    except sqlite3.IntegrityError:
        return False


def update_passkey_sign_count(
    data_dir: Path, subject: str, credential_id: str, sign_count: int
) -> bool:
    with sqlite3.connect(database_path(data_dir), timeout=5) as connection:
        result = connection.execute(
            "UPDATE webauthn_credentials SET sign_count = MAX(sign_count, ?) "
            "WHERE subject = ? AND credential_id = ?",
            (sign_count, subject, credential_id),
        )
        return result.rowcount == 1


def delete_passkey(data_dir: Path, subject: str, credential_id: str, actor: str) -> bool:
    with sqlite3.connect(database_path(data_dir), timeout=5) as connection:
        connection.execute("BEGIN IMMEDIATE")
        passkey = connection.execute(
            "SELECT name FROM webauthn_credentials WHERE subject = ? AND credential_id = ?",
            (subject, credential_id),
        ).fetchone()
        if passkey is None:
            return False
        result = connection.execute(
            "DELETE FROM webauthn_credentials WHERE subject = ? AND credential_id = ? "
            "AND (SELECT COUNT(*) FROM webauthn_credentials WHERE subject = ?) > 1",
            (subject, credential_id, subject),
        )
        if result.rowcount == 1:
            connection.execute(
                "DELETE FROM webauthn_challenges WHERE subject = ? AND purpose = 'register'",
                (subject,),
            )
            connection.execute(
                "DELETE FROM webauthn_grants WHERE subject = ? AND operation = 'register_passkey'",
                (subject,),
            )
            connection.execute(
                "INSERT INTO audit_events (id, actor, operation, target, result, created_at, details) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    str(uuid4()),
                    actor,
                    "passkey.remove",
                    credential_id,
                    "succeeded",
                    datetime.now(UTC).isoformat(),
                    passkey[0],
                ),
            )
        return result.rowcount == 1


def issue_webauthn_challenge(
    data_dir: Path,
    challenge_id: str,
    subject: str,
    purpose: str,
    operation: str,
    target: str,
    challenge: bytes,
    bootstrap: bool,
    expires_at: float,
) -> None:
    with sqlite3.connect(database_path(data_dir), timeout=5) as connection:
        connection.execute("DELETE FROM webauthn_challenges WHERE expires_at < ?", (time(),))
        connection.execute(
            "INSERT INTO webauthn_challenges "
            "(id, subject, purpose, operation, target, challenge, bootstrap, expires_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                challenge_id,
                subject,
                purpose,
                operation,
                target,
                challenge,
                int(bootstrap),
                expires_at,
            ),
        )


def consume_webauthn_challenge(
    data_dir: Path, challenge_id: str, subject: str, purpose: str, now: float
) -> dict | None:
    with sqlite3.connect(database_path(data_dir), timeout=5) as connection:
        connection.row_factory = sqlite3.Row
        row = connection.execute(
            "UPDATE webauthn_challenges SET used = 1 "
            "WHERE id = ? AND subject = ? AND purpose = ? AND used = 0 AND expires_at > ? "
            "RETURNING operation, target, challenge, bootstrap",
            (challenge_id, subject, purpose, now),
        ).fetchone()
    return dict(row) if row else None


def store_reauth_grant(
    data_dir: Path,
    token_hash: str,
    subject: str,
    operation: str,
    target: str,
    expires_at: float,
) -> None:
    with sqlite3.connect(database_path(data_dir), timeout=5) as connection:
        connection.execute(
            "DELETE FROM webauthn_grants WHERE expires_at < ? OR consumed = 1", (time(),)
        )
        connection.execute(
            "INSERT INTO webauthn_grants "
            "(token_hash, subject, operation, target, expires_at) VALUES (?, ?, ?, ?, ?)",
            (token_hash, subject, operation, target, expires_at),
        )


def consume_reauth_grant(
    data_dir: Path,
    token_hash: str,
    subject: str,
    operation: str,
    target: str,
    now: float,
) -> bool:
    with sqlite3.connect(database_path(data_dir), timeout=5) as connection:
        result = connection.execute(
            "UPDATE webauthn_grants SET consumed = 1 WHERE token_hash = ? AND subject = ? "
            "AND operation = ? AND target = ? AND consumed = 0 AND expires_at > ?",
            (token_hash, subject, operation, target, now),
        )
        return result.rowcount == 1


def _job_from_row(row: sqlite3.Row) -> dict:
    return {
        "id": row["id"],
        "operation": row["operation"],
        "target": row["target"],
        "state": row["state"],
        "simulation": bool(row["simulation"]),
        "message": row["message"],
        "createdAt": row["created_at"],
    }


def list_jobs(data_dir: Path, limit: int = 50) -> list[dict]:
    with sqlite3.connect(database_path(data_dir), timeout=5) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            "SELECT id, operation, target, state, simulation, message, created_at "
            "FROM jobs ORDER BY created_at DESC LIMIT ?",
            (min(max(limit, 1), 100),),
        ).fetchall()
    return [_job_from_row(row) for row in rows]


def get_job(data_dir: Path, job_id: str) -> dict | None:
    with sqlite3.connect(database_path(data_dir), timeout=5) as connection:
        connection.row_factory = sqlite3.Row
        row = connection.execute(
            "SELECT id, operation, target, state, simulation, message, created_at "
            "FROM jobs WHERE id = ?",
            (job_id,),
        ).fetchone()
    return _job_from_row(row) if row else None


def prune_history(data_dir: Path, retention_days: int) -> None:
    if not 1 <= retention_days <= 3650:
        raise ValueError("retention_days must be between 1 and 3650")
    cutoff = (datetime.now(UTC) - timedelta(days=retention_days)).isoformat()
    with sqlite3.connect(database_path(data_dir), timeout=5) as connection:
        connection.execute("DELETE FROM audit_events WHERE created_at < ?", (cutoff,))
        connection.execute(
            "DELETE FROM jobs WHERE state IN ('succeeded', 'failed', 'unknown') AND created_at < ?",
            (cutoff,),
        )


def utc_now() -> str:
    return datetime.now(UTC).isoformat()
