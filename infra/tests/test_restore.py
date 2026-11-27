import os
import shutil
import sqlite3
import subprocess
import tempfile
import unittest
from pathlib import Path


class RestoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        infra = self.root / "infra"
        infra.mkdir()
        source = Path(__file__).resolve().parents[1]
        shutil.copy2(source / "restore.sh", infra / "restore.sh")
        shutil.copy2(source / "compose-prod.sh", infra / "compose-prod.sh")
        (self.root / "compose.prod.yaml").touch()
        digest = "sha256:" + "0" * 64
        (self.root / ".env").write_text(
            f"IMAGE_TAG=v1.0.0\n"
            f"API_IMAGE_DIGEST={digest}\n"
            f"AGENT_IMAGE_DIGEST={digest}\n"
        )
        (infra / "backup.sh").write_text("#!/bin/sh\nexit 0\n")
        (infra / "backup.sh").chmod(0o755)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.docker_log = self.root / "docker-log"
        docker = self.bin / "docker"
        docker.write_text(
            "#!/bin/sh\n"
            "printf '%s\\n' \"$*\" >> \"$MOCK_DOCKER_LOG\"\n"
            "case \"$*\" in *'ps --status running --services'*) echo api;; esac\n"
        )
        docker.chmod(0o755)
        self.backup_dir = self.root / "backups"
        self.backup_dir.mkdir(mode=0o700)
        self.backup = self.backup_dir / "audit.sqlite3"
        with sqlite3.connect(self.backup) as db:
            db.executescript("CREATE TABLE jobs(id TEXT); CREATE TABLE audit_events(id TEXT);")
        self.backup.chmod(0o600)

    def tearDown(self):
        self.temp.cleanup()

    def test_restore_container_gets_only_required_file_repair_capabilities(self):
        env = os.environ.copy()
        env.update(PATH=f"{self.bin}:{env['PATH']}", MOCK_DOCKER_LOG=str(self.docker_log))

        result = subprocess.run(
            [self.root / "infra/restore.sh", "--confirm", self.backup],
            capture_output=True,
            text=True,
            env=env,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        run = next(
            line
            for line in self.docker_log.read_text().splitlines()
            if " compose -f compose.prod.yaml run " in f" {line} "
        )
        for capability in ("DAC_OVERRIDE", "CHOWN", "FOWNER"):
            self.assertIn(f"--cap-add {capability}", run)
        logged_calls = self.docker_log.read_text()
        self.assertIn(
            '("webauthn_credentials", "webauthn_challenges", "webauthn_grants")',
            logged_calls,
        )
        self.assertIn('DELETE FROM {table}', logged_calls)


if __name__ == "__main__":
    unittest.main()
