import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


class RollbackTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        infra = self.root / "infra"
        infra.mkdir()
        source = Path(__file__).resolve().parents[1]
        shutil.copy2(source / "rollback.sh", infra / "rollback.sh")
        shutil.copy2(source / "compose-prod.sh", infra / "compose-prod.sh")
        (self.root / "compose.prod.yaml").touch()
        digest = "sha256:" + "0" * 64
        (self.root / ".env").write_text(
            f"IMAGE_TAG=v9.9.9\n"
            f"API_IMAGE_DIGEST={digest}\n"
            f"WEB_IMAGE_DIGEST={digest}\n"
            f"AGENT_IMAGE_DIGEST={digest}\n"
        )
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.calls = self.root / "docker-calls"
        docker = self.bin / "docker"
        docker.write_text(
            "#!/bin/sh\n"
            "printf '%s|%s|%s|%s|%s\\n' \"$IMAGE_TAG\" \"$API_IMAGE_DIGEST\" "
            "\"$WEB_IMAGE_DIGEST\" \"$AGENT_IMAGE_DIGEST\" \"$*\" >> \"$MOCK_DOCKER_CALLS\"\n"
        )
        docker.chmod(0o755)

    def tearDown(self):
        self.temp.cleanup()

    def run_rollback(self, *args):
        env = os.environ.copy()
        for name in ("IMAGE_TAG", "API_IMAGE_DIGEST", "WEB_IMAGE_DIGEST", "AGENT_IMAGE_DIGEST"):
            env.pop(name, None)
        env.update(PATH=f"{self.bin}:{env['PATH']}", MOCK_DOCKER_CALLS=str(self.calls))
        return subprocess.run(
            [self.root / "infra/rollback.sh", *args],
            capture_output=True,
            text=True,
            env=env,
        )

    def test_rollback_uses_tag_and_each_supplied_digest(self):
        digests = [f"sha256:{letter * 64}" for letter in "abc"]

        result = self.run_rollback("v1.2.3", *digests)

        self.assertEqual(result.returncode, 0, result.stderr)
        calls = self.calls.read_text().splitlines()
        env = "|".join(["v1.2.3", *(f"sha256:{letter * 64}" for letter in "abc")])
        self.assertTrue(any(call.startswith(env) and "pull api web agent" in call for call in calls))
        self.assertTrue(any(call.startswith(env) and "up -d --wait" in call for call in calls))

    def test_rollback_rejects_missing_or_invalid_digests_before_compose(self):
        missing = self.run_rollback("v1.2.3")
        invalid = self.run_rollback("v1.2.3", "latest", "sha256:" + "b" * 64, "sha256:" + "c" * 64)
        invalid_tag = self.run_rollback("latest", "sha256:" + "a" * 64, "sha256:" + "b" * 64, "sha256:" + "c" * 64)

        self.assertEqual(missing.returncode, 2)
        self.assertEqual(invalid.returncode, 2)
        self.assertEqual(invalid_tag.returncode, 2)
        self.assertFalse(self.calls.exists())


if __name__ == "__main__":
    unittest.main()
