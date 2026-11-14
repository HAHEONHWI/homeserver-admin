import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


class ComposeProdTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        infra = self.root / "infra"
        infra.mkdir()
        self.script = infra / "compose-prod.sh"
        shutil.copy2(Path(__file__).resolve().parents[1] / "compose-prod.sh", self.script)
        (self.root / "compose.prod.yaml").touch()
        (self.root / "compose.storage.prod.yaml").touch()
        self.env_file = self.root / ".env"
        self.image_settings = (
            "IMAGE_TAG=v1.0.0\n"
            f"API_IMAGE_DIGEST=sha256:{'0' * 64}\n"
            f"WEB_IMAGE_DIGEST=sha256:{'0' * 64}\n"
            f"AGENT_IMAGE_DIGEST=sha256:{'0' * 64}\n"
        )
        self.env_file.write_text(self.image_settings)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.args_file = self.root / "docker-args"
        self.env_file_capture = self.root / "docker-env"
        docker = self.bin / "docker"
        docker.write_text(
            "#!/bin/sh\n"
            "printf '%s\\n' \"$@\" > \"$MOCK_DOCKER_ARGS\"\n"
            "printf '%s\\n' \"$HOST_SSD_PATH\" \"$HOST_HDD_PATH\" > \"$MOCK_DOCKER_ENV\"\n"
        )
        docker.chmod(0o755)
        findmnt = self.bin / "findmnt"
        findmnt.write_text(
            "#!/bin/sh\n"
            "[ \"${MOCK_FINDMNT_EXIT:-0}\" = 0 ] || exit \"$MOCK_FINDMNT_EXIT\"\n"
            "for arg do last=\"$arg\"; done\n"
            "case \"$*\" in\n"
            "  *SOURCE*) case \"$last\" in */ssd-probe) echo /dev/ssd;; *) echo /dev/hdd;; esac;;\n"
            "  *) case \"$last\" in */ssd-probe) echo /;; *) echo /mnt/hdd;; esac;;\n"
            "esac\n"
        )
        findmnt.chmod(0o755)

    def tearDown(self):
        self.temp.cleanup()

    def run_helper(self, **values):
        env = os.environ.copy()
        env.pop("HOST_SSD_PATH", None)
        env.pop("HOST_HDD_PATH", None)
        env.update(
            PATH=f"{self.bin}:{env['PATH']}",
            MOCK_DOCKER_ARGS=str(self.args_file),
            MOCK_DOCKER_ENV=str(self.env_file_capture),
            **values,
        )
        return subprocess.run(
            [self.script, "config", "-q"], capture_output=True, text=True, env=env
        )

    def test_reads_two_paths_from_env_file_and_selects_storage_overlay(self):
        ssd, hdd = self.root / "ssd-probe", self.root / "hdd-probe"
        ssd.touch()
        hdd.touch()
        self.env_file.write_text(
            f"HOST_SSD_PATH={ssd}\nHOST_HDD_PATH={hdd}\n{self.image_settings}"
        )

        result = self.run_helper()

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("compose.storage.prod.yaml", self.args_file.read_text().splitlines())
        self.assertEqual(self.env_file_capture.read_text().splitlines(), [str(ssd), str(hdd)])

    def test_validated_paths_override_export_syntax_in_compose_env_file(self):
        ssd, hdd = self.root / "ssd-probe", self.root / "hdd-probe"
        ssd.touch()
        hdd.touch()
        self.env_file.write_text(
            f"HOST_SSD_PATH={ssd}\nHOST_HDD_PATH={hdd}\nexport HOST_SSD_PATH=/\n"
            f"{self.image_settings}"
        )

        result = self.run_helper()

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.env_file_capture.read_text().splitlines(), [str(ssd), str(hdd)])

    def test_omits_overlay_when_storage_is_unset(self):
        result = self.run_helper()

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("compose.storage.prod.yaml", self.args_file.read_text().splitlines())

    def test_rejects_mutable_or_malformed_image_reference(self):
        self.env_file.write_text(
            "IMAGE_TAG=v1.0.0\n"
            "API_IMAGE_DIGEST=latest\n"
            f"WEB_IMAGE_DIGEST=sha256:{'0' * 64}\n"
            f"AGENT_IMAGE_DIGEST=sha256:{'0' * 64}\n"
        )

        result = self.run_helper()

        self.assertEqual(result.returncode, 2)
        self.assertIn("API_IMAGE_DIGEST", result.stderr)
        self.assertFalse(self.args_file.exists())

    def test_rejects_mutable_release_tag(self):
        self.env_file.write_text(
            "IMAGE_TAG=latest\n"
            f"API_IMAGE_DIGEST=sha256:{'0' * 64}\n"
            f"WEB_IMAGE_DIGEST=sha256:{'0' * 64}\n"
            f"AGENT_IMAGE_DIGEST=sha256:{'0' * 64}\n"
        )

        result = self.run_helper()

        self.assertEqual(result.returncode, 2)
        self.assertIn("IMAGE_TAG", result.stderr)
        self.assertFalse(self.args_file.exists())

    def test_rejects_partial_or_traversing_storage_paths(self):
        ssd = self.root / "ssd-probe"
        ssd.touch()
        partial = self.run_helper(HOST_SSD_PATH=str(ssd))
        traversal = self.run_helper(
            HOST_SSD_PATH=f"{self.root}/../ssd", HOST_HDD_PATH=str(ssd)
        )

        self.assertEqual(partial.returncode, 2)
        self.assertEqual(traversal.returncode, 2)

    def test_rejects_paths_when_filesystem_cannot_be_identified(self):
        ssd, hdd = self.root / "ssd-probe", self.root / "hdd-probe"
        ssd.touch()
        hdd.touch()
        result = self.run_helper(
            HOST_SSD_PATH=str(ssd),
            HOST_HDD_PATH=str(hdd),
            MOCK_FINDMNT_EXIT="1",
        )

        self.assertEqual(result.returncode, 2)
        self.assertFalse(self.args_file.exists())


if __name__ == "__main__":
    unittest.main()
