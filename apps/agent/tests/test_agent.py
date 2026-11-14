import json
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from apps.agent.agent import MetricsSampler, make_handler


def write_snapshot(host_dir, *, cpu_user, cpu_idle, rx, memory_available):
    (host_dir / "stat").write_text(
        f"cpu {cpu_user} 0 100 {cpu_idle} 0 0 0 0\n"
        f"cpu0 {cpu_user // 2} 0 50 {cpu_idle // 2} 0 0 0 0\n"
        f"cpu1 {cpu_user // 2} 0 50 {cpu_idle // 2} 0 0 0 0\n"
    )
    (host_dir / "net-dev").write_text(
        "Inter-| Receive | Transmit\n"
        " face |bytes packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed\n"
        f"  eth0: {rx} 0 0 0 0 0 0 0 200 0 0 0 0 0 0 0\n"
        "    lo: 9000 0 0 0 0 0 0 0 9000 0 0 0 0 0 0 0\n"
    )
    (host_dir / "meminfo").write_text(
        f"MemTotal: 1000 kB\nMemAvailable: {memory_available} kB\n"
        "SwapTotal: 500 kB\nSwapFree: 300 kB\n"
    )
    (host_dir / "loadavg").write_text("0.50 0.40 0.30 1/100 123\n")
    (host_dir / "uptime").write_text("1234.5 900.0\n")
    (host_dir / "hostname").write_text("heonhwi-homeserver\n")
    (host_dir / "cpuinfo").write_text(
        "processor : 0\nmodel name : Intel Core i7-2600\nphysical id : 0\ncore id : 0\ncpu cores : 1\nflags : sse4_2 avx\n\n"
        "processor : 1\nmodel name : Intel Core i7-2600\nphysical id : 0\ncore id : 0\ncpu cores : 1\nflags : sse4_2 avx\n"
    )


class AgentTests(unittest.TestCase):
    def test_sampler_reports_live_metrics(self):
        with tempfile.TemporaryDirectory() as directory:
            host_dir = Path(directory)
            write_snapshot(host_dir, cpu_user=100, cpu_idle=100, rx=1000, memory_available=400)
            sampler = MetricsSampler(host_dir)
            with patch("apps.agent.agent.time.monotonic", side_effect=[1.0, 3.0]):
                first = sampler.sample()
                write_snapshot(host_dir, cpu_user=110, cpu_idle=110, rx=1400, memory_available=300)
                second = sampler.sample()
            self.assertEqual(first["serverName"], "heonhwi-homeserver")
            self.assertEqual(first["cpu"]["modelName"], "Intel Core i7-2600")
            self.assertEqual(first["cpu"]["physicalCores"], 1)
            self.assertFalse(first["cpu"]["avx2"])
            self.assertEqual(len(first["cpu"]["cores"]), 2)
            self.assertEqual(first["network"]["receivedBytesPerSecond"], 0)
            self.assertEqual(second["cpu"]["percent"], 50)
            self.assertEqual(second["network"]["receivedBytesPerSecond"], 200)
            self.assertEqual(second["memory"]["usedBytes"], 716800)
            self.assertEqual(second["swap"]["usedBytes"], 204800)
            self.assertEqual(len(second["history"]), 2)

    def test_sampler_keeps_metrics_when_cpuinfo_is_unavailable(self):
        with tempfile.TemporaryDirectory() as directory:
            host_dir = Path(directory)
            write_snapshot(host_dir, cpu_user=100, cpu_idle=100, rx=1000, memory_available=400)
            (host_dir / "cpuinfo").unlink()

            cpu = MetricsSampler(host_dir).sample()["cpu"]

        self.assertIsNone(cpu["modelName"])
        self.assertIsNone(cpu["physicalCores"])
        self.assertIsNone(cpu["avx2"])

    def test_sampler_reports_host_os_and_kernel(self):
        with tempfile.TemporaryDirectory() as directory:
            host_dir = Path(directory)
            write_snapshot(host_dir, cpu_user=100, cpu_idle=100, rx=1000, memory_available=400)
            (host_dir / "os-release").write_text('NAME=Ubuntu\nPRETTY_NAME="Ubuntu 26.04.1 LTS"\n')

            snapshot = MetricsSampler(host_dir).sample()

        self.assertEqual(snapshot["osName"], "Ubuntu 26.04.1 LTS")
        self.assertTrue(snapshot["kernelVersion"])

    def test_sampler_reads_only_bounded_read_only_hwmon_temperatures(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            host_dir = root / "host"
            host_dir.mkdir()
            write_snapshot(host_dir, cpu_user=100, cpu_idle=100, rx=1000, memory_available=400)
            hwmon_dir = root / "sys/class/hwmon"
            cpu = hwmon_dir / "hwmon0"
            gpu = hwmon_dir / "hwmon1"
            devices = root / "sys/devices"
            cpu_device = devices / "platform/coretemp.0/hwmon/hwmon0"
            gpu_device = devices / "pci0000:00/0000:00:02.0/hwmon/hwmon1"
            cpu_device.mkdir(parents=True)
            gpu_device.mkdir(parents=True)
            hwmon_dir.mkdir(parents=True)
            cpu.symlink_to("../../devices/platform/coretemp.0/hwmon/hwmon0")
            gpu.symlink_to("../../devices/pci0000:00/0000:00:02.0/hwmon/hwmon1")
            (cpu_device / "name").write_text("coretemp\n")
            (cpu_device / "temp1_input").write_text("42000\n")
            (cpu_device / "temp2_input").write_text("98000\n")
            (cpu_device / "temp3_input").write_text("bad\n")
            (gpu_device / "name").write_text("nvidia\n")
            (gpu_device / "temp1_input").write_text("56000\n")
            (gpu_device / "temp2_input").write_text("200000\n")

            sensors = MetricsSampler(host_dir, hwmon_dir=hwmon_dir).sample()["sensors"]

        self.assertEqual(sensors["cpuTemperaturesCelsius"], [42.0, 98.0])
        self.assertEqual(sensors["gpuName"], "NVIDIA")
        self.assertEqual(sensors["gpuTemperatureCelsius"], 56.0)

    def test_sampler_reports_unavailable_when_hwmon_is_missing(self):
        with tempfile.TemporaryDirectory() as directory:
            host_dir = Path(directory)
            write_snapshot(host_dir, cpu_user=100, cpu_idle=100, rx=1000, memory_available=400)

            sensors = MetricsSampler(host_dir, hwmon_dir=host_dir / "missing").sample()["sensors"]

        self.assertEqual(sensors, {
            "cpuTemperaturesCelsius": [],
            "gpuName": None,
            "gpuTemperatureCelsius": None,
        })

    def test_sampler_reports_only_explicit_storage_mounts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ssd = root / "ssd disk" / "probe file"
            ssd.parent.mkdir()
            ssd.touch()
            mountinfo = root / "mountinfo"
            escaped_mount = str(ssd).replace(" ", "\\040")
            mountinfo.write_text(
                f"36 25 8:1 / {escaped_mount} ro,relatime - ext4 /dev/sda2 rw\n"
            )
            sampler = MetricsSampler(
                storage_volumes=(
                    ("System SSD", "/mnt/ssd", ssd),
                    ("Data HDD", "/mnt/hdd", root / "unmounted"),
                ),
                mountinfo_path=mountinfo,
            )

            storage = sampler._storage()

        self.assertEqual(len(storage), 1)
        self.assertEqual(storage[0]["name"], "System SSD")
        self.assertEqual(storage[0]["device"], "/dev/sda2")
        self.assertEqual(storage[0]["mount"], "/mnt/ssd")
        self.assertEqual(storage[0]["fileSystem"], "ext4")
        self.assertGreater(storage[0]["totalBytes"], 0)
        self.assertGreaterEqual(storage[0]["percent"], 0)
        self.assertLessEqual(storage[0]["percent"], 100)
        self.assertEqual(storage[0]["health"], "not_reported")

    def test_metrics_require_bearer_and_agent_is_read_only(self):
        token = "a" * 64
        server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(token, MetricsSampler()))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        url = f"http://127.0.0.1:{server.server_port}"
        try:
            with self.assertRaises(HTTPError) as unauthorized:
                urlopen(f"{url}/v1/metrics")
            self.assertEqual(unauthorized.exception.code, 401)
            unauthorized.exception.close()
            request = Request(f"{url}/v1/metrics", headers={"Authorization": f"Bearer {token}"})
            with self.assertRaises(HTTPError) as unavailable:
                urlopen(request)
            self.assertEqual(unavailable.exception.code, 503)
            unavailable.exception.close()
            post = Request(f"{url}/v1/metrics", data=b"{}", method="POST")
            with self.assertRaises(HTTPError) as read_only:
                urlopen(post)
            self.assertEqual(read_only.exception.code, 405)
            read_only.exception.close()
            with urlopen(f"{url}/healthz") as response:
                health = json.load(response)
            self.assertEqual(health, {"status": "ok"})
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
