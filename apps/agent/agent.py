import hmac
import json
import os
import re
import time
from collections import deque
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Lock


class MetricsSampler:
    def __init__(
        self,
        host_dir: Path = Path("/host"),
        storage_volumes: tuple[tuple[str, str, Path], ...] = (),
        mountinfo_path: Path = Path("/proc/self/mountinfo"),
        hwmon_dir: Path = Path("/host/sys/class/hwmon"),
    ):
        self.host_dir = host_dir
        self.storage_volumes = storage_volumes
        self.mountinfo_path = mountinfo_path
        self.hwmon_dir = hwmon_dir
        self.previous = None
        self.history = deque(maxlen=12)
        self.lock = Lock()

    def _cpu(self):
        result = []
        for line in (self.host_dir / "stat").read_text().splitlines():
            fields = line.split()
            if not fields or not (fields[0] == "cpu" or re.fullmatch(r"cpu\d+", fields[0])):
                continue
            values = [int(value) for value in fields[1:]]
            result.append((sum(values), values[3] + (values[4] if len(values) > 4 else 0)))
        if not result:
            raise ValueError("CPU counters are unavailable")
        return result

    def _network(self):
        received = sent = 0
        for line in (self.host_dir / "net-dev").read_text().splitlines():
            if ":" not in line:
                continue
            interface, values = line.split(":", 1)
            counters = values.split()
            if interface.strip() == "lo" or len(counters) < 9:
                continue
            received += int(counters[0])
            sent += int(counters[8])
        return received, sent

    def _cpu_identity(self):
        try:
            content = (self.host_dir / "cpuinfo").read_text()
        except OSError:
            return None, None, None
        records = []
        for block in content.split("\n\n"):
            record = {}
            for line in block.splitlines():
                if ":" in line:
                    key, value = line.split(":", 1)
                    record[key.strip().lower()] = value.strip()
            if record:
                records.append(record)
        model = next(
            (
                record.get("model name") or record.get("hardware")
                for record in records
                if record.get("model name") or record.get("hardware")
            ),
            None,
        )
        physical = {
            (record["physical id"], record["core id"])
            for record in records
            if record.get("physical id") is not None and record.get("core id") is not None
        }
        counts = [
            int(record["cpu cores"])
            for record in records
            if record.get("cpu cores", "").isdigit()
        ]
        physical_cores = len(physical) if physical else max(counts, default=None)
        flags = next((record["flags"] for record in records if "flags" in record), None)
        has_avx2 = "avx2" in flags.split() if flags is not None else None
        return model[:256] if model else None, physical_cores, has_avx2

    def _os_name(self):
        try:
            for line in (self.host_dir / "os-release").read_text().splitlines():
                if line.startswith("PRETTY_NAME="):
                    value = line.partition("=")[2].strip().strip('"')
                    return value[:128] or None
        except OSError:
            pass
        return None

    def _sensors(self):
        cpu = []
        gpu = []
        gpu_name = None
        try:
            devices = sorted(self.hwmon_dir.iterdir())
        except OSError:
            devices = []
        for device in devices:
            if not re.fullmatch(r"hwmon\d+", device.name):
                continue
            try:
                name = (device / "name").read_text().strip().lower()
            except OSError:
                continue
            if name not in {"coretemp", "k10temp", "zenpower", "nvidia", "nouveau", "amdgpu", "i915"}:
                continue
            readings = []
            try:
                inputs = sorted(device.glob("temp*_input"))
            except OSError:
                continue
            for path in inputs:
                if not re.fullmatch(r"temp\d+_input", path.name):
                    continue
                try:
                    value = int(path.read_text().strip()) / 1000
                except (OSError, ValueError):
                    continue
                if -40 <= value <= 150:
                    readings.append(round(value, 1))
            if name in {"coretemp", "k10temp", "zenpower"}:
                cpu.extend(readings)
            elif readings:
                gpu.extend(readings)
                gpu_name = {
                    "nvidia": "NVIDIA",
                    "nouveau": "NVIDIA · nouveau",
                    "amdgpu": "AMD GPU",
                    "i915": "Intel GPU",
                }[name]
        return {
            "cpuTemperaturesCelsius": sorted(cpu)[:64],
            "gpuName": gpu_name,
            "gpuTemperatureCelsius": max(gpu) if gpu else None,
        }

    def _storage(self):
        if not self.storage_volumes:
            return []
        try:
            lines = self.mountinfo_path.read_text().splitlines()
        except OSError:
            return []
        mounts = {}
        for line in lines:
            before, separator, after = line.partition(" - ")
            fields = before.split()
            filesystem = after.split()
            if not separator or len(fields) < 5 or len(filesystem) < 2:
                continue
            mount = re.sub(
                r"\\([0-7]{3})", lambda match: chr(int(match.group(1), 8)), fields[4]
            )
            mounts[mount] = (filesystem[0], filesystem[1])

        storage = []
        for name, host_mount, path in self.storage_volumes:
            filesystem = mounts.get(str(path))
            if not filesystem:
                continue
            try:
                stats = os.statvfs(path)
            except OSError:
                continue
            total = stats.f_blocks * stats.f_frsize
            if total <= 0:
                continue
            available = max(0, stats.f_bavail) * stats.f_frsize
            used = max(0, total - available)
            storage.append(
                {
                    "name": name,
                    "device": filesystem[1],
                    "mount": host_mount,
                    "fileSystem": filesystem[0],
                    "usedBytes": used,
                    "totalBytes": total,
                    "percent": round(min(100.0, used / total * 100), 1),
                    "health": "not_reported",
                }
            )
        return storage

    def sample(self):
        with self.lock:
            return self._sample()

    def _sample(self):
        now = time.monotonic()
        cpu = self._cpu()
        network = self._network()
        cores = cpu[1:] or cpu[:1]
        if self.previous:
            then, old_cpu, old_cores, old_network = self.previous
            elapsed = max(now - then, 0.001)
            cpu_percent = self._percent(old_cpu, cpu[0])
            core_percent = [
                self._percent(old_cores[index], current) if index < len(old_cores) else 0.0
                for index, current in enumerate(cores)
            ]
            received_rate = max(0, network[0] - old_network[0]) / elapsed
            sent_rate = max(0, network[1] - old_network[1]) / elapsed
        else:
            cpu_percent = 0.0
            core_percent = [0.0] * len(cores)
            received_rate = sent_rate = 0.0
        self.previous = (now, cpu[0], cores, network)

        memory = {}
        for line in (self.host_dir / "meminfo").read_text().splitlines():
            key, value = line.split(":", 1)
            memory[key] = int(value.split()[0]) * 1024
        total = memory["MemTotal"]
        available = memory.get("MemAvailable", memory.get("MemFree", 0))
        swap_total = memory.get("SwapTotal", 0)
        swap_free = memory.get("SwapFree", 0)
        load = [float(value) for value in (self.host_dir / "loadavg").read_text().split()[:3]]
        uptime = float((self.host_dir / "uptime").read_text().split()[0])
        hostname = (self.host_dir / "hostname").read_text().strip()
        model_name, physical_cores, has_avx2 = self._cpu_identity()
        sensors = self._sensors()
        used = max(0, total - available)
        swap_used = max(0, swap_total - swap_free)
        memory_percent = max(0.0, min(100.0, used / total * 100)) if total else 0.0
        swap_percent = max(0.0, min(100.0, swap_used / swap_total * 100)) if swap_total else 0.0
        cpu_percent = round(cpu_percent, 1)
        memory_percent = round(memory_percent, 1)
        self.history.append(
            {
                "time": datetime.now(UTC).strftime("%H:%M:%S"),
                "cpu": cpu_percent,
                "memory": memory_percent,
            }
        )
        return {
            "serverName": hostname or "Linux host",
            "osName": self._os_name(),
            "kernelVersion": os.uname().release[:128],
            "updatedAt": datetime.now(UTC).isoformat(),
            "uptimeSeconds": uptime,
            "cpu": {
                "percent": cpu_percent,
                "cores": [round(value, 1) for value in core_percent],
                "loadAverage": load,
                "modelName": model_name,
                "physicalCores": physical_cores,
                "avx2": has_avx2,
            },
            "sensors": sensors,
            "memory": {"usedBytes": used, "totalBytes": total, "percent": memory_percent},
            "swap": {
                "usedBytes": swap_used,
                "totalBytes": swap_total,
                "percent": round(swap_percent, 1),
            },
            "network": {
                "receivedBytesPerSecond": round(received_rate, 1),
                "sentBytesPerSecond": round(sent_rate, 1),
            },
            "storage": self._storage(),
            "history": list(self.history),
        }

    @staticmethod
    def _percent(previous, current):
        total_delta = current[0] - previous[0]
        idle_delta = current[1] - previous[1]
        if total_delta <= 0:
            return 0.0
        return max(0.0, min(100.0, (total_delta - idle_delta) / total_delta * 100))


def make_handler(token, sampler):
    class Handler(BaseHTTPRequestHandler):
        def _json(self, code, value):
            body = json.dumps(value, separators=(",", ":")).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path == "/healthz":
                self._json(200, {"status": "ok"})
                return
            if self.path != "/v1/metrics":
                self._json(404, {"detail": "Not found"})
                return
            authorization = self.headers.get("Authorization", "")
            scheme, separator, presented = authorization.partition(" ")
            if (
                scheme != "Bearer"
                or not separator
                or len(presented) > 128
                or not hmac.compare_digest(presented.encode(), token.encode())
            ):
                self._json(401, {"detail": "Unauthorized"})
                return
            try:
                self._json(200, sampler.sample())
            except OSError, KeyError, ValueError:
                self._json(503, {"detail": "Host metrics unavailable"})

        def do_POST(self):
            self._json(405, {"detail": "Read-only agent"})

        do_PUT = do_POST
        do_PATCH = do_POST
        do_DELETE = do_POST

        def log_message(self, *_):
            return

    return Handler


def main():
    token = os.environ.get("AGENT_TOKEN", "")
    if not re.fullmatch(r"[0-9a-f]{64}", token):
        raise SystemExit("AGENT_TOKEN must be 32 random bytes encoded as lowercase hex")
    storage_volumes = tuple(
        (name, os.environ.get(mount_variable, ""), Path(target))
        for name, probe_variable, mount_variable, target in (
            (
                "System SSD",
                "HOST_SSD_PROBE_PATH",
                "HOST_SSD_MOUNT_LABEL",
                "/host/storage/ssd-probe",
            ),
            (
                "Data HDD",
                "HOST_HDD_PROBE_PATH",
                "HOST_HDD_MOUNT_LABEL",
                "/host/storage/hdd-probe",
            ),
        )
        if os.environ.get(probe_variable) and os.environ.get(mount_variable)
    )
    sampler = MetricsSampler(storage_volumes=storage_volumes)
    server = ThreadingHTTPServer(("0.0.0.0", 9000), make_handler(token, sampler))
    server.daemon_threads = True
    server.serve_forever()


if __name__ == "__main__":
    main()
