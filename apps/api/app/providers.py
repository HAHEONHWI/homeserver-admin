import json
import math
import re
from datetime import UTC, datetime, timedelta
from http.client import HTTPException
from random import Random
from time import monotonic
from typing import Literal
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

import psycopg
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from redis import Redis
from redis.exceptions import RedisError

from app.dns_actions import dns_writes_enabled, normalize_dns_record
from app.schemas import DnsRecordChange, DnsRecordValue, HostSnapshot
from app.settings import Settings


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_AGENT_OPENER = build_opener(ProxyHandler({}), _NoRedirect())
_HEALTH_OPENER = build_opener(ProxyHandler({}), _NoRedirect())


def _read_limited(response, limit: int, timeout: float) -> bytes:
    # shortcut: CPython urllib internals bound body only; replace for end-to-end deadlines or runtime change.
    try:
        sock = response.fp.raw._sock
    except AttributeError:
        return response.read(limit + 1)
    if sock is None or getattr(sock, "_closed", False):
        return response.read(limit + 1)
    deadline = monotonic() + timeout
    body = bytearray()
    while len(body) <= limit:
        remaining = deadline - monotonic()
        if remaining <= 0:
            raise TimeoutError("Provider response exceeded its read deadline")
        try:
            sock.settimeout(remaining)
        except OSError:
            if not getattr(sock, "_closed", False):
                raise
            body.extend(response.read(limit + 1 - len(body)))
            break
        chunk = response.read1(min(65_536, limit + 1 - len(body)))
        if not chunk:
            break
        body.extend(chunk)
    return bytes(body)


class PortainerPort(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)

    PrivatePort: int = Field(ge=1, le=65535)
    PublicPort: int | None = Field(default=None, ge=1, le=65535)
    Type: Literal["tcp", "udp", "sctp"] = "tcp"


class PortainerHealth(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)

    Status: Literal["none", "starting", "healthy", "unhealthy"]


class PortainerImage(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)

    Id: str = Field(min_length=71, max_length=71, pattern=r"^sha256:[0-9a-fA-F]{64}$")
    RepoTags: list[str] | None = Field(default=None, max_length=64)
    Created: int = Field(ge=0, le=4_102_444_800)
    Size: int = Field(ge=0, le=1_000_000_000_000_000_000)


class PortainerStack(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)

    Id: int = Field(ge=1)
    Name: str = Field(min_length=1, max_length=128)
    Type: int = Field(ge=1, le=3)
    EndpointId: int | None = Field(default=0, ge=0)
    Status: int = Field(ge=1, le=2)
    EntryPoint: str | None = Field(default=None, max_length=512)
    CreationDate: int = Field(default=0, ge=0, le=4_102_444_800)
    UpdateDate: int = Field(default=0, ge=0, le=4_102_444_800)


class MailcowDomain(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)

    domain: str = Field(min_length=1, max_length=253)
    active: bool | int | str
    quota: int | str | None = None


class MailcowMailbox(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)

    username: str = Field(min_length=3, max_length=320)
    domain: str | None = Field(default=None, max_length=253)
    name: str | None = Field(default=None, max_length=256)
    active: bool | int | str
    quota: int | str | None = None
    quota_used: int | str | None = None
    percent_in_use: int | float | str | None = None


class MailcowAlias(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)

    address: str = Field(min_length=3, max_length=320)
    goto: str | None = Field(default=None, max_length=2048)
    active: bool | int | str


class PortainerContainer(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)

    Id: str = Field(min_length=12, max_length=64, pattern=r"^[0-9a-fA-F]+$")
    Names: list[str] = Field(min_length=1, max_length=8)
    Image: str = Field(min_length=1, max_length=512)
    State: str = Field(min_length=1, max_length=64)
    Status: str = Field(min_length=1, max_length=256)
    Created: int = Field(ge=0)
    Ports: list[PortainerPort] = Field(default_factory=list, max_length=128)
    Health: PortainerHealth | None = None


class PortainerCpuUsage(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)

    total_usage: int | None = Field(default=None, ge=0)
    percpu_usage: list[int] | None = Field(default=None, max_length=1024)


class PortainerCpuStats(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)

    cpu_usage: PortainerCpuUsage
    system_cpu_usage: int | None = Field(default=None, ge=0)
    online_cpus: int | None = Field(default=None, ge=1, le=4096)


class PortainerMemoryStats(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)

    usage: int = Field(ge=0)
    limit: int = Field(ge=0)
    stats: dict[str, int] | None = Field(default=None, max_length=64)


class PortainerContainerStats(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)

    cpu_stats: PortainerCpuStats
    precpu_stats: PortainerCpuStats
    memory_stats: PortainerMemoryStats


class GitHubWorkflowRun(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)

    id: int = Field(ge=0)
    name: str | None = Field(default=None, max_length=256)
    display_title: str = Field(max_length=256)
    head_branch: str | None = Field(default=None, max_length=256)
    head_sha: str = Field(min_length=40, max_length=64, pattern=r"^[0-9a-fA-F]+$")
    run_number: int = Field(ge=1)
    status: str = Field(min_length=1, max_length=64)
    conclusion: str | None = Field(default=None, max_length=64)
    updated_at: datetime


class GitHubWorkflowRunsResponse(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)

    workflow_runs: list[GitHubWorkflowRun] = Field(max_length=5)


class N8nExecution(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)

    id: str = Field(min_length=1, max_length=128)
    workflowId: str = Field(min_length=1, max_length=128)
    status: str | None = Field(default=None, max_length=32)
    finished: bool | None = None
    startedAt: datetime | None = None
    stoppedAt: datetime | None = None


class N8nExecutionsResponse(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)

    data: list[N8nExecution] = Field(max_length=5)


class NetdataAlertInstance(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)

    name: str = Field(alias="nm", min_length=1, max_length=128)
    context: str | None = Field(default=None, alias="ctx", max_length=128)
    status: Literal["CRITICAL", "WARNING"] = Field(alias="st")
    value: float | int | str | None = Field(default=None, alias="v")
    units: str | None = Field(default=None, max_length=64)
    last_evaluated_at: float | int | None = Field(
        default=None, alias="t", ge=0, le=4_102_444_800
    )


class NetdataAlertsResponse(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)

    alert_instances: list[NetdataAlertInstance] = Field(max_length=100)


class ScrutinyDevice(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)

    device_name: str = Field(default="", max_length=256)
    device_label: str = Field(default="", max_length=256)
    label: str = Field(default="", max_length=256)
    manufacturer: str = Field(default="", max_length=128)
    model_name: str = Field(default="", max_length=128)
    capacity: int = Field(default=0, ge=0, le=10_000_000_000_000_000)
    device_status: int = Field(ge=0, le=3)
    smart_support: bool = False


class ScrutinySmartSummary(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)

    collector_date: datetime | None = None
    temp: int | None = Field(default=None, ge=-100, le=300)
    power_on_hours: int | None = Field(default=None, ge=0, le=10_000_000)


class ScrutinyDeviceSummary(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)

    device: ScrutinyDevice
    smart: ScrutinySmartSummary | None = None


class ScrutinyData(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)

    summary: dict[str, ScrutinyDeviceSummary] = Field(max_length=100)


class ScrutinySummaryResponse(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)

    success: bool
    data: ScrutinyData


class CloudflareDnsRecord(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)

    id: str = Field(min_length=32, max_length=32, pattern=r"^[0-9a-fA-F]{32}$")
    name: str = Field(min_length=1, max_length=255)
    type: str = Field(min_length=1, max_length=16)
    content: str = Field(max_length=8192)
    ttl: int = Field(ge=1, le=86_400)
    proxied: bool = False
    proxiable: bool = False
    priority: int | None = Field(default=None, ge=0, le=65_535)
    modified_on: datetime | None = None


class CloudflareDnsResultInfo(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)

    total_count: int | None = Field(default=None, ge=0)


class CloudflareDnsResponse(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)

    success: bool
    result: list[CloudflareDnsRecord] = Field(max_length=100)
    result_info: CloudflareDnsResultInfo | None = None


class CloudflareDnsRecordResponse(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)

    success: bool
    result: CloudflareDnsRecord


class CloudflareDnsDeleteResponse(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)

    success: bool
    result: dict[str, str]


def iso_now(offset: int = 0) -> str:
    return (datetime.now(UTC) - timedelta(seconds=offset)).isoformat()


def _health_status(url: str, path: str) -> int | None:
    request = Request(
        f"{url.rstrip('/')}{path}",
        headers={"Accept": "application/json, text/plain"},
    )
    try:
        with _HEALTH_OPENER.open(request, timeout=2) as response:
            return response.status
    except HTTPError as error:
        status = error.code
        error.close()
        return status
    except (HTTPException, OSError, TimeoutError, ValueError):
        return None


def n8n_executions(settings: Settings) -> list[N8nExecution] | None:
    token = settings.n8n_api_key.get_secret_value()
    if not settings.n8n_url or not token:
        return None
    url = f"{settings.n8n_url.rstrip('/')}/api/v1/executions?{urlencode({'limit': 5})}"
    request = Request(
        url,
        headers={"Accept": "application/json", "X-N8N-API-KEY": token},
    )
    try:
        with _HEALTH_OPENER.open(request, timeout=2) as response:
            if response.status != 200:
                return None
            body = _read_limited(response, 262_144, 2)
        if len(body) > 262_144:
            return None
        return N8nExecutionsResponse.model_validate_json(body).data
    except HTTPException, OSError, TimeoutError, ValueError, ValidationError:
        return None


def netdata_alerts(settings: Settings) -> list[NetdataAlertInstance] | None:
    if not settings.netdata_url:
        return None
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    token = settings.netdata_api_token.get_secret_value()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = Request(
        f"{settings.netdata_url.rstrip('/')}/api/v3/alerts",
        data=json.dumps(
            {
                "status": ["CRITICAL", "WARNING"],
                "options": ["values", "instances"],
                "cardinality": 100,
            },
            separators=(",", ":"),
        ).encode(),
        headers=headers,
        method="POST",
    )
    try:
        with _HEALTH_OPENER.open(request, timeout=2) as response:
            if response.status != 200:
                return None
            body = _read_limited(response, 262_144, 2)
        if len(body) > 262_144:
            return None
        return NetdataAlertsResponse.model_validate_json(body).alert_instances
    except HTTPException, OSError, TimeoutError, ValueError, ValidationError:
        return None


def scrutiny_devices(settings: Settings) -> list[ScrutinyDeviceSummary] | None:
    if not settings.scrutiny_url:
        return None
    request = Request(
        f"{settings.scrutiny_url.rstrip('/')}/api/summary",
        headers={"Accept": "application/json"},
    )
    try:
        with _HEALTH_OPENER.open(request, timeout=2) as response:
            if response.status != 200:
                return None
            body = _read_limited(response, 262_144, 2)
        if len(body) > 262_144:
            return None
        result = ScrutinySummaryResponse.model_validate_json(body)
        return list(result.data.summary.values()) if result.success else None
    except HTTPException, OSError, TimeoutError, ValueError, ValidationError:
        return None


def _scrutiny_row(device: ScrutinyDeviceSummary, index: int, updated: str, prefix: str) -> dict:
    details = []
    if device.device.manufacturer or device.device.model_name:
        details.append(" ".join(filter(None, (device.device.manufacturer, device.device.model_name))))
    if device.device.capacity:
        details.append(f"{device.device.capacity / 1_000_000_000:.1f} GB")
    smart = device.smart
    if smart:
        if smart.temp is not None:
            details.append(f"{smart.temp}°C")
        if smart.power_on_hours is not None:
            details.append(f"{smart.power_on_hours}시간")
    failures = []
    if device.device.device_status & 1:
        failures.append("S.M.A.R.T 검사 실패")
    if device.device.device_status & 2:
        failures.append("Scrutiny 검사 실패")
    status = "오류" if failures else "미지원" if not device.device.smart_support else "정상"
    if failures:
        details.append(" · ".join(failures))
    elif not device.device.smart_support:
        details.append("S.M.A.R.T 미지원")
    if smart and smart.collector_date:
        updated = smart.collector_date.isoformat()
    return {
        "id": f"scrutiny:{index}",
        "name": prefix + (device.device.label or device.device.device_label or device.device.device_name or device.device.model_name or f"장치 {index + 1}"),
        "status": status,
        "detail": " · ".join(details) or "S.M.A.R.T 상세 정보 없음",
        "updatedAt": updated,
    }


def host_snapshot(settings: Settings) -> HostSnapshot | None:
    if not settings.host_agent_url:
        return None
    request = Request(
        settings.host_agent_url,
        headers={"Authorization": f"Bearer {settings.host_agent_token.get_secret_value()}"},
    )
    try:
        with _AGENT_OPENER.open(request, timeout=2) as response:
            if response.status != 200:
                return None
            body = _read_limited(response, 65_536, 2)
        if len(body) > 65_536:
            return None
        return HostSnapshot.model_validate_json(body)
    except HTTPException, OSError, TimeoutError, ValueError, ValidationError:
        return None


def portainer_containers(settings: Settings) -> list[PortainerContainer] | None:
    if not settings.portainer_url:
        return None
    url = (
        f"{settings.portainer_url.rstrip('/')}/api/endpoints/"
        f"{settings.portainer_endpoint_id}/docker/containers/json?all=1"
    )
    request = Request(
        url,
        headers={
            "Accept": "application/json",
            "X-API-Key": settings.portainer_api_key.get_secret_value(),
        },
    )
    try:
        with _AGENT_OPENER.open(request, timeout=3) as response:
            if response.status != 200:
                return None
            body = _read_limited(response, 1_048_576, 3)
        if len(body) > 1_048_576:
            return None
        payload = json.loads(body)
        if not isinstance(payload, list) or len(payload) > 1000:
            return None
        return [PortainerContainer.model_validate(item) for item in payload]
    except HTTPException, OSError, TimeoutError, ValueError, ValidationError:
        return None


def portainer_container_action(
    settings: Settings, container_id: str, operation: Literal["start", "stop", "restart"]
) -> bool | None:
    token = settings.portainer_actions_api_key.get_secret_value()
    if (
        not settings.portainer_url
        or not token
        or not re.fullmatch(r"[0-9a-fA-F]{12,64}", container_id)
        or operation not in {"start", "stop", "restart"}
    ):
        return False
    timeout = "?t=10" if operation in {"stop", "restart"} else ""
    try:
        request = Request(
            f"{settings.portainer_url.rstrip('/')}/api/endpoints/{settings.portainer_endpoint_id}"
            f"/docker/containers/{container_id}/{operation}{timeout}",
            headers={"Accept": "application/json", "X-API-Key": token},
            method="POST",
        )
        with _AGENT_OPENER.open(request, timeout=12) as response:
            return response.status == 204
    except HTTPError as error:
        return None if error.code >= 500 else False
    except (OSError, TimeoutError, ValueError):
        return None


def portainer_container_stats(settings: Settings, container_id: str) -> dict | None:
    if not settings.portainer_url or not re.fullmatch(r"[0-9a-fA-F]{12,64}", container_id):
        return None
    request = Request(
        f"{settings.portainer_url.rstrip('/')}/api/endpoints/{settings.portainer_endpoint_id}"
        f"/docker/containers/{container_id}/stats?stream=false",
        headers={
            "Accept": "application/json",
            "X-API-Key": settings.portainer_api_key.get_secret_value(),
        },
    )
    try:
        with _AGENT_OPENER.open(request, timeout=3) as response:
            if response.status != 200:
                return None
            body = _read_limited(response, 262_144, 3)
        if len(body) > 262_144:
            return None
        stats = PortainerContainerStats.model_validate_json(body)
        cpu_now = stats.cpu_stats.cpu_usage.total_usage
        cpu_before = stats.precpu_stats.cpu_usage.total_usage
        system_now = stats.cpu_stats.system_cpu_usage
        system_before = stats.precpu_stats.system_cpu_usage
        cpu_count = stats.cpu_stats.online_cpus or len(stats.cpu_stats.cpu_usage.percpu_usage or [])
        cpu_percent = (
            max(0.0, (cpu_now - cpu_before) / (system_now - system_before) * cpu_count * 100)
            if cpu_now is not None and cpu_before is not None
            and system_now is not None and system_before is not None
            and cpu_now >= cpu_before and system_now > system_before and cpu_count > 0
            else 0.0
        )
        memory = stats.memory_stats
        cache = (memory.stats or {}).get("inactive_file", (memory.stats or {}).get("cache", 0))
        used = max(0, memory.usage - cache)
        return {
            "cpuPercent": round(cpu_percent, 1),
            "memoryUsedBytes": used,
            "memoryLimitBytes": memory.limit,
            "memoryPercent": round(min(100.0, used / memory.limit * 100), 1) if memory.limit else 0.0,
        }
    except HTTPException, OSError, TimeoutError, ValueError, ValidationError:
        return None


def portainer_images(settings: Settings) -> list[PortainerImage] | None:
    if not settings.portainer_url:
        return None
    url = (
        f"{settings.portainer_url.rstrip('/')}/api/endpoints/"
        f"{settings.portainer_endpoint_id}/docker/images/json?all=1"
    )
    request = Request(
        url,
        headers={
            "Accept": "application/json",
            "X-API-Key": settings.portainer_api_key.get_secret_value(),
        },
    )
    try:
        with _AGENT_OPENER.open(request, timeout=3) as response:
            if response.status != 200:
                return None
            body = _read_limited(response, 1_048_576, 3)
        if len(body) > 1_048_576:
            return None
        payload = json.loads(body)
        if not isinstance(payload, list) or len(payload) > 1000:
            return None
        return [PortainerImage.model_validate(item) for item in payload]
    except HTTPException, OSError, TimeoutError, ValueError, ValidationError:
        return None


def portainer_stacks(settings: Settings) -> list[PortainerStack] | None:
    if not settings.portainer_url:
        return None
    filters = urlencode(
        {"filters": json.dumps({"EndpointID": settings.portainer_endpoint_id}, separators=(",", ":"))}
    )
    request = Request(
        f"{settings.portainer_url.rstrip('/')}/api/stacks?{filters}",
        headers={
            "Accept": "application/json",
            "X-API-Key": settings.portainer_api_key.get_secret_value(),
        },
    )
    try:
        with _AGENT_OPENER.open(request, timeout=3) as response:
            if response.status != 200:
                return None
            body = _read_limited(response, 1_048_576, 3)
        if len(body) > 1_048_576:
            return None
        payload = json.loads(body)
        if not isinstance(payload, list) or len(payload) > 1000:
            return None
        stacks = [PortainerStack.model_validate(item) for item in payload]
        return [
            stack
            for stack in stacks
            if stack.EndpointId == settings.portainer_endpoint_id and stack.Type in {1, 2}
        ]
    except HTTPException, OSError, TimeoutError, ValueError, ValidationError:
        return None


def mailcow_list(settings: Settings, category: str) -> list[dict] | None:
    request = Request(
        f"{settings.mailcow_url.rstrip('/')}/api/v1/get/{category}/all",
        headers={
            "Accept": "application/json",
            "X-API-Key": settings.mailcow_api_key.get_secret_value(),
        },
    )
    try:
        with _AGENT_OPENER.open(request, timeout=3) as response:
            if response.status != 200:
                return None
            body = _read_limited(response, 4_194_304, 3)
        if len(body) > 4_194_304:
            return None
        payload = json.loads(body)
        if payload == {}:
            return []
        if not isinstance(payload, list) or len(payload) > 1000:
            return None
        return payload if all(isinstance(item, dict) for item in payload) else None
    except HTTPException, OSError, TimeoutError, ValueError:
        return None


def mailcow_lists(
    settings: Settings,
) -> tuple[list[MailcowDomain], list[MailcowMailbox], list[MailcowAlias]] | None:
    domains = mailcow_list(settings, "domain")
    mailboxes = mailcow_list(settings, "mailbox")
    aliases = mailcow_list(settings, "alias")
    if domains is None or mailboxes is None or aliases is None:
        return None
    try:
        return (
            [MailcowDomain.model_validate(item) for item in domains],
            [MailcowMailbox.model_validate(item) for item in mailboxes],
            [MailcowAlias.model_validate(item) for item in aliases],
        )
    except ValidationError:
        return None


def github_workflow_runs(settings: Settings, repository: str) -> list[GitHubWorkflowRun] | None:
    if repository not in settings.github_repo_list or not settings.github_api_token.get_secret_value():
        return None
    owner, name = repository.split("/", 1)
    request = Request(
        f"https://api.github.com/repos/{owner}/{name}/actions/runs?per_page=5",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {settings.github_api_token.get_secret_value()}",
            "X-GitHub-Api-Version": "2026-03-10",
        },
    )
    try:
        with _AGENT_OPENER.open(request, timeout=3) as response:
            if response.status != 200:
                return None
            body = _read_limited(response, 1_048_576, 3)
        if len(body) > 1_048_576:
            return None
        return GitHubWorkflowRunsResponse.model_validate_json(body).workflow_runs
    except HTTPException, OSError, TimeoutError, ValueError, ValidationError:
        return None


def cloudflare_dns_records(
    settings: Settings,
) -> tuple[list[CloudflareDnsRecord], int] | None:
    token = settings.cloudflare_api_token.get_secret_value()
    zone_id = settings.cloudflare_zone_id.strip()
    if not token or not re.fullmatch(r"[0-9a-fA-F]{32}", zone_id):
        return None
    request = Request(
        f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records?per_page=100",
        headers={
            "Accept": "application/json",
            "Authorization": f"Bearer {token}",
        },
    )
    try:
        with _AGENT_OPENER.open(request, timeout=3) as response:
            if response.status != 200:
                return None
            body = _read_limited(response, 1_048_576, 3)
        if len(body) > 1_048_576:
            return None
        payload = CloudflareDnsResponse.model_validate_json(body)
        if not payload.success:
            return None
        total = payload.result_info.total_count if payload.result_info else None
        return payload.result, total if total is not None else len(payload.result)
    except HTTPException, OSError, TimeoutError, ValueError, ValidationError:
        return None


def cloudflare_dns_record(settings: Settings, record_id: str) -> CloudflareDnsRecord | None:
    token = settings.cloudflare_api_token.get_secret_value()
    zone_id = settings.cloudflare_zone_id.strip()
    if not token or not re.fullmatch(r"[0-9a-fA-F]{32}", zone_id) or not re.fullmatch(
        r"[0-9a-fA-F]{32}", record_id
    ):
        return None
    request = Request(
        f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{record_id}",
        headers={"Accept": "application/json", "Authorization": f"Bearer {token}"},
    )
    try:
        with _AGENT_OPENER.open(request, timeout=3) as response:
            if response.status != 200:
                return None
            body = _read_limited(response, 1_048_576, 3)
        if len(body) > 1_048_576:
            return None
        result = CloudflareDnsRecordResponse.model_validate_json(body)
        return result.result if result.success else None
    except HTTPException, HTTPError, OSError, TimeoutError, ValueError, ValidationError:
        return None


def cloudflare_dns_record_matches(
    settings: Settings, record_id: str, expected: DnsRecordValue
) -> bool | None:
    record = cloudflare_dns_record(settings, record_id)
    if record is None:
        return None
    try:
        actual = normalize_dns_record(DnsRecordValue(
            name=record.name.rstrip(".").lower(),
            type=record.type,
            content=record.content,
            ttl=record.ttl,
            proxied=record.proxied,
            priority=record.priority,
        ), settings.cloudflare_zone_name)
    except (ValueError, HTTPException):
        return False
    return actual == expected


def cloudflare_dns_mutation(
    settings: Settings, operation: str, change: DnsRecordChange
) -> tuple[bool | None, dict | None]:
    token = settings.cloudflare_dns_write_token.get_secret_value()
    zone_id = settings.cloudflare_zone_id.strip()
    if operation not in {"dns_create", "dns_update", "dns_delete"} or not token or not re.fullmatch(
        r"[0-9a-fA-F]{32}", zone_id
    ):
        return False, None
    record_id = change.recordId
    record = change.after
    if operation != "dns_delete" and record is None:
        return False, None
    if operation != "dns_create" and (
        not record_id or not re.fullmatch(r"[0-9a-fA-F]{32}", record_id)
    ):
        return False, None
    if operation != "dns_create":
        if change.before is None:
            return False, None
        current = cloudflare_dns_record_matches(settings, record_id, change.before)
        if current is None:
            return None, None
        if not current:
            return False, None
    path = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records"
    method = "POST"
    data = None
    if operation in {"dns_update", "dns_delete"}:
        path += f"/{record_id}"
        method = "PATCH" if operation == "dns_update" else "DELETE"
    if method != "DELETE" and record is not None:
        payload = {
            "name": record.name,
            "type": record.type,
            "content": record.content,
            "ttl": record.ttl,
        }
        if record.type in {"A", "AAAA", "CNAME"}:
            payload["proxied"] = record.proxied
        if record.type == "MX":
            payload["priority"] = record.priority
        data = json.dumps(payload, separators=(",", ":")).encode()
    request = Request(
        path,
        data=data,
        headers={
            "Accept": "application/json",
            "Authorization": f"Bearer {token}",
            **({"Content-Type": "application/json"} if data is not None else {}),
        },
        method=method,
    )
    try:
        with _AGENT_OPENER.open(request, timeout=8) as response:
            if response.status not in {200, 201}:
                return (None, None) if response.status >= 500 or response.status == 202 else (False, None)
            body = _read_limited(response, 1_048_576, 8)
        if len(body) > 1_048_576:
            return None, None
        if operation == "dns_delete":
            result = CloudflareDnsDeleteResponse.model_validate_json(body)
            return (True, {"id": result.result.get("id", record_id)}) if result.success else (False, None)
        result = CloudflareDnsRecordResponse.model_validate_json(body)
        if not result.success:
            return False, None
        return True, {
            "id": result.result.id,
            "name": result.result.name,
            "type": result.result.type,
            "content": result.result.content,
            "ttl": result.result.ttl,
            "proxied": result.result.proxied,
            "priority": result.result.priority,
        }
    except HTTPError as error:
        return (False, None) if error.code < 500 else (None, None)
    except (HTTPException, OSError, TimeoutError, ValueError, ValidationError):
        return None, None


def _decode_docker_log_frames(body: bytes) -> str | None:
    output = []
    offset = 0
    while offset < len(body):
        if (
            len(body) - offset < 8
            or body[offset] not in {1, 2}
            or body[offset + 1 : offset + 4] != b"\0\0\0"
        ):
            return None
        size = int.from_bytes(body[offset + 4 : offset + 8], "big")
        end = offset + 8 + size
        if end > len(body):
            return None
        output.append(body[offset + 8 : end].decode("utf-8", errors="replace"))
        offset = end
    return "".join(output)


def _decode_docker_logs(body: bytes, content_type: str) -> str | None:
    if content_type == "application/vnd.docker.raw-stream":
        return body.decode("utf-8", errors="replace")
    decoded = _decode_docker_log_frames(body)
    if content_type == "application/vnd.docker.multiplexed-stream":
        return decoded
    return decoded if decoded is not None else body.decode("utf-8", errors="replace")


def container_logs(settings: Settings, container_id: str, tail: int) -> str | None:
    if (
        not settings.portainer_url
        or not re.fullmatch(r"[0-9a-fA-F]{12,64}", container_id)
        or not 1 <= tail <= 500
    ):
        return None
    url = (
        f"{settings.portainer_url.rstrip('/')}/api/endpoints/{settings.portainer_endpoint_id}"
        f"/docker/containers/{container_id}/logs?stdout=1&stderr=1&timestamps=1&tail={tail}"
    )
    request = Request(
        url,
        headers={
            "Accept": "application/vnd.docker.multiplexed-stream",
            "X-API-Key": settings.portainer_api_key.get_secret_value(),
        },
    )
    try:
        with _AGENT_OPENER.open(request, timeout=3) as response:
            if response.status != 200:
                return None
            body = _read_limited(response, 1_048_576, 3)
            if len(body) > 1_048_576:
                return None
            content_type = response.headers.get("Content-Type", "").split(";", 1)[0].lower()
        return _decode_docker_logs(body, content_type)
    except HTTPException, OSError, TimeoutError, ValueError:
        return None


def _docker_metrics(settings: Settings, containers: list[PortainerContainer] | None) -> dict:
    if not settings.portainer_url:
        return {
            "status": "not_configured",
            "running": 0,
            "total": 0,
            "message": "Portainer API 미설정",
        }
    if containers is None:
        return {
            "status": "unavailable",
            "running": 0,
            "total": 0,
            "message": "Portainer API 응답 없음",
        }
    return {
        "status": "connected",
        "running": sum(container.State == "running" for container in containers),
        "total": len(containers),
        "message": (
            "Portainer 상태 조회 · 쓰기 작업은 제한된 컨테이너 제어 키와 Passkey 필요"
            if settings.portainer_actions_api_key.get_secret_value()
            else "Portainer 읽기 전용 연결"
        ),
    }


def _portainer_service(docker: dict, updated: str) -> dict:
    return {
        "name": "Portainer",
        "status": {
            "connected": "healthy",
            "unavailable": "failed",
            "not_configured": "not_configured",
        }[docker["status"]],
        "detail": docker["message"],
        "checkedAt": updated,
    }


def _container_service_rows(containers: list[PortainerContainer], updated: str) -> list[dict]:
    rows = []
    for container in sorted(containers, key=lambda item: item.Names[0].lower()):
        name = container.Names[0].lstrip("/")[:128] or container.Id[:12]
        health = container.Health.Status if container.Health else None
        if container.State == "running":
            state = {"healthy": "healthy", "unhealthy": "failed", "starting": "warning"}.get(
                health, "warning"
            )
            detail = (
                container.Status
                if health in {"healthy", "unhealthy", "starting"}
                else "실행 중 · Healthcheck 미설정"
                if health == "none"
                else "실행 중 · Healthcheck 미보고"
            )
        elif container.State in {"exited", "stopped"}:
            state = "stopped"
            detail = container.Status
        elif container.State == "dead":
            state = "failed"
            detail = container.Status
        else:
            state = "warning"
            detail = container.Status
        rows.append(
            {
                "id": container.Id,
                "name": f"Docker · {name}",
                "status": state,
                "detail": f"{container.Image[:256]} · {detail[:256]}",
                "updatedAt": updated,
            }
        )
    return rows


def _container_service_items(containers: list[PortainerContainer], updated: str) -> list[dict]:
    return [
        {
            "name": row["name"],
            "status": row["status"],
            "detail": row["detail"],
            "checkedAt": row["updatedAt"],
        }
        for row in _container_service_rows(containers, updated)
    ]


def _services_resource(settings: Settings, containers: list[PortainerContainer] | None) -> dict:
    updated = iso_now()
    if containers is None:
        return {
            "key": "services",
            "mode": "live",
            "status": "unavailable",
            "message": "Portainer 컨테이너 상태 응답 없음",
            "updatedAt": updated,
            "metrics": [],
            "columns": ["컨테이너", "상태", "이미지 · Docker 상태", "확인"],
            "rows": [],
            "actions": [],
        }
    rows = _container_service_rows(containers, updated)
    return {
        "key": "services",
        "mode": "live",
        "status": "connected",
        "message": "Portainer 컨테이너 상태 조회 · 명시적 Healthcheck 결과만 정상으로 표시",
        "updatedAt": updated,
        "metrics": [
            {"label": "Endpoint", "value": str(settings.portainer_endpoint_id), "detail": "Portainer"},
            {"label": "컨테이너", "value": str(len(rows)), "detail": "전체 상태"},
            {"label": "정상", "value": str(sum(row["status"] == "healthy" for row in rows)), "detail": "Healthcheck"},
            {"label": "확인 필요", "value": str(sum(row["status"] != "healthy" for row in rows)), "detail": "미설정 · 중지 · 이상"},
        ],
        "columns": ["컨테이너", "상태", "이미지 · Docker 상태", "확인"],
        "rows": rows,
        "actions": [],
    }


def _images_resource(settings: Settings, images: list[PortainerImage] | None) -> dict:
    updated = iso_now()
    if images is None:
        return {
            "key": "images",
            "mode": "live",
            "status": "unavailable",
            "message": "Portainer 이미지 목록 응답 없음",
            "updatedAt": updated,
            "metrics": [],
            "columns": ["이미지", "태그", "크기 · ID", "생성"],
            "rows": [],
            "actions": [],
        }
    rows = []
    for image in sorted(images, key=lambda item: (item.RepoTags or [item.Id])[0].lower()):
        tags = [tag[:512] for tag in image.RepoTags or [] if tag != "<none>:<none>"]
        reference = tags[0] if tags else ""
        name = (
            reference.rsplit(":", 1)[0]
            if reference.rfind(":") > reference.rfind("/")
            else reference
        )
        rows.append(
            {
                "id": image.Id,
                "name": name or f"untagged · {image.Id[7:19]}",
                "status": ", ".join(tags) if tags else "태그 없음",
                "detail": f"{image.Size:,} bytes · {image.Id[7:19]}",
                "updatedAt": datetime.fromtimestamp(image.Created, UTC).isoformat(),
            }
        )
    tagged = sum(bool(image.RepoTags and any(tag != "<none>:<none>" for tag in image.RepoTags)) for image in images)
    return {
        "key": "images",
        "mode": "live",
        "status": "connected",
        "message": "조회된 로컬 이미지 없음" if not images else "Portainer 이미지 목록 읽기 전용 연결",
        "updatedAt": updated,
        "metrics": [
            {"label": "Endpoint", "value": str(settings.portainer_endpoint_id), "detail": "Portainer"},
            {"label": "이미지", "value": str(len(images)), "detail": "로컬 레이어"},
            {"label": "태그 있음", "value": str(tagged), "detail": "이름 지정 이미지"},
            {"label": "태그 없음", "value": str(len(images) - tagged), "detail": "dangling 포함"},
        ],
        "columns": ["이미지", "태그", "크기 · ID", "생성"],
        "rows": rows,
        "actions": [],
    }


def _stacks_resource(settings: Settings, stacks: list[PortainerStack] | None) -> dict:
    updated = iso_now()
    columns = ["Stack", "상태", "종류 · Compose 파일", "마지막 변경"]
    if stacks is None:
        return {
            "key": "stacks",
            "mode": "live",
            "status": "unavailable",
            "message": "Portainer stack 목록 응답 없음",
            "updatedAt": updated,
            "metrics": [],
            "columns": columns,
            "rows": [],
            "actions": [],
        }
    rows = [
        {
            "id": str(stack.Id),
            "name": stack.Name,
            "status": "활성" if stack.Status == 1 else "중지",
            "detail": f"{'Swarm' if stack.Type == 1 else 'Compose'} · {stack.EntryPoint or '파일 정보 없음'}",
            "updatedAt": datetime.fromtimestamp(
                max(stack.CreationDate, stack.UpdateDate), UTC
            ).isoformat(),
        }
        for stack in sorted(stacks, key=lambda item: item.Name.lower())
    ]
    return {
        "key": "stacks",
        "mode": "live",
        "status": "connected",
        "message": "조회된 Compose stack 없음" if not rows else "Portainer stack 목록 읽기 전용 연결",
        "updatedAt": updated,
        "metrics": [
            {"label": "Endpoint", "value": str(settings.portainer_endpoint_id), "detail": "Portainer"},
            {"label": "Stack", "value": str(len(rows)), "detail": "Compose · Swarm"},
            {"label": "활성", "value": str(sum(stack.Status == 1 for stack in stacks)), "detail": "Portainer 상태"},
            {"label": "중지", "value": str(sum(stack.Status == 2 for stack in stacks)), "detail": "Portainer 상태"},
        ],
        "columns": columns,
        "rows": rows,
        "actions": [],
    }


def _mailcow_status(value: bool | int | str) -> str:
    if value is True or value == 1 or value == "1":
        return "활성"
    if value is False or value == 0 or value == "0":
        return "중지"
    return "미확인"


def _mailcow_quota(value: int | str | None) -> str:
    try:
        amount = int(value)
    except (TypeError, ValueError):
        return "미보고"
    return f"{amount:,} bytes" if 0 <= amount <= 1_000_000_000_000_000_000 else "미보고"


def _mailcow_percent(value: int | float | str | None) -> str | None:
    try:
        percent = float(value)
    except (TypeError, ValueError):
        return None
    return f"{percent:g}" if math.isfinite(percent) and 0 <= percent <= 100 else None


def _mailcow_resource(
    settings: Settings,
    data: tuple[list[MailcowDomain], list[MailcowMailbox], list[MailcowAlias]] | None,
) -> dict:
    updated = iso_now()
    columns = ["도메인 · 계정", "상태", "사용량 · 별칭 전달", "조회"]
    if data is None:
        return {
            "key": "mail",
            "mode": "live",
            "status": "unavailable",
            "message": "mailcow 읽기 전용 API 응답 없음 또는 형식이 올바르지 않음",
            "updatedAt": updated,
            "metrics": [],
            "columns": columns,
            "rows": [],
            "actions": [],
        }
    domains, mailboxes, aliases = data
    mailbox_counts = {}
    for mailbox in mailboxes:
        domain = mailbox.domain or mailbox.username.rpartition("@")[2]
        mailbox_counts[domain.lower()] = mailbox_counts.get(domain.lower(), 0) + 1
    rows = [
        {
            "id": f"domain:{domain.domain}",
            "name": domain.domain,
            "status": _mailcow_status(domain.active),
            "detail": f"계정 {mailbox_counts.get(domain.domain.lower(), 0)}개 · 도메인 quota {_mailcow_quota(domain.quota)}",
            "updatedAt": updated,
        }
        for domain in sorted(domains, key=lambda item: item.domain.lower())
    ]
    rows.extend(
        {
            "id": f"mailbox:{mailbox.username}",
            "name": mailbox.username,
            "status": _mailcow_status(mailbox.active),
            "detail": (
                f"{mailbox.domain or mailbox.name or 'mailbox'} · 사용량 "
                f"{_mailcow_quota(mailbox.quota_used)} / {_mailcow_quota(mailbox.quota)}"
                + (f" · {percent}%" if (percent := _mailcow_percent(mailbox.percent_in_use)) else "")
            ),
            "updatedAt": updated,
        }
        for mailbox in sorted(mailboxes, key=lambda item: item.username.lower())
    )
    rows.extend(
        {
            "id": f"alias:{alias.address}",
            "name": alias.address,
            "status": _mailcow_status(alias.active),
            "detail": f"전달 → {alias.goto or '대상 미설정'}",
            "updatedAt": updated,
        }
        for alias in sorted(aliases, key=lambda item: item.address.lower())
    )
    return {
        "key": "mail",
        "mode": "live",
        "status": "connected",
        "message": "mailcow 도메인 · 계정 · 별칭 읽기 전용 연결",
        "updatedAt": updated,
        "metrics": [
            {"label": "도메인", "value": str(len(domains)), "detail": "mailcow"},
            {
                "label": "활성 계정",
                "value": str(sum(_mailcow_status(item.active) == "활성" for item in mailboxes)),
                "detail": f"전체 {len(mailboxes)}개",
            },
            {"label": "별칭", "value": str(len(aliases)), "detail": "전달 규칙"},
            {"label": "접근", "value": "읽기 전용", "detail": "API key 권한"},
        ],
        "columns": columns,
        "rows": rows,
        "actions": [],
    }


def _bounded_metric(value) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool):
        amount = value
    elif isinstance(value, str) and value.isdecimal():
        try:
            amount = int(value)
        except (ValueError, OverflowError):
            return None
    else:
        return None
    return amount if 0 <= amount <= 1_000_000_000_000_000_000 else None


def _postgres_stats(settings: Settings) -> dict | None:
    try:
        with psycopg.connect(
            settings.postgres_url.get_secret_value(),
            connect_timeout=3,
            sslmode="verify-full",
            gssencmode="disable",
            options="-c statement_timeout=3000",
        ) as connection:
            with connection.transaction():
                connection.execute("SET TRANSACTION READ ONLY")
                row = connection.execute(
                    "SELECT current_database(), pg_database_size(current_database()), "
                    "numbackends, current_setting('max_connections')::integer "
                    "FROM pg_stat_database WHERE datname = current_database()"
                ).fetchone()
        if row is None:
            return None
        size, connections, maximum = (_bounded_metric(value) for value in row[1:])
        if not isinstance(row[0], str) or not row[0] or None in {size, connections, maximum}:
            return None
        return {
            "database": row[0][:128],
            "size_bytes": size,
            "connections": connections,
            "max_connections": maximum,
        }
    except (psycopg.Error, OSError, TypeError, ValueError):
        return None


def _redis_stats(settings: Settings) -> dict | None:
    client = None
    try:
        client = Redis.from_url(
            settings.redis_url.get_secret_value(),
            decode_responses=True,
            socket_connect_timeout=2,
            socket_timeout=2,
        )
        if not client.ping():
            return None
        info = {section: client.info(section) for section in ("memory", "clients", "stats")}
        if any(not isinstance(values, dict) for values in info.values()):
            return None
        memory = _bounded_metric(info["memory"].get("used_memory"))
        clients = _bounded_metric(info["clients"].get("connected_clients"))
        if memory is None or clients is None:
            return None
        keys = _bounded_metric(client.dbsize())
        if keys is None:
            return None
        operations = _bounded_metric(info["stats"].get("instantaneous_ops_per_sec"))
        return {
            "memory_bytes": memory,
            "clients": clients,
            "keys": keys,
            "operations_per_second": operations,
        }
    except (RedisError, OSError, TypeError, ValueError):
        return None
    finally:
        if client is not None:
            try:
                client.close()
            except (RedisError, OSError):
                pass


def _database_resource(settings: Settings) -> dict:
    updated = iso_now()
    rows = []
    metrics = []
    configured = 0
    reachable = 0
    if settings.postgres_url.get_secret_value():
        configured += 1
        postgres = _postgres_stats(settings)
        if postgres is None:
            rows.append(
                {
                    "id": "postgresql",
                    "name": "PostgreSQL",
                    "status": "주의",
                    "detail": "읽기 전용 DB 지표 조회 실패",
                    "updatedAt": updated,
                }
            )
        else:
            reachable += 1
            rows.append(
                {
                    "id": "postgresql",
                    "name": f"PostgreSQL · {postgres['database']}",
                    "status": "정상",
                    "detail": (
                        f"{postgres['size_bytes']:,} bytes · "
                        f"연결 {postgres['connections']}/{postgres['max_connections']}"
                    ),
                    "updatedAt": updated,
                }
            )
            metrics.extend(
                [
                    {
                        "label": "PostgreSQL 크기",
                        "value": f"{postgres['size_bytes']:,} B",
                        "detail": postgres["database"],
                    },
                    {
                        "label": "PostgreSQL 연결",
                        "value": f"{postgres['connections']}/{postgres['max_connections']}",
                        "detail": "현재 연결 / 최대 연결",
                    },
                ]
            )
    if settings.redis_url.get_secret_value():
        configured += 1
        redis = _redis_stats(settings)
        if redis is None:
            rows.append(
                {
                    "id": "redis",
                    "name": "Redis",
                    "status": "주의",
                    "detail": "PING 또는 INFO 조회 실패",
                    "updatedAt": updated,
                }
            )
        else:
            reachable += 1
            rows.append(
                {
                    "id": "redis",
                    "name": "Redis",
                    "status": "정상",
                    "detail": (
                        f"메모리 {redis['memory_bytes']:,} bytes · "
                        f"클라이언트 {redis['clients']} · 키 {redis['keys']}"
                    ),
                    "updatedAt": updated,
                }
            )
            metrics.extend(
                [
                    {
                        "label": "Redis 메모리",
                        "value": f"{redis['memory_bytes']:,} B",
                        "detail": "used_memory",
                    },
                    {
                        "label": "Redis 클라이언트",
                        "value": str(redis["clients"]),
                        "detail": (
                            f"{redis['keys']} keys · "
                            f"{redis['operations_per_second'] if redis['operations_per_second'] is not None else '—'} ops/s"
                        ),
                    },
                ]
            )
    status = "unavailable" if reachable == 0 else "partial" if reachable < configured else "connected"
    return {
        "key": "database",
        "mode": "live",
        "status": status,
        "message": "고정 조회만 실행 · PostgreSQL 트랜잭션은 읽기 전용",
        "updatedAt": updated,
        "metrics": metrics,
        "columns": ["서비스", "상태", "용량 · 연결 지표", "갱신"],
        "rows": rows,
        "actions": [],
    }


def _settings_resource(settings: Settings) -> dict:
    updated = iso_now()
    integrations = [
        ("Cloudflare Access", True, "API JWT issuer/audience 검증"),
        ("Linux Agent", bool(settings.host_agent_url), "호스트 지표 읽기 전용"),
        ("Portainer", bool(settings.portainer_url), "컨테이너 · 이미지 · Stack 조회"),
        (
            "Portainer 제어",
            bool(settings.portainer_actions_api_key.get_secret_value()),
            "컨테이너 시작 · 중지 · 재시작 · 별도 키 필요",
        ),
        ("n8n", bool(settings.n8n_url), "준비 상태 HTTP health check"),
        (
            "n8n 실행 이력",
            bool(settings.n8n_api_key.get_secret_value()),
            "최근 5개 실행 메타데이터 · payload 제외",
        ),
        ("OpenClaw", bool(settings.openclaw_url), "Gateway liveness HTTP health check"),
        (
            "Netdata Alerts",
            bool(settings.netdata_url),
            "단일 Agent의 최근 WARNING · CRITICAL 경보 조회",
        ),
        ("Scrutiny", bool(settings.scrutiny_url), "장치 요약 · S.M.A.R.T 상태 · 온도 조회"),
        ("mailcow", bool(settings.mailcow_url), "도메인 · 계정 · 별칭 조회"),
        (
            "PostgreSQL",
            bool(settings.postgres_url.get_secret_value()),
            "DB 크기 · 연결 수 읽기 전용",
        ),
        (
            "Redis",
            bool(settings.redis_url.get_secret_value()),
            "메모리 · 클라이언트 지표 읽기 전용",
        ),
        ("ntfy", bool(settings.ntfy_url), "상태 변경 경고 전달"),
        (
            "GitHub Actions",
            bool(settings.github_api_token.get_secret_value()),
            "허용 저장소 workflow 조회",
        ),
        (
            "Cloudflare DNS",
            bool(settings.cloudflare_api_token.get_secret_value()),
            "단일 Zone DNS 조회",
        ),
        (
            "Cloudflare DNS 쓰기",
            dns_writes_enabled(settings),
            "단일 Zone 변경 · Owner · WebAuthn · 감사 기록",
        ),
    ]
    configured = sum(is_configured for _, is_configured, _ in integrations)
    rows = [
        {
            "id": name,
            "name": name,
            "status": "설정됨" if is_configured else "미설정",
            "detail": detail,
            "updatedAt": updated,
        }
        for name, is_configured, detail in integrations
    ]
    rows.extend(
        [
            {
                "id": "audit",
                "name": "감사 저장소",
                "status": "사용 중",
                "detail": f"SQLite · {settings.audit_retention_days}일 보관",
                "updatedAt": updated,
            },
            {
                "id": "writes",
                "name": "서버 쓰기 작업",
                "status": "부분 지원",
                "detail": "Docker 제어 · 단일 Zone DNS만 제한 지원 · systemd, 배포, 백업/복원 미지원",
                "updatedAt": updated,
            },
        ]
    )
    return {
        "key": "settings",
        "mode": "live",
        "status": "connected",
        "message": "환경 변수 설정 여부만 표시 · 실제 API 연결 상태는 각 리소스에서 확인",
        "updatedAt": updated,
        "metrics": [
            {"label": "모드", "value": "Live", "detail": "실제 공급자"},
            {"label": "연동 설정", "value": f"{configured}/{len(integrations)}", "detail": "비밀값 미표시"},
            {"label": "감사 보관", "value": f"{settings.audit_retention_days}일", "detail": "SQLite"},
            {"label": "쓰기 작업", "value": "부분 지원", "detail": "Docker 제어 · 단일 Zone DNS만 제한 지원"},
        ],
        "columns": ["연동", "구성", "설명", "갱신"],
        "rows": rows,
        "actions": [],
    }


def _notifications_resource(settings: Settings) -> dict:
    updated = iso_now()
    rows = []
    configured = 0
    reachable = 0
    if settings.host_agent_url:
        configured += 1
        snapshot = host_snapshot(settings)
        if snapshot is None:
            rows.append(
                {
                    "id": "host-agent",
                    "name": "호스트 Agent",
                    "status": "warning",
                    "detail": "호스트 지표 연결 실패",
                    "updatedAt": updated,
                }
            )
        else:
            reachable += 1
            if snapshot.cpu.percent >= 85:
                rows.append(
                    {
                        "id": "host-cpu",
                        "name": "CPU 사용률",
                        "status": "warning",
                        "detail": f"{snapshot.cpu.percent:.1f}% · 주의 기준 85%",
                        "updatedAt": snapshot.updatedAt.isoformat(),
                    }
                )
            if snapshot.memory.percent >= 90:
                rows.append(
                    {
                        "id": "host-memory",
                        "name": "메모리 사용률",
                        "status": "warning",
                        "detail": f"{snapshot.memory.percent:.1f}% · 주의 기준 90%",
                        "updatedAt": snapshot.updatedAt.isoformat(),
                    }
                )
            rows.extend(
                {
                    "id": f"storage:{item.name}",
                    "name": f"스토리지 · {item.name}",
                    "status": "warning",
                    "detail": f"{item.percent:.1f}% 사용 · 주의 기준 85%",
                    "updatedAt": snapshot.updatedAt.isoformat(),
                }
                for item in snapshot.storage
                if item.percent >= 85
            )
    if settings.portainer_url:
        configured += 1
        containers = portainer_containers(settings)
        if containers is None:
            rows.append(
                {
                    "id": "portainer",
                    "name": "Portainer",
                    "status": "warning",
                    "detail": "Docker 상태 조회 실패",
                    "updatedAt": updated,
                }
            )
        else:
            reachable += 1
            rows.extend(
                {
                    "id": f"container:{row['id']}",
                    "name": row["name"],
                    "status": row["status"],
                    "detail": row["detail"],
                    "updatedAt": row["updatedAt"],
                }
                for row in _container_service_rows(containers, updated)
                if row["status"] != "healthy"
            )
    automation = _automation_resource(settings)
    automation_rows = [
        row for row in automation["rows"] if row["id"] in {"n8n", "openclaw"}
    ]
    configured += sum(row["status"] != "미설정" for row in automation_rows)
    reachable += sum(row["status"] == "정상" for row in automation_rows)
    rows.extend(
        {
            "id": f"automation:{row['id']}",
            "name": f"자동화 · {row['name']}",
            "status": "failed" if row["status"] == "미준비" else "warning",
            "detail": row["detail"],
            "updatedAt": row["updatedAt"],
        }
        for row in automation_rows
        if row["status"] not in {"미설정", "정상"}
    )
    status = (
        "not_configured"
        if configured == 0
        else "unavailable"
        if reachable == 0
        else "partial"
        if reachable < configured
        else "connected"
    )
    return {
        "key": "notifications",
        "mode": "live",
        "status": status,
        "message": (
            "구성된 호스트·Docker 경고 · ntfy 상태 변경 전달"
            if settings.ntfy_url
            else "구성된 호스트·Docker 경고 · ntfy 미구성"
        ),
        "updatedAt": updated,
        "metrics": [
            {"label": "현재 경고", "value": str(len(rows)), "detail": "Agent · Portainer · 자동화"},
            {"label": "확인 가능", "value": f"{reachable}/{configured}", "detail": "구성 공급자"},
            {"label": "심각", "value": str(sum(row["status"] == "failed" for row in rows)), "detail": "실패 상태"},
            {
                "label": "전달",
                "value": "설정됨" if settings.ntfy_url else "미구성",
                "detail": "ntfy · 상태 변경 시",
            },
        ],
        "columns": ["이벤트", "상태", "설명", "갱신"],
        "rows": rows,
        "actions": [],
    }


def _monitoring_resource(settings: Settings) -> dict:
    updated = iso_now()
    alerts = netdata_alerts(settings) if settings.netdata_url else None
    devices = scrutiny_devices(settings) if settings.scrutiny_url else None
    critical = sum(alert.status == "CRITICAL" for alert in alerts or [])
    warning = sum(alert.status == "WARNING" for alert in alerts or [])
    connected = int(alerts is not None) + int(devices is not None)
    configured = int(bool(settings.netdata_url)) + int(bool(settings.scrutiny_url))
    scrutiny_rows = [
        _scrutiny_row(device, index, updated, "Scrutiny · ")
        for index, device in enumerate(
            sorted(
                devices or [],
                key=lambda item: item.device.label
                or item.device.device_label
                or item.device.device_name
                or item.device.model_name,
            )
        )
    ]
    disk_errors = sum(row["status"] == "오류" for row in scrutiny_rows)
    netdata_status = (
        "미설정"
        if not settings.netdata_url
        else "응답 없음"
        if alerts is None
        else "오류"
        if critical
        else "주의"
        if warning
        else "정상"
    )
    scrutiny_status = (
        "미설정"
        if not settings.scrutiny_url
        else "응답 없음"
        if devices is None
        else "정상"
    )
    rows = [
        {
            "id": "netdata",
            "name": "Netdata Agent",
            "status": netdata_status,
            "detail": (
                f"현재 WARNING {warning} · CRITICAL {critical} · 최근 경보 최대 100개"
                if alerts is not None
                else "경보 API 미설정" if not settings.netdata_url else "경보 API 응답 없음"
            ),
            "updatedAt": updated,
        },
        {
            "id": "uptime-kuma",
            "name": "Uptime Kuma",
            "status": "미연결",
            "detail": "공식 지원 읽기 API adapter 없음",
            "updatedAt": updated,
        },
        {
            "id": "scrutiny",
            "name": "Scrutiny",
            "status": scrutiny_status,
            "detail": (
                f"{len(devices)}개 장치 · 비정상 {disk_errors}개"
                if devices is not None
                else "API 미설정" if not settings.scrutiny_url else "요약 API 응답 없음"
            ),
            "updatedAt": updated,
        },
    ]
    rows.extend(
        {
            "id": f"netdata-alert:{index}",
            "name": alert.name,
            "status": alert.status,
            "detail": " · ".join(
                part
                for part in (
                    alert.context,
                    f"{alert.value} {alert.units or ''}".strip()
                    if alert.value is not None
                    else None,
                )
                if part
            )
            or "Netdata 경보",
            "updatedAt": (
                datetime.fromtimestamp(alert.last_evaluated_at, UTC).isoformat()
                if alert.last_evaluated_at is not None
                else updated
            ),
        }
        for index, alert in enumerate(alerts or [])
    )
    rows.extend(scrutiny_rows)
    status = (
        "not_configured"
        if configured == 0
        else "unavailable"
        if connected == 0
        else "partial"
    )
    return {
        "key": "monitoring",
        "mode": "live",
        "status": status,
        "message": f"Netdata {netdata_status} · Scrutiny {scrutiny_status} · Uptime Kuma 미연결",
        "updatedAt": updated,
        "metrics": [
            {"label": "연동", "value": f"{connected}/3", "detail": "Netdata · Uptime Kuma · Scrutiny"},
            {"label": "활성 경보", "value": str(len(alerts or [])), "detail": f"CRITICAL {critical} · WARNING {warning}"},
            {"label": "디스크", "value": str(len(devices)) if devices is not None else "미연결", "detail": "Scrutiny 장치 요약"},
            {"label": "디스크 이상", "value": str(disk_errors), "detail": "Scrutiny S.M.A.R.T 상태"},
        ],
        "columns": ["모니터", "상태", "설명", "갱신"],
        "rows": rows,
        "actions": [],
    }


def _automation_resource(settings: Settings) -> dict:
    updated = iso_now()
    configured = 0
    healthy = 0
    rows = []
    integrations = [
        ("n8n", "n8n", settings.n8n_url, "/healthz/readiness", "N8N_URL"),
        (
            "openclaw",
            "OpenClaw Gateway",
            settings.openclaw_url,
            "/health",
            "OPENCLAW_URL",
        ),
    ]
    for integration_id, name, url, path, env_name in integrations:
        if not url:
            rows.append(
                {
                    "id": integration_id,
                    "name": name,
                    "status": "미설정",
                    "detail": f"{env_name} 미설정",
                    "updatedAt": updated,
                }
            )
            continue
        configured += 1
        status = _health_status(url, path)
        is_healthy = status == 200
        healthy += int(is_healthy)
        rows.append(
            {
                "id": integration_id,
                "name": name,
                "status": "정상" if is_healthy else "응답 없음" if status is None else "미준비",
                "detail": (
                    f"HTTP {status} · {'준비 상태' if integration_id == 'n8n' else 'Gateway 응답'}"
                    if is_healthy
                    else "요청 실패 또는 시간 초과"
                    if status is None
                    else f"HTTP {status} · health check 실패"
                ),
                "updatedAt": updated,
            }
        )
    rows.append(
        {
            "id": "mcp",
            "name": "MCP 서버",
            "status": "미설정",
            "detail": "MCP 표준 health endpoint 없음 · 서버별 adapter 미구성",
            "updatedAt": updated,
        }
    )
    executions = n8n_executions(settings)
    if not settings.n8n_url or not settings.n8n_api_key.get_secret_value():
        rows.append(
            {
                "id": "n8n-history",
                "name": "n8n 실행 이력",
                "status": "미설정",
                "detail": "N8N_URL 또는 N8N_API_KEY 미설정",
                "updatedAt": updated,
            }
        )
    elif executions is None:
        rows.append(
            {
                "id": "n8n-history",
                "name": "n8n 실행 이력",
                "status": "응답 없음",
                "detail": "공개 API 요청 실패 · 실행 payload는 조회하지 않음",
                "updatedAt": updated,
            }
        )
    else:
        rows.append(
            {
                "id": "n8n-history",
                "name": "n8n 실행 이력",
                "status": f"최근 {len(executions)}개",
                "detail": "메타데이터만 조회 · 실행 payload 제외",
                "updatedAt": updated,
            }
        )
        for execution in executions:
            execution_status = execution.status or (
                "success" if execution.finished else "running"
            )
            status = {
                "success": "성공",
                "error": "실패",
                "crashed": "실패",
                "running": "실행 중",
                "waiting": "대기",
                "new": "대기",
                "canceled": "취소",
            }.get(execution_status, execution_status)
            rows.append(
                {
                    "id": f"n8n-execution:{execution.id}",
                    "name": f"n8n workflow {execution.workflowId}",
                    "status": status,
                    "detail": f"실행 {execution.id} · 실행 상태 메타데이터",
                    "updatedAt": (execution.stoppedAt or execution.startedAt or datetime.now(UTC)),
                }
            )
    status = (
        "not_configured"
        if configured == 0
        else "connected"
        if healthy == configured
        else "partial"
        if healthy > 0
        else "unavailable"
    )
    return {
        "key": "automation",
        "mode": "live",
        "status": status,
        "message": "n8n readiness · OpenClaw liveness · API key 설정 시 최근 n8n 실행 이력 · 서비스 재시작 미구현",
        "updatedAt": updated,
        "metrics": [
            {"label": "설정", "value": f"{configured}/2", "detail": "n8n · OpenClaw"},
            {"label": "정상", "value": str(healthy), "detail": "HTTP 200"},
            {"label": "MCP", "value": "미연결", "detail": "별도 health adapter 필요"},
            {
                "label": "실행 이력",
                "value": "미설정" if executions is None and not settings.n8n_api_key.get_secret_value() else str(len(executions or [])),
                "detail": "n8n · payload 제외 · limit 5",
            },
        ],
        "columns": ["연동", "상태", "확인 결과", "갱신"],
        "rows": rows,
        "actions": [],
    }


def _container_resource(
    settings: Settings, containers: list[PortainerContainer] | None
) -> dict | None:
    if not settings.portainer_url:
        return None
    updated = iso_now()
    if containers is None:
        return {
            "key": "containers",
            "mode": "live",
            "status": "unavailable",
            "message": "Portainer API 응답 없음",
            "updatedAt": updated,
            "metrics": [],
            "columns": ["컨테이너", "상태", "이미지 · 포트", "갱신"],
            "rows": [],
            "actions": [],
        }
    running = sum(container.State == "running" for container in containers)
    metrics = [
        {"label": "Endpoint", "value": str(settings.portainer_endpoint_id), "detail": "Portainer"},
        {"label": "전체", "value": str(len(containers)), "detail": "컨테이너"},
        {"label": "실행", "value": str(running), "detail": "running"},
        {"label": "중지", "value": str(len(containers) - running), "detail": "그 외 상태"},
    ]
    rows = []
    for container in sorted(containers, key=lambda item: item.Names[0].lower()):
        name = container.Names[0].lstrip("/")[:128] or container.Id[:12]
        ports = [
            f"{port.PublicPort}:{port.PrivatePort}/{port.Type}"
            if port.PublicPort
            else f"{port.PrivatePort}/{port.Type}"
            for port in container.Ports[:8]
        ]
        rows.append(
            {
                "id": container.Id,
                "name": name,
                "status": container.Status[:128],
                "detail": f"{container.Image[:256]} · {', '.join(ports) or '포트 미공개'}",
                "updatedAt": updated,
                "actions": [
                    {
                        "id": operation,
                        "label": label,
                        "operation": operation,
                        "target": container.Id,
                        "targetLabel": name,
                        "enabled": bool(settings.portainer_actions_api_key.get_secret_value()),
                        "reason": (
                            "Passkey 재인증 후 이 작업만 실행합니다."
                            if settings.portainer_actions_api_key.get_secret_value()
                            else "PORTAINER_ACTIONS_API_KEY가 구성되지 않았습니다."
                        ),
                    }
                    for operation, label in (
                        [("stop", "중지"), ("restart", "재시작")]
                        if container.State == "running"
                        else [("start", "시작")]
                        if container.State in {"created", "exited"}
                        else []
                    )
                ],
            }
        )
    return {
        "key": "containers",
        "mode": "live",
        "status": "connected",
        "message": (
            "Portainer 상태 조회 · 제한된 컨테이너 제어는 작업별 Passkey 확인 필요"
            if settings.portainer_actions_api_key.get_secret_value()
            else "Portainer 읽기 전용 연결 · 제어 키 미구성, 컨테이너 작업 비활성화"
        ),
        "updatedAt": updated,
        "metrics": metrics,
        "columns": ["컨테이너", "상태", "이미지 · 포트", "갱신"],
        "rows": rows,
        "actions": [],
    }


def _unavailable_overview(
    settings: Settings, docker: dict, containers: list[PortainerContainer] | None
) -> dict:
    now = iso_now()
    configured = bool(settings.host_agent_url)
    return {
        "mode": "live",
        "status": "unavailable" if configured else "not_configured",
        "serverName": "호스트 에이전트 응답 없음" if configured else "호스트 에이전트 미연결",
        "updatedAt": now,
        "uptimeSeconds": 0,
        "cpu": {"percent": 0, "cores": [0], "loadAverage": [0, 0, 0]},
        "memory": {"usedBytes": 0, "totalBytes": 0, "percent": 0},
        "swap": {"usedBytes": 0, "totalBytes": 0, "percent": 0},
        "storage": [],
        "network": {"receivedBytesPerSecond": 0, "sentBytesPerSecond": 0},
        "docker": docker,
        "history": [],
        "services": [
            {
                "name": "호스트 에이전트",
                "status": "failed" if configured else "not_configured",
                "detail": "호스트 지표를 받을 수 없습니다"
                if configured
                else "안전한 호스트 에이전트 미연결",
                "checkedAt": now,
            },
            _portainer_service(docker, now),
        ] + _container_service_items(containers or [], now),
        "activity": [],
    }


def overview(settings: Settings) -> dict:
    if settings.app_mode == "live":
        containers = portainer_containers(settings)
        docker = _docker_metrics(settings, containers)
        snapshot = host_snapshot(settings)
        if snapshot is None:
            return _unavailable_overview(settings, docker, containers)
        return {
            "mode": "live",
            "status": "connected",
            "serverName": snapshot.serverName,
            "updatedAt": snapshot.updatedAt,
            "uptimeSeconds": snapshot.uptimeSeconds,
            "cpu": snapshot.cpu.model_dump(),
            "memory": snapshot.memory.model_dump(),
            "swap": snapshot.swap.model_dump(),
            "storage": [item.model_dump() for item in snapshot.storage],
            "network": snapshot.network.model_dump(),
            "docker": docker,
            "history": [point.model_dump() for point in snapshot.history],
            "services": [
                {
                    "name": "호스트 에이전트",
                    "status": "healthy",
                    "detail": "읽기 전용 시스템 지표 연결",
                    "checkedAt": snapshot.updatedAt,
                },
                _portainer_service(docker, snapshot.updatedAt.isoformat()),
            ] + _container_service_items(containers or [], snapshot.updatedAt.isoformat()),
            "activity": [],
        }

    now = iso_now()
    random = Random(314)
    history = [
        {
            "time": (datetime.now(UTC) - timedelta(minutes=5 * (11 - i))).strftime("%H:%M"),
            "cpu": round(18 + random.random() * 24, 1),
            "memory": round(58 + random.random() * 6, 1),
        }
        for i in range(12)
    ]
    return {
        "mode": "mock",
        "status": "connected",
        "serverName": "heonhwi-homeserver · DEMO",
        "updatedAt": now,
        "uptimeSeconds": 8 * 86400 + 7 * 3600 + 31 * 60,
        "cpu": {
            "percent": history[-1]["cpu"],
            "cores": [22.4, 18.2, 31.8, 20.1, 16.5, 25.6, 19.4, 21.2],
            "loadAverage": [0.84, 0.73, 0.69],
            "modelName": "Intel Core i7-2600 · DEMO",
            "physicalCores": 4,
            "avx2": False,
        },
        "memory": {"usedBytes": 21_303_037_788, "totalBytes": 34_359_738_368, "percent": 62},
        "swap": {"usedBytes": 1_342_177_280, "totalBytes": 8_589_934_592, "percent": 15.6},
        "storage": [
            {
                "name": "System SSD",
                "device": "확인 필요 · DEMO",
                "mount": "확인 필요 · DEMO",
                "fileSystem": "확인 필요 · DEMO",
                "usedBytes": 72_000_000_000,
                "totalBytes": 120_000_000_000,
                "percent": 60,
                "health": "not_reported",
            },
            {
                "name": "Data HDD",
                "device": "확인 필요 · DEMO",
                "mount": "확인 필요 · DEMO",
                "fileSystem": "확인 필요 · DEMO",
                "usedBytes": 100_000_000_000,
                "totalBytes": 500_000_000_000,
                "percent": 20,
                "health": "not_reported",
            },
        ],
        "network": {"receivedBytesPerSecond": 3_145_728, "sentBytesPerSecond": 1_048_576},
        "docker": {
            "status": "not_configured",
            "running": 0,
            "total": 0,
            "message": "DEMO 데이터 · 런타임은 연결되지 않음",
        },
        "history": history,
        "services": [
            {
                "name": "Cloudflare Tunnel",
                "status": "healthy",
                "detail": "모의 상태 · 실제 연결 없음",
                "checkedAt": iso_now(28),
            },
            {
                "name": "Caddy",
                "status": "healthy",
                "detail": "모의 상태 · 실제 연결 없음",
                "checkedAt": iso_now(45),
            },
            {
                "name": "PostgreSQL",
                "status": "warning",
                "detail": "모의 상태 · 실제 연결 없음",
                "checkedAt": iso_now(72),
            },
            {
                "name": "Mail",
                "status": "not_configured",
                "detail": "공급자 미설정",
                "checkedAt": iso_now(90),
            },
        ],
        "activity": [
            {
                "id": "demo-deploy",
                "kind": "deployment",
                "title": "DEMO 배포 기록",
                "detail": "실제 배포를 실행하지 않았습니다.",
                "createdAt": iso_now(1200),
            },
            {
                "id": "demo-alert",
                "kind": "alert",
                "title": "DEMO 알림 확인",
                "detail": "실제 서비스 상태가 아닙니다.",
                "createdAt": iso_now(3600),
            },
        ],
    }


MOCK_RESOURCES: dict[str, dict] = {
    "services": (
        "서비스",
        [
            {
                "id": "web",
                "name": "web",
                "status": "healthy",
                "detail": "DEMO · 가상 컨테이너",
                "updatedAt": iso_now(),
            }
        ],
    ),
    "notifications": (
        "알림",
        [
            {
                "id": "alert-1",
                "name": "CPU 임계치 알림",
                "status": "DEMO",
                "detail": "모의 이벤트 · 실제 알림 없음",
                "updatedAt": iso_now(300),
            }
        ],
    ),
    "system": (
        "시스템",
        [
            {
                "id": "host",
                "name": "heonhwi-homeserver",
                "status": "DEMO",
                "detail": "모의 지표 · 호스트 에이전트 미연결",
                "updatedAt": iso_now(),
            }
        ],
    ),
    "automation": (
        "자동화",
        [
            {
                "id": "backup",
                "name": "야간 백업",
                "status": "paused",
                "detail": "DEMO · 공급자 미연결",
                "updatedAt": iso_now(),
            }
        ],
    ),
    "domains": (
        "도메인",
        [
            {
                "id": "e" * 32,
                "name": "api.example.invalid",
                "status": "DEMO · A · DNS only",
                "detail": "192.0.2.42 · TTL 자동",
                "updatedAt": iso_now(),
                "dnsRecord": {
                    "name": "api.example.invalid",
                    "type": "A",
                    "content": "192.0.2.42",
                    "ttl": 1,
                    "proxied": False,
                },
            }
        ],
    ),
    "mail": (
        "메일",
        [
            {
                "id": "mail",
                "name": "Mail provider",
                "status": "미연결",
                "detail": "메일 API 미설정",
                "updatedAt": iso_now(),
            }
        ],
    ),
    "database": (
        "데이터베이스",
        [
            {
                "id": "db",
                "name": "PostgreSQL",
                "status": "미연결",
                "detail": "데이터베이스 DSN 미설정",
                "updatedAt": iso_now(),
            }
        ],
    ),
    "storage": (
        "스토리지",
        [
            {
                "id": "ssd",
                "name": "시스템 볼륨",
                "status": "DEMO",
                "detail": "실제 디스크에 접근하지 않습니다.",
                "updatedAt": iso_now(),
            }
        ],
    ),
    "monitoring": (
        "모니터링",
        [
            {
                "id": "monitor",
                "name": "상태 확인",
                "status": "DEMO",
                "detail": "모의 이벤트 · 공급자 미연결",
                "updatedAt": iso_now(),
            }
        ],
    ),
    "security": (
        "보안",
        [
            {
                "id": "access",
                "name": "Cloudflare Access",
                "status": "미연결",
                "detail": "개발 Mock에서 JWT 검증 생략",
                "updatedAt": iso_now(),
            }
        ],
    ),
    "settings": (
        "설정",
        [
            {
                "id": "mode",
                "name": "애플리케이션 모드",
                "status": "DEMO",
                "detail": "개발용 Mock 공급자",
                "updatedAt": iso_now(),
            }
        ],
    ),
    "containers": (
        "컨테이너",
        [
            {
                "id": "container",
                "name": "web",
                "status": "DEMO",
                "detail": "Docker 런타임은 연결되지 않음",
                "updatedAt": iso_now(),
            }
        ],
    ),
    "images": (
        "이미지",
        [
            {
                "id": "sha256:" + "d" * 64,
                "name": "nginx:stable",
                "status": "DEMO",
                "detail": "가상 이미지 · 실제 런타임 미연결",
                "updatedAt": iso_now(),
            }
        ],
    ),
    "stacks": (
        "Compose Stack",
        [
            {
                "id": "1",
                "name": "homeserver-admin",
                "status": "DEMO",
                "detail": "Compose · docker-compose.yml · 가상 데이터",
                "updatedAt": iso_now(),
            }
        ],
    ),
    "deployments": (
        "배포",
        [
            {
                "id": "release",
                "name": "현재 릴리스",
                "status": "DEMO",
                "detail": "CI 공급자 미연결",
                "updatedAt": iso_now(),
            }
        ],
    ),
}

READ_ONLY_RESOURCE_MESSAGES = {
    "services": "Portainer 미연결 · Docker 컨테이너 Healthcheck 상태 없음",
    "notifications": "알림 공급자 미설정",
    "system": "호스트 에이전트 미연결",
    "automation": "자동화 공급자 미설정",
    "domains": "DNS 공급자 미설정",
    "mail": "메일 공급자 미설정",
    "database": "데이터베이스 공급자 미설정",
    "storage": "호스트 스토리지 에이전트 미연결",
    "monitoring": "모니터링 공급자 미설정",
    "security": "Access 구성 후 확인 가능 · 감사 이벤트는 별도 저장",
    "settings": "설정할 공급자가 없음",
    "containers": "제한된 컨테이너 에이전트 미연결",
    "images": "Portainer 미연결 · Docker 이미지 목록 없음",
    "stacks": "Portainer 미연결 · Compose stack 목록 없음",
    "deployments": "배포 공급자 미설정",
}


def github_deployment_resource(settings: Settings) -> dict:
    rows = []
    failed_repositories = []
    repositories = settings.github_repo_list
    for repository in repositories:
        runs = github_workflow_runs(settings, repository)
        if runs is None:
            failed_repositories.append(repository)
            continue
        for run in runs:
            name = run.name or "workflow"
            title = run.display_title or name
            state = run.conclusion if run.status == "completed" and run.conclusion else run.status
            rows.append(
                {
                    "id": f"{repository}#{run.id}",
                    "name": f"{repository} · {name}",
                    "status": state,
                    "detail": f"{title} · {run.head_branch or 'branch unknown'} · {run.head_sha[:7]} · #{run.run_number}",
                    "updatedAt": run.updated_at,
                }
            )
    status = "partial" if failed_repositories and len(failed_repositories) < len(repositories) else (
        "unavailable" if failed_repositories else "connected"
    )
    message = (
        f"GitHub Actions 조회 실패: {', '.join(failed_repositories)}"
        if failed_repositories
        else "GitHub Actions 읽기 전용 연결 · 최근 실행 없음"
        if not rows
        else "GitHub Actions 읽기 전용 연결"
    )
    now = iso_now()
    return {
        "key": "deployments",
        "mode": "live",
        "status": status,
        "message": message,
        "updatedAt": now,
        "metrics": [
            {"label": "저장소", "value": str(len(repositories)), "detail": "허용 목록"},
            {"label": "최근 실행", "value": str(len(rows)), "detail": "저장소별 최대 5개"},
            {"label": "권한", "value": "읽기 전용", "detail": "Actions: read"},
            {"label": "조회", "value": "GitHub API", "detail": "서버 측 요청"},
        ],
        "columns": ["저장소 · 워크플로", "상태", "실행 요약", "마지막 갱신"],
        "rows": rows,
        "actions": [],
    }


def cloudflare_dns_resource(settings: Settings) -> dict:
    result = cloudflare_dns_records(settings)
    now = iso_now()
    if result is None:
        return {
            "key": "domains",
            "mode": "live",
            "status": "unavailable",
            "message": "Cloudflare DNS API 응답 없음",
            "updatedAt": now,
            "metrics": [],
            "columns": ["호스트명", "유형 · Proxy", "값 · TTL", "갱신"],
            "rows": [],
            "actions": [],
        }
    records, total = result
    rows = [
        {
            "id": record.id,
            "name": record.name,
            "status": f"{record.type} · {'Proxied' if record.proxied else 'DNS only'}",
            "detail": (
                f"{record.content[:512]}{'…' if len(record.content) > 512 else ''} · "
                f"TTL {'자동' if record.ttl == 1 else f'{record.ttl}초'}"
                f"{' · 우선순위 ' + str(record.priority) if record.type == 'MX' and record.priority is not None else ''}"
            ),
            "updatedAt": record.modified_on or now,
            "dnsRecord": (
                {
                    "name": record.name,
                    "type": record.type,
                    "content": record.content,
                    "ttl": record.ttl,
                    "proxied": record.proxied,
                    "priority": record.priority,
                }
                if record.type in {"A", "AAAA", "CNAME", "TXT", "MX"}
                and len(record.content) <= 2048
                and (record.type != "MX" or record.priority is not None)
                else None
            ),
        }
        for record in records
    ]
    partial = total > len(rows)
    message = (
        f"Cloudflare DNS 조회 · {len(rows)}/{total}개 표시"
        if partial
        else "Cloudflare DNS 조회 · 변경 전후 확인 및 감사 기록 제공"
        if rows
        else "Cloudflare DNS 조회 · 레코드 없음"
    )
    return {
        "key": "domains",
        "mode": "live",
        "status": "partial" if partial else "connected",
        "message": message,
        "updatedAt": now,
        "metrics": [
            {"label": "레코드", "value": str(total), "detail": "연결된 Zone"},
            {"label": "표시", "value": str(len(rows)), "detail": "최대 100개"},
            {
                "label": "DNS 권한",
                "value": "읽기 · 쓰기" if dns_writes_enabled(settings) else "읽기 전용",
                "detail": "쓰기에는 Passkey 재인증 필요",
            },
            {"label": "권한 범위", "value": "단일 Zone", "detail": settings.cloudflare_zone_id[-8:]},
        ],
        "columns": ["호스트명", "유형 · Proxy", "값 · TTL", "갱신"],
        "rows": rows,
        "actions": [],
        "writeEnabled": dns_writes_enabled(settings),
    }


def _storage_resource(settings: Settings) -> dict:
    snapshot = host_snapshot(settings)
    now = iso_now()
    scrutiny_configured = bool(settings.scrutiny_url)
    devices = scrutiny_devices(settings) if scrutiny_configured else None
    scrutiny_rows = [
        _scrutiny_row(device, index, now, "S.M.A.R.T · ")
        for index, device in enumerate(
            sorted(
                devices or [],
                key=lambda item: item.device.label
                or item.device.device_label
                or item.device.device_name
                or item.device.model_name,
            )
        )
    ]
    disk_errors = sum(row["status"] == "오류" for row in scrutiny_rows)
    if snapshot is None:
        if not settings.host_agent_url and not scrutiny_configured:
            return {
                "key": "storage",
                "mode": "live",
                "status": "not_configured",
                "message": "확인된 읽기 전용 스토리지 경로 미구성",
                "updatedAt": now,
                "metrics": [],
                "columns": ["볼륨", "사용률", "장치 · 파일시스템 · 경로", "갱신"],
                "rows": [],
                "actions": [],
            }
        rows = scrutiny_rows
        if scrutiny_configured and devices is None:
            rows.append({"id": "scrutiny", "name": "Scrutiny", "status": "응답 없음", "detail": "요약 API 응답 없음", "updatedAt": now})
        return {
            "key": "storage",
            "mode": "live",
            "status": "partial" if devices is not None else "unavailable",
            "message": "Scrutiny 장치 상태 · 호스트 용량 정보 미연결" if devices is not None else "스토리지 API 응답 없음",
            "updatedAt": now,
            "metrics": [
                {"label": "마운트", "value": "미연결", "detail": "Linux Agent 필요"},
                {"label": "디스크 건강", "value": str(len(devices)) if devices is not None else "응답 없음", "detail": "Scrutiny 장치 요약"},
                {"label": "디스크 이상", "value": str(disk_errors), "detail": "Scrutiny S.M.A.R.T 상태"},
                {"label": "전체 용량", "value": "미보고", "detail": "Linux Agent 필요"},
            ],
            "columns": ["볼륨", "사용률", "장치 · 파일시스템 · 경로", "갱신"],
            "rows": rows,
            "actions": [],
        }
    storage = snapshot.storage
    if not storage and not scrutiny_configured:
        return {
            "key": "storage",
            "mode": "live",
            "status": "not_configured",
            "message": "확인된 읽기 전용 스토리지 경로 미구성",
            "updatedAt": snapshot.updatedAt,
            "metrics": [],
            "columns": ["볼륨", "사용률", "장치 · 파일시스템 · 경로", "갱신"],
            "rows": [],
            "actions": [],
        }
    used = sum(item.usedBytes for item in storage)
    total = sum(item.totalBytes for item in storage)
    rows = [
        {
            "id": item.name,
            "name": item.name,
            "status": f"{item.percent:.1f}% 사용",
            "detail": (
                f"{item.device} · {item.fileSystem} · {item.mount} · "
                f"{item.usedBytes:.0f}/{item.totalBytes:.0f} bytes · 상태 {item.health}"
            ),
            "updatedAt": snapshot.updatedAt,
        }
        for item in storage
    ]
    rows.extend(scrutiny_rows)
    if scrutiny_configured and devices is None:
        rows.append({"id": "scrutiny", "name": "Scrutiny", "status": "응답 없음", "detail": "요약 API 응답 없음", "updatedAt": now})
    return {
        "key": "storage",
        "mode": "live",
        "status": "partial" if scrutiny_configured and devices is None else "connected",
        "message": "명시된 읽기 전용 마운트 용량 · Scrutiny S.M.A.R.T 요약",
        "updatedAt": snapshot.updatedAt,
        "metrics": [
            {"label": "마운트", "value": str(len(storage)), "detail": "명시적 허용 목록"},
            {"label": "사용", "value": f"{used / 1_000_000_000:.1f} GB", "detail": "전체 용량 합계"},
            {"label": "전체", "value": f"{total / 1_000_000_000:.1f} GB", "detail": "statvfs"},
            {"label": "디스크 건강", "value": str(len(devices)) if devices is not None else "미연결", "detail": "Scrutiny 장치 요약"},
        ],
        "columns": ["볼륨 · 장치", "사용률 · S.M.A.R.T", "장치 · 파일시스템 · 상태", "갱신"],
        "rows": rows,
        "actions": [],
    }


def resource(key: str, settings: Settings) -> dict | None:
    if settings.app_mode == "live":
        if key not in READ_ONLY_RESOURCE_MESSAGES:
            return None
        if key == "settings":
            return _settings_resource(settings)
        if key == "notifications":
            return _notifications_resource(settings)
        if key == "automation":
            return _automation_resource(settings)
        if key == "monitoring":
            return _monitoring_resource(settings)
        if key == "database" and (
            settings.postgres_url.get_secret_value() or settings.redis_url.get_secret_value()
        ):
            return _database_resource(settings)
        if key == "deployments" and settings.github_api_token.get_secret_value():
            return github_deployment_resource(settings)
        if key == "domains" and settings.cloudflare_api_token.get_secret_value():
            return cloudflare_dns_resource(settings)
        if key == "storage":
            return _storage_resource(settings)
        if key == "services" and settings.portainer_url:
            return _services_resource(settings, portainer_containers(settings))
        if key == "images" and settings.portainer_url:
            return _images_resource(settings, portainer_images(settings))
        if key == "stacks" and settings.portainer_url:
            return _stacks_resource(settings, portainer_stacks(settings))
        if key == "mail" and settings.mailcow_url:
            return _mailcow_resource(settings, mailcow_lists(settings))
        if key == "system":
            snapshot = host_snapshot(settings)
            if snapshot is not None:
                updated = snapshot.updatedAt.isoformat()
                metrics = [
                    {
                        "label": "호스트",
                        "value": snapshot.serverName,
                        "detail": f"{snapshot.osName or 'Linux'} · {snapshot.kernelVersion or '커널 미보고'}",
                    },
                    {
                        "label": "CPU",
                        "value": f"{snapshot.cpu.percent:.1f}%",
                        "detail": (
                            f"{snapshot.cpu.modelName} · "
                            if snapshot.cpu.modelName
                            else ""
                        )
                        + (
                            f"{snapshot.cpu.physicalCores}코어 / "
                            if snapshot.cpu.physicalCores
                            else ""
                        )
                        + f"{len(snapshot.cpu.cores)}스레드"
                        + (
                            " · AVX2 지원"
                            if snapshot.cpu.avx2
                            else " · AVX2 미지원"
                            if snapshot.cpu.avx2 is False
                            else ""
                        ),
                    },
                    {
                        "label": "메모리",
                        "value": f"{snapshot.memory.percent:.1f}%",
                        "detail": f"{snapshot.memory.usedBytes} / {snapshot.memory.totalBytes} bytes",
                    },
                    {
                        "label": "가동 시간",
                        "value": f"{snapshot.uptimeSeconds:.0f}초",
                        "detail": "호스트 uptime",
                    },
                ]
                rows = [
                    {
                        "id": "os",
                        "name": "운영 체제",
                        "status": snapshot.osName or "Linux",
                        "detail": f"Kernel {snapshot.kernelVersion or '미보고'}",
                        "updatedAt": updated,
                    },
                    {
                        "id": "cpu",
                        "name": "CPU",
                        "status": f"{snapshot.cpu.percent:.1f}%",
                        "detail": f"Load {' / '.join(f'{value:.2f}' for value in snapshot.cpu.loadAverage)}",
                        "updatedAt": updated,
                    },
                    {
                        "id": "memory",
                        "name": "메모리",
                        "status": f"{snapshot.memory.percent:.1f}%",
                        "detail": f"{snapshot.memory.usedBytes} / {snapshot.memory.totalBytes} bytes",
                        "updatedAt": updated,
                    },
                    {
                        "id": "swap",
                        "name": "Swap",
                        "status": f"{snapshot.swap.percent:.1f}%",
                        "detail": f"{snapshot.swap.usedBytes} / {snapshot.swap.totalBytes} bytes",
                        "updatedAt": updated,
                    },
                    {
                        "id": "cpu-temperature",
                        "name": "CPU 온도",
                        "status": (
                            f"{max(snapshot.sensors.cpuTemperaturesCelsius):.1f}°C"
                            if snapshot.sensors.cpuTemperaturesCelsius
                            else "미보고"
                        ),
                        "detail": (
                            f"{len(snapshot.sensors.cpuTemperaturesCelsius)}개 센서"
                            if snapshot.sensors.cpuTemperaturesCelsius
                            else "CPU 온도 센서를 사용할 수 없습니다."
                        ),
                        "updatedAt": updated,
                    },
                    {
                        "id": "gpu",
                        "name": "GPU",
                        "status": snapshot.sensors.gpuName or "미보고",
                        "detail": (
                            f"{snapshot.sensors.gpuTemperatureCelsius:.1f}°C"
                            if snapshot.sensors.gpuTemperatureCelsius is not None
                            else "GPU 또는 온도 센서를 사용할 수 없습니다."
                        ),
                        "updatedAt": updated,
                    },
                    {
                        "id": "network",
                        "name": "네트워크",
                        "status": "connected",
                        "detail": f"↓ {snapshot.network.receivedBytesPerSecond:.1f} B/s · ↑ {snapshot.network.sentBytesPerSecond:.1f} B/s",
                        "updatedAt": updated,
                    },
                ]
                return {
                    "key": key,
                    "mode": "live",
                    "status": "connected",
                    "message": "제한된 /proc 파일과 읽기 전용 hwmon 센서에서 읽은 실제 호스트 지표",
                    "updatedAt": updated,
                    "metrics": metrics,
                    "columns": ["항목", "상태", "세부 정보", "갱신"],
                    "rows": rows,
                    "actions": [],
                }
            return {
                "key": key,
                "mode": "live",
                "status": "unavailable" if settings.host_agent_url else "not_configured",
                "message": "호스트 에이전트 응답 없음"
                if settings.host_agent_url
                else READ_ONLY_RESOURCE_MESSAGES[key],
                "updatedAt": iso_now(),
                "metrics": [],
                "columns": ["이름", "상태", "설명", "갱신"],
                "rows": [],
                "actions": [],
            }
        if key == "containers":
            return _container_resource(settings, portainer_containers(settings))
        return {
            "key": key,
            "mode": "live",
            "status": "not_configured",
            "message": READ_ONLY_RESOURCE_MESSAGES[key],
            "updatedAt": iso_now(),
            "metrics": [],
            "columns": ["이름", "상태", "설명", "갱신"],
            "rows": [],
            "actions": [],
        }

    entry = MOCK_RESOURCES.get(key)
    if not entry:
        return None
    label, rows = entry
    operations: list[tuple[str, str, str]] = []
    if key in {"services", "containers"}:
        operations = [("restart", "재시작", rows[0]["name"]), ("stop", "중지", rows[0]["name"])]
    elif key == "storage":
        operations = [("backup", "백업 시뮬레이션", rows[0]["name"])]
    elif key == "deployments":
        operations = [
            ("deploy", "배포 시뮬레이션", rows[0]["name"]),
            ("rollback", "롤백 시뮬레이션", rows[0]["name"]),
        ]
    actions = [
        {
            "id": operation,
            "label": label,
            "operation": operation,
            "target": target,
            "enabled": True,
            "reason": "개발 Mock에서만 시뮬레이션 가능",
        }
        for operation, label, target in operations
    ]
    return {
        "key": key,
        "mode": "mock" if settings.app_mode == "mock" else "live",
        "status": "connected",
        "message": f"{label} DEMO 데이터 · 실제 공급자 연결 없음",
        "updatedAt": iso_now(),
        "metrics": [
            {"label": "공급자", "value": "DEMO", "detail": "실제 연결 없음"},
            {"label": "항목", "value": str(len(rows)), "detail": "모의 데이터"},
            {"label": "환경", "value": "Mock", "detail": "개발 전용"},
            {"label": "갱신", "value": datetime.now(UTC).strftime("%H:%M"), "detail": "API 응답"},
        ],
        "columns": ["이름", "상태", "설명", "갱신"],
        "rows": rows,
        "actions": actions,
    }
