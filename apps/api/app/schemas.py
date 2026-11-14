from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, SecretStr, model_validator

JobOperation = Literal[
    "restart", "start", "stop", "backup", "deploy", "rollback", "reboot", "shutdown",
    "dns_create", "dns_update", "dns_delete",
]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class DnsRecordValue(StrictModel):
    name: str = Field(min_length=1, max_length=255)
    type: Literal["A", "AAAA", "CNAME", "TXT", "MX"]
    content: str = Field(min_length=1, max_length=2048)
    ttl: int = Field(ge=1, le=86_400)
    proxied: bool = False
    priority: int | None = Field(default=None, ge=0, le=65_535)

    @model_validator(mode="after")
    def validate_record_fields(self):
        if self.ttl != 1 and self.ttl < 30:
            raise ValueError("DNS TTL must be automatic or at least 30 seconds")
        if (self.type == "MX") != (self.priority is not None):
            raise ValueError("Only MX records require a priority")
        if self.proxied and self.type not in {"A", "AAAA", "CNAME"}:
            raise ValueError("Only A, AAAA, and CNAME records can be proxied")
        return self


class DnsRecordChange(StrictModel):
    recordId: str | None = Field(default=None, pattern=r"^[0-9a-fA-F]{32}$")
    before: DnsRecordValue | None = None
    after: DnsRecordValue | None = None


class JobRequest(StrictModel):
    operation: JobOperation
    target: str = Field(min_length=1, max_length=128, pattern=r"^[^\x00-\x1f\x7f]+$")
    reauthGrant: SecretStr | None = Field(default=None, min_length=32, max_length=128)
    dnsChange: DnsRecordChange | None = None

    @model_validator(mode="after")
    def validate_dns_change(self):
        is_dns = self.operation.startswith("dns_")
        if is_dns != (self.dnsChange is not None):
            raise ValueError("DNS operations require a DNS change payload")
        return self


class PasskeyItem(StrictModel):
    id: str = Field(min_length=1, max_length=1024)
    name: str = Field(min_length=1, max_length=64)
    createdAt: datetime


class PasskeyStatus(StrictModel):
    passkeys: list[PasskeyItem]
    bootstrapRequired: bool


class ReauthOptionsRequest(StrictModel):
    operation: Literal[
        "register_passkey", "delete_passkey", "start", "stop", "restart",
        "dns_create", "dns_update", "dns_delete",
    ]
    target: str = Field(min_length=1, max_length=1024, pattern=r"^[A-Za-z0-9_-]+$")
    dnsChange: DnsRecordChange | None = None

    @model_validator(mode="after")
    def validate_dns_scope(self):
        if self.operation.startswith("dns_") != (self.dnsChange is not None):
            raise ValueError("DNS reauthentication requires a DNS change payload")
        return self


class ReauthVerifyRequest(StrictModel):
    challengeId: str = Field(pattern=r"^[0-9a-f-]{36}$")
    credential: dict[str, Any]


class ReauthOptionsResponse(StrictModel):
    challengeId: str
    options: dict[str, Any]


class ReauthGrantResponse(StrictModel):
    grant: str


class RegistrationOptionsRequest(StrictModel):
    name: str = Field(min_length=1, max_length=64, pattern=r"^[^\x00-\x1f\x7f]+$")
    bootstrapToken: SecretStr | None = Field(default=None, min_length=64, max_length=64)
    reauthGrant: SecretStr | None = Field(default=None, min_length=32, max_length=128)


class RegistrationVerifyRequest(StrictModel):
    challengeId: str = Field(pattern=r"^[0-9a-f-]{36}$")
    credential: dict[str, Any]


class RegistrationVerifyResponse(StrictModel):
    passkey: PasskeyItem


class DeletePasskeyRequest(StrictModel):
    credentialId: str = Field(min_length=1, max_length=1024, pattern=r"^[A-Za-z0-9_-]+$")
    reauthGrant: SecretStr = Field(min_length=32, max_length=128)


class JobResponse(StrictModel):
    id: str
    operation: JobOperation
    target: str
    state: Literal["queued", "running", "succeeded", "failed", "unknown"]
    simulation: bool
    message: str
    createdAt: datetime


class StorageItem(StrictModel):
    name: str = Field(min_length=1, max_length=80)
    device: str = Field(min_length=1, max_length=256)
    mount: str = Field(min_length=1, max_length=512)
    fileSystem: str = Field(min_length=1, max_length=32)
    usedBytes: float = Field(ge=0)
    totalBytes: float = Field(gt=0)
    percent: float = Field(ge=0, le=100)
    health: Literal["healthy", "warning", "not_reported"]


class HistoryPoint(StrictModel):
    time: str
    cpu: float
    memory: float


class ServiceItem(StrictModel):
    name: str
    status: Literal["healthy", "warning", "failed", "stopped", "not_configured"]
    detail: str
    checkedAt: datetime


class CpuMetrics(StrictModel):
    percent: float
    cores: list[float]
    loadAverage: list[float]
    modelName: str | None = Field(default=None, max_length=256)
    physicalCores: int | None = Field(default=None, ge=1)
    avx2: bool | None = None


class MemoryMetrics(StrictModel):
    usedBytes: float
    totalBytes: float
    percent: float


class NetworkMetrics(StrictModel):
    receivedBytesPerSecond: float
    sentBytesPerSecond: float


class SensorMetrics(StrictModel):
    cpuTemperaturesCelsius: list[Annotated[float, Field(ge=-40, le=150)]] = Field(
        default_factory=list, max_length=64
    )
    gpuName: str | None = Field(default=None, max_length=64)
    gpuTemperatureCelsius: float | None = Field(default=None, ge=-40, le=150)


class HostSnapshot(StrictModel):
    serverName: str = Field(min_length=1, max_length=128)
    osName: str | None = Field(default=None, max_length=128)
    kernelVersion: str | None = Field(default=None, max_length=128)
    updatedAt: datetime
    uptimeSeconds: float = Field(ge=0)
    cpu: CpuMetrics
    memory: MemoryMetrics
    swap: MemoryMetrics
    network: NetworkMetrics
    sensors: SensorMetrics = Field(default_factory=SensorMetrics)
    storage: list[StorageItem] = Field(default_factory=list, max_length=2)
    history: list[HistoryPoint]


class DockerMetrics(StrictModel):
    status: Literal["connected", "not_configured", "unavailable"]
    running: int
    total: int
    message: str


class ActivityItem(StrictModel):
    id: str
    kind: Literal["deployment", "alert", "action", "security"]
    title: str
    detail: str
    createdAt: datetime


class OverviewResponse(StrictModel):
    mode: Literal["mock", "live"]
    status: Literal["connected", "not_configured", "unavailable"]
    serverName: str
    updatedAt: datetime
    uptimeSeconds: float
    cpu: CpuMetrics
    memory: MemoryMetrics
    swap: MemoryMetrics
    storage: list[StorageItem]
    network: NetworkMetrics
    docker: DockerMetrics
    history: list[HistoryPoint]
    services: list[ServiceItem]
    activity: list[ActivityItem]


class MetricItem(StrictModel):
    label: str
    value: str
    detail: str


class ResourceAction(StrictModel):
    id: str
    label: str
    operation: JobOperation
    target: str
    targetLabel: str | None = Field(default=None, max_length=128)
    enabled: bool
    reason: str


class ResourceRow(StrictModel):
    id: str
    name: str
    status: str
    detail: str
    updatedAt: datetime
    actions: list[ResourceAction] = Field(default_factory=list)
    dnsRecord: DnsRecordValue | None = None


class ResourceResponse(StrictModel):
    key: str
    mode: Literal["mock", "live"]
    status: Literal["connected", "partial", "not_configured", "unavailable"]
    message: str
    updatedAt: datetime
    metrics: list[MetricItem]
    columns: list[str]
    rows: list[ResourceRow]
    actions: list[ResourceAction]
    writeEnabled: bool = False


class ContainerLogsResponse(StrictModel):
    mode: Literal["mock", "live"]
    id: str
    tail: int = Field(ge=1, le=500)
    logs: str = Field(max_length=1_048_576)
    updatedAt: datetime


class ContainerStatsResponse(StrictModel):
    mode: Literal["mock", "live"]
    id: str
    status: Literal["connected", "not_configured", "unavailable"]
    cpuPercent: float | None = Field(default=None, ge=0, le=100_000)
    memoryUsedBytes: float | None = Field(default=None, ge=0)
    memoryLimitBytes: float | None = Field(default=None, ge=0)
    memoryPercent: float | None = Field(default=None, ge=0, le=100)
    message: str
    updatedAt: datetime


class AuditEvent(StrictModel):
    id: str
    actor: str
    operation: str
    target: str
    result: str
    created_at: datetime
    details: str = ""
