import asyncio
import hashlib
import json
import re
from contextlib import asynccontextmanager, suppress
from datetime import UTC, datetime
from uuid import uuid4

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, StreamingResponse

from app import passkeys
from app.auth import Identity, current_identity, require_role
from app.body_limit import RequestBodyLimitMiddleware
from app.dns_actions import dns_action_label, dns_action_scope, validate_dns_change
from app.notifications import run_notification_loop
from app.providers import (
    cloudflare_dns_mutation,
    cloudflare_dns_record_matches,
    container_logs,
    overview,
    portainer_container_action,
    portainer_container_stats,
    portainer_containers,
    resource,
)
from app.rate_limit import RequestRateLimiter
from app.schemas import (
    AuditEvent,
    ContainerLogsResponse,
    ContainerStatsResponse,
    DeletePasskeyRequest,
    JobRequest,
    JobResponse,
    OverviewResponse,
    PasskeyStatus,
    ReauthGrantResponse,
    ReauthOptionsRequest,
    ReauthOptionsResponse,
    ReauthVerifyRequest,
    RegistrationOptionsRequest,
    RegistrationVerifyRequest,
    RegistrationVerifyResponse,
    ResourceResponse,
)
from app.settings import Settings
from app.store import (
    begin_live_job,
    consume_reauth_grant,
    finish_live_job,
    get_job,
    initialize,
    list_audit,
    list_jobs,
    prune_history,
    record_simulated_job,
)

RESOURCE_KEYS = {
    "services",
    "notifications",
    "system",
    "automation",
    "domains",
    "mail",
    "database",
    "storage",
    "monitoring",
    "security",
    "settings",
    "containers",
    "images",
    "stacks",
    "deployments",
}
_CONTAINER_ACTIONS = {"start", "stop", "restart"}
_DNS_ACTIONS = {"dns_create", "dns_update", "dns_delete"}
STREAM_MAX_AGE_SECONDS = 60


def _container_action_target(settings: Settings, operation: str, container_id: str):
    if not settings.portainer_actions_api_key.get_secret_value():
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Portainer control is not configured")
    if not re.fullmatch(r"[0-9a-fA-F]{12,64}", container_id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Container not found")
    containers = portainer_containers(settings)
    if containers is None:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Portainer container list unavailable")
    container = next((item for item in containers if item.Id.lower() == container_id.lower()), None)
    if container is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Container not found")
    allowed = container.State == "running" if operation in {"stop", "restart"} else container.State in {"created", "exited"}
    if not allowed:
        raise HTTPException(status.HTTP_409_CONFLICT, "Container state changed; refresh before retrying")
    return container


def _dns_action_target(settings: Settings, operation: str, target: str, change):
    normalized = validate_dns_change(settings, operation, change)
    expected_target = normalized.recordId or "zone"
    if target.lower() != expected_target.lower():
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "DNS action target does not match its payload")
    if normalized.before:
        current_matches = cloudflare_dns_record_matches(
            settings, normalized.recordId, normalized.before
        )
        if current_matches is None:
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Cloudflare DNS record could not be verified")
        if not current_matches:
            raise HTTPException(status.HTTP_409_CONFLICT, "DNS record changed since it was loaded")
    return normalized


def rate_limited_identity(
    request: Request, identity: Identity = Depends(current_identity)
) -> Identity:
    if request.app.state.settings.app_mode == "live":
        request.app.state.rate_limiter.check(identity.subject)
    return identity


def create_app(settings: Settings | None = None) -> FastAPI:
    config = settings or Settings()

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        initialize(config.app_data_dir)
        prune_history(config.app_data_dir, config.audit_retention_days)
        notification_task = (
            asyncio.create_task(run_notification_loop(config, config.app_data_dir))
            if config.app_mode == "live" and config.ntfy_url
            else None
        )
        try:
            yield
        finally:
            if notification_task is not None:
                notification_task.cancel()
                with suppress(asyncio.CancelledError):
                    await notification_task

    application = FastAPI(
        title="HomeServer Admin API",
        version="0.1.0",
        docs_url="/docs" if config.app_env == "development" else None,
        redoc_url=None,
        lifespan=lifespan,
    )
    application.add_middleware(RequestBodyLimitMiddleware, max_bytes=65_536)
    application.state.settings = config
    application.state.rate_limiter = RequestRateLimiter()
    application.state.stream_slots = asyncio.Semaphore(32)
    application.state.stream_subjects = {}

    @application.exception_handler(RequestValidationError)
    async def validation_error_response(_: Request, __: RequestValidationError):
        return JSONResponse(status_code=422, content={"detail": "Invalid request"})

    @application.get("/health", include_in_schema=False)
    def health():
        return {"status": "ok"}

    def overview_payload() -> dict:
        result = overview(config)
        events = list_audit(config.app_data_dir, 5)
        if events:
            result["activity"] = [
                {
                    "id": event["id"],
                    "kind": "action",
                    "title": f"{event['operation']} · {event['result']}",
                    "detail": f"{event['target']} · {event['result']}",
                    "createdAt": event["created_at"],
                }
                for event in events
            ] + result["activity"][:2]
        return result

    def container_logs_payload(container_id: str, tail: int) -> dict:
        if config.app_mode == "mock":
            if container_id != "container":
                raise HTTPException(status.HTTP_404_NOT_FOUND, "Container not found")
            return {
                "mode": "mock",
                "id": container_id,
                "tail": tail,
                "logs": "2026-11-09T12:00:00Z DEMO · 컨테이너가 시작되었습니다.\n2026-11-09T12:00:01Z DEMO · 실제 로그가 아닙니다.\n",
                "updatedAt": datetime.now(UTC),
            }
        if not re.fullmatch(r"[0-9a-fA-F]{12,64}", container_id):
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Container not found")
        logs = container_logs(config, container_id, tail)
        if logs is None:
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Container logs unavailable")
        return {
            "mode": "live",
            "id": container_id,
            "tail": tail,
            "logs": logs,
            "updatedAt": datetime.now(UTC),
        }

    def container_stats_payload(container_id: str) -> dict:
        if config.app_mode == "mock":
            if container_id != "container":
                raise HTTPException(status.HTTP_404_NOT_FOUND, "Container not found")
            return {
                "mode": "mock",
                "id": container_id,
                "status": "connected",
                "cpuPercent": 3.2,
                "memoryUsedBytes": 44_040_192,
                "memoryLimitBytes": 268_435_456,
                "memoryPercent": 16.4,
                "message": "DEMO 통계 · 실제 컨테이너 사용량이 아닙니다.",
                "updatedAt": datetime.now(UTC),
            }
        if not re.fullmatch(r"[0-9a-fA-F]{12,64}", container_id):
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Container not found")
        stats = portainer_container_stats(config, container_id)
        return {
            "mode": "live",
            "id": container_id,
            "status": "connected" if stats else "unavailable" if config.portainer_url else "not_configured",
            **(stats or {}),
            "message": "Portainer Docker stats" if stats else "컨테이너 통계를 조회할 수 없습니다.",
            "updatedAt": datetime.now(UTC),
        }

    async def acquire_stream_slot(subject: str) -> None:
        try:
            await asyncio.wait_for(application.state.stream_slots.acquire(), timeout=0.1)
        except TimeoutError as error:
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Stream capacity reached") from error
        active = application.state.stream_subjects.get(subject, 0)
        if active >= 4:
            application.state.stream_slots.release()
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Stream capacity reached")
        application.state.stream_subjects[subject] = active + 1

    def release_stream_slot(subject: str) -> None:
        active = application.state.stream_subjects[subject]
        if active == 1:
            del application.state.stream_subjects[subject]
        else:
            application.state.stream_subjects[subject] = active - 1
        application.state.stream_slots.release()

    async def stream_read(source, deadline: float):
        remaining = deadline - asyncio.get_running_loop().time()
        if remaining <= 0:
            return None
        try:
            return await asyncio.wait_for(asyncio.to_thread(source), timeout=remaining)
        except TimeoutError:
            return None

    @application.get("/api/v1/metrics/overview", response_model=OverviewResponse)
    def get_overview(_: Identity = Depends(rate_limited_identity)):
        return overview_payload()

    @application.get("/api/v1/metrics/overview/stream", include_in_schema=False)
    async def stream_overview(
        request: Request, identity: Identity = Depends(rate_limited_identity)
    ):
        await acquire_stream_slot(identity.subject)

        async def events():
            loop = asyncio.get_running_loop()
            deadline = loop.time() + STREAM_MAX_AGE_SECONDS
            try:
                yield "retry: 3000\n\n"
                for interval in range(6):
                    if await request.is_disconnected():
                        break
                    payload = await stream_read(overview_payload, deadline)
                    if payload is None:
                        break
                    data = OverviewResponse.model_validate(payload).model_dump_json()
                    yield f"data: {data}\n\n"
                    if interval < 5:
                        await asyncio.sleep(min(10, max(0, deadline - loop.time())))
            finally:
                release_stream_slot(identity.subject)

        return StreamingResponse(
            events(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache, no-transform", "X-Accel-Buffering": "no"},
        )

    @application.get("/api/v1/resources/{key}", response_model=ResourceResponse)
    def get_resource(key: str, identity: Identity = Depends(rate_limited_identity)):
        if key not in RESOURCE_KEYS:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Resource not found")
        if key == "mail":
            require_role(identity, "owner", "operator")
        result = resource(key, config)
        if result is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Resource not found")
        if key == "containers" and identity.role not in {"owner", "operator"}:
            for row in result["rows"]:
                for action in row.get("actions", []):
                    action["enabled"] = False
                    action["reason"] = "Owner 또는 Operator 권한이 필요합니다."
        if key in {"security", "notifications"}:
            events = list_audit(config.app_data_dir, 50)
            if events:
                audit_rows = [
                    {
                        "id": event["id"],
                        "name": (
                            event["actor"]
                            if key == "security"
                            else f"관리 작업 · {event['actor']}"
                        ),
                        "status": event["result"],
                        "detail": f"{event['operation']} · {event['target']}",
                        "updatedAt": event["created_at"],
                    }
                    for event in events
                ]
                if key == "security":
                    result["columns"] = ["작업자", "결과", "작업 · 대상", "시간"]
                    result["rows"] = audit_rows
                else:
                    result["rows"] = sorted(
                        [*result["rows"], *audit_rows],
                        key=lambda row: row["updatedAt"],
                        reverse=True,
                    )
        if key == "security" and config.app_mode == "live":
            result["status"] = "partial"
            result["message"] = (
                "Cloudflare Access JWT와 계정 Passkey는 API에서 검증합니다. Live 서버 작업은 제한 실행기가 검증될 때까지 차단됩니다."
            )
        return result

    @application.get("/api/v1/containers/{container_id}/logs", response_model=ContainerLogsResponse)
    def get_container_logs(
        container_id: str,
        tail: int = Query(default=200, ge=1, le=500),
        identity: Identity = Depends(rate_limited_identity),
    ):
        if config.app_mode == "live":
            require_role(identity, "owner", "operator")
        return container_logs_payload(container_id, tail)

    @application.get("/api/v1/containers/{container_id}/stats", response_model=ContainerStatsResponse)
    def get_container_stats(
        container_id: str, _: Identity = Depends(rate_limited_identity)
    ):
        return container_stats_payload(container_id)

    @application.get(
        "/api/v1/containers/{container_id}/logs/stream", include_in_schema=False
    )
    async def stream_container_logs(
        container_id: str,
        request: Request,
        tail: int = Query(default=200, ge=1, le=500),
        identity: Identity = Depends(rate_limited_identity),
    ):
        if config.app_mode == "live":
            require_role(identity, "owner", "operator")
            if not re.fullmatch(r"[0-9a-fA-F]{12,64}", container_id):
                raise HTTPException(status.HTTP_404_NOT_FOUND, "Container not found")
        elif container_id != "container":
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Container not found")
        await acquire_stream_slot(identity.subject)

        async def events():
            loop = asyncio.get_running_loop()
            deadline = loop.time() + STREAM_MAX_AGE_SECONDS
            try:
                yield "retry: 3000\n\n"
                previous_logs = None
                for interval in range(20):
                    if await request.is_disconnected():
                        break
                    payload = await stream_read(
                        lambda: container_logs_payload(container_id, tail), deadline
                    )
                    if payload is None:
                        break
                    data = ContainerLogsResponse.model_validate(payload).model_dump_json()
                    if payload["logs"] != previous_logs:
                        yield f"data: {data}\n\n"
                        previous_logs = payload["logs"]
                    elif interval % 5 == 0:
                        yield ": keep-alive\n\n"
                    if interval < 19:
                        await asyncio.sleep(min(3, max(0, deadline - loop.time())))
            finally:
                release_stream_slot(identity.subject)

        return StreamingResponse(
            events(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache, no-transform", "X-Accel-Buffering": "no"},
        )

    @application.get("/api/v1/audit", response_model=list[AuditEvent])
    def get_audit(
        limit: int = Query(default=50, ge=1, le=100), _: Identity = Depends(rate_limited_identity)
    ):
        return list_audit(config.app_data_dir, limit)

    @application.get("/api/v1/webauthn/status", response_model=PasskeyStatus)
    def get_passkey_status(
        response: Response, identity: Identity = Depends(rate_limited_identity)
    ):
        response.headers["Cache-Control"] = "no-store"
        return passkeys.status_for(config.app_data_dir, identity.subject)

    @application.post(
        "/api/v1/webauthn/reauth/options", response_model=ReauthOptionsResponse
    )
    def get_reauthentication_options(
        payload: ReauthOptionsRequest,
        request: Request,
        response: Response,
        identity: Identity = Depends(rate_limited_identity),
    ):
        _require_verified_origin(request)
        response.headers["Cache-Control"] = "no-store"
        if payload.operation in _CONTAINER_ACTIONS:
            require_role(identity, "owner", "operator")
            if config.app_env != "production" or config.app_mode != "live":
                raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Live container actions require production mode")
            _container_action_target(config, payload.operation, payload.target)
        elif payload.operation in _DNS_ACTIONS:
            require_role(identity, "owner")
            if config.app_env != "production" or config.app_mode != "live":
                raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Live DNS actions require production mode")
            change = _dns_action_target(
                config, payload.operation, payload.target, payload.dnsChange
            )
            payload.target = dns_action_scope(payload.operation, change)
        return passkeys.begin_reauthentication(
            config,
            config.app_data_dir,
            identity.subject,
            payload.operation,
            payload.target,
        )

    @application.post(
        "/api/v1/webauthn/reauth/verify", response_model=ReauthGrantResponse
    )
    def verify_reauthentication(
        payload: ReauthVerifyRequest,
        request: Request,
        response: Response,
        identity: Identity = Depends(rate_limited_identity),
    ):
        _require_verified_origin(request)
        response.headers["Cache-Control"] = "no-store"
        return {
            "grant": passkeys.finish_reauthentication(
                config,
                config.app_data_dir,
                identity.subject,
                payload.challengeId,
                payload.credential,
            )
        }

    @application.post(
        "/api/v1/webauthn/register/options", response_model=ReauthOptionsResponse
    )
    def get_registration_options(
        payload: RegistrationOptionsRequest,
        request: Request,
        response: Response,
        identity: Identity = Depends(rate_limited_identity),
    ):
        _require_verified_origin(request)
        response.headers["Cache-Control"] = "no-store"
        return passkeys.begin_registration(
            config,
            config.app_data_dir,
            identity,
            payload.name,
            payload.bootstrapToken.get_secret_value() if payload.bootstrapToken else None,
            payload.reauthGrant.get_secret_value() if payload.reauthGrant else None,
        )

    @application.post(
        "/api/v1/webauthn/register/verify", response_model=RegistrationVerifyResponse
    )
    def verify_registration(
        payload: RegistrationVerifyRequest,
        request: Request,
        response: Response,
        identity: Identity = Depends(rate_limited_identity),
    ):
        _require_verified_origin(request)
        response.headers["Cache-Control"] = "no-store"
        passkey = passkeys.finish_registration(
            config,
            config.app_data_dir,
            identity.subject,
            identity.email or identity.subject,
            payload.challengeId,
            payload.credential,
        )
        return {"passkey": passkey}

    @application.post("/api/v1/webauthn/passkeys/delete", status_code=status.HTTP_204_NO_CONTENT)
    def delete_registered_passkey(
        payload: DeletePasskeyRequest,
        request: Request,
        response: Response,
        identity: Identity = Depends(rate_limited_identity),
    ):
        _require_verified_origin(request)
        response.headers["Cache-Control"] = "no-store"
        passkeys.remove_passkey(
            config.app_data_dir,
            identity.subject,
            identity.email or identity.subject,
            payload.credentialId,
            payload.reauthGrant.get_secret_value(),
        )
        return Response(status_code=status.HTTP_204_NO_CONTENT, headers={"Cache-Control": "no-store"})

    @application.get("/api/v1/jobs", response_model=list[JobResponse])
    def get_jobs(
        limit: int = Query(default=50, ge=1, le=100), _: Identity = Depends(rate_limited_identity)
    ):
        return list_jobs(config.app_data_dir, limit)

    @application.get("/api/v1/jobs/{job_id}", response_model=JobResponse)
    def get_job_status(job_id: str, _: Identity = Depends(rate_limited_identity)):
        result = get_job(config.app_data_dir, job_id)
        if result is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Job not found")
        return result

    @application.post(
        "/api/v1/jobs", response_model=JobResponse, status_code=status.HTTP_201_CREATED
    )
    def create_job(
        payload: JobRequest, request: Request, identity: Identity = Depends(rate_limited_identity)
    ):
        if request.headers.get("x-hs-origin-verified") != "1":
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Same-origin verification required")
        if config.app_env == "development" and config.app_mode == "mock":
            if payload.operation in {"reboot", "shutdown", "deploy", "rollback", "backup"} | _DNS_ACTIONS:
                require_role(identity, "owner")
            else:
                require_role(identity, "owner", "operator")
            job = {
                "id": str(uuid4()),
                "operation": payload.operation,
                "target": dns_action_label(payload.operation, payload.dnsChange)
                if payload.operation in _DNS_ACTIONS
                else payload.target,
                "state": "succeeded",
                "simulation": True,
                "message": "시뮬레이션만 완료했습니다. 호스트 명령은 실행하지 않았습니다.",
                "createdAt": datetime.now(UTC).isoformat(),
            }
            details = ""
            if payload.operation in _DNS_ACTIONS and payload.dnsChange:
                details = json.dumps(
                    {
                        "before": payload.dnsChange.before.model_dump(mode="json")
                        if payload.dnsChange.before
                        else None,
                        "after": payload.dnsChange.after.model_dump(mode="json")
                        if payload.dnsChange.after
                        else None,
                    },
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
            record_simulated_job(
                job, identity.email or identity.subject, config.app_data_dir, details
            )
            return job
        if payload.operation in _CONTAINER_ACTIONS:
            require_role(identity, "owner", "operator")
            if config.app_env != "production" or config.app_mode != "live":
                raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Live container actions require production mode")
            _container_action_target(config, payload.operation, payload.target)
            grant = payload.reauthGrant.get_secret_value() if payload.reauthGrant else ""
            if not grant or not consume_reauth_grant(
                config.app_data_dir,
                hashlib.sha256(grant.encode()).hexdigest(),
                identity.subject,
                payload.operation,
                payload.target,
                datetime.now(UTC).timestamp(),
            ):
                raise HTTPException(status.HTTP_403_FORBIDDEN, "Fresh Passkey verification required")
            job = {
                "id": str(uuid4()),
                "operation": payload.operation,
                "target": payload.target,
                "state": "running",
                "simulation": False,
                "message": "Portainer 작업 요청 중",
                "createdAt": datetime.now(UTC).isoformat(),
            }
            begin_live_job(job, identity.email or identity.subject, config.app_data_dir)
            outcome = portainer_container_action(config, payload.target, payload.operation)
            job["state"] = "succeeded" if outcome is True else "failed" if outcome is False else "unknown"
            job["message"] = (
                "Portainer가 작업 요청을 수락했습니다. 실제 서비스 상태는 Live 목록에서 확인하세요."
                if outcome is True
                else "Portainer가 작업을 거부했습니다. Live 상태를 확인하세요."
                if outcome is False
                else "응답을 받지 못해 결과가 불명확합니다. 재시도 전에 Live 상태를 확인하세요."
            )
            finish_live_job(job, config.app_data_dir)
            return job
        if payload.operation in _DNS_ACTIONS:
            require_role(identity, "owner")
            if config.app_env != "production" or config.app_mode != "live":
                raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Live DNS actions require production mode")
            change = _dns_action_target(
                config, payload.operation, payload.target, payload.dnsChange
            )
            grant = payload.reauthGrant.get_secret_value() if payload.reauthGrant else ""
            if not grant or not consume_reauth_grant(
                config.app_data_dir,
                hashlib.sha256(grant.encode()).hexdigest(),
                identity.subject,
                payload.operation,
                dns_action_scope(payload.operation, change),
                datetime.now(UTC).timestamp(),
            ):
                raise HTTPException(status.HTTP_403_FORBIDDEN, "Fresh Passkey verification required")
            target = dns_action_label(payload.operation, change)
            details = json.dumps(
                {
                    "before": change.before.model_dump(mode="json") if change.before else None,
                    "after": change.after.model_dump(mode="json") if change.after else None,
                    "recordId": change.recordId,
                },
                ensure_ascii=False,
                separators=(",", ":"),
            )
            job = {
                "id": str(uuid4()),
                "operation": payload.operation,
                "target": target,
                "state": "running",
                "simulation": False,
                "message": "Cloudflare DNS change requested",
                "createdAt": datetime.now(UTC).isoformat(),
            }
            begin_live_job(
                job, identity.email or identity.subject, config.app_data_dir, details
            )
            outcome, result = cloudflare_dns_mutation(config, payload.operation, change)
            job["state"] = "succeeded" if outcome is True else "failed" if outcome is False else "unknown"
            if outcome is True and result:
                details = json.dumps(
                    {
                        "before": change.before.model_dump(mode="json") if change.before else None,
                        "after": change.after.model_dump(mode="json") if change.after else None,
                        "result": result,
                    },
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
            job["message"] = (
                "Cloudflare accepted the DNS change; verify the resolved record before further edits."
                if outcome is True
                else "Cloudflare rejected the DNS change."
                if outcome is False
                else "Cloudflare response was unavailable; inspect DNS before retrying."
            )
            finish_live_job(job, config.app_data_dir, details)
            return job
        if config.app_env != "development" or config.app_mode != "mock":
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                "Live host operation is not configured; job blocked",
            )
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Live host operation is blocked")

    return application


def _require_verified_origin(request: Request) -> None:
    if request.headers.get("x-hs-origin-verified") != "1":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Same-origin verification required")


app = create_app()
