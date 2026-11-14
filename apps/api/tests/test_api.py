import asyncio
import hashlib
import json
from contextlib import nullcontext
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer
from io import BytesIO
from threading import Event, Thread
from time import time
from types import SimpleNamespace
from unittest.mock import patch
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlsplit
from urllib.request import Request

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

import app.auth as auth
import app.notifications as notifications
import app.providers as providers
from app.auth import Identity, current_identity, resolve_role
from app.main import create_app
from app.rate_limit import RequestRateLimiter
from app.schemas import OverviewResponse, ResourceResponse
from app.settings import Settings
from app.store import (
    begin_live_job,
    initialize,
    list_audit,
    list_jobs,
    list_notification_alerts,
    record_simulated_job,
    store_reauth_grant,
)


@pytest.fixture(autouse=True)
def configured_web_origin(monkeypatch):
    monkeypatch.setenv("WEB_ORIGIN", "https://dashboard.heonhwi.dev")


def test_production_rejects_mock_mode(tmp_path):
    with pytest.raises(ValueError, match="Mock mode is allowed only in development"):
        Settings(app_env="production", app_mode="mock", app_data_dir=tmp_path)


def test_swagger_ui_is_enabled_only_in_development(tmp_path):
    development = create_app(Settings(app_data_dir=tmp_path / "development"))
    production = create_app(
        Settings(
            app_env="production",
            app_mode="live",
            app_data_dir=tmp_path / "production",
            web_origin="https://dashboard.example.com",
            cf_access_issuer="https://team.cloudflareaccess.com",
            cf_access_aud="audience",
        )
    )
    with TestClient(development) as client:
        assert client.get("/docs").status_code == 200
    with TestClient(production) as client:
        assert client.get("/docs").status_code == 404


def test_api_rejects_oversized_json_body_before_authentication(tmp_path):
    app = create_app(Settings(app_data_dir=tmp_path))
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/jobs",
            content=b"x" * 65_537,
            headers={"Content-Type": "application/json"},
        )
    assert response.status_code == 413
    assert response.json() == {"detail": "Request too large"}


def test_provider_response_reader_enforces_size_and_total_read_deadline():
    class MockSocket:
        def __init__(self):
            self.timeouts = []

        def settimeout(self, timeout):
            self.timeouts.append(timeout)

        def fileno(self):
            return 1

    class MockResponse:
        def __init__(self, sock, chunks):
            self.fp = SimpleNamespace(raw=SimpleNamespace(_sock=sock))
            self.chunks = iter(chunks)
            self.read_sizes = []

        def read1(self, size):
            self.read_sizes.append(size)
            return next(self.chunks)

    sock = MockSocket()
    response = MockResponse(sock, [b"abc", b"de"])
    clock = iter([10, 10, 10.5])
    with patch.object(providers, "monotonic", side_effect=lambda: next(clock)):
        assert providers._read_limited(response, 4, 2) == b"abcde"
    assert response.read_sizes == [5, 2]
    assert sock.timeouts == [2, 1.5]

    sock = MockSocket()
    response = MockResponse(sock, [b"a"])
    clock = iter([0, 0, 2])
    with patch.object(providers, "monotonic", side_effect=lambda: next(clock)):
        with pytest.raises(TimeoutError, match="read deadline"):
            providers._read_limited(response, 4, 2)


def test_provider_response_reader_handles_closed_and_open_urllib_sockets():
    for protocol in ("HTTP/1.0", "HTTP/1.1"):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                body = b'{"ok":true}'
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_):
                pass

        Handler.protocol_version = protocol
        server = HTTPServer(("127.0.0.1", 0), Handler)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            request = Request(f"http://127.0.0.1:{server.server_port}/")
            with providers._AGENT_OPENER.open(request, timeout=2) as response:
                assert providers._read_limited(response, 100, 2) == b'{"ok":true}'
        finally:
            server.shutdown()
            thread.join()
            server.server_close()


def test_audit_retention_days_are_bounded(tmp_path):
    assert Settings(app_data_dir=tmp_path).audit_retention_days == 365
    with pytest.raises(ValueError):
        Settings(app_data_dir=tmp_path, audit_retention_days=0)


def test_live_requires_access_config(tmp_path):
    with pytest.raises(ValueError, match="CF_ACCESS_ISSUER and CF_ACCESS_AUD"):
        Settings(app_env="production", app_mode="live", app_data_dir=tmp_path)


def test_jwks_must_match_access_issuer(tmp_path):
    with pytest.raises(ValueError, match="must use the configured Access issuer"):
        Settings(
            app_env="production",
            app_mode="live",
            app_data_dir=tmp_path,
            cf_access_issuer="https://team.cloudflareaccess.com",
            cf_access_aud="aud",
            cf_access_jwks_url="https://attacker.example/cdn-cgi/access/certs",
        )


def test_host_agent_configuration_is_internal_and_authenticated(tmp_path):
    with pytest.raises(ValueError, match="must target the internal read-only agent"):
        Settings(
            app_data_dir=tmp_path,
            host_agent_url="http://attacker.example/v1/metrics",
            host_agent_token="a" * 64,
        )
    with pytest.raises(ValueError, match="must be configured together"):
        Settings(app_data_dir=tmp_path, host_agent_token="a" * 64)
    config = Settings(
        app_data_dir=tmp_path,
        host_agent_url="http://agent:9000/v1/metrics",
        host_agent_token="a" * 64,
    )
    assert "a" * 64 not in repr(config)


def test_automation_health_urls_allow_https_or_fixed_internal_services(tmp_path):
    config = Settings(
        app_data_dir=tmp_path,
        n8n_url="http://n8n:5678",
        openclaw_url="https://gateway.example",
    )
    assert config.n8n_url == "http://n8n:5678"
    assert config.openclaw_url == "https://gateway.example"
    with pytest.raises(ValueError, match="N8N_URL must use HTTPS"):
        Settings(app_data_dir=tmp_path, n8n_url="http://public.example:5678")
    with pytest.raises(ValueError, match="OPENCLAW_URL must use HTTPS"):
        Settings(app_data_dir=tmp_path, openclaw_url="https://gateway.example/path")


def test_netdata_configuration_is_private_and_token_is_bound_to_agent(tmp_path):
    with pytest.raises(ValueError, match="NETDATA_API_TOKEN requires NETDATA_URL"):
        Settings(app_data_dir=tmp_path, netdata_api_token="n" * 24)
    with pytest.raises(ValueError, match="NETDATA_URL must use HTTPS"):
        Settings(app_data_dir=tmp_path, netdata_url="http://public.example:19999")
    with pytest.raises(ValueError, match="NETDATA_API_TOKEN is invalid"):
        Settings(app_data_dir=tmp_path, netdata_url="http://netdata:19999", netdata_api_token="short")
    config = Settings(
        app_data_dir=tmp_path,
        netdata_url="http://netdata:19999",
        netdata_api_token="netdata-private-token-123456",
    )
    assert "netdata-private-token-123456" not in repr(config)


def test_scrutiny_url_requires_private_http_or_https(tmp_path):
    config = Settings(app_data_dir=tmp_path, scrutiny_url="http://scrutiny:8080")
    assert config.scrutiny_url == "http://scrutiny:8080"
    with pytest.raises(ValueError, match="SCRUTINY_URL must use HTTPS"):
        Settings(app_data_dir=tmp_path, scrutiny_url="http://public.example:8080")
    with pytest.raises(ValueError, match="SCRUTINY_URL must use HTTPS"):
        Settings(app_data_dir=tmp_path, scrutiny_url="https://scrutiny.example/path")


def test_n8n_api_key_is_optional_private_and_bound_to_n8n(tmp_path):
    with pytest.raises(ValueError, match="N8N_API_KEY requires N8N_URL"):
        Settings(app_data_dir=tmp_path, n8n_api_key="n" * 24)
    with pytest.raises(ValueError, match="N8N_API_KEY is invalid"):
        Settings(app_data_dir=tmp_path, n8n_url="http://n8n:5678", n8n_api_key="short")
    config = Settings(
        app_data_dir=tmp_path,
        n8n_url="http://n8n:5678",
        n8n_api_key="n8n-private-api-key-123456",
    )
    assert "n8n-private-api-key-123456" not in repr(config)


def test_portainer_configuration_requires_https_and_hides_api_key(tmp_path):
    with pytest.raises(ValueError, match="must use HTTPS"):
        Settings(
            app_data_dir=tmp_path,
            portainer_url="http://untrusted.example:9000",
            portainer_api_key="p" * 24,
            portainer_endpoint_id=1,
        )
    with pytest.raises(ValueError, match="configured together"):
        Settings(
            app_data_dir=tmp_path,
            portainer_url="https://portainer.example",
            portainer_api_key="p" * 24,
        )
    config = Settings(
        app_data_dir=tmp_path,
        portainer_url="https://portainer.example",
        portainer_api_key="p" * 24,
        portainer_endpoint_id=1,
    )
    assert "p" * 24 not in repr(config)
    with pytest.raises(ValueError, match="PORTAINER_ACTIONS_API_KEY is invalid"):
        Settings(
            app_data_dir=tmp_path,
            portainer_url="https://portainer.example",
            portainer_api_key="p" * 24,
            portainer_actions_api_key="a" * 24 + "\n",
            portainer_endpoint_id=1,
        )


def test_mailcow_configuration_requires_https_and_hides_api_key(tmp_path):
    with pytest.raises(ValueError, match="MAILCOW_URL and MAILCOW_API_KEY"):
        Settings(app_data_dir=tmp_path, mailcow_api_key="m" * 24)
    with pytest.raises(ValueError, match="HTTPS origin"):
        Settings(
            app_data_dir=tmp_path,
            mailcow_url="http://mailcow.example",
            mailcow_api_key="m" * 24,
        )
    config = Settings(
        app_data_dir=tmp_path,
        mailcow_url="https://mailcow.example",
        mailcow_api_key="m" * 24,
    )
    assert "m" * 24 not in repr(config)


def test_database_urls_are_validated_and_secrets_are_hidden(tmp_path):
    with pytest.raises(ValueError, match="PostgreSQL connection URL"):
        Settings(app_data_dir=tmp_path, postgres_url="https://db.example/app")
    with pytest.raises(ValueError, match="sslmode=verify-full"):
        Settings(
            app_data_dir=tmp_path,
            postgres_url="postgresql://report:secret@db.example/app",
        )
    for sslmode in ("prefer", "require", "disable"):
        with pytest.raises(ValueError, match="sslmode=verify-full"):
            Settings(
                app_data_dir=tmp_path,
                postgres_url=(
                    "postgresql://report:secret@db.example/app?sslmode=" + sslmode
                ),
            )
    with pytest.raises(ValueError, match="sslmode=verify-full"):
        Settings(
            app_data_dir=tmp_path,
            postgres_url=(
                "postgresql://report:secret@db.example/app"
                "?sslmode=verify-full&sslmode=disable"
            ),
        )
    for insecure_option in (
        "ssl=true",
        "requiressl=0",
        "service=unsafe",
        "SSLMODE=disable",
        "SSLmode=disable",
    ):
        with pytest.raises(ValueError, match="sslmode=verify-full"):
            Settings(
                app_data_dir=tmp_path,
                postgres_url=(
                    "postgresql://report:secret@db.example/app"
                    f"?sslmode=verify-full&{insecure_option}"
                ),
            )
    with pytest.raises(ValueError, match="Redis connection URL"):
        Settings(app_data_dir=tmp_path, redis_url="rediss://redis.example/0?ssl_cert_reqs=none")
    with pytest.raises(ValueError, match="must use rediss:// for remote hosts"):
        Settings(app_data_dir=tmp_path, redis_url="redis://redis.example/0")
    assert Settings(app_data_dir=tmp_path, redis_url="redis://redis:6379/0").redis_url
    config = Settings(
        app_data_dir=tmp_path,
        postgres_url=(
            "postgresql://report:pg-secret@db.example/app"
            "?sslmode=verify-full&sslrootcert=system"
        ),
        redis_url="rediss://report:redis-secret@redis.example/0",
    )
    assert "pg-secret" not in repr(config)
    assert "redis-secret" not in repr(config)


def test_ntfy_configuration_requires_safe_origin_and_hides_token(tmp_path):
    with pytest.raises(ValueError, match="configured together"):
        Settings(app_data_dir=tmp_path, ntfy_url="https://ntfy.example")
    with pytest.raises(ValueError, match="HTTPS or the internal ntfy service"):
        Settings(
            app_data_dir=tmp_path,
            ntfy_url="http://attacker.example",
            ntfy_topic="homeserver",
        )
    config = Settings(
        app_data_dir=tmp_path,
        ntfy_url="https://ntfy.example",
        ntfy_topic="homeserver_alerts",
        ntfy_token="ntfy-private-token-1234",
    )
    assert "ntfy-private-token-1234" not in repr(config)


def test_github_configuration_is_allowlisted_and_secret_is_hidden(tmp_path):
    with pytest.raises(ValueError, match="must be configured together"):
        Settings(app_data_dir=tmp_path, github_repositories="owner/repo")
    with pytest.raises(ValueError, match="valid owner/repo"):
        Settings(
            app_data_dir=tmp_path,
            github_api_token="g" * 40,
            github_repositories="https://api.github.com/owner/repo",
        )
    config = Settings(
        app_data_dir=tmp_path,
        github_api_token="g" * 40,
        github_repositories="HAHEONHWI/homeserver-admin",
    )
    assert config.github_repo_list == ["HAHEONHWI/homeserver-admin"]
    assert "g" * 40 not in repr(config)


def test_cloudflare_configuration_is_zone_scoped_and_secret_is_hidden(tmp_path):
    with pytest.raises(ValueError, match="must be configured together"):
        Settings(app_data_dir=tmp_path, cloudflare_zone_id="a" * 32)
    with pytest.raises(ValueError, match="32-character Zone ID"):
        Settings(
            app_data_dir=tmp_path,
            cloudflare_api_token="c" * 40,
            cloudflare_zone_id="not-a-zone-id",
        )
    config = Settings(
        app_data_dir=tmp_path,
        cloudflare_api_token="c" * 40,
        cloudflare_zone_id="a" * 32,
    )
    assert "c" * 40 not in repr(config)
    with pytest.raises(ValueError, match="DNS read config and CLOUDFLARE_ZONE_NAME"):
        Settings(
            app_data_dir=tmp_path,
            cloudflare_dns_write_token="w" * 24,
        )
    with pytest.raises(ValueError, match="must differ from the DNS read token"):
        Settings(
            app_data_dir=tmp_path,
            cloudflare_api_token="c" * 40,
            cloudflare_dns_write_token="c" * 40,
            cloudflare_zone_id="a" * 32,
            cloudflare_zone_name="example.com",
        )
    with pytest.raises(ValueError, match="DNS read config and CLOUDFLARE_ZONE_NAME"):
        Settings(
            app_data_dir=tmp_path,
            cloudflare_api_token="c" * 40,
            cloudflare_zone_id="a" * 32,
            cloudflare_dns_write_token="w" * 24,
        )
    writable = Settings(
        app_data_dir=tmp_path,
        cloudflare_api_token="c" * 40,
        cloudflare_dns_write_token="w" * 24,
        cloudflare_zone_id="a" * 32,
        cloudflare_zone_name="example.com",
    )
    assert "w" * 24 not in repr(writable)


def test_live_deployments_read_github_actions_without_exposing_token(tmp_path):
    now = "2026-11-09T12:30:00+00:00"
    payload = {
        "workflow_runs": [
            {
                "id": 42,
                "name": "CI",
                "display_title": "Update API adapter",
                "head_branch": "main",
                "head_sha": "a" * 40,
                "run_number": 7,
                "status": "completed",
                "conclusion": "success",
                "updated_at": now,
            }
        ]
    }

    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return None

        def read(self, _limit):
            return json.dumps(payload).encode()

    config = Settings(
        app_env="production",
        app_mode="live",
        app_data_dir=tmp_path,
        cf_access_issuer="https://team.cloudflareaccess.com",
        cf_access_aud="aud",
        github_api_token="g" * 40,
        github_repositories="HAHEONHWI/homeserver-admin",
    )
    app = create_app(config)
    app.dependency_overrides[current_identity] = lambda: Identity(
        "owner@example.com", "owner@example.com", "owner"
    )
    with patch.object(providers._AGENT_OPENER, "open", return_value=Response()) as open_api:
        with TestClient(app) as client:
            response = client.get("/api/v1/resources/deployments")

    assert response.status_code == 200
    result = response.json()
    request = open_api.call_args.args[0]
    assert request.full_url == (
        "https://api.github.com/repos/HAHEONHWI/homeserver-admin/actions/runs?per_page=5"
    )
    assert request.get_header("Authorization") == f"Bearer {'g' * 40}"
    assert result["status"] == "connected"
    assert result["rows"][0]["status"] == "success"
    assert result["rows"][0]["name"] == "HAHEONHWI/homeserver-admin · CI"
    assert result["actions"] == []
    assert "g" * 40 not in json.dumps(result, default=str)


def test_live_deployments_report_partial_github_failures(tmp_path):
    payload = {"workflow_runs": []}

    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return None

        def read(self, _limit):
            return json.dumps(payload).encode()

    config = Settings(
        app_env="production",
        app_mode="live",
        app_data_dir=tmp_path,
        cf_access_issuer="https://team.cloudflareaccess.com",
        cf_access_aud="aud",
        github_api_token="g" * 40,
        github_repositories="owner/available,owner/unavailable",
    )
    with patch.object(
        providers._AGENT_OPENER,
        "open",
        side_effect=[Response(), URLError("GitHub unavailable")],
    ):
        result = providers.resource("deployments", config)

    assert result["status"] == "partial"
    assert "owner/unavailable" in result["message"]
    assert result["rows"] == []


def test_live_domains_read_cloudflare_dns_without_exposing_token(tmp_path):
    zone_id = "a" * 32
    token = "c" * 40
    payload = {
        "success": True,
        "result": [
            {
                "id": "b" * 32,
                "name": "dashboard.example.com",
                "type": "A",
                "content": "192.0.2.10",
                "ttl": 1,
                "proxied": True,
                "proxiable": True,
                "modified_on": "2026-11-09T12:30:00Z",
            }
        ],
        "result_info": {"total_count": 1},
    }

    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return None

        def read(self, _limit):
            return json.dumps(payload).encode()

    config = Settings(
        app_env="production",
        app_mode="live",
        app_data_dir=tmp_path,
        cf_access_issuer="https://team.cloudflareaccess.com",
        cf_access_aud="aud",
        cloudflare_api_token=token,
        cloudflare_dns_write_token="w" * 24,
        cloudflare_zone_id=zone_id,
        cloudflare_zone_name="example.com",
    )
    app = create_app(config)
    app.dependency_overrides[current_identity] = lambda: Identity(
        "owner@example.com", "owner@example.com", "owner"
    )
    with patch.object(providers._AGENT_OPENER, "open", return_value=Response()) as open_api:
        with TestClient(app) as client:
            response = client.get("/api/v1/resources/domains")

    assert response.status_code == 200
    result = response.json()
    request = open_api.call_args.args[0]
    assert request.get_method() == "GET"
    assert request.full_url == (
        f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records?per_page=100"
    )
    assert request.get_header("Authorization") == f"Bearer {token}"
    assert result["status"] == "connected"
    assert result["rows"][0]["name"] == "dashboard.example.com"
    assert result["rows"][0]["status"] == "A · Proxied"
    assert result["rows"][0]["dnsRecord"] == {
        "name": "dashboard.example.com",
        "type": "A",
        "content": "192.0.2.10",
        "ttl": 1,
        "proxied": True,
        "priority": None,
    }
    assert result["writeEnabled"] is True
    assert result["actions"] == []
    assert token not in json.dumps(result)


def test_live_domains_mark_truncated_cloudflare_results_partial(tmp_path):
    payload = {"success": True, "result": [], "result_info": {"total_count": 101}}

    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return None

        def read(self, _limit):
            return json.dumps(payload).encode()

    config = Settings(
        app_env="production",
        app_mode="live",
        app_data_dir=tmp_path,
        cf_access_issuer="https://team.cloudflareaccess.com",
        cf_access_aud="aud",
        cloudflare_api_token="c" * 40,
        cloudflare_zone_id="a" * 32,
    )
    with patch.object(providers._AGENT_OPENER, "open", return_value=Response()):
        result = providers.resource("domains", config)

    assert result["status"] == "partial"
    assert "0/101" in result["message"]
    assert result["actions"] == []


def test_live_domains_fail_closed_when_cloudflare_reports_failure(tmp_path):
    payload = {"success": False, "result": [], "result_info": {"total_count": 0}}

    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return None

        def read(self, _limit):
            return json.dumps(payload).encode()

    config = Settings(
        app_env="production",
        app_mode="live",
        app_data_dir=tmp_path,
        cf_access_issuer="https://team.cloudflareaccess.com",
        cf_access_aud="aud",
        cloudflare_api_token="c" * 40,
        cloudflare_zone_id="a" * 32,
    )
    with patch.object(providers._AGENT_OPENER, "open", return_value=Response()):
        result = providers.resource("domains", config)

    assert result["status"] == "unavailable"
    assert result["rows"] == []


def test_domains_keep_oversized_records_read_only_and_response_valid(tmp_path):
    record = providers.CloudflareDnsRecord(
        id="a" * 32,
        name="_long.example.com",
        type="TXT",
        content="x" * 2049,
        ttl=1,
    )
    with patch.object(providers, "cloudflare_dns_records", return_value=([record], 1)):
        result = providers.cloudflare_dns_resource(Settings(app_data_dir=tmp_path))

    validated = ResourceResponse.model_validate(result)
    assert validated.rows[0].dnsRecord is None
    assert len(validated.rows[0].detail) < 600
    assert result["actions"] == []


def test_portainer_container_list_is_validated_and_read_only(tmp_path):
    payload = [
        {
            "Id": "a" * 64,
            "Names": ["/web"],
            "Image": "nginx:stable",
            "State": "running",
            "Status": "Up 2 hours",
            "Created": 1_762_685_400,
            "Ports": [{"IP": "0.0.0.0", "PrivatePort": 80, "PublicPort": 8080, "Type": "tcp"}],
            "Labels": {"example": "ignored safely"},
        }
    ]

    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return None

        def read(self, _limit):
            return json.dumps(payload).encode()

    config = Settings(
        app_env="production",
        app_mode="live",
        app_data_dir=tmp_path,
        cf_access_issuer="https://team.cloudflareaccess.com",
        cf_access_aud="aud",
        portainer_url="https://portainer.example",
        portainer_api_key="p" * 24,
        portainer_endpoint_id=1,
    )
    with patch.object(providers._AGENT_OPENER, "open", return_value=Response()) as request:
        containers = providers.portainer_containers(config)
        result = providers.resource("containers", config)
        services = providers.resource("services", config)
        summary = providers.overview(config)
    sent_request = request.call_args.args[0]
    assert sent_request.full_url.endswith("/api/endpoints/1/docker/containers/json?all=1")
    assert sent_request.get_header("X-api-key") == "p" * 24
    assert sent_request.get_method() == "GET"
    assert containers is not None and containers[0].State == "running"
    assert result["status"] == "connected"
    assert result["rows"][0]["name"] == "web"
    assert result["rows"][0]["detail"] == "nginx:stable · 8080:80/tcp"
    assert [item["id"] for item in result["rows"][0]["actions"]] == ["stop", "restart"]
    assert all(not item["enabled"] for item in result["rows"][0]["actions"])
    assert result["actions"] == []
    assert services["status"] == "connected"
    assert services["rows"][0]["status"] == "warning"
    assert "Healthcheck 미보고" in services["rows"][0]["detail"]
    assert summary["services"][-1]["status"] == "warning"
    ResourceResponse.model_validate(services)
    OverviewResponse.model_validate(summary)
    assert summary["docker"] == {
        "status": "connected",
        "running": 1,
        "total": 1,
        "message": "Portainer 읽기 전용 연결",
    }


@pytest.mark.parametrize(
    ("operation", "suffix"),
    [("start", "/start"), ("stop", "/stop?t=10"), ("restart", "/restart?t=10")],
)
def test_portainer_container_actions_use_only_fixed_paths_and_control_key(
    tmp_path, operation, suffix
):
    class Response:
        status = 204

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return None

    config = Settings(
        app_env="production",
        app_mode="live",
        app_data_dir=tmp_path,
        cf_access_issuer="https://team.cloudflareaccess.com",
        cf_access_aud="aud",
        portainer_url="https://portainer.example",
        portainer_api_key="r" * 24,
        portainer_actions_api_key="w" * 24,
        portainer_endpoint_id=7,
    )
    container_id = "a" * 64
    with patch.object(providers._AGENT_OPENER, "open", return_value=Response()) as opener:
        assert providers.portainer_container_action(config, container_id, operation)

    request = opener.call_args.args[0]
    assert request.full_url.endswith(f"/api/endpoints/7/docker/containers/{container_id}{suffix}")
    assert request.get_method() == "POST"
    assert request.get_header("X-api-key") == "w" * 24


def test_portainer_container_action_distinguishes_rejection_from_unknown_result(tmp_path):
    config = Settings(
        app_env="production",
        app_mode="live",
        app_data_dir=tmp_path,
        cf_access_issuer="https://team.cloudflareaccess.com",
        cf_access_aud="aud",
        portainer_url="https://portainer.example",
        portainer_api_key="r" * 24,
        portainer_actions_api_key="w" * 24,
        portainer_endpoint_id=1,
    )
    with patch.object(
        providers._AGENT_OPENER,
        "open",
        side_effect=HTTPError("https://portainer.example", 409, "conflict", {}, None),
    ):
        assert providers.portainer_container_action(config, "a" * 64, "restart") is False
    with patch.object(
        providers._AGENT_OPENER,
        "open",
        side_effect=HTTPError("https://portainer.example", 502, "bad gateway", {}, None),
    ):
        assert providers.portainer_container_action(config, "a" * 64, "restart") is None
    with patch.object(providers._AGENT_OPENER, "open", side_effect=TimeoutError):
        assert providers.portainer_container_action(config, "a" * 64, "restart") is None
    with patch.object(providers, "Request", side_effect=ValueError("invalid header value")):
        assert providers.portainer_container_action(config, "a" * 64, "restart") is None


def test_live_portainer_actions_require_scoped_passkey_grant_and_audit_each_result(tmp_path):
    container_id = "a" * 64
    payload = {
        "Id": container_id,
        "Names": ["/web"],
        "Image": "nginx:stable",
        "State": "running",
        "Status": "Up 2 hours",
        "Created": 1_762_685_400,
    }
    container = providers.PortainerContainer.model_validate(payload)
    config = Settings(
        app_env="production",
        app_mode="live",
        app_data_dir=tmp_path,
        cf_access_issuer="https://team.cloudflareaccess.com",
        cf_access_aud="aud",
        portainer_url="https://portainer.example",
        portainer_api_key="r" * 24,
        portainer_actions_api_key="w" * 24,
        portainer_endpoint_id=1,
    )
    app = create_app(config)
    app.dependency_overrides[current_identity] = lambda: Identity(
        "operator", "ops@example.com", "operator"
    )
    token = "g" * 43
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    headers = {"x-hs-origin-verified": "1"}
    with TestClient(app) as client:
        store_reauth_grant(
            tmp_path, token_hash, "operator", "restart", container_id, time() + 60
        )
        with (
            patch("app.main.portainer_containers", return_value=[container]),
            patch("app.main.portainer_container_action", return_value=True) as action,
        ):
            success = client.post(
                "/api/v1/jobs",
                headers=headers,
                json={"operation": "restart", "target": container_id, "reauthGrant": token},
            )
        assert success.status_code == 201
        assert success.json()["state"] == "succeeded"
        assert success.json()["simulation"] is False
        action.assert_called_once_with(config, container_id, "restart")

        store_reauth_grant(
            tmp_path,
            hashlib.sha256(b"f" * 43).hexdigest(),
            "operator",
            "stop",
            container_id,
            time() + 60,
        )
        with (
            patch("app.main.portainer_containers", return_value=[container]),
            patch("app.main.portainer_container_action", return_value=False),
        ):
            failure = client.post(
                "/api/v1/jobs",
                headers=headers,
                json={"operation": "stop", "target": container_id, "reauthGrant": "f" * 43},
            )
        assert failure.status_code == 201
        assert failure.json()["state"] == "failed"
        assert "상태를 확인" in failure.json()["message"]
        unknown_token = "u" * 43
        store_reauth_grant(
            tmp_path,
            hashlib.sha256(unknown_token.encode()).hexdigest(),
            "operator",
            "restart",
            container_id,
            time() + 60,
        )
        with (
            patch("app.main.portainer_containers", return_value=[container]),
            patch("app.main.portainer_container_action", return_value=None),
        ):
            unknown = client.post(
                "/api/v1/jobs",
                headers=headers,
                json={
                    "operation": "restart",
                    "target": container_id,
                    "reauthGrant": unknown_token,
                },
            )
        assert unknown.status_code == 201
        assert unknown.json()["state"] == "unknown"
        assert "재시도 전에" in unknown.json()["message"]
        assert [job["state"] for job in client.get("/api/v1/jobs").json()] == [
            "unknown",
            "failed",
            "succeeded",
        ]
        assert [event["result"] for event in client.get("/api/v1/audit").json()[:3]] == [
            "unknown",
            "failed",
            "succeeded",
        ]


def test_interrupted_live_job_is_not_recovered_as_success(tmp_path):
    initialize(tmp_path)
    job = {
        "id": "job-1",
        "operation": "restart",
        "target": "a" * 64,
        "message": "Portainer 작업 요청 중",
        "createdAt": datetime.now(UTC).isoformat(),
    }
    begin_live_job(job, "owner@example.com", tmp_path)

    initialize(tmp_path)

    assert list_jobs(tmp_path)[0]["state"] == "unknown"
    assert list_jobs(tmp_path)[0]["simulation"] is False
    assert list_audit(tmp_path)[0]["result"] == "unknown"


def test_live_portainer_action_rejects_viewer_and_missing_grant(tmp_path):
    container_id = "a" * 64
    container = providers.PortainerContainer.model_validate(
        {
            "Id": container_id,
            "Names": ["/web"],
            "Image": "nginx:stable",
            "State": "running",
            "Status": "Up 2 hours",
            "Created": 1_762_685_400,
        }
    )
    config = Settings(
        app_env="production",
        app_mode="live",
        app_data_dir=tmp_path,
        cf_access_issuer="https://team.cloudflareaccess.com",
        cf_access_aud="aud",
        portainer_url="https://portainer.example",
        portainer_api_key="r" * 24,
        portainer_actions_api_key="w" * 24,
        portainer_endpoint_id=1,
    )
    app = create_app(config)
    identity = Identity("viewer", "viewer@example.com", "viewer")
    app.dependency_overrides[current_identity] = lambda: identity
    with TestClient(app) as client:
        with patch("app.providers.portainer_containers", return_value=[container]):
            resource = client.get("/api/v1/resources/containers")
        assert resource.status_code == 200
        assert all(not action["enabled"] for action in resource.json()["rows"][0]["actions"])

        with patch("app.main.portainer_containers", return_value=[container]) as listing:
            response = client.post(
                "/api/v1/jobs",
                headers={"x-hs-origin-verified": "1"},
                json={"operation": "stop", "target": container_id},
            )
        assert response.status_code == 403
        listing.assert_not_called()

        app.dependency_overrides[current_identity] = lambda: Identity(
            "operator", "ops@example.com", "operator"
        )
        with patch("app.main.portainer_containers", return_value=[container]):
            response = client.post(
                "/api/v1/jobs",
                headers={"x-hs-origin-verified": "1"},
                json={"operation": "start", "target": container_id},
            )
        assert response.status_code == 409

        with patch("app.main.portainer_containers", return_value=[container]), patch(
            "app.main.portainer_container_action"
        ) as action:
            response = client.post(
                "/api/v1/jobs",
                headers={"x-hs-origin-verified": "1"},
                json={"operation": "stop", "target": container_id},
            )
        assert response.status_code == 403
        assert response.json()["detail"] == "Fresh Passkey verification required"
        action.assert_not_called()


@pytest.mark.parametrize(
    ("state", "status", "health", "expected"),
    [
        ("running", "Up 3 minutes (healthy)", "healthy", "healthy"),
        ("running", "Up 3 minutes (unhealthy)", "unhealthy", "failed"),
        ("running", "Up 3 minutes (health: starting)", "starting", "warning"),
        ("running", "Up 3 minutes (none)", "none", "warning"),
        ("running", "Up 3 minutes", None, "warning"),
        ("exited", "Exited (0) 3 minutes ago", None, "stopped"),
        ("dead", "Dead", None, "failed"),
    ],
)
def test_container_service_status_requires_explicit_healthcheck(state, status, health, expected):
    payload = {
        "Id": "a" * 64,
        "Names": ["/web"],
        "Image": "nginx:stable",
        "State": state,
        "Status": status,
        "Created": 1_762_685_400,
    }
    if health:
        payload["Health"] = {"Status": health}
    container = providers.PortainerContainer.model_validate(payload)
    assert providers._container_service_rows([container], "2026-11-09T00:00:00Z")[0]["status"] == expected


def test_portainer_image_list_is_validated_and_read_only(tmp_path):
    payload = [
        {
            "Id": "sha256:" + "b" * 64,
            "RepoTags": ["nginx:stable", "nginx:latest"],
            "Created": 1_762_685_400,
            "Size": 74_000_000,
            "Containers": 1,
        },
        {
            "Id": "sha256:" + "c" * 64,
            "RepoTags": None,
            "Created": 1_762_685_401,
            "Size": 0,
        },
    ]

    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return None

        def read(self, _limit):
            return json.dumps(payload).encode()

    config = Settings(
        app_env="production",
        app_mode="live",
        app_data_dir=tmp_path,
        cf_access_issuer="https://team.cloudflareaccess.com",
        cf_access_aud="aud",
        portainer_url="https://portainer.example",
        portainer_api_key="p" * 24,
        portainer_endpoint_id=1,
    )
    app = create_app(config)
    app.dependency_overrides[current_identity] = lambda: Identity(
        "owner", "owner@example.com", "owner"
    )
    with patch.object(providers._AGENT_OPENER, "open", return_value=Response()) as request:
        with TestClient(app) as client:
            result = client.get("/api/v1/resources/images")
    sent_request = request.call_args.args[0]
    assert sent_request.full_url.endswith("/api/endpoints/1/docker/images/json?all=1")
    assert sent_request.get_header("X-api-key") == "p" * 24
    assert sent_request.get_method() == "GET"
    assert result.status_code == 200
    assert len(result.json()["rows"]) == 2
    assert result.json()["status"] == "connected"
    assert result.json()["rows"][0]["name"] == "nginx"
    assert result.json()["rows"][0]["status"] == "nginx:stable, nginx:latest"
    assert result.json()["rows"][1]["status"] == "태그 없음"
    assert result.json()["actions"] == []


def test_portainer_stack_list_is_endpoint_scoped_and_read_only(tmp_path):
    payload = [
        {
            "Id": 1,
            "Name": "homeserver",
            "Type": 2,
            "EndpointId": 1,
            "Status": 1,
            "EntryPoint": "compose.yaml",
            "CreationDate": 1_762_685_400,
            "UpdateDate": 1_762_685_500,
        },
        {
            "Id": 2,
            "Name": "database",
            "Type": 1,
            "EndpointId": 1,
            "Status": 2,
            "EntryPoint": "stack.yaml",
            "CreationDate": 1_762_685_300,
            "UpdateDate": 0,
        },
        {
            "Id": 3,
            "Name": "other-endpoint",
            "Type": 2,
            "EndpointId": 2,
            "Status": 1,
        },
        {
            "Id": 4,
            "Name": "kubernetes",
            "Type": 3,
            "EndpointId": 1,
            "Status": 1,
        },
        {
            "Id": 5,
            "Name": "legacy",
            "Type": 2,
            "EndpointId": None,
            "Status": 1,
            "EntryPoint": None,
        },
    ]

    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return None

        def read(self, _limit):
            return json.dumps(payload).encode()

    config = Settings(
        app_env="production",
        app_mode="live",
        app_data_dir=tmp_path,
        cf_access_issuer="https://team.cloudflareaccess.com",
        cf_access_aud="aud",
        portainer_url="https://portainer.example",
        portainer_api_key="p" * 24,
        portainer_endpoint_id=1,
    )
    app = create_app(config)
    app.dependency_overrides[current_identity] = lambda: Identity(
        "owner", "owner@example.com", "owner"
    )
    with patch.object(providers._AGENT_OPENER, "open", return_value=Response()) as request:
        with TestClient(app) as client:
            result = client.get("/api/v1/resources/stacks")
    sent_request = request.call_args.args[0]
    assert sent_request.get_method() == "GET"
    assert sent_request.get_header("X-api-key") == "p" * 24
    assert json.loads(parse_qs(urlsplit(sent_request.full_url).query)["filters"][0]) == {
        "EndpointID": 1
    }
    assert result.status_code == 200
    assert [row["name"] for row in result.json()["rows"]] == ["database", "homeserver"]
    assert result.json()["rows"][0]["status"] == "중지"
    assert result.json()["rows"][0]["detail"] == "Swarm · stack.yaml"
    assert result.json()["rows"][1]["status"] == "활성"
    assert result.json()["metrics"][2]["value"] == "1"
    assert result.json()["actions"] == []


def test_mailcow_directory_is_read_only_and_restricted_to_operators(tmp_path):
    payloads = [
        [{"domain": "example.com", "active": 1, "quota": 1073741824}],
        [
            {
                "username": "owner@example.com",
                "domain": "example.com",
                "name": "Owner",
                "active": 1,
                "quota": 536870912,
                "quota_used": 2956,
                "percent_in_use": 0,
            },
            {
                "username": "disabled@example.com",
                "domain": "example.com",
                "active": 0,
                "quota": 0,
                "quota_used": 0,
            },
        ],
        [{"address": "info@example.com", "goto": None, "active": 1}],
    ]

    class Response:
        status = 200

        def __init__(self, payload):
            self.payload = payload

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return None

        def read(self, _limit):
            return json.dumps(self.payload).encode()

    config = Settings(
        app_env="production",
        app_mode="live",
        app_data_dir=tmp_path,
        cf_access_issuer="https://team.cloudflareaccess.com",
        cf_access_aud="aud",
        mailcow_url="https://mailcow.example",
        mailcow_api_key="m" * 24,
    )
    app = create_app(config)
    app.dependency_overrides[current_identity] = lambda: Identity(
        "owner", "owner@example.com", "owner"
    )
    with patch.object(
        providers._AGENT_OPENER,
        "open",
        side_effect=[Response(payload) for payload in payloads],
    ) as request:
        with TestClient(app) as client:
            result = client.get("/api/v1/resources/mail")
    assert result.status_code == 200
    assert [call.args[0].get_method() for call in request.call_args_list] == ["GET"] * 3
    assert [urlsplit(call.args[0].full_url).path for call in request.call_args_list] == [
        "/api/v1/get/domain/all",
        "/api/v1/get/mailbox/all",
        "/api/v1/get/alias/all",
    ]
    assert all(call.args[0].get_header("X-api-key") == "m" * 24 for call in request.call_args_list)
    assert result.json()["status"] == "connected"
    assert [row["name"] for row in result.json()["rows"]] == [
        "example.com",
        "disabled@example.com",
        "owner@example.com",
        "info@example.com",
    ]
    assert result.json()["rows"][1]["status"] == "중지"
    assert "2,956 bytes" in result.json()["rows"][2]["detail"]
    assert result.json()["rows"][3]["detail"] == "전달 → 대상 미설정"
    assert result.json()["actions"] == []

    app.dependency_overrides[current_identity] = lambda: Identity(
        "viewer", "viewer@example.com", "viewer"
    )
    with patch.object(providers._AGENT_OPENER, "open") as request:
        with TestClient(app) as client:
            denied = client.get("/api/v1/resources/mail")
    assert denied.status_code == 403
    request.assert_not_called()


def test_mailcow_empty_collection_object_is_treated_as_empty_list(tmp_path):
    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return None

        def read(self, _limit):
            return b"{}"

    config = Settings(
        app_data_dir=tmp_path,
        mailcow_url="https://mailcow.example",
        mailcow_api_key="m" * 24,
    )
    with patch.object(providers._AGENT_OPENER, "open", return_value=Response()):
        assert providers.mailcow_list(config, "alias") == []


def test_live_settings_reports_configuration_without_secret_values(tmp_path):
    config = Settings(
        app_env="production",
        app_mode="live",
        app_data_dir=tmp_path,
        audit_retention_days=30,
        cf_access_issuer="https://team.cloudflareaccess.com",
        cf_access_aud="aud",
        host_agent_url="http://agent:9000/v1/metrics",
        host_agent_token="a" * 64,
        mailcow_url="https://mailcow.example",
        mailcow_api_key="m" * 24,
    )
    app = create_app(config)
    app.dependency_overrides[current_identity] = lambda: Identity(
        "owner", "owner@example.com", "owner"
    )
    with TestClient(app) as client:
        result = client.get("/api/v1/resources/settings")
    body = json.dumps(result.json())
    assert result.status_code == 200
    assert result.json()["metrics"][1]["value"] == "3/16"
    rows = {row["name"]: row for row in result.json()["rows"]}
    assert rows["mailcow"]["status"] == "설정됨"
    assert rows["Portainer"]["status"] == "미설정"
    assert rows["Portainer 제어"]["status"] == "미설정"
    assert rows["n8n 실행 이력"]["status"] == "미설정"
    assert rows["Cloudflare DNS 쓰기"]["status"] == "미설정"
    assert rows["Netdata Alerts"]["status"] == "미설정"
    assert rows["Scrutiny"]["status"] == "미설정"
    assert rows["서버 쓰기 작업"]["status"] == "부분 지원"
    assert "백업/복원 미지원" in rows["서버 쓰기 작업"]["detail"]
    assert "a" * 64 not in body
    assert "m" * 24 not in body
    assert result.json()["actions"] == []


def test_live_database_metrics_use_fixed_read_only_provider_calls(tmp_path):
    class Result:
        def __init__(self, row=None):
            self.row = row

        def fetchone(self):
            return self.row

    class Connection:
        def __init__(self):
            self.statements = []

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

        def transaction(self):
            return nullcontext()

        def execute(self, statement):
            self.statements.append(statement)
            return Result(("appdb", 2_000_000, 3, 100) if statement.startswith("SELECT") else None)

    class RedisClient:
        def __init__(self):
            self.closed = False
            self.sections = []
            self.key_count_calls = 0

        def ping(self):
            return True

        def info(self, section):
            self.sections.append(section)
            return {
                "memory": {"used_memory": 5000},
                "clients": {"connected_clients": 2},
                "stats": {"instantaneous_ops_per_sec": 4},
            }[section]

        def dbsize(self):
            self.key_count_calls += 1
            return 10

        def close(self):
            self.closed = True

    connection = Connection()
    redis = RedisClient()
    config = Settings(
        app_env="production",
        app_mode="live",
        app_data_dir=tmp_path,
        cf_access_issuer="https://team.cloudflareaccess.com",
        cf_access_aud="aud",
        postgres_url=(
            "postgresql://report:pg-secret@db.example/app"
            "?sslmode=verify-full&sslrootcert=system"
        ),
        redis_url="rediss://report:redis-secret@redis.example/0",
    )
    app = create_app(config)
    app.dependency_overrides[current_identity] = lambda: Identity(
        "owner", "owner@example.com", "owner"
    )
    with (
        patch.object(providers.psycopg, "connect", return_value=connection) as connect,
        patch.object(providers.Redis, "from_url", return_value=redis) as from_url,
        TestClient(app) as client,
    ):
        result = client.get("/api/v1/resources/database")
    body = result.json()
    rows = {row["id"]: row for row in body["rows"]}
    metrics = {metric["label"]: metric["value"] for metric in body["metrics"]}
    assert result.status_code == 200
    assert body["status"] == "connected"
    assert rows["postgresql"]["status"] == rows["redis"]["status"] == "정상"
    assert metrics["PostgreSQL 크기"] == "2,000,000 B"
    assert metrics["PostgreSQL 연결"] == "3/100"
    assert metrics["Redis 메모리"] == "5,000 B"
    assert metrics["Redis 클라이언트"] == "2"
    assert connection.statements[0] == "SET TRANSACTION READ ONLY"
    assert connection.statements[1].startswith("SELECT current_database(), pg_database_size")
    connect.assert_called_once_with(
        "postgresql://report:pg-secret@db.example/app?sslmode=verify-full&sslrootcert=system",
        connect_timeout=3,
        sslmode="verify-full",
        gssencmode="disable",
        options="-c statement_timeout=3000",
    )
    from_url.assert_called_once_with(
        "rediss://report:redis-secret@redis.example/0",
        decode_responses=True,
        socket_connect_timeout=2,
        socket_timeout=2,
    )
    assert redis.sections == ["memory", "clients", "stats"]
    assert redis.key_count_calls == 1
    assert redis.closed
    assert body["actions"] == []
    assert "pg-secret" not in json.dumps(body)
    assert "redis-secret" not in json.dumps(body)


def test_live_notifications_report_thresholds_container_health_and_audit(tmp_path):
    now = datetime.now(UTC).isoformat()
    snapshot = providers.HostSnapshot.model_validate(
        {
            "serverName": "heonhwi-homeserver",
            "osName": "Ubuntu 26.04.1 LTS",
            "kernelVersion": "6.14.0-1-generic",
            "updatedAt": now,
            "uptimeSeconds": 123,
            "cpu": {"percent": 87, "cores": [87], "loadAverage": [1, 1, 1]},
            "memory": {"usedBytes": 930, "totalBytes": 1000, "percent": 93},
            "swap": {"usedBytes": 0, "totalBytes": 0, "percent": 0},
            "network": {"receivedBytesPerSecond": 0, "sentBytesPerSecond": 0},
            "storage": [
                {
                    "name": "Data HDD",
                    "device": "/dev/sdb1",
                    "mount": "/mnt/data",
                    "fileSystem": "ext4",
                    "usedBytes": 90,
                    "totalBytes": 100,
                    "percent": 90,
                    "health": "not_reported",
                }
            ],
            "history": [],
        }
    )
    containers = [
        providers.PortainerContainer.model_validate(
            {
                "Id": "a" * 64,
                "Names": ["/web"],
                "Image": "nginx:stable",
                "State": "running",
                "Status": "Up 10 minutes (unhealthy)",
                "Created": 1_762_685_400,
                "Health": {"Status": "unhealthy"},
            }
        )
    ]
    config = Settings(
        app_env="production",
        app_mode="live",
        app_data_dir=tmp_path,
        cf_access_issuer="https://team.cloudflareaccess.com",
        cf_access_aud="aud",
        host_agent_url="http://agent:9000/v1/metrics",
        host_agent_token="a" * 64,
        portainer_url="https://portainer.example",
        portainer_api_key="p" * 24,
        portainer_endpoint_id=1,
    )
    app = create_app(config)
    app.dependency_overrides[current_identity] = lambda: Identity(
        "owner", "owner@example.com", "owner"
    )
    with patch.object(providers, "host_snapshot", return_value=snapshot), patch.object(
        providers, "portainer_containers", return_value=containers
    ):
        with TestClient(app) as client:
            record_simulated_job(
                {
                    "id": "recent-job",
                    "operation": "restart",
                    "target": "web",
                    "state": "succeeded",
                    "message": "demo",
                    "createdAt": now,
                },
                "owner@example.com",
                tmp_path,
            )
            result = client.get("/api/v1/resources/notifications")
    assert result.status_code == 200
    rows = result.json()["rows"]
    assert {row["name"] for row in rows} >= {
        "CPU 사용률",
        "메모리 사용률",
        "스토리지 · Data HDD",
        "Docker · web",
        "관리 작업 · owner@example.com",
    }
    assert next(row for row in rows if row["name"] == "Docker · web")["status"] == "failed"
    assert next(row for row in rows if row["name"] == "관리 작업 · owner@example.com")["status"] == "simulated"
    assert result.json()["metrics"][0]["value"] == "4"


def test_ntfy_sends_only_alert_transitions_and_retries_failed_delivery(tmp_path):
    config = Settings(
        app_env="production",
        app_mode="live",
        app_data_dir=tmp_path,
        cf_access_issuer="https://team.cloudflareaccess.com",
        cf_access_aud="aud",
        ntfy_url="https://ntfy.example",
        ntfy_topic="homeserver_alerts",
        ntfy_token="ntfy-private-token-1234",
    )
    initialize(tmp_path)
    alerts = {
        "status": "connected",
        "rows": [
            {
                "id": "host-cpu",
                "name": "CPU 사용률",
                "status": "warning",
                "detail": "88% · 기준 85%",
            },
            {
                "id": "container:web",
                "name": "Docker · web",
                "status": "failed",
                "detail": "Healthcheck failed",
            },
        ],
    }
    with (
        patch.object(notifications, "resource", return_value=alerts),
        patch.object(notifications, "_publish", side_effect=[False, True, True]) as publish,
    ):
        assert not notifications.send_notification_changes(config, tmp_path)
        assert list_notification_alerts(tmp_path) == {}
        assert notifications.send_notification_changes(config, tmp_path)
        assert list_notification_alerts(tmp_path) == {
            "host-cpu": "CPU 사용률",
            "container:web": "Docker · web",
        }
        assert not notifications.send_notification_changes(config, tmp_path)
        assert publish.call_count == 2

        with patch.object(
            notifications,
            "resource",
            return_value={"status": "connected", "rows": []},
        ):
            assert notifications.send_notification_changes(config, tmp_path)
    assert list_notification_alerts(tmp_path) == {}
    assert "정상화: CPU 사용률" in publish.call_args.args[1]
    assert "88%" in publish.call_args_list[1].args[1]


def test_ntfy_publishes_to_configured_topic_with_bearer_token(tmp_path):
    class Response:
        status = 202

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

    config = Settings(
        app_data_dir=tmp_path,
        ntfy_url="https://ntfy.example",
        ntfy_topic="homeserver_alerts",
        ntfy_token="ntfy-private-token-1234",
    )
    with patch.object(notifications._NTFY_OPENER, "open", return_value=Response()) as open_request:
        assert notifications._publish(config, "CPU 경고")
    request = open_request.call_args.args[0]
    assert request.full_url == "https://ntfy.example/homeserver_alerts"
    assert request.method == "POST"
    assert request.get_header("Authorization") == "Bearer ntfy-private-token-1234"
    assert request.data == "CPU 경고".encode()
    assert open_request.call_args.kwargs == {"timeout": 3}
    assert not notifications._publish(config, "경고" * 1_001)
    open_request.assert_called_once()


def test_notification_alerts_survive_provider_outages_until_recovery(tmp_path):
    config = Settings(
        app_data_dir=tmp_path,
        ntfy_url="https://ntfy.example",
        ntfy_topic="homeserver_alerts",
    )
    initialize(tmp_path)
    host_and_container_alerts = {
        "status": "connected",
        "rows": [
            {"id": "host-cpu", "name": "CPU", "status": "warning", "detail": "90%"},
            {
                "id": "container:web",
                "name": "web",
                "status": "failed",
                "detail": "Healthcheck failed",
            },
        ],
    }
    provider_outages = {
        "status": "partial",
        "rows": [
            {
                "id": "host-agent",
                "name": "호스트 Agent",
                "status": "warning",
                "detail": "연결 실패",
            },
            {
                "id": "portainer",
                "name": "Portainer",
                "status": "warning",
                "detail": "연결 실패",
            },
        ],
    }
    with patch.object(
        notifications,
        "resource",
        side_effect=[host_and_container_alerts, provider_outages, {"status": "connected", "rows": []}],
    ), patch.object(notifications, "_publish", return_value=True):
        assert notifications.send_notification_changes(config, tmp_path)
        assert notifications.send_notification_changes(config, tmp_path)
        alerts_during_outage = list_notification_alerts(tmp_path)
        assert {"host-cpu", "container:web"} <= alerts_during_outage.keys()
        assert notifications.send_notification_changes(config, tmp_path)
    assert list_notification_alerts(tmp_path) == {}


def test_notification_batches_respect_ntfy_limit_and_save_only_delivered_changes(tmp_path):
    config = Settings(
        app_data_dir=tmp_path,
        ntfy_url="https://ntfy.example",
        ntfy_topic="homeserver_alerts",
    )
    initialize(tmp_path)
    alerts = {
        "status": "connected",
        "rows": [
            {
                "id": f"host-{index}",
                "name": f"알림 {index}",
                "status": "warning",
                "detail": "높음" * 180,
            }
            for index in range(8)
        ],
    }
    published = []

    def publish(_settings, message):
        published.append(message)
        return len(published) == 1

    with patch.object(notifications, "resource", return_value=alerts), patch.object(
        notifications, "_publish", side_effect=publish
    ):
        assert not notifications.send_notification_changes(config, tmp_path)

    assert len(published) > 1
    assert all(len(message.encode("utf-8")) <= 2_000 for message in published)
    saved = list_notification_alerts(tmp_path)
    assert 0 < len(saved) < len(alerts["rows"])


def test_live_app_runs_and_cancels_ntfy_worker(tmp_path):
    config = Settings(
        app_env="production",
        app_mode="live",
        app_data_dir=tmp_path,
        cf_access_issuer="https://team.cloudflareaccess.com",
        cf_access_aud="aud",
        ntfy_url="https://ntfy.example",
        ntfy_topic="homeserver_alerts",
    )
    started = Event()

    async def worker(_settings, _data_dir):
        started.set()
        await asyncio.Future()

    with patch("app.main.run_notification_loop", new=worker):
        with TestClient(create_app(config)):
            assert started.wait(timeout=1)


def test_authenticated_api_requests_are_rate_limited_per_subject(tmp_path):
    config = Settings(
        app_env="production",
        app_mode="live",
        app_data_dir=tmp_path,
        cf_access_issuer="https://team.cloudflareaccess.com",
        cf_access_aud="aud",
    )
    app = create_app(config)
    app.state.rate_limiter = RequestRateLimiter(limit=1)
    subject = ["owner-subject"]
    app.dependency_overrides[current_identity] = lambda: Identity(
        subject[0], "owner@example.com", "owner"
    )
    with TestClient(app) as client:
        first = client.get("/api/v1/resources/settings")
        limited = client.get("/api/v1/audit")
        subject[0] = "operator-subject"
        other_subject = client.get("/api/v1/audit")
    assert first.status_code == 200
    assert limited.status_code == 429
    assert int(limited.headers["retry-after"]) >= 1
    assert other_subject.status_code == 200

    mock_app = create_app(Settings(app_data_dir=tmp_path / "mock"))
    mock_app.state.rate_limiter = RequestRateLimiter(limit=1)
    mock_app.dependency_overrides[current_identity] = lambda: Identity(
        "demo-subject", "demo@example.com", "owner"
    )
    with TestClient(mock_app) as client:
        assert client.get("/api/v1/resources/settings").status_code == 200
        assert client.get("/api/v1/audit").status_code == 200


def test_docker_log_frames_decode_streams_and_reject_truncation():
    stdout = b"hello\n"
    stderr = b"problem\n"
    body = (
        b"\x01\0\0\0"
        + len(stdout).to_bytes(4, "big")
        + stdout
        + b"\x02\0\0\0"
        + len(stderr).to_bytes(4, "big")
        + stderr
    )
    assert providers._decode_docker_log_frames(body) == "hello\nproblem\n"
    assert providers._decode_docker_log_frames(body[:-1]) is None
    assert providers._decode_docker_log_frames(b"plain output") is None
    raw_frame_like = b"\x01\0\0\0\0\0\0\x01a"
    assert (
        providers._decode_docker_logs(raw_frame_like, "application/vnd.docker.raw-stream")
        == raw_frame_like.decode()
    )
    assert (
        providers._decode_docker_logs(raw_frame_like, "application/vnd.docker.multiplexed-stream")
        == "a"
    )


def test_provider_opener_does_not_forward_credentials_through_redirects():
    handler = providers._NoRedirect()
    request = providers.Request("https://portainer.example")
    assert (
        handler.redirect_request(request, None, 302, "Found", {}, "https://other.example") is None
    )


def test_live_container_logs_are_scoped_bounded_and_authenticated(tmp_path):
    container_id = "a" * 64

    class Response:
        def __init__(self, body, content_type="application/json"):
            self.status = 200
            self.headers = {"Content-Type": content_type}
            self.body = body

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return None

        def read(self, _limit):
            return self.body

    raw_logs = b"service started\n"
    frame = b"\x01\0\0\0" + len(raw_logs).to_bytes(4, "big") + raw_logs
    config = Settings(
        app_env="production",
        app_mode="live",
        app_data_dir=tmp_path,
        cf_access_issuer="https://team.cloudflareaccess.com",
        cf_access_aud="aud",
        portainer_url="https://portainer.example",
        portainer_api_key="p" * 24,
        portainer_endpoint_id=1,
    )
    app = create_app(config)
    app.dependency_overrides[current_identity] = lambda: Identity(
        "ops@example.com", "ops@example.com", "operator"
    )
    with patch.object(
        providers._AGENT_OPENER,
        "open",
        return_value=Response(frame, "application/vnd.docker.multiplexed-stream"),
    ) as request:
        with TestClient(app) as client:
            result = client.get(f"/api/v1/containers/{container_id}/logs?tail=12")
            invalid = client.get("/api/v1/containers/not-a-container/logs")
    assert result.status_code == 200
    assert result.json()["logs"] == "service started\n"
    assert result.json()["mode"] == "live"
    assert result.json()["tail"] == 12
    log_request = request.call_args.args[0]
    assert log_request.get_method() == "GET"
    assert log_request.full_url.endswith(
        f"/docker/containers/{container_id}/logs?stdout=1&stderr=1&timestamps=1&tail=12"
    )
    assert log_request.get_header("X-api-key") == "p" * 24
    assert invalid.status_code == 404


def test_mock_container_logs_are_explicitly_labeled(tmp_path):
    with TestClient(create_app(Settings(app_data_dir=tmp_path))) as client:
        result = client.get("/api/v1/containers/container/logs")
        invalid = client.get("/api/v1/containers/other/logs")
        excessive_tail = client.get("/api/v1/containers/container/logs?tail=501")
    assert result.status_code == 200
    assert result.json()["mode"] == "mock"
    assert "DEMO" in result.json()["logs"]
    assert invalid.status_code == 404
    assert excessive_tail.status_code == 422


def test_live_container_stats_are_bounded_and_validated(tmp_path):
    container_id = "a" * 64

    class Response:
        status = 200

        def __init__(self, body):
            self.body = body

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return None

        def read(self, _limit):
            return self.body

    payload = {
        "cpu_stats": {
            "cpu_usage": {"total_usage": 200, "percpu_usage": [100, 100, 0, 0]},
            "system_cpu_usage": 1000,
            "online_cpus": 4,
        },
        "precpu_stats": {
            "cpu_usage": {"total_usage": 100},
            "system_cpu_usage": 900,
            "online_cpus": 4,
        },
        "memory_stats": {"usage": 1000, "limit": 2000, "stats": {"inactive_file": 200}},
    }
    config = Settings(
        app_env="production",
        app_mode="live",
        app_data_dir=tmp_path,
        cf_access_issuer="https://team.cloudflareaccess.com",
        cf_access_aud="aud",
        portainer_url="https://portainer.example",
        portainer_api_key="p" * 24,
        portainer_endpoint_id=1,
    )
    app = create_app(config)
    app.dependency_overrides[current_identity] = lambda: Identity(
        "viewer@example.com", "viewer@example.com", "viewer"
    )
    with patch.object(
        providers._AGENT_OPENER,
        "open",
        return_value=Response(json.dumps(payload).encode()),
    ) as request:
        with TestClient(app) as client:
            result = client.get(f"/api/v1/containers/{container_id}/stats")
            invalid = client.get("/api/v1/containers/not-a-container/stats")
    assert result.status_code == 200
    assert result.json()["cpuPercent"] == 400
    assert result.json()["memoryUsedBytes"] == 800
    assert result.json()["memoryPercent"] == 40
    assert request.call_args.args[0].full_url.endswith(
        f"/docker/containers/{container_id}/stats?stream=false"
    )
    assert invalid.status_code == 404


def test_mock_container_stats_are_labeled_as_demo(tmp_path):
    with TestClient(create_app(Settings(app_data_dir=tmp_path))) as client:
        result = client.get("/api/v1/containers/container/stats")
        invalid = client.get("/api/v1/containers/not-a-container/stats")
    assert result.status_code == 200
    assert result.json()["mode"] == "mock"
    assert "DEMO" in result.json()["message"]
    assert invalid.status_code == 404


def test_history_retention_prunes_expired_records_and_keeps_recent_jobs(tmp_path):
    config = Settings(app_data_dir=tmp_path)
    initialize(tmp_path)
    old = (datetime.now(UTC) - timedelta(days=400)).isoformat()
    recent = datetime.now(UTC).isoformat()
    record_simulated_job(
        {
            "id": "old-job",
            "operation": "deploy",
            "target": "web",
            "state": "succeeded",
            "message": "old",
            "createdAt": old,
        },
        "owner@example.com",
        tmp_path,
    )
    record_simulated_job(
        {
            "id": "recent-job",
            "operation": "deploy",
            "target": "web",
            "state": "succeeded",
            "message": "recent",
            "createdAt": recent,
        },
        "owner@example.com",
        tmp_path,
    )
    with TestClient(create_app(config)) as client:
        jobs = client.get("/api/v1/jobs").json()
        audit = client.get("/api/v1/audit").json()
    assert [job["id"] for job in jobs] == ["recent-job"]
    assert [event["id"] for event in audit] == ["recent-job"]


def test_live_viewer_cannot_read_container_logs(tmp_path):
    config = Settings(
        app_env="production",
        app_mode="live",
        app_data_dir=tmp_path,
        cf_access_issuer="https://team.cloudflareaccess.com",
        cf_access_aud="aud",
    )
    app = create_app(config)
    app.dependency_overrides[current_identity] = lambda: Identity(
        "viewer@example.com", "viewer@example.com", "viewer"
    )
    with TestClient(app) as client:
        result = client.get(f"/api/v1/containers/{'a' * 64}/logs")
        stream = client.get(f"/api/v1/containers/{'a' * 64}/logs/stream")
    assert result.status_code == 403
    assert stream.status_code == 403


def test_one_access_subject_cannot_consume_all_sse_slots(tmp_path):
    app = create_app(Settings(app_data_dir=tmp_path))
    contexts = []
    with TestClient(app) as client:
        try:
            for _ in range(4):
                stream = client.stream("GET", "/api/v1/metrics/overview/stream")
                response = stream.__enter__()
                contexts.append(stream)
                assert response.status_code == 200
            assert client.get("/api/v1/metrics/overview/stream").status_code == 503
        finally:
            for stream in contexts:
                stream.__exit__(None, None, None)


def test_sse_stream_stops_when_its_absolute_deadline_expires(tmp_path):
    app = create_app(Settings(app_data_dir=tmp_path))
    with patch("app.main.STREAM_MAX_AGE_SECONDS", 0), TestClient(app) as client:
        response = client.get("/api/v1/metrics/overview/stream")
    assert response.status_code == 200
    assert response.text == "retry: 3000\n\n"


def test_live_overview_uses_validated_agent_metrics(tmp_path):
    now = "2026-11-09T12:30:00+00:00"
    payload = {
        "serverName": "heonhwi-homeserver",
        "osName": "Ubuntu 26.04.1 LTS",
        "kernelVersion": "6.14.0-1-generic",
        "updatedAt": now,
        "uptimeSeconds": 123,
        "cpu": {
            "percent": 25,
            "cores": [10, 20],
            "loadAverage": [1, 0.5, 0.25],
            "modelName": "Intel Core i7-2600",
            "physicalCores": 1,
            "avx2": False,
        },
        "memory": {"usedBytes": 500, "totalBytes": 1000, "percent": 50},
        "swap": {"usedBytes": 0, "totalBytes": 0, "percent": 0},
        "network": {"receivedBytesPerSecond": 10, "sentBytesPerSecond": 4},
        "sensors": {
            "cpuTemperaturesCelsius": [42.0, 48.0],
            "gpuName": "NVIDIA",
            "gpuTemperatureCelsius": 56.0,
        },
        "storage": [
            {
                "name": "System SSD",
                "device": "/dev/sda2",
                "mount": "/mnt/ssd",
                "fileSystem": "ext4",
                "usedBytes": 60,
                "totalBytes": 100,
                "percent": 60,
                "health": "not_reported",
            }
        ],
        "history": [{"time": "12:30:00", "cpu": 25, "memory": 50}],
    }

    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return None

        def read(self, _limit):
            return json.dumps(payload).encode()

    config = Settings(
        app_env="production",
        app_mode="live",
        app_data_dir=tmp_path,
        cf_access_issuer="https://team.cloudflareaccess.com",
        cf_access_aud="aud",
        host_agent_url="http://agent:9000/v1/metrics",
        host_agent_token="a" * 64,
    )
    with patch.object(providers._AGENT_OPENER, "open", return_value=Response()):
        result = providers.overview(config)
        system = providers.resource("system", config)
        storage = providers.resource("storage", config)
        app = create_app(config)
        app.dependency_overrides[current_identity] = lambda: Identity(
            "owner@example.com", "owner@example.com", "owner"
        )
        with TestClient(app) as client:
            api_result = client.get("/api/v1/metrics/overview")
            storage_api_result = client.get("/api/v1/resources/storage")
    assert result["status"] == "connected"
    assert result["serverName"] == "heonhwi-homeserver"
    assert result["cpu"]["percent"] == 25
    assert result["cpu"]["modelName"] == "Intel Core i7-2600"
    assert result["cpu"]["physicalCores"] == 1
    assert result["cpu"]["avx2"] is False
    assert result["memory"]["percent"] == 50
    assert result["network"]["receivedBytesPerSecond"] == 10
    assert result["storage"][0]["mount"] == "/mnt/ssd"
    assert result["docker"]["status"] == "not_configured"
    assert system["status"] == "connected"
    assert "Ubuntu 26.04.1 LTS" in system["metrics"][0]["detail"]
    assert system["rows"][0]["name"] == "운영 체제"
    assert system["rows"][0]["status"] == "Ubuntu 26.04.1 LTS"
    assert "AVX2 미지원" in system["metrics"][1]["detail"]
    assert next(row for row in system["rows"] if row["id"] == "cpu-temperature")["status"] == "48.0°C"
    assert next(row for row in system["rows"] if row["id"] == "gpu")["detail"] == "56.0°C"
    assert storage["status"] == "connected"
    assert storage["rows"][0]["name"] == "System SSD"
    assert storage["rows"][0]["status"] == "60.0% 사용"
    assert api_result.status_code == 200
    assert api_result.json()["serverName"] == "heonhwi-homeserver"
    assert storage_api_result.status_code == 200
    assert storage_api_result.json()["rows"][0]["detail"].startswith("/dev/sda2 · ext4 · /mnt/ssd")


def test_operator_cannot_run_owner_only_job(tmp_path):
    app = create_app(Settings(app_data_dir=tmp_path))
    app.dependency_overrides[current_identity] = lambda: Identity(
        "ops@example.com", "ops@example.com", "operator"
    )
    with TestClient(app) as client:
        reboot = client.post(
            "/api/v1/jobs",
            headers={"x-hs-origin-verified": "1"},
            json={"operation": "reboot", "target": "server"},
        )
        restart = client.post(
            "/api/v1/jobs",
            headers={"x-hs-origin-verified": "1"},
            json={"operation": "restart", "target": "web"},
        )
    assert reboot.status_code == 403
    assert restart.status_code == 201


def test_live_agent_failure_is_unavailable_without_mock_fallback(tmp_path):
    config = Settings(
        app_env="production",
        app_mode="live",
        app_data_dir=tmp_path,
        cf_access_issuer="https://team.cloudflareaccess.com",
        cf_access_aud="aud",
        host_agent_url="http://agent:9000/v1/metrics",
        host_agent_token="a" * 64,
    )
    with patch.object(providers._AGENT_OPENER, "open", side_effect=URLError("offline")):
        result = providers.overview(config)
        storage = providers.resource("storage", config)
    assert result["status"] == "unavailable"
    assert result["cpu"]["percent"] == 0
    assert result["services"][0]["status"] == "failed"
    assert "DEMO" not in result["serverName"]
    assert storage["mode"] == "live"
    assert storage["status"] == "unavailable"
    assert storage["rows"] == []


def test_role_defaults_to_viewer_and_matches_case_insensitively(tmp_path):
    config = Settings(
        owner_emails="owner@example.com", operator_emails="ops@example.com", app_data_dir=tmp_path
    )
    assert resolve_role("OWNER@example.com", config) == "owner"
    assert resolve_role("unknown@example.com", config) == "viewer"


def test_mock_api_is_labeled_and_job_is_audited(tmp_path):
    config = Settings(app_data_dir=tmp_path)
    app = create_app(config)
    with TestClient(app) as client:
        overview = client.get("/api/v1/metrics/overview")
        images = client.get("/api/v1/resources/images")
        stacks = client.get("/api/v1/resources/stacks")
        assert overview.status_code == 200
        assert overview.json()["mode"] == "mock"
        assert "DEMO" in overview.json()["serverName"]
        assert images.status_code == 200
        assert images.json()["mode"] == "mock"
        assert stacks.status_code == 200
        assert stacks.json()["mode"] == "mock"
        job = client.post(
            "/api/v1/jobs",
            headers={"x-hs-origin-verified": "1"},
            json={"operation": "restart", "target": "web"},
        )
        history = client.get("/api/v1/jobs")
        detail = client.get(f"/api/v1/jobs/{job.json()['id']}")
        missing = client.get("/api/v1/jobs/unknown")
        assert job.status_code == 201
        assert job.json()["simulation"] is True
        assert "호스트 명령은 실행하지 않았습니다" in job.json()["message"]
        assert history.json()[0]["id"] == job.json()["id"]
        assert detail.json() == job.json()
        assert missing.status_code == 404
        audit = list_audit(tmp_path)
        assert audit[0]["result"] == "simulated"
        assert audit[0]["target"] == "web"


def test_mock_overview_matches_known_host_hardware(tmp_path):
    result = providers.overview(Settings(app_data_dir=tmp_path))

    assert len(result["cpu"]["cores"]) == 8
    assert result["cpu"]["modelName"] == "Intel Core i7-2600 · DEMO"
    assert result["cpu"]["physicalCores"] == 4
    assert result["cpu"]["avx2"] is False
    assert result["memory"]["totalBytes"] == 32 * 1024**3
    assert [disk["totalBytes"] for disk in result["storage"]] == [120_000_000_000, 500_000_000_000]
    assert all(disk["health"] == "not_reported" for disk in result["storage"])
    assert all(disk["mount"].startswith("확인 필요") for disk in result["storage"])


def test_job_requires_same_origin_marker(tmp_path):
    with TestClient(create_app(Settings(app_data_dir=tmp_path))) as client:
        response = client.post("/api/v1/jobs", json={"operation": "restart", "target": "web"})
    assert response.status_code == 403


def test_live_mode_fails_closed_without_access_assertion(tmp_path):
    config = Settings(
        app_env="production",
        app_mode="live",
        app_data_dir=tmp_path,
        cf_access_issuer="https://team.cloudflareaccess.com",
        cf_access_aud="aud",
    )
    with TestClient(create_app(config)) as client:
        response = client.get("/api/v1/metrics/overview")
        logs = client.get(f"/api/v1/containers/{'a' * 64}/logs")
    assert response.status_code == 401
    assert logs.status_code == 401


def test_live_access_assertion_checks_signature_issuer_and_audience(tmp_path, monkeypatch):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    class SigningKey:
        key = private_key.public_key()

    class LocalJwks:
        def get_signing_key_from_jwt(self, _token):
            return SigningKey()

    monkeypatch.setattr(auth, "jwks_client", lambda _url: LocalJwks())
    config = Settings(
        app_env="production",
        app_mode="live",
        app_data_dir=tmp_path,
        cf_access_issuer="https://team.cloudflareaccess.com",
        cf_access_aud="expected-audience",
        owner_emails="owner@example.com",
    )
    app = create_app(config)
    now = int(time())

    def token(audience, issuer=config.cf_access_issuer, signing_key=private_key):
        return jwt.encode(
            {
                "iss": issuer,
                "aud": audience,
                "sub": "owner@example.com",
                "email": "owner@example.com",
                "exp": now + 120,
            },
            signing_key,
            algorithm="RS256",
            headers={"kid": "test-key"},
        )

    with TestClient(app) as client:
        valid = client.get(
            "/api/v1/metrics/overview",
            headers={"Cf-Access-Jwt-Assertion": token("expected-audience")},
        )
        wrong_audience = client.get(
            "/api/v1/metrics/overview", headers={"Cf-Access-Jwt-Assertion": token("wrong-audience")}
        )
        wrong_issuer = client.get(
            "/api/v1/metrics/overview",
            headers={
                "Cf-Access-Jwt-Assertion": token(
                    "expected-audience", issuer="https://wrong.example"
                )
            },
        )
        wrong_signature = client.get(
            "/api/v1/metrics/overview",
            headers={
                "Cf-Access-Jwt-Assertion": token(
                    "expected-audience",
                    signing_key=rsa.generate_private_key(public_exponent=65537, key_size=2048),
                )
            },
        )
    assert valid.status_code == 200
    assert wrong_audience.status_code == 401
    assert wrong_issuer.status_code == 401
    assert wrong_signature.status_code == 401


def test_live_mode_never_accepts_host_job(tmp_path):
    config = Settings(
        app_env="production",
        app_mode="live",
        app_data_dir=tmp_path,
        cf_access_issuer="https://team.cloudflareaccess.com",
        cf_access_aud="aud",
    )
    app = create_app(config)
    app.dependency_overrides[current_identity] = lambda: Identity(
        "operator", "ops@example.com", "owner"
    )
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/jobs",
            headers={"x-hs-origin-verified": "1"},
            json={"operation": "reboot", "target": "server"},
        )
    assert response.status_code == 503
    assert "blocked" in response.json()["detail"]


def test_live_automation_resource_uses_readiness_and_liveness_probes(tmp_path):
    config = Settings(
        app_env="production",
        app_mode="live",
        app_data_dir=tmp_path,
        cf_access_issuer="https://team.cloudflareaccess.com",
        cf_access_aud="aud",
        n8n_url="http://n8n:5678",
        openclaw_url="https://openclaw.example",
    )
    app = create_app(config)
    app.dependency_overrides[current_identity] = lambda: Identity(
        "owner", "owner@example.com", "owner"
    )

    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

    with (
        patch.object(
            providers._HEALTH_OPENER,
            "open",
            side_effect=[
                Response(),
                HTTPError(
                    "https://openclaw.example/health",
                    503,
                    "not ready",
                    {},
                    BytesIO(),
                ),
            ],
        ) as opener,
        TestClient(app) as client,
    ):
        response = client.get("/api/v1/resources/automation")

    result = response.json()
    rows = {row["id"]: row for row in result["rows"]}
    assert response.status_code == 200
    assert result["status"] == "partial"
    assert rows["n8n"]["detail"] == "HTTP 200 · 준비 상태"
    assert rows["openclaw"]["status"] == "미준비"
    assert rows["mcp"]["status"] == "미설정"
    assert rows["n8n-history"]["status"] == "미설정"
    n8n_request = opener.call_args_list[0].args[0]
    openclaw_request = opener.call_args_list[1].args[0]
    assert n8n_request.full_url == "http://n8n:5678/healthz/readiness"
    assert openclaw_request.full_url == "https://openclaw.example/health"
    assert n8n_request.get_header("Authorization") is None
    assert openclaw_request.get_header("Authorization") is None
    assert opener.call_args.kwargs == {"timeout": 2}


def test_live_automation_resource_reads_bounded_n8n_metadata_only(tmp_path):
    config = Settings(
        app_env="production",
        app_mode="live",
        app_data_dir=tmp_path,
        cf_access_issuer="https://team.cloudflareaccess.com",
        cf_access_aud="aud",
        n8n_url="http://n8n:5678",
        n8n_api_key="n8n-private-api-key-123456",
    )

    class Response:
        status = 200

        def __init__(self, body=b""):
            self.body = BytesIO(body)

        def __enter__(self):
            return self

        def __exit__(self, *_):
            self.body.close()
            return False

        def read(self, size):
            return self.body.read(size)

    payload = {
        "data": [
            {
                "id": "42",
                "workflowId": "workflow-7",
                "status": "error",
                "startedAt": "2026-11-10T03:00:00Z",
                "stoppedAt": "2026-11-10T03:00:02Z",
                "data": {"runData": {"secret-output": "never return"}},
            }
        ]
    }
    with patch.object(
        providers._HEALTH_OPENER,
        "open",
        side_effect=[Response(), Response(json.dumps(payload).encode())],
    ) as opener:
        result = providers.resource("automation", config)

    rows = {row["id"]: row for row in result["rows"]}
    assert result["status"] == "connected"
    assert rows["n8n-history"]["status"] == "최근 1개"
    assert rows["n8n-execution:42"]["status"] == "실패"
    assert "workflow-7" in rows["n8n-execution:42"]["name"]
    assert "secret-output" not in json.dumps(result, default=str)
    request = opener.call_args_list[1].args[0]
    assert request.full_url == "http://n8n:5678/api/v1/executions?limit=5"
    assert request.get_header("X-n8n-api-key") == "n8n-private-api-key-123456"
    assert opener.call_args_list[1].kwargs == {"timeout": 2}


def test_n8n_execution_reader_rejects_oversized_and_unbounded_responses(tmp_path):
    config = Settings(
        app_data_dir=tmp_path,
        n8n_url="http://n8n:5678",
        n8n_api_key="n8n-private-api-key-123456",
    )

    class Response:
        status = 200

        def __init__(self, body):
            self.body = BytesIO(body)

        def __enter__(self):
            return self

        def __exit__(self, *_):
            self.body.close()
            return False

        def read(self, size):
            return self.body.read(size)

    execution = {
        "id": "42",
        "workflowId": "workflow-7",
        "status": "success",
        "startedAt": "2026-11-10T03:00:00Z",
    }
    responses = [
        Response(b" " * 262_145),
        Response(json.dumps({"data": [execution] * 6}).encode()),
    ]
    for response in responses:
        with patch.object(providers._HEALTH_OPENER, "open", return_value=response):
            assert providers.n8n_executions(config) is None


def test_live_monitoring_reads_bounded_netdata_alerts_without_write_controls(tmp_path):
    class Response:
        status = 200

        def __init__(self, body):
            self.body = BytesIO(body)

        def __enter__(self):
            return self

        def __exit__(self, *_):
            self.body.close()
            return False

        def read(self, size):
            return self.body.read(size)

    config = Settings(
        app_env="production",
        app_mode="live",
        app_data_dir=tmp_path,
        cf_access_issuer="https://team.cloudflareaccess.com",
        cf_access_aud="aud",
        netdata_url="http://netdata:19999",
        netdata_api_token="netdata-private-token-123456",
    )
    payload = {
        "alert_instances": [
            {"nm": "disk_space_usage", "ctx": "disk.space", "st": "CRITICAL", "v": 91.5, "units": "%", "t": 1_794_283_200},
            {"nm": "cpu_usage", "ctx": "system.cpu", "st": "WARNING", "v": 78, "units": "%", "t": 1_794_283_200},
        ],
        "private_config": "never return",
    }
    with patch.object(
        providers._HEALTH_OPENER,
        "open",
        return_value=Response(json.dumps(payload).encode()),
    ) as opener:
        result = providers.resource("monitoring", config)

    rows = {row["id"]: row for row in result["rows"]}
    assert result["status"] == "partial"
    assert result["metrics"][0]["value"] == "1/3"
    assert result["metrics"][1]["value"] == "2"
    assert rows["netdata-alert:0"]["status"] == "CRITICAL"
    assert rows["netdata-alert:0"]["detail"] == "disk.space · 91.5 %"
    assert rows["uptime-kuma"]["status"] == "미연결"
    assert rows["scrutiny"]["status"] == "미설정"
    assert "private_config" not in json.dumps(result)
    request = opener.call_args.args[0]
    assert request.full_url == "http://netdata:19999/api/v3/alerts"
    assert request.get_method() == "POST"
    assert request.get_header("Authorization") == "Bearer netdata-private-token-123456"
    assert json.loads(request.data) == {
        "status": ["CRITICAL", "WARNING"],
        "options": ["values", "instances"],
        "cardinality": 100,
    }
    assert opener.call_args.kwargs == {"timeout": 2}


def test_scrutiny_summary_is_bounded_and_redacts_device_identifiers(tmp_path):
    class Response:
        status = 200

        def __init__(self, body):
            self.body = BytesIO(body)

        def __enter__(self):
            return self

        def __exit__(self, *_):
            self.body.close()
            return False

        def read(self, size):
            return self.body.read(size)

    config = Settings(
        app_env="production",
        app_mode="live",
        app_data_dir=tmp_path,
        cf_access_issuer="https://team.cloudflareaccess.com",
        cf_access_aud="aud",
        scrutiny_url="http://scrutiny:8080",
    )
    payload = {
        "success": True,
        "errors": [],
        "data": {
            "summary": {
                "device-a": {
                    "device": {
                        "device_name": "sda",
                        "device_label": "Archive HDD",
                        "manufacturer": "Seagate",
                        "model_name": "IronWolf",
                        "capacity": 4_000_000_000_000,
                        "device_status": 3,
                        "smart_support": True,
                        "serial_number": "serial-private",
                        "wwn": "wwn-private",
                    },
                    "smart": {
                        "collector_date": "2026-11-10T02:50:00Z",
                        "temp": 43,
                        "power_on_hours": 1234,
                    },
                    "temp_history": [{"date": "private history"}],
                },
                "device-b": {
                    "device": {
                        "device_name": "nvme0n1",
                        "label": "OS SSD",
                        "manufacturer": "Samsung",
                        "model_name": "980 PRO",
                        "capacity": 1_000_000_000_000,
                        "device_status": 0,
                        "smart_support": True,
                    },
                    "smart": {"temp": 38, "power_on_hours": 800},
                },
            }
        },
    }
    encoded = json.dumps(payload).encode()
    with patch.object(
        providers._HEALTH_OPENER,
        "open",
        side_effect=[Response(encoded), Response(encoded)],
    ) as opener:
        monitoring = providers.resource("monitoring", config)
        storage = providers.resource("storage", config)

    monitoring_rows = {row["id"]: row for row in monitoring["rows"]}
    storage_rows = {row["name"]: row for row in storage["rows"]}
    assert monitoring["status"] == "partial"
    assert monitoring["metrics"][0]["value"] == "1/3"
    assert monitoring["metrics"][2]["value"] == "2"
    assert monitoring["metrics"][3]["value"] == "1"
    assert monitoring_rows["scrutiny"]["status"] == "정상"
    assert monitoring_rows["scrutiny:0"]["status"] == "오류"
    assert monitoring_rows["scrutiny:0"]["name"] == "Scrutiny · Archive HDD"
    assert monitoring_rows["scrutiny:0"]["detail"] == "Seagate IronWolf · 4000.0 GB · 43°C · 1234시간 · S.M.A.R.T 검사 실패 · Scrutiny 검사 실패"
    assert storage["status"] == "partial"
    assert storage_rows["S.M.A.R.T · Archive HDD"]["status"] == "오류"
    body = json.dumps([monitoring, storage])
    assert "serial-private" not in body
    assert "wwn-private" not in body
    assert "private history" not in body
    for request in (call.args[0] for call in opener.call_args_list):
        assert request.full_url == "http://scrutiny:8080/api/summary"
        assert request.get_method() == "GET"
        assert request.get_header("Authorization") is None
    assert all(call.kwargs == {"timeout": 2} for call in opener.call_args_list)


def test_scrutiny_reader_rejects_oversized_and_unbounded_summaries(tmp_path):
    class Response:
        status = 200

        def __init__(self, body):
            self.body = BytesIO(body)

        def __enter__(self):
            return self

        def __exit__(self, *_):
            self.body.close()
            return False

        def read(self, size):
            return self.body.read(size)

    config = Settings(app_data_dir=tmp_path, scrutiny_url="http://scrutiny:8080")
    device = {"device": {"device_status": 0}}
    too_many = json.dumps({"success": True, "data": {"summary": {str(index): device for index in range(101)}}}).encode()
    for response in (Response(b" " * 262_145), Response(too_many)):
        with patch.object(providers._HEALTH_OPENER, "open", return_value=response):
            assert providers.scrutiny_devices(config) is None


def test_netdata_reader_rejects_oversized_and_unbounded_alert_payloads(tmp_path):
    class Response:
        status = 200

        def __init__(self, body):
            self.body = BytesIO(body)

        def __enter__(self):
            return self

        def __exit__(self, *_):
            self.body.close()
            return False

        def read(self, size):
            return self.body.read(size)

    config = Settings(
        app_data_dir=tmp_path,
        netdata_url="http://netdata:19999",
    )
    alert = {"nm": "cpu_usage", "st": "WARNING"}
    for response in (
        Response(b" " * 262_145),
        Response(json.dumps({"alert_instances": [alert] * 101}).encode()),
    ):
        with patch.object(providers._HEALTH_OPENER, "open", return_value=response):
            assert providers.netdata_alerts(config) is None


def test_live_automation_resource_shows_unconfigured_integrations(tmp_path):
    config = Settings(
        app_env="production",
        app_mode="live",
        app_data_dir=tmp_path,
        cf_access_issuer="https://team.cloudflareaccess.com",
        cf_access_aud="aud",
    )

    result = providers.resource("automation", config)

    assert result["status"] == "not_configured"
    assert {row["id"] for row in result["rows"]} == {
        "n8n",
        "openclaw",
        "mcp",
        "n8n-history",
    }
    assert all(row["status"] == "미설정" for row in result["rows"][:2])


def test_live_notifications_include_automation_readiness_failures(tmp_path):
    config = Settings(
        app_env="production",
        app_mode="live",
        app_data_dir=tmp_path,
        cf_access_issuer="https://team.cloudflareaccess.com",
        cf_access_aud="aud",
        n8n_url="http://n8n:5678",
    )
    failure = HTTPError(
        "http://n8n:5678/healthz/readiness", 503, "not ready", {}, BytesIO()
    )

    with patch.object(providers._HEALTH_OPENER, "open", side_effect=failure):
        result = providers.resource("notifications", config)

    assert result["status"] == "unavailable"
    row = next(row for row in result["rows"] if row["id"] == "automation:n8n")
    assert row["status"] == "failed"
    assert row["detail"] == "HTTP 503 · health check 실패"


def test_ntfy_sends_and_resolves_automation_health_alerts(tmp_path):
    class HealthyResponse:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

    class NtfyResponse:
        status = 202

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

    config = Settings(
        app_env="production",
        app_mode="live",
        app_data_dir=tmp_path,
        cf_access_issuer="https://team.cloudflareaccess.com",
        cf_access_aud="aud",
        n8n_url="http://n8n:5678",
        ntfy_url="https://ntfy.example",
        ntfy_topic="homeserver_alerts",
    )
    initialize(tmp_path)
    failure = HTTPError(
        "http://n8n:5678/healthz/readiness", 503, "not ready", {}, BytesIO()
    )

    with (
        patch.object(
            providers._HEALTH_OPENER,
            "open",
            side_effect=[failure, HealthyResponse()],
        ),
        patch.object(
            notifications._NTFY_OPENER, "open", return_value=NtfyResponse()
        ) as publish,
    ):
        assert notifications.send_notification_changes(config, tmp_path)
        assert list_notification_alerts(tmp_path) == {
            "automation:n8n": "자동화 · n8n"
        }
        assert notifications.send_notification_changes(config, tmp_path)

    assert list_notification_alerts(tmp_path) == {}
    assert "경고: 자동화 · n8n" in publish.call_args_list[0].args[0].data.decode()
    assert "정상화: 자동화 · n8n" in publish.call_args_list[1].args[0].data.decode()
