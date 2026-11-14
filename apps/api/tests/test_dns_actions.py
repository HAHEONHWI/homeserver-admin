import hashlib
import json
import sqlite3
from time import time
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app import providers
from app.auth import Identity, current_identity
from app.dns_actions import dns_action_scope, validate_dns_change
from app.main import create_app
from app.schemas import DnsRecordChange, DnsRecordValue
from app.settings import Settings
from app.store import initialize, list_audit, store_reauth_grant


def config(tmp_path):
    return Settings(
        app_env="production",
        app_mode="live",
        app_data_dir=tmp_path,
        web_origin="https://dashboard.example.com",
        cf_access_issuer="https://team.cloudflareaccess.com",
        cf_access_aud="audience",
        cloudflare_api_token="r" * 24,
        cloudflare_dns_write_token="w" * 24,
        cloudflare_zone_id="a" * 32,
        cloudflare_zone_name="example.com",
    )


def live_config(tmp_path):
    return config(tmp_path)


def test_dns_change_normalizes_names_and_requires_zone_scope(tmp_path):
    result = validate_dns_change(
        config(tmp_path),
        "dns_create",
        DnsRecordChange(
            after=DnsRecordValue(
                name="API.Example.com.", type="A", content="192.0.2.4", ttl=1
            )
        ),
    )
    assert result.after.name == "api.example.com"
    assert result.after.content == "192.0.2.4"

    wildcard = validate_dns_change(
        config(tmp_path),
        "dns_create",
        DnsRecordChange(
            after=DnsRecordValue(
                name="*.example.com", type="A", content="192.0.2.4", ttl=1
            )
        ),
    )
    assert wildcard.after.name == "*.example.com"

    with pytest.raises(HTTPException) as error:
        validate_dns_change(
            config(tmp_path),
            "dns_create",
            DnsRecordChange(
                after=DnsRecordValue(
                    name="attacker.example.net", type="A", content="192.0.2.4", ttl=1
                )
            ),
        )
    assert error.value.status_code == 422

    with pytest.raises(HTTPException, match="DNS name must be inside the configured zone"):
        validate_dns_change(
            config(tmp_path),
            "dns_create",
            DnsRecordChange(
                after=DnsRecordValue(
                    name="api*.example.com", type="A", content="192.0.2.4", ttl=1
                )
            ),
        )


def test_dns_change_requires_consistent_record_shape_and_content(tmp_path):
    existing = DnsRecordValue(
        name="api.example.com", type="A", content="192.0.2.4", ttl=300
    )
    with pytest.raises(HTTPException) as shape_error:
        validate_dns_change(
            config(tmp_path), "dns_update", DnsRecordChange(before=existing, after=existing)
        )
    assert "DNS update requires" in shape_error.value.detail
    with pytest.raises(ValidationError, match="Only MX records require a priority"):
        DnsRecordValue(name="mail.example.com", type="MX", content="mx.example.com", ttl=300)
    with pytest.raises(HTTPException) as content_error:
        validate_dns_change(
            config(tmp_path),
            "dns_create",
            DnsRecordChange(
                after=DnsRecordValue(name="api.example.com", type="AAAA", content="192.0.2.4", ttl=300)
            ),
        )
    assert "DNS content is invalid" in content_error.value.detail


def test_dns_reauthentication_scope_binds_every_change_field(tmp_path):
    change = validate_dns_change(
        config(tmp_path),
        "dns_create",
        DnsRecordChange(
            after=DnsRecordValue(
                name="api.example.com", type="A", content="192.0.2.4", ttl=300
            )
        ),
    )
    original = dns_action_scope("dns_create", change)
    changed = validate_dns_change(
        config(tmp_path),
        "dns_create",
        DnsRecordChange(
            after=DnsRecordValue(
                name="api.example.com", type="A", content="192.0.2.5", ttl=300
            )
        ),
    )
    assert len(original) == 64
    assert original != dns_action_scope("dns_create", changed)


def test_audit_store_migrates_existing_database_to_dns_details(tmp_path):
    with sqlite3.connect(tmp_path / "admin.sqlite3") as connection:
        connection.execute(
            "CREATE TABLE audit_events (id TEXT PRIMARY KEY, actor TEXT NOT NULL, "
            "operation TEXT NOT NULL, target TEXT NOT NULL, result TEXT NOT NULL, "
            "created_at TEXT NOT NULL)"
        )
        connection.execute(
            "INSERT INTO audit_events VALUES ('event-1', 'owner', 'dns_create', "
            "'A example.com', 'succeeded', '2026-11-10T00:00:00+00:00')"
        )
    initialize(tmp_path)
    event = list_audit(tmp_path)[0]
    assert event["id"] == "event-1"
    assert event["details"] == ""


@pytest.mark.parametrize(
    ("operation", "method", "suffix"),
    [
        ("dns_create", "POST", ""),
        ("dns_update", "PATCH", f"/{'b' * 32}"),
        ("dns_delete", "DELETE", f"/{'b' * 32}"),
    ],
)
def test_cloudflare_dns_mutations_use_fixed_zone_routes_and_write_token(
    tmp_path, operation, method, suffix
):
    config_value = config(tmp_path)
    record_id = "b" * 32
    record = DnsRecordValue(
        name="api.example.com", type="A", content="192.0.2.4", ttl=300
    )
    change = DnsRecordChange(
        recordId=record_id if operation != "dns_create" else None,
        before=record if operation != "dns_create" else None,
        after=record if operation != "dns_delete" else None,
    )
    payload = (
        {"success": True, "result": {"id": record_id}}
        if operation == "dns_delete"
        else {
            "success": True,
            "result": {
                "id": record_id,
                "name": record.name,
                "type": record.type,
                "content": record.content,
                "ttl": record.ttl,
                "proxied": False,
            },
        }
    )

    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return None

        def read(self, _limit):
            import json

            return json.dumps(payload).encode()

    with (
        patch.object(providers, "cloudflare_dns_record_matches", return_value=True) as matches,
        patch.object(providers._AGENT_OPENER, "open", return_value=Response()) as opener,
    ):
        result, details = providers.cloudflare_dns_mutation(config_value, operation, change)

    request: Request = opener.call_args.args[0]
    assert request.full_url.endswith(f"/zones/{'a' * 32}/dns_records{suffix}")
    assert request.get_method() == method
    assert request.get_header("Authorization") == f"Bearer {'w' * 24}"
    assert result is True
    assert details["id"] == record_id
    if operation == "dns_create":
        matches.assert_not_called()
    else:
        matches.assert_called_once_with(config_value, record_id, record)


@pytest.mark.parametrize(
    ("current", "expected"),
    [(False, (False, None)), (None, (None, None))],
)
def test_cloudflare_dns_mutation_rechecks_existing_record_before_write(
    tmp_path, current, expected
):
    config_value = config(tmp_path)
    record = DnsRecordValue(
        name="api.example.com", type="A", content="192.0.2.4", ttl=300
    )
    change = DnsRecordChange(
        recordId="b" * 32,
        before=record,
        after=record.model_copy(update={"content": "192.0.2.5"}),
    )
    with (
        patch.object(providers, "cloudflare_dns_record_matches", return_value=current),
        patch.object(providers._AGENT_OPENER, "open") as opener,
    ):
        assert providers.cloudflare_dns_mutation(config_value, "dns_update", change) == expected
    opener.assert_not_called()


def test_cloudflare_dns_mutation_distinguishes_rejection_and_unknown_result(tmp_path):
    config_value = config(tmp_path)
    record = DnsRecordValue(
        name="api.example.com", type="A", content="192.0.2.4", ttl=300
    )
    change = DnsRecordChange(after=record)
    http_error = HTTPError("https://api.cloudflare.com", 400, "invalid", {}, None)
    with patch.object(providers._AGENT_OPENER, "open", side_effect=http_error):
        assert providers.cloudflare_dns_mutation(config_value, "dns_create", change) == (False, None)
    server_error = HTTPError("https://api.cloudflare.com", 503, "unavailable", {}, None)
    with patch.object(providers._AGENT_OPENER, "open", side_effect=server_error):
        assert providers.cloudflare_dns_mutation(config_value, "dns_create", change) == (None, None)
    with patch.object(providers._AGENT_OPENER, "open", side_effect=TimeoutError):
        assert providers.cloudflare_dns_mutation(config_value, "dns_create", change) == (None, None)


def test_cloudflare_dns_record_uses_read_token_on_fixed_zone_route(tmp_path):
    config_value = config(tmp_path)
    record_id = "b" * 32

    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return None

        def read(self, _limit):
            return json.dumps({
                "success": True,
                "result": {
                    "id": record_id,
                    "name": "api.example.com",
                    "type": "A",
                    "content": "192.0.2.4",
                    "ttl": 300,
                    "proxied": False,
                },
            }).encode()

    with patch.object(providers._AGENT_OPENER, "open", return_value=Response()) as opener:
        result = providers.cloudflare_dns_record(config_value, record_id)
    request = opener.call_args.args[0]
    assert request.full_url == (
        f"https://api.cloudflare.com/client/v4/zones/{'a' * 32}/dns_records/{record_id}"
    )
    assert request.get_method() == "GET"
    assert request.get_header("Authorization") == f"Bearer {'r' * 24}"
    assert result.id == record_id


def test_live_dns_reauthentication_binds_change_and_requires_owner(tmp_path):
    settings = live_config(tmp_path)
    app = create_app(settings)
    app.dependency_overrides[current_identity] = lambda: Identity(
        "owner", "owner@example.com", "owner"
    )
    change = DnsRecordChange(
        after=DnsRecordValue(
            name="api.example.com", type="A", content="192.0.2.4", ttl=300
        )
    )
    with patch(
        "app.main.passkeys.begin_reauthentication",
        return_value={"challengeId": "test", "options": {}},
    ) as reauth:
        with TestClient(app) as client:
            response = client.post(
                "/api/v1/webauthn/reauth/options",
                headers={"x-hs-origin-verified": "1"},
                json={
                    "operation": "dns_create",
                    "target": "zone",
                    "dnsChange": change.model_dump(mode="json", exclude_none=True),
                },
            )
    assert response.status_code == 200
    assert reauth.call_args.args[3:] == (
        "dns_create",
        dns_action_scope("dns_create", validate_dns_change(settings, "dns_create", change)),
    )

    app.dependency_overrides[current_identity] = lambda: Identity(
        "viewer", "viewer@example.com", "viewer"
    )
    with patch("app.main.passkeys.begin_reauthentication") as reauth:
        with TestClient(app) as client:
            denied = client.post(
                "/api/v1/webauthn/reauth/options",
                headers={"x-hs-origin-verified": "1"},
                json={
                    "operation": "dns_create",
                    "target": "zone",
                    "dnsChange": change.model_dump(mode="json", exclude_none=True),
                },
            )
    assert denied.status_code == 403
    reauth.assert_not_called()


def test_live_dns_update_rejects_stale_snapshot_before_passkey_prompt(tmp_path):
    app = create_app(live_config(tmp_path))
    app.dependency_overrides[current_identity] = lambda: Identity(
        "owner", "owner@example.com", "owner"
    )
    before = DnsRecordValue(
        name="api.example.com", type="A", content="192.0.2.4", ttl=300
    )
    after = before.model_copy(update={"content": "192.0.2.5"})
    change = DnsRecordChange(recordId="b" * 32, before=before, after=after)
    with (
        patch("app.main.cloudflare_dns_record_matches", return_value=False),
        patch("app.main.passkeys.begin_reauthentication") as reauth,
    ):
        with TestClient(app) as client:
            response = client.post(
                "/api/v1/webauthn/reauth/options",
                headers={"x-hs-origin-verified": "1"},
                json={
                    "operation": "dns_update",
                    "target": "b" * 32,
                    "dnsChange": change.model_dump(mode="json", exclude_none=True),
                },
            )
    assert response.status_code == 409
    reauth.assert_not_called()


def test_live_dns_job_consumes_exact_grant_and_audits_before_after(tmp_path):
    settings = live_config(tmp_path)
    app = create_app(settings)
    app.dependency_overrides[current_identity] = lambda: Identity(
        "owner", "owner@example.com", "owner"
    )
    change = DnsRecordChange(
        after=DnsRecordValue(
            name="api.example.com", type="A", content="192.0.2.4", ttl=300
        )
    )
    scope = dns_action_scope("dns_create", validate_dns_change(settings, "dns_create", change))
    token = "g" * 43
    body = {
        "operation": "dns_create",
        "target": "zone",
        "dnsChange": change.model_dump(mode="json", exclude_none=True),
        "reauthGrant": token,
    }
    with TestClient(app) as client:
        store_reauth_grant(
            tmp_path,
            hashlib.sha256(token.encode()).hexdigest(),
            "owner",
            "dns_create",
            scope,
            time() + 60,
        )
        with patch(
            "app.main.cloudflare_dns_mutation", return_value=(True, {"id": "b" * 32})
        ) as mutate:
            altered = {**body, "dnsChange": {"after": {**body["dnsChange"]["after"], "content": "192.0.2.5"}}}
            wrong_change = client.post(
                "/api/v1/jobs", headers={"x-hs-origin-verified": "1"}, json=altered
            )
            assert wrong_change.status_code == 403
            mutate.assert_not_called()

            result = client.post(
                "/api/v1/jobs", headers={"x-hs-origin-verified": "1"}, json=body
            )
            replay = client.post(
                "/api/v1/jobs", headers={"x-hs-origin-verified": "1"}, json=body
            )
        assert result.status_code == 201
        assert result.json()["state"] == "succeeded"
        assert result.json()["target"] == "A api.example.com"
        assert replay.status_code == 403
        mutate.assert_called_once()

    event = list_audit(tmp_path)[0]
    assert event["result"] == "succeeded"
    details = json.loads(event["details"])
    assert details["before"] is None
    assert details["after"]["content"] == "192.0.2.4"
    assert details["result"]["id"] == "b" * 32
