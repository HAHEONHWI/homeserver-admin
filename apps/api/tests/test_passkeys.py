import hashlib
import time
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

import app.passkeys as passkeys
from app.auth import Identity, current_identity
from app.main import create_app
from app.settings import Settings
from app.store import (
    add_passkey,
    consume_reauth_grant,
    consume_webauthn_challenge,
    delete_passkey,
    initialize,
    issue_webauthn_challenge,
    store_reauth_grant,
)

ORIGIN = "https://dashboard.example.com"
TOKEN = "a" * 64
IDENTITY = Identity("account-1", "owner@example.com", "owner")
HEADERS = {"x-hs-origin-verified": "1"}


@pytest.mark.parametrize(
    "origin",
    [
        "https://dashboard.example.com/",
        "https://dashboard.example.com:443",
        "https://DASHBOARD.example.com",
        "https://dashboard.example.com:99999",
    ],
)
def test_webauthn_origin_must_be_canonical(origin, tmp_path):
    with pytest.raises(ValueError):
        Settings(app_data_dir=tmp_path, web_origin=origin)


def test_webauthn_challenge_is_subject_scoped_and_single_use(tmp_path):
    initialize(tmp_path)
    issue_webauthn_challenge(
        tmp_path, "challenge-1", "account-1", "reauth", "delete_passkey", "credential-1",
        b"challenge", False, time.time() + 120,
    )

    assert consume_webauthn_challenge(tmp_path, "challenge-1", "account-2", "reauth", time.time()) is None
    consumed = consume_webauthn_challenge(
        tmp_path, "challenge-1", "account-1", "reauth", time.time()
    )
    assert consumed == {
        "operation": "delete_passkey",
        "target": "credential-1",
        "challenge": b"challenge",
        "bootstrap": 0,
    }
    assert consume_webauthn_challenge(
        tmp_path, "challenge-1", "account-1", "reauth", time.time()
    ) is None


def test_reauthentication_grant_is_scoped_and_single_use(tmp_path):
    initialize(tmp_path)
    grant = "g" * 43
    token_hash = hashlib.sha256(grant.encode()).hexdigest()
    store_reauth_grant(
        tmp_path, token_hash, "account-1", "delete_passkey", "credential-1", time.time() + 60
    )

    assert not consume_reauth_grant(
        tmp_path, token_hash, "account-1", "delete_passkey", "credential-2", time.time()
    )
    assert consume_reauth_grant(
        tmp_path, token_hash, "account-1", "delete_passkey", "credential-1", time.time()
    )
    assert not consume_reauth_grant(
        tmp_path, token_hash, "account-1", "delete_passkey", "credential-1", time.time()
    )


def test_passkey_removal_revokes_pending_registration_authorization(tmp_path):
    initialize(tmp_path)
    for credential_id in ("AQID", "BAUG"):
        add_passkey(
            tmp_path,
            "account-1",
            credential_id,
            b"public-key",
            0,
            "device",
            "2026-11-10T00:00:00+00:00",
            "owner@example.com",
        )
    issue_webauthn_challenge(
        tmp_path,
        "pending-registration",
        "account-1",
        "register",
        "register_passkey",
        "account",
        b"challenge",
        False,
        time.time() + 120,
    )
    pending_grant = "g" * 43
    pending_grant_hash = hashlib.sha256(pending_grant.encode()).hexdigest()
    store_reauth_grant(
        tmp_path,
        pending_grant_hash,
        "account-1",
        "register_passkey",
        "account",
        time.time() + 60,
    )

    assert delete_passkey(tmp_path, "account-1", "AQID", "owner@example.com")
    assert not consume_reauth_grant(
        tmp_path,
        pending_grant_hash,
        "account-1",
        "register_passkey",
        "account",
        time.time(),
    )
    assert consume_webauthn_challenge(
        tmp_path, "pending-registration", "account-1", "register", time.time()
    ) is None


def test_used_registration_challenge_survives_issue_of_another_challenge(tmp_path):
    initialize(tmp_path)
    issue_webauthn_challenge(
        tmp_path,
        "registration",
        "account-1",
        "register",
        "register_passkey",
        "account",
        b"registration-challenge",
        False,
        time.time() + 120,
    )
    assert consume_webauthn_challenge(
        tmp_path, "registration", "account-1", "register", time.time()
    )
    issue_webauthn_challenge(
        tmp_path,
        "reauthentication",
        "account-1",
        "reauth",
        "register_passkey",
        "account",
        b"reauthentication-challenge",
        False,
        time.time() + 120,
    )

    assert add_passkey(
        tmp_path,
        "account-1",
        "AQID",
        b"public-key",
        0,
        "MacBook",
        "2026-11-10T00:00:00+00:00",
        "owner@example.com",
        registration_challenge_id="registration",
    )


def test_container_reauthentication_challenge_binds_operation_to_exact_container(tmp_path):
    initialize(tmp_path)
    add_passkey(
        tmp_path,
        "account-1",
        "AQID",
        b"public-key",
        0,
        "MacBook",
        "2026-11-10T00:00:00+00:00",
        "owner@example.com",
    )
    container_id = "a" * 64
    settings = Settings(
        app_env="production",
        app_mode="live",
        app_data_dir=tmp_path,
        web_origin=ORIGIN,
        cf_access_issuer="https://team.cloudflareaccess.com",
        cf_access_aud="aud",
    )

    challenge = passkeys.begin_reauthentication(
        settings, tmp_path, "account-1", "restart", container_id
    )
    consumed = consume_webauthn_challenge(
        tmp_path, challenge["challengeId"], "account-1", "reauth", time.time()
    )

    assert consumed["operation"] == "restart"
    assert consumed["target"] == container_id


def test_database_initialization_invalidates_pending_ceremonies_and_grants(tmp_path):
    initialize(tmp_path)
    expires = time.time() + 120
    issue_webauthn_challenge(
        tmp_path, "challenge-1", "account-1", "reauth", "delete_passkey", "credential-1",
        b"challenge", False, expires,
    )
    token_hash = hashlib.sha256(b"grant").hexdigest()
    store_reauth_grant(
        tmp_path, token_hash, "account-1", "delete_passkey", "credential-1", expires
    )

    initialize(tmp_path)

    assert consume_webauthn_challenge(
        tmp_path, "challenge-1", "account-1", "reauth", time.time()
    ) is None
    assert not consume_reauth_grant(
        tmp_path, token_hash, "account-1", "delete_passkey", "credential-1", time.time()
    )


def test_passkey_routes_require_same_origin_bootstrap_and_fresh_reauthentication(tmp_path):
    settings = Settings(
        app_env="production",
        app_mode="live",
        app_data_dir=tmp_path,
        web_origin=ORIGIN,
        webauthn_bootstrap_token=TOKEN,
        cf_access_issuer="https://team.cloudflareaccess.com",
        cf_access_aud="audience",
    )
    app = create_app(settings)
    app.dependency_overrides[current_identity] = lambda: IDENTITY
    registered = SimpleNamespace(
        credential_id=b"credential-1",
        credential_public_key=b"public-key",
        sign_count=0,
        user_verified=True,
    )
    authenticated = SimpleNamespace(
        credential_id=b"credential-1", new_sign_count=1, user_verified=True
    )
    authenticated_second = SimpleNamespace(
        credential_id=b"credential-2", new_sign_count=1, user_verified=True
    )
    authenticated_second_again = SimpleNamespace(
        credential_id=b"credential-2", new_sign_count=2, user_verified=True
    )

    with TestClient(app) as client:
        missing_origin = client.post(
            "/api/v1/webauthn/register/options",
            json={"name": "MacBook", "bootstrapToken": TOKEN},
        )
        assert missing_origin.status_code == 403

        bad_token = client.post(
            "/api/v1/webauthn/register/options",
            headers=HEADERS,
            json={"name": "MacBook", "bootstrapToken": "b" * 64},
        )
        assert bad_token.status_code == 403
        assert TOKEN not in bad_token.text and "b" * 64 not in bad_token.text
        malformed_token = client.post(
            "/api/v1/webauthn/register/options",
            headers=HEADERS,
            json={"name": "MacBook", "bootstrapToken": "short"},
        )
        assert malformed_token.status_code == 422
        assert "short" not in malformed_token.text

        start = client.post(
            "/api/v1/webauthn/register/options",
            headers=HEADERS,
            json={"name": "MacBook", "bootstrapToken": TOKEN},
        )
        assert start.status_code == 200
        options = start.json()["options"]
        assert options["rp"]["id"] == "dashboard.example.com"
        assert options["authenticatorSelection"]["residentKey"] == "required"
        assert options["authenticatorSelection"]["userVerification"] == "required"
        assert client.get("/api/v1/webauthn/status").json() == {
            "passkeys": [], "bootstrapRequired": True
        }

        registration = {"id": "Y3JlZGVudGlhbC0x", "rawId": "Y3JlZGVudGlhbC0x"}
        with patch.object(passkeys, "verify_registration_response", return_value=registered) as verify:
            finish = client.post(
                "/api/v1/webauthn/register/verify",
                headers=HEADERS,
                json={"challengeId": start.json()["challengeId"], "credential": registration},
            )
        assert finish.status_code == 200
        assert finish.json()["passkey"]["name"] == "MacBook"
        assert verify.call_args.kwargs["expected_origin"] == ORIGIN
        assert verify.call_args.kwargs["require_user_verification"] is True
        replay = client.post(
            "/api/v1/webauthn/register/verify",
            headers=HEADERS,
            json={"challengeId": start.json()["challengeId"], "credential": registration},
        )
        assert replay.status_code == 400

        key_id = finish.json()["passkey"]["id"]
        reauth = client.post(
            "/api/v1/webauthn/reauth/options",
            headers=HEADERS,
            json={"operation": "register_passkey", "target": "account"},
        )
        assert reauth.status_code == 200
        assert reauth.json()["options"]["userVerification"] == "required"
        assertion = {"id": key_id, "rawId": key_id}
        with patch.object(passkeys, "verify_authentication_response", return_value=authenticated) as verify:
            proof = client.post(
                "/api/v1/webauthn/reauth/verify",
                headers=HEADERS,
                json={"challengeId": reauth.json()["challengeId"], "credential": assertion},
            )
        assert proof.status_code == 200
        assert verify.call_args.kwargs["expected_origin"] == ORIGIN
        grant = proof.json()["grant"]

        add_second = client.post(
            "/api/v1/webauthn/register/options",
            headers=HEADERS,
            json={"name": "Phone", "reauthGrant": grant},
        )
        assert add_second.status_code == 200
        replayed_grant = client.post(
            "/api/v1/webauthn/register/options",
            headers=HEADERS,
            json={"name": "Tablet", "reauthGrant": grant},
        )
        assert replayed_grant.status_code == 403

        second_credential = SimpleNamespace(
            credential_id=b"credential-2",
            credential_public_key=b"second-public-key",
            sign_count=0,
            user_verified=True,
        )
        with patch.object(passkeys, "verify_registration_response", return_value=second_credential):
            second_finish = client.post(
                "/api/v1/webauthn/register/verify",
                headers=HEADERS,
                json={
                    "challengeId": add_second.json()["challengeId"],
                    "credential": {"id": "Y3JlZGVudGlhbC0y", "rawId": "Y3JlZGVudGlhbC0y"},
                },
            )
        assert second_finish.status_code == 200
        second_id = second_finish.json()["passkey"]["id"]

        pending_auth = client.post(
            "/api/v1/webauthn/reauth/options",
            headers=HEADERS,
            json={"operation": "register_passkey", "target": "account"},
        )
        with patch.object(passkeys, "verify_authentication_response", return_value=authenticated):
            pending_proof = client.post(
                "/api/v1/webauthn/reauth/verify",
                headers=HEADERS,
                json={
                    "challengeId": pending_auth.json()["challengeId"],
                    "credential": {"id": key_id, "rawId": key_id},
                },
            )
        pending_add = client.post(
            "/api/v1/webauthn/register/options",
            headers=HEADERS,
            json={"name": "Unapproved device", "reauthGrant": pending_proof.json()["grant"]},
        )
        assert pending_add.status_code == 200

        delete_auth = client.post(
            "/api/v1/webauthn/reauth/options",
            headers=HEADERS,
            json={"operation": "delete_passkey", "target": key_id},
        )
        assert delete_auth.status_code == 200
        with patch.object(passkeys, "verify_authentication_response", return_value=authenticated_second):
            delete_proof = client.post(
                "/api/v1/webauthn/reauth/verify",
                headers=HEADERS,
                json={
                    "challengeId": delete_auth.json()["challengeId"],
                    "credential": {"id": second_id, "rawId": second_id},
                },
            )
        delete_grant = delete_proof.json()["grant"]
        wrong_target = client.post(
            "/api/v1/webauthn/passkeys/delete",
            headers=HEADERS,
            json={"credentialId": second_id, "reauthGrant": delete_grant},
        )
        assert wrong_target.status_code == 403
        deleted = client.post(
            "/api/v1/webauthn/passkeys/delete",
            headers=HEADERS,
            json={"credentialId": key_id, "reauthGrant": delete_grant},
        )
        assert deleted.status_code == 204
        with patch.object(passkeys, "verify_registration_response") as stale_verify:
            stale_finish = client.post(
                "/api/v1/webauthn/register/verify",
                headers=HEADERS,
                json={
                    "challengeId": pending_add.json()["challengeId"],
                    "credential": {"id": "YXR0YWNrZXItZGV2aWNl", "rawId": "YXR0YWNrZXItZGV2aWNl"},
                },
            )
        assert stale_finish.status_code == 400
        stale_verify.assert_not_called()

        last_auth = client.post(
            "/api/v1/webauthn/reauth/options",
            headers=HEADERS,
            json={"operation": "delete_passkey", "target": second_id},
        )
        assert last_auth.status_code == 200
        with patch.object(passkeys, "verify_authentication_response", return_value=authenticated_second_again):
            last_proof = client.post(
                "/api/v1/webauthn/reauth/verify",
                headers=HEADERS,
                json={
                    "challengeId": last_auth.json()["challengeId"],
                    "credential": {"id": second_id, "rawId": second_id},
                },
            )
        last_delete = client.post(
            "/api/v1/webauthn/passkeys/delete",
            headers=HEADERS,
            json={"credentialId": second_id, "reauthGrant": last_proof.json()["grant"]},
        )
        assert last_delete.status_code == 409

        status_response = client.get("/api/v1/webauthn/status")
        assert status_response.headers["cache-control"] == "no-store"
        assert status_response.json()["bootstrapRequired"] is False
        assert len(status_response.json()["passkeys"]) == 1
        audit = client.get("/api/v1/audit").json()
        assert [event["operation"] for event in audit].count("passkey.add") == 2
        assert [event["operation"] for event in audit].count("passkey.remove") == 1
        removed_event = next(event for event in audit if event["operation"] == "passkey.remove")
        assert removed_event["target"] == key_id
        assert removed_event["details"] == "MacBook"
