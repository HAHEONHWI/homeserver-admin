import hashlib
import hmac
import json
import re
import secrets
import time
from datetime import UTC, datetime
from urllib.parse import urlsplit
from uuid import uuid4

from fastapi import HTTPException, status
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url, options_to_json
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from app.auth import Identity
from app.settings import Settings
from app.store import (
    add_passkey,
    consume_reauth_grant,
    consume_webauthn_challenge,
    delete_passkey,
    get_passkey,
    issue_webauthn_challenge,
    list_passkeys,
    store_reauth_grant,
    update_passkey_sign_count,
)

_CHALLENGE_TTL = 120
_GRANT_TTL = 60
_PASSKEY_ID = re.compile(r"^[A-Za-z0-9_-]{1,1024}$")


def status_for(data_dir, subject: str) -> dict:
    passkeys = list_passkeys(data_dir, subject)
    return {
        "passkeys": [
            {"id": item["credential_id"], "name": item["name"], "createdAt": item["created_at"]}
            for item in passkeys
        ],
        "bootstrapRequired": not passkeys,
    }


def begin_reauthentication(settings: Settings, data_dir, subject: str, operation: str, target: str):
    rp_id = _rp_id(settings)
    if operation == "register_passkey" and target != "account":
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid reauthentication scope")
    if operation in {"start", "stop", "restart"} and not re.fullmatch(
        r"[0-9a-fA-F]{12,64}", target
    ):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid container reauthentication scope")
    if operation in {"dns_create", "dns_update", "dns_delete"} and not re.fullmatch(
        r"[0-9a-f]{64}", target
    ):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid DNS reauthentication scope")
    if operation not in {
        "register_passkey", "delete_passkey", "start", "stop", "restart",
        "dns_create", "dns_update", "dns_delete",
    }:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid reauthentication operation")
    credentials = list_passkeys(data_dir, subject)
    if not credentials:
        raise HTTPException(status.HTTP_409_CONFLICT, "Passkey setup required")
    if operation == "delete_passkey" and not any(
        item["credential_id"] == target for item in credentials
    ):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Passkey not found")

    challenge_id, challenge = _new_challenge(
        data_dir, subject, "reauth", operation, target
    )
    options = generate_authentication_options(
        rp_id=rp_id,
        challenge=challenge,
        timeout=_CHALLENGE_TTL * 1000,
        allow_credentials=[
            PublicKeyCredentialDescriptor(id=base64url_to_bytes(item["credential_id"]))
            for item in credentials
        ],
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    return {"challengeId": challenge_id, "options": json.loads(options_to_json(options))}


def finish_reauthentication(settings: Settings, data_dir, subject: str, challenge_id: str, credential: dict):
    challenge = consume_webauthn_challenge(
        data_dir, challenge_id, subject, "reauth", time.time()
    )
    if not challenge:
        raise _verification_failed()
    credential_id = credential.get("id")
    if not isinstance(credential_id, str) or not _PASSKEY_ID.fullmatch(credential_id):
        raise _verification_failed()
    stored = get_passkey(data_dir, subject, credential_id)
    if not stored:
        raise _verification_failed()
    try:
        verified = verify_authentication_response(
            credential=credential,
            expected_challenge=challenge["challenge"],
            expected_rp_id=_rp_id(settings),
            expected_origin=settings.web_origin,
            credential_public_key=stored["public_key"],
            credential_current_sign_count=stored["sign_count"],
            require_user_verification=True,
        )
    except Exception as error:
        raise _verification_failed() from error
    if bytes_to_base64url(verified.credential_id) != credential_id or not verified.user_verified:
        raise _verification_failed()
    if not update_passkey_sign_count(
        data_dir, subject, credential_id, verified.new_sign_count
    ):
        raise _verification_failed()

    token = secrets.token_urlsafe(32)
    store_reauth_grant(
        data_dir,
        hashlib.sha256(token.encode()).hexdigest(),
        subject,
        challenge["operation"],
        challenge["target"],
        time.time() + _GRANT_TTL,
    )
    return token


def begin_registration(
    settings: Settings,
    data_dir,
    identity: Identity,
    name: str,
    bootstrap_token: str | None,
    reauth_grant: str | None,
):
    rp_id = _rp_id(settings)
    name = name.strip()
    if not name:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Passkey name is required")
    credentials = list_passkeys(data_dir, identity.subject)
    now = time.time()
    bootstrap = not credentials
    if bootstrap:
        expected = settings.webauthn_bootstrap_token.get_secret_value()
        if not expected:
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Passkey bootstrap is not configured")
        if not bootstrap_token or not hmac.compare_digest(bootstrap_token, expected):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Valid bootstrap token required")
    else:
        if not reauth_grant or not consume_reauth_grant(
            data_dir,
            hashlib.sha256(reauth_grant.encode()).hexdigest(),
            identity.subject,
            "register_passkey",
            "account",
            now,
        ):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Fresh passkey verification required")

    challenge_id, challenge = _new_challenge(
        data_dir, identity.subject, "register", "register_passkey", name, bootstrap
    )
    options = generate_registration_options(
        rp_id=rp_id,
        rp_name="HomeServer Admin",
        user_name=(identity.email or identity.subject)[:256],
        user_display_name=(identity.email or identity.subject)[:256],
        user_id=hashlib.sha256(identity.subject.encode()).digest(),
        challenge=challenge,
        timeout=_CHALLENGE_TTL * 1000,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.REQUIRED,
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
        exclude_credentials=[
            PublicKeyCredentialDescriptor(id=base64url_to_bytes(item["credential_id"]))
            for item in credentials
        ],
    )
    return {"challengeId": challenge_id, "options": json.loads(options_to_json(options))}


def finish_registration(
    settings: Settings,
    data_dir,
    subject: str,
    actor: str,
    challenge_id: str,
    credential: dict,
):
    challenge = consume_webauthn_challenge(
        data_dir, challenge_id, subject, "register", time.time()
    )
    if not challenge:
        raise _verification_failed()
    credentials = list_passkeys(data_dir, subject)
    if (challenge["bootstrap"] and credentials) or (
        not challenge["bootstrap"] and not credentials
    ):
        raise _verification_failed()
    try:
        verified = verify_registration_response(
            credential=credential,
            expected_challenge=challenge["challenge"],
            expected_rp_id=_rp_id(settings),
            expected_origin=settings.web_origin,
            require_user_verification=True,
        )
    except Exception as error:
        raise _verification_failed() from error
    if not verified.user_verified:
        raise _verification_failed()

    credential_id = bytes_to_base64url(verified.credential_id)
    created_at = datetime.now(UTC).isoformat()
    if not add_passkey(
        data_dir,
        subject,
        credential_id,
        verified.credential_public_key,
        verified.sign_count,
        challenge["target"],
        created_at,
        actor,
        registration_challenge_id=challenge_id,
    ):
        raise _verification_failed()
    return {"id": credential_id, "name": challenge["target"], "createdAt": created_at}


def remove_passkey(
    data_dir, subject: str, actor: str, credential_id: str, grant: str
) -> None:
    credentials = list_passkeys(data_dir, subject)
    if not any(item["credential_id"] == credential_id for item in credentials):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Passkey not found")
    if len(credentials) < 2:
        raise HTTPException(status.HTTP_409_CONFLICT, "Keep at least one passkey registered")
    if not consume_reauth_grant(
        data_dir,
        hashlib.sha256(grant.encode()).hexdigest(),
        subject,
        "delete_passkey",
        credential_id,
        time.time(),
    ):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Fresh passkey verification required")
    if not delete_passkey(data_dir, subject, credential_id, actor):
        raise HTTPException(status.HTTP_409_CONFLICT, "Passkey could not be removed")


def _new_challenge(data_dir, subject, purpose, operation, target, bootstrap=False):
    challenge_id = str(uuid4())
    challenge = secrets.token_bytes(32)
    issue_webauthn_challenge(
        data_dir,
        challenge_id,
        subject,
        purpose,
        operation,
        target,
        challenge,
        bootstrap,
        time.time() + _CHALLENGE_TTL,
    )
    return challenge_id, challenge


def _rp_id(settings: Settings) -> str:
    if not settings.web_origin:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "WebAuthn origin is not configured")
    return urlsplit(settings.web_origin).hostname or ""


def _verification_failed() -> HTTPException:
    return HTTPException(status.HTTP_400_BAD_REQUEST, "WebAuthn verification failed")
