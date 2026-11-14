from dataclasses import dataclass
from functools import lru_cache

import jwt
from fastapi import HTTPException, Request, status
from jwt import PyJWKClient
from jwt.exceptions import PyJWKClientConnectionError

from app.settings import Settings


@dataclass(frozen=True)
class Identity:
    subject: str
    email: str
    role: str


def resolve_role(email: str, settings: Settings) -> str:
    normalized = email.strip().lower()
    if normalized in settings.emails("owner_emails"):
        return "owner"
    if normalized in settings.emails("operator_emails"):
        return "operator"
    return "viewer"


@lru_cache(maxsize=8)
def jwks_client(url: str) -> PyJWKClient:
    return PyJWKClient(url, cache_jwk_set=True, lifespan=3600, timeout=3)


def current_identity(request: Request) -> Identity:
    settings: Settings = request.app.state.settings
    token = request.headers.get("cf-access-jwt-assertion")
    if not token and settings.app_env == "development" and settings.app_mode == "mock":
        return Identity("local-development", "local@development.invalid", "owner")
    if not token:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Access assertion required")
    try:
        key = jwks_client(settings.jwks_url).get_signing_key_from_jwt(token).key
        claims = jwt.decode(
            token,
            key,
            algorithms=["RS256"],
            issuer=settings.cf_access_issuer,
            audience=settings.cf_access_aud,
            options={"require": ["exp", "iss", "aud", "sub"]},
            leeway=30,
        )
        subject = claims.get("sub")
        email = claims.get("email", "")
        if not isinstance(subject, str) or not subject or not isinstance(email, str):
            raise ValueError("invalid identity claims")
    except PyJWKClientConnectionError as error:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE, "Access signing keys unavailable"
        ) from error
    except Exception as error:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid Access assertion") from error
    return Identity(subject, email, resolve_role(email, settings))


def require_role(identity: Identity, *roles: str) -> Identity:
    if identity.role not in roles:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Insufficient role")
    return identity
