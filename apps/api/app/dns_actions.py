import hashlib
import ipaddress
import json
import re

from fastapi import HTTPException, status

from app.schemas import DnsRecordChange, DnsRecordValue
from app.settings import Settings

_NAME_LABEL = re.compile(r"^(?:\*|[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?)$")
_HOST_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


def dns_writes_enabled(settings: Settings) -> bool:
    return (
        settings.app_env == "production"
        and settings.app_mode == "live"
        and bool(settings.cloudflare_dns_write_token.get_secret_value())
    )


def normalize_dns_record(record: DnsRecordValue, zone_name: str) -> DnsRecordValue:
    name = record.name.rstrip(".")
    zone = zone_name.strip().rstrip(".")
    labels = name.split(".")
    if (
        len(name) > 253
        or not labels
        or any(not _NAME_LABEL.fullmatch(label) for label in labels)
        or not (name.lower() == zone.lower() or name.lower().endswith(f".{zone.lower()}"))
    ):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "DNS name must be inside the configured zone")
    if any(ord(char) < 32 or ord(char) == 127 for char in record.content):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "DNS content contains control characters")
    try:
        if record.type == "A":
            content = str(ipaddress.IPv4Address(record.content))
        elif record.type == "AAAA":
            content = str(ipaddress.IPv6Address(record.content))
        elif record.type in {"CNAME", "MX"}:
            content = record.content.rstrip(".")
            if len(content) > 253 or any(
                not _HOST_LABEL.fullmatch(label) for label in content.split(".")
            ):
                raise ValueError("invalid DNS target")
        else:
            content = record.content
    except ValueError as error:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "DNS content is invalid for its record type") from error
    return record.model_copy(update={"name": name.lower(), "content": content})


def validate_dns_change(
    settings: Settings, operation: str, change: DnsRecordChange | None
) -> DnsRecordChange:
    if change is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "DNS change payload is required")
    if not dns_writes_enabled(settings):
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Cloudflare DNS writes are not configured")
    before = normalize_dns_record(change.before, settings.cloudflare_zone_name) if change.before else None
    after = normalize_dns_record(change.after, settings.cloudflare_zone_name) if change.after else None
    if operation == "dns_create" and (change.recordId or before or not after):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "DNS create requires only a new record")
    if operation == "dns_update" and (
        not change.recordId or not before or not after or before.type != after.type
    ):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "DNS update requires one existing record and its replacement")
    if operation == "dns_delete" and (not change.recordId or not before or after):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "DNS delete requires one existing record")
    if operation not in {"dns_create", "dns_update", "dns_delete"}:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid DNS operation")
    return DnsRecordChange(recordId=change.recordId, before=before, after=after)


def dns_action_scope(operation: str, change: DnsRecordChange) -> str:
    payload = json.dumps(
        {"operation": operation, "change": change.model_dump(mode="json", exclude_none=True)},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return hashlib.sha256(payload.encode()).hexdigest()


def dns_action_label(operation: str, change: DnsRecordChange) -> str:
    record = change.after or change.before
    if record is None:
        return "DNS record"
    return f"{record.type} {record.name}"
