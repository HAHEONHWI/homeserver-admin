import asyncio
import logging
from http.client import HTTPException
from pathlib import Path
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from app.providers import resource
from app.settings import Settings
from app.store import list_notification_alerts, replace_notification_alerts


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_NTFY_OPENER = build_opener(ProxyHandler({}), _NoRedirect())


def _publish(settings: Settings, message: str) -> bool:
    body = message.encode("utf-8")
    if len(body) > 2_000:
        return False
    headers = {"Title": "HomeServer Admin", "Content-Type": "text/plain; charset=utf-8"}
    token = settings.ntfy_token.get_secret_value()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = Request(
        f"{settings.ntfy_url.rstrip('/')}/{settings.ntfy_topic}",
        data=body,
        headers=headers,
        method="POST",
    )
    try:
        with _NTFY_OPENER.open(request, timeout=3) as response:
            return 200 <= response.status < 300
    except (HTTPException, OSError, TimeoutError, ValueError):
        return False


def send_notification_changes(settings: Settings, data_dir: Path) -> bool:
    if not settings.ntfy_url:
        return False
    current_resource = resource("notifications", settings)
    if current_resource is None or current_resource["status"] == "not_configured":
        return False
    current = {
        row["id"]: (row["name"][:128], " ".join(row["detail"].split())[:200])
        for row in current_resource["rows"]
        if row["status"] in {"warning", "failed", "stopped"}
    }
    previous = list_notification_alerts(data_dir)
    if "host-agent" in current:
        for alert_id, name in previous.items():
            if (alert_id.startswith("host-") or alert_id.startswith("storage:")) and alert_id not in current:
                current[alert_id] = (name[:128], "연결 복구 대기")
    if "portainer" in current:
        for alert_id, name in previous.items():
            if alert_id.startswith("container:") and alert_id not in current:
                current[alert_id] = (name[:128], "연결 복구 대기")
    added = current.keys() - previous.keys()
    resolved = previous.keys() - current.keys()
    if not added and not resolved:
        return False
    changes = [
        (item, current[item][0], f"경고: {current[item][0]} · {current[item][1]}")
        for item in sorted(added)
    ]
    changes.extend((item, None, f"정상화: {previous[item][:128]}") for item in sorted(resolved))
    delivered = previous.copy()
    batch: list[tuple[str, str | None, str]] = []
    batch_bytes = 0
    for change in changes:
        item, _, line = change
        line_bytes = len(line.encode("utf-8"))
        if line_bytes > 2_000:
            return False
        if batch and batch_bytes + line_bytes + 1 > 2_000:
            if not _publish(settings, "\n".join(entry[2] for entry in batch)):
                return False
            for alert_id, name, _ in batch:
                if name is None:
                    delivered.pop(alert_id, None)
                else:
                    delivered[alert_id] = name
            replace_notification_alerts(data_dir, delivered)
            batch, batch_bytes = [], 0
        batch.append(change)
        batch_bytes += line_bytes + (1 if len(batch) > 1 else 0)
    if batch:
        if not _publish(settings, "\n".join(entry[2] for entry in batch)):
            return False
        for alert_id, name, _ in batch:
            if name is None:
                delivered.pop(alert_id, None)
            else:
                delivered[alert_id] = name
        replace_notification_alerts(data_dir, delivered)
    return True


async def run_notification_loop(settings: Settings, data_dir: Path) -> None:
    while True:
        try:
            await asyncio.to_thread(send_notification_changes, settings, data_dir)
        except Exception:
            logging.getLogger(__name__).warning("ntfy alert polling failed")
        await asyncio.sleep(60)
