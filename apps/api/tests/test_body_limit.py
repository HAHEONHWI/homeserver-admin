import asyncio

from app.body_limit import RequestBodyLimitMiddleware


def test_request_body_limit_rejects_chunked_bodies_before_route_accepts_them():
    async def endpoint(scope, receive, send):
        while (message := await receive())["type"] == "http.request":
            if not message.get("more_body", False):
                break
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    messages = iter(
        [
            {"type": "http.request", "body": b"123", "more_body": True},
            {"type": "http.request", "body": b"45", "more_body": False},
        ]
    )
    sent = []
    scope = {"type": "http", "method": "POST", "path": "/api/v1/jobs", "headers": []}

    async def receive():
        return next(messages)

    async def send(message):
        sent.append(message)

    asyncio.run(RequestBodyLimitMiddleware(endpoint, max_bytes=4)(scope, receive, send))

    assert sent[0]["status"] == 413
    assert sent[1]["body"] == b'{"detail":"Request too large"}'


def test_request_body_limit_rejects_large_content_length_without_reading_body():
    async def endpoint(*_):
        raise AssertionError("oversized request reached the application")

    sent = []
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/api/v1/jobs",
        "headers": [(b"content-length", b"5")],
    }

    async def receive():
        raise AssertionError("oversized body should not be read")

    async def send(message):
        sent.append(message)

    asyncio.run(RequestBodyLimitMiddleware(endpoint, max_bytes=4)(scope, receive, send))

    assert sent[0]["status"] == 413
