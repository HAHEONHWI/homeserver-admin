from starlette.responses import JSONResponse


class _RequestBodyTooLarge(Exception):
    pass


class RequestBodyLimitMiddleware:
    def __init__(self, app, max_bytes: int = 65_536):
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send):
        if (
            scope["type"] != "http"
            or scope["method"] not in {"POST", "PUT", "PATCH", "DELETE"}
            or not scope["path"].startswith("/api/v1/")
        ):
            await self.app(scope, receive, send)
            return

        lengths = [value for name, value in scope["headers"] if name == b"content-length"]
        if len(lengths) == 1:
            try:
                if int(lengths[0]) > self.max_bytes:
                    await self._reject(scope, receive, send)
                    return
            except ValueError:
                pass

        received = 0

        async def limited_receive():
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    raise _RequestBodyTooLarge
            return message

        try:
            await self.app(scope, limited_receive, send)
        except _RequestBodyTooLarge:
            await self._reject(scope, receive, send)

    async def _reject(self, scope, receive, send):
        response = JSONResponse(
            {"detail": "Request too large"},
            status_code=413,
            headers={"Cache-Control": "no-store"},
        )
        await response(scope, receive, send)
