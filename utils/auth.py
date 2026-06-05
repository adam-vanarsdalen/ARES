"""
ARES API key authentication.

Set ARES_API_KEY in the environment (or .env).
If the variable is empty/unset the server refuses to start in production mode
(ARES_ENV != "dev").

Header: X-ARES-Key: <key>
"""

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

_SKIP_PATHS = {"/", "/ARES_dashboard.html"}


class APIKeyMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, api_key: str):
        super().__init__(app)
        self._key = api_key

    async def dispatch(self, request: Request, call_next):
        if request.url.path in _SKIP_PATHS:
            return await call_next(request)
        provided = request.headers.get("X-ARES-Key", "")
        if not provided or provided != self._key:
            return JSONResponse(
                status_code=401,
                content={
                    "error": "Unauthorized",
                    "detail": "Missing or invalid X-ARES-Key header",
                },
            )
        return await call_next(request)
