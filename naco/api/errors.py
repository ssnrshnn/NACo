"""One error shape for the whole API: {"error": {"code", "message", ...}}."""
from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

_CODES = {400: "bad_request", 401: "unauthenticated", 403: "forbidden", 404: "not_found",
          405: "method_not_allowed", 409: "conflict", 413: "too_large", 422: "validation_error",
          429: "rate_limited", 500: "internal_error", 503: "unavailable"}


class ApiError(StarletteHTTPException):
    def __init__(self, status: int, message: str, code: str | None = None,
                 headers: dict[str, str] | None = None) -> None:
        super().__init__(status_code=status, detail=message, headers=headers)
        self.code = code or _CODES.get(status, "error")


def _body(code: str, message: str, **extra: Any) -> dict[str, Any]:
    return {"error": {"code": code, "message": message, **extra}}


def install(app: FastAPI) -> None:
    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        code = getattr(exc, "code", None) or _CODES.get(exc.status_code, "error")
        return JSONResponse(_body(code, str(exc.detail)), status_code=exc.status_code, headers=exc.headers)

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
        fields = [{"loc": [str(p) for p in e["loc"]], "message": e["msg"]} for e in exc.errors()]
        message = fields[0]["message"] if fields else "invalid request"
        return JSONResponse(_body("validation_error", message, fields=fields), status_code=422)
