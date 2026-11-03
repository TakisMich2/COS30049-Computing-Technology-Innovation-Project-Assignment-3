"""
Every error leaves the API in one JSON shape (schemas.ErrorResponse):

    {"error": {"code": "...", "message": "...", "details": [...], "request_id": "..."}}

Unexpected exceptions are logged server-side with their stack trace, but the
client only ever sees a generic message and a request ID to quote.
"""

import logging

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from .schemas import ErrorBody, ErrorDetail, ErrorResponse

logger = logging.getLogger('phishcheck')


class ApiError(Exception):
    """An expected error with a status code and a user-safe message."""

    def __init__(self, status_code: int, code: str, message: str, headers: dict[str, str] | None = None):
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message
        self.headers = headers


class ServiceBusyError(ApiError):
    def __init__(self) -> None:
        super().__init__(
            503,
            'service_busy',
            'The server is busy checking other addresses. Please wait a few seconds and try again.',
            headers={'Retry-After': '5'},
        )


_STATUS_CODES = {
    400: ('bad_request', 'The request could not be understood.'),
    404: ('not_found', 'There is no API endpoint at this address.'),
    405: ('method_not_allowed', 'This endpoint does not support that HTTP method.'),
    413: ('payload_too_large', 'The request body is too large.'),
    415: ('unsupported_media_type', 'Send the request body as JSON.'),
}


def _request_id(request: Request) -> str | None:
    return getattr(request.state, 'request_id', None)


def error_response(
    status_code: int,
    code: str,
    message: str,
    *,
    details: list[ErrorDetail] | None = None,
    request_id: str | None = None,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    body = ErrorResponse(error=ErrorBody(code=code, message=message, details=details, request_id=request_id))
    return JSONResponse(body.model_dump(exclude_none=True), status_code=status_code, headers=headers)


def _field_name(loc: tuple) -> str:
    # ('body', 'url') -> 'url'; a missing or non-object body -> 'body'
    parts = [str(p) for p in loc if p != 'body']
    return '.'.join(parts) or 'body'


def _clean_message(message: str) -> str:
    # Pydantic prefixes custom validator messages with "Value error, ".
    return message.removeprefix('Value error, ')


def register_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(ApiError)
    async def handle_api_error(request: Request, exc: ApiError) -> JSONResponse:
        return error_response(exc.status_code, exc.code, exc.message, request_id=_request_id(request), headers=exc.headers)

    @app.exception_handler(RequestValidationError)
    async def handle_validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
        # Only the field and message are returned: never the submitted input or internal types.
        errors = exc.errors()
        if any(err.get('type') == 'json_invalid' for err in errors):
            return error_response(422, 'invalid_input', 'The request body is not valid JSON.',
                                  request_id=_request_id(request))
        details = [ErrorDetail(field=_field_name(err.get('loc', ())), message=_clean_message(err.get('msg', 'Invalid value.')))
                   for err in errors]
        message = details[0].message if len(details) == 1 else 'Some of the submitted fields are invalid.'
        return error_response(422, 'invalid_input', message, details=details, request_id=_request_id(request))

    @app.exception_handler(StarletteHTTPException)
    async def handle_http_error(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        code, message = _STATUS_CODES.get(exc.status_code, ('http_error', 'The request could not be completed.'))
        return error_response(exc.status_code, code, message, request_id=_request_id(request), headers=exc.headers)

    @app.exception_handler(Exception)
    async def handle_unexpected_error(request: Request, exc: Exception) -> JSONResponse:
        logger.exception('Unhandled error (request_id=%s)', _request_id(request))
        return error_response(
            500,
            'internal_error',
            'Something went wrong on our side. Please try again; if it keeps happening, quote the request ID.',
            request_id=_request_id(request),
        )
