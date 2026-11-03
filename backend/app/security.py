"""
ASGI middleware: request IDs and logging, a request body size limit enforced
before anything is parsed, and security headers on every response.

These are plain ASGI classes (not BaseHTTPMiddleware) so the body limit works
on the raw byte stream and the headers are added even to error responses.
"""

import json
import logging
import time
import uuid

logger = logging.getLogger('phishcheck')

# Content Security Policy for the front end served by this app. Scripts and
# styles only from our own origin; nothing may frame the site.
CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'self'; "
    "form-action 'self'; frame-ancestors 'none'"
)

# Looser policy for the /docs page only (off by default; ENABLE_DOCS=true). FastAPI's
# Swagger UI loads its script and styles from jsDelivr and starts with an inline script.
DOCS_CSP = (
    "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "style-src 'self' https://cdn.jsdelivr.net; img-src 'self' data: https://fastapi.tiangolo.com; "
    "connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
)

SECURITY_HEADERS = [
    (b'x-content-type-options', b'nosniff'),
    (b'x-frame-options', b'DENY'),
    (b'referrer-policy', b'no-referrer'),
    (b'permissions-policy', b'camera=(), microphone=(), geolocation=(), payment=(), usb=()'),
    (b'cross-origin-opener-policy', b'same-origin'),
    (b'cross-origin-resource-policy', b'same-origin'),
]


class RequestContextMiddleware:
    """Gives every request an ID (returned as X-Request-ID) and logs one line per request.
    Submitted URLs are never logged: only method, path, status and duration.

    It is also the last line of defence: any exception that escapes the app is
    logged here with its stack trace and turned into the standard JSON 500, so
    the client never sees a traceback or a plain-text error page."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http':
            return await self.app(scope, receive, send)

        request_id = uuid.uuid4().hex[:16]
        scope.setdefault('state', {})['request_id'] = request_id
        started = time.perf_counter()
        status = {'code': 500, 'started': False}

        async def send_with_id(message):
            if message['type'] == 'http.response.start':
                status['code'] = message['status']
                status['started'] = True
                message.setdefault('headers', []).append((b'x-request-id', request_id.encode()))
            await send(message)

        try:
            await self.app(scope, receive, send_with_id)
        except Exception:
            logger.exception('Unhandled error (request_id=%s)', request_id)
            if not status['started']:
                await _send_json_error(
                    send_with_id, 500, 'internal_error',
                    'Something went wrong on our side. Please try again; if it keeps happening, quote the request ID.',
                    request_id,
                )
        finally:
            logger.info(
                '%s %s -> %s in %.1f ms (request_id=%s)',
                scope['method'], scope['path'], status['code'], (time.perf_counter() - started) * 1000, request_id,
            )


class _BodyTooLarge(Exception):
    pass


async def _send_json_error(send, status: int, code: str, message: str, request_id: str | None = None):
    error = {'code': code, 'message': message}
    if request_id:
        error['request_id'] = request_id
    body = json.dumps({'error': error}).encode()
    await send({
        'type': 'http.response.start',
        'status': status,
        'headers': [(b'content-type', b'application/json'), (b'content-length', str(len(body)).encode())],
    })
    await send({'type': 'http.response.body', 'body': body})


class BodySizeLimitMiddleware:
    """Rejects request bodies over max_bytes with 413, whether or not the client
    sends an honest Content-Length, without ever buffering the oversized body."""

    def __init__(self, app, max_bytes: int):
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http':
            return await self.app(scope, receive, send)

        request_id = scope.get('state', {}).get('request_id')
        message = f'The request body is too large (limit {self.max_bytes:,} bytes).'
        length = dict(scope['headers']).get(b'content-length')
        if length is not None:
            if not length.isdigit():
                return await _send_json_error(send, 400, 'bad_request', 'Invalid Content-Length header.', request_id)
            if int(length) > self.max_bytes:
                return await _send_json_error(send, 413, 'payload_too_large', message, request_id)

        received = 0
        too_large = False
        response_started = False

        async def limited_receive():
            nonlocal received, too_large
            incoming = await receive()
            if incoming['type'] == 'http.request':
                received += len(incoming.get('body', b''))
                if received > self.max_bytes:
                    too_large = True
                    raise _BodyTooLarge()
            return incoming

        async def guarded_send(outgoing):
            # FastAPI turns exceptions raised while reading the body into its own 400,
            # so once the limit is hit, whatever the app sends is replaced by our 413.
            nonlocal response_started
            if too_large:
                if outgoing['type'] == 'http.response.start' and not response_started:
                    response_started = True
                    await _send_json_error(send, 413, 'payload_too_large', message, request_id)
                return
            if outgoing['type'] == 'http.response.start':
                response_started = True
            await send(outgoing)

        try:
            await self.app(scope, limited_receive, guarded_send)
        except _BodyTooLarge:
            if not response_started:
                await _send_json_error(send, 413, 'payload_too_large', message, request_id)


class SecurityHeadersMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http':
            return await self.app(scope, receive, send)
        is_api = scope['path'].startswith('/api')
        csp = DOCS_CSP if scope['path'] == '/docs' else CSP

        async def send_with_headers(message):
            if message['type'] == 'http.response.start':
                headers = message.setdefault('headers', [])
                existing = {name.lower() for name, _ in headers}
                headers.extend(h for h in [(b'content-security-policy', csp.encode()), *SECURITY_HEADERS]
                               if h[0] not in existing)
                if is_api:
                    headers.append((b'cache-control', b'no-store'))
            await send(message)

        await self.app(scope, receive, send_with_headers)
