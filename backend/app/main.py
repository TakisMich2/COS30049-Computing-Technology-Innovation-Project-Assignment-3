"""
FastAPI application.

    POST /api/assess   score one URL (the main feature)
    GET  /api/health   is the server up and the model loaded? (used by the front end's status check)
    GET  /*            the built React front end, when frontend/dist exists
"""

import logging
from contextlib import asynccontextmanager
from functools import partial
from pathlib import Path
from typing import Annotated, Any

from fastapi import Body, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from . import api_docs
from .assess import assess
from .config import Settings
from .errors import ApiError, register_error_handlers
from .model_service import InferenceGate, load_verified_model
from .schemas import AssessRequest, AssessResponse, ErrorResponse, HealthResponse
from .security import BodySizeLimitMiddleware, RequestContextMiddleware, SecurityHeadersMiddleware

logger = logging.getLogger('phishcheck')


def create_app(settings: Settings | None = None, model: Any = None) -> FastAPI:
    """Build the app. Tests pass a stand-in `model`; otherwise the verified model file is loaded at startup."""
    settings = settings or Settings()
    dos_defence = settings.defence_enabled('dos')
    evasion_defence = settings.defence_enabled('evasion')
    hardening = settings.defence_enabled('hardening')
    show_docs = settings.enable_docs or not hardening

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        if settings.disabled_defences:
            logger.warning('DEMO MODE: defences disabled: %s. Never run like this in normal use.',
                           ', '.join(sorted(settings.disabled_defences)))
        # Loaded once at startup, not per request. A failed integrity check stops the server here.
        app.state.model = model if model is not None else load_verified_model(
            settings.model_path, settings.model_sha256, verify=settings.defence_enabled('model')
        )
        app.state.gate = InferenceGate(
            settings.inference_workers, settings.max_queued_requests, settings.queue_timeout_seconds
        )
        yield
        app.state.gate.shutdown()

    app = FastAPI(
        title='PhishCheck API',
        version='1.0.0',
        description=api_docs.API_DESCRIPTION,
        openapi_tags=api_docs.OPENAPI_TAGS,
        lifespan=lifespan,
        docs_url='/docs' if show_docs else None,
        redoc_url=None,
        openapi_url='/openapi.json' if show_docs else None,
    )
    register_error_handlers(app)

    # Starlette runs the last-added middleware first, so this list reads inside -> outside.
    if dos_defence:
        app.add_middleware(BodySizeLimitMiddleware, max_bytes=settings.max_body_bytes)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allowed_origins,
        allow_methods=['GET', 'POST'],
        allow_headers=['Content-Type'],
        allow_credentials=False,
        max_age=600,
    )
    app.add_middleware(RequestContextMiddleware)
    if hardening:
        app.add_middleware(SecurityHeadersMiddleware)

    @app.post(
        '/api/assess',
        response_model=AssessResponse,
        tags=['assessment'],
        summary='Score a URL and explain the result',
        description=api_docs.ASSESS_DESCRIPTION,
        response_description='The trust score, prediction and explained warnings.',
        responses={
            200: {'content': {'application/json': {'examples': api_docs.ASSESS_SUCCESS_EXAMPLES}}},
            **api_docs.error_responses(ErrorResponse),
        },
    )
    async def assess_url(
        body: Annotated[AssessRequest, Body(openapi_examples=api_docs.ASSESS_REQUEST_EXAMPLES)],
        request: Request,
    ) -> dict:
        if dos_defence and len(body.url) > settings.max_url_length:
            raise ApiError(
                422, 'invalid_input',
                f'The URL is {len(body.url):,} characters long; the limit is {settings.max_url_length:,}.',
            )
        model = request.app.state.model
        if dos_defence:
            # Runs in the bounded inference pool; the event loop stays free for other requests.
            return await request.app.state.gate.run(partial(assess, model, body.url, normalise=evasion_defence))
        # Undefended (demo only): CPU-bound work directly on the event loop blocks every other request.
        return assess(model, body.url, normalise=evasion_defence)

    @app.get(
        '/api/health',
        response_model=HealthResponse,
        tags=['status'],
        summary='Check that the service is ready',
        description=api_docs.HEALTH_DESCRIPTION,
        response_description='The server is up.',
        responses={
            200: {'content': {'application/json': {'examples': api_docs.HEALTH_SUCCESS_EXAMPLES}}},
            500: {'model': ErrorResponse, 'description': 'Something unexpected failed.'},
        },
    )
    async def health(request: Request) -> HealthResponse:
        return HealthResponse(
            status='ok',
            model_loaded=getattr(request.app.state, 'model', None) is not None,
            max_url_length=settings.max_url_length,
        )

    _mount_frontend(app, settings.frontend_dist)
    return app


def _mount_frontend(app: FastAPI, dist: Path) -> None:
    """Serve the built single-page app from the same origin as the API."""
    index = dist / 'index.html'
    if not index.is_file():
        logger.info('No built front end at %s; serving the API only.', dist)
        return

    if (dist / 'assets').is_dir():
        app.mount('/assets', StaticFiles(directory=dist / 'assets'), name='assets')
    root = dist.resolve()

    @app.get('/{full_path:path}', include_in_schema=False)
    async def spa(full_path: str) -> FileResponse:
        if full_path.startswith('api/') or full_path == 'api':
            raise ApiError(404, 'not_found', 'There is no API endpoint at this address.')
        candidate = (root / full_path).resolve()
        # Only serve real files inside dist (blocks ../ traversal); everything else is a client-side route.
        if full_path and candidate.is_file() and candidate.is_relative_to(root):
            return FileResponse(candidate)
        # Revalidate the page on every visit so a rebuilt front end is picked up at once
        # (its /assets files have content-hashed names, so they can still be cached).
        return FileResponse(index, headers={'Cache-Control': 'no-cache'})
