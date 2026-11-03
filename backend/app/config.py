"""
Settings, read from environment variables (and an optional backend/.env file)
so that nothing deployment-specific or secret lives in the source code.
"""

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

BACKEND_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BACKEND_DIR / '.env')

KNOWN_DEFENCES = {'dos', 'evasion', 'hardening', 'model'}


def _path(name: str, default: str) -> Path:
    path = Path(os.getenv(name) or default)
    return path if path.is_absolute() else (BACKEND_DIR / path).resolve()


def _int(name: str, default: int) -> int:
    return int(os.getenv(name) or default)


def _list(name: str, default: str) -> list[str]:
    return [item.strip() for item in (os.getenv(name) or default).split(',') if item.strip()]


@dataclass(frozen=True)
class Settings:
    model_path: Path = field(default_factory=lambda: _path('MODEL_PATH', 'models/MODEL_FINAL.joblib'))
    model_sha256: str = field(default_factory=lambda: (os.getenv('MODEL_SHA256') or '').strip().lower())
    allowed_origins: list[str] = field(
        default_factory=lambda: _list('ALLOWED_ORIGINS', 'http://localhost:5173,http://127.0.0.1:5173')
    )
    frontend_dist: Path = field(default_factory=lambda: _path('FRONTEND_DIST', '../frontend/dist'))
    max_url_length: int = field(default_factory=lambda: _int('MAX_URL_LENGTH', 2048))
    max_body_bytes: int = field(default_factory=lambda: _int('MAX_BODY_BYTES', 8192))
    inference_workers: int = field(default_factory=lambda: _int('INFERENCE_WORKERS', 2))
    max_queued_requests: int = field(default_factory=lambda: _int('MAX_QUEUED_REQUESTS', 8))
    queue_timeout_seconds: float = field(default_factory=lambda: float(os.getenv('QUEUE_TIMEOUT_SECONDS') or 2))
    enable_docs: bool = field(default_factory=lambda: os.getenv('ENABLE_DOCS', 'false').lower() == 'true')
    disabled_defences: frozenset[str] = field(
        default_factory=lambda: frozenset(d.lower() for d in _list('DISABLED_DEFENCES', ''))
    )

    def __post_init__(self) -> None:
        if '*' in self.allowed_origins:
            raise ValueError('ALLOWED_ORIGINS must list the front end explicitly; "*" is not allowed.')
        unknown = self.disabled_defences - KNOWN_DEFENCES
        if unknown:
            raise ValueError(f'Unknown DISABLED_DEFENCES: {", ".join(sorted(unknown))}')

    def defence_enabled(self, name: str) -> bool:
        return name not in self.disabled_defences
