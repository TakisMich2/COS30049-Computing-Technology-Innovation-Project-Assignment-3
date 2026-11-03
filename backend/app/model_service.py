"""
Loading the model safely, and running it without letting one caller starve the others.

Unsafe model loading: joblib/pickle files can run arbitrary code when loaded,
so the file's SHA-256 is checked against MODEL_SHA256 before joblib.load is
ever called. The server refuses to start on a mismatch. The file is read once
and the verified bytes themselves are unpickled, so it cannot be swapped
between the check and the load.

Denial of service: inference is CPU work. It runs in a small dedicated thread
pool (never on the event loop), and an admission gate caps how many requests
may run or wait at once. Excess requests get an immediate 503 instead of
piling up until the server freezes.
"""

import asyncio
import hashlib
import hmac
import io
import logging
import re
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from pathlib import Path
from typing import Any, Callable

import joblib

from .errors import ServiceBusyError

logger = logging.getLogger('phishcheck')

MAX_MODEL_BYTES = 200 * 1024 * 1024  # the real model is 0.3 MB
_SHA256_RE = re.compile(r'[0-9a-f]{64}')


class ModelIntegrityError(RuntimeError):
    pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def load_verified_model(path: Path, expected_sha256: str, *, verify: bool = True) -> Any:
    """
    Load the model only if its SHA-256 matches expected_sha256.

    verify=False is the undefended behaviour (plain joblib.load), kept only so
    the attack can be demonstrated with DISABLED_DEFENCES=model.
    """
    if not path.is_file():
        raise ModelIntegrityError(
            f'No model file at {path}. Train it with the Assignment 2 pipeline and copy MODEL_FINAL.joblib there.'
        )
    if not verify:
        logger.warning('DEMO MODE: loading %s WITHOUT checking its hash.', path.name)
        return joblib.load(path)

    expected = expected_sha256.strip().lower()
    if not expected:
        raise ModelIntegrityError(
            'MODEL_SHA256 is not set, so the model cannot be verified and will not be loaded. '
            'Run "python -m scripts.hash_model" and put the hash in backend/.env.'
        )
    if not _SHA256_RE.fullmatch(expected):
        raise ModelIntegrityError('MODEL_SHA256 must be the full 64-character hexadecimal SHA-256 of the model file.')
    if path.stat().st_size > MAX_MODEL_BYTES:
        raise ModelIntegrityError(f'The model file is larger than {MAX_MODEL_BYTES // 1024 ** 2} MB; refusing to load it.')

    # Read once and unpickle exactly the bytes that were hashed: replacing the
    # file on disk after this point cannot change what gets loaded.
    data = path.read_bytes()
    actual = hashlib.sha256(data).hexdigest()
    if not hmac.compare_digest(actual, expected):
        raise ModelIntegrityError(
            f'Model file hash does not match MODEL_SHA256 (expected {expected[:12]}..., got {actual[:12]}...). '
            'Refusing to load it: the file may have been tampered with or replaced.'
        )

    model = joblib.load(io.BytesIO(data))  # safe to unpickle only now that the hash matched
    if not hasattr(model, 'predict_proba') or 1 not in list(getattr(model, 'classes_', [])):
        raise ModelIntegrityError('The model file does not contain a classifier with phishing class label 1.')
    logger.info('Loaded model %s (sha256 %s...)', path.name, actual[:12])
    return model


class InferenceGate:
    """Bounded concurrency for model inference, with fast rejection of excess load."""

    def __init__(self, workers: int, max_queued: int, queue_timeout: float):
        self._executor = ThreadPoolExecutor(max_workers=workers, thread_name_prefix='inference')
        self._workers = asyncio.Semaphore(workers)
        self._capacity = workers + max_queued
        self._queue_timeout = queue_timeout
        self._admitted = 0

    async def run(self, func: Callable[..., Any], *args: Any) -> Any:
        if self._admitted >= self._capacity:
            raise ServiceBusyError()
        self._admitted += 1
        try:
            try:
                await asyncio.wait_for(self._workers.acquire(), timeout=self._queue_timeout)
            except TimeoutError:
                raise ServiceBusyError() from None
            try:
                loop = asyncio.get_running_loop()
                return await loop.run_in_executor(self._executor, partial(func, *args))
            finally:
                self._workers.release()
        finally:
            self._admitted -= 1

    def shutdown(self) -> None:
        self._executor.shutdown(wait=False, cancel_futures=True)
