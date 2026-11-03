"""
Download the trained model and check it before it is ever loaded.

    python -m scripts.download_model                 # uses MODEL_URL from .env
    python -m scripts.download_model https://.../MODEL_FINAL.joblib

The file is saved to MODEL_PATH only if its SHA-256 matches MODEL_SHA256 in
backend/.env; otherwise it is deleted. A pickled model can run code when it is
loaded, so a file that fails the check must never be used.
"""

import hashlib
import hmac
import os
import sys
import tempfile
import urllib.request
from pathlib import Path

from app.config import Settings

CHUNK = 1024 * 1024
MAX_BYTES = 2 * 1024 ** 3  # refuse anything over 2 GB


def download(url: str, destination: Path, expected_sha256: str) -> None:
    if not url.startswith('https://'):
        sys.exit('Refusing to download the model over an unencrypted connection; use an https:// link.')
    if not expected_sha256:
        sys.exit('Set MODEL_SHA256 in backend/.env first (the README gives the published value).')

    destination.parent.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256()
    received = 0
    handle, temp_name = tempfile.mkstemp(dir=destination.parent, suffix='.part')
    temp_path = Path(temp_name)
    try:
        request = urllib.request.Request(url, headers={'User-Agent': 'phishcheck-model-download'})
        with os.fdopen(handle, 'wb') as out, urllib.request.urlopen(request, timeout=60) as response:
            while chunk := response.read(CHUNK):
                received += len(chunk)
                if received > MAX_BYTES:
                    sys.exit('Download is larger than 2 GB; stopping.')
                digest.update(chunk)
                out.write(chunk)
                print(f'\r{received / 1024 ** 2:,.1f} MB', end='', flush=True)
        print()

        actual = digest.hexdigest()
        if not hmac.compare_digest(actual, expected_sha256.lower()):
            sys.exit(f'Hash mismatch: expected {expected_sha256}, got {actual}. The file was deleted.')
        temp_path.replace(destination)
        print(f'Saved {destination} ({received / 1024 ** 2:,.1f} MB); hash verified.')
    finally:
        temp_path.unlink(missing_ok=True)


def main() -> None:
    settings = Settings()
    url = sys.argv[1] if len(sys.argv) > 1 else os.getenv('MODEL_URL', '')
    if not url:
        sys.exit('Give the download link as an argument or set MODEL_URL in backend/.env.')
    download(url, settings.model_path, settings.model_sha256)


if __name__ == '__main__':
    main()
