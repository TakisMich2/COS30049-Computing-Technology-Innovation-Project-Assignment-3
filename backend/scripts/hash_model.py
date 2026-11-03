"""
Print the SHA-256 of a model file, for MODEL_SHA256 in backend/.env.

    python -m scripts.hash_model                       # uses MODEL_PATH from .env
    python -m scripts.hash_model models/MODEL_FINAL.joblib

Only run this on a model file you trained yourself or otherwise trust: the
hash is what the server uses to decide the file is safe to unpickle.
"""

import sys
from pathlib import Path

from app.config import Settings
from app.model_service import sha256_file


def main() -> None:
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else Settings().model_path
    if not path.is_file():
        sys.exit(f'No file at {path}')
    print(f'MODEL_SHA256={sha256_file(path)}')


if __name__ == '__main__':
    main()
