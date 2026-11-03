"""
Build the submission ZIP:  python make_submission_zip.py

Writes PhishCheck-Group5.zip next to this folder with frontend/, backend/
(including models/MODEL_FINAL.joblib when it exists), README.md and
SECURITY.md. Leaves out everything that is installed or generated
(node_modules, .venv, dist, caches) and local secrets (.env).
"""

import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
OUTPUT = ROOT.parent / 'PhishCheck-Group5.zip'
TOP_LEVEL = ['frontend', 'backend', 'README.md', 'SECURITY.md', '.gitignore', 'make_submission_zip.py']

SKIP_DIRS = {'node_modules', '.venv', 'venv', 'dist', '__pycache__', '.pytest_cache', '.vite', '.git'}
SKIP_FILES = {'.env', '.DS_Store', 'Thumbs.db'}
SKIP_SUFFIXES = {'.pyc', '.part', '.log', '.zip'}
MODEL = ROOT / 'backend' / 'models' / 'MODEL_FINAL.joblib'


def wanted(path: Path) -> bool:
    relative = path.relative_to(ROOT)
    if any(part in SKIP_DIRS for part in relative.parts[:-1]):
        return False
    if path.name in SKIP_FILES or path.suffix in SKIP_SUFFIXES:
        return False
    # Only the final model; other .joblib files (stand-ins, experiments) stay out.
    return path.suffix != '.joblib' or path == MODEL


def main() -> None:
    files = []
    for name in TOP_LEVEL:
        target = ROOT / name
        candidates = [target] if target.is_file() else sorted(target.rglob('*'))
        files += [p for p in candidates if p.is_file() and wanted(p)]

    with zipfile.ZipFile(OUTPUT, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in files:
            archive.write(path, Path('PhishCheck') / path.relative_to(ROOT))

    size_mb = OUTPUT.stat().st_size / 1024 ** 2
    print(f'Wrote {OUTPUT} ({len(files)} files, {size_mb:.1f} MB)')
    if MODEL.is_file():
        print(f'Included the model ({MODEL.stat().st_size / 1024 ** 2:.1f} MB).')
    else:
        print('WARNING: backend/models/MODEL_FINAL.joblib not found, so the model is NOT in the ZIP.\n'
              'Train it (README step 2C) and run this again, or publish it and fill in MODEL_URL '
              'and MODEL_SHA256 in the README (step 2B).', file=sys.stderr)


if __name__ == '__main__':
    main()
