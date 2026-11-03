import time
from dataclasses import replace

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app

SUSPICIOUS = ('paypal', 'login', 'verify', 'secure', 'account')


class FakeModel:
    """Stand-in for the trained pipeline: flags URLs containing phishing-ish words,
    except the genuine PayPal site. Only the interface matters for these tests."""

    classes_ = [0, 1]

    def predict_proba(self, urls):
        rows = []
        for url in urls:
            lowered = url.lower()
            phishing = any(w in lowered for w in SUSPICIOUS) and not lowered.startswith('https://www.paypal.com')
            p = 0.92 if phishing else 0.08
            rows.append([1 - p, p])
        return rows


class SlowModel(FakeModel):
    def predict_proba(self, urls):
        time.sleep(0.3)
        return super().predict_proba(urls)


class BrokenModel(FakeModel):
    def predict_proba(self, urls):
        raise RuntimeError('secret internal detail: /srv/models/MODEL_FINAL.joblib')


def make_settings(**overrides) -> Settings:
    base = Settings(model_sha256='unused-in-tests', frontend_dist=Settings().model_path.parent / 'no-frontend')
    return replace(base, **overrides)


@pytest.fixture
def client():
    with TestClient(create_app(make_settings(), model=FakeModel())) as test_client:
        yield test_client
