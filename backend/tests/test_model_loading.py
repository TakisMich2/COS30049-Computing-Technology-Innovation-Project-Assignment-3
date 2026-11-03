import joblib
import pytest

from app.model_service import ModelIntegrityError, load_verified_model, sha256_file
from tests.conftest import FakeModel


@pytest.fixture
def model_file(tmp_path):
    path = tmp_path / 'model.joblib'
    joblib.dump(FakeModel(), path)
    return path


def test_loads_when_hash_matches(model_file):
    model = load_verified_model(model_file, sha256_file(model_file))
    assert list(model.classes_) == [0, 1]


def test_refuses_tampered_file(model_file, monkeypatch):
    expected = sha256_file(model_file)
    model_file.write_bytes(model_file.read_bytes() + b'tampered')
    loaded = []
    monkeypatch.setattr(joblib, 'load', lambda *a, **k: loaded.append(1))
    with pytest.raises(ModelIntegrityError, match='does not match'):
        load_verified_model(model_file, expected)
    assert not loaded, 'joblib.load must never run on an unverified file'


def test_refuses_when_no_hash_configured(model_file):
    with pytest.raises(ModelIntegrityError, match='MODEL_SHA256 is not set'):
        load_verified_model(model_file, '')


def test_missing_file(tmp_path):
    with pytest.raises(ModelIntegrityError, match='No model file'):
        load_verified_model(tmp_path / 'missing.joblib', 'abc')


def test_refuses_shortened_hash(model_file):
    with pytest.raises(ModelIntegrityError, match='64-character'):
        load_verified_model(model_file, sha256_file(model_file)[:12])


def test_hash_is_case_insensitive(model_file):
    assert load_verified_model(model_file, sha256_file(model_file).upper())


def test_refuses_oversized_file(model_file, monkeypatch):
    import app.model_service as model_service

    monkeypatch.setattr(model_service, 'MAX_MODEL_BYTES', 10)
    with pytest.raises(ModelIntegrityError, match='larger than'):
        load_verified_model(model_file, sha256_file(model_file))


def test_unpickles_the_verified_bytes_not_the_file(model_file, monkeypatch):
    # If the file is swapped after the hash check, the swap must not be what gets loaded.
    expected = sha256_file(model_file)
    real_load = joblib.load

    def load_then_swap(source, *args, **kwargs):
        model_file.write_bytes(b'swapped after the check')
        assert not isinstance(source, (str, type(model_file))), 'must load from memory, not the path'
        return real_load(source, *args, **kwargs)

    monkeypatch.setattr(joblib, 'load', load_then_swap)
    assert list(load_verified_model(model_file, expected).classes_) == [0, 1]


class _HiddenCode:
    def __reduce__(self):
        return exec, ("import builtins; builtins.PHISHCHECK_PWNED = True",)


def test_hidden_code_never_runs_when_hash_differs(tmp_path, model_file):
    import builtins

    evil = tmp_path / 'evil.joblib'
    joblib.dump(_HiddenCode(), evil)
    with pytest.raises(ModelIntegrityError, match='does not match'):
        load_verified_model(evil, sha256_file(model_file))
    assert not getattr(builtins, 'PHISHCHECK_PWNED', False)


def test_hidden_code_runs_without_the_defence(tmp_path):
    import builtins

    evil = tmp_path / 'evil.joblib'
    joblib.dump(_HiddenCode(), evil)
    try:
        load_verified_model(evil, '', verify=False)
        assert builtins.PHISHCHECK_PWNED is True  # the attack the defence exists to stop
    finally:
        builtins.__dict__.pop('PHISHCHECK_PWNED', None)
