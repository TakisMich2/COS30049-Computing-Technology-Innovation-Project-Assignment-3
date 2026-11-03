from fastapi.testclient import TestClient

from app.main import create_app

from .conftest import FakeModel, make_settings


def test_docs_hidden_by_default(client):
    assert client.get('/docs').status_code == 404
    assert client.get('/openapi.json').status_code == 404


def test_every_endpoint_documented_with_examples():
    with TestClient(create_app(make_settings(enable_docs=True), model=FakeModel())) as docs_client:
        page = docs_client.get('/docs')
        assert page.status_code == 200
        assert 'cdn.jsdelivr.net' in page.headers['content-security-policy']

        spec = docs_client.get('/openapi.json').json()
        for path, methods in spec['paths'].items():
            for method, operation in methods.items():
                assert operation.get('description'), f'{method} {path} has no description'
                assert operation['responses']['200']['content']['application/json']['examples'], \
                    f'{method} {path} has no example response'

        assess = spec['paths']['/api/assess']['post']
        assert len(assess['requestBody']['content']['application/json']['examples']) >= 2
        for status in ('413', '422', '500', '503'):
            assert assess['responses'][status]['content']['application/json']['examples']


def test_strict_csp_everywhere_except_docs(client):
    assert 'jsdelivr' not in client.get('/api/health').headers['content-security-policy']
