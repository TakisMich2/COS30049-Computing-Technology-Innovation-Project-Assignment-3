import asyncio

import httpx
from fastapi.testclient import TestClient

from app.main import create_app
from tests.conftest import BrokenModel, FakeModel, SlowModel, make_settings

ORIGIN = 'http://localhost:5173'


def assert_error_shape(response, status, code):
    assert response.status_code == status
    assert response.headers['content-type'].startswith('application/json')
    body = response.json()
    assert set(body) == {'error'}
    assert body['error']['code'] == code
    assert isinstance(body['error']['message'], str) and body['error']['message']
    return body['error']


def test_assess_returns_score_and_explanations(client):
    response = client.post('/api/assess', json={'url': 'http://secure-login.example.bond/verify'})
    assert response.status_code == 200
    body = response.json()
    assert body['prediction'] == 'phishing'
    assert body['trust_score'] == 8
    assert body['analysed_url'] == 'http://secure-login.example.bond/verify'
    assert {w['part'] for w in body['warnings']} >= {'scheme', 'top-level domain', 'path'}


def test_health(client):
    response = client.get('/api/health')
    assert response.status_code == 200
    assert response.json() == {'status': 'ok', 'model_loaded': True, 'max_url_length': 2048}


def test_empty_url_is_rejected_with_clear_message(client):
    error = assert_error_shape(client.post('/api/assess', json={'url': '   '}), 422, 'invalid_input')
    assert error['message'] == 'URL cannot be empty.'
    assert error['details'][0]['field'] == 'url'


def test_spaces_and_unknown_fields_rejected(client):
    assert_error_shape(client.post('/api/assess', json={'url': 'a b.com'}), 422, 'invalid_input')
    assert_error_shape(client.post('/api/assess', json={'url': 'a.com', 'admin': True}), 422, 'invalid_input')


def test_missing_body_and_bad_json(client):
    assert_error_shape(client.post('/api/assess'), 422, 'invalid_input')
    response = client.post('/api/assess', content=b'{not json', headers={'content-type': 'application/json'})
    error = assert_error_shape(response, 422, 'invalid_input')
    assert error['message'] == 'The request body is not valid JSON.'


def test_validation_errors_do_not_echo_input(client):
    response = client.post('/api/assess', json={'url': '<script>alert(1)</script> x'})
    assert '<script>' not in response.text


def test_url_length_limit(client):
    error = assert_error_shape(client.post('/api/assess', json={'url': 'a.com/' + 'x' * 2100}), 422, 'invalid_input')
    assert 'limit is 2,048' in error['message']


def test_body_size_limit_with_content_length(client):
    response = client.post('/api/assess', content=b'{"url": "' + b'x' * 20000 + b'"}',
                           headers={'content-type': 'application/json'})
    assert_error_shape(response, 413, 'payload_too_large')


def test_body_size_limit_without_content_length(client):
    def chunks():
        for _ in range(100):
            yield b'x' * 1000
    response = client.post('/api/assess', content=chunks(), headers={'content-type': 'application/json'})
    assert_error_shape(response, 413, 'payload_too_large')


def test_unknown_route_and_wrong_method(client):
    assert_error_shape(client.get('/api/nope'), 404, 'not_found')
    assert_error_shape(client.get('/api/assess'), 405, 'method_not_allowed')


def test_unexpected_error_hides_internal_details():
    with TestClient(create_app(make_settings(), model=BrokenModel()), raise_server_exceptions=False) as client:
        response = client.post('/api/assess', json={'url': 'example.com'})
    error = assert_error_shape(response, 500, 'internal_error')
    assert 'secret' not in response.text and 'Traceback' not in response.text
    assert error['request_id'] == response.headers['x-request-id']


def test_cors_allows_only_the_front_end(client):
    allowed = client.options('/api/assess', headers={'Origin': ORIGIN, 'Access-Control-Request-Method': 'POST'})
    assert allowed.headers.get('access-control-allow-origin') == ORIGIN
    evil = client.post('/api/assess', json={'url': 'a.com'}, headers={'Origin': 'https://evil.example'})
    assert 'access-control-allow-origin' not in evil.headers


def test_wildcard_cors_is_refused():
    import pytest
    with pytest.raises(ValueError):
        make_settings(allowed_origins=['*'])


def test_security_headers_present(client):
    response = client.get('/api/health')
    for header in ('content-security-policy', 'x-content-type-options', 'x-frame-options', 'referrer-policy'):
        assert header in response.headers
    assert response.headers['cache-control'] == 'no-store'
    assert 'server' not in response.headers


def test_excess_concurrent_requests_get_503():
    app = create_app(make_settings(inference_workers=1, max_queued_requests=1, queue_timeout_seconds=5), model=SlowModel())

    async def scenario():
        async with app.router.lifespan_context(app):
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url='http://test') as client:
                responses = await asyncio.gather(*[client.post('/api/assess', json={'url': 'a.com'}) for _ in range(6)])
                health = await client.get('/api/health')
        return responses, health

    responses, health = asyncio.run(scenario())
    codes = sorted(r.status_code for r in responses)
    assert codes.count(200) == 2 and codes.count(503) == 4
    busy = next(r for r in responses if r.status_code == 503)
    assert busy.json()['error']['code'] == 'service_busy'
    assert busy.headers['retry-after'] == '5'
    assert health.status_code == 200


def test_lookalike_hostname_is_flagged(client):
    response = client.post('/api/assess', json={'url': 'https://www.раураl.com/'})  # Cyrillic а, р, у
    body = response.json()
    assert body['analysed_url'] == 'https://www.paypal.com/'
    assert body['prediction'] == 'phishing'
    assert body['warnings'][0]['part'] == 'overall assessment'
