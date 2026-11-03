"""
Descriptions and examples for the interactive API documentation at /docs.

Kept apart from main.py so the route code stays short. The example responses
are real outputs of the explanation rules; the scores are illustrative.
"""

from .assess import NOTE

API_DESCRIPTION = """
PhishCheck scores how trustworthy a web address is (0-100) using a character
n-gram model, and explains any suspicious part of the address in plain language.

**How to try it:** open an endpoint below, choose **Try it out**, pick one of
the examples (or type your own) and choose **Execute**.

**Limits:** URLs up to 2,048 characters; request bodies up to 8 KB. When the
model is busy the API answers `503` with a `Retry-After` header.

**Errors** always use the same JSON shape, with no stack traces:
`{"error": {"code": "...", "message": "...", "details": [...], "request_id": "..."}}`.
Quote the `request_id` (also sent as the `X-Request-ID` header) when reporting a problem.
"""

OPENAPI_TAGS = [
    {'name': 'assessment', 'description': 'Score a URL and explain the result.'},
    {'name': 'status', 'description': 'Check that the service is up.'},
]

ASSESS_DESCRIPTION = """
Scores one URL and explains it.

1. The URL is **normalised** the way a browser would read it: invisible
   characters removed, full-width and look-alike letters mapped to plain
   letters, punycode (`xn--`) decoded and percent-encoded host names decoded.
   The result is returned as `analysed_url`.
2. The trained model estimates the **phishing probability**.
   `trust_score = round((1 - phishing_probability) * 100)`.
3. Rule-based checks add **warnings** naming the part of the URL that looks
   suspicious and why.

A `trust_score` below **30** gives `prediction: "phishing"`. A website name
disguised with look-alike letters is capped at a trust score of 5.

Nothing you submit is stored or logged by the server.
"""

HEALTH_DESCRIPTION = """
Reports that the server is running and the model is loaded, plus the maximum
URL length it accepts. The front end calls this when it opens so it can warn
straight away if the back end is unreachable. It is never blocked by the
inference queue, so it stays fast even when `/api/assess` is busy.
"""

ASSESS_REQUEST_EXAMPLES = {
    'suspicious': {
        'summary': 'Suspicious URL',
        'description': 'Unencrypted, with account-action words in the path and query.',
        'value': {'url': 'http://paypal.com.account-verify.xyz/login?session=update'},
    },
    'safe': {
        'summary': 'Ordinary URL',
        'value': {'url': 'https://www.abc.net.au/news'},
    },
    'lookalike': {
        'summary': 'Look-alike letters (evasion attempt)',
        'description': 'The first "a" is Cyrillic. The server normalises it and caps the trust score.',
        'value': {'url': 'https://pаypal.com/signin'},
    },
    'empty': {
        'summary': 'Invalid: empty URL (returns 422)',
        'value': {'url': ''},
    },
}

_LOGIN_WORD = 'This word is often used in credential or account-action links; legitimate sites may use it too.'

ASSESS_SUCCESS_EXAMPLES = {
    'suspicious': {
        'summary': 'Suspicious URL',
        'value': {
            'url': 'http://paypal.com.account-verify.xyz/login?session=update',
            'analysed_url': 'http://paypal.com.account-verify.xyz/login?session=update',
            'trust_score': 4,
            'phishing_probability': 0.9612,
            'prediction': 'phishing',
            'warnings': [
                {'part': 'scheme', 'text': 'http://',
                 'reason': 'This is not an HTTPS connection; data sent through it may not be encrypted.'},
                {'part': 'path', 'text': 'login', 'reason': _LOGIN_WORD},
                {'part': 'query', 'text': 'update', 'reason': _LOGIN_WORD},
            ],
            'note': NOTE,
        },
    },
    'safe': {
        'summary': 'Ordinary URL',
        'value': {
            'url': 'https://www.abc.net.au/news',
            'analysed_url': 'https://www.abc.net.au/news',
            'trust_score': 91,
            'phishing_probability': 0.0874,
            'prediction': 'likely benign',
            'warnings': [],
            'note': NOTE,
        },
    },
    'lookalike': {
        'summary': 'Look-alike letters, normalised and capped',
        'value': {
            'url': 'https://pаypal.com/signin',
            'analysed_url': 'https://paypal.com/signin',
            'trust_score': 5,
            'phishing_probability': 0.95,
            'prediction': 'phishing',
            'warnings': [
                {'part': 'overall assessment', 'text': 'The website name is disguised with look-alike letters.',
                 'reason': 'Real websites do not mix alphabets in their name to imitate another site, so this '
                           'address is treated as high risk whatever the model scored.'},
                {'part': 'hostname', 'text': 'pаypal',
                 'reason': 'This website name uses look-alike letters from another alphabet to imitate "paypal".'},
                {'part': 'path', 'text': 'signin', 'reason': _LOGIN_WORD},
            ],
            'note': NOTE,
        },
    },
}


def _error_example(code: str, message: str, details: list | None = None) -> dict:
    error = {'code': code, 'message': message}
    if details:
        error['details'] = details
    error['request_id'] = '8e0a5c0dbdc24f41'
    return {'error': error}


def _examples(**examples: tuple[str, dict]) -> dict:
    return {name: {'summary': summary, 'value': value} for name, (summary, value) in examples.items()}


def error_responses(model) -> dict:
    """The error responses /api/assess can return, each with an example body."""

    def response(description: str, examples: dict, headers: dict | None = None) -> dict:
        entry = {'model': model, 'description': description,
                 'content': {'application/json': {'examples': examples}}}
        if headers:
            entry['headers'] = headers
        return entry

    return {
        413: response('The request body is over 8 KB. Checked before the body is parsed.', _examples(
            too_large=('Body too large', _error_example(
                'payload_too_large', 'The request body is too large (limit 8,192 bytes).')),
        )),
        422: response('The input is invalid: empty, too long, contains spaces, has unknown fields, is not '
                      'valid JSON, or is not a web address.', _examples(
            empty=('Empty URL', _error_example(
                'invalid_input', 'URL cannot be empty.', [{'field': 'url', 'message': 'URL cannot be empty.'}])),
            too_long=('URL too long', _error_example(
                'invalid_input', 'The URL is 3,000 characters long; the limit is 2,048.')),
            bad_json=('Body is not JSON', _error_example('invalid_input', 'The request body is not valid JSON.')),
            not_a_url=('Not a web address', _error_example(
                'invalid_url', 'This does not look like a valid web address.')),
        )),
        500: response('Something unexpected failed. Details are logged on the server only.', _examples(
            internal=('Unexpected error', _error_example(
                'internal_error',
                'Something went wrong on our side. Please try again; if it keeps happening, quote the request ID.')),
        )),
        503: response('All inference workers and queue places are in use. Wait and retry.', _examples(
            busy=('Server busy', _error_example(
                'service_busy',
                'The server is busy checking other addresses. Please wait a few seconds and try again.')),
        ), headers={'Retry-After': {'description': 'Seconds to wait before retrying.',
                                    'schema': {'type': 'integer', 'example': 5}}}),
    }


HEALTH_SUCCESS_EXAMPLES = {
    'ok': {'summary': 'Server ready', 'value': {'status': 'ok', 'model_loaded': True, 'max_url_length': 2048}},
}
