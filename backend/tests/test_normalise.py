import pytest

from app.normalise import normalise_url


@pytest.mark.parametrize('raw, expected', [
    ('https://www.pаypal.com/login', 'https://www.paypal.com/login'),                # Cyrillic а
    ('https://ｐａｙｐａｌ.com/ｌｏｇｉｎ', 'https://paypal.com/login'),               # full-width
    ('https://pay​pal.com/log​in', 'https://paypal.com/login'),           # zero-width space
    ('https://xn--pypal-4ve.com/', 'https://paypal.com/'),                          # punycode of pаypal
    ('https://%70aypal.com/', 'https://paypal.com/'),                               # percent-encoded host
    ('https://secure.example.com/lоgin', 'https://secure.example.com/login'),       # Cyrillic о in path
    ('HTTPS://WWW.Example.COM/Path', 'HTTPS://www.example.com/Path'),               # host lower-cased only
])
def test_disguises_are_removed(raw, expected):
    assert normalise_url(raw).url == expected


@pytest.mark.parametrize('raw', [
    'https://www.google.com/search?q=test',
    'http://192.168.0.1:8080/admin',
    'https://user@example.com/',
    'example.com',
])
def test_ordinary_urls_are_unchanged(raw):
    result = normalise_url(raw)
    assert result.url == raw
    assert not result.notes and not result.lookalike_host


def test_lookalike_host_is_marked():
    assert normalise_url('https://www.pаypal.com/').lookalike_host
    assert normalise_url('https://xn--pypal-4ve.com/').lookalike_host
    assert not normalise_url('https://paypal.com/lоgin').lookalike_host  # path only


def test_genuine_international_domain_is_kept():
    # A real Russian name is not a disguise: it stays, in the punycode form browsers use.
    result = normalise_url('https://пример.рф/')
    assert result.url == 'https://xn--e1afmkfd.xn--p1ai/'
    assert not result.lookalike_host


def test_output_is_ascii():
    assert normalise_url('https://例え.jp/パス').url.isascii()
