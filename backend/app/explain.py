"""
Rule-based explanations of suspicious URL parts. This is _suspicious_components()
from the Assignment 2 assess_url.py, unchanged apart from the imports.
"""

import ipaddress
import re
from urllib.parse import parse_qsl, urlsplit

from .url_indicators import ABUSED_TLDS, REDIRECT_KEYS, SENSITIVE_WORDS, SHORTENER_HOSTS

_SCHEME_RE = re.compile(r'^[A-Za-z][A-Za-z0-9+.-]*://')
_ENCODED_DELIMITER_RE = re.compile(r'%(?:2f|40|3a|2e)', re.IGNORECASE)
_SENSITIVE_WORD_RE = re.compile(
    '|'.join(re.escape(word) for word in sorted(SENSITIVE_WORDS, key=len, reverse=True)),
    re.IGNORECASE,
)


def parse_url(url: str):
    """Parse both complete and scheme-less URLs, rejecting empty or malformed input."""
    value = url.strip()
    if not value:
        raise ValueError('URL cannot be empty.')

    if value.startswith('//') or _SCHEME_RE.match(value):
        parseable = value
    else:
        parseable = '//' + value

    try:
        return urlsplit(parseable)
    except ValueError as error:
        raise ValueError(f'URL is malformed: {error}') from error


def suspicious_components(url: str) -> list[dict[str, str]]:
    """Return explainable warning signals tied to specific URL parts."""
    parts = parse_url(url)
    warnings: list[dict[str, str]] = []

    def add(part: str, text: str, reason: str) -> None:
        warnings.append({'part': part, 'text': text, 'reason': reason})

    host = parts.hostname or ''
    authority = parts.netloc
    if not host:
        add('hostname', authority or url, 'The URL does not contain a recognizable hostname.')

    if parts.scheme and parts.scheme.lower() != 'https':
        add(
            'scheme',
            f'{parts.scheme}://',
            'This is not an HTTPS connection; data sent through it may not be encrypted.',
        )

    if '@' in authority:
        userinfo = authority.rsplit('@', 1)[0] + '@'
        add(
            'userinfo',
            userinfo,
            'Browsers treat text before @ as login information, not the website; it can disguise the real hostname.',
        )

    if host:
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            add('hostname', host, 'A raw IP address hides the recognizable domain name users normally expect.')

        for label in host.split('.'):
            if label.lower().startswith('xn--'):
                add(
                    'hostname',
                    label,
                    'This is an internationalized (punycode) domain label; similar-looking characters can imitate another site.',
                )

        if host.rsplit('.', 1)[-1].lower() in ABUSED_TLDS:
            suffix = host.rsplit('.', 1)[-1]
            add('top-level domain', f'.{suffix}', "This top-level domain appears on the project's higher-risk TLD watchlist.")

        if any(host == shortener or host.endswith('.' + shortener) for shortener in SHORTENER_HOSTS):
            add('hostname', host, 'This is a known link-shortening host, which hides the final destination.')

        labels = host.split('.')
        if len(labels) > 4:
            add(
                'hostname',
                host,
                f'This hostname has {len(labels)} labels, which can make the actual site harder to identify.',
            )

    try:
        port = parts.port
    except ValueError:
        add('port', authority, 'The URL contains a malformed or out-of-range port.')
    else:
        if port is not None and port not in (80, 443):
            add('port', f':{port}', 'This is a non-standard web port and is unusual for a public website.')

    query_items = parse_qsl(parts.query, keep_blank_values=True)
    for key, value in query_items:
        normalized_key = key.lower()
        if (
            normalized_key in REDIRECT_KEYS
            or 'redirect' in normalized_key
            or 'next' in normalized_key
            or 'return' in normalized_key
        ):
            add(
                'query parameter',
                f'{key}={value}',
                'This parameter can send users to another destination, so check where it leads before opening it.',
            )

    for section_name, section in (('path', parts.path), ('query', parts.query)):
        for match in _SENSITIVE_WORD_RE.finditer(section):
            add(
                section_name,
                match.group(),
                'This word is often used in credential or account-action links; legitimate sites may use it too.',
            )
        for match in _ENCODED_DELIMITER_RE.finditer(section):
            add(
                section_name,
                match.group(),
                'This encoded URL delimiter can make the link’s structure or destination harder to inspect.',
            )

    return warnings
