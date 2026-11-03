"""
Assess one URL: normalise it, score it with the model, and explain it.
Adapted from assess_url() in the Assignment 2 assess_url.py.
"""

from typing import Any

from .errors import ApiError
from .explain import parse_url, suspicious_components
from .normalise import normalise_url

PHISHING_TRUST_SCORE_THRESHOLD = 30
# A website name disguised with look-alike letters is never trusted above this.
LOOKALIKE_MAX_TRUST_SCORE = 5

NOTE = (
    'The score is a model estimate, not a guarantee. Warnings identify common URL patterns '
    'and do not prove a site is malicious.'
)


def assess(model: Any, url: str, *, normalise: bool = True) -> dict:
    """
    Return the trust score and explanations for one URL.

    With normalise=False the raw string goes straight to the model; that is the
    undefended behaviour, kept only so the evasion attack can be demonstrated.
    """
    normalised = normalise_url(url) if normalise else None
    analysed = normalised.url if normalised else url

    try:
        parse_url(analysed)
    except ValueError:
        raise ApiError(422, 'invalid_url', 'This does not look like a valid web address.') from None

    classes = list(model.classes_)
    probabilities = model.predict_proba([analysed])[0]
    phishing_probability = float(probabilities[classes.index(1)])
    trust_score = round((1 - phishing_probability) * 100)

    warnings = list(normalised.notes) if normalised else []
    warnings += suspicious_components(analysed)

    if normalised and normalised.lookalike_host and trust_score > LOOKALIKE_MAX_TRUST_SCORE:
        trust_score = LOOKALIKE_MAX_TRUST_SCORE
        phishing_probability = max(phishing_probability, 1 - trust_score / 100)
        warnings.insert(0, {
            'part': 'overall assessment',
            'text': 'The website name is disguised with look-alike letters.',
            'reason': (
                'Real websites do not mix alphabets in their name to imitate another site, so this address is '
                'treated as high risk whatever the model scored.'
            ),
        })

    if trust_score < PHISHING_TRUST_SCORE_THRESHOLD and not warnings:
        warnings.append({
            'part': 'overall model assessment',
            'text': f'The classifier estimates a {phishing_probability:.0%} chance that this URL is phishing.',
            'reason': (
                'The model learned character patterns from its training URLs and flagged this URL, '
                'even though the separate rule-based checks did not identify a specific suspicious part.'
            ),
        })

    return {
        'url': url,
        'analysed_url': analysed,
        'trust_score': trust_score,
        'phishing_probability': round(phishing_probability, 4),
        'prediction': 'phishing' if trust_score < PHISHING_TRUST_SCORE_THRESHOLD else 'likely benign',
        'warnings': warnings,
        'note': NOTE,
    }
