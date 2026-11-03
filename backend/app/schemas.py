"""Pydantic request and response models for every endpoint."""

import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

_CONTROL_OR_SPACE_RE = re.compile(r'[\x00-\x20\x7F]')


class AssessRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')

    # The length limit is enforced in main.py from settings (MAX_URL_LENGTH), so
    # it can be configured; the body-size middleware caps raw bytes before this.
    url: str = Field(description='The web address to assess.', examples=['https://example.com/login'])

    @field_validator('url')
    @classmethod
    def no_spaces_or_control_characters(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError('URL cannot be empty.')
        if _CONTROL_OR_SPACE_RE.search(value):
            raise ValueError('URL cannot contain spaces, line breaks or control characters.')
        return value


class UrlWarning(BaseModel):
    part: str = Field(description='Which part of the URL the warning is about, e.g. "hostname".')
    text: str = Field(description='The exact text that triggered the warning.')
    reason: str = Field(description='Plain-language explanation for the user.')


class AssessResponse(BaseModel):
    url: str = Field(description='The URL as submitted.')
    analysed_url: str = Field(description='The URL after normalisation; this is what the model scored.')
    trust_score: int = Field(ge=0, le=100, description='100 minus the phishing probability, as a percentage.')
    phishing_probability: float = Field(ge=0, le=1, description="The model's estimated probability (0-1) that the URL is phishing.")
    prediction: Literal['phishing', 'likely benign'] = Field(
        description='"phishing" when the trust score is below 30, otherwise "likely benign".')
    warnings: list[UrlWarning] = Field(description='Suspicious parts of the URL, most important first. May be empty.')
    note: str = Field(description='A reminder that the score is an estimate, not a guarantee.')


class HealthResponse(BaseModel):
    status: Literal['ok'] = Field(description='Always "ok" when the server can answer.')
    model_loaded: bool = Field(description='Whether the trained model is loaded and ready.')
    max_url_length: int = Field(description='The longest URL, in characters, that /api/assess accepts.')


class ErrorDetail(BaseModel):
    field: str = Field(description='The request field the problem is in, e.g. "url".')
    message: str = Field(description='What is wrong with that field.')


class ErrorBody(BaseModel):
    code: str = Field(description='Stable machine-readable error code, e.g. "invalid_input".')
    message: str = Field(description='Human-readable explanation, safe to show to the user.')
    details: list[ErrorDetail] | None = Field(default=None, description='Per-field problems, for invalid input.')
    request_id: str | None = Field(default=None, description='Quote this when reporting a problem.')


class ErrorResponse(BaseModel):
    """The single JSON shape used for every error the API returns."""

    error: ErrorBody
