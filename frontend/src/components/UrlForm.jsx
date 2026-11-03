import { useRef, useState } from 'react';
import { MAX_URL_LENGTH, validateUrl } from '../utils/validateUrl.js';

const EXAMPLES = [
  { label: 'A well-known site', url: 'https://www.google.com' },
  { label: 'A suspicious link', url: 'http://secure-login.account-verify.paypal.com.example.bond/signin?redirect=%2Fwallet' },
  { label: 'A shortened link', url: 'https://bit.ly/3xYz12' },
];

/**
 * URL input with validation. Nothing reaches onSubmit until validateUrl passes.
 */
export default function UrlForm({ onSubmit, isLoading }) {
  const [value, setValue] = useState('');
  const [error, setError] = useState('');
  const [submitted, setSubmitted] = useState(false);
  const inputRef = useRef(null);

  function submit(url) {
    setSubmitted(true);
    const check = validateUrl(url);
    if (!check.valid) {
      setError(check.error);
      inputRef.current?.focus();
      return;
    }
    setError('');
    onSubmit(check.value);
  }

  function handleChange(event) {
    const next = event.target.value;
    setValue(next);
    // Once the user has tried to submit, re-check as they type so the message clears when fixed.
    if (submitted) {
      const check = validateUrl(next);
      setError(check.valid ? '' : check.error);
    }
  }

  function tryExample(url) {
    setValue(url);
    submit(url);
  }

  return (
    <form
      className="url-form card"
      noValidate
      onSubmit={(event) => {
        event.preventDefault();
        submit(value);
      }}
      aria-busy={isLoading}
    >
      <label htmlFor="url-input" className="field-label">
        Website address (URL)
      </label>
      <p id="url-hint" className="field-hint">
        Paste the full link from an email, text message or website, e.g. <span className="mono">example.com/login</span>
      </p>
      <div className="url-form__row">
        <input
          ref={inputRef}
          id="url-input"
          name="url"
          type="text"
          inputMode="url"
          autoComplete="off"
          autoCapitalize="off"
          spellCheck={false}
          maxLength={MAX_URL_LENGTH + 500}
          className={`text-input${error ? ' text-input--invalid' : ''}`}
          placeholder="https://"
          value={value}
          onChange={handleChange}
          aria-invalid={Boolean(error)}
          aria-describedby={error ? 'url-hint url-error' : 'url-hint'}
          disabled={isLoading}
        />
        <button type="submit" className="button button--primary button--large" disabled={isLoading}>
          {isLoading ? (
            <>
              <span className="spinner spinner--small" aria-hidden="true" />
              Checking…
            </>
          ) : (
            'Check URL'
          )}
        </button>
      </div>
      {error && (
        <p id="url-error" className="field-error" role="alert">
          {error}
        </p>
      )}

      <div className="examples">
        <span className="examples__label" id="examples-label">
          Or try an example:
        </span>
        <ul className="examples__list" aria-labelledby="examples-label">
          {EXAMPLES.map((example) => (
            <li key={example.url}>
              <button
                type="button"
                className="chip"
                onClick={() => tryExample(example.url)}
                disabled={isLoading}
              >
                {example.label}
              </button>
            </li>
          ))}
        </ul>
      </div>
    </form>
  );
}
