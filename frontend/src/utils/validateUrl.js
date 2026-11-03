/**
 * Client-side URL validation, run before anything is sent to the back end.
 * This is for usability only: the back end repeats every check (schemas.py,
 * main.py), because an attacker can skip this page and call the API directly.
 *
 * Non-ASCII characters are allowed on purpose. Look-alike letters are a common
 * phishing disguise, so the back end normalises them and warns the user rather
 * than the front end refusing the link.
 */

export const MAX_URL_LENGTH = 2048;

const SCHEME_RE = /^([A-Za-z][A-Za-z0-9+.-]*):\/\//;
const ALLOWED_SCHEMES = ['http', 'https'];
const INVISIBLE_RE = /[­᠎​-‏‪-‮⁠-⁤⁦-⁩﻿]/g;

/**
 * @param {string} raw - what the user typed
 * @returns {{ valid: true, value: string } | { valid: false, error: string }}
 */
export function validateUrl(raw) {
  const value = (raw ?? '').trim();

  if (!value) {
    return { valid: false, error: 'Enter a web address to check, for example example.com/login.' };
  }
  if (value.length > MAX_URL_LENGTH) {
    return {
      valid: false,
      error: `This address is ${value.length.toLocaleString()} characters long. The limit is ${MAX_URL_LENGTH.toLocaleString()}.`,
    };
  }
  if (/[\x00-\x1F\x7F]/.test(value) || /\s/.test(value)) {
    return { valid: false, error: 'Web addresses cannot contain spaces or line breaks. Remove them and try again.' };
  }

  const scheme = value.match(SCHEME_RE);
  if (scheme && !ALLOWED_SCHEMES.includes(scheme[1].toLowerCase())) {
    return { valid: false, error: 'Only web addresses that start with http:// or https:// can be checked.' };
  }

  // Invisible characters are removed only for this structural check; the
  // original text is what gets sent, so the back end can warn about them.
  const visible = value.replace(INVISIBLE_RE, '');
  let parsed;
  try {
    parsed = new URL(scheme ? visible : `http://${visible.replace(/^\/\//, '')}`);
  } catch {
    return { valid: false, error: 'This does not look like a valid web address. Check it for typos, e.g. example.com/login.' };
  }

  const host = parsed.hostname;
  const looksLikeHost = host.includes('.') || host === 'localhost' || host.startsWith('[');
  if (!host || !looksLikeHost) {
    return { valid: false, error: 'The address needs a website name, such as example.com.' };
  }

  return { valid: true, value };
}
