/**
 * Demo-mode stand-in for the back end (enabled with VITE_USE_MOCK=true).
 *
 * The warnings are a JavaScript port of _suspicious_components() in
 * assess_url.py, so they match the real output. The phishing probability is
 * a rough heuristic, NOT the trained model; use the real back end for results.
 *
 * Checking any address on the host "error.test" simulates a server failure,
 * so the error state can be demonstrated.
 */

import { ApiError } from './ApiError.js';

// Copied from url_indicators.py
const ABUSED_TLDS = new Set(['bond', 'buzz', 'sbs', 'cc', 'zip', 'beer']);
const SHORTENER_HOSTS = [
  'bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 't.co', 'is.gd', 'buff.ly', 'tiny.cc',
  'short.cm', 'adf.ly', 'clk.im', 'cutt.ly', 'rebrand.ly', 'b.name', 'bit.do', 'rb.gy',
];
const REDIRECT_KEYS = new Set([
  'redirect', 'next', 'url', 'target', 'return', 'returnurl', 'dest', 'destination',
  'continue', 'go', 'r', 'uri', 'redirecturl', 'redirect_uri',
]);
const SENSITIVE_WORDS = [
  'login', 'logon', 'signin', 'sign-in', 'verify', 'verification', 'secure',
  'account', 'update', 'confirm', 'password', 'banking', 'webscr',
  'suspend', 'unlock', 'wallet', 'billing', 'authenticate', 'validate',
];

const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const SENSITIVE_RE = new RegExp(
  [...SENSITIVE_WORDS].sort((a, b) => b.length - a.length).map(escapeRe).join('|'),
  'gi',
);
const ENCODED_DELIMITER_RE = /%(?:2f|40|3a|2e)/gi;
const SCHEME_RE = /^([A-Za-z][A-Za-z0-9+.-]*):\/\//;
const IPV4_RE = /^\d{1,3}(\.\d{1,3}){3}$/;

function suspiciousComponents(value) {
  const scheme = value.match(SCHEME_RE)?.[1] ?? '';
  const rest = scheme ? value.slice(scheme.length + 3) : value.replace(/^\/\//, '');
  const authority = rest.split(/[/?#]/)[0];
  const parsed = new URL(`http://${rest}`);
  const host = parsed.hostname.replace(/^\[|\]$/g, '');
  const warnings = [];
  const add = (part, text, reason) => warnings.push({ part, text, reason });

  if (!host) add('hostname', authority || value, 'The URL does not contain a recognizable hostname.');

  if (scheme && scheme.toLowerCase() !== 'https') {
    add('scheme', `${scheme}://`, 'This is not an HTTPS connection; data sent through it may not be encrypted.');
  }

  if (authority.includes('@')) {
    add(
      'userinfo',
      `${authority.slice(0, authority.lastIndexOf('@'))}@`,
      'Browsers treat text before @ as login information, not the website; it can disguise the real hostname.',
    );
  }

  if (host) {
    if (IPV4_RE.test(host) || host.includes(':')) {
      add('hostname', host, 'A raw IP address hides the recognizable domain name users normally expect.');
    }
    for (const label of host.split('.')) {
      if (label.toLowerCase().startsWith('xn--')) {
        add('hostname', label, 'This is an internationalized (punycode) domain label; similar-looking characters can imitate another site.');
      }
    }
    const suffix = host.split('.').pop();
    if (ABUSED_TLDS.has(suffix.toLowerCase())) {
      add('top-level domain', `.${suffix}`, "This top-level domain appears on the project's higher-risk TLD watchlist.");
    }
    if (SHORTENER_HOSTS.some((s) => host === s || host.endsWith(`.${s}`))) {
      add('hostname', host, 'This is a known link-shortening host, which hides the final destination.');
    }
    const labels = host.split('.');
    if (labels.length > 4) {
      add('hostname', host, `This hostname has ${labels.length} labels, which can make the actual site harder to identify.`);
    }
  }

  const port = authority.match(/:(\d+)$/)?.[1];
  if (port && !['80', '443'].includes(port)) {
    add('port', `:${port}`, 'This is a non-standard web port and is unusual for a public website.');
  }

  const query = parsed.search.replace(/^\?/, '');
  for (const [key, val] of new URLSearchParams(query)) {
    const k = key.toLowerCase();
    if (REDIRECT_KEYS.has(k) || k.includes('redirect') || k.includes('next') || k.includes('return')) {
      add('query parameter', `${key}=${val}`, 'This parameter can send users to another destination, so check where it leads before opening it.');
    }
  }

  for (const [section, text] of [['path', parsed.pathname], ['query', query]]) {
    for (const match of text.matchAll(SENSITIVE_RE)) {
      add(section, match[0], 'This word is often used in credential or account-action links; legitimate sites may use it too.');
    }
    for (const match of text.matchAll(ENCODED_DELIMITER_RE)) {
      add(section, match[0], 'This encoded URL delimiter can make the link’s structure or destination harder to inspect.');
    }
  }

  return warnings;
}

function delay(ms, signal) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(resolve, ms);
    signal?.addEventListener('abort', () => {
      clearTimeout(timer);
      reject(new DOMException('Aborted', 'AbortError'));
    });
  });
}

export async function mockAssess(url, signal) {
  await delay(500 + Math.random() * 500, signal);
  const value = url.trim();

  if (/^(https?:\/\/)?([^/?#@]*@)?error\.test\b/i.test(value)) {
    throw new ApiError('The analysis server ran into a problem. Please try again in a moment. (Simulated error)', 'server', 500);
  }

  const warnings = suspiciousComponents(value);
  const probability = Math.min(0.97, 0.06 + warnings.length * 0.17 + Math.max(0, value.length - 60) / 600);
  const trustScore = Math.round((1 - probability) * 100);

  return {
    url: value,
    analysed_url: value,
    trust_score: trustScore,
    phishing_probability: Math.round(probability * 10000) / 10000,
    prediction: trustScore < 30 ? 'phishing' : 'likely benign',
    warnings,
    note:
      'The score is a model estimate, not a guarantee. Warnings identify common URL patterns ' +
      'and do not prove a site is malicious.',
  };
}
