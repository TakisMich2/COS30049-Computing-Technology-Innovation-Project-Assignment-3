/**
 * Interpretation of the back end's result. The thresholds match assess_url.py:
 * a trust score below 30 (phishing probability above 70%) is predicted phishing.
 */

export const PHISHING_TRUST_THRESHOLD = 30;
export const PHISHING_PROBABILITY_THRESHOLD = 100 - PHISHING_TRUST_THRESHOLD;
export const SAFE_TRUST_THRESHOLD = 70;

const BANDS = {
  danger: {
    key: 'danger',
    label: 'Likely phishing',
    advice: 'Do not enter passwords, card numbers or personal details on this site. If the link came in an email or text, delete it.',
  },
  caution: {
    key: 'caution',
    label: 'Probably safe, but be careful',
    advice: 'The model did not flag this as phishing, but it is not confident. Check the warnings below before you sign in or pay.',
  },
  safe: {
    key: 'safe',
    label: 'Likely safe',
    advice: 'Nothing in this address looks unusual to the model. Still only enter details on sites you opened yourself.',
  },
};

export function getBand(trustScore) {
  if (trustScore < PHISHING_TRUST_THRESHOLD) return BANDS.danger;
  if (trustScore < SAFE_TRUST_THRESHOLD) return BANDS.caution;
  return BANDS.safe;
}

/** The model's probability for the outcome it predicted, as a 0-100 percentage. */
export function getConfidence({ trust_score: trustScore, phishing_probability: probability }) {
  const isPhishing = trustScore < PHISHING_TRUST_THRESHOLD;
  return Math.round((isPhishing ? probability : 1 - probability) * 100);
}

export function isPhishing(result) {
  return result.trust_score < PHISHING_TRUST_THRESHOLD;
}
