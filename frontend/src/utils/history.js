/**
 * Analysis history (FR8), kept in this browser only. Storage can be unavailable
 * (private browsing, blocked site data), so every access is wrapped.
 */

const STORAGE_KEY = 'phishcheck.history.v1';
const MAX_ENTRIES = 50;

export function loadHistory() {
  try {
    const stored = JSON.parse(localStorage.getItem(STORAGE_KEY) ?? '[]');
    return Array.isArray(stored) ? stored : [];
  } catch {
    return [];
  }
}

function saveHistory(entries) {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(entries));
  } catch {
    // History is a convenience; the check itself still succeeded.
  }
}

export function addToHistory(result) {
  const entry = {
    id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    url: result.url,
    trust_score: result.trust_score,
    phishing_probability: result.phishing_probability,
    prediction: result.prediction,
    warning_count: result.warnings.length,
    checked_at: new Date().toISOString(),
  };
  const entries = [entry, ...loadHistory()].slice(0, MAX_ENTRIES);
  saveHistory(entries);
  return entries;
}

export function clearHistory() {
  saveHistory([]);
}

// Stops a spreadsheet from treating a URL that starts with = + - @ as a formula.
function csvCell(value) {
  let text = String(value ?? '');
  if (/^[=+\-@\t\r]/.test(text)) text = `'${text}`;
  return `"${text.replace(/"/g, '""')}"`;
}

export function exportHistoryCsv(entries) {
  const header = ['Checked at', 'URL', 'Trust score', 'Phishing probability', 'Prediction', 'Warnings'];
  const rows = entries.map((e) => [
    e.checked_at,
    e.url,
    e.trust_score,
    e.phishing_probability,
    e.prediction,
    e.warning_count,
  ]);
  const csv = [header, ...rows].map((row) => row.map(csvCell).join(',')).join('\r\n');

  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' });
  const link = document.createElement('a');
  link.href = URL.createObjectURL(blob);
  link.download = `phishcheck-history-${new Date().toISOString().slice(0, 10)}.csv`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(link.href);
}
