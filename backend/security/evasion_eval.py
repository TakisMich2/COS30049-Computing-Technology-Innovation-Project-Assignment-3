"""
Detection-evasion experiment (section 2.8): measure how often small, visually
invisible changes make a detected phishing URL pass as benign, with and without
input normalisation.

    python -m security.evasion_eval --csv path/to/CODECREATED_final_cleaned_csv_phishing.csv --sample 1000

Uses the same verified model as the server (MODEL_PATH / MODEL_SHA256 in .env)
and the same assess() function, called in-process so thousands of URLs run in
seconds. Without --csv it falls back to the small illustrative sample in
security/sample_urls.csv; use your real dataset for the numbers you report.

For each attack, evasion rate = share of phishing URLs that the model detects
unmodified but classifies as "likely benign" after the change.
"""

import argparse
import csv
import json
import random
import time
from pathlib import Path
from urllib.parse import quote

from app.assess import assess
from app.config import Settings
from app.explain import parse_url
from app.model_service import load_verified_model

RESULTS = Path(__file__).resolve().parent / 'results'
SAMPLE = Path(__file__).resolve().parent / 'sample_urls.csv'

# Latin letter -> Cyrillic look-alike (the attacker's direction).
HOMOGLYPHS = {'a': 'а', 'c': 'с', 'e': 'е', 'i': 'і', 'j': 'ј', 'o': 'о', 'p': 'р', 's': 'ѕ', 'x': 'х', 'y': 'у'}


def _host_bounds(url: str) -> tuple[int, int] | None:
    host = parse_url(url).hostname
    if not host:
        return None
    start = url.lower().find(host)
    return (start, start + len(host)) if start >= 0 else None


def _swap(text: str, limit: int | None) -> str:
    out, swapped = [], 0
    for ch in text:
        if ch.lower() in HOMOGLYPHS and (limit is None or swapped < limit):
            out.append(HOMOGLYPHS[ch.lower()])
            swapped += 1
        else:
            out.append(ch)
    return ''.join(out)


def _on_host(url: str, change) -> str | None:
    bounds = _host_bounds(url)
    if not bounds:
        return None
    start, end = bounds
    new_host = change(url[start:end])
    return None if new_host == url[start:end] else url[:start] + new_host + url[end:]


def homoglyph_host_3(url):
    """Swap up to 3 hostname letters for Cyrillic look-alikes."""
    return _on_host(url, lambda h: _swap(h, 3))


def homoglyph_everywhere(url):
    """Swap every swappable letter in the whole URL."""
    changed = _swap(url, None)
    return changed if changed != url else None


def fullwidth_host(url):
    """Write the hostname in full-width characters."""
    return _on_host(url, lambda h: ''.join(chr(ord(c) + 0xFEE0) if c.isalnum() and c.isascii() else c for c in h))


def zero_width(url):
    """Insert a zero-width space after every third character."""
    return ''.join(c + ('​' if i % 3 == 2 else '') for i, c in enumerate(url))


def punycode_homoglyph_host(url):
    """Look-alike hostname written in its punycode (xn--) form."""
    def encode(host):
        labels = []
        for label in _swap(host, 3).split('.'):
            labels.append(label if label.isascii() else 'xn--' + label.encode('punycode').decode())
        return '.'.join(labels)
    return _on_host(url, encode)


def percent_encoded_host(url):
    """Percent-encode every hostname letter."""
    return _on_host(url, lambda h: ''.join(quote(c, safe='') if not c.isalpha() else f'%{ord(c):02X}' for c in h))


ATTACKS = [homoglyph_host_3, homoglyph_everywhere, fullwidth_host, zero_width, punycode_homoglyph_host,
           percent_encoded_host]


def load_urls(path: Path, sample: int, seed: int) -> tuple[list[str], list[str]]:
    csv.field_size_limit(10_000_000)
    phishing, benign = [], []
    with path.open(newline='', encoding='utf-8') as handle:
        for row in csv.DictReader(handle):
            label = row.get('is_phishing', '').split('.')[0]
            (phishing if label == '1' else benign if label == '0' else []).append(row['url'])
    rng = random.Random(seed)
    return (rng.sample(phishing, min(sample, len(phishing))), rng.sample(benign, min(sample, len(benign))))


def is_phishing(model, url: str, normalise: bool) -> bool:
    try:
        return assess(model, url, normalise=normalise)['prediction'] == 'phishing'
    except Exception:
        return False  # an input the pipeline cannot parse is not a detection


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--csv', type=Path, default=SAMPLE)
    parser.add_argument('--sample', type=int, default=1000, help='phishing and benign URLs to sample (each)')
    parser.add_argument('--seed', type=int, default=42)
    args = parser.parse_args()

    settings = Settings()
    model = load_verified_model(settings.model_path, settings.model_sha256)
    phishing, benign = load_urls(args.csv, args.sample, args.seed)
    if args.csv == SAMPLE:
        print('NOTE: using the small illustrative sample; pass --csv with your dataset for reportable numbers.')

    started = time.perf_counter()
    detected = [u for u in phishing if is_phishing(model, u, normalise=False)]
    print(f'{len(detected)} of {len(phishing)} sampled phishing URLs are detected unmodified.\n')

    rows = []
    for attack in ATTACKS:
        attacked = [(u, a) for u in detected if (a := attack(u)) is not None]
        if not attacked:
            continue
        before = sum(not is_phishing(model, a, normalise=False) for _, a in attacked) / len(attacked)
        after = sum(not is_phishing(model, a, normalise=True) for _, a in attacked) / len(attacked)
        rows.append({'attack': attack.__name__, 'description': attack.__doc__, 'urls': len(attacked),
                     'evasion_before': round(before, 4), 'evasion_after': round(after, 4)})

    # Cost of the defence: does normalisation change verdicts on ordinary traffic?
    fp_before = sum(is_phishing(model, u, normalise=False) for u in benign) / max(len(benign), 1)
    fp_after = sum(is_phishing(model, u, normalise=True) for u in benign) / max(len(benign), 1)
    tp_before = len(detected) / max(len(phishing), 1)
    tp_after = sum(is_phishing(model, u, normalise=True) for u in phishing) / max(len(phishing), 1)

    print(f'{"Attack":28} {"URLs":>6} {"Evasion before":>15} {"Evasion after":>14}')
    for row in rows:
        print(f'{row["attack"]:28} {row["urls"]:>6} {row["evasion_before"]:>15.1%} {row["evasion_after"]:>14.1%}')
    print(f'\nUnmodified traffic: detection rate {tp_before:.1%} -> {tp_after:.1%}, '
          f'false-positive rate on {len(benign)} benign URLs {fp_before:.1%} -> {fp_after:.1%}')
    print(f'({time.perf_counter() - started:.1f} s)')

    RESULTS.mkdir(exist_ok=True)
    out = RESULTS / 'evasion.json'
    out.write_text(json.dumps({
        'dataset': str(args.csv), 'phishing_sampled': len(phishing), 'phishing_detected': len(detected),
        'benign_sampled': len(benign), 'attacks': rows,
        'unmodified': {'detection_before': tp_before, 'detection_after': tp_after,
                       'false_positive_before': fp_before, 'false_positive_after': fp_after},
    }, indent=2))
    print(f'Saved {out}')


if __name__ == '__main__':
    main()
