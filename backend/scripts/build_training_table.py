"""
Build the model's training table with Assignment 2's own cleaning code, without
computing the 50 engineered features (the character n-gram model only reads
the URL and its label).

    python scripts/build_training_table.py path/to/assignment2-folder output.csv

Runs Assignment 2's unify_labels, clean_combined and apply_label_fixes on the
raw files in <assignment2-folder>/data/original_data. The Kaggle file
(malicious_phish.csv) needs a Kaggle sign-in to download, so it is optional:
without it the table is built from the Mendeley and PhiUSIIL datasets only.

Run it with an interpreter that has pandas and tldextract installed (the
Assignment 2 environment), not the back end's.
"""

import sys
from pathlib import Path


def main() -> None:
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    pipeline, output = Path(sys.argv[1]).resolve(), Path(sys.argv[2])
    sys.path.insert(0, str(pipeline))

    import pandas as pd
    from main import LABEL_FIXES, apply_label_fixes, clean_combined, unify_labels

    raw = pipeline / 'data' / 'original_data'
    kaggle_path = raw / 'malicious_phish.csv'
    if kaggle_path.is_file():
        kaggle = pd.read_csv(kaggle_path)
    else:
        print('malicious_phish.csv not found: building the table without the Kaggle dataset.')
        kaggle = pd.DataFrame({'url': pd.Series(dtype=str), 'type': pd.Series(dtype=str)})
    mendeley = pd.read_csv(raw / 'URL dataset.csv')
    phiusiil = pd.read_csv(raw / 'PhiUSIIL_Phishing_URL_Dataset.csv')

    table = apply_label_fixes(clean_combined(unify_labels(kaggle, mendeley, phiusiil)), LABEL_FIXES)
    output.parent.mkdir(parents=True, exist_ok=True)
    table[['url', 'is_phishing', 'source']].to_csv(output, index=False)

    print(f'Saved {len(table):,} URLs to {output}')
    print(table.groupby('source')['is_phishing'].agg(urls='size', phishing_share='mean').round(3))


if __name__ == '__main__':
    main()
