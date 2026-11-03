"""
Train the final character n-gram model with this back end's pinned scikit-learn
(a pickled model only loads reliably in the version that created it).

Same model and settings as train_model.py in Assignment 2. Input is the stage 2
table that Assignment 2's main.py writes (CODECREATED_final_cleaned_csv_phishing.csv).

    python -m scripts.train_model path/to/CODECREATED_final_cleaned_csv_phishing.csv

Writes models/MODEL_FINAL.joblib and prints the MODEL_SHA256 line for .env.
"""

import csv
import sys
from pathlib import Path

import joblib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import SGDClassifier
from sklearn.pipeline import Pipeline

from app.config import BACKEND_DIR
from app.model_service import sha256_file

OUTPUT = BACKEND_DIR / 'models' / 'MODEL_FINAL.joblib'


def read_table(path: Path) -> tuple[list[str], list[int]]:
    csv.field_size_limit(10_000_000)
    urls, labels = [], []
    with path.open(newline='', encoding='utf-8') as handle:
        for row in csv.DictReader(handle):
            if row.get('url') and row.get('is_phishing') in ('0', '1', '0.0', '1.0'):
                urls.append(row['url'])
                labels.append(int(float(row['is_phishing'])))
    if len(set(labels)) != 2:
        sys.exit('Training data must contain both benign and phishing URLs.')
    return urls, labels


def main() -> None:
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    urls, labels = read_table(Path(sys.argv[1]))

    model = Pipeline([
        ('tfidf', TfidfVectorizer(
            analyzer='char', ngram_range=(2, 5), min_df=10, max_features=10000,
            sublinear_tf=True, dtype=np.float32,
        )),
        ('classifier', SGDClassifier(
            loss='log_loss', max_iter=20, tol=1e-3, class_weight='balanced', random_state=432, n_jobs=-1,
        )),
    ])
    model.fit(urls, labels)
    # stop_words_ only records the n-grams that were discarded; it is not used for
    # prediction and can make the file hundreds of megabytes.
    model.named_steps['tfidf'].stop_words_ = None

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, OUTPUT)
    print(f'Trained on {len(urls):,} URLs; saved {OUTPUT}')
    print(f'Add this line to backend/.env:\nMODEL_SHA256={sha256_file(OUTPUT)}')


if __name__ == '__main__':
    main()
