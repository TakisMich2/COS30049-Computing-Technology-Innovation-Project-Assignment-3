# PhishCheck – Phishing URL Detection System

COS30049 Computing Technology Innovation Project

PhishCheck scores how trustworthy a web address is (0–100) using the character
n-gram model trained in Assignment 2, and explains any suspicious part of the
address in plain language. It is part of an education campaign helping
Australians protect their own data.

| Part | Folder | Stack |
|---|---|---|
| Front end | [`frontend/`](frontend/) | React 19, React Router 7, Recharts 2, Vite 8 |
| Back end | [`backend/`](backend/) | FastAPI, Pydantic 2, scikit-learn 1.9.1, Uvicorn |
| Security analysis | [`SECURITY.md`](SECURITY.md) | Full threat model, defences, attack scripts and results |

## For marking: chosen security work

| Section | Chosen | Evidence |
|---|---|---|
| 2.7 Defence 1 | **Denial of service (Advanced)** | [SECURITY.md §2](SECURITY.md#2-defence-1--denial-of-service-advanced), `security/dos_attack.py` |
| 2.7 Defence 2 | **Unsafe model loading (Basic)** | [SECURITY.md §3](SECURITY.md#3-defence-2--unsafe-model-loading-basic), `security/model_tamper.py` |
| 2.8 Advanced attack | **Detection evasion** | [SECURITY.md §4](SECURITY.md#4-advanced-security--detection-evasion-section-28), `security/evasion_eval.py` |

Misconfiguration and vulnerable dependencies are also hardened (security
headers, docs off, audited dependencies), but that is **not** one of the two
defences we want marked.

Each defence can be switched off for the before/after demonstration with
`DISABLED_DEFENCES` in `backend/.env` (`dos`, `model`, `evasion`, `hardening`).

## Architecture

```
 Browser (React single-page app)
 ┌────────────────────────────────────────────┐
 │ UrlForm ── validateUrl (usability only)    │      localStorage
 │ ResultPanel · TrustGauge · WarningList     │◄────► history of checks
 │ Charts: confidence · warnings · history    │      (never sent anywhere)
 └──────────────────┬─────────────────────────┘
                    │ POST /api/assess {"url": "..."}   GET /api/health
                    │ (same origin; JSON only)
 ┌──────────────────▼─────────────────────────────────────────────────┐
 │ FastAPI back end (Uvicorn, 127.0.0.1:8000)                         │
 │                                                                    │
 │  Middleware, outermost first:                                      │
 │   SecurityHeaders ─► RequestContext ─► CORS ─► BodySizeLimit       │
 │   (CSP, nosniff…)    (request ID,        (own     (8 KB, before    │
 │                       JSON 500)           origins)  parsing)       │
 │                                                                    │
 │  Pydantic validation (AssessRequest) ─► URL length limit (2,048)   │
 │        │                                                           │
 │        ▼                                                           │
 │  InferenceGate: 2 worker threads + 8 queue places, else 503        │
 │        │                                                           │
 │        ▼                                                           │
 │  assess():  normalise_url ─► model.predict_proba ─► explain rules  │
 │             (evasion          (TF-IDF char 2–5-grams  (url_        │
 │              defence)          + SGD, log loss)        indicators) │
 │                                                                    │
 │  Startup: SHA-256 check ─► joblib.load(MODEL_FINAL.joblib), once   │
 │  Also serves frontend/dist (the built React app) at /              │
 └────────────────────────────────────────────────────────────────────┘
```

The back end never fetches or resolves the submitted URL; it only analyses the
text. There is no database: history stays in the user's own browser.

## Run it on a clean machine

You need **Python 3.14** (tested with 3.14.7) and **Node.js 22.12 or newer**
(tested with 26.13). Commands are for Windows PowerShell; on macOS/Linux use
`source .venv/bin/activate` and `cp` instead of `copy`.

### 1. Back-end environment

```bash
cd backend
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
```

### 2. Get the trained model

The server needs `backend/models/MODEL_FINAL.joblib` and its SHA-256 hash in
`backend/.env`. It refuses to load a model whose hash does not match (see
SECURITY.md). Use whichever option applies:

**A. Use the included model (normal case).** The submission includes
`backend/models/MODEL_FINAL.joblib` (0.3 MB). Put its hash in `backend/.env`:

```
MODEL_SHA256=04b478c5fd5ee801e08499f7e32ef4bee92c6ce954f5b1d69767e8436a3d26c7
```

You can confirm it with `python -m scripts.hash_model`.

**B. Download it (only if the model file is missing).** If the model is ever
hosted separately, set `MODEL_URL` (an `https://` link to the file) and the
`MODEL_SHA256` above in `backend/.env`, then run
`python -m scripts.download_model`. The script deletes the download if its hash
does not match.

**C. Train it yourself.** Use this back end's pinned scikit-learn, because a
pickled model only loads reliably in the version that created it.

1. Put the Assignment 2 code in a folder (here `assignment2-pipeline/`), create a virtual environment there with `pip install pandas tldextract`, and save the raw datasets in its `data/original_data/` folder (names and links in its README).
2. Build the training table with Assignment 2's own cleaning code (`unify_labels`, `clean_combined`, `apply_label_fixes`). The 50 engineered features are skipped, because the character n-gram model only reads the URL:

   ```bash
   assignment2-pipeline\.venv\Scripts\python backend\scripts\build_training_table.py assignment2-pipeline assignment2-pipeline\data\combined_data\training_table.csv
   ```

3. In `backend/`, with its virtual environment active:

   ```bash
   python -m scripts.train_model "..\assignment2-pipeline\data\combined_data\training_table.csv"
   ```

   This saves `backend/models/MODEL_FINAL.joblib` (about 2.5 minutes) and prints
   a `MODEL_SHA256=...` line. Paste that line into `backend/.env`.

**What the included model was trained on.** 684,806 URLs: 449,866 from the
Mendeley dataset (23% phishing) and 234,940 from PhiUSIIL (43% phishing),
cleaned exactly as in Assignment 2. The Kaggle dataset was **not** used: it
can only be downloaded with a Kaggle account. `build_training_table.py`
includes it automatically (with Assignment 2's label fixes) if
`malicious_phish.csv` is present. The model's settings are unchanged from
Assignment 2: TF-IDF over character 2–5-grams with a logistic-loss SGD
classifier. Accuracy is not assessed in this assignment, so the model is
treated as a black box.

### 3. Build the front end

```bash
cd ../frontend
npm ci
npm run build
```

`npm ci` installs exactly the versions in `package-lock.json`.

### 4. Start

```bash
cd ../backend
python run.py
```

Open **http://127.0.0.1:8000**. The back end serves both the API and the built
front end from one origin.

### Development mode (optional)

Run `python run.py` in `backend/` and `npm run dev` in `frontend/`, then open
http://localhost:5173. Vite reloads on save and forwards `/api` to port 8000.
`npm run dev:mock` runs the front end alone with simulated results.

### Tests and audits

```bash
cd backend
pip install -r requirements-dev.txt
python -m pytest
python -m pip_audit -r requirements.txt -r requirements-dev.txt
cd ../frontend
npm audit
```

## API documentation

Interactive documentation is generated by FastAPI at **`/docs`**. It is turned
off by default, because exposed docs are a misconfiguration risk.
To view it:

1. Set `ENABLE_DOCS=true` in `backend/.env`.
2. Restart `python run.py` and open **http://127.0.0.1:8000/docs**.

Every endpoint has a description, example requests (choose one from the
**Examples** list after **Try it out**), and example responses for success and
for each error status. The `/docs` page alone gets a looser Content Security
Policy so Swagger UI can load from its CDN; every other page keeps the strict one.

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/api/assess` | Score one URL. Body `{"url": "..."}` (max 2,048 characters, 8 KB body). Returns the trust score, phishing probability, prediction, the URL the model analysed after normalisation, and explained warnings. |
| `GET` | `/api/health` | Whether the server is up and the model is loaded. The front end calls it on load to warn early if the back end is down. |

Every error uses one JSON shape, with no stack traces or internal details:

```json
{"error": {"code": "invalid_input", "message": "URL cannot be empty.",
           "details": [{"field": "url", "message": "URL cannot be empty."}],
           "request_id": "8e0a5c0dbdc24f41"}}
```

| Status | Code | When |
|---|---|---|
| 422 | `invalid_input` / `invalid_url` | Empty, too long, contains spaces, unknown fields, bad JSON |
| 413 | `payload_too_large` | Body over 8 KB (checked before parsing, even without Content-Length) |
| 404 / 405 | `not_found` / `method_not_allowed` | Unknown endpoint or wrong method |
| 503 | `service_busy` | Inference capacity full; includes `Retry-After` |
| 500 | `internal_error` | Anything unexpected; details logged server-side only |

## Threat model (summary)

**Assets:** the service's availability; the integrity of its verdicts (a
phishing link must not be passed as safe); the server that loads the model
file; and the privacy of the addresses users check.

**Attackers:** anyone who can reach the API. There are no accounts, so every
caller is anonymous and untrusted, and attacks are made directly against the
API, not through our interface.

**Entry points:** `POST /api/assess`, `GET /api/health`, the static front-end
files, and the model file on disk.

| Risk | Applies? | Response |
|---|---|---|
| Denial of service | Yes | **Defence 1.** Body and URL size limits, inference off the event loop, bounded queue with 503 |
| Unsafe model loading | Yes | **Defence 2.** SHA-256 of the model checked at startup before `joblib.load`; the server refuses to start on a mismatch, and the verified bytes are what gets unpickled |
| Detection evasion (look-alike letters, invisible characters, encodings) | Yes | **Advanced attack.** Unicode normalisation before the model; look-alike host names capped at trust 5 |
| Misconfiguration / vulnerable dependencies | Yes | Hardened but not marked: security headers, docs off, no server banner, strict CORS, audited pinned dependencies |
| Missing rate limiting | Yes | Partly covered by the global admission gate; per-client limits not built |
| Command injection, SQL injection, file upload, SSRF, broken access control | No | No shell calls, no database, no uploads, the URL is never fetched, and no accounts |

The full table with reasons, measurements and costs is in [SECURITY.md](SECURITY.md).

## Pinned dependency versions

**Back end** (`backend/requirements.txt`, every package including transitive ones):

| Package | Version | Package | Version |
|---|---|---|---|
| fastapi | 0.162.0 | scikit-learn | 1.9.1 |
| starlette | 1.10.0 | numpy | 2.5.4 |
| pydantic | 2.14.2 | scipy | 1.18.1 |
| pydantic_core | 2.50.2 | joblib | 1.6.0 |
| uvicorn | 0.54.0 | threadpoolctl | 3.7.0 |
| python-dotenv | 1.2.4 | idna | 3.20 |
| anyio | 4.16.0 | httptools | 0.9.0 |
| h11 | 0.16.0 | watchfiles | 1.3.0 |
| click | 8.5.0 | websockets | 17.4 |
| annotated-doc | 0.0.5 | PyYAML | 6.0.3 |
| annotated-types | 0.8.0 | colorama | 0.4.6 |
| typing-inspection | 0.4.4 | typing_extensions | 4.16.0 |

Development only (`backend/requirements-dev.txt`): pytest 9.2.0, httpx 0.28.1,
httpcore 1.0.9, pip-audit 2.10.1, certifi 2026.10.23, iniconfig 2.3.1,
packaging 26.3, pluggy 1.7.0, Pygments 2.21.0.

**Front end** (`frontend/package.json`, exact versions; `package-lock.json`
pins the full tree):

| Package | Version |
|---|---|
| react | 19.3.1 |
| react-dom | 19.3.1 |
| react-router-dom | 7.18.5 |
| recharts | 2.15.4 |
| @fontsource-variable/inter | 5.3.0 (Inter typeface, self-hosted so the CSP needs no font CDN) |
| vite (dev) | 8.3.5 |
| @vitejs/plugin-react (dev) | 6.2.1 |

**Runtimes:** Python 3.14.7, Node.js 26.13.0 (22.12 or newer required).

## Configuration

All settings live in `backend/.env` (see [`.env.example`](backend/.env.example));
nothing deployment-specific or secret is in the source code. The front end has
no secrets. `.env` is git-ignored and is not included in the submission ZIP.

## Statement on the use of generative AI

We used **Claude Code** (Anthropic, model Claude Opus 5.5) as a coding
assistant throughout this assignment. Working from the requirements we gave it
(the assignment brief, our Assignment 1 requirements document and our
Assignment 2 model code), it:

- wrote the React front end, the FastAPI back end and the automated tests, and helped us debug them, particularly the API functions and documentation;
- helped us decide which security defences were most appropriate for a phishing checker application, then implemented them;
- helped us define test cases and edge cases to try to 'break' or 'breach' the application, and wrote the attack and measurement scripts;
- retrained our Assignment 2 model with the back end's library versions, reusing our Assignment 2 cleaning code, and ran the security measurements reported in SECURITY.md;
- drafted this README, SECURITY.md and the API documentation text.

The model's design (data cleaning, label fixes and model settings) is our
Assignment 2 work. We directed the work, chose the requirements, design and
defences, and reviewed and tested the application.

All AI output was checked by the group, and we take responsibility for the submitted work.

## References

Andersson, R. (2026) *Inter* [Typeface]. Available at: https://rsms.me/inter/ (Accessed: 3 November 2026).

Anthropic (2026) *Claude Code* [Computer software]. Available at: https://claude.com/claude-code (Accessed: 3 November 2026).

Costello, A. (2003) *Punycode: A Bootstring encoding of Unicode for Internationalized Domain Names in Applications (IDNA)*. RFC 3492. Internet Engineering Task Force. Available at: https://www.rfc-editor.org/rfc/rfc3492 (Accessed: 3 November 2026).

Fielding, R., Nottingham, M. and Reschke, J. (eds) (2022) *HTTP Semantics*. RFC 9110. Internet Engineering Task Force. Available at: https://www.rfc-editor.org/rfc/rfc9110 (Accessed: 3 November 2026).

Gabrilovich, E. and Gontmakher, A. (2002) 'The homograph attack', *Communications of the ACM*, 45(2), p. 128.

Kaitholikkal, J.K.S. and B, A. (2024) *Phishing URL dataset*. Mendeley Data, V1. doi: 10.17632/vfszbj9b36.1.

Meta Platforms (2026) *React* [Computer software]. Available at: https://react.dev (Accessed: 3 November 2026).

Mozilla (2026) *Content Security Policy (CSP)*. MDN Web Docs. Available at: https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP (Accessed: 3 November 2026).

OWASP Foundation (2021) *OWASP Top 10:2021*. Available at: https://owasp.org/Top10/ (Accessed: 3 November 2026).

OWASP Foundation (2023) *OWASP API Security Top 10 2023*. Available at: https://owasp.org/API-Security/editions/2023/en/0x11-t10/ (Accessed: 3 November 2026).

Pedregosa, F., Varoquaux, G., Gramfort, A., Michel, V., Thirion, B., Grisel, O., Blondel, M., Prettenhofer, P., Weiss, R., Dubourg, V., Vanderplas, J., Passos, A., Cournapeau, D., Brucher, M., Perrot, M. and Duchesnay, É. (2011) 'Scikit-learn: Machine learning in Python', *Journal of Machine Learning Research*, 12, pp. 2825–2830.

Prasad, A. and Chandra, S. (2024) 'PhiUSIIL: A diverse security profile empowered phishing URL detection framework based on similarity index and incremental learning', *Computers & Security*, 136, 103545. doi: 10.1016/j.cose.2023.103545.

Ramírez, S. (2026) *FastAPI* [Computer software]. Available at: https://fastapi.tiangolo.com (Accessed: 3 November 2026).

Recharts Group (2026) *Recharts* [Computer software]. Available at: https://recharts.org (Accessed: 3 November 2026).

Siddhartha, M. (2021) *Malicious URLs dataset*. Kaggle. Available at: https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset (Accessed: 3 November 2026).

Unicode Consortium (2025) *Unicode Technical Standard #39: Unicode Security Mechanisms*. Available at: https://www.unicode.org/reports/tr39/ (Accessed: 3 November 2026).
