# PhishCheck – Threat model and security defences

Front-end checks are for usability; back-end checks are for security. Every
attack below is demonstrated by calling the API directly (curl or a Python
script), because an attacker does not use our interface.

Each defence can be switched off **for the demonstration video only** with
`DISABLED_DEFENCES` in `backend/.env` (`dos`, `model`, `evasion`, `hardening`).
The server logs a warning at startup whenever any defence is off.

**Marked work:** defence 1 – denial of service (§2); defence 2 – unsafe model
loading (§3); advanced security – detection evasion (§4). The hardening in §5
is kept as good practice but is not one of the two marked defences.

## 1. Threat model

**What we protect:** the service's availability, the integrity of its verdicts
(a phishing link must not be passed as safe), the server that loads the model
file, and the privacy of the addresses users check.

**Who attacks:** anyone on the network who can reach the API. There are no
accounts, so every caller is anonymous and untrusted.

**Entry points:** `POST /api/assess`, `GET /api/health`, the static front-end
files, and the model file on disk.

| Risk (level) | Applies? | Why / what we do |
|---|---|---|
| **Denial of service** (Advanced) | **Yes – chosen defence 1** | Inference is CPU work whose cost grows with input length, and FastAPI sets no limits. See §2. |
| **Unsafe model loading** (Basic) | **Yes – chosen defence 2** | The server loads a joblib file, which can run code hidden inside it, and the model can arrive by download script or from a teammate. See §3. |
| Misconfiguration & vulnerable dependencies (Intermediate) | Yes | Applies to every application. **Also hardened, but not one of the two marked defences.** See §5. |
| Missing rate limiting (Basic) | Yes | Not chosen. Partly covered by the global admission gate in §2, which limits total load but not any one client's share. A per-client limit would be the next step. |
| Command injection (Basic) | No | The back end never runs a system command (no `whois`, `dig` or shell calls). |
| SQL injection (Intermediate) | No | There is no database. Analysis history is kept only in the user's own browser (`localStorage`). |
| Unsafe file upload (Intermediate) | No | The API accepts no files, only a JSON body capped at 8 KB. |
| SSRF (Advanced) | No | The submitted URL is analysed **as text only**. The back end never fetches it, resolves it or follows redirects, so it cannot be pointed at internal addresses. This is a deliberate design choice. |
| Broken access control (Advanced) | No | There are no user accounts or per-user records. |

## 2. Defence 1 – Denial of service (Advanced)

**Attack.** One request can cost the server far more than it costs to send.
Model inference (TF-IDF over character 2–5-grams) costs about 4 µs per
character: under 10 ms for a 2,048-character URL, but **about 20 s for a
5 MB URL**. Running that inside an `async def` endpoint blocks the single
event loop, so every other user waits. Flooding the API piles up unbounded work.

**Defence** (`app/security.py`, `app/model_service.py`, `app/main.py`):

1. **Body size limit before parsing.** Pure-ASGI middleware rejects bodies over 8 KB with 413. It works on the raw byte stream, so it also stops chunked uploads that lie about or omit `Content-Length`. Nothing oversized is buffered or parsed.
2. **Input length limit.** URLs over 2,048 characters are rejected with 422, which caps the cost of a single inference at under 10 ms.
3. **Inference off the event loop.** The model runs in a dedicated two-thread pool, so the server keeps accepting and answering other requests (such as `/api/health`) while it works.
4. **Admission gate with fast rejection.** At most 2 running plus 8 waiting inferences, with a 2 s queue timeout. Anything beyond that gets an immediate **503 with `Retry-After`** instead of queueing until the server freezes.

**Demonstrate it** (with the server running):

```bash
python -m security.dos_attack --label defended
# set DISABLED_DEFENCES=dos in .env, restart the server, then:
python -m security.dos_attack --label undefended
```

Phase 1 sends one 5 MB URL while a "normal user" checks an ordinary URL every
100 ms. Phase 2 sends 300 maximum-size requests at once while another client
polls `/api/health`. Results are saved in `security/results/`.

**Results** (trained model `MODEL_FINAL.joblib`, Windows laptop, client and
server on the same machine, 3 November 2026; raw output in
`security/results/dos-*.json`):

| | Undefended | Defended |
|---|---|---|
| 5 MB request | 200 after **20,670 ms** | **413 after 37 ms** |
| Normal user's slowest response during that request | **20,511 ms** (blocked) | 63 ms |
| Flood of 300 requests | all 300 accepted and processed | 13 answered, **287 rejected with 503** |
| Flood: total time to answer all 300 | 6,155 ms | 4,435 ms |
| `/api/health` slowest response during the flood | 3,900 ms | 2,168 ms |

**Variations covered:** a body without `Content-Length` or with a dishonest
one (test `test_body_size_limit_without_content_length`); a URL just under the
byte limit but over the character limit (422); many cheap requests at once
(503 gate); a slow request occupying a worker (queue timeout, then 503).
Inputs crafted to make the regular expressions backtrack were also timed at
the maximum length (2,048 characters): repeated hyphens, dots, digits,
percent escapes, query parameters, `@` signs, slashes, `xn--` labels,
sensitive words, zero-width and Cyrillic characters. The slowest took 36 ms,
so no input under the limit is disproportionately expensive.

**What it costs.** Legitimate URLs over 2,048 characters cannot be checked;
browsers and most servers cap URLs around there, so real links are rarely
affected. Under a burst, some genuine users receive "busy, try again" (503)
instead of a slow answer. That was a deliberate choice: a fast, honest
refusal beats a frozen site. The two-thread pool also caps throughput on a
large machine; raise `INFERENCE_WORKERS` there.

**Limits.** Health latency during the flood improves only modestly, because on
one laptop the cost of accepting 300 connections in a single Python process
dominates. Defending against that volume needs a reverse proxy or a hosting
provider's protection in front of the application. Distributed attacks are
out of scope, as the brief says.

## 3. Defence 2 – Unsafe model loading (Basic)

**Attack.** `joblib.load` is pickle underneath, and pickle can be told to call
any function while it rebuilds an object. An attacker who can replace the
model file (a tampered download, a file passed around the group, write access
to the server's folder) can hide code in it that runs with the server's
permissions the moment it starts. `security/model_tamper.py` builds such a
file: a working copy of our model whose hidden code runs first and then hands
back the genuine model. The server starts, answers correctly, and nothing looks
wrong. Our payload is harmless (it writes `security/results/PWNED.txt`); a real
one could read `.env`, install a backdoor or quietly change verdicts.

**Defence** (`app/model_service.py`, `load_verified_model`):

1. The trusted SHA-256 of the model lives in `MODEL_SHA256` (in `backend/.env`, and published in the README). It is configuration, kept out of the model file.
2. At startup the file is read **once**, its hash is compared with `hmac.compare_digest`, and on any mismatch the server **refuses to start**. `joblib.load` is never called on an unverified file.
3. The bytes that were hashed are the bytes that are unpickled (from memory). Swapping the file between the check and the load has no effect.
4. A missing or malformed `MODEL_SHA256` (empty, or shortened to a prefix) also refuses to start, so the check cannot be quietly skipped. Files over 200 MB are refused before they are read.
5. The model is loaded once at startup, never per request; a file replaced while the server runs is only loaded, and checked, at the next start.
6. `scripts/download_model.py` applies the same rule to downloads: https only, and the file is deleted unless its hash matches.

**Demonstrate it** (`python -m security.model_tamper build`, then):

| Step | Undefended (`DISABLED_DEFENCES=model`) | Defended |
|---|---|---|
| `.env`: `MODEL_PATH=models/TAMPERED.joblib`, real `MODEL_SHA256` | | |
| `python run.py` | Server starts; logs "loading TAMPERED.joblib WITHOUT checking its hash" | **Server refuses to start**: "Model file hash does not match MODEL_SHA256 (expected 04b478c5fd5e…, got bd2642cc847c…)" |
| `curl -X POST http://127.0.0.1:8000/api/assess -H "Content-Type: application/json" -d "{\"url\":\"https://www.abc.net.au/news\"}"` | Normal answer (trust 96): the attack is invisible | No server to answer |
| `security/results/PWNED.txt` | **Created**: the hidden code ran | **Not created** |

**Variations** (`python -m security.model_tamper measure`, saved in
`security/results/model-tamper.json`, and `tests/test_model_loading.py`):

| Case | Result | Hidden code ran? |
|---|---|---|
| Undefended: plain `joblib.load` of the tampered file | loaded | **yes** |
| Tampered file, real `MODEL_SHA256` | refused (hash mismatch) | no |
| Tampered file, `MODEL_SHA256` left empty | refused (hash not set) | no |
| Tampered file, hash shortened to 12 characters | refused (must be 64 hex characters) | no |
| File swapped on disk after the hash check (test) | the verified bytes are loaded, not the swap | no |
| File over the size limit (test) | refused before reading | no |
| Genuine model | loaded | no |
| *Limit:* attacker can also rewrite `MODEL_SHA256` in `.env` | loaded | yes |

The last row is the trust boundary, not a bypass: whoever controls `.env`
decides which file is trusted, so the hash must come from a trusted source
(the README and the person who trained the model), never from the same place
as the file.

**What it costs.** Startup takes about 0.5 ms longer (40.3 ms against 39.8 ms
to load the 0.3 MB model, best of 20). Every retrained model needs its new hash
copied into `.env`, and until that is done the server will not start: we chose
an outage over running a file we cannot verify. Reading the file into memory
once uses as much memory as the file (0.3 MB). The check proves the file is the
one we trained, not that the training was sound.

## 4. Advanced security – Detection evasion (section 2.8)

**Attack.** Small changes that a person cannot see change what the model sees.
The model learned character n-grams from plain-ASCII URLs, so an attacker can:

| Attack | Example |
|---|---|
| `homoglyph_host_3` | Up to 3 hostname letters swapped for Cyrillic look-alikes (`pаypal`) |
| `homoglyph_everywhere` | Every swappable letter in the URL swapped |
| `fullwidth_host` | Hostname in full-width letters (`ｐａｙｐａｌ.com`) |
| `zero_width` | A zero-width space after every third character |
| `punycode_homoglyph_host` | The look-alike hostname in its `xn--` form |
| `percent_encoded_host` | Every hostname letter percent-encoded |

Browsers resolve full-width, zero-width and percent-encoded forms to the same
site, and look-alike domains are a classic phishing technique. In every case
the link still works for the victim.

**Defence: normalise before the model** (`app/normalise.py`, applied in `app/assess.py`):

1. Remove invisible characters (zero-width, BOM, soft hyphen, bidi controls).
2. Apply Unicode NFKC normalisation (full-width and other compatibility forms become ASCII).
3. Percent-decode and lower-case the hostname, and decode `xn--` labels.
4. Map Cyrillic and Greek look-alikes to their Latin "skeleton" (based on Unicode UTS #39 confusables), but only within words that are disguises: they mix Latin with look-alikes, or consist entirely of look-alikes. A genuine Russian domain such as `пример.рф` is left alone.
5. Re-encode anything still non-ASCII as a browser would (punycode host, percent-encoded path).
6. A hostname disguised with look-alike letters is capped at a trust score of 5. No real site mixes alphabets to imitate another, and the skeleton of `pаypal.com` *is* `paypal.com`, which the model would otherwise rate safe.

The user sees an explanation for each step that changed their link, and the
result shows the address the browser would actually visit.

**Measure it** with your trained model and dataset:

```bash
python -m security.evasion_eval --csv "path\to\CODECREATED_final_cleaned_csv_phishing.csv" --sample 1000
```

The script samples phishing URLs the model detects unmodified, applies each
attack, and reports the share now classified "likely benign", with
normalisation off (before) and on (after). It also reports detection and
false-positive rates on unmodified traffic, which shows the defence's cost.
Results are saved in `security/results/evasion.json`.

**Results** (trained model, 2,000 phishing and 2,000 benign URLs sampled from
the training table with seed 432; 1,913 of the phishing URLs are detected
unmodified; raw output in `security/results/evasion.json`):

```bash
python -m security.evasion_eval --csv "..\assignment2-pipeline\data\combined_data\training_table.csv" --sample 2000 --seed 432
```

| Attack | URLs | Evasion before | Evasion after |
|---|---|---|---|
| homoglyph_host_3 | 1,870 | 2.0% | **0.0%** |
| homoglyph_everywhere | 1,913 | **31.4%** | **0.0%** |
| fullwidth_host | 1,913 | **16.8%** | **0.0%** |
| zero_width | 1,913 | 3.0% | **0.0%** |
| punycode_homoglyph_host | 1,870 | 2.5% | **0.0%** |
| percent_encoded_host | 1,871 | 1.9% | **0.0%** |
| *Unmodified traffic* | 2,000 + 2,000 | detection 95.7%, false positives 0.0% | detection 95.7%, false positives 0.0% |

(URL counts differ slightly because some URLs have no letter the attack can
change, e.g. a hostname that is an IP address.)

**Reading the results.** Swapping a few hostname letters for look-alikes
rarely fools this model on its own (2%), because the rest of the URL still
looks like phishing. Disguising the whole URL does: almost a third of
detected phishing links passed as "likely benign" with every letter swapped,
and one in six with a full-width hostname. After normalisation the model sees
exactly what it would have seen without the disguise, and a look-alike hostname
is capped at trust 5, so no attack evaded detection. Normalisation did not
change the detection or false-positive rate on ordinary URLs.

**Limits of the measurement.** The sample comes from the model's own training
data, so the 95.7% detection rate is optimistic; it is reported only as the
baseline the attacks are measured against. The Kaggle dataset was not used to
train this model (see the README), and only the six attacks above were tested.

**What it costs.** Legitimate internationalised domains that happen to mix in
look-alike letters (rare, but they exist in some brand names) are flagged as
high risk. Look-alike mapping covers Cyrillic and Greek only, so other scripts
(such as Armenian) can still be used, and the table needs maintenance as new
tricks appear. Normalisation adds well under a millisecond per request. The
front end now accepts non-ASCII input instead of rejecting it, so the server
can warn about disguised links rather than turning them away.

## 5. Additional hardening – misconfiguration and vulnerable dependencies (not marked)

**Risk.** Default settings leak information and leave browser protections
off: no security headers, interactive API docs exposed, the server software
advertised, and libraries with known vulnerabilities.

**Defence:**

| Item | What we did | Where |
|---|---|---|
| Security headers on every response, including errors | `Content-Security-Policy` (scripts and styles only from our own origin, no framing, no plugins), `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Permissions-Policy`, `Cross-Origin-Opener-Policy` and `-Resource-Policy`; `Cache-Control: no-store` on API responses | `app/security.py` |
| Debug features off | `/docs` and `/openapi.json` disabled unless `ENABLE_DOCS=true` (when on, only `/docs` gets a looser CSP so Swagger UI can load from jsDelivr); no debug mode; errors never include stack traces | `app/main.py`, `app/errors.py`, `app/security.py` |
| No server fingerprint | Uvicorn's `Server` header removed | `run.py` |
| CORS | Only the configured front-end origins; a `*` value makes the server refuse to start | `app/config.py` |
| Privacy in logs | Request logs record method, path, status and time, never the submitted URL | `app/security.py` |
| Pinned dependencies | Every Python package pinned exactly (including transitive ones); `package-lock.json` with exact versions | `requirements*.txt`, `package.json` |
| Vulnerable dependencies | `npm audit` first reported **4 vulnerable packages (3 moderate, 1 high)**: esbuild through Vite 5 (dev server readable by any website, GHSA-67mh-4wv8-2f99) and React Router 6 (open redirect, GHSA-wrjc-x8rr-h8h6; constructor injection in SSR hydration, GHSA-337j-9hxr-rhxg). Fixed by upgrading to Vite 8.3.5 and React Router 7.18.5 (and React 19). Now `npm audit` reports **0 vulnerabilities** and `pip-audit` reports **no known vulnerabilities**. | `package.json` |

**Check it.** `curl -I http://127.0.0.1:8000/` shows the headers;
`DISABLED_DEFENCES=hardening` turns them off for comparison. An OWASP ZAP scan
was not run, because this is not one of our marked defences.

**What it costs.** The strict CSP forbids inline scripts and styles, so
components must use stylesheets and DOM style properties (all of ours already
do). Disabling `/docs` removes a convenience for developers. Pinned versions
need deliberate upgrades, so security fixes do not arrive automatically:
re-run both audits regularly.

## 6. Security hygiene checklist (section 2.3)

| Requirement | How it is met |
|---|---|
| User input never rendered as HTML | React escapes all text. The code has no `dangerouslySetInnerHTML`, `innerHTML`, `window.open` or `window.location` assignments, and no user-controlled `href`. React 19 also neutralises `javascript:` URLs. The API returns JSON only. CSV export prefixes formula characters (`= + - @`) to stop spreadsheet injection. |
| Size limits enforced on the back end | 8 KB request body (middleware) and 2,048-character URL (422). There are no file uploads. |
| CORS allows only our front end | `ALLOWED_ORIGINS` lists explicit origins; `*` is refused at startup; tested in `test_cors_allows_only_the_front_end`. In production the front end is served from the same origin, so no cross-origin access is needed at all. |
| Secrets out of source code | All configuration comes from environment variables or `backend/.env` (git-ignored). The model hash is configuration, not a secret, but lives there too so a new model needs no code change. The app has no passwords or API keys. |
