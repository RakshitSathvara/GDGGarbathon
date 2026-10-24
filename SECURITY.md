# Security policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately through GitHub's
**Security → Report a vulnerability** (private vulnerability reporting) on this repository rather
than opening a public issue. Include steps to reproduce and the affected backend (Node or Python).

## Threat model

Saavdhan is a public demo: anyone can load the page, start sessions, trigger paid Gemini requests and
upload audio. The main risks are abuse of the Gemini key, resource exhaustion, malicious uploads,
cross-site scripting through model output or file names, and leaking internal details in errors.

## Controls

| Risk | Control | Code |
| --- | --- | --- |
| API key exposure | Key read from the environment on the server only; the browser never calls Gemini. | `server/config.ts`, `app/config.py` |
| XSS / injection | Strict CSP (`script-src 'self'`, no `unsafe-inline`, `object-src 'none'`); all dynamic text rendered via `textContent`; quotes highlighted by splitting text, never by building HTML. | `server/security.ts`, `app/security.py`, `static/js/view.js`, `static/js/dom.js` |
| Untrusted model output | Gemini JSON validated against the shared schema (zod / Pydantic) before use; invalid output becomes an "unavailable" chunk, never a verdict. | `server/validation.ts`, `app/detector.py` |
| Malformed requests | Schema validation of every body; UUID session IDs; integer chunk indexes; strict base64; WAV structure parsing. | `server/validation.ts`, `app/main.py` |
| Resource exhaustion | 16 KB JSON / 16 MB upload body limits (enforced even for chunked bodies), per-IP rate limits, session TTL and cap, upload cap, bounded audio cache, `ffmpeg` timeout. | `server/app.ts`, `server/config.ts`, `app/security.py` |
| Path traversal / file overwrite | Upload names sanitized and namespaced (`upload_*`); atomic temp-file + rename writes; only `^[A-Za-z0-9][A-Za-z0-9_-]*\.wav$` files in `calls/` are served. | `server/upload.ts`, `app/storage.py` |
| Command injection | `ffmpeg` invoked with an argument array (no shell) and server-generated paths only. | `server/upload.ts`, `app/storage.py` |
| Information disclosure | Generic 500 responses, sanitized upstream error messages, no `X-Powered-By`, API docs disabled, `Cache-Control: no-store` on API responses. | `server/app.ts`, `app/main.py` |
| Clickjacking | CSP `frame-ancestors` configurable via `FRAME_ANCESTORS`; left open by default so the Google AI Studio preview iframe keeps working (the app has no authenticated actions). | `server/security.ts` |
| Supply chain | Lockfile-pinned npm dependencies, `npm audit` in CI, minimal dependency set. | `package-lock.json`, `.github/workflows/ci.yml` |

Security behaviour is covered by tests (headers, rate limits, body limits, traversal attempts,
upload validation, error hiding) in `tests/node/app.test.ts`, `tests/node/upload.test.ts`,
`tests/python/test_api.py`, `tests/python/test_sessions_security.py` and `tests/python/test_storage.py`.
