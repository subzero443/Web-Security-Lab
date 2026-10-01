# Breakpoint Web Security Lab

A local-only training application comparing deliberately vulnerable examples with secure implementations. It uses a React + Tailwind frontend, Flask API, and synthetic SQLite data.

> **Safety boundary:** This app intentionally contains unsafe patterns for education. Run it only on your own machine. Both servers bind to `127.0.0.1`; do not expose or deploy the vulnerable routes. The fixtures are synthetic and path traversal is confined to `backend/lab_data/`.

## Requirements

- Python 3.10 or newer
- Node.js 20 or newer and npm

## Run locally

From the project root, open two terminals.

Backend:

```powershell
cd backend
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python app.py
```

Frontend:

```powershell
cd frontend
npm install
npm run dev
```

Open the local URL printed by Vite (normally `http://127.0.0.1:5173`). The Vite development server proxies `/api` to Flask on `127.0.0.1:5000`.

## Demonstrations

- SQL injection: unsafe string-built search query vs bound SQLite parameter.
- XSS: raw HTML preview vs text output. The vulnerable preview is intentionally rendered as HTML; only use harmless training inputs or the included local payload.
- Broken authentication: predictable training password with no throttling vs Werkzeug password hashes, generic failures, bounded input, and a five-attempt per-client cooldown. Training logins are `alice / password123` (vulnerable) and `alice / secure-demo-pass` (secure).
- IDOR: caller-supplied identity vs signed-in identity and per-document ownership checks. Secure demo sign-in is `alice / secure-demo-pass`.
- Path traversal: file lookup can escape `public/` only into a synthetic fixture still inside `backend/lab_data/` vs canonical public-root containment.
- Security misconfiguration: verbose synthetic runtime details and wildcard CORS vs a minimal response with security headers.
- Weak session handling: editable numeric identity cookie with no expiry or rotation vs a signed 30-minute Flask session, rotation on login, HttpOnly, and SameSite=Strict.

The secure cookie's `Secure` flag is enabled with `LAB_HTTPS_ONLY=1` when running behind HTTPS. For local plain HTTP it stays off so the demo session works; do not use that local configuration in production.

## Tests

```powershell
cd backend
python -m pip install -r requirements.txt
python -m pytest -q
```

The tests use a temporary SQLite database and cover SQL parameterization, ownership enforcement, traversal containment, XSS-safe output, and security headers.
