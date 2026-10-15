# Guardian

Guardian is a browser-first phishing and scam protection system built as a monorepo. It combines:

- a Chrome MV3 extension that watches navigation and surfaces warnings
- a FastAPI backend that validates device tokens, stores analysis results, and exposes analytics endpoints
- an ML and signal-analysis layer that scores URLs and message content for malicious behavior

The project is designed for a privacy-aware, local-first security workflow: the extension performs quick checks in-page, the API records structured results, and the backend can sync blocklist updates back to the browser.

## Repository structure

```text
.
├── README.md
├── Makefile
├── docs/
├── extension/         # Chrome extension (React + Vite + TypeScript)
├── api/               # FastAPI backend (Python)
├── ml/                # Model and feature pipeline
├── infra/             # Deployment and infrastructure config
├── .github/
├── docker-compose.yml
├── docker-compose.prod.yml
└── package.json       # Monorepo scripts
```

## What the app does

### Browser extension
The extension is the main user-facing part of the product.

It can:
- redirect suspicious pages to a blocked warning page
- show inline badges for risky pages
- inspect links and message content in supported flows
- create a popup with status, stats, and settings
- register/report/track malicious URLs

The extension entry points are under `extension/src/`:
- `src/background/` - service worker logic and page interception
- `src/content/` - content script behavior for security warnings and injected UI
- `src/popup/` - extension popup UI
- `src/options/` - settings page
- `src/blocked/` - blocked-page experience
- `src/analyze-popup/` - pop-up analysis view

### API backend
The API is implemented in `api/src/main.py` and is responsible for:
- validating `X-Device-Token` requests
- storing analysis case data and device state
- serving case history, statistics, reports, and blocklist deltas
- exposing health/readiness checks and Prometheus metrics
- tracking API usage and structured events

Key endpoints in `api/src/main.py`:

- `POST /v1/analyze` - analyze a message/text + URLs and return a score, risk level, and explainable signals
- `GET /v1/cases` - list recent cases for the current device
- `GET /v1/cases/{case_id}` - fetch a single case record
- `POST /v1/feedback` - accept FP/FN feedback for a case
- `POST /v1/report` - submit a malicious URL report
- `GET /v1/stats` - aggregated statistics for the last 7/30/90 days
- `GET /v1/blocklist/delta` - return blocklist updates since a timestamp
- `POST /v1/devices` - register a new device token
- `DELETE /v1/devices/me` - wipe device data
- `GET /health` and `GET /ready` - health and readiness checks
- `GET /metrics` - Prometheus output

### ML + detection layer
The project includes a model pipeline and rule-based detection logic to calculate risk. The backend doesn’t just return static blocklists; it combines:
- URL structure analysis
- domain and DNS signals
- suspicious wording / message heuristics
- intel source checks and risk scoring
- explainable evidence attached to each result

This is the core of the “Guardian” scoring model.

## End-to-end flow

1. A user visits or interacts with a website/message that the extension monitors.
2. The extension evaluates whether it should inspect the content or redirect to a blocked page.
3. The browser sends a request to the backend with device metadata and analysis payload.
4. The API validates the device token, runs the analyzer, and persists a case.
5. The analyzer collects signals and URLs, generates a score/level/action, and returns an explainable response.
6. The extension handles the result by showing a badge, warning page, or allowing the request through.
7. Blocklist information and telemetry are recorded for future checks and audits.

## Local development

### Prerequisites

- Node.js 20+
- Python 3.11+
- Docker and Docker Compose
- Chrome or Chromium for extension testing

### Start the stack

```bash
make dev
```

This brings up the app services defined by Docker Compose. For a more focused workflow:

```bash
make dev-api
make dev-extension
```

The API is available at:
- http://localhost:8000
- Swagger/OpenAPI docs: http://localhost:8000/docs

### Extension build and verification

From the extension folder:

```bash
cd extension
npm install
npm run build
npm run verify-dist
```

Production builds require a valid `API_ORIGIN` value and will fail if it is missing or ends with `.example`:

```bash
export API_ORIGIN=https://api.guardian.app
npm run build:prod
```

To load the extension in Chrome:
1. Open `chrome://extensions/`
2. Enable Developer mode
3. Click “Load unpacked”
4. Select `extension/dist`

## Useful repo commands

From the repo root:

```bash
make help
make test
make lint
make build
make build-extension
make generate-types
```

Common package-specific commands:

```bash
cd api && python -m pytest tests/
cd extension && npm test
cd ml && python -m pytest tests/
```

## API configuration

The backend reads settings from `api/.env` using the config in `api/src/core/config.py`.

Normal environment variables include:

```env
DATABASE_URL=postgresql+asyncpg://guardian:guardian@localhost:5432/guardian
REDIS_URL=redis://localhost:6379/0
SECRET_KEY=change-me-in-production-use-strong-random-key
GOOGLE_SAFE_BROWSING_API_KEY=...
VIRUSTOTAL_API_KEY=...
SENTRY_DSN=
```

The repository also ships with example configs under:
- `api/.env.example`
- `api/.env.production.example`
- `extension/.env.example`

## Observability and security

The API includes:
- Prometheus metrics at `/metrics`
- Sentry integration when configured
- structured request logging middleware
- device-token-based authentication
- CORS restrictions for extension-origin access

## Notes for contributors

- The extension is the main user-facing delivery surface and must keep the dist output valid for Chrome MV3.
- The backend relies on typed request/response contracts and DB-backed device state.
- The ML layer and signal analysis are designed to explain why a result was classified as suspicious or malicious.

## License

Project licensing is handled in the repo’s top-level legal files. Check the repository for the exact license text before redistribution or publication.
