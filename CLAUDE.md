# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

PurViewEr is a browser-based forensic analysis tool for Microsoft Purview (Office 365) audit logs. It is 100% client-side — no backend, no build step, no package.json. All data processing happens in the browser.

## Running Locally

Serve from a local HTTP server (required for ES module/CDN loading):
```bash
python -m http.server 8000    # then open http://localhost:8000/index.html
npx http-server -p 8000
```

There is no build, lint, or test command. There is no package.json or bundler.

## Architecture

There are two equivalent versions of the app:

1. **`index.html`** — Standalone single-file app. Loads React, Babel, PapaParse, and Recharts from the `libs/` directory. Uses `<script type="text/babel">` for in-browser JSX transformation. This is the primary deployment artifact (GitHub Pages, local file).

2. **`purview-forensic-analyzer-v2.jsx`** — The same app as an importable React component (`export default function App`). For integration into React projects with a bundler. Requires `npm install react react-dom papaparse recharts`.

Both files contain the full application (~1200 lines). Changes should be kept in sync between them.

### State Management

Single `useReducer` manages global state. Action types: `SET_RECORDS`, `APPEND_RECORDS`, `SET_IP_CLASS`, `SET_IP_MAP`, `SET_VIEW`, `SET_FILTER`, `CLEAR_FILTERS`, `SET_IOCS`, `SET_LOADING`, `SET_ERROR`. No external state library.

### Data Flow

```
CSV file(s) → processRecords(csvText, sourceFile) → normalized record objects
  → useReducer state (records, ipMap, filters, iocs)
  → useMemo for filtering/grouping
  → view components (Timeline, By IP, By User, By Message, By Operation, By Session, Raw)
```

### Key Functions

- `processRecords(csvText, sourceFile)` — Parses CSV via PapaParse, extracts fields from nested AuditData JSON using `FIELD_EXTRACTION` map with fallback field paths.
- `flattenObject(obj, prefix)` — Flattens nested JSON from AuditData column for field extraction.
- `classifyIp(ip)` / `isMicrosoftIp(ip)` — Auto-classifies private ranges as Trusted; detects Microsoft IPs via `KNOWN_MSFT_PREFIXES`.
- `matchesIoc(record, iocSet)` — Checks record fields against imported IOC indicators.
- `bucketByMinute(records, ipMap)` — Aggregates records by minute for the Recharts activity timeline.

### IP Classification Cycle

Click an IP to cycle: Unknown → Trusted → Suspicious → Unknown. Classifications persist in localStorage under key `purview-forensic-ip-classifications`.

### Styling

All styles are inline React style objects defined in a `S` (styles) constant. Dark theme with DM Sans (UI) and JetBrains Mono (data) fonts loaded from Google Fonts. No CSS files, no Tailwind, no CSS-in-JS library.

### Persistence

Two localStorage keys: `purview-forensic-ip-classifications` (IP map) and `purview-forensic-iocs` (IOC list). CSV data is in-memory only and lost on reload.

## Key Constants to Know

- `RECORDS_PER_PAGE = 50` — Pagination size
- `DEBOUNCE_MS = 250` — Search input debounce
- `KNOWN_MSFT_PREFIXES` — Array of ~50 Microsoft IP prefixes for auto-detection
- `FIELD_EXTRACTION` — Maps logical field names to arrays of fallback JSON paths in AuditData

## Modifying the App

- To add a new extracted field: add an entry to `FIELD_EXTRACTION` and update `processRecords` plus any relevant view components and the CSV export column list.
- To add a new view mode: add to the view selector buttons, add the grouping logic in `useMemo`, and add the rendering branch.
- To update Microsoft IP ranges: edit the `KNOWN_MSFT_PREFIXES` array.
- When editing `index.html`, note the JSX starts inside a `<script type="text/babel">` tag — the same code as the `.jsx` file but wrapped in HTML boilerplate.

## Other Files

- `libs/` — Vendored minified dependencies (React 18, ReactDOM, Babel Standalone, PapaParse, Recharts). These are checked in for offline/air-gapped use.
- `install.ps1` / `install.sh` — Download-and-open installer scripts for Windows/macOS/Linux.
- `404.html` — GitHub Pages SPA redirect.
- `test.html` — Dependency verification page (checks CDN connectivity).
