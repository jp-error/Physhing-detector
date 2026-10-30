# Phishing Detector

PhishGuard is a browser-based phishing warning-sign checker. It combines explainable local heuristics with an optional Google Safe Browsing URL lookup.

## Features

- **Message and URL analysis:** flags common social-engineering language, suspicious URL structures, shortened links, raw IP hosts, look-alike internationalized domain labels, and brand-name/domain mismatches.
- **Optional URL reputation lookup:** submits extracted URLs (not the full message) to Google Safe Browsing when the server is configured with an API key.
- **Security dashboard:** summarizes checks, high-risk flags, and average heuristic score.
- **Local history:** keeps the latest 100 checks in the browser's local storage.
- **Exportable reports:** download an individual check or the local history as JSON.

## Requirements

- Node.js 20 or newer
- A Google Cloud project with the Google Safe Browsing API enabled and an API key for live lookups

## Run locally

PowerShell:

```powershell
$env:SAFE_BROWSING_API_KEY = "your-key"
npm start
```

Then open http://localhost:3000. To use local heuristic checks without the external lookup, omit the API key. Do not put a real key in source files or commit it.

## How checks work

The browser analyzes the message text and URL structure locally. It extracts up to 10 HTTP or HTTPS URLs and sends only those URLs to the app backend. The backend validates the URLs and, when configured, calls Google's Safe Browsing API. The API key stays in the server environment. The full message is not sent to Google.

The risk score is a heuristic indicator, not a probability or a definitive verdict. A URL not found in a threat feed is not necessarily safe, and a low score does not prove a message is genuine. The local dashboard and history are stored in the current browser and are not synchronized across devices. Clearing browser site data may remove them.

## Deployment and security control

Run `npm start` on a Node.js 20+ host and set `SAFE_BROWSING_API_KEY` in the host's secret/environment settings. Serve over HTTPS. Restrict the key in Google Cloud Console to the Safe Browsing API and set appropriate quotas. Do not commit `.env` files or expose this key to browser code.

Google Safe Browsing may receive submitted URLs. Its service is subject to Google's terms and usage requirements; review [Google Safe Browsing's terms](https://developers.google.com/safe-browsing/terms) before deployment, especially for commercial use.

## Current limitations

- Heuristic rules can produce false positives and false negatives.
- The optional threat lookup only reports matches returned by the configured provider.
- Domain ownership, registration age, sender identity, email authentication (SPF/DKIM/DMARC), and page contents are not independently verified.
- History is local to one browser; it is not a shared account or central database.
- Exported JSON reports contain the submitted message text. Store and share them carefully.
