# Phishing Detector

A browser-based phishing checker that combines explainable local warning-sign rules with an optional Google Safe Browsing URL lookup.

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

The browser analyzes message text and URL structure locally. It extracts up to 10 HTTP or HTTPS URLs and sends only those URLs to the app backend. The backend validates them and, when configured, calls Google's Safe Browsing API. The API key stays in the server environment. The full email or message is not sent to Google. Recent checks are stored in the browser's local storage.

Google may receive URLs submitted for live checking. Google Safe Browsing is for non-commercial use unless you have a separate agreement. Its results may be inaccurate; a missing match is not proof that a message is safe. Review [Google Safe Browsing's terms](https://developers.google.com/safe-browsing/terms) before deployment.

## Deployment

Run `npm start` on a Node.js 20+ host and set `SAFE_BROWSING_API_KEY` in the host's secret/environment settings. Serve over HTTPS. Restrict the key in Google Cloud Console to the Safe Browsing API and set appropriate quotas. Do not commit `.env` files or expose this key to browser code.
