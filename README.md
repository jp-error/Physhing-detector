# Phishing Detector

A browser-based phishing message checker. Paste a suspicious URL, email, or text to see common warning signs and an explainable heuristic risk score.

## Run

Open [index.html](index.html) in a modern browser. This first version is a static page with no build step or server.

## What it does

- Checks URL structure and message wording for common warning signs.
- Explains the signals behind its heuristic score.
- Stores up to 20 recent checks in browser local storage.
- Keeps pasted text in the browser; no backend request is made.

## Current limits

This is an initial rule-based prototype, not a trained AI model. It does not visit submitted URLs, validate website ownership, or consult a live malicious-domain feed. A low score does not mean a message is safe. Production use would need a maintained threat-intelligence provider, an evaluated detection model, and a backend with explicit privacy and security controls.