import http from 'node:http';
import { readFile } from 'node:fs/promises';
import { extname, join, normalize } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('.', import.meta.url));
const PORT = Number(process.env.PORT || 3000);
const API_KEY = process.env.SAFE_BROWSING_API_KEY;
const MAX_BODY = 12_000;
const MIME = { '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.json': 'application/json; charset=utf-8' };

function send(res, status, body) {
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
  res.end(JSON.stringify(body));
}
async function readJson(req) {
  let raw = '';
  for await (const chunk of req) {
    raw += chunk;
    if (raw.length > MAX_BODY) throw Object.assign(new Error('Request body too large'), { status: 413 });
  }
  try { return JSON.parse(raw || '{}'); } catch { throw Object.assign(new Error('Invalid JSON'), { status: 400 }); }
}
async function handleCheck(req, res) {
  if (!API_KEY) return send(res, 200, { configured: false, threats: [] });
  let body;
  try { body = await readJson(req); } catch (error) { return send(res, error.status || 400, { error: error.message }); }
  if (!Array.isArray(body.urls) || body.urls.length > 10) return send(res, 400, { error: 'Provide up to 10 URLs.' });
  const urls = [...new Set(body.urls.map(value => {
    if (typeof value !== 'string' || value.length > 2048) return null;
    try {
      const url = new URL(value);
      return ['http:', 'https:'].includes(url.protocol) ? url.href : null;
    } catch { return null; }
  }).filter(Boolean))];
  if (!urls.length) return send(res, 200, { configured: true, checkedCount: 0, threats: [] });
  const endpoint = new URL('https://safebrowsing.googleapis.com/v5/urls:search');
  endpoint.searchParams.set('key', API_KEY);
  for (const url of urls) endpoint.searchParams.append('urls', url);
  try {
    const upstream = await fetch(endpoint, { signal: AbortSignal.timeout(8000) });
    if (!upstream.ok) {
      const status = upstream.status === 429 ? 503 : 502;
      return send(res, status, { error: 'Threat lookup is temporarily unavailable.' });
    }
    const data = await upstream.json();
    return send(res, 200, {
      configured: true,
      checkedCount: urls.length,
      threats: Array.isArray(data.threats) ? data.threats.map(item => ({
        url: typeof item.url === 'string' ? item.url : '',
        threatTypes: Array.isArray(item.threatTypes) ? item.threatTypes : []
      })) : []
    });
  } catch {
    return send(res, 502, { error: 'Could not reach the threat lookup service.' });
  }
}
const server = http.createServer(async (req, res) => {
  const pathname = new URL(req.url, 'http://localhost').pathname;
  if (req.method === 'GET' && pathname === '/api/status') return send(res, 200, { configured: Boolean(API_KEY) });
  if (req.method === 'POST' && pathname === '/api/check') return handleCheck(req, res);
  if (req.method !== 'GET' && req.method !== 'HEAD') return send(res, 405, { error: 'Method not allowed.' });
  const requested = pathname === '/' ? 'index.html' : decodeURIComponent(pathname).replace(/^\/+/, '');
  const filename = normalize(join(ROOT, requested));
  if (!filename.startsWith(ROOT)) { res.writeHead(403); return res.end('Forbidden'); }
  try {
    const data = await readFile(filename);
    res.writeHead(200, { 'content-type': MIME[extname(filename)] || 'application/octet-stream', 'x-content-type-options': 'nosniff', 'content-security-policy': "default-src 'self' https://fonts.googleapis.com https://fonts.gstatic.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; script-src 'self' 'unsafe-inline'; connect-src 'self'" });
    res.end(req.method === 'HEAD' ? undefined : data);
  } catch { res.writeHead(404); res.end('Not found'); }
});
server.listen(PORT, () => console.log(`PhishGuard running at http://localhost:${PORT}`));
