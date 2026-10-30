const $ = selector => document.querySelector(selector);
const form = $('#form');
const input = $('#message');
const result = $('#result');
const history = $('#history');
const KEY = 'phishguard.history.v1';
let latestItem = null;

input.addEventListener('input', () => $('#count').textContent = input.value.length);
const escapeHTML = value => { const node = document.createElement('span'); node.textContent = String(value); return node.innerHTML; };
function loadHistory() {
  try {
    const value = JSON.parse(localStorage.getItem(KEY) || '[]');
    return Array.isArray(value) ? value.filter(item => item && typeof item.text === 'string' && Number.isFinite(item.score)) : [];
  } catch { return []; }
}
function saveHistory(items) { localStorage.setItem(KEY, JSON.stringify(items.slice(0, 100))); }
function extractUrls(text) {
  return [...new Set((text.match(/(?:https?:\/\/|www\.)[^\s<>"']+/gi) || [])
    .map(value => value.replace(/[),.;!?]+$/, ''))
    .map(value => value.startsWith('www.') ? 'https://' + value : value)
    .filter(value => { try { return ['http:', 'https:'].includes(new URL(value).protocol); } catch { return false; } }))].slice(0, 10);
}
function analyze(text) {
  let score = 0;
  const signals = [];
  const urls = extractUrls(text);
  const add = (points, message) => { score += points; signals.push(message); };
  const urgency = /\b(urgent|immediately|act now|within 24 hours|suspended|blocked|expire|final warning|verify now|limited time)\b/i;
  const credentials = /\b(password|passcode|one[- ]time code|otp|social security|ssn|credit card|bank details|login|sign in|recovery phrase)\b/i;
  const threat = /\b(account.{0,20}(?:suspend|close|block)|unauthorized|unusual activity|payment failed|delivery failed)\b/i;
  const shortener = /\b(bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly|is\.gd|cutt\.ly|rb\.gy|shorturl\.at)\b/i;
  if (!urls.length) signals.push('No web link was found; only message wording can be assessed.');
  for (const raw of urls) {
    let url;
    try { url = new URL(raw); } catch { add(12, 'A link could not be parsed cleanly.'); continue; }
    const host = url.hostname.toLowerCase();
    const labels = host.split('.');
    if (url.protocol !== 'https:') add(12, 'The link does not use HTTPS. HTTPS is not proof that a site is legitimate.');
    if (host.startsWith('xn--') || host.includes('.xn--')) add(28, 'The address contains an internationalized domain label that may disguise look-alike characters.');
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) add(25, 'The link uses a raw IP address instead of a recognizable domain.');
    if (labels.length >= 5) add(10, 'The address has several subdomains; check the registered domain carefully.');
    if (url.username || url.password) add(24, 'The URL contains user-info before the @ sign, which can obscure its real destination.');
    if (shortener.test(host)) add(18, 'This shortened link hides its final destination.');
    if (labels.length > 1 && /^(zip|mov|top|click|work|country|gq|tk)$/i.test(labels.at(-1))) add(10, 'The domain uses a top-level domain that is sometimes abused. This alone does not mean it is malicious.');
    if (host.length > 55) add(8, 'The hostname is unusually long.');
    if (url.search.length > 100) add(5, 'The URL has a long query string that may contain tracking or personal data.');
    const brand = ['paypal', 'microsoft', 'apple', 'google', 'amazon', 'netflix', ' instagram', 'facebook'].map(v => v.trim()).find(name => host.includes(name));
    const official = { paypal: ['paypal.com'], microsoft: ['microsoft.com','live.com','office.com'], apple: ['apple.com','icloud.com'], google: ['google.com','youtube.com'], amazon: ['amazon.com','amazon.in'], netflix: ['netflix.com'], instagram: ['instagram.com'], facebook: ['facebook.com','fb.com'] };
    if (brand && !official[brand].some(domain => host === domain || host.endsWith('.' + domain))) add(25, 'The hostname mentions ' + brand + ' but is not on a commonly used official domain. Verify through the official app or website.');
  }
  if (urgency.test(text)) add(18, 'The message pressures you to act quickly or threatens a consequence.');
  if (credentials.test(text)) add(20, 'It asks about login, recovery, or financial information. Do not share passwords or one-time codes through message links.');
  if (threat.test(text)) add(12, 'It claims there is an account, delivery, or payment problem, which can pressure people into rushed clicks.');
  if (/\b(gift card|claim your prize|you have won|free reward|lottery)\b/i.test(text)) add(12, 'It uses prize or reward language that can be used in scams.');
  score = Math.min(99, score);
  if (urls.length && !signals.some(value => /link|address|domain|hostname|URL|shortened/i.test(value))) signals.push('No common URL warning was detected; this does not verify the site.');
  if (!signals.length) signals.push('No common warning phrase was detected. That does not establish that the message is genuine.');
  return { score, level: score >= 50 ? 'high' : score >= 25 ? 'medium' : 'low', signals, urls };
}
function renderHistory() {
  const items = loadHistory();
  const counts = { high: 0, medium: 0, low: 0 };
  items.forEach(item => { if (counts[item.level] !== undefined) counts[item.level]++; });
  $('#totalChecks').textContent = items.length;
  $('#highChecks').textContent = counts.high;
  $('#averageScore').textContent = items.length ? Math.round(items.reduce((sum, item) => sum + item.score, 0) / items.length) : '—';
  $('#history').innerHTML = items.length ? items.slice(0, 12).map(item =>
    '<div class="row"><div style="min-width:0"><strong>' + escapeHTML(item.text.replace(/\s+/g, ' ').slice(0, 90)) +
    '</strong><small>' + escapeHTML(new Date(item.at).toLocaleString()) + ' · Score ' + item.score +
    '/99 · ' + (item.urls?.length || 0) + ' URL(s)</small></div><span class="pill ' + escapeHTML(item.level) + '">' + escapeHTML(item.level.toUpperCase()) +
    '</span></div>').join('') : '<p class="empty">Your checks will appear here on this device.</p>';
}
async function checkThreatFeed(urls) {
  if (!urls.length) return { configured: null, threats: [] };
  const response = await fetch('/api/check', {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ urls })
  });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || 'Threat lookup failed.');
  return data;
}
function showResult(item, lookupMessage) {
  const title = item.level === 'high' ? 'High risk signals' : item.level === 'medium' ? 'Some warning signs' : 'Few warning signs found';
  result.hidden = false;
  result.className = 'result ' + item.level;
  result.innerHTML = '<div class="result-head"><div><h2>' + title + '</h2><p>Heuristic estimate · not a safety verdict</p></div><div class="score">' +
    item.score + '<small>RISK / 99</small></div></div><div class="signals"><h3>WHAT STOOD OUT</h3>' +
    item.signals.map(signal => '<p class="signal">• ' + escapeHTML(signal) + '</p>').join('') +
    (item.urls.length ? '<h3>URL REPUTATION</h3><p class="signal">' + (item.threatMatch ? 'A submitted URL matched a known threat list. Avoid opening it.' : 'No submitted URL was returned as a known threat by the configured feed. A missing match is not proof of safety.') + '</p>' : '') +
    (lookupMessage ? '<p class="signal">' + escapeHTML(lookupMessage) + '</p>' : '') +
    '<div class="result-actions"><button class="button secondary" id="exportLatest" type="button">Export this report ↓</button></div></div>';
  $('#exportLatest').addEventListener('click', () => exportReport(item));
}
function exportReport(item) {
  const report = {
    product: 'PhishGuard', generatedAt: new Date().toISOString(),
    disclaimer: 'This is an informational heuristic assessment, not a guarantee or professional security verdict.',
    score: item.score, riskLevel: item.level, message: item.text,
    urls: item.urls || [], signals: item.signals, threatFeedMatch: Boolean(item.threatMatch)
  };
  const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
  const link = document.createElement('a');
  link.href = URL.createObjectURL(blob);
  link.download = 'phishguard-report-' + new Date().toISOString().slice(0, 10) + '.json';
  link.click();
  URL.revokeObjectURL(link.href);
}
form.addEventListener('submit', async event => {
  event.preventDefault();
  const text = input.value.trim();
  if (!text) return;
  const button = form.querySelector('button');
  button.disabled = true;
  button.textContent = 'Checking…';
  const item = { text, ...analyze(text), at: Date.now(), threatMatch: false };
  let lookupMessage = '';
  try {
    const lookup = await checkThreatFeed(item.urls);
    if (lookup.configured === false) lookupMessage = 'Live URL reputation lookup is not configured. Showing local warning signs only.';
    else if (lookup.threats?.length) {
      item.threatMatch = true;
      item.score = Math.max(item.score, 90);
      item.level = 'high';
      const categories = [...new Set(lookup.threats.flatMap(threat => threat.threatTypes || []))];
      item.signals.unshift('Google Safe Browsing returned a known threat match' +
        (categories.length ? ' (' + categories.join(', ') + ')' : '') + '. Avoid opening the URL.');
      lookupMessage = 'Known-threat match provided by Google Safe Browsing.';
    } else if (lookup.configured) lookupMessage = 'No known-threat match was returned by Google Safe Browsing. This does not prove the URL is safe.';
  } catch {
    lookupMessage = 'Live URL reputation lookup is unavailable. Showing local warning signs only.';
  } finally {
    button.disabled = false;
    button.textContent = 'Check for warning signs →';
  }
  latestItem = item;
  const rows = loadHistory();
  rows.unshift(item);
  saveHistory(rows);
  showResult(item, lookupMessage);
  renderHistory();
  result.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
});
$('#clear').addEventListener('click', () => {
  if (!confirm('Clear all PhishGuard checks saved in this browser?')) return;
  localStorage.removeItem(KEY);
  renderHistory();
});
$('#exportHistory').addEventListener('click', () => {
  const items = loadHistory();
  const blob = new Blob([JSON.stringify({ product: 'PhishGuard', exportedAt: new Date().toISOString(), checks: items }, null, 2)], { type: 'application/json' });
  const link = document.createElement('a');
  link.href = URL.createObjectURL(blob);
  link.download = 'phishguard-history-' + new Date().toISOString().slice(0, 10) + '.json';
  link.click();
  URL.revokeObjectURL(link.href);
});
renderHistory();
