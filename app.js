const $ = selector => document.querySelector(selector);
const form = $('#form');
const input = $('#message');
const result = $('#result');
const history = $('#history');
const KEY = 'phishguard.history.v1';
input.addEventListener('input', () => $('#count').textContent = input.value.length);
const escapeHTML = value => { const node = document.createElement('span'); node.textContent = value; return node.innerHTML; };
function loadHistory() { try { return JSON.parse(localStorage.getItem(KEY) || '[]'); } catch { return []; } }
function extractUrls(text) {
  return [...new Set((text.match(/(?:https?:\/\/|www\.)[^\s<>"']+/gi) || [])
    .map(value => value.replace(/[),.;!?]+$/, ''))
    .map(value => value.startsWith('www.') ? 'https://' + value : value)
    .filter(value => { try { return ['http:', 'https:'].includes(new URL(value).protocol); } catch { return false; } }))].slice(0, 10);
}
function analyze(text) {
  let score = 0; const signals = []; const urls = extractUrls(text);
  const urgency = /\b(urgent|immediately|act now|within 24 hours|suspended|blocked|expire|final warning|verify now)\b/i;
  const credentials = /\b(password|passcode|one[- ]time code|otp|social security|ssn|credit card|bank details|login|sign in)\b/i;
  const threat = /\b(account.{0,20}(?:suspend|close|block)|unauthorized|unusual activity|payment failed)\b/i;
  const shortener = /\b(bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly|is\.gd|cutt\.ly)\b/i;
  if (!urls.length) signals.push('No web link was found; only wording clues can be checked.');
  for (const raw of urls) {
    let url; try { url = new URL(raw); } catch { score += 12; signals.push('A link could not be parsed cleanly. Check the address before opening it.'); continue; }
    const host = url.hostname.toLowerCase();
    if (url.protocol !== 'https:') { score += 12; signals.push('The link does not use HTTPS.'); }
    if (host.startsWith('xn--') || host.includes('.xn--')) { score += 28; signals.push('The address contains an internationalized domain that may disguise look-alike characters.'); }
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) { score += 25; signals.push('The link uses a raw IP address instead of a recognizable domain.'); }
    if (host.split('.').length >= 5) { score += 10; signals.push('The address has several subdomains; check which domain owns the site.'); }
    if (url.username || url.password) { score += 24; signals.push('Text before the @ sign may make the real destination harder to spot.'); }
    if (shortener.test(host)) { score += 18; signals.push('This shortened link hides its final destination.'); }
    const brand = ['paypal', 'microsoft', 'apple', 'google', 'amazon', 'netflix'].find(name => host.includes(name));
    if (brand && !host.endsWith(brand + '.com') && !host.endsWith(brand + '.co.uk')) { score += 25; signals.push('The domain mentions ' + brand + ' but does not appear to be its standard domain. Verify independently.'); }
    if (url.search.length > 100) { score += 5; signals.push('The URL has a long query string; it may contain tracking or personal data.'); }
  }
  if (urgency.test(text)) { score += 18; signals.push('The message pressures you to act quickly or threatens a consequence.'); }
  if (credentials.test(text)) { score += 20; signals.push('It mentions login or financial details. Never share passwords or one-time codes through a message link.'); }
  if (threat.test(text)) { score += 12; signals.push('It claims there is an account or payment problem, a common way to prompt a rushed click.'); }
  score = Math.min(99, score);
  if (urls.length && !signals.some(value => /link|address|domain|destination/i.test(value))) signals.push('No obvious URL warning was detected; this does not verify the site.');
  if (!signals.length) signals.push('No common warning phrase was detected. That does not establish that the message is genuine.');
  return { score, level: score >= 50 ? 'high' : score >= 25 ? 'medium' : 'low', signals };
}
function renderHistory() {
  const items = loadHistory();
  history.innerHTML = items.length ? items.map(item =>
    '<div class="row"><div style="min-width:0"><strong>' + escapeHTML(item.text.replace(/\s+/g, ' ').slice(0, 90)) +
    '</strong><small>' + escapeHTML(new Date(item.at).toLocaleString()) + ' · Score ' + item.score +
    '/99</small></div><span class="pill ' + item.level + '">' + item.level.toUpperCase() +
    ' RISK</span></div>').join('') :
    '<p style="color:#95a098;font-size:12px">Your checks will appear here on this device.</p>';
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
form.addEventListener('submit', async event => {
  event.preventDefault();
  const text = input.value.trim(); if (!text) return;
  const button = form.querySelector('button'); button.disabled = true; button.textContent = 'Checking…';
  const item = { text, ...analyze(text), at: Date.now() };
  let lookupMessage = '';
  try {
    const lookup = await checkThreatFeed(extractUrls(text));
    if (lookup.configured === false) lookupMessage = 'Live threat lookup is not configured. Showing local warning signs only.';
    else if (lookup.threats?.length) {
      item.score = Math.max(item.score, 90); item.level = 'high';
      const categories = [...new Set(lookup.threats.flatMap(threat => threat.threatTypes || []))];
      item.signals.unshift('Google Safe Browsing lists a URL in this message as a known threat' +
        (categories.length ? ' (' + categories.join(', ') + ')' : '') +
        '. Google cannot guarantee the reliability or accuracy of its information. Avoid opening it.');
      lookupMessage = 'Threat match provided by Google Safe Browsing.';
    } else if (lookup.configured) lookupMessage = 'Google Safe Browsing found no listed URL match. This does not prove the message is safe.';
  } catch {
    lookupMessage = 'Live threat lookup is unavailable. Showing local warning signs only.';
  } finally { button.disabled = false; button.textContent = 'Check for warning signs →'; }
  const rows = loadHistory(); rows.unshift(item); localStorage.setItem(KEY, JSON.stringify(rows.slice(0, 20)));
  const title = item.level === 'high' ? 'High risk signals' : item.level === 'medium' ? 'Some warning signs' : 'Few warning signs found';
  result.hidden = false; result.className = 'result ' + item.level;
  result.innerHTML = '<div class="result-head"><div><h2>' + title + '</h2><p>Heuristic estimate · not a safety verdict</p></div><div class="score">' +
    item.score + '<small>RISK / 99</small></div></div><div class="signals"><h3>WHAT STOOD OUT</h3>' +
    item.signals.map(signal => '<p class="signal">• ' + escapeHTML(signal) + '</p>').join('') +
    (lookupMessage ? '<p class="signal">' + escapeHTML(lookupMessage) + '</p>' : '') + '</div>';
  renderHistory(); result.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
});
$('#clear').addEventListener('click', () => { localStorage.removeItem(KEY); renderHistory(); });
renderHistory();
