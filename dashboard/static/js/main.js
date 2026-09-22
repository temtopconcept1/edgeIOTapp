/**
 * dashboard/static/js/main.js
 * Small fetch wrapper used by every dashboard page. Centralizes:
 *   - sending credentials (session cookie) with every request,
 *   - JSON content-type headers,
 *   - redirecting to /login on session expiry (401),
 *   - basic handling of 403 (forbidden) and 429 (rate limited) responses.
 */
async function ssemsFetch(url, options = {}, returnErrorDetails = false) {
  const opts = Object.assign({
    headers: { 'Content-Type': 'application/json' },
    credentials: 'same-origin',
  }, options);

  let response;
  try {
    response = await fetch(url, opts);
  } catch (err) {
    console.error('Network error calling', url, err);
    return null;
  }

  if (response.status === 401) {
    window.location.href = '/login';
    return null;
  }

  if (!response.ok) {
    let data = null;
    try { data = await response.json(); } catch (e) { /* no body */ }
    if (response.status === 403) {
      console.warn('Forbidden:', url);
    } else if (response.status === 429) {
      console.warn('Rate limited:', url);
    } else {
      console.error('API error', response.status, url, data);
    }
    return returnErrorDetails ? { ok: false, status: response.status, data } : null;
  }

  const data = await response.json();
  return returnErrorDetails ? { ok: true, data } : data;
}
