/* ═══════════════════════════════════════════════════════════
   TERNAKAI — Service Worker v4
   Strategy: Cache-first for static assets, network-first for API
═══════════════════════════════════════════════════════════ */
'use strict';

const CACHE_NAME   = 'ternakai-v4.0';
const OFFLINE_PAGE = 'index.html';

const PRECACHE_ASSETS = [
  'index.html',
  'manifest.json',
  'icon.svg',
  // CDN assets cached at runtime on first request
];

/* ── Install: pre-cache shell ── */
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => cache.addAll(PRECACHE_ASSETS))
      .catch(() => { /* graceful: some assets may not exist yet */ })
      .finally(() => self.skipWaiting())
  );
});

/* ── Activate: purge old caches ── */
self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys()
      .then(keys => Promise.all(
        keys
          .filter(k => k !== CACHE_NAME)
          .map(k => caches.delete(k))
      ))
      .then(() => self.clients.claim())
  );
});

/* ── Fetch: stale-while-revalidate for same-origin, cache-first for CDN ── */
self.addEventListener('fetch', event => {
  const { request } = event;

  // Only handle GET requests
  if (request.method !== 'GET') return;

  // Skip chrome-extension, data, and non-http(s) schemes
  if (!request.url.startsWith('http')) return;

  // Network-first for Anthropic API (never cache sensitive calls)
  if (request.url.includes('api.anthropic.com') || request.url.includes('rss2json.com')) {
    event.respondWith(
      fetch(request).catch(() =>
        new Response(JSON.stringify({ error: 'offline' }), {
          headers: { 'Content-Type': 'application/json' }
        })
      )
    );
    return;
  }

  // Cache-first for CDN (fonts, icons, libs)
  if (
    request.url.includes('fonts.googleapis.com') ||
    request.url.includes('fonts.gstatic.com')    ||
    request.url.includes('cdnjs.cloudflare.com') ||
    request.url.includes('cdn.jsdelivr.net')      ||
    request.url.includes('www.google.com/s2/favicons')
  ) {
    event.respondWith(
      caches.match(request).then(cached => {
        if (cached) return cached;
        return fetch(request).then(response => {
          if (!response || response.status !== 200) return response;
          const clone = response.clone();
          caches.open(CACHE_NAME).then(c => c.put(request, clone));
          return response;
        }).catch(() => cached || new Response('', { status: 503 }));
      })
    );
    return;
  }

  // Stale-while-revalidate for same-origin assets
  event.respondWith(
    caches.open(CACHE_NAME).then(cache =>
      cache.match(request).then(cached => {
        const fetchPromise = fetch(request).then(response => {
          if (response && response.status === 200) {
            cache.put(request, response.clone());
          }
          return response;
        }).catch(() => null);

        return cached || fetchPromise || caches.match(OFFLINE_PAGE);
      })
    )
  );
});
