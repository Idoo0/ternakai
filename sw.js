/* ═══════════════════════════════════════════════════════════
   TERNAKAI v4 — sw.js  (lives at repo root)
   Scope covers the entire site including /app/
═══════════════════════════════════════════════════════════ */
'use strict';

const CACHE  = 'ternakai-v4.1';
const SHELL  = [
  './app/index.html',
  './app/styles.css',
  './app/script.js',
  './manifest.json',
  './icon.svg',
  './icon-192.png',
  './icon-512.png',
  './apple-touch-icon.png',
];

/* ── Install ── */
self.addEventListener('install', e => {
  e.waitUntil(
    caches.open(CACHE)
      .then(c => c.addAll(SHELL).catch(() => {}))
      .finally(() => self.skipWaiting())
  );
});

/* ── Activate: purge old caches ── */
self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys()
      .then(keys => Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

/* ── Fetch strategy ── */
self.addEventListener('fetch', e => {
  const { request } = e;
  if (request.method !== 'GET') return;
  if (!request.url.startsWith('http')) return;

  // Never cache Anthropic API or RSS calls
  if (request.url.includes('api.anthropic.com') || request.url.includes('rss2json.com')) {
    e.respondWith(
      fetch(request).catch(() =>
        new Response(JSON.stringify({ error:'offline' }), {
          headers:{ 'Content-Type':'application/json' }
        })
      )
    );
    return;
  }

  // Cache-first for CDN (fonts, icons, lib JS)
  if (
    request.url.includes('fonts.googleapis.com') ||
    request.url.includes('fonts.gstatic.com')    ||
    request.url.includes('cdnjs.cloudflare.com') ||
    request.url.includes('cdn.jsdelivr.net')      ||
    request.url.includes('google.com/s2/favicons')
  ) {
    e.respondWith(
      caches.match(request).then(hit => {
        if (hit) return hit;
        return fetch(request).then(res => {
          if (res && res.status === 200) {
            caches.open(CACHE).then(c => c.put(request, res.clone()));
          }
          return res;
        }).catch(() => new Response('', { status:503 }));
      })
    );
    return;
  }

  // Stale-while-revalidate for same-origin (app shell)
  e.respondWith(
    caches.open(CACHE).then(cache =>
      cache.match(request).then(cached => {
        const fetched = fetch(request).then(res => {
          if (res && res.status === 200) cache.put(request, res.clone());
          return res;
        }).catch(() => null);
        return cached || fetched || caches.match('./app/index.html');
      })
    )
  );
});
