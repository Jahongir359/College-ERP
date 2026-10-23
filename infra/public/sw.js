/* ============================================================
   ICEBERG LC — Service Worker
   Strategy:
     • Static assets  → Cache-first (CSS, JS, images, fonts)
     • HTML pages     → Network-only, offline.html if network fails
     • AJAX / API     → Network-only (never cache dynamic data)

   HTML pages are NEVER cached because they contain per-session
   CSRF tokens. Caching them would cause 403 Forbidden errors
   on form submissions.
   ============================================================ */

const CACHE_VERSION = 'v2';
const STATIC_CACHE  = 'iceberg-static-' + CACHE_VERSION;

/* Assets to precache on install */
const PRECACHE = [
  '/offline.html',
  '/favicon.ico',
  '/android-chrome-192x192.png',
  '/android-chrome-512x512.png',
];

/* ── Install ──────────────────────────────────────────────── */
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(STATIC_CACHE)
      .then(cache => cache.addAll(PRECACHE))
      .then(() => self.skipWaiting())
  );
});

/* ── Activate: delete all old caches ─────────────────────── */
self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys()
      .then(keys => Promise.all(
        keys.filter(k => k !== STATIC_CACHE).map(k => caches.delete(k))
      ))
      .then(() => self.clients.claim())
  );
});

/* ── Fetch ────────────────────────────────────────────────── */
self.addEventListener('fetch', event => {
  const { request } = event;
  const url = new URL(request.url);

  /* Only handle same-origin GETs */
  if (url.origin !== self.location.origin) return;
  if (request.method !== 'GET') return;

  /* Static assets only → cache-first */
  if (isStaticAsset(url.pathname)) {
    event.respondWith(cacheFirst(request));
    return;
  }

  /* HTML navigation → always network, show offline page if down */
  if (request.mode === 'navigate') {
    event.respondWith(
      fetch(request).catch(() => caches.match('/offline.html'))
    );
    return;
  }
});

/* ── Helpers ──────────────────────────────────────────────── */
function isStaticAsset(path) {
  return path.startsWith('/static/') ||
    /\.(css|js|woff2?|ttf|eot|svg|png|jpg|jpeg|gif|webp|ico)$/.test(path);
}

async function cacheFirst(request) {
  const cached = await caches.match(request);
  if (cached) return cached;
  const response = await fetch(request);
  if (response.ok) {
    const cache = await caches.open(STATIC_CACHE);
    cache.put(request, response.clone());
  }
  return response;
}
