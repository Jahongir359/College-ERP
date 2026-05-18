/* ============================================================
   ICEBERG LC — Service Worker
   Strategy:
     • Static assets  → Cache-first (CSS, JS, images, fonts)
     • HTML pages     → Network-first → offline.html fallback
     • AJAX / API     → Network-only (never cache dynamic data)
   ============================================================ */

const CACHE_VERSION = 'v1';
const STATIC_CACHE  = 'iceberg-static-' + CACHE_VERSION;
const PAGE_CACHE    = 'iceberg-pages-'  + CACHE_VERSION;

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

/* ── Activate: delete stale caches ───────────────────────── */
self.addEventListener('activate', event => {
  const KEEP = [STATIC_CACHE, PAGE_CACHE];
  event.waitUntil(
    caches.keys()
      .then(keys => Promise.all(
        keys.filter(k => !KEEP.includes(k)).map(k => caches.delete(k))
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

  /* Never cache: AJAX, API, admin, media uploads */
  const skipPaths = ['/api/', '/ajax/', '/admin/', '/media/', '/accounts/'];
  if (skipPaths.some(p => url.pathname.startsWith(p))) return;
  if (request.headers.get('X-Requested-With') === 'XMLHttpRequest') return;

  /* Static assets → cache-first */
  if (isStaticAsset(url.pathname)) {
    event.respondWith(cacheFirst(request, STATIC_CACHE));
    return;
  }

  /* HTML navigation → network-first */
  if (request.mode === 'navigate') {
    event.respondWith(networkFirstWithOffline(request));
    return;
  }
});

/* ── Helpers ──────────────────────────────────────────────── */
function isStaticAsset(path) {
  return path.startsWith('/static/') ||
    /\.(css|js|woff2?|ttf|eot|svg|png|jpg|jpeg|gif|webp|ico)$/.test(path);
}

async function cacheFirst(request, cacheName) {
  const cached = await caches.match(request);
  if (cached) return cached;
  const response = await fetch(request);
  if (response.ok) {
    const cache = await caches.open(cacheName);
    cache.put(request, response.clone());
  }
  return response;
}

async function networkFirstWithOffline(request) {
  try {
    const response = await fetch(request);
    /* Cache successful page responses for offline use */
    if (response.ok) {
      const cache = await caches.open(PAGE_CACHE);
      cache.put(request, response.clone());
    }
    return response;
  } catch {
    /* Try the cache first, then show the offline page */
    const cached = await caches.match(request);
    if (cached) return cached;
    return caches.match('/offline.html');
  }
}
