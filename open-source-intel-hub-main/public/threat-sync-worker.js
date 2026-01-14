// Threat Intelligence Background Sync Service Worker
// This service worker enables background synchronization of threat data

const CACHE_NAME = 'threat-intel-v1';
const SYNC_TAG = 'threat-intelligence-sync';

// URLs to cache for offline functionality
const STATIC_ASSETS = [
  '/',
  '/index.html',
];

// Threat feed URLs to sync
const THREAT_FEED_URLS = [
  '/api/feodo/ipblocklist_recommended.json',
  '/api/urlhaus/json_recent/',
  '/api/threatfox/json/recent/',
  '/api/bazaar/txt/sha256/recent/'
];

// Install event - cache static assets
self.addEventListener('install', (event) => {
  console.log('[SW] Installing service worker...');
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => {
        console.log('[SW] Caching static assets');
        return cache.addAll(STATIC_ASSETS);
      })
      .then(() => self.skipWaiting())
  );
});

// Activate event - clean up old caches
self.addEventListener('activate', (event) => {
  console.log('[SW] Activating service worker...');
  event.waitUntil(
    caches.keys().then(cacheNames => {
      return Promise.all(
        cacheNames
          .filter(cacheName => cacheName !== CACHE_NAME)
          .map(cacheName => caches.delete(cacheName))
      );
    }).then(() => self.clients.claim())
  );
});

// Background sync event handler
self.addEventListener('sync', (event) => {
  console.log('[SW] Background sync triggered:', event.tag);
  
  if (event.tag === SYNC_TAG) {
    event.waitUntil(syncThreatData());
  }
});

// Periodic background sync (if supported)
self.addEventListener('periodicsync', (event) => {
  console.log('[SW] Periodic sync triggered:', event.tag);
  
  if (event.tag === 'threat-intel-periodic') {
    event.waitUntil(syncThreatData());
  }
});

// Sync threat data from all sources
async function syncThreatData() {
  console.log('[SW] Syncing threat intelligence data...');
  
  const results = {
    success: [],
    failed: []
  };

  for (const url of THREAT_FEED_URLS) {
    try {
      const response = await fetch(url, {
        method: 'GET',
        headers: {
          'Accept': 'application/json',
          'Cache-Control': 'no-cache'
        }
      });

      if (response.ok) {
        // Cache the response
        const cache = await caches.open(CACHE_NAME);
        await cache.put(url, response.clone());
        results.success.push(url);
        console.log(`[SW] Successfully synced: ${url}`);
      } else {
        results.failed.push({ url, status: response.status });
        console.warn(`[SW] Failed to sync ${url}: ${response.status}`);
      }
    } catch (error) {
      results.failed.push({ url, error: error.message });
      console.error(`[SW] Error syncing ${url}:`, error);
    }
  }

  // Notify all clients about the sync completion
  const clients = await self.clients.matchAll();
  clients.forEach(client => {
    client.postMessage({
      type: 'THREAT_SYNC_COMPLETE',
      results,
      timestamp: Date.now()
    });
  });

  console.log('[SW] Sync complete:', results);
  return results;
}

// Fetch event - serve from cache with network fallback
self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);
  
  // Handle threat feed API requests
  if (url.pathname.startsWith('/api/')) {
    event.respondWith(
      fetch(event.request)
        .then(response => {
          // Cache successful API responses
          if (response.ok) {
            const responseClone = response.clone();
            caches.open(CACHE_NAME).then(cache => {
              cache.put(event.request, responseClone);
            });
          }
          return response;
        })
        .catch(async () => {
          // Fallback to cache on network failure
          console.log('[SW] Network failed, serving from cache:', url.pathname);
          const cachedResponse = await caches.match(event.request);
          if (cachedResponse) {
            return cachedResponse;
          }
          // Return empty response if no cache
          return new Response(JSON.stringify({ error: 'Offline', cached: false }), {
            status: 503,
            headers: { 'Content-Type': 'application/json' }
          });
        })
    );
    return;
  }

  // Handle static assets
  event.respondWith(
    caches.match(event.request)
      .then(cachedResponse => {
        if (cachedResponse) {
          return cachedResponse;
        }
        return fetch(event.request);
      })
  );
});

// Message handler for manual sync triggers
self.addEventListener('message', (event) => {
  console.log('[SW] Message received:', event.data);
  
  if (event.data && event.data.type === 'TRIGGER_SYNC') {
    syncThreatData().then(results => {
      event.ports[0].postMessage({ type: 'SYNC_COMPLETE', results });
    });
  }
  
  if (event.data && event.data.type === 'SKIP_WAITING') {
    self.skipWaiting();
  }
});

// Push notification handler (for server-triggered updates)
self.addEventListener('push', (event) => {
  console.log('[SW] Push notification received');
  
  if (event.data) {
    const data = event.data.json();
    
    if (data.type === 'THREAT_ALERT') {
      event.waitUntil(
        self.registration.showNotification('Threat Intelligence Alert', {
          body: data.message || 'New threat indicators detected',
          icon: '/img/threat-icon.png',
          badge: '/img/badge-icon.png',
          tag: 'threat-alert',
          data: data
        })
      );
    }
  }
});

// Notification click handler
self.addEventListener('notificationclick', (event) => {
  console.log('[SW] Notification clicked');
  event.notification.close();
  
  event.waitUntil(
    self.clients.matchAll({ type: 'window' }).then(clients => {
      // Focus existing window or open new one
      for (const client of clients) {
        if (client.url.includes('/') && 'focus' in client) {
          return client.focus();
        }
      }
      if (self.clients.openWindow) {
        return self.clients.openWindow('/');
      }
    })
  );
});

console.log('[SW] Service worker script loaded');
