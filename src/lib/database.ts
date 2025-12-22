// IndexedDB Database for OSINT data storage

import { IntelligenceRecord, Monitor, MonitoringAlert, ImportedDataset, BreachRecord } from '@/types/osint';

const DB_NAME = 'osint_platform';
const DB_VERSION = 1;

let db: IDBDatabase | null = null;

export async function initDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    if (db) {
      resolve(db);
      return;
    }

    const request = indexedDB.open(DB_NAME, DB_VERSION);

    request.onerror = () => reject(request.error);

    request.onsuccess = () => {
      db = request.result;
      resolve(db);
    };

    request.onupgradeneeded = (event) => {
      const database = (event.target as IDBOpenDBRequest).result;

      // Intelligence Records
      if (!database.objectStoreNames.contains('records')) {
        const recordStore = database.createObjectStore('records', { keyPath: 'id' });
        recordStore.createIndex('target', 'target', { unique: false });
        recordStore.createIndex('type', 'type', { unique: false });
        recordStore.createIndex('timestamp', 'timestamp', { unique: false });
        recordStore.createIndex('threatLevel', 'threatLevel', { unique: false });
      }

      // Monitors
      if (!database.objectStoreNames.contains('monitors')) {
        const monitorStore = database.createObjectStore('monitors', { keyPath: 'id' });
        monitorStore.createIndex('target', 'target', { unique: false });
        monitorStore.createIndex('status', 'status', { unique: false });
      }

      // Alerts
      if (!database.objectStoreNames.contains('alerts')) {
        const alertStore = database.createObjectStore('alerts', { keyPath: 'id' });
        alertStore.createIndex('monitorId', 'monitorId', { unique: false });
        alertStore.createIndex('timestamp', 'timestamp', { unique: false });
        alertStore.createIndex('read', 'read', { unique: false });
        alertStore.createIndex('severity', 'severity', { unique: false });
      }

      // Breach Data
      if (!database.objectStoreNames.contains('breaches')) {
        const breachStore = database.createObjectStore('breaches', { keyPath: 'id' });
        breachStore.createIndex('email', 'email', { unique: false });
        breachStore.createIndex('source', 'source', { unique: false });
      }

      // Imported Datasets
      if (!database.objectStoreNames.contains('datasets')) {
        database.createObjectStore('datasets', { keyPath: 'id' });
      }

      // API Cache
      if (!database.objectStoreNames.contains('cache')) {
        const cacheStore = database.createObjectStore('cache', { keyPath: 'key' });
        cacheStore.createIndex('expiresAt', 'expiresAt', { unique: false });
      }

      // Activity Log
      if (!database.objectStoreNames.contains('activity')) {
        const activityStore = database.createObjectStore('activity', { keyPath: 'id' });
        activityStore.createIndex('timestamp', 'timestamp', { unique: false });
      }
    };
  });
}

// Generic CRUD operations
async function getStore(storeName: string, mode: IDBTransactionMode = 'readonly'): Promise<IDBObjectStore> {
  const database = await initDatabase();
  const transaction = database.transaction(storeName, mode);
  return transaction.objectStore(storeName);
}

// Intelligence Records
export async function saveRecord(record: IntelligenceRecord): Promise<void> {
  const store = await getStore('records', 'readwrite');
  return new Promise((resolve, reject) => {
    const request = store.put(record);
    request.onsuccess = () => resolve();
    request.onerror = () => reject(request.error);
  });
}

export async function getRecords(limit = 100): Promise<IntelligenceRecord[]> {
  const store = await getStore('records');
  return new Promise((resolve, reject) => {
    const request = store.index('timestamp').openCursor(null, 'prev');
    const results: IntelligenceRecord[] = [];
    
    request.onsuccess = (event) => {
      const cursor = (event.target as IDBRequest<IDBCursorWithValue>).result;
      if (cursor && results.length < limit) {
        results.push(cursor.value);
        cursor.continue();
      } else {
        resolve(results);
      }
    };
    request.onerror = () => reject(request.error);
  });
}

export async function searchRecords(query: string): Promise<IntelligenceRecord[]> {
  const store = await getStore('records');
  return new Promise((resolve, reject) => {
    const request = store.getAll();
    request.onsuccess = () => {
      const results = request.result.filter((record: IntelligenceRecord) =>
        record.target.toLowerCase().includes(query.toLowerCase()) ||
        JSON.stringify(record.data).toLowerCase().includes(query.toLowerCase())
      );
      resolve(results);
    };
    request.onerror = () => reject(request.error);
  });
}

export async function getRecordCount(): Promise<number> {
  const store = await getStore('records');
  return new Promise((resolve, reject) => {
    const request = store.count();
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

// Monitors
export async function saveMonitor(monitor: Monitor): Promise<void> {
  const store = await getStore('monitors', 'readwrite');
  return new Promise((resolve, reject) => {
    const request = store.put(monitor);
    request.onsuccess = () => resolve();
    request.onerror = () => reject(request.error);
  });
}

export async function getMonitors(): Promise<Monitor[]> {
  const store = await getStore('monitors');
  return new Promise((resolve, reject) => {
    const request = store.getAll();
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

export async function getActiveMonitorCount(): Promise<number> {
  const store = await getStore('monitors');
  return new Promise((resolve, reject) => {
    const request = store.index('status').count(IDBKeyRange.only('active'));
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

export async function deleteMonitor(id: string): Promise<void> {
  const store = await getStore('monitors', 'readwrite');
  return new Promise((resolve, reject) => {
    const request = store.delete(id);
    request.onsuccess = () => resolve();
    request.onerror = () => reject(request.error);
  });
}

// Alerts
export async function saveAlert(alert: MonitoringAlert): Promise<void> {
  const store = await getStore('alerts', 'readwrite');
  return new Promise((resolve, reject) => {
    const request = store.put(alert);
    request.onsuccess = () => resolve();
    request.onerror = () => reject(request.error);
  });
}

export async function getAlerts(limit = 50): Promise<MonitoringAlert[]> {
  const store = await getStore('alerts');
  return new Promise((resolve, reject) => {
    const request = store.index('timestamp').openCursor(null, 'prev');
    const results: MonitoringAlert[] = [];
    
    request.onsuccess = (event) => {
      const cursor = (event.target as IDBRequest<IDBCursorWithValue>).result;
      if (cursor && results.length < limit) {
        results.push(cursor.value);
        cursor.continue();
      } else {
        resolve(results);
      }
    };
    request.onerror = () => reject(request.error);
  });
}

export async function getUnreadAlertCount(): Promise<number> {
  const store = await getStore('alerts');
  return new Promise((resolve, reject) => {
    const request = store.index('read').count(IDBKeyRange.only(false));
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

export async function getAlertsToday(): Promise<number> {
  const store = await getStore('alerts');
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  
  return new Promise((resolve, reject) => {
    const request = store.index('timestamp').count(IDBKeyRange.lowerBound(today));
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

export async function markAlertRead(id: string): Promise<void> {
  const store = await getStore('alerts', 'readwrite');
  return new Promise((resolve, reject) => {
    const getRequest = store.get(id);
    getRequest.onsuccess = () => {
      const alert = getRequest.result;
      if (alert) {
        alert.read = true;
        const putRequest = store.put(alert);
        putRequest.onsuccess = () => resolve();
        putRequest.onerror = () => reject(putRequest.error);
      } else {
        resolve();
      }
    };
    getRequest.onerror = () => reject(getRequest.error);
  });
}

// Breach Data
export async function importBreaches(breaches: BreachRecord[]): Promise<void> {
  const store = await getStore('breaches', 'readwrite');
  return new Promise((resolve, reject) => {
    let completed = 0;
    breaches.forEach((breach) => {
      const request = store.put(breach);
      request.onsuccess = () => {
        completed++;
        if (completed === breaches.length) resolve();
      };
      request.onerror = () => reject(request.error);
    });
    if (breaches.length === 0) resolve();
  });
}

export async function searchBreaches(email: string): Promise<BreachRecord[]> {
  const store = await getStore('breaches');
  return new Promise((resolve, reject) => {
    const request = store.index('email').getAll(IDBKeyRange.only(email.toLowerCase()));
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

export async function getBreachCount(): Promise<number> {
  const store = await getStore('breaches');
  return new Promise((resolve, reject) => {
    const request = store.count();
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

// Datasets
export async function saveDataset(dataset: ImportedDataset): Promise<void> {
  const store = await getStore('datasets', 'readwrite');
  return new Promise((resolve, reject) => {
    const request = store.put(dataset);
    request.onsuccess = () => resolve();
    request.onerror = () => reject(request.error);
  });
}

export async function getDatasets(): Promise<ImportedDataset[]> {
  const store = await getStore('datasets');
  return new Promise((resolve, reject) => {
    const request = store.getAll();
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

// Cache
export async function cacheAPIResponse(key: string, data: any, ttlMinutes: number): Promise<void> {
  const store = await getStore('cache', 'readwrite');
  const expiresAt = new Date(Date.now() + ttlMinutes * 60 * 1000);
  return new Promise((resolve, reject) => {
    const request = store.put({ key, data, expiresAt, cachedAt: new Date() });
    request.onsuccess = () => resolve();
    request.onerror = () => reject(request.error);
  });
}

export async function getCachedData(key: string): Promise<any | null> {
  const store = await getStore('cache');
  return new Promise((resolve, reject) => {
    const request = store.get(key);
    request.onsuccess = () => {
      const result = request.result;
      if (result && new Date(result.expiresAt) > new Date()) {
        resolve(result.data);
      } else {
        resolve(null);
      }
    };
    request.onerror = () => reject(request.error);
  });
}

// Activity Log
export async function logActivity(activity: { type: string; title: string; description: string }): Promise<void> {
  const store = await getStore('activity', 'readwrite');
  return new Promise((resolve, reject) => {
    const request = store.put({
      id: crypto.randomUUID(),
      ...activity,
      timestamp: new Date(),
    });
    request.onsuccess = () => resolve();
    request.onerror = () => reject(request.error);
  });
}

export async function getRecentActivity(limit = 20): Promise<any[]> {
  const store = await getStore('activity');
  return new Promise((resolve, reject) => {
    const request = store.index('timestamp').openCursor(null, 'prev');
    const results: any[] = [];
    
    request.onsuccess = (event) => {
      const cursor = (event.target as IDBRequest<IDBCursorWithValue>).result;
      if (cursor && results.length < limit) {
        results.push(cursor.value);
        cursor.continue();
      } else {
        resolve(results);
      }
    };
    request.onerror = () => reject(request.error);
  });
}

// Cleanup
export async function clearAllData(): Promise<void> {
  const database = await initDatabase();
  const storeNames = Array.from(database.objectStoreNames);
  
  return new Promise((resolve, reject) => {
    const transaction = database.transaction(storeNames, 'readwrite');
    storeNames.forEach((storeName) => {
      transaction.objectStore(storeName).clear();
    });
    transaction.oncomplete = () => resolve();
    transaction.onerror = () => reject(transaction.error);
  });
}
