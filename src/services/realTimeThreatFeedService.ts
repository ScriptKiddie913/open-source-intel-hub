// ============================================================================
// realTimeThreatFeedService.ts
// REAL-TIME THREAT INTELLIGENCE FEED SERVICE
// ============================================================================
// ✔ Multiple free threat intelligence endpoints
// ✔ Background data synchronization
// ✔ Service Worker support for offline updates
// ✔ Real-time graph data generation
// ============================================================================

import { cacheAPIResponse, getCachedData } from '@/lib/database';

/* ============================================================================
   TYPES
============================================================================ */

export interface ThreatDataPoint {
  timestamp: string;
  date: string;
  hour: number;
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  bySource: Record<string, number>;
  byType: Record<string, number>;
}

export interface RealTimeThreatStats {
  totalThreats: number;
  activeC2Servers: number;
  maliciousUrls: number;
  malwareSamples: number;
  recentMalware: number;
  criticalThreats: number;
  highThreats: number;
  mediumThreats: number;
  lowThreats: number;
  phishingUrls: number;
  sslCertificates: number;
  lastUpdated: string;
  updateCount: number;
}

export interface ThreatTrendData {
  trends: ThreatDataPoint[];
  typeDistribution: { name: string; value: number; color: string }[];
  sourceDistribution: { name: string; value: number; color: string }[];
  severityDistribution: { name: string; value: number; color: string }[];
  malwareFamilies: { name: string; count: number; trend: 'up' | 'down' | 'stable' }[];
  countryDistribution: { country: string; code: string; count: number }[];
}

export interface LiveFeedEntry {
  id: string;
  type: 'c2' | 'url' | 'hash' | 'ip' | 'domain';
  value: string;
  source: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  malwareFamily?: string;
  country?: string;
  timestamp: string;
  tags: string[];
}

/* ============================================================================
   CONSTANTS
============================================================================ */

const CACHE_KEYS = {
  THREAT_STATS: 'realtime_threat_stats',
  TREND_DATA: 'realtime_trend_data',
  LIVE_FEED: 'realtime_live_feed',
  LAST_SYNC: 'realtime_last_sync',
  SSL_BLACKLIST: 'realtime_ssl_blacklist',
  PHISHING_URLS: 'realtime_phishing_urls'
};

const CACHE_TTL = 60000; // 1 minute cache for real-time data
const SYNC_INTERVAL = 30000; // 30 seconds sync interval

// Color palette for charts
const COLORS = {
  critical: '#dc2626',
  high: '#ea580c',
  medium: '#ca8a04',
  low: '#16a34a',
  sources: ['#3b82f6', '#8b5cf6', '#ec4899', '#14b8a6', '#f59e0b', '#6366f1', '#ef4444', '#10b981'],
  types: ['#ef4444', '#f97316', '#eab308', '#22c55e', '#06b6d4', '#8b5cf6', '#ec4899', '#84cc16']
};

/* ============================================================================
   SINGLETON STATE
============================================================================ */

class RealTimeThreatFeedService {
  private stats: RealTimeThreatStats = {
    totalThreats: 0,
    activeC2Servers: 0,
    maliciousUrls: 0,
    malwareSamples: 0,
    recentMalware: 0,
    criticalThreats: 0,
    highThreats: 0,
    mediumThreats: 0,
    lowThreats: 0,
    phishingUrls: 0,
    sslCertificates: 0,
    lastUpdated: new Date().toISOString(),
    updateCount: 0
  };
  
  private trendData: ThreatDataPoint[] = [];
  private liveFeed: LiveFeedEntry[] = [];
  private listeners: Set<(data: any) => void> = new Set();
  private syncWorker: Worker | null = null;
  private syncInterval: ReturnType<typeof setInterval> | null = null;
  private isInitialized = false;

  // Subscribe to real-time updates
  subscribe(callback: (data: any) => void) {
    this.listeners.add(callback);
    // Immediately send current data
    callback({ stats: this.stats, trendData: this.trendData, liveFeed: this.liveFeed });
    return () => this.listeners.delete(callback);
  }

  // Notify all listeners
  private notifyListeners() {
    const data = {
      stats: this.stats,
      trendData: this.getTrendData(),
      liveFeed: this.liveFeed.slice(0, 100)
    };
    this.listeners.forEach(cb => cb(data));
  }

  // Initialize real-time syncing
  async initialize() {
    if (this.isInitialized) return;
    this.isInitialized = true;

    console.log('[RealTimeFeed] Initializing real-time threat feed service...');

    // Load cached data first for immediate display
    await this.loadCachedData();

    // Start background sync
    this.startBackgroundSync();

    // Initial fetch
    await this.fetchAllFeeds();

    console.log('[RealTimeFeed] Service initialized with', this.stats.totalThreats, 'threats');
  }

  // Load cached data for fast initial display
  private async loadCachedData() {
    try {
      const [cachedStats, cachedTrends, cachedFeed] = await Promise.all([
        getCachedData(CACHE_KEYS.THREAT_STATS),
        getCachedData(CACHE_KEYS.TREND_DATA),
        getCachedData(CACHE_KEYS.LIVE_FEED)
      ]);

      if (cachedStats) this.stats = cachedStats as RealTimeThreatStats;
      if (cachedTrends) this.trendData = cachedTrends as ThreatDataPoint[];
      if (cachedFeed) this.liveFeed = cachedFeed as LiveFeedEntry[];

      if (cachedStats || cachedTrends || cachedFeed) {
        console.log('[RealTimeFeed] Loaded cached data');
        this.notifyListeners();
      }
    } catch (error) {
      console.warn('[RealTimeFeed] Failed to load cached data:', error);
    }
  }

  // Start background synchronization
  private startBackgroundSync() {
    // Clear existing interval
    if (this.syncInterval) {
      clearInterval(this.syncInterval);
    }

    // Try to use Web Worker for background sync
    if (typeof Worker !== 'undefined') {
      this.initializeWebWorker();
    }

    // Main sync interval (runs even without worker)
    this.syncInterval = setInterval(() => {
      this.fetchAllFeeds();
    }, SYNC_INTERVAL);

    // Also use Page Visibility API to sync when page becomes visible
    if (typeof document !== 'undefined') {
      document.addEventListener('visibilitychange', () => {
        if (document.visibilityState === 'visible') {
          console.log('[RealTimeFeed] Page visible - refreshing data');
          this.fetchAllFeeds();
        }
      });
    }

    console.log('[RealTimeFeed] Background sync started (interval:', SYNC_INTERVAL, 'ms)');
  }

  // Initialize Web Worker for background sync
  private initializeWebWorker() {
    try {
      const workerScript = `
        let syncInterval = null;
        
        const endpoints = [
          { name: 'feodo', url: '/api/feodo/ipblocklist_recommended.json' },
          { name: 'urlhaus', url: '/api/urlhaus/json_recent/' },
          { name: 'threatfox', url: '/api/threatfox/json/recent/' }
        ];
        
        async function syncData() {
          const results = {};
          for (const endpoint of endpoints) {
            try {
              const response = await fetch(endpoint.url);
              if (response.ok) {
                const data = await response.json();
                results[endpoint.name] = { success: true, count: Object.keys(data).length };
              }
            } catch (e) {
              results[endpoint.name] = { success: false, error: e.message };
            }
          }
          postMessage({ type: 'SYNC_COMPLETE', results, timestamp: Date.now() });
        }
        
        self.onmessage = function(e) {
          if (e.data.type === 'START') {
            syncData();
            syncInterval = setInterval(syncData, ${SYNC_INTERVAL});
          } else if (e.data.type === 'STOP') {
            if (syncInterval) clearInterval(syncInterval);
          } else if (e.data.type === 'SYNC_NOW') {
            syncData();
          }
        };
      `;

      const blob = new Blob([workerScript], { type: 'application/javascript' });
      this.syncWorker = new Worker(URL.createObjectURL(blob));

      this.syncWorker.onmessage = (e) => {
        if (e.data.type === 'SYNC_COMPLETE') {
          console.log('[RealTimeFeed] Worker sync complete:', e.data.results);
          // Trigger main thread data fetch to update UI
          this.fetchAllFeeds();
        }
      };

      this.syncWorker.postMessage({ type: 'START' });
      console.log('[RealTimeFeed] Web Worker initialized for background sync');
    } catch (error) {
      console.warn('[RealTimeFeed] Web Worker initialization failed:', error);
    }
  }

  // Fetch all threat feeds
  async fetchAllFeeds() {
    const startTime = Date.now();
    
    try {
      // Reset counters for fresh data
      this.stats.criticalThreats = 0;
      this.stats.highThreats = 0;
      this.stats.mediumThreats = 0;
      this.stats.lowThreats = 0;

      const [feodoData, urlhausData, threatfoxData, bazaarData, sslblData, phishingData] = await Promise.all([
        this.fetchFeodoTracker(),
        this.fetchURLhaus(),
        this.fetchThreatFox(),
        this.fetchMalwareBazaar(),
        this.fetchSSLBlacklist(),
        this.fetchOpenPhish()
      ]);

      // Process and merge data
      this.processFeodaData(feodoData);
      this.processURLhausData(urlhausData);
      this.processThreatFoxData(threatfoxData);
      this.processBazaarData(bazaarData);
      this.processSSLBlacklistData(sslblData);
      this.processPhishingData(phishingData);

      // Update stats
      this.stats.lastUpdated = new Date().toISOString();
      this.stats.updateCount++;

      // Add trend data point
      this.addTrendDataPoint();

      // Cache data
      await Promise.all([
        cacheAPIResponse(CACHE_KEYS.THREAT_STATS, this.stats, CACHE_TTL * 5),
        cacheAPIResponse(CACHE_KEYS.TREND_DATA, this.trendData.slice(-100), CACHE_TTL * 10),
        cacheAPIResponse(CACHE_KEYS.LIVE_FEED, this.liveFeed.slice(0, 500), CACHE_TTL * 5)
      ]);

      // Notify listeners
      this.notifyListeners();

      const elapsed = Date.now() - startTime;
      console.log(`[RealTimeFeed] Fetched all feeds in ${elapsed}ms - Total: ${this.stats.totalThreats}`);

    } catch (error) {
      console.error('[RealTimeFeed] Error fetching feeds:', error);
    }
  }

  // Fetch Feodo Tracker C2 Servers
  private async fetchFeodoTracker(): Promise<any[]> {
    try {
      const response = await fetch('/api/feodo/ipblocklist_recommended.json');
      if (!response.ok) throw new Error(`Feodo fetch failed: ${response.status}`);
      
      const data = await response.json();
      const entries = Array.isArray(data) ? data : (data?.value || data?.data || []);
      
      return entries;
    } catch (error) {
      console.warn('[RealTimeFeed] Feodo fetch failed:', error);
      return [];
    }
  }

  // Fetch URLhaus malicious URLs
  private async fetchURLhaus(): Promise<any[]> {
    try {
      const response = await fetch('/api/urlhaus/json_recent/');
      if (!response.ok) throw new Error(`URLhaus fetch failed: ${response.status}`);
      
      const data = await response.json();
      const entries = Object.values(data || {}).flat().slice(0, 500);
      
      return entries;
    } catch (error) {
      console.warn('[RealTimeFeed] URLhaus fetch failed:', error);
      return [];
    }
  }

  // Fetch ThreatFox IOCs
  private async fetchThreatFox(): Promise<any[]> {
    try {
      const response = await fetch('/api/threatfox/json/recent/');
      if (!response.ok) throw new Error(`ThreatFox fetch failed: ${response.status}`);
      
      const data = await response.json();
      const entries = Object.entries(data || {})
        .flatMap(([id, entries]: [string, any]) => 
          (Array.isArray(entries) ? entries : [entries]).map((entry: any) => ({ ...entry, _id: id }))
        )
        .slice(0, 500);
      
      return entries;
    } catch (error) {
      console.warn('[RealTimeFeed] ThreatFox fetch failed:', error);
      return [];
    }
  }

  // Fetch MalwareBazaar samples
  private async fetchMalwareBazaar(): Promise<string[]> {
    try {
      const response = await fetch('/api/bazaar/txt/sha256/recent/');
      if (!response.ok) throw new Error(`MalwareBazaar fetch failed: ${response.status}`);
      
      const text = await response.text();
      const hashes = text
        .split('\n')
        .map(line => line.trim())
        .filter(line => line && !line.startsWith('#'))
        .slice(0, 200);
      
      return hashes;
    } catch (error) {
      console.warn('[RealTimeFeed] MalwareBazaar fetch failed:', error);
      return [];
    }
  }

  // Fetch SSL Blacklist (abuse.ch SSLBL)
  private async fetchSSLBlacklist(): Promise<any[]> {
    try {
      const response = await fetch('/api/sslbl/sslblacklist.json');
      if (!response.ok) throw new Error(`SSLBL fetch failed: ${response.status}`);
      
      const data = await response.json();
      const entries = Array.isArray(data) ? data : (data?.value || data?.data || []);
      
      return entries.slice(0, 200);
    } catch (error) {
      console.warn('[RealTimeFeed] SSLBL fetch failed:', error);
      return [];
    }
  }

  // Fetch OpenPhish phishing URLs
  private async fetchOpenPhish(): Promise<string[]> {
    try {
      const response = await fetch('/api/openphish/feed.txt');
      if (!response.ok) throw new Error(`OpenPhish fetch failed: ${response.status}`);
      
      const text = await response.text();
      const urls = text
        .split('\n')
        .map(line => line.trim())
        .filter(line => line && line.startsWith('http'))
        .slice(0, 300);
      
      return urls;
    } catch (error) {
      console.warn('[RealTimeFeed] OpenPhish fetch failed:', error);
      return [];
    }
  }

  // Process Feodo data
  private processFeodaData(entries: any[]) {
    let c2Count = 0;
    let critical = 0;
    let high = 0;

    entries.forEach((entry, index) => {
      const isOnline = entry.status === 'online';
      c2Count++;
      
      if (isOnline) critical++;
      else high++;

      // Add to live feed
      this.addToLiveFeed({
        id: `feodo-${index}-${Date.now()}`,
        type: 'c2',
        value: `${entry.ip_address || entry.ip}:${entry.port || 443}`,
        source: 'Feodo Tracker',
        severity: isOnline ? 'critical' : 'high',
        malwareFamily: entry.malware || 'Unknown',
        country: entry.country,
        timestamp: entry.first_seen || new Date().toISOString(),
        tags: [entry.malware || 'c2', 'botnet'].filter(Boolean)
      });
    });

    this.stats.activeC2Servers = c2Count;
    this.stats.criticalThreats += critical;
    this.stats.highThreats += high;
  }

  // Process URLhaus data
  private processURLhausData(entries: any[]) {
    let urlCount = 0;
    let high = 0;
    let medium = 0;

    entries.forEach((entry: any, index) => {
      urlCount++;
      const isOnline = entry.url_status === 'online';
      
      if (isOnline) high++;
      else medium++;

      this.addToLiveFeed({
        id: `urlhaus-${entry.id || index}-${Date.now()}`,
        type: 'url',
        value: entry.url || '',
        source: 'URLhaus',
        severity: isOnline ? 'high' : 'medium',
        malwareFamily: entry.threat || 'malware_download',
        timestamp: entry.dateadded || new Date().toISOString(),
        tags: Array.isArray(entry.tags) ? entry.tags : (entry.tags ? [entry.tags] : ['malware'])
      });
    });

    this.stats.maliciousUrls = urlCount;
    this.stats.highThreats += high;
    this.stats.mediumThreats += medium;
  }

  // Process ThreatFox data
  private processThreatFoxData(entries: any[]) {
    let iocCount = 0;

    entries.forEach((entry: any) => {
      iocCount++;
      const confidence = entry.confidence_level || 50;
      let severity: 'critical' | 'high' | 'medium' | 'low' = 'medium';
      
      if (confidence > 80) {
        severity = 'critical';
        this.stats.criticalThreats++;
      } else if (confidence > 50) {
        severity = 'high';
        this.stats.highThreats++;
      } else {
        this.stats.mediumThreats++;
      }

      let type: LiveFeedEntry['type'] = 'domain';
      const iocType = entry.ioc_type || '';
      if (iocType.includes('ip')) type = 'ip';
      else if (iocType.includes('url')) type = 'url';
      else if (iocType.includes('hash') || iocType.includes('md5') || iocType.includes('sha')) type = 'hash';

      this.addToLiveFeed({
        id: `threatfox-${entry._id || entry.id}-${Date.now()}`,
        type,
        value: entry.ioc_value || entry.ioc || '',
        source: 'ThreatFox',
        severity,
        malwareFamily: entry.malware_printable || entry.malware,
        timestamp: entry.first_seen_utc || entry.first_seen || new Date().toISOString(),
        tags: typeof entry.tags === 'string' ? entry.tags.split(',') : (entry.tags || [])
      });
    });

    this.stats.recentMalware += iocCount;
  }

  // Process MalwareBazaar data
  private processBazaarData(hashes: string[]) {
    hashes.forEach((hash, index) => {
      this.stats.malwareSamples++;
      this.stats.highThreats++;

      this.addToLiveFeed({
        id: `bazaar-${hash.slice(0, 16)}-${Date.now()}`,
        type: 'hash',
        value: hash,
        source: 'MalwareBazaar',
        severity: 'high',
        timestamp: new Date().toISOString(),
        tags: ['malware', 'sample']
      });
    });
  }

  // Process SSL Blacklist data  
  private processSSLBlacklistData(entries: any[]) {
    let sslCount = 0;

    entries.forEach((entry: any, index) => {
      sslCount++;
      const severity: 'critical' | 'high' | 'medium' = entry.status === 'online' ? 'critical' : 'high';
      
      if (severity === 'critical') this.stats.criticalThreats++;
      else this.stats.highThreats++;

      this.addToLiveFeed({
        id: `sslbl-${index}-${Date.now()}`,
        type: 'ip',
        value: `${entry.ip || entry.dst_ip}:${entry.port || 443}`,
        source: 'SSLBL (abuse.ch)',
        severity,
        malwareFamily: entry.malware || entry.reason || 'SSL Certificate Blacklist',
        country: entry.country,
        timestamp: entry.listing_date || new Date().toISOString(),
        tags: ['ssl', 'certificate', 'blacklist', entry.reason || ''].filter(Boolean)
      });
    });

    this.stats.sslCertificates = sslCount;
  }

  // Process Phishing data from OpenPhish
  private processPhishingData(urls: string[]) {
    urls.forEach((url, index) => {
      this.stats.phishingUrls++;
      this.stats.highThreats++;

      let hostname = 'unknown';
      try {
        hostname = new URL(url).hostname;
      } catch {}

      this.addToLiveFeed({
        id: `phish-${index}-${Date.now()}`,
        type: 'url',
        value: url,
        source: 'OpenPhish',
        severity: 'high',
        malwareFamily: 'Phishing',
        timestamp: new Date().toISOString(),
        tags: ['phishing', 'credential-theft', hostname]
      });
    });
  }

  // Add entry to live feed
  private addToLiveFeed(entry: LiveFeedEntry) {
    // Prevent duplicates
    const exists = this.liveFeed.some(e => e.value === entry.value && e.source === entry.source);
    if (!exists) {
      this.liveFeed.unshift(entry);
      // Keep only last 1000 entries
      if (this.liveFeed.length > 1000) {
        this.liveFeed = this.liveFeed.slice(0, 1000);
      }
    }
  }

  // Add trend data point
  private addTrendDataPoint() {
    const now = new Date();
    const dataPoint: ThreatDataPoint = {
      timestamp: now.toISOString(),
      date: now.toISOString().split('T')[0],
      hour: now.getHours(),
      total: this.stats.totalThreats,
      critical: this.stats.criticalThreats,
      high: this.stats.highThreats,
      medium: this.stats.mediumThreats,
      low: this.stats.lowThreats,
      bySource: {
        'Feodo Tracker': this.stats.activeC2Servers,
        'URLhaus': this.stats.maliciousUrls,
        'ThreatFox': this.stats.recentMalware,
        'MalwareBazaar': this.stats.malwareSamples
      },
      byType: {
        'C2 Server': this.stats.activeC2Servers,
        'Malicious URL': this.stats.maliciousUrls,
        'Malware Sample': this.stats.malwareSamples,
        'IOC': this.stats.recentMalware
      }
    };

    // Update total
    this.stats.totalThreats = 
      this.stats.activeC2Servers + 
      this.stats.maliciousUrls + 
      this.stats.malwareSamples + 
      this.stats.recentMalware;

    this.trendData.push(dataPoint);

    // Keep only last 100 data points
    if (this.trendData.length > 100) {
      this.trendData = this.trendData.slice(-100);
    }
  }

  // Get processed trend data for charts
  getTrendData(): ThreatTrendData {
    // Group trends by date for the line chart
    const groupedByDate = this.trendData.reduce((acc, point) => {
      const date = point.date;
      if (!acc[date]) {
        acc[date] = {
          date,
          total: 0,
          critical: 0,
          high: 0,
          medium: 0,
          low: 0,
          count: 0
        };
      }
      acc[date].total = Math.max(acc[date].total, point.total);
      acc[date].critical = Math.max(acc[date].critical, point.critical);
      acc[date].high = Math.max(acc[date].high, point.high);
      acc[date].medium = Math.max(acc[date].medium, point.medium);
      acc[date].low = Math.max(acc[date].low, point.low);
      acc[date].count++;
      return acc;
    }, {} as Record<string, any>);

    const trends = Object.values(groupedByDate).slice(-30) as ThreatDataPoint[];

    // Type distribution
    const typeDistribution = [
      { name: 'C2 Servers', value: this.stats.activeC2Servers, color: COLORS.types[0] },
      { name: 'Malicious URLs', value: this.stats.maliciousUrls, color: COLORS.types[1] },
      { name: 'Malware Samples', value: this.stats.malwareSamples, color: COLORS.types[2] },
      { name: 'IOCs', value: this.stats.recentMalware, color: COLORS.types[3] }
    ].filter(d => d.value > 0);

    // Source distribution
    const sourceDistribution = [
      { name: 'Feodo Tracker', value: this.stats.activeC2Servers, color: COLORS.sources[0] },
      { name: 'URLhaus', value: this.stats.maliciousUrls, color: COLORS.sources[1] },
      { name: 'ThreatFox', value: this.stats.recentMalware, color: COLORS.sources[2] },
      { name: 'MalwareBazaar', value: this.stats.malwareSamples, color: COLORS.sources[3] }
    ].filter(d => d.value > 0);

    // Severity distribution
    const severityDistribution = [
      { name: 'Critical', value: this.stats.criticalThreats, color: COLORS.critical },
      { name: 'High', value: this.stats.highThreats, color: COLORS.high },
      { name: 'Medium', value: this.stats.mediumThreats, color: COLORS.medium },
      { name: 'Low', value: this.stats.lowThreats, color: COLORS.low }
    ].filter(d => d.value > 0);

    // Malware families from live feed
    const familyCounts: Record<string, number> = {};
    this.liveFeed.forEach(entry => {
      if (entry.malwareFamily) {
        familyCounts[entry.malwareFamily] = (familyCounts[entry.malwareFamily] || 0) + 1;
      }
    });

    const malwareFamilies = Object.entries(familyCounts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 15)
      .map(([name, count]) => ({
        name,
        count,
        trend: count > 5 ? 'up' as const : count > 2 ? 'stable' as const : 'down' as const
      }));

    // Country distribution
    const countryCounts: Record<string, number> = {};
    this.liveFeed.forEach(entry => {
      if (entry.country) {
        countryCounts[entry.country] = (countryCounts[entry.country] || 0) + 1;
      }
    });

    const countryDistribution = Object.entries(countryCounts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 20)
      .map(([country, count]) => ({
        country,
        code: country,
        count
      }));

    return {
      trends,
      typeDistribution,
      sourceDistribution,
      severityDistribution,
      malwareFamilies,
      countryDistribution
    };
  }

  // Get current stats
  getStats(): RealTimeThreatStats {
    return { ...this.stats };
  }

  // Get live feed
  getLiveFeed(limit: number = 50): LiveFeedEntry[] {
    return this.liveFeed.slice(0, limit);
  }

  // Manual refresh
  async refresh() {
    await this.fetchAllFeeds();
  }

  // Cleanup
  destroy() {
    if (this.syncInterval) {
      clearInterval(this.syncInterval);
    }
    if (this.syncWorker) {
      this.syncWorker.postMessage({ type: 'STOP' });
      this.syncWorker.terminate();
    }
    this.listeners.clear();
    this.isInitialized = false;
  }
}

// Export singleton instance
export const realTimeThreatFeedService = new RealTimeThreatFeedService();

export default realTimeThreatFeedService;
