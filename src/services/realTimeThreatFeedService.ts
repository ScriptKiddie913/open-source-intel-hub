// ============================================================================
// realTimeThreatFeedService.ts
// REAL-TIME THREAT INTELLIGENCE FEED SERVICE
// ============================================================================
// Fetches REAL threat data from multiple free abuse.ch APIs - NO MOCK DATA
// - Feodo Tracker (C2 Servers)
// - URLhaus (Malicious URLs)
// - ThreatFox (IOCs - IPs, domains, URLs)
// - MalwareBazaar (Malware samples SHA256)
// ============================================================================

/* ============================================================================
   TYPES
============================================================================ */

export interface ThreatDataPoint {
  timestamp: string;
  time: string;
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface RealTimeThreatStats {
  totalThreats: number;
  activeC2Servers: number;
  maliciousUrls: number;
  malwareSamples: number;
  threatfoxIOCs: number;
  criticalThreats: number;
  highThreats: number;
  mediumThreats: number;
  lowThreats: number;
  lastUpdated: string;
  updateCount: number;
  isLoading: boolean;
  errors: string[];
}

export interface ThreatTrendData {
  trends: ThreatDataPoint[];
  typeDistribution: { name: string; value: number; color: string }[];
  sourceDistribution: { name: string; value: number; color: string }[];
  severityDistribution: { name: string; value: number; color: string }[];
  malwareFamilies: { name: string; count: number; trend: 'up' | 'down' | 'stable' }[];
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
  port?: number;
  status?: string;
}

// Raw API response types based on actual API structure
interface FeodoEntry {
  ip_address: string;
  port: number;
  status: 'online' | 'offline';
  hostname: string | null;
  as_number: number;
  as_name: string;
  country: string;
  first_seen: string;
  last_online: string;
  malware: string;
}

interface URLhausEntry {
  dateadded: string;
  url: string;
  url_status: 'online' | 'offline';
  last_online: string | null;
  threat: string;
  tags: string[];
  urlhaus_link: string;
  reporter: string;
}

interface ThreatFoxEntry {
  ioc_value: string;
  ioc_type: string;
  threat_type: string;
  malware: string;
  malware_alias: string | null;
  malware_printable: string;
  first_seen_utc: string;
  last_seen_utc: string | null;
  confidence_level: number;
  reference: string | null;
  tags: string;
  reporter: string;
}

/* ============================================================================
   CONSTANTS
============================================================================ */

const SYNC_INTERVAL = 30000; // 30 seconds

const COLORS = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#22c55e',
  sources: ['#3b82f6', '#8b5cf6', '#ec4899', '#14b8a6'],
  types: ['#ef4444', '#f97316', '#eab308', '#22c55e', '#06b6d4']
};

/* ============================================================================
   SERVICE CLASS - 100% REAL DATA ONLY
============================================================================ */

class RealTimeThreatFeedService {
  private stats: RealTimeThreatStats = {
    totalThreats: 0,
    activeC2Servers: 0,
    maliciousUrls: 0,
    malwareSamples: 0,
    threatfoxIOCs: 0,
    criticalThreats: 0,
    highThreats: 0,
    mediumThreats: 0,
    lowThreats: 0,
    lastUpdated: new Date().toISOString(),
    updateCount: 0,
    isLoading: false,
    errors: []
  };

  private trendData: ThreatDataPoint[] = [];
  private liveFeed: LiveFeedEntry[] = [];
  private malwareFamilyCounts: Map<string, number> = new Map();
  private listeners: Set<(data: any) => void> = new Set();
  private syncInterval: ReturnType<typeof setInterval> | null = null;
  private isInitialized = false;

  // Subscribe to updates
  subscribe(callback: (data: any) => void): () => void {
    this.listeners.add(callback);
    // Send current data immediately
    callback(this.getSubscriptionData());
    return () => this.listeners.delete(callback);
  }

  private getSubscriptionData() {
    return {
      stats: { ...this.stats },
      trendData: this.getTrendData(),
      liveFeed: this.liveFeed.slice(0, 100)
    };
  }

  private notifyListeners() {
    const data = this.getSubscriptionData();
    this.listeners.forEach(cb => {
      try {
        cb(data);
      } catch (e) {
        console.error('[RealTimeFeed] Listener error:', e);
      }
    });
  }

  // Initialize service
  async initialize(): Promise<void> {
    if (this.isInitialized) {
      console.log('[RealTimeFeed] Already initialized');
      return;
    }
    
    this.isInitialized = true;
    console.log('[RealTimeFeed] Initializing with REAL data sources only...');

    // Start fetching immediately
    await this.fetchAllFeeds();

    // Set up periodic refresh
    this.syncInterval = setInterval(() => {
      this.fetchAllFeeds();
    }, SYNC_INTERVAL);

    // Refresh on visibility change
    if (typeof document !== 'undefined') {
      document.addEventListener('visibilitychange', () => {
        if (document.visibilityState === 'visible') {
          this.fetchAllFeeds();
        }
      });
    }

    console.log('[RealTimeFeed] Initialized successfully - REAL DATA ONLY');
  }

  // Fetch all threat feeds - REAL DATA ONLY
  async fetchAllFeeds(): Promise<void> {
    if (this.stats.isLoading) return;
    
    this.stats.isLoading = true;
    this.stats.errors = [];
    this.notifyListeners();

    const startTime = Date.now();

    try {
      console.log('[RealTimeFeed] Fetching REAL data from abuse.ch APIs...');

      // Fetch all feeds in parallel
      const [feodoData, urlhausData, threatfoxData, bazaarData] = await Promise.allSettled([
        this.fetchFeodoTracker(),
        this.fetchURLhaus(),
        this.fetchThreatFox(),
        this.fetchMalwareBazaar()
      ]);

      // Reset counters
      this.stats.activeC2Servers = 0;
      this.stats.maliciousUrls = 0;
      this.stats.threatfoxIOCs = 0;
      this.stats.malwareSamples = 0;
      this.stats.criticalThreats = 0;
      this.stats.highThreats = 0;
      this.stats.mediumThreats = 0;
      this.stats.lowThreats = 0;
      this.liveFeed = [];
      this.malwareFamilyCounts.clear();

      // Process each feed
      if (feodoData.status === 'fulfilled' && feodoData.value && feodoData.value.length > 0) {
        this.processFeodoData(feodoData.value);
        console.log('[Feodo] ✅ Processed', feodoData.value.length, 'REAL C2 servers');
      } else if (feodoData.status === 'rejected') {
        this.stats.errors.push('Feodo: ' + (feodoData.reason?.message || 'Failed to fetch real data'));
        console.error('[Feodo] ❌ Failed to fetch real data');
      }

      if (urlhausData.status === 'fulfilled' && urlhausData.value && urlhausData.value.length > 0) {
        this.processURLhausData(urlhausData.value);
        console.log('[URLhaus] ✅ Processed', urlhausData.value.length, 'REAL malware URLs');
      } else if (urlhausData.status === 'rejected') {
        this.stats.errors.push('URLhaus: ' + (urlhausData.reason?.message || 'Failed to fetch real data'));
        console.error('[URLhaus] ❌ Failed to fetch real data');
      }

      if (threatfoxData.status === 'fulfilled' && threatfoxData.value && threatfoxData.value.length > 0) {
        this.processThreatFoxData(threatfoxData.value);
        console.log('[ThreatFox] ✅ Processed', threatfoxData.value.length, 'REAL IOCs');
      } else if (threatfoxData.status === 'rejected') {
        this.stats.errors.push('ThreatFox: ' + (threatfoxData.reason?.message || 'Failed to fetch real data'));
        console.error('[ThreatFox] ❌ Failed to fetch real data');
      }

      if (bazaarData.status === 'fulfilled' && bazaarData.value && bazaarData.value.length > 0) {
        this.processBazaarData(bazaarData.value);
        console.log('[Bazaar] ✅ Processed', bazaarData.value.length, 'REAL malware samples');
      } else if (bazaarData.status === 'rejected') {
        this.stats.errors.push('Bazaar: ' + (bazaarData.reason?.message || 'Failed to fetch real data'));
        console.error('[Bazaar] ❌ Failed to fetch real data');
      }

      // Calculate totals
      this.stats.totalThreats = 
        this.stats.activeC2Servers + 
        this.stats.maliciousUrls + 
        this.stats.threatfoxIOCs + 
        this.stats.malwareSamples;

      // Add trend data point
      this.addTrendDataPoint();

      this.stats.updateCount++;
      this.stats.lastUpdated = new Date().toISOString();

      const elapsed = Date.now() - startTime;
      console.log(`[RealTimeFeed] ✅ Fetched REAL data in ${elapsed}ms - Total: ${this.stats.totalThreats} threats`);

      if (this.stats.errors.length > 0) {
        console.warn('[RealTimeFeed] ⚠️ Some sources failed:', this.stats.errors);
      }

    } catch (error) {
      console.error('[RealTimeFeed] ❌ Error fetching real data:', error);
      this.stats.errors.push('Error: ' + (error as Error).message);
    } finally {
      this.stats.isLoading = false;
      this.notifyListeners();
    }
  }

  // Fetch REAL Feodo Tracker C2 Servers - NO MOCK DATA
  private async fetchFeodoTracker(): Promise<FeodoEntry[]> {
    const urls = [
      'https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json',
      '/api/feodo/ipblocklist_recommended.json'
    ];

    for (const url of urls) {
      try {
        console.log('[Feodo] Attempting to fetch from:', url);
        
        const response = await fetch(url, {
          headers: { 
            'Accept': 'application/json',
            'User-Agent': 'OSINT-Hub/1.0'
          },
          signal: AbortSignal.timeout(10000) // 10 second timeout
        });
        
        if (response.ok) {
          const text = await response.text();
          
          // Skip HTML error pages
          if (text.startsWith('<')) {
            console.warn('[Feodo] Received HTML instead of JSON from:', url);
            continue;
          }
          
          if (!text.trim()) {
            console.warn('[Feodo] Empty response from:', url);
            continue;
          }
          
          const data = JSON.parse(text);
          const entries: FeodoEntry[] = Array.isArray(data) ? data : (data?.value || []);
          
          if (entries.length > 0) {
            console.log(`[Feodo] ✅ Successfully fetched ${entries.length} REAL C2 servers from ${url}`);
            return entries;
          } else {
            console.warn('[Feodo] Got empty array from:', url);
          }
        } else {
          console.warn(`[Feodo] HTTP ${response.status} from ${url}`);
        }
      } catch (e) {
        console.warn(`[Feodo] Failed with ${url}:`, e);
      }
    }

    console.error('[Feodo] ❌ All REAL endpoints failed - returning empty array (NO MOCK DATA)');
    return [];
  }

  // Fetch REAL URLhaus malicious URLs - NO MOCK DATA
  private async fetchURLhaus(): Promise<URLhausEntry[]> {
    const configs = [
      {
        url: 'https://urlhaus-api.abuse.ch/v1/urls/recent/',
        method: 'GET' as const
      },
      {
        url: 'https://urlhaus-api.abuse.ch/v1/urls/recent/limit/1000/',
        method: 'GET' as const
      },
      {
        url: '/api/urlhaus/json_recent/',
        method: 'GET' as const
      }
    ];

    for (const config of configs) {
      try {
        console.log('[URLhaus] Attempting to fetch from:', config.url);
        
        const response = await fetch(config.url, {
          method: config.method,
          headers: {
            'Accept': 'application/json',
            'User-Agent': 'OSINT-Hub/1.0'
          },
          signal: AbortSignal.timeout(10000)
        });
        
        if (response.ok) {
          const text = await response.text();
          
          if (text.startsWith('<')) {
            console.warn('[URLhaus] Received HTML instead of JSON from:', config.url);
            continue;
          }
          
          if (!text.trim()) {
            console.warn('[URLhaus] Empty response from:', config.url);
            continue;
          }
          
          const data = JSON.parse(text);
          
          // URLhaus API can return different formats
          let entries: any[] = [];
          if (data.urls) {
            entries = data.urls;
          } else if (Array.isArray(data)) {
            entries = data;
          } else if (typeof data === 'object') {
            // Handle numeric keys format: { "0": {...}, "1": {...} }
            entries = Object.values(data).filter(v => typeof v === 'object' && v.url);
          }
          
          if (entries.length > 0) {
            const processed = entries.slice(0, 1000).map((u: any) => ({
              dateadded: u.dateadded || u.date_added || new Date().toISOString(),
              url: u.url,
              url_status: u.url_status || 'online',
              last_online: u.last_online,
              threat: u.threat || 'malware_download',
              tags: Array.isArray(u.tags) ? u.tags : [],
              urlhaus_link: u.urlhaus_link || '',
              reporter: u.reporter || 'anonymous'
            }));
            
            console.log(`[URLhaus] ✅ Successfully fetched ${processed.length} REAL malware URLs from ${config.url}`);
            return processed;
          }
        } else {
          console.warn(`[URLhaus] HTTP ${response.status} from ${config.url}`);
        }
      } catch (e) {
        console.warn(`[URLhaus] Failed with ${config.url}:`, e);
      }
    }

    console.error('[URLhaus] ❌ All REAL endpoints failed - returning empty array (NO MOCK DATA)');
    return [];
  }

  // Fetch REAL ThreatFox IOCs - NO MOCK DATA
  private async fetchThreatFox(): Promise<ThreatFoxEntry[]> {
    const configs = [
      {
        url: 'https://threatfox-api.abuse.ch/api/v1/',
        body: { query: 'get_iocs', days: 7 }
      },
      {
        url: '/api/threatfox/json/recent/',
        body: null
      }
    ];

    for (const config of configs) {
      try {
        console.log('[ThreatFox] Attempting to fetch from:', config.url);
        
        const fetchOptions: RequestInit = {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'User-Agent': 'OSINT-Hub/1.0'
          },
          signal: AbortSignal.timeout(10000)
        };
        
        if (config.body) {
          fetchOptions.body = JSON.stringify(config.body);
        }
        
        const response = await fetch(config.url, fetchOptions);
        
        if (response.ok) {
          const text = await response.text();
          
          if (text.startsWith('<')) {
            console.warn('[ThreatFox] Received HTML instead of JSON from:', config.url);
            continue;
          }
          
          if (!text.trim()) {
            console.warn('[ThreatFox] Empty response from:', config.url);
            continue;
          }
          
          const data = JSON.parse(text);
          
          let entries: ThreatFoxEntry[] = [];
          
          if (data.query_status === 'ok' && data.data) {
            entries = Array.isArray(data.data) ? data.data : Object.values(data.data);
          } else if (Array.isArray(data)) {
            entries = data;
          } else if (typeof data === 'object') {
            // Handle numeric keys format
            entries = Object.values(data).filter((v: any) => v && typeof v === 'object' && v.ioc_value);
          }
          
          if (entries.length > 0) {
            console.log(`[ThreatFox] ✅ Successfully fetched ${entries.length} REAL IOCs from ${config.url}`);
            return entries.slice(0, 1000);
          }
        } else {
          console.warn(`[ThreatFox] HTTP ${response.status} from ${config.url}`);
        }
      } catch (e) {
        console.warn(`[ThreatFox] Failed with ${config.url}:`, e);
      }
    }

    console.error('[ThreatFox] ❌ All REAL endpoints failed - returning empty array (NO MOCK DATA)');
    return [];
  }

  // Fetch REAL MalwareBazaar samples - NO MOCK DATA
  private async fetchMalwareBazaar(): Promise<string[]> {
    const configs = [
      {
        url: 'https://mb-api.abuse.ch/api/v1/',
        method: 'POST' as const,
        body: 'query=get_recent&selector=time'
      },
      {
        url: '/api/bazaar/txt/sha256/recent/',
        method: 'GET' as const
      }
    ];

    for (const config of configs) {
      try {
        console.log('[Bazaar] Attempting to fetch from:', config.url);
        
        const response = await fetch(config.url, {
          method: config.method,
          headers: config.method === 'POST' 
            ? { 'Content-Type': 'application/x-www-form-urlencoded' }
            : { 'Accept': 'text/plain,application/json' },
          body: config.body,
          signal: AbortSignal.timeout(10000)
        });
        
        if (response.ok) {
          const contentType = response.headers.get('content-type') || '';
          
          if (contentType.includes('text/plain')) {
            // Handle text format (SHA256 hashes, one per line)
            const text = await response.text();
            const hashes = text
              .split('\n')
              .map(line => line.trim())
              .filter(line => line && !line.startsWith('#') && /^[a-f0-9]{64}$/i.test(line));
            
            if (hashes.length > 0) {
              console.log(`[Bazaar] ✅ Successfully fetched ${hashes.length} REAL malware hashes from ${config.url}`);
              return hashes.slice(0, 500);
            }
          } else {
            // Handle JSON format
            const text = await response.text();
            
            if (text.startsWith('<')) {
              console.warn('[Bazaar] Received HTML instead of JSON from:', config.url);
              continue;
            }
            
            const data = JSON.parse(text);
            
            if (data.query_status === 'ok' && data.data) {
              const hashes = data.data
                .map((s: any) => s.sha256_hash || s.sha256)
                .filter((h: any) => h && typeof h === 'string');
              
              if (hashes.length > 0) {
                console.log(`[Bazaar] ✅ Successfully fetched ${hashes.length} REAL malware hashes from ${config.url}`);
                return hashes.slice(0, 500);
              }
            }
          }
        } else {
          console.warn(`[Bazaar] HTTP ${response.status} from ${config.url}`);
        }
      } catch (e) {
        console.warn(`[Bazaar] Failed with ${config.url}:`, e);
      }
    }

    console.error('[Bazaar] ❌ All REAL endpoints failed - returning empty array (NO MOCK DATA)');
    return [];
  }

  // Process REAL Feodo data
  private processFeodoData(entries: FeodoEntry[]) {
    entries.forEach((entry, idx) => {
      const isOnline = entry.status === 'online';
      this.stats.activeC2Servers++;
      
      if (isOnline) this.stats.criticalThreats++;
      else this.stats.highThreats++;

      if (entry.malware) {
        const count = this.malwareFamilyCounts.get(entry.malware) || 0;
        this.malwareFamilyCounts.set(entry.malware, count + 1);
      }

      this.liveFeed.push({
        id: `feodo-${entry.ip_address}-${entry.port}`,
        type: 'c2',
        value: `${entry.ip_address}:${entry.port}`,
        source: 'Feodo Tracker',
        severity: isOnline ? 'critical' : 'high',
        malwareFamily: entry.malware,
        country: entry.country,
        timestamp: entry.first_seen || new Date().toISOString(),
        tags: [entry.malware, 'C2', entry.as_name].filter(Boolean),
        port: entry.port,
        status: entry.status
      });
    });
  }

  // Process REAL URLhaus data
  private processURLhausData(entries: URLhausEntry[]) {
    entries.forEach((entry, idx) => {
      const isOnline = entry.url_status === 'online';
      this.stats.maliciousUrls++;
      
      if (isOnline) this.stats.highThreats++;
      else this.stats.mediumThreats++;

      if (entry.tags?.length) {
        entry.tags.forEach(tag => {
          if (tag && !['32-bit', '64-bit', 'arm', 'mips', 'elf'].includes(tag.toLowerCase())) {
            const count = this.malwareFamilyCounts.get(tag) || 0;
            this.malwareFamilyCounts.set(tag, count + 1);
          }
        });
      }

      this.liveFeed.push({
        id: `urlhaus-${entry.url.substring(0, 50)}-${idx}`,
        type: 'url',
        value: entry.url,
        source: 'URLhaus',
        severity: isOnline ? 'high' : 'medium',
        malwareFamily: entry.threat || entry.tags?.[0],
        timestamp: entry.dateadded,
        tags: entry.tags || [],
        status: entry.url_status
      });
    });
  }

  // Process REAL ThreatFox data
  private processThreatFoxData(entries: ThreatFoxEntry[]) {
    entries.forEach((entry, idx) => {
      this.stats.threatfoxIOCs++;
      
      const confidence = entry.confidence_level || 50;
      let severity: LiveFeedEntry['severity'] = 'medium';
      
      if (confidence >= 90) { severity = 'critical'; this.stats.criticalThreats++; }
      else if (confidence >= 70) { severity = 'high'; this.stats.highThreats++; }
      else if (confidence >= 40) { severity = 'medium'; this.stats.mediumThreats++; }
      else { severity = 'low'; this.stats.lowThreats++; }

      let type: LiveFeedEntry['type'] = 'domain';
      if (entry.ioc_type === 'ip:port') type = 'ip';
      else if (entry.ioc_type === 'url') type = 'url';
      else if (entry.ioc_type?.includes('hash')) type = 'hash';

      const malwareName = entry.malware_printable || entry.malware;
      if (malwareName && malwareName !== 'Unknown malware') {
        const count = this.malwareFamilyCounts.get(malwareName) || 0;
        this.malwareFamilyCounts.set(malwareName, count + 1);
      }

      const tags = typeof entry.tags === 'string' 
        ? entry.tags.split(',').map(t => t.trim()).filter(Boolean) : [];

      this.liveFeed.push({
        id: `threatfox-${entry.ioc_value.substring(0, 30)}-${idx}`,
        type,
        value: entry.ioc_value,
        source: 'ThreatFox',
        severity,
        malwareFamily: malwareName,
        timestamp: entry.first_seen_utc,
        tags: [...tags, entry.threat_type].filter(Boolean)
      });
    });
  }

  // Process REAL MalwareBazaar data
  private processBazaarData(hashes: string[]) {
    hashes.forEach((hash, idx) => {
      this.stats.malwareSamples++;
      this.stats.highThreats++;

      this.liveFeed.push({
        id: `bazaar-${hash.substring(0, 16)}`,
        type: 'hash',
        value: hash,
        source: 'MalwareBazaar',
        severity: 'high',
        timestamp: new Date().toISOString(),
        tags: ['malware', 'sha256']
      });
    });
  }

  // Add trend data point
  private addTrendDataPoint() {
    const now = new Date();
    
    this.trendData.push({
      timestamp: now.toISOString(),
      time: now.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' }),
      total: this.stats.totalThreats,
      critical: this.stats.criticalThreats,
      high: this.stats.highThreats,
      medium: this.stats.mediumThreats,
      low: this.stats.lowThreats
    });

    if (this.trendData.length > 50) {
      this.trendData = this.trendData.slice(-50);
    }
  }

  // Get trend data for charts
  getTrendData(): ThreatTrendData {
    const typeDistribution = [
      { name: 'C2 Servers', value: this.stats.activeC2Servers, color: COLORS.types[0] },
      { name: 'Malicious URLs', value: this.stats.maliciousUrls, color: COLORS.types[1] },
      { name: 'ThreatFox IOCs', value: this.stats.threatfoxIOCs, color: COLORS.types[2] },
      { name: 'Malware Samples', value: this.stats.malwareSamples, color: COLORS.types[3] }
    ].filter(d => d.value > 0);

    const sourceDistribution = [
      { name: 'Feodo Tracker', value: this.stats.activeC2Servers, color: COLORS.sources[0] },
      { name: 'URLhaus', value: this.stats.maliciousUrls, color: COLORS.sources[1] },
      { name: 'ThreatFox', value: this.stats.threatfoxIOCs, color: COLORS.sources[2] },
      { name: 'MalwareBazaar', value: this.stats.malwareSamples, color: COLORS.sources[3] }
    ].filter(d => d.value > 0);

    const severityDistribution = [
      { name: 'Critical', value: this.stats.criticalThreats, color: COLORS.critical },
      { name: 'High', value: this.stats.highThreats, color: COLORS.high },
      { name: 'Medium', value: this.stats.mediumThreats, color: COLORS.medium },
      { name: 'Low', value: this.stats.lowThreats, color: COLORS.low }
    ].filter(d => d.value > 0);

    const malwareFamilies = Array.from(this.malwareFamilyCounts.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 15)
      .map(([name, count]) => ({
        name,
        count,
        trend: count > 10 ? 'up' as const : count > 3 ? 'stable' as const : 'down' as const
      }));

    return {
      trends: this.trendData,
      typeDistribution,
      sourceDistribution,
      severityDistribution,
      malwareFamilies
    };
  }

  getStats(): RealTimeThreatStats { return { ...this.stats }; }
  getLiveFeed(limit = 50): LiveFeedEntry[] { return this.liveFeed.slice(0, limit); }
  async refresh(): Promise<void> { await this.fetchAllFeeds(); }

  destroy() {
    if (this.syncInterval) {
      clearInterval(this.syncInterval);
      this.syncInterval = null;
    }
    this.listeners.clear();
    this.isInitialized = false;
  }
}

export const realTimeThreatFeedService = new RealTimeThreatFeedService();
export default realTimeThreatFeedService;
