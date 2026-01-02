// ============================================================================
// realTimeThreatFeedService.ts
// REAL-TIME THREAT INTELLIGENCE FEED SERVICE
// ============================================================================
// Fetches real threat data from multiple free abuse.ch APIs:
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

// Raw API response types based on actual testing
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
   SERVICE CLASS
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
    console.log('[RealTimeFeed] Initializing...');

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

    console.log('[RealTimeFeed] Initialized successfully');
  }

  // Fetch all threat feeds
  async fetchAllFeeds(): Promise<void> {
    if (this.stats.isLoading) return;
    
    this.stats.isLoading = true;
    this.stats.errors = [];
    this.notifyListeners();

    const startTime = Date.now();

    try {
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
      if (feodoData.status === 'fulfilled' && feodoData.value) {
        this.processFeodoData(feodoData.value);
      } else if (feodoData.status === 'rejected') {
        this.stats.errors.push('Feodo: ' + (feodoData.reason?.message || 'Failed'));
      }

      if (urlhausData.status === 'fulfilled' && urlhausData.value) {
        this.processURLhausData(urlhausData.value);
      } else if (urlhausData.status === 'rejected') {
        this.stats.errors.push('URLhaus: ' + (urlhausData.reason?.message || 'Failed'));
      }

      if (threatfoxData.status === 'fulfilled' && threatfoxData.value) {
        this.processThreatFoxData(threatfoxData.value);
      } else if (threatfoxData.status === 'rejected') {
        this.stats.errors.push('ThreatFox: ' + (threatfoxData.reason?.message || 'Failed'));
      }

      if (bazaarData.status === 'fulfilled' && bazaarData.value) {
        this.processBazaarData(bazaarData.value);
      } else if (bazaarData.status === 'rejected') {
        this.stats.errors.push('Bazaar: ' + (bazaarData.reason?.message || 'Failed'));
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
      console.log(`[RealTimeFeed] Fetched in ${elapsed}ms - Total: ${this.stats.totalThreats}`);

    } catch (error) {
      console.error('[RealTimeFeed] Error:', error);
      this.stats.errors.push('Error: ' + (error as Error).message);
    } finally {
      this.stats.isLoading = false;
      this.notifyListeners();
    }
  }

  // Fetch Feodo Tracker C2 Servers (using text format as fallback)
  private async fetchFeodoTracker(): Promise<FeodoEntry[]> {
    try {
      // Try JSON first
      const response = await fetch('/api/feodo/ipblocklist_recommended.json', {
        headers: { 'Accept': 'application/json' }
      });
      
      if (response.ok) {
        const text = await response.text();
        if (text.startsWith('<')) throw new Error('HTML response');
        const data = JSON.parse(text);
        const entries: FeodoEntry[] = Array.isArray(data) ? data : (data?.value || []);
        console.log(`[Feodo] ${entries.length} C2 servers (JSON)`);
        return entries;
      }
    } catch (e) {
      console.warn('[Feodo] JSON failed, trying text format');
    }

    // Fallback to text format
    const response = await fetch('/api/feodo/ipblocklist_recommended.txt');
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    
    const text = await response.text();
    if (text.startsWith('<')) throw new Error('HTML response received');
    
    const entries: FeodoEntry[] = text.split('\n')
      .filter(line => line && !line.startsWith('#'))
      .map(ip => ({
        ip_address: ip.trim(),
        port: 443,
        status: 'online' as const,
        hostname: null,
        as_number: 0,
        as_name: 'Unknown',
        country: 'XX',
        first_seen: new Date().toISOString(),
        last_online: new Date().toISOString(),
        malware: 'Unknown'
      }));
    
    console.log(`[Feodo] ${entries.length} C2 servers (TXT)`);
    return entries;
  }

  // Fetch URLhaus malicious URLs (POST API)
  private async fetchURLhaus(): Promise<URLhausEntry[]> {
    try {
      // Use POST API which is more reliable
      const response = await fetch('/api/urlhaus-api/', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'query=get_recent&limit=500'
      });
      
      if (response.ok) {
        const text = await response.text();
        if (!text.startsWith('<')) {
          const data = JSON.parse(text);
          if (data.query_status === 'ok' && data.urls) {
            console.log(`[URLhaus] ${data.urls.length} URLs (API)`);
            return data.urls.map((u: any) => ({
              dateadded: u.dateadded,
              url: u.url,
              url_status: u.url_status,
              last_online: u.last_online,
              threat: u.threat,
              tags: u.tags || [],
              urlhaus_link: u.urlhaus_link,
              reporter: u.reporter
            }));
          }
        }
      }
    } catch (e) {
      console.warn('[URLhaus] API failed, trying text format');
    }

    // Fallback to text format
    const response = await fetch('/api/urlhaus/text_recent/');
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    
    const text = await response.text();
    if (text.startsWith('<')) throw new Error('HTML response received');
    
    const entries: URLhausEntry[] = text.split('\n')
      .filter(line => line && !line.startsWith('#'))
      .slice(0, 500)
      .map(url => ({
        dateadded: new Date().toISOString(),
        url: url.trim(),
        url_status: 'online' as const,
        last_online: null,
        threat: 'malware_download',
        tags: [],
        urlhaus_link: '',
        reporter: ''
      }));
    
    console.log(`[URLhaus] ${entries.length} URLs (TXT)`);
    return entries;
  }

  // Fetch ThreatFox IOCs (POST API)
  private async fetchThreatFox(): Promise<ThreatFoxEntry[]> {
    try {
      // Use POST API
      const response = await fetch('/api/threatfox-api/', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: 'get_iocs', days: 1 })
      });
      
      if (response.ok) {
        const text = await response.text();
        if (!text.startsWith('<')) {
          const data = JSON.parse(text);
          if (data.query_status === 'ok' && data.data) {
            console.log(`[ThreatFox] ${data.data.length} IOCs (API)`);
            return data.data.slice(0, 500);
          }
        }
      }
    } catch (e) {
      console.warn('[ThreatFox] API failed, trying export format');
    }

    // Fallback - try JSON export
    const response = await fetch('/api/threatfox/json/recent/');
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    
    const text = await response.text();
    if (text.startsWith('<')) throw new Error('HTML response received');
    
    const data = JSON.parse(text);
    const entries: ThreatFoxEntry[] = [];
    
    if (data && typeof data === 'object') {
      Object.values(data).forEach((item: any) => {
        if (Array.isArray(item)) entries.push(...item);
        else if (item && typeof item === 'object') entries.push(item);
      });
    }
    
    console.log(`[ThreatFox] ${entries.length} IOCs`);
    return entries.slice(0, 500);
  }

  // Fetch MalwareBazaar samples (POST API)
  private async fetchMalwareBazaar(): Promise<string[]> {
    try {
      // Use POST API
      const response = await fetch('/api/bazaar-api/', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'query=get_recent&selector=time'
      });
      
      if (response.ok) {
        const text = await response.text();
        if (!text.startsWith('<')) {
          const data = JSON.parse(text);
          if (data.query_status === 'ok' && data.data) {
            const hashes = data.data.map((s: any) => s.sha256_hash).filter(Boolean);
            console.log(`[Bazaar] ${hashes.length} hashes (API)`);
            return hashes.slice(0, 200);
          }
        }
      }
    } catch (e) {
      console.warn('[Bazaar] API failed, trying text format');
    }

    // Fallback to text format
    const response = await fetch('/api/bazaar/txt/sha256/recent/');
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    
    const text = await response.text();
    if (text.startsWith('<')) throw new Error('HTML response received');
    
    const hashes = text.split('\n')
      .map(line => line.trim())
      .filter(line => line && !line.startsWith('#') && line.length === 64);
    
    console.log(`[Bazaar] ${hashes.length} hashes (TXT)`);
    return hashes.slice(0, 200);
  }

  // Process Feodo data
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
        id: `feodo-${idx}`,
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

  // Process URLhaus data
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
        id: `urlhaus-${idx}`,
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

  // Process ThreatFox data
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
        id: `threatfox-${idx}`,
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

  // Process MalwareBazaar data
  private processBazaarData(hashes: string[]) {
    hashes.forEach((hash, idx) => {
      this.stats.malwareSamples++;
      this.stats.highThreats++;

      this.liveFeed.push({
        id: `bazaar-${idx}`,
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
