// ============================================================================
// realTimeThreatFeedService.ts
// REAL-TIME THREAT INTELLIGENCE FEED SERVICE
// ============================================================================
// Fetches real threat data via Edge Function from abuse.ch APIs:
// - Feodo Tracker (C2 Servers)
// - URLhaus (Malicious URLs)
// - ThreatFox (IOCs - IPs, domains, URLs)
// - MalwareBazaar (Malware samples SHA256)
// ============================================================================

import { threatFeedsAPI, type FeodoEntry, type URLhausEntry, type ThreatFoxEntry, type MalwareBazaarEntry } from '@/lib/api/threatFeeds';

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
      liveFeed: [...this.liveFeed]
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

  // Fetch all threat feeds via Edge Function
  async fetchAllFeeds(): Promise<void> {
    if (this.stats.isLoading) return;
    
    this.stats.isLoading = true;
    this.stats.errors = [];
    this.notifyListeners();

    const startTime = Date.now();

    try {
      console.log('[RealTimeFeed] Fetching all feeds from Edge Function...');
      
      // Use Edge Function to fetch all feeds at once
      const response = await threatFeedsAPI.fetchAllFeeds(7, 200);
      
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

      if (!response.success) {
        throw new Error('Edge function returned failure');
      }

      const { sources } = response;

      // Process each feed
      if (sources.feodo.success && sources.feodo.data?.length) {
        this.processFeodoData(sources.feodo.data);
      } else if (!sources.feodo.success) {
        this.stats.errors.push('Feodo: ' + (sources.feodo.error || 'Failed'));
      }

      if (sources.urlhaus.success && sources.urlhaus.data?.length) {
        this.processURLhausData(sources.urlhaus.data);
      } else if (!sources.urlhaus.success) {
        this.stats.errors.push('URLhaus: ' + (sources.urlhaus.error || 'Failed'));
      }

      if (sources.threatfox.success && sources.threatfox.data?.length) {
        this.processThreatFoxData(sources.threatfox.data);
      } else if (!sources.threatfox.success) {
        this.stats.errors.push('ThreatFox: ' + (sources.threatfox.error || 'Failed'));
      }

      if (sources.malwarebazaar.success && sources.malwarebazaar.data?.length) {
        this.processBazaarData(sources.malwarebazaar.data);
      } else if (!sources.malwarebazaar.success) {
        this.stats.errors.push('Bazaar: ' + (sources.malwarebazaar.error || 'Failed'));
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
      console.log(`[RealTimeFeed] C2: ${this.stats.activeC2Servers}, URLs: ${this.stats.maliciousUrls}, IOCs: ${this.stats.threatfoxIOCs}, Samples: ${this.stats.malwareSamples}`);

    } catch (error) {
      console.error('[RealTimeFeed] Error:', error);
      this.stats.errors.push('Error: ' + (error as Error).message);
    } finally {
      this.stats.isLoading = false;
      this.notifyListeners();
    }
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
  private processBazaarData(samples: MalwareBazaarEntry[]) {
    samples.forEach((sample, idx) => {
      // Validate hash format
      if (!sample.sha256_hash || !/^[a-fA-F0-9]{64}$/.test(sample.sha256_hash)) {
        return; // Skip invalid hashes
      }

      this.stats.malwareSamples++;
      this.stats.highThreats++;

      const malwareName = sample.signature || 'Unknown';
      if (malwareName && malwareName !== 'Unknown') {
        const count = this.malwareFamilyCounts.get(malwareName) || 0;
        this.malwareFamilyCounts.set(malwareName, count + 1);
      }

      this.liveFeed.push({
        id: `bazaar-${idx}`,
        type: 'hash',
        value: sample.sha256_hash,
        source: 'MalwareBazaar',
        severity: 'high',
        malwareFamily: malwareName,
        timestamp: sample.first_seen || new Date().toISOString(),
        tags: ['malware', 'sha256', ...(sample.tags || []), malwareName].filter(t => t && t !== 'Unknown')
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
      .slice(0, 20)
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
  getLiveFeed(): LiveFeedEntry[] { return [...this.liveFeed]; }
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
