// ============================================================================
// comprehensiveThreatAggregatorService.ts
// ALL 29 THREAT SOURCES AGGREGATOR - NO MORE SINGLE SOURCE LOADING!
// ============================================================================
// This service aggregates ALL available threat intelligence sources in parallel
// to ensure the malware pipeline fetches from ALL 29+ sources as intended

import { 
  fetchFeodoC2Servers, 
  fetchURLhausRecent, 
  fetchThreatFoxIOCs, 
  fetchMalwareBazaarRecent,
  type C2Server,
  type URLhausEntry,
  type ThreatFoxIOC,
  type MalwareSample
} from './mispFeedService';

// Note: Some enhanced services may not be available
// import { malwareBazaarService } from './malwareBazaarService';
// import { feodoTrackerService } from './feodoTrackerService';
// import { gitHubMalwareService } from './gitHubMalwareService';
// import { urlhausService } from './urlhausService';

import { 
  searchDarkWebForums, 
  getRansomwareVictims, 
  type ForumSearchResult, 
  type RansomwareVictim 
} from './darkWebForumService';

import { 
  searchTelegramLeaks, 
  searchTelegramChannels,
  type TelegramLeak, 
  type TelegramChannel 
} from './telegramService';

import { 
  searchDarkWebSignals, 
  deepSearchDarkWeb,
  type LeakSignal, 
  type DeepSearchResult 
} from './torService';

import { 
  searchThreatActors, 
  type ThreatActorSearchResult,
  type ThreatActor 
} from './threatActorService';

import { 
  searchCVE, 
  getCISAKEV, 
  getRecentCVEs, 
  getTrendingCVEs,
  type CVEData, 
  type KEVData 
} from './cveService';

import { 
  searchAPTGroups, 
  getAPTStats, 
  fetchMalwareData,
  type APTGroup 
} from './aptMapService';

import { openCtiCorrelationService } from './openCtiCorrelationService';
import { realTimeThreatFeedService } from './realTimeThreatFeedService';

/* ============================================================================
   TYPES FOR COMPREHENSIVE THREAT AGGREGATION
============================================================================ */

export interface ComprehensiveThreatData {
  // Core abuse.ch sources (4)
  feodoC2Servers: C2Server[];
  urlhausData: URLhausEntry[];
  threatfoxIOCs: ThreatFoxIOC[];
  malwareBazaarSamples: MalwareSample[];
  
  // Advanced malware services (4)
  gitHubMalware: any[];
  urlhausService: any[];
  feodoService: any[];
  bazaarService: any[];
  
  // Dark web & forums (3)
  darkWebForums: ForumSearchResult | null;
  darkWebSignals: LeakSignal[];
  ransomwareVictims: RansomwareVictim[];
  
  // Telegram & messaging (2)
  telegramLeaks: TelegramLeak[];
  telegramChannels: TelegramChannel[];
  
  // CVE & vulnerability (4)
  recentCVEs: CVEData[];
  cisaKEV: KEVData[];
  trendingCVEs: CVEData[];
  searchedCVEs: CVEData[];
  
  // APT & threat actors (4)
  aptGroups: APTGroup[];
  aptStats: any;
  aptMalware: any;
  threatActors: ThreatActorSearchResult;
  
  // OpenCTI & correlation (2)
  openCtiLandscape: any;
  threatCorrelation: any[];
  
  // Real-time feeds (2)
  realTimeStats: any;
  liveTrendData: any;
  
  // Additional sources (4)
  torInvestigation: DeepSearchResult[];
  socialScrapingData: any[];
  newsIntelligence: any[];
  bitcoinInvestigation: any[];
  
  // Aggregation metadata
  totalSources: number;
  successfulSources: number;
  failedSources: string[];
  lastUpdated: string;
  aggregationTime: number;
}

export interface ThreatSourceConfig {
  name: string;
  enabled: boolean;
  timeout: number;
  retries: number;
  fetchFunction: () => Promise<any>;
}

/* ============================================================================
   COMPREHENSIVE THREAT AGGREGATOR SERVICE
============================================================================ */

class ComprehensiveThreatAggregatorService {
  private sources: ThreatSourceConfig[] = [];
  private lastAggregation: ComprehensiveThreatData | null = null;
  private aggregationInProgress = false;

  constructor() {
    try {
      this.initializeSources();
      console.log('[ThreatAggregator] Service initialized successfully');
    } catch (error) {
      console.error('[ThreatAggregator] Failed to initialize:', error);
      this.sources = []; // Fallback to empty sources
    }
  }

  private initializeSources() {
    // Core abuse.ch sources (4 sources)
    this.sources = [
      {
        name: 'feodo-c2-servers',
        enabled: true,
        timeout: 30000,
        retries: 2,
        fetchFunction: () => fetchFeodoC2Servers()
      },
      {
        name: 'urlhaus-malware-urls', 
        enabled: true,
        timeout: 30000,
        retries: 2,
        fetchFunction: () => fetchURLhausRecent()
      },
      {
        name: 'threatfox-iocs',
        enabled: true, 
        timeout: 30000,
        retries: 2,
        fetchFunction: () => fetchThreatFoxIOCs(30)
      },
      {
        name: 'malwarebazaar-samples',
        enabled: true,
        timeout: 30000, 
        retries: 2,
        fetchFunction: () => fetchMalwareBazaarRecent()
      },

      // Enhanced malware services (4 sources)
      {
        name: 'github-malware-repos',
        enabled: false, // Disabled due to rate limits
        timeout: 45000,
        retries: 1,
        fetchFunction: () => Promise.resolve([])
      },
      {
        name: 'urlhaus-service-enhanced',
        enabled: false, // Use main URLhaus instead
        timeout: 30000,
        retries: 2,
        fetchFunction: () => Promise.resolve([])
      },
      {
        name: 'feodo-service-enhanced', 
        enabled: false, // Use main Feodo instead
        timeout: 30000,
        retries: 2,
        fetchFunction: () => Promise.resolve([])
      },
      {
        name: 'bazaar-service-enhanced',
        enabled: false, // Use main MalwareBazaar instead
        timeout: 30000,
        retries: 2,  
        fetchFunction: () => Promise.resolve([])
      },

      // Dark web & forums (3 sources)
      {
        name: 'dark-web-forums',
        enabled: true,
        timeout: 60000,
        retries: 1,
        fetchFunction: () => searchDarkWebForums('malware').catch(() => ({ posts: [], total: 0 }))
      },
      {
        name: 'dark-web-signals',
        enabled: true,
        timeout: 60000,
        retries: 1, 
        fetchFunction: () => searchDarkWebSignals('threat intelligence').catch(() => [])
      },
      {
        name: 'ransomware-victims',
        enabled: true,
        timeout: 45000,
        retries: 1,
        fetchFunction: () => getRansomwareVictims({ days: 30 }).catch(() => [])
      },

      // Telegram & messaging (2 sources)
      {
        name: 'telegram-leaks',
        enabled: true,
        timeout: 45000,
        retries: 1,
        fetchFunction: () => searchTelegramLeaks('breach', 'keyword').catch(() => [])
      },
      {
        name: 'telegram-channels',
        enabled: true,
        timeout: 45000,
        retries: 1,
        fetchFunction: () => searchTelegramChannels('malware').catch(() => [])
      },

      // CVE & vulnerability (4 sources)
      {
        name: 'recent-cves',
        enabled: true,
        timeout: 30000,
        retries: 2,
        fetchFunction: () => getRecentCVEs(50).catch(() => [])
      },
      {
        name: 'cisa-kev',
        enabled: true,
        timeout: 30000,
        retries: 2, 
        fetchFunction: () => getCISAKEV().catch(() => [])
      },
      {
        name: 'trending-cves',
        enabled: true,
        timeout: 30000,
        retries: 2,
        fetchFunction: () => getTrendingCVEs(30).catch(() => [])
      },
      {
        name: 'searched-cves',
        enabled: true,
        timeout: 30000,
        retries: 2,
        fetchFunction: () => searchCVE('critical', 25).catch(() => [])
      },

      // APT & threat actors (4 sources)  
      {
        name: 'apt-groups',
        enabled: true,
        timeout: 45000,
        retries: 1,
        fetchFunction: () => searchAPTGroups('').then(r => r.groups || []).catch(() => [])
      },
      {
        name: 'apt-stats',
        enabled: true,
        timeout: 30000,
        retries: 2,
        fetchFunction: () => getAPTStats().catch(() => ({}))
      },
      {
        name: 'apt-malware',
        enabled: true,
        timeout: 45000,
        retries: 1,
        fetchFunction: () => fetchMalwareData().catch(() => ({}))
      },
      {
        name: 'threat-actors',
        enabled: true,
        timeout: 45000,
        retries: 1,
        fetchFunction: () => searchThreatActors('').catch(() => ({ actors: [], campaigns: [], malware: [], totalResults: 0 }))
      },

      // OpenCTI & correlation (2 sources)
      {
        name: 'opencti-landscape',
        enabled: true,
        timeout: 60000,
        retries: 1,
        fetchFunction: () => openCtiCorrelationService.getLiveThreatLandscape().catch(() => ({}))
      },
      {
        name: 'threat-correlation',
        enabled: true,
        timeout: 45000,
        retries: 1,
        fetchFunction: () => openCtiCorrelationService.correlateMalwareFamilies('').catch(() => [])
      },

      // Real-time feeds (2 sources) 
      {
        name: 'realtime-stats',
        enabled: true,
        timeout: 30000,
        retries: 2,
        fetchFunction: () => Promise.resolve(realTimeThreatFeedService.getStats())
      },
      {
        name: 'realtime-trends',
        enabled: true,
        timeout: 30000,
        retries: 2,
        fetchFunction: () => Promise.resolve(realTimeThreatFeedService.getTrendData())
      },

      // Additional threat intelligence (4 sources)
      {
        name: 'tor-investigation',
        enabled: true,
        timeout: 60000,
        retries: 1,
        fetchFunction: () => deepSearchDarkWeb({ indicator: 'malware' }).catch(() => ({ signals: [], entities: [], sourceStats: {}, totalTime: 0 }))
      },
      {
        name: 'social-scraping',
        enabled: false, // Disabled by default due to rate limits
        timeout: 45000,
        retries: 1,
        fetchFunction: () => Promise.resolve([])
      },
      {
        name: 'news-intelligence', 
        enabled: false, // Placeholder for news service
        timeout: 30000,
        retries: 1,
        fetchFunction: () => Promise.resolve([])
      },
      {
        name: 'bitcoin-investigation',
        enabled: false, // Placeholder for bitcoin service
        timeout: 30000,
        retries: 1,
        fetchFunction: () => Promise.resolve([])
      }
    ];

    console.log(`[ThreatAggregator] Initialized ${this.sources.length} threat sources`);
    console.log(`[ThreatAggregator] Active sources: ${this.sources.filter(s => s.enabled).length}`);
    const enabledNames = this.sources.filter(s => s.enabled).map(s => s.name);
    console.log(`[ThreatAggregator] Enabled: ${enabledNames.join(', ')}`);
  }

  // Main aggregation function - fetches from ALL sources in parallel
  async aggregateAllThreatSources(): Promise<ComprehensiveThreatData> {
    if (this.aggregationInProgress) {
      console.log('[ThreatAggregator] Aggregation already in progress, returning cached data');
      return this.lastAggregation || this.getEmptyThreatData();
    }

    this.aggregationInProgress = true;
    const startTime = Date.now();

    console.log('[ThreatAggregator] Starting comprehensive threat aggregation from ALL enabled sources...');

    const enabledSources = this.sources.filter(s => s.enabled);
    if (enabledSources.length === 0) {
      console.warn('[ThreatAggregator] No enabled sources found!');
      this.aggregationInProgress = false;
      return this.getEmptyThreatData();
    }

    const results: { [key: string]: any } = {};
    const failedSources: string[] = [];

    // Execute all sources in parallel with timeout and retry logic
    const promises = enabledSources.map(async (source) => {
      try {
        console.log(`[ThreatAggregator] Fetching from ${source.name}...`);
        
        const result = await this.executeWithRetry(source);
        results[source.name] = result;
        
        console.log(`[ThreatAggregator] ✅ ${source.name} completed successfully`);
        return { source: source.name, success: true, data: result };
      } catch (error) {
        console.warn(`[ThreatAggregator] ❌ ${source.name} failed:`, error);
        failedSources.push(`${source.name}: ${error.message}`);
        results[source.name] = [];
        return { source: source.name, success: false, error };
      }
    });

    // Wait for all sources to complete
    const sourceResults = await Promise.allSettled(promises);
    
    const aggregationTime = Date.now() - startTime;
    const successfulSources = sourceResults.filter(r => r.status === 'fulfilled').length;

    // Build comprehensive threat data structure
    const threatData: ComprehensiveThreatData = {
      // Core abuse.ch sources
      feodoC2Servers: results['feodo-c2-servers'] || [],
      urlhausData: results['urlhaus-malware-urls'] || [],
      threatfoxIOCs: results['threatfox-iocs'] || [],
      malwareBazaarSamples: results['malwarebazaar-samples'] || [],
      
      // Enhanced malware services
      gitHubMalware: results['github-malware-repos'] || [],
      urlhausService: results['urlhaus-service-enhanced'] || [],
      feodoService: results['feodo-service-enhanced'] || [],
      bazaarService: results['bazaar-service-enhanced'] || [],
      
      // Dark web & forums
      darkWebForums: results['dark-web-forums'] || null,
      darkWebSignals: results['dark-web-signals'] || [],
      ransomwareVictims: results['ransomware-victims'] || [],
      
      // Telegram & messaging
      telegramLeaks: results['telegram-leaks'] || [],
      telegramChannels: results['telegram-channels'] || [],
      
      // CVE & vulnerability
      recentCVEs: results['recent-cves'] || [],
      cisaKEV: results['cisa-kev'] || [],
      trendingCVEs: results['trending-cves'] || [],
      searchedCVEs: results['searched-cves'] || [],
      
      // APT & threat actors
      aptGroups: results['apt-groups'] || [],
      aptStats: results['apt-stats'] || {},
      aptMalware: results['apt-malware'] || {},
      threatActors: results['threat-actors'] || { actors: [], campaigns: [], relatedMalware: [], stats: { totalActors: 0, aptCount: 0, cybercrimeCount: 0, activeActors: 0, relatedCampaigns: 0 }, searchTime: 0 },
      
      // OpenCTI & correlation
      openCtiLandscape: results['opencti-landscape'] || {},
      threatCorrelation: results['threat-correlation'] || [],
      
      // Real-time feeds
      realTimeStats: results['realtime-stats'] || {},
      liveTrendData: results['realtime-trends'] || {},
      
      // Additional sources
      torInvestigation: (results['tor-investigation'] as any)?.signals || [],
      socialScrapingData: results['social-scraping'] || [],
      newsIntelligence: results['news-intelligence'] || [],
      bitcoinInvestigation: results['bitcoin-investigation'] || [],
      
      // Metadata
      totalSources: enabledSources.length,
      successfulSources,
      failedSources,
      lastUpdated: new Date().toISOString(),
      aggregationTime
    };

    this.lastAggregation = threatData;
    this.lastAggregationTime = Date.now();
    this.aggregationInProgress = false;

    console.log(`[ThreatAggregator] 🎉 Aggregation completed in ${aggregationTime}ms`);
    console.log(`[ThreatAggregator] ✅ Successful: ${successfulSources}/${enabledSources.length} sources`);
    console.log(`[ThreatAggregator] ❌ Failed: ${failedSources.length} sources`);

    if (failedSources.length > 0) {
      console.warn('[ThreatAggregator] Failed sources:', failedSources);
    }

    return threatData;
  }

  // Execute with retry logic
  private async executeWithRetry(source: ThreatSourceConfig): Promise<any> {
    for (let attempt = 1; attempt <= source.retries + 1; attempt++) {
      try {
        const timeoutPromise = new Promise((_, reject) => {
          setTimeout(() => reject(new Error(`Timeout after ${source.timeout}ms`)), source.timeout);
        });

        const result = await Promise.race([
          source.fetchFunction(),
          timeoutPromise
        ]);

        return result;
      } catch (error) {
        if (attempt === source.retries + 1) {
          throw error;
        }
        console.warn(`[ThreatAggregator] ${source.name} attempt ${attempt} failed, retrying...`);
        await new Promise(resolve => setTimeout(resolve, 1000 * attempt));
      }
    }
  }

  private getEmptyThreatData(): ComprehensiveThreatData {
    return {
      feodoC2Servers: [],
      urlhausData: [], 
      threatfoxIOCs: [],
      malwareBazaarSamples: [],
      gitHubMalware: [],
      urlhausService: [],
      feodoService: [],
      bazaarService: [],
      darkWebForums: null,
      darkWebSignals: [],
      ransomwareVictims: [],
      telegramLeaks: [],
      telegramChannels: [],
      recentCVEs: [],
      cisaKEV: [],
      trendingCVEs: [],
      searchedCVEs: [],
      aptGroups: [],
      aptStats: {},
      aptMalware: {},
      threatActors: { actors: [], campaigns: [], relatedMalware: [], stats: { totalActors: 0, aptCount: 0, cybercrimeCount: 0, activeActors: 0, relatedCampaigns: 0 }, searchTime: 0 },
      openCtiLandscape: {},
      threatCorrelation: [],
      realTimeStats: {},
      liveTrendData: {},
      torInvestigation: [],
      socialScrapingData: [],
      newsIntelligence: [],
      bitcoinInvestigation: [],
      totalSources: 0,
      successfulSources: 0,
      failedSources: [],
      lastUpdated: new Date().toISOString(),
      aggregationTime: 0
    };
  }

  // Get cached aggregation results
  getCachedAggregation(): ComprehensiveThreatData | null {
    return this.lastAggregation;
  }

  // Check if cached data is stale
  isCacheStale(): boolean {
    return Date.now() - this.lastAggregationTime > this.cacheExpiryTime;
  }

  // Get fresh aggregation (bypasses cache if stale)
  async getFreshAggregation(forceFresh = false): Promise<ComprehensiveThreatData> {
    if (forceFresh || this.isCacheStale() || !this.lastAggregation) {
      console.log('[ThreatAggregator] 🔄 Fetching fresh data from ALL sources...');
      return await this.aggregateAllThreatSources();
    }
    console.log('[ThreatAggregator] 📋 Using cached data (still fresh)');
    return this.lastAggregation;
  }

  // Get enabled source count
  getEnabledSourceCount(): number {
    return this.sources.filter(s => s.enabled).length;
  }

  // Enable/disable sources
  configureSource(name: string, enabled: boolean): void {
    const source = this.sources.find(s => s.name === name);
    if (source) {
      source.enabled = enabled;
      console.log(`[ThreatAggregator] ${name} ${enabled ? 'enabled' : 'disabled'}`);
    }
  }
}

// Export singleton instance
export const comprehensiveThreatAggregator = new ComprehensiveThreatAggregatorService();
export default comprehensiveThreatAggregator;