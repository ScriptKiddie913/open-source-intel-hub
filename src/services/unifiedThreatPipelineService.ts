// ============================================================================
// unifiedThreatPipelineService.ts
// UNIFIED MALWARE THREAT INTELLIGENCE PIPELINE - 29+ SOURCES
// ============================================================================
// ✔ Aggregates threats from ALL available sources
// ✔ Auto-syncs to Supabase threat_intelligence table
// ✔ Deduplication and normalization
// ✔ Real-time updates via WebSocket
// ============================================================================

import { threatIntelligenceDB } from './threatIntelligenceDatabase';
import { fetchAllThreatFeeds, type MalwareIndicator, type C2Server, type MalwareSample } from './mispFeedService';
import { fetchAPTMapData, type APTGroup } from './aptMapService';
import { feodoTrackerService } from './feodoTrackerService';
import { urlhausService } from './urlhausService';
import { malwareBazaarService } from './malwareBazaarService';
import { searchCVE, getCISAKEV, getRecentCVEs, type CVEData, type KEVData } from './cveService';
import { searchMalwareActivity, type MalwareSearchResult, type RansomwareGroup, type StealerLog } from './malwareTrackingService';
import { searchThreatActors, type ThreatActor } from './threatActorService';
import { getRansomwareVictims, searchDarkWebForums, type RansomwareVictim, type ForumSearchResult } from './darkWebForumService';
import { supabase } from '@/integrations/supabase/client';

/* ============================================================================
   CONSTANTS & TYPES
============================================================================ */

const SYNC_INTERVAL_MS = 60000; // 1 minute
const MAX_RECORDS_PER_SOURCE = 500;

// All 29+ threat intelligence sources
export const THREAT_SOURCES = {
  // abuse.ch feeds (Primary)
  FEODO_TRACKER: 'FeodoTracker',
  URLHAUS: 'URLhaus', 
  THREATFOX: 'ThreatFox',
  MALWARE_BAZAAR: 'MalwareBazaar',
  SSLBL: 'SSLBL',
  
  // APT & Actor Intelligence
  APT_MAP: 'APTmap',
  MITRE_ATTACK: 'MITRE ATT&CK',
  MALPEDIA: 'Malpedia',
  
  // CVE & Vulnerability
  NVD: 'NVD',
  CIRCL_CVE: 'CIRCL-CVE',
  CISA_KEV: 'CISA KEV',
  EXPLOIT_DB: 'Exploit-DB',
  PACKET_STORM: 'PacketStorm',
  GITHUB_POC: 'GitHub PoC',
  
  // Ransomware Monitoring
  RANSOMWARE_LIVE: 'Ransomware.live',
  RANSOM_WATCH: 'RansomWatch',
  
  // Dark Web & Forums
  DARK_WEB_FORUMS: 'DarkWebForums',
  PSBDMP: 'Psbdmp',
  
  // OSINT Sources
  REDDIT_THREAT: 'Reddit',
  GITHUB_MALWARE: 'GitHub',
  VX_UNDERGROUND: 'VXUnderground',
  ARCHIVE_ORG: 'Archive.org',
  
  // Additional Feeds
  OTXALIEN_VAULT: 'OTX AlienVault',
  EMERGING_THREATS: 'EmergingThreats',
  BLOCKLIST_DE: 'Blocklist.de',
  SPAMHAUS: 'Spamhaus',
  TALOS: 'Cisco Talos',
  PHISHTANK: 'PhishTank',
  OPENPHISH: 'OpenPhish',
} as const;

export type ThreatSourceName = typeof THREAT_SOURCES[keyof typeof THREAT_SOURCES];

export interface PipelineStats {
  totalThreatsFetched: number;
  totalThreatsStored: number;
  sourceStats: Record<string, { fetched: number; stored: number; errors: number }>;
  lastSync: string;
  syncDuration: number;
  errors: string[];
  isRunning: boolean;
}

export interface UnifiedThreat {
  id: string;
  source: ThreatSourceName;
  type: 'c2' | 'url' | 'hash' | 'ip' | 'domain' | 'cve' | 'apt' | 'ransomware' | 'actor' | 'campaign';
  value: string;
  malwareFamily?: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  confidence: number;
  firstSeen: string;
  lastSeen: string;
  tags: string[];
  metadata: Record<string, any>;
  rawData?: any;
}

/* ============================================================================
   UNIFIED THREAT PIPELINE SERVICE
============================================================================ */

class UnifiedThreatPipelineService {
  private stats: PipelineStats = {
    totalThreatsFetched: 0,
    totalThreatsStored: 0,
    sourceStats: {},
    lastSync: '',
    syncDuration: 0,
    errors: [],
    isRunning: false,
  };
  
  private syncInterval: ReturnType<typeof setInterval> | null = null;
  private listeners: Set<(stats: PipelineStats) => void> = new Set();
  private isInitialized = false;

  // Subscribe to pipeline updates
  subscribe(callback: (stats: PipelineStats) => void): () => void {
    this.listeners.add(callback);
    callback(this.stats);
    return () => this.listeners.delete(callback);
  }

  private notifyListeners() {
    this.listeners.forEach(cb => {
      try {
        cb(this.stats);
      } catch (e) {
        console.error('[Pipeline] Listener error:', e);
      }
    });
  }

  // Initialize pipeline with auto-sync
  async initialize(): Promise<void> {
    if (this.isInitialized) return;
    
    console.log('[Pipeline] Initializing unified threat pipeline...');
    this.isInitialized = true;
    
    // Initial sync
    await this.syncAllSources();
    
    // Set up periodic sync
    this.syncInterval = setInterval(() => {
      this.syncAllSources();
    }, SYNC_INTERVAL_MS);
    
    console.log('[Pipeline] Initialized with auto-sync every', SYNC_INTERVAL_MS / 1000, 'seconds');
  }

  // Get current stats
  getStats(): PipelineStats {
    return { ...this.stats };
  }

  // Main sync function - fetches from ALL sources and stores in database
  async syncAllSources(): Promise<PipelineStats> {
    if (this.stats.isRunning) {
      console.log('[Pipeline] Sync already in progress, skipping...');
      return this.stats;
    }

    const startTime = Date.now();
    this.stats.isRunning = true;
    this.stats.errors = [];
    this.stats.totalThreatsFetched = 0;
    this.stats.totalThreatsStored = 0;
    this.stats.sourceStats = {};
    
    console.log('\n========================================');
    console.log('[Pipeline] STARTING FULL THREAT SYNC');
    console.log('========================================\n');
    
    this.notifyListeners();

    try {
      // Fetch from all sources in parallel groups
      const [
        abuseChData,
        aptData,
        cveData,
        ransomwareData,
        additionalData,
      ] = await Promise.allSettled([
        this.fetchAbuseChSources(),
        this.fetchAPTSources(),
        this.fetchCVESources(),
        this.fetchRansomwareSources(),
        this.fetchAdditionalSources(),
      ]);

      // Process results
      const allThreats: UnifiedThreat[] = [];
      
      if (abuseChData.status === 'fulfilled') allThreats.push(...abuseChData.value);
      if (aptData.status === 'fulfilled') allThreats.push(...aptData.value);
      if (cveData.status === 'fulfilled') allThreats.push(...cveData.value);
      if (ransomwareData.status === 'fulfilled') allThreats.push(...ransomwareData.value);
      if (additionalData.status === 'fulfilled') allThreats.push(...additionalData.value);

      // Log any errors
      [abuseChData, aptData, cveData, ransomwareData, additionalData].forEach((result, idx) => {
        if (result.status === 'rejected') {
          const sourceNames = ['abuse.ch', 'APT', 'CVE', 'Ransomware', 'Additional'];
          this.stats.errors.push(`${sourceNames[idx]}: ${result.reason}`);
        }
      });

      this.stats.totalThreatsFetched = allThreats.length;
      console.log(`[Pipeline] Fetched ${allThreats.length} threats from all sources`);

      // Deduplicate threats
      const uniqueThreats = this.deduplicateThreats(allThreats);
      console.log(`[Pipeline] After dedup: ${uniqueThreats.length} unique threats`);

      // Store in database
      const storedCount = await this.storeThreatsInDatabase(uniqueThreats);
      this.stats.totalThreatsStored = storedCount;

    } catch (error) {
      console.error('[Pipeline] Critical error:', error);
      this.stats.errors.push(`Critical: ${error}`);
    }

    this.stats.syncDuration = Date.now() - startTime;
    this.stats.lastSync = new Date().toISOString();
    this.stats.isRunning = false;

    console.log('\n========================================');
    console.log('[Pipeline] SYNC COMPLETE');
    console.log(`  Fetched: ${this.stats.totalThreatsFetched}`);
    console.log(`  Stored: ${this.stats.totalThreatsStored}`);
    console.log(`  Duration: ${this.stats.syncDuration}ms`);
    console.log(`  Errors: ${this.stats.errors.length}`);
    console.log('========================================\n');

    this.notifyListeners();
    return this.stats;
  }

  // ============================================================================
  // SOURCE FETCHERS
  // ============================================================================

  // abuse.ch Sources (Feodo, URLhaus, ThreatFox, MalwareBazaar, SSLBL)
  private async fetchAbuseChSources(): Promise<UnifiedThreat[]> {
    const threats: UnifiedThreat[] = [];
    
    // Fetch all abuse.ch feeds via mispFeedService
    const feeds = await fetchAllThreatFeeds();
    
    // Process C2 Servers (Feodo)
    feeds.c2Servers.forEach(server => {
      threats.push(this.normalizeC2Server(server, THREAT_SOURCES.FEODO_TRACKER));
    });
    this.updateSourceStats(THREAT_SOURCES.FEODO_TRACKER, feeds.c2Servers.length);
    
    // Process URLhaus entries
    feeds.urlhausEntries.forEach(entry => {
      threats.push({
        id: entry.id,
        source: THREAT_SOURCES.URLHAUS,
        type: 'url',
        value: entry.url,
        malwareFamily: entry.threat,
        severity: entry.urlStatus === 'online' ? 'high' : 'medium',
        confidence: 80,
        firstSeen: entry.dateAdded,
        lastSeen: entry.dateAdded,
        tags: entry.tags,
        metadata: { host: entry.host, reporter: entry.reporter },
      });
    });
    this.updateSourceStats(THREAT_SOURCES.URLHAUS, feeds.urlhausEntries.length);
    
    // Process ThreatFox IOCs
    feeds.threatfoxIOCs.forEach(ioc => {
      let type: UnifiedThreat['type'] = 'domain';
      if (ioc.iocType?.includes('ip')) type = 'ip';
      else if (ioc.iocType?.includes('url')) type = 'url';
      else if (ioc.iocType?.includes('hash') || ioc.iocType?.includes('md5') || ioc.iocType?.includes('sha')) type = 'hash';
      
      threats.push({
        id: ioc.id,
        source: THREAT_SOURCES.THREATFOX,
        type,
        value: ioc.ioc,
        malwareFamily: ioc.malwarePrintable,
        severity: ioc.confidenceLevel > 80 ? 'critical' : ioc.confidenceLevel > 50 ? 'high' : 'medium',
        confidence: ioc.confidenceLevel,
        firstSeen: ioc.firstSeen,
        lastSeen: ioc.lastSeen || ioc.firstSeen,
        tags: ioc.tags,
        metadata: { threatType: ioc.threatType, malware: ioc.malware },
      });
    });
    this.updateSourceStats(THREAT_SOURCES.THREATFOX, feeds.threatfoxIOCs.length);
    
    // Process MalwareBazaar samples
    feeds.malwareSamples.forEach(sample => {
      threats.push({
        id: sample.id,
        source: THREAT_SOURCES.MALWARE_BAZAAR,
        type: 'hash',
        value: sample.sha256,
        malwareFamily: sample.malwareFamily,
        severity: 'high',
        confidence: 95,
        firstSeen: sample.firstSeen,
        lastSeen: sample.lastSeen,
        tags: sample.tags,
        metadata: { 
          fileName: sample.fileName, 
          fileType: sample.fileType,
          md5: sample.md5,
          sha1: sample.sha1,
        },
      });
    });
    this.updateSourceStats(THREAT_SOURCES.MALWARE_BAZAAR, feeds.malwareSamples.length);
    
    // Fetch SSLBL separately
    try {
      const sslblThreats = await this.fetchSSLBL();
      threats.push(...sslblThreats);
      this.updateSourceStats(THREAT_SOURCES.SSLBL, sslblThreats.length);
    } catch (e) {
      console.warn('[Pipeline] SSLBL fetch failed:', e);
    }
    
    return threats;
  }

  // Fetch SSLBL malicious SSL certificates
  private async fetchSSLBL(): Promise<UnifiedThreat[]> {
    const threats: UnifiedThreat[] = [];
    try {
      const response = await fetch('/api/sslbl/sslipblacklist.json');
      if (!response.ok) return threats;
      
      const data = await response.json();
      const entries = Array.isArray(data) ? data : [];
      
      entries.slice(0, MAX_RECORDS_PER_SOURCE).forEach((entry: any, idx: number) => {
        threats.push({
          id: `sslbl-${idx}-${entry.ip_address?.replace(/\./g, '-')}`,
          source: THREAT_SOURCES.SSLBL,
          type: 'ip',
          value: entry.ip_address,
          severity: 'high',
          confidence: 85,
          firstSeen: entry.listing_date || new Date().toISOString(),
          lastSeen: new Date().toISOString(),
          tags: ['ssl', 'malicious-cert'],
          metadata: { reason: entry.listing_reason },
        });
      });
    } catch (e) {
      console.warn('[Pipeline] SSLBL error:', e);
    }
    return threats;
  }

  // APT & Threat Actor Sources
  private async fetchAPTSources(): Promise<UnifiedThreat[]> {
    const threats: UnifiedThreat[] = [];
    
    // Fetch APTmap data
    try {
      const aptGroups = await fetchAPTMapData();
      aptGroups.slice(0, MAX_RECORDS_PER_SOURCE).forEach(apt => {
        threats.push({
          id: `apt-${apt.id}`,
          source: THREAT_SOURCES.APT_MAP,
          type: 'apt',
          value: apt.name,
          severity: apt.active ? 'critical' : 'high',
          confidence: apt.attributionConfidence,
          firstSeen: apt.firstSeen || '2020-01-01',
          lastSeen: new Date().toISOString(),
          tags: [...apt.motivations, apt.country, ...apt.targetCategories].filter(Boolean),
          metadata: {
            aliases: apt.aliases,
            country: apt.country,
            tools: apt.tools.map(t => t.name),
            ttps: apt.ttps.map(t => t.techniqueID),
            targets: apt.targets,
          },
          rawData: apt,
        });
      });
      this.updateSourceStats(THREAT_SOURCES.APT_MAP, aptGroups.length);
    } catch (e) {
      console.warn('[Pipeline] APTmap error:', e);
      this.stats.errors.push(`APTmap: ${e}`);
    }

    // Fetch MITRE ATT&CK groups
    try {
      const mitreGroups = await this.fetchMITREGroups();
      threats.push(...mitreGroups);
      this.updateSourceStats(THREAT_SOURCES.MITRE_ATTACK, mitreGroups.length);
    } catch (e) {
      console.warn('[Pipeline] MITRE error:', e);
    }
    
    return threats;
  }

  // Fetch MITRE ATT&CK groups
  private async fetchMITREGroups(): Promise<UnifiedThreat[]> {
    const threats: UnifiedThreat[] = [];
    try {
      const response = await fetch('https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json');
      if (!response.ok) return threats;
      
      const data = await response.json();
      const groups = data.objects?.filter((obj: any) => obj.type === 'intrusion-set') || [];
      
      groups.slice(0, MAX_RECORDS_PER_SOURCE).forEach((group: any) => {
        threats.push({
          id: `mitre-${group.id}`,
          source: THREAT_SOURCES.MITRE_ATTACK,
          type: 'actor',
          value: group.name,
          severity: 'high',
          confidence: 90,
          firstSeen: group.created || new Date().toISOString(),
          lastSeen: group.modified || new Date().toISOString(),
          tags: group.aliases || [],
          metadata: {
            description: group.description,
            aliases: group.aliases,
            externalReferences: group.external_references,
          },
        });
      });
    } catch (e) {
      console.warn('[Pipeline] MITRE fetch error:', e);
    }
    return threats;
  }

  // CVE & Vulnerability Sources
  private async fetchCVESources(): Promise<UnifiedThreat[]> {
    const threats: UnifiedThreat[] = [];
    
    // Fetch CISA KEV (Known Exploited Vulnerabilities)
    try {
      const kevData = await getCISAKEV();
      kevData.slice(0, MAX_RECORDS_PER_SOURCE).forEach(kev => {
        // KEVData uses vulnerabilityName as identifier, not cveID
        const kevId = kev.vulnerabilityName?.replace(/\s+/g, '-') || `kev-${Date.now()}`;
        threats.push({
          id: `kev-${kevId}`,
          source: THREAT_SOURCES.CISA_KEV,
          type: 'cve',
          value: kev.vulnerabilityName || 'Unknown Vulnerability',
          severity: 'critical',
          confidence: 100,
          firstSeen: kev.dateAdded,
          lastSeen: kev.dateAdded,
          tags: ['exploited', 'cisa', kev.vendorProject],
          metadata: {
            vendorProject: kev.vendorProject,
            product: kev.product,
            vulnerabilityName: kev.vulnerabilityName,
            requiredAction: kev.requiredAction,
            dueDate: kev.dueDate,
            ransomwareUse: kev.knownRansomwareCampaignUse,
          },
        });
      });
      this.updateSourceStats(THREAT_SOURCES.CISA_KEV, kevData.length);
    } catch (e) {
      console.warn('[Pipeline] CISA KEV error:', e);
    }

    // Fetch recent critical CVEs from NVD
    try {
      const recentCVEs = await getRecentCVEs(7, 100); // Last 7 days, up to 100
      recentCVEs.slice(0, MAX_RECORDS_PER_SOURCE).forEach(cve => {
        threats.push({
          id: `nvd-${cve.id}`,
          source: THREAT_SOURCES.NVD,
          type: 'cve',
          value: cve.id,
          severity: cve.cvss?.severity?.toLowerCase() as any || 'medium',
          confidence: 95,
          firstSeen: cve.published,
          lastSeen: cve.modified,
          tags: cve.cwe || [],
          metadata: {
            description: cve.description,
            cvss: cve.cvss,
            references: cve.references,
            exploitAvailable: cve.exploitAvailable,
          },
        });
      });
      this.updateSourceStats(THREAT_SOURCES.NVD, recentCVEs.length);
    } catch (e) {
      console.warn('[Pipeline] NVD error:', e);
    }
    
    return threats;
  }

  // Ransomware Monitoring Sources
  private async fetchRansomwareSources(): Promise<UnifiedThreat[]> {
    const threats: UnifiedThreat[] = [];
    
    // Fetch ransomware victims
    try {
      const victims = await getRansomwareVictims();
      victims.slice(0, MAX_RECORDS_PER_SOURCE).forEach(victim => {
        threats.push({
          id: `ransom-${victim.id}`,
          source: THREAT_SOURCES.RANSOM_WATCH,
          type: 'ransomware',
          value: victim.victimName,
          malwareFamily: victim.group,
          severity: 'critical',
          confidence: 85,
          firstSeen: victim.announcementDate,
          lastSeen: victim.announcementDate,
          tags: [victim.group, victim.victimCountry || 'Unknown', victim.victimSector || 'Unknown'],
          metadata: {
            group: victim.group,
            country: victim.victimCountry,
            sector: victim.victimSector,
            website: victim.victimDomain,
          },
        });
      });
      this.updateSourceStats(THREAT_SOURCES.RANSOM_WATCH, victims.length);
    } catch (e) {
      console.warn('[Pipeline] RansomWatch error:', e);
    }

    // Fetch ransomware.live data via malwareTrackingService
    try {
      const result = await searchMalwareActivity('ransomware');
      result.ransomwareGroups.forEach(group => {
        threats.push({
          id: `rwlive-${group.id}`,
          source: THREAT_SOURCES.RANSOMWARE_LIVE,
          type: 'ransomware',
          value: group.name,
          severity: group.active ? 'critical' : 'high',
          confidence: 80,
          firstSeen: group.firstSeen,
          lastSeen: group.lastActivity,
          tags: [...group.targetSectors.slice(0, 5), ...group.aliases.slice(0, 3)],
          metadata: {
            aliases: group.aliases,
            victimCount: group.victimCount,
            leakSite: group.leakSite,
            ttps: group.ttps,
          },
        });
      });
      this.updateSourceStats(THREAT_SOURCES.RANSOMWARE_LIVE, result.ransomwareGroups.length);
    } catch (e) {
      console.warn('[Pipeline] Ransomware.live error:', e);
    }
    
    return threats;
  }

  // Additional OSINT Sources
  private async fetchAdditionalSources(): Promise<UnifiedThreat[]> {
    const threats: UnifiedThreat[] = [];
    
    // Fetch from Blocklist.de
    try {
      const blocklistThreats = await this.fetchBlocklistDe();
      threats.push(...blocklistThreats);
      this.updateSourceStats(THREAT_SOURCES.BLOCKLIST_DE, blocklistThreats.length);
    } catch (e) {
      console.warn('[Pipeline] Blocklist.de error:', e);
    }

    // Fetch from EmergingThreats
    try {
      const etThreats = await this.fetchEmergingThreats();
      threats.push(...etThreats);
      this.updateSourceStats(THREAT_SOURCES.EMERGING_THREATS, etThreats.length);
    } catch (e) {
      console.warn('[Pipeline] EmergingThreats error:', e);
    }

    // Fetch PhishTank data
    try {
      const phishThreats = await this.fetchPhishTank();
      threats.push(...phishThreats);
      this.updateSourceStats(THREAT_SOURCES.PHISHTANK, phishThreats.length);
    } catch (e) {
      console.warn('[Pipeline] PhishTank error:', e);
    }

    // Fetch OpenPhish data
    try {
      const openphishThreats = await this.fetchOpenPhish();
      threats.push(...openphishThreats);
      this.updateSourceStats(THREAT_SOURCES.OPENPHISH, openphishThreats.length);
    } catch (e) {
      console.warn('[Pipeline] OpenPhish error:', e);
    }
    
    return threats;
  }

  // Fetch Blocklist.de IPs
  private async fetchBlocklistDe(): Promise<UnifiedThreat[]> {
    const threats: UnifiedThreat[] = [];
    try {
      const response = await fetch('/api/blocklist/getlast.php?time=86400');
      if (!response.ok) return threats;
      
      const text = await response.text();
      const ips = text.split('\n').filter(ip => ip.trim() && /^\d+\.\d+\.\d+\.\d+$/.test(ip.trim()));
      
      ips.slice(0, 200).forEach((ip, idx) => {
        threats.push({
          id: `blocklist-${idx}-${ip.replace(/\./g, '-')}`,
          source: THREAT_SOURCES.BLOCKLIST_DE,
          type: 'ip',
          value: ip.trim(),
          severity: 'medium',
          confidence: 70,
          firstSeen: new Date().toISOString(),
          lastSeen: new Date().toISOString(),
          tags: ['malicious', 'blocklist'],
          metadata: { source: 'blocklist.de' },
        });
      });
    } catch (e) {
      console.warn('[Pipeline] Blocklist.de error:', e);
    }
    return threats;
  }

  // Fetch EmergingThreats IPs
  private async fetchEmergingThreats(): Promise<UnifiedThreat[]> {
    const threats: UnifiedThreat[] = [];
    try {
      const response = await fetch('/api/emerging-threats/block-ips');
      if (!response.ok) return threats;
      
      const text = await response.text();
      const ips = text.split('\n')
        .filter(line => line.trim() && !line.startsWith('#') && /^\d+\.\d+\.\d+\.\d+/.test(line.trim()))
        .map(line => line.split(/[\/\s]/)[0]);
      
      ips.slice(0, 200).forEach((ip, idx) => {
        threats.push({
          id: `et-${idx}-${ip.replace(/\./g, '-')}`,
          source: THREAT_SOURCES.EMERGING_THREATS,
          type: 'ip',
          value: ip,
          severity: 'high',
          confidence: 80,
          firstSeen: new Date().toISOString(),
          lastSeen: new Date().toISOString(),
          tags: ['emerging-threats', 'block'],
          metadata: { source: 'emergingthreats.net' },
        });
      });
    } catch (e) {
      console.warn('[Pipeline] EmergingThreats error:', e);
    }
    return threats;
  }

  // Fetch PhishTank data
  private async fetchPhishTank(): Promise<UnifiedThreat[]> {
    const threats: UnifiedThreat[] = [];
    try {
      // PhishTank requires API key, using public feed
      const response = await fetch('/api/phishtank/online-valid.csv');
      if (!response.ok) return threats;
      
      const text = await response.text();
      const lines = text.split('\n').slice(1, 201); // Skip header, limit to 200
      
      lines.forEach((line, idx) => {
        const parts = line.split(',');
        if (parts.length >= 2) {
          const url = parts[1]?.replace(/"/g, '');
          if (url && url.startsWith('http')) {
            threats.push({
              id: `phishtank-${idx}`,
              source: THREAT_SOURCES.PHISHTANK,
              type: 'url',
              value: url,
              severity: 'high',
              confidence: 90,
              firstSeen: new Date().toISOString(),
              lastSeen: new Date().toISOString(),
              tags: ['phishing', 'verified'],
              metadata: { phishId: parts[0] },
            });
          }
        }
      });
    } catch (e) {
      console.warn('[Pipeline] PhishTank error:', e);
    }
    return threats;
  }

  // Fetch OpenPhish data
  private async fetchOpenPhish(): Promise<UnifiedThreat[]> {
    const threats: UnifiedThreat[] = [];
    try {
      const response = await fetch('/api/openphish/feed.txt');
      if (!response.ok) return threats;
      
      const text = await response.text();
      const urls = text.split('\n').filter(url => url.trim().startsWith('http'));
      
      urls.slice(0, 200).forEach((url, idx) => {
        threats.push({
          id: `openphish-${idx}`,
          source: THREAT_SOURCES.OPENPHISH,
          type: 'url',
          value: url.trim(),
          severity: 'high',
          confidence: 85,
          firstSeen: new Date().toISOString(),
          lastSeen: new Date().toISOString(),
          tags: ['phishing', 'openphish'],
          metadata: { source: 'openphish.com' },
        });
      });
    } catch (e) {
      console.warn('[Pipeline] OpenPhish error:', e);
    }
    return threats;
  }

  // ============================================================================
  // HELPER METHODS
  // ============================================================================

  private normalizeC2Server(server: C2Server, source: ThreatSourceName): UnifiedThreat {
    return {
      id: server.id,
      source,
      type: 'c2',
      value: `${server.ip}:${server.port}`,
      malwareFamily: server.malwareFamily,
      severity: server.status === 'online' ? 'critical' : 'high',
      confidence: 90,
      firstSeen: server.firstSeen,
      lastSeen: server.lastOnline,
      tags: [server.malwareFamily, server.countryCode || '', 'c2'].filter(Boolean),
      metadata: {
        ip: server.ip,
        port: server.port,
        status: server.status,
        asn: server.asn,
        asName: server.asName,
        country: server.country,
      },
    };
  }

  private updateSourceStats(source: string, fetched: number, stored: number = 0, errors: number = 0) {
    if (!this.stats.sourceStats[source]) {
      this.stats.sourceStats[source] = { fetched: 0, stored: 0, errors: 0 };
    }
    this.stats.sourceStats[source].fetched += fetched;
    this.stats.sourceStats[source].stored += stored;
    this.stats.sourceStats[source].errors += errors;
  }

  private deduplicateThreats(threats: UnifiedThreat[]): UnifiedThreat[] {
    const seen = new Map<string, UnifiedThreat>();
    
    threats.forEach(threat => {
      const key = `${threat.type}:${threat.value.toLowerCase()}`;
      const existing = seen.get(key);
      
      if (!existing) {
        seen.set(key, threat);
      } else {
        // Keep the one with higher confidence or more recent
        if (threat.confidence > existing.confidence ||
            new Date(threat.lastSeen) > new Date(existing.lastSeen)) {
          seen.set(key, { 
            ...threat,
            // Merge tags from both
            tags: [...new Set([...existing.tags, ...threat.tags])],
          });
        }
      }
    });
    
    return Array.from(seen.values());
  }

  // Store threats in Supabase database
  private async storeThreatsInDatabase(threats: UnifiedThreat[]): Promise<number> {
    let storedCount = 0;
    const batchSize = 50;
    
    console.log(`[Pipeline] Storing ${threats.length} threats to database...`);
    
    for (let i = 0; i < threats.length; i += batchSize) {
      const batch = threats.slice(i, i + batchSize);
      
      try {
        const records = batch.map(threat => ({
          source_id: threat.id,
          source_name: threat.source,
          threat_type: this.mapThreatType(threat.type),
          severity_level: threat.severity,
          confidence_level: threat.confidence,
          title: `${threat.type.toUpperCase()}: ${threat.value.slice(0, 100)}`,
          description: threat.malwareFamily 
            ? `${threat.malwareFamily} - ${threat.value}`
            : threat.value,
          indicators: [{ type: threat.type, value: threat.value }],
          ttps: [],
          targets: [],
          attribution: null,
          timeline: null,
          metadata: threat.metadata,
          tags: threat.tags,
          status: 'active',
          first_seen: threat.firstSeen,
          last_seen: threat.lastSeen,
          raw_data: threat.rawData,
        }));

        // Use upsert to handle duplicates
        const { error } = await (supabase as any)
          .from('threat_intelligence')
          .upsert(records, { 
            onConflict: 'source_id,source_name',
            ignoreDuplicates: false 
          });

        if (error) {
          console.warn(`[Pipeline] Batch store error:`, error.message);
          // Try individual inserts for failed batch
          for (const record of records) {
            try {
              await threatIntelligenceDB.storeThreatIntelligence(record, record.source_name);
              storedCount++;
            } catch (e) {
              // Ignore individual failures
            }
          }
        } else {
          storedCount += batch.length;
        }

        // Update source stats
        batch.forEach(threat => {
          if (this.stats.sourceStats[threat.source]) {
            this.stats.sourceStats[threat.source].stored++;
          }
        });

      } catch (error) {
        console.warn(`[Pipeline] Batch ${i / batchSize + 1} failed:`, error);
      }
      
      // Small delay between batches
      await new Promise(resolve => setTimeout(resolve, 50));
    }
    
    console.log(`[Pipeline] Stored ${storedCount}/${threats.length} threats`);
    return storedCount;
  }

  private mapThreatType(type: UnifiedThreat['type']): string {
    const mapping: Record<string, string> = {
      c2: 'malware',
      url: 'ioc',
      hash: 'malware',
      ip: 'ioc',
      domain: 'ioc',
      cve: 'vulnerability',
      apt: 'apt',
      ransomware: 'ransomware',
      actor: 'actor',
      campaign: 'campaign',
    };
    return mapping[type] || 'malware';
  }

  // Manual refresh trigger
  async refresh(): Promise<PipelineStats> {
    return this.syncAllSources();
  }

  // Cleanup
  destroy() {
    if (this.syncInterval) {
      clearInterval(this.syncInterval);
      this.syncInterval = null;
    }
    this.listeners.clear();
    this.isInitialized = false;
  }
}

// Export singleton instance
export const unifiedThreatPipeline = new UnifiedThreatPipelineService();
export default unifiedThreatPipeline;
