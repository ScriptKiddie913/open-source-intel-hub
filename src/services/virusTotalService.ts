// ============================================================================
// virusTotalService.ts
// REAL-TIME MALWARE DATA FETCHING SERVICE
// ============================================================================
// ✔ Fetches latest malware data from public threat intelligence APIs
// ✔ Auto-refresh with configurable intervals
// ✔ Database persistence for continuous updates
// ✔ No data deletion - only appends and updates
// ============================================================================

import { supabase } from '@/integrations/supabase/client';

/* ============================================================================
   TYPES
============================================================================ */

export interface MalwareSample {
  id: string;
  sha256: string;
  sha1?: string;
  md5?: string;
  fileName?: string;
  fileType?: string;
  fileSize?: number;
  malwareFamily?: string;
  tags: string[];
  firstSeen: string;
  lastSeen: string;
  source: string;
  confidence: number;
  severity: 'critical' | 'high' | 'medium' | 'low';
  metadata: Record<string, any>;
}

export interface ThreatIndicator {
  id: string;
  type: 'hash' | 'ip' | 'domain' | 'url' | 'c2';
  value: string;
  malwareFamily?: string;
  threatType?: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  confidence: number;
  firstSeen: string;
  lastSeen: string;
  source: string;
  tags: string[];
  metadata: Record<string, any>;
}

export interface C2Server {
  id: string;
  ip: string;
  port: number;
  malwareFamily: string;
  status: 'active' | 'inactive' | 'sinkholed';
  firstSeen: string;
  lastSeen: string;
  country?: string;
  asn?: string;
  source: string;
}

export interface FeedStats {
  totalIndicators: number;
  newIndicators: number;
  updatedIndicators: number;
  byType: Record<string, number>;
  bySeverity: Record<string, number>;
  bySource: Record<string, number>;
  lastRefresh: string;
}

/* ============================================================================
   CONFIGURATION
============================================================================ */

const REFRESH_INTERVAL = 5 * 60 * 1000; // 5 minutes
const FEEDS_CONFIG = {
  // Abuse.ch feeds (public, no API key required)
  feodoTracker: 'https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json',
  urlhaus: 'https://urlhaus.abuse.ch/downloads/json_recent/',
  threatfox: 'https://threatfox.abuse.ch/export/json/recent/',
  malwareBazaar: 'https://mb-api.abuse.ch/api/v1/',
  sslBlacklist: 'https://sslbl.abuse.ch/blacklist/sslipblacklist.json',
  
  // Alternative threat intelligence (public)
  otxAlienVault: 'https://otx.alienvault.com/api/v1/pulses/subscribed',
  emergingThreats: 'https://rules.emergingthreats.net/blockrules/compromised-ips.txt',
};

// Local cache to prevent duplicate processing
const processedIndicators = new Set<string>();
let refreshTimer: number | null = null;
let isRefreshing = false;

/* ============================================================================
   PUBLIC API FEED FETCHERS
============================================================================ */

/**
 * Fetch C2 servers from Feodo Tracker (Abuse.ch)
 */
async function fetchFeodoTrackerData(): Promise<C2Server[]> {
  try {
    const response = await fetch(FEEDS_CONFIG.feodoTracker);
    if (!response.ok) throw new Error(`Feodo fetch failed: ${response.status}`);
    
    const data = await response.json();
    const servers: C2Server[] = [];
    
    // Process Feodo data format
    if (Array.isArray(data)) {
      data.forEach((entry: any) => {
        const id = `feodo-${entry.ip_address}-${entry.port}`;
        if (!processedIndicators.has(id)) {
          processedIndicators.add(id);
          servers.push({
            id,
            ip: entry.ip_address || entry.ip,
            port: parseInt(entry.port) || 443,
            malwareFamily: entry.malware || entry.malware_printable || 'Unknown',
            status: entry.status === 'online' ? 'active' : 'inactive',
            firstSeen: entry.first_seen || new Date().toISOString(),
            lastSeen: entry.last_online || new Date().toISOString(),
            country: entry.country,
            asn: entry.as_number,
            source: 'Feodo Tracker',
          });
        }
      });
    }
    
    console.log(`[VirusTotal] Fetched ${servers.length} C2 servers from Feodo Tracker`);
    return servers;
  } catch (error) {
    console.error('[VirusTotal] Feodo Tracker fetch error:', error);
    return [];
  }
}

/**
 * Fetch malicious URLs from URLhaus (Abuse.ch)
 */
async function fetchURLhausData(): Promise<ThreatIndicator[]> {
  try {
    const response = await fetch(FEEDS_CONFIG.urlhaus, {
      method: 'GET',
      headers: { 'Accept': 'application/json' },
    });
    
    if (!response.ok) throw new Error(`URLhaus fetch failed: ${response.status}`);
    
    const data = await response.json();
    const indicators: ThreatIndicator[] = [];
    
    // URLhaus returns { urls: [...] } or array directly
    const urls = data.urls || data;
    
    if (Array.isArray(urls)) {
      urls.forEach((entry: any) => {
        const id = `urlhaus-${entry.id || entry.url_id}`;
        if (!processedIndicators.has(id)) {
          processedIndicators.add(id);
          
          const threat = entry.threat || 'malware_download';
          const severity = threat.includes('ransomware') ? 'critical' :
                          threat.includes('c2') ? 'high' :
                          threat.includes('phishing') ? 'medium' : 'high';
          
          indicators.push({
            id,
            type: 'url',
            value: entry.url,
            malwareFamily: entry.tags?.[0] || undefined,
            threatType: threat,
            severity,
            confidence: 85,
            firstSeen: entry.dateadded || entry.date_added || new Date().toISOString(),
            lastSeen: new Date().toISOString(),
            source: 'URLhaus',
            tags: entry.tags || [],
            metadata: {
              host: entry.host,
              urlStatus: entry.url_status,
              reporter: entry.reporter,
            },
          });
        }
      });
    }
    
    console.log(`[VirusTotal] Fetched ${indicators.length} URLs from URLhaus`);
    return indicators;
  } catch (error) {
    console.error('[VirusTotal] URLhaus fetch error:', error);
    return [];
  }
}

/**
 * Fetch IOCs from ThreatFox (Abuse.ch)
 */
async function fetchThreatFoxData(): Promise<ThreatIndicator[]> {
  try {
    const response = await fetch(FEEDS_CONFIG.threatfox);
    if (!response.ok) throw new Error(`ThreatFox fetch failed: ${response.status}`);
    
    const data = await response.json();
    const indicators: ThreatIndicator[] = [];
    
    // ThreatFox returns { query_status: "ok", data: [...] }
    const iocs = data.data || data;
    
    if (Array.isArray(iocs)) {
      iocs.forEach((entry: any) => {
        const id = `threatfox-${entry.id || entry.ioc_id}`;
        if (!processedIndicators.has(id)) {
          processedIndicators.add(id);
          
          const iocType = entry.ioc_type || 'unknown';
          const type = iocType.includes('ip') ? 'ip' :
                      iocType.includes('domain') ? 'domain' :
                      iocType.includes('url') ? 'url' :
                      iocType.includes('hash') ? 'hash' : 'c2';
          
          const severity = entry.confidence_level >= 90 ? 'critical' :
                          entry.confidence_level >= 70 ? 'high' :
                          entry.confidence_level >= 50 ? 'medium' : 'low';
          
          indicators.push({
            id,
            type,
            value: entry.ioc || entry.ioc_value,
            malwareFamily: entry.malware_printable || entry.malware,
            threatType: entry.threat_type || entry.threat_type_desc,
            severity,
            confidence: entry.confidence_level || 75,
            firstSeen: entry.first_seen || entry.first_seen_utc || new Date().toISOString(),
            lastSeen: entry.last_seen || entry.last_seen_utc || new Date().toISOString(),
            source: 'ThreatFox',
            tags: entry.tags || [],
            metadata: {
              reference: entry.reference,
              reporter: entry.reporter,
              malware_alias: entry.malware_alias,
            },
          });
        }
      });
    }
    
    console.log(`[VirusTotal] Fetched ${indicators.length} IOCs from ThreatFox`);
    return indicators;
  } catch (error) {
    console.error('[VirusTotal] ThreatFox fetch error:', error);
    return [];
  }
}

/**
 * Fetch recent malware samples from MalwareBazaar (Abuse.ch)
 */
async function fetchMalwareBazaarData(): Promise<MalwareSample[]> {
  try {
    const formData = new FormData();
    formData.append('query', 'get_recent');
    formData.append('selector', '100');
    
    const response = await fetch(FEEDS_CONFIG.malwareBazaar, {
      method: 'POST',
      body: formData,
    });
    
    if (!response.ok) throw new Error(`MalwareBazaar fetch failed: ${response.status}`);
    
    const data = await response.json();
    const samples: MalwareSample[] = [];
    
    // MalwareBazaar returns { query_status: "ok", data: [...] }
    const entries = data.data || [];
    
    entries.forEach((entry: any) => {
      const id = `bazaar-${entry.sha256_hash}`;
      if (!processedIndicators.has(id)) {
        processedIndicators.add(id);
        
        const tags = entry.tags || [];
        const severity = tags.some((t: string) => t.toLowerCase().includes('ransomware')) ? 'critical' :
                        tags.some((t: string) => t.toLowerCase().includes('stealer')) ? 'high' :
                        tags.some((t: string) => t.toLowerCase().includes('rat')) ? 'high' : 'medium';
        
        samples.push({
          id,
          sha256: entry.sha256_hash,
          sha1: entry.sha1_hash,
          md5: entry.md5_hash,
          fileName: entry.file_name,
          fileType: entry.file_type_mime || entry.file_type,
          fileSize: entry.file_size,
          malwareFamily: entry.signature || entry.tags?.[0],
          tags,
          firstSeen: entry.first_seen || new Date().toISOString(),
          lastSeen: new Date().toISOString(),
          source: 'MalwareBazaar',
          confidence: 90,
          severity,
          metadata: {
            deliveryMethod: entry.delivery_method,
            intelligence: entry.intelligence,
            origin_country: entry.origin_country,
          },
        });
      }
    });
    
    console.log(`[VirusTotal] Fetched ${samples.length} samples from MalwareBazaar`);
    return samples;
  } catch (error) {
    console.error('[VirusTotal] MalwareBazaar fetch error:', error);
    return [];
  }
}

/**
 * Fetch SSL blocklist from Abuse.ch
 */
async function fetchSSLBlacklist(): Promise<ThreatIndicator[]> {
  try {
    const response = await fetch(FEEDS_CONFIG.sslBlacklist);
    if (!response.ok) throw new Error(`SSL Blacklist fetch failed: ${response.status}`);
    
    const data = await response.json();
    const indicators: ThreatIndicator[] = [];
    
    if (Array.isArray(data)) {
      data.forEach((entry: any) => {
        const id = `sslbl-${entry.ip_address || entry.ip}`;
        if (!processedIndicators.has(id)) {
          processedIndicators.add(id);
          
          indicators.push({
            id,
            type: 'ip',
            value: entry.ip_address || entry.ip,
            malwareFamily: entry.malware || entry.threat,
            threatType: 'c2_ssl',
            severity: 'high',
            confidence: 85,
            firstSeen: entry.first_seen || new Date().toISOString(),
            lastSeen: entry.last_seen || new Date().toISOString(),
            source: 'SSLBL Abuse.ch',
            tags: ['c2', 'ssl', 'botnet'],
            metadata: {
              port: entry.port,
              ja3: entry.ja3,
              sha1: entry.sha1,
            },
          });
        }
      });
    }
    
    console.log(`[VirusTotal] Fetched ${indicators.length} IPs from SSL Blacklist`);
    return indicators;
  } catch (error) {
    console.error('[VirusTotal] SSL Blacklist fetch error:', error);
    return [];
  }
}

/* ============================================================================
   DATABASE OPERATIONS
============================================================================ */

/**
 * Save indicators to Supabase threats table
 * Uses UPSERT to update existing records without deletion
 */
async function saveToDatabase(
  indicators: ThreatIndicator[],
  samples: MalwareSample[],
  c2Servers: C2Server[]
): Promise<{ saved: number; errors: number }> {
  let saved = 0;
  let errors = 0;
  
  // Convert to threats table format
  const threats = [
    // Indicators
    ...indicators.map(ind => ({
      id: ind.id,
      type: ind.type === 'c2' ? 'c2' : 'ioc',
      name: ind.malwareFamily || ind.threatType || ind.value.substring(0, 50),
      severity: ind.severity,
      country: ind.metadata?.country || null,
      indicators: [ind.value],
      metadata: {
        ...ind.metadata,
        threatType: ind.threatType,
        confidence: ind.confidence,
        tags: ind.tags,
      },
      source: ind.source,
      first_seen: ind.firstSeen,
      last_seen: ind.lastSeen,
    })),
    // Malware samples
    ...samples.map(sample => ({
      id: sample.id,
      type: 'malware' as const,
      name: sample.malwareFamily || sample.fileName || sample.sha256.substring(0, 16),
      severity: sample.severity,
      country: sample.metadata?.origin_country || null,
      indicators: [sample.sha256, sample.md5, sample.sha1].filter(Boolean) as string[],
      metadata: {
        ...sample.metadata,
        fileName: sample.fileName,
        fileType: sample.fileType,
        fileSize: sample.fileSize,
        tags: sample.tags,
      },
      source: sample.source,
      first_seen: sample.firstSeen,
      last_seen: sample.lastSeen,
    })),
    // C2 Servers
    ...c2Servers.map(c2 => ({
      id: c2.id,
      type: 'c2' as const,
      name: c2.malwareFamily || `C2: ${c2.ip}`,
      severity: 'high' as const,
      country: c2.country || null,
      indicators: [`${c2.ip}:${c2.port}`],
      metadata: {
        ip: c2.ip,
        port: c2.port,
        status: c2.status,
        asn: c2.asn,
      },
      source: c2.source,
      first_seen: c2.firstSeen,
      last_seen: c2.lastSeen,
    })),
  ];
  
  // Batch upsert to database
  const batchSize = 100;
  for (let i = 0; i < threats.length; i += batchSize) {
    const batch = threats.slice(i, i + batchSize);
    
    try {
      const { error } = await supabase
        .from('threats')
        .upsert(batch, {
          onConflict: 'id',
          ignoreDuplicates: false, // Update existing records
        });
      
      if (error) {
        console.error('[VirusTotal] Database upsert error:', error);
        errors += batch.length;
      } else {
        saved += batch.length;
      }
    } catch (err) {
      console.error('[VirusTotal] Database batch error:', err);
      errors += batch.length;
    }
  }
  
  console.log(`[VirusTotal] Database save complete: ${saved} saved, ${errors} errors`);
  return { saved, errors };
}

/**
 * Get threat by value from database (for graph lookups)
 */
export async function getThreatFromDatabase(value: string): Promise<any | null> {
  try {
    // Search by indicator value
    const { data, error } = await supabase
      .from('threats')
      .select('*')
      .contains('indicators', [value])
      .limit(1)
      .maybeSingle();
    
    if (error) {
      console.error('[VirusTotal] Database lookup error:', error);
      return null;
    }
    
    return data;
  } catch (err) {
    console.error('[VirusTotal] Database lookup failed:', err);
    return null;
  }
}

/**
 * Search threats by name or indicator
 */
export async function searchThreatsInDatabase(query: string): Promise<any[]> {
  try {
    const { data, error } = await supabase
      .from('threats')
      .select('*')
      .or(`name.ilike.%${query}%,indicators.cs.{${query}}`)
      .order('last_seen', { ascending: false })
      .limit(50);
    
    if (error) {
      console.error('[VirusTotal] Database search error:', error);
      return [];
    }
    
    return data || [];
  } catch (err) {
    console.error('[VirusTotal] Database search failed:', err);
    return [];
  }
}

/* ============================================================================
   MAIN REFRESH FUNCTION
============================================================================ */

/**
 * Fetch all feeds and update database
 */
export async function refreshAllFeeds(): Promise<FeedStats> {
  if (isRefreshing) {
    console.log('[VirusTotal] Refresh already in progress, skipping...');
    return {
      totalIndicators: 0,
      newIndicators: 0,
      updatedIndicators: 0,
      byType: {},
      bySeverity: {},
      bySource: {},
      lastRefresh: new Date().toISOString(),
    };
  }
  
  isRefreshing = true;
  console.log('[VirusTotal] Starting feed refresh...');
  
  const startTime = Date.now();
  const previousCount = processedIndicators.size;
  
  try {
    // Fetch all feeds in parallel
    const [
      c2Servers,
      urlhausIndicators,
      threatfoxIndicators,
      malwareSamples,
      sslIndicators,
    ] = await Promise.all([
      fetchFeodoTrackerData(),
      fetchURLhausData(),
      fetchThreatFoxData(),
      fetchMalwareBazaarData(),
      fetchSSLBlacklist(),
    ]);
    
    // Combine all indicators
    const allIndicators = [
      ...urlhausIndicators,
      ...threatfoxIndicators,
      ...sslIndicators,
    ];
    
    // Save to database
    const { saved, errors } = await saveToDatabase(allIndicators, malwareSamples, c2Servers);
    
    // Calculate stats
    const stats: FeedStats = {
      totalIndicators: processedIndicators.size,
      newIndicators: processedIndicators.size - previousCount,
      updatedIndicators: saved,
      byType: {
        url: urlhausIndicators.length,
        ioc: threatfoxIndicators.length,
        ip: sslIndicators.length + c2Servers.length,
        malware: malwareSamples.length,
      },
      bySeverity: {
        critical: allIndicators.filter(i => i.severity === 'critical').length,
        high: allIndicators.filter(i => i.severity === 'high').length,
        medium: allIndicators.filter(i => i.severity === 'medium').length,
        low: allIndicators.filter(i => i.severity === 'low').length,
      },
      bySource: {
        URLhaus: urlhausIndicators.length,
        ThreatFox: threatfoxIndicators.length,
        'SSL Blacklist': sslIndicators.length,
        MalwareBazaar: malwareSamples.length,
        'Feodo Tracker': c2Servers.length,
      },
      lastRefresh: new Date().toISOString(),
    };
    
    const elapsed = ((Date.now() - startTime) / 1000).toFixed(2);
    console.log(`[VirusTotal] Refresh complete in ${elapsed}s:`, stats);
    
    return stats;
  } catch (error) {
    console.error('[VirusTotal] Refresh failed:', error);
    throw error;
  } finally {
    isRefreshing = false;
  }
}

/**
 * Start automatic refresh timer
 */
export function startAutoRefresh(intervalMs: number = REFRESH_INTERVAL): void {
  stopAutoRefresh();
  
  console.log(`[VirusTotal] Starting auto-refresh every ${intervalMs / 1000}s`);
  
  // Initial fetch
  refreshAllFeeds().catch(console.error);
  
  // Set up interval
  refreshTimer = window.setInterval(() => {
    refreshAllFeeds().catch(console.error);
  }, intervalMs);
}

/**
 * Stop automatic refresh timer
 */
export function stopAutoRefresh(): void {
  if (refreshTimer) {
    clearInterval(refreshTimer);
    refreshTimer = null;
    console.log('[VirusTotal] Auto-refresh stopped');
  }
}

/**
 * Get current feed status
 */
export function getFeedStatus(): { isRefreshing: boolean; cachedCount: number } {
  return {
    isRefreshing,
    cachedCount: processedIndicators.size,
  };
}

/**
 * Get all cached indicators for graph display
 */
export async function getAllThreatsForGraph(): Promise<any[]> {
  try {
    const { data, error } = await supabase
      .from('threats')
      .select('*')
      .order('last_seen', { ascending: false })
      .limit(1000);
    
    if (error) {
      console.error('[VirusTotal] Failed to fetch threats for graph:', error);
      return [];
    }
    
    return data || [];
  } catch (err) {
    console.error('[VirusTotal] Graph data fetch failed:', err);
    return [];
  }
}
