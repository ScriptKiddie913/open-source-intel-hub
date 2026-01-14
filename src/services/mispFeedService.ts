// ============================================================================
// mispFeedService.ts
// MISP THREAT INTELLIGENCE FEEDS SERVICE
// ============================================================================
// ✔ Fetches real-time malware data from MISP-compatible feeds
// ✔ Integrates abuse.ch feeds (Feodo, URLhaus, ThreatFox, MalwareBazaar)
// ✔ Aggregates threat indicators from multiple sources
// ✔ Provides unified threat intelligence interface
// ============================================================================

import { cacheAPIResponse, getCachedData } from '@/lib/database';

/* ============================================================================
   TYPES
============================================================================ */

export interface MalwareIndicator {
  id: string;
  type: 'hash' | 'ip' | 'domain' | 'url' | 'email' | 'c2';
  value: string;
  source: string;
  malwareFamily?: string;
  threatType?: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  confidence: number;
  firstSeen: string;
  lastSeen: string;
  tags: string[];
  metadata: Record<string, any>;
}

export interface C2Server {
  id: string;
  ip: string;
  port: number;
  malwareFamily: string;
  status: 'online' | 'offline';
  firstSeen: string;
  lastOnline: string;
  asn?: string;
  asName?: string;
  country?: string;
  countryCode?: string;
}

export interface MalwareSample {
  id: string;
  sha256: string;
  sha1?: string;
  md5?: string;
  fileName?: string;
  fileType?: string;
  fileSize?: number;
  signature?: string;
  malwareFamily?: string;
  tags: string[];
  firstSeen: string;
  lastSeen: string;
  downloadUrl?: string;
  intelligence?: string[];
}

export interface URLhausEntry {
  id: string;
  url: string;
  urlStatus: 'online' | 'offline';
  host: string;
  dateAdded: string;
  threat: string;
  tags: string[];
  reporter: string;
}

export interface ThreatFoxIOC {
  id: string;
  ioc: string;
  iocType: string;
  threatType: string;
  malware?: string;
  malwarePrintable?: string;
  confidenceLevel: number;
  firstSeen: string;
  lastSeen?: string;
  tags: string[];
  reference?: string;
}

export interface ThreatFeedSummary {
  indicators: MalwareIndicator[];
  c2Servers: C2Server[];
  malwareSamples: MalwareSample[];
  urlhausEntries: URLhausEntry[];
  threatfoxIOCs: ThreatFoxIOC[];
  stats: {
    totalIndicators: number;
    bySource: Record<string, number>;
    byType: Record<string, number>;
    bySeverity: Record<string, number>;
    malwareFamilies: { name: string; count: number }[];
  };
  lastUpdated: Date;
}

/* ============================================================================
   CACHE CONFIGURATION
============================================================================ */

const CACHE_TTL = {
  feodo: 600000,      // 10 minutes
  urlhaus: 600000,    // 10 minutes  
  threatfox: 600000,  // 10 minutes
  malwarebazaar: 1800000, // 30 minutes
};

/* ============================================================================
   FEODO TRACKER (C2 Servers)
============================================================================ */

export async function fetchFeodoC2Servers(): Promise<C2Server[]> {
  const cacheKey = 'feodo_c2_servers';
  const cached = await getCachedData(cacheKey) as C2Server[] | null;
  if (cached && Array.isArray(cached) && cached.length > 0) {
    return cached;
  }
  
  try {
    console.log('[FeodoTracker] Fetching C2 server data...');
    
    // Use local proxy to avoid CORS (proxied via vite.config.ts)
    const response = await fetch('/api/feodo/ipblocklist_recommended.json');
    
    if (!response.ok) {
      throw new Error(`Feodo fetch failed: ${response.status}`);
    }
    
    const data = await response.json();
    
    // API returns { value: [...] } structure - extract the array
    const entries = Array.isArray(data) ? data : (data?.value || data?.data || []);
    console.log('[FeodoTracker] Raw entries:', entries.length);
    
    const servers: C2Server[] = entries.map((entry: any, index: number) => ({
      id: `feodo-${index}-${entry.ip_address?.replace(/\./g, '-') || index}`,
      ip: entry.ip_address || '',
      port: entry.port || 443,
      malwareFamily: entry.malware || 'Unknown',
      status: entry.status === 'online' ? 'online' : 'offline',
      firstSeen: entry.first_seen || new Date().toISOString(),
      lastOnline: entry.last_online || new Date().toISOString(),
      asn: entry.as_number?.toString(),
      asName: entry.as_name,
      country: entry.country,
      countryCode: entry.country_code,
    }));
    
    await cacheAPIResponse(cacheKey, servers, CACHE_TTL.feodo);
    console.log(`[FeodoTracker] Loaded ${servers.length} C2 servers`);
    return servers;
  } catch (error) {
    console.error('[FeodoTracker] Error:', error);
    return [];
  }
}

/* ============================================================================
   URLHAUS (Malware URLs)
============================================================================ */

export async function fetchURLhausRecent(): Promise<URLhausEntry[]> {
  const cacheKey = 'urlhaus_recent';
  const cached = await getCachedData(cacheKey) as URLhausEntry[] | null;
  if (cached && Array.isArray(cached) && cached.length > 0) {
    return cached;
  }
  
  try {
    console.log('[URLhaus] Fetching recent malware URLs...');
    
    // Use local proxy: /api/urlhaus -> https://urlhaus.abuse.ch/downloads
    const response = await fetch('/api/urlhaus/json_recent/');
    
    if (!response.ok) {
      console.warn(`[URLhaus] Download endpoint failed (${response.status}), trying POST API...`);
      // Fallback to POST API which works directly (CORS-allowed)
      const postResponse = await fetch('https://urlhaus-api.abuse.ch/v1/urls/recent/', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'selector=100'
      });
      
      if (!postResponse.ok) {
        throw new Error(`URLhaus POST API failed: ${postResponse.status}`);
      }
      
      const postData = await postResponse.json();
      if (postData.query_status !== 'ok' || !postData.urls) {
        console.warn('[URLhaus] POST API returned no data');
        return [];
      }
      
      const postEntries: URLhausEntry[] = postData.urls.map((entry: any, index: number) => {
        let host = '';
        try {
          host = entry.host || (entry.url ? new URL(entry.url).hostname : 'unknown');
        } catch {
          host = 'unknown';
        }
        return {
          id: `urlhaus-${entry.id || index}`,
          url: entry.url || '',
          urlStatus: entry.url_status === 'online' ? 'online' : 'offline',
          host,
          dateAdded: entry.dateadded || new Date().toISOString(),
          threat: entry.threat || 'malware_download',
          tags: Array.isArray(entry.tags) ? entry.tags : (entry.tags ? entry.tags.split(',') : []),
          reporter: entry.reporter || 'anonymous',
        };
      });
      
      await cacheAPIResponse(cacheKey, postEntries, CACHE_TTL.urlhaus);
      console.log(`[URLhaus] Loaded ${postEntries.length} malware URLs via POST API`);
      return postEntries;
    }
    
    const data = await response.json();
    
    // API returns object with numeric keys, each containing an array with one entry
    // Format: { "3722626": [{ dateadded, url, url_status, ... }], ... }
    const rawEntries = Object.values(data || {})
      .flat() // Flatten the arrays
      .slice(0, 1000);
    
    console.log('[URLhaus] Raw entries:', rawEntries.length);
    
    const entries: URLhausEntry[] = rawEntries.map((entry: any, index: number) => {
      let host = '';
      try {
        host = entry.host || (entry.url ? new URL(entry.url).hostname : 'unknown');
      } catch {
        host = 'unknown';
      }
      
      return {
        id: `urlhaus-${entry.id || index}`,
        url: entry.url || '',
        urlStatus: entry.url_status === 'online' ? 'online' : 'offline',
        host,
        dateAdded: entry.dateadded || new Date().toISOString(),
        threat: entry.threat || 'malware_download',
        tags: Array.isArray(entry.tags) ? entry.tags : (entry.tags ? [entry.tags] : []),
        reporter: entry.reporter || 'anonymous',
      };
    });
    
    await cacheAPIResponse(cacheKey, entries, CACHE_TTL.urlhaus);
    console.log(`[URLhaus] Loaded ${entries.length} malware URLs`);
    return entries;
  } catch (error) {
    console.error('[URLhaus] Error:', error);
    return [];
  }
}

/* ============================================================================
   THREATFOX (IOCs)
============================================================================ */

export async function fetchThreatFoxIOCs(days: number = 1): Promise<ThreatFoxIOC[]> {
  const cacheKey = `threatfox_iocs_${days}d`;
  const cached = await getCachedData(cacheKey) as ThreatFoxIOC[] | null;
  if (cached && Array.isArray(cached) && cached.length > 0) {
    return cached;
  }
  
  try {
    console.log('[ThreatFox] Fetching recent IOCs via POST API...');
    
    // Use the POST API which allows CORS and returns proper JSON
    const response = await fetch('https://threatfox-api.abuse.ch/api/v1/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ query: 'get_iocs', days: days })
    });
    
    if (!response.ok) {
      throw new Error(`ThreatFox POST API failed: ${response.status}`);
    }
    
    const data = await response.json();
    
    if (data.query_status !== 'ok' || !data.data) {
      console.warn('[ThreatFox] No data returned:', data.query_status);
      return [];
    }
    
    console.log('[ThreatFox] Raw IOCs:', data.data.length);
    
    const iocs: ThreatFoxIOC[] = data.data.slice(0, 1000).map((entry: any) => ({
      id: `threatfox-${entry.id || Math.random().toString(36).slice(2)}`,
      ioc: entry.ioc || entry.ioc_value || '',
      iocType: entry.ioc_type || 'unknown',
      threatType: entry.threat_type || 'unknown',
      malware: entry.malware,
      malwarePrintable: entry.malware_printable,
      confidenceLevel: entry.confidence_level || 50,
      firstSeen: entry.first_seen_utc || entry.first_seen || new Date().toISOString(),
      lastSeen: entry.last_seen_utc || entry.last_seen,
      tags: typeof entry.tags === 'string' ? entry.tags.split(',') : (entry.tags || []),
      reference: entry.reference,
    }));
    
    await cacheAPIResponse(cacheKey, iocs, CACHE_TTL.threatfox);
    console.log(`[ThreatFox] Loaded ${iocs.length} IOCs`);
    return iocs;
  } catch (error) {
    console.error('[ThreatFox] Error:', error);
    return [];
  }
}

/* ============================================================================
   MALWAREBAZAAR (Samples)
============================================================================ */

export async function fetchMalwareBazaarRecent(): Promise<MalwareSample[]> {
  const cacheKey = `malwarebazaar_recent`;
  const cached = await getCachedData(cacheKey) as MalwareSample[] | null;
  if (cached && Array.isArray(cached) && cached.length > 0) {
    return cached;
  }
  
  try {
    console.log('[MalwareBazaar] Fetching recent samples via POST API...');
    
    // Use the POST API which returns proper JSON with metadata
    const response = await fetch('https://mb-api.abuse.ch/api/v1/', {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: 'query=get_recent&selector=100'
    });
    
    if (!response.ok) {
      throw new Error(`MalwareBazaar API failed: ${response.status}`);
    }
    
    const data = await response.json();
    
    if (data.query_status !== 'ok' || !data.data) {
      console.warn('[MalwareBazaar] No data returned');
      return [];
    }
    
    console.log('[MalwareBazaar] Raw samples:', data.data.length);
    
    // Parse proper JSON response - each entry has full metadata
    const samples: MalwareSample[] = data.data
      .filter((entry: any) => entry.sha256_hash && /^[a-fA-F0-9]{64}$/.test(entry.sha256_hash))
      .map((entry: any) => ({
        id: `bazaar-${entry.sha256_hash.slice(0, 16)}`,
        sha256: entry.sha256_hash,
        sha1: entry.sha1_hash,
        md5: entry.md5_hash,
        fileName: entry.file_name || undefined,
        fileType: entry.file_type_mime || entry.file_type || 'unknown',
        fileSize: entry.file_size,
        signature: entry.signature || 'Unknown',
        malwareFamily: entry.signature || entry.tags?.[0] || 'Unknown',
        tags: entry.tags || ['malware', 'recent'],
        firstSeen: entry.first_seen || new Date().toISOString(),
        lastSeen: entry.last_seen || new Date().toISOString(),
        downloadUrl: `https://bazaar.abuse.ch/sample/${entry.sha256_hash}/`,
        intelligence: entry.intelligence || [],
      }));
    
    await cacheAPIResponse(cacheKey, samples, CACHE_TTL.malwarebazaar);
    console.log(`[MalwareBazaar] Loaded ${samples.length} valid samples`);
    return samples;
  } catch (error) {
    console.error('[MalwareBazaar] Error:', error);
    return [];
  }
}

/* ============================================================================
   AGGREGATED FEED
============================================================================ */

export async function fetchAllThreatFeeds(): Promise<ThreatFeedSummary> {
  console.log('[MISP] Fetching all threat feeds...');
  
  // Fetch all feeds in parallel
  const [c2Servers, urlhausEntries, threatfoxIOCs, malwareSamples] = await Promise.all([
    fetchFeodoC2Servers(),
    fetchURLhausRecent(),
    fetchThreatFoxIOCs(30),  // Last 30 days for more data
    fetchMalwareBazaarRecent(),
  ]);
  
  // Convert to unified indicators
  const indicators: MalwareIndicator[] = [];
  const bySource: Record<string, number> = {};
  const byType: Record<string, number> = {};
  const bySeverity: Record<string, number> = {};
  const malwareFamilyCount: Record<string, number> = {};
  
  // Process C2 servers
  c2Servers.forEach(server => {
    const indicator: MalwareIndicator = {
      id: server.id,
      type: 'c2',
      value: `${server.ip}:${server.port}`,
      source: 'FeodoTracker',
      malwareFamily: server.malwareFamily,
      threatType: 'c2_server',
      severity: server.status === 'online' ? 'critical' : 'high',
      confidence: 90,
      firstSeen: server.firstSeen,
      lastSeen: server.lastOnline,
      tags: [server.malwareFamily, 'c2', server.countryCode || ''].filter(Boolean),
      metadata: { asn: server.asn, asName: server.asName, country: server.country },
    };
    indicators.push(indicator);
    
    bySource['FeodoTracker'] = (bySource['FeodoTracker'] || 0) + 1;
    byType['c2'] = (byType['c2'] || 0) + 1;
    bySeverity[indicator.severity] = (bySeverity[indicator.severity] || 0) + 1;
    malwareFamilyCount[server.malwareFamily] = (malwareFamilyCount[server.malwareFamily] || 0) + 1;
  });
  
  // Process URLhaus entries
  urlhausEntries.forEach(entry => {
    const indicator: MalwareIndicator = {
      id: entry.id,
      type: 'url',
      value: entry.url,
      source: 'URLhaus',
      threatType: entry.threat,
      severity: entry.urlStatus === 'online' ? 'high' : 'medium',
      confidence: 80,
      firstSeen: entry.dateAdded,
      lastSeen: entry.dateAdded,
      tags: entry.tags,
      metadata: { host: entry.host, reporter: entry.reporter },
    };
    indicators.push(indicator);
    
    bySource['URLhaus'] = (bySource['URLhaus'] || 0) + 1;
    byType['url'] = (byType['url'] || 0) + 1;
    bySeverity[indicator.severity] = (bySeverity[indicator.severity] || 0) + 1;
  });
  
  // Process ThreatFox IOCs
  threatfoxIOCs.forEach(ioc => {
    let type: MalwareIndicator['type'] = 'domain';
    if (ioc.iocType.includes('ip')) type = 'ip';
    else if (ioc.iocType.includes('url')) type = 'url';
    else if (ioc.iocType.includes('hash') || ioc.iocType.includes('md5') || ioc.iocType.includes('sha')) type = 'hash';
    
    const indicator: MalwareIndicator = {
      id: ioc.id,
      type,
      value: ioc.ioc,
      source: 'ThreatFox',
      malwareFamily: ioc.malwarePrintable,
      threatType: ioc.threatType,
      severity: ioc.confidenceLevel > 80 ? 'critical' : ioc.confidenceLevel > 50 ? 'high' : 'medium',
      confidence: ioc.confidenceLevel,
      firstSeen: ioc.firstSeen,
      lastSeen: ioc.lastSeen || ioc.firstSeen,
      tags: ioc.tags,
      metadata: { malware: ioc.malware, reference: ioc.reference },
    };
    indicators.push(indicator);
    
    bySource['ThreatFox'] = (bySource['ThreatFox'] || 0) + 1;
    byType[type] = (byType[type] || 0) + 1;
    bySeverity[indicator.severity] = (bySeverity[indicator.severity] || 0) + 1;
    if (ioc.malwarePrintable) {
      malwareFamilyCount[ioc.malwarePrintable] = (malwareFamilyCount[ioc.malwarePrintable] || 0) + 1;
    }
  });
  
  // Process malware samples
  malwareSamples.forEach(sample => {
    const indicator: MalwareIndicator = {
      id: sample.id,
      type: 'hash',
      value: sample.sha256,
      source: 'MalwareBazaar',
      malwareFamily: sample.malwareFamily,
      threatType: 'malware_sample',
      severity: 'high',
      confidence: 95,
      firstSeen: sample.firstSeen,
      lastSeen: sample.lastSeen,
      tags: sample.tags,
      metadata: { 
        fileName: sample.fileName, 
        fileType: sample.fileType, 
        fileSize: sample.fileSize,
        md5: sample.md5,
        sha1: sample.sha1,
      },
    };
    indicators.push(indicator);
    
    bySource['MalwareBazaar'] = (bySource['MalwareBazaar'] || 0) + 1;
    byType['hash'] = (byType['hash'] || 0) + 1;
    bySeverity[indicator.severity] = (bySeverity[indicator.severity] || 0) + 1;
    if (sample.malwareFamily && sample.malwareFamily !== 'Unknown') {
      malwareFamilyCount[sample.malwareFamily] = (malwareFamilyCount[sample.malwareFamily] || 0) + 1;
    }
  });
  
  // Sort malware families by count
  const malwareFamilies = Object.entries(malwareFamilyCount)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 20)
    .map(([name, count]) => ({ name, count }));
  
  return {
    indicators,
    c2Servers,
    malwareSamples,
    urlhausEntries,
    threatfoxIOCs,
    stats: {
      totalIndicators: indicators.length,
      bySource,
      byType,
      bySeverity,
      malwareFamilies,
    },
    lastUpdated: new Date(),
  };
}

/* ============================================================================
   SEARCH & FILTER
============================================================================ */

export async function searchMalwareIndicators(query: string): Promise<MalwareIndicator[]> {
  const feeds = await fetchAllThreatFeeds();
  const lowerQuery = query.toLowerCase();
  
  return feeds.indicators.filter(indicator => {
    if (indicator.value.toLowerCase().includes(lowerQuery)) return true;
    if (indicator.malwareFamily?.toLowerCase().includes(lowerQuery)) return true;
    if (indicator.threatType?.toLowerCase().includes(lowerQuery)) return true;
    if (indicator.tags.some(tag => tag.toLowerCase().includes(lowerQuery))) return true;
    return false;
  });
}

export async function getMalwareByFamily(family: string): Promise<MalwareIndicator[]> {
  const feeds = await fetchAllThreatFeeds();
  const lowerFamily = family.toLowerCase();
  
  return feeds.indicators.filter(indicator => 
    indicator.malwareFamily?.toLowerCase().includes(lowerFamily)
  );
}

export async function getRecentC2Activity(): Promise<C2Server[]> {
  const servers = await fetchFeodoC2Servers();
  
  // Sort by last online, most recent first
  return servers
    .sort((a, b) => new Date(b.lastOnline).getTime() - new Date(a.lastOnline).getTime())
    .slice(0, 50);
}

/* ============================================================================
   THREAT MAP DATA
============================================================================ */

export interface MalwareThreatPoint {
  id: string;
  lat: number;
  lon: number;
  country: string;
  countryCode: string;
  type: 'c2' | 'malware_url' | 'ioc';
  malwareFamily?: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  count: number;
  indicators: string[];
}

// Country coordinates for mapping
const COUNTRY_COORDS: Record<string, { lat: number; lon: number }> = {
  'US': { lat: 39.8283, lon: -98.5795 },
  'CN': { lat: 35.8617, lon: 104.1954 },
  'RU': { lat: 61.5240, lon: 105.3188 },
  'DE': { lat: 51.1657, lon: 10.4515 },
  'NL': { lat: 52.1326, lon: 5.2913 },
  'FR': { lat: 46.2276, lon: 2.2137 },
  'GB': { lat: 55.3781, lon: -3.4360 },
  'JP': { lat: 36.2048, lon: 138.2529 },
  'KR': { lat: 35.9078, lon: 127.7669 },
  'IN': { lat: 20.5937, lon: 78.9629 },
  'BR': { lat: -14.2350, lon: -51.9253 },
  'CA': { lat: 56.1304, lon: -106.3468 },
  'AU': { lat: -25.2744, lon: 133.7751 },
  'IT': { lat: 41.8719, lon: 12.5674 },
  'ES': { lat: 40.4637, lon: -3.7492 },
  'PL': { lat: 51.9194, lon: 19.1451 },
  'UA': { lat: 48.3794, lon: 31.1656 },
  'IR': { lat: 32.4279, lon: 53.6880 },
  'KP': { lat: 40.3399, lon: 127.5101 },
  'SG': { lat: 1.3521, lon: 103.8198 },
  'HK': { lat: 22.3193, lon: 114.1694 },
  'TW': { lat: 23.6978, lon: 120.9605 },
  'VN': { lat: 14.0583, lon: 108.2772 },
  'TH': { lat: 15.8700, lon: 100.9925 },
  'MY': { lat: 4.2105, lon: 101.9758 },
  'ID': { lat: -0.7893, lon: 113.9213 },
  'PH': { lat: 12.8797, lon: 121.7740 },
  'MX': { lat: 23.6345, lon: -102.5528 },
  'AR': { lat: -38.4161, lon: -63.6167 },
  'CL': { lat: -35.6751, lon: -71.5430 },
  'CO': { lat: 4.5709, lon: -74.2973 },
  'ZA': { lat: -30.5595, lon: 22.9375 },
  'EG': { lat: 26.8206, lon: 30.8025 },
  'TR': { lat: 38.9637, lon: 35.2433 },
  'SA': { lat: 23.8859, lon: 45.0792 },
  'AE': { lat: 23.4241, lon: 53.8478 },
  'IL': { lat: 31.0461, lon: 34.8516 },
  'SE': { lat: 60.1282, lon: 18.6435 },
  'NO': { lat: 60.4720, lon: 8.4689 },
  'FI': { lat: 61.9241, lon: 25.7482 },
  'DK': { lat: 56.2639, lon: 9.5018 },
  'CH': { lat: 46.8182, lon: 8.2275 },
  'AT': { lat: 47.5162, lon: 14.5501 },
  'BE': { lat: 50.5039, lon: 4.4699 },
  'CZ': { lat: 49.8175, lon: 15.4730 },
  'RO': { lat: 45.9432, lon: 24.9668 },
  'HU': { lat: 47.1625, lon: 19.5033 },
  'BG': { lat: 42.7339, lon: 25.4858 },
};

export async function getMalwareThreatMapData(): Promise<MalwareThreatPoint[]> {
  const c2Servers = await fetchFeodoC2Servers();
  
  // Group by country
  const byCountry: Record<string, { 
    count: number; 
    indicators: string[]; 
    malwareFamilies: Set<string>;
    online: number;
  }> = {};
  
  c2Servers.forEach(server => {
    const cc = server.countryCode || 'XX';
    if (!byCountry[cc]) {
      byCountry[cc] = { count: 0, indicators: [], malwareFamilies: new Set(), online: 0 };
    }
    byCountry[cc].count++;
    byCountry[cc].indicators.push(`${server.ip}:${server.port}`);
    byCountry[cc].malwareFamilies.add(server.malwareFamily);
    if (server.status === 'online') byCountry[cc].online++;
  });
  
  // Convert to map points
  const points: MalwareThreatPoint[] = [];
  
  Object.entries(byCountry).forEach(([cc, data]) => {
    const coords = COUNTRY_COORDS[cc];
    if (!coords) return;
    
    // Determine severity based on count and online status
    let severity: MalwareThreatPoint['severity'] = 'low';
    if (data.online > 5) severity = 'critical';
    else if (data.online > 2 || data.count > 10) severity = 'high';
    else if (data.count > 5) severity = 'medium';
    
    points.push({
      id: `c2-${cc}`,
      lat: coords.lat,
      lon: coords.lon,
      country: cc,
      countryCode: cc,
      type: 'c2',
      malwareFamily: Array.from(data.malwareFamilies).slice(0, 3).join(', '),
      severity,
      count: data.count,
      indicators: data.indicators.slice(0, 10),
    });
  });
  
  return points;
}

/* ============================================================================
   EXPORTS
============================================================================ */

export default {
  fetchFeodoC2Servers,
  fetchURLhausRecent,
  fetchThreatFoxIOCs,
  fetchMalwareBazaarRecent,
  fetchAllThreatFeeds,
  searchMalwareIndicators,
  getMalwareByFamily,
  getRecentC2Activity,
  getMalwareThreatMapData,
};
