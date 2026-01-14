// ============================================================================
// firecrawlThreatService.ts
// THREAT INTELLIGENCE FETCHING VIA FIRECRAWL (CORS-FREE)
// ============================================================================

const FIRECRAWL_API_KEY = 'fc-46d8c57409df439085a2365efc5b9d79';
const FIRECRAWL_API_URL = 'https://api.firecrawl.dev/v1/scrape';

export interface ThreatIndicator {
  id: string;
  indicator_type: 'ip' | 'domain' | 'url' | 'hash';
  value: string;
  threat_level: 'critical' | 'high' | 'medium' | 'low';
  source: string;
  tags: string[];
  description: string;
  first_seen: string;
  last_seen?: string;
  confidence: number;
  malware_family?: string;
  raw_data?: any;
}

export interface ThreatFeedResult {
  indicators: ThreatIndicator[];
  summary: {
    total_threats: number;
    critical_count: number;
    high_count: number;
    medium_count: number;
    by_type: Record<string, number>;
    by_source: Record<string, number>;
    top_malware: string[];
  };
  last_updated: string;
}

// Fetch data using Firecrawl API
async function firecrawlFetch(url: string): Promise<any> {
  try {
    console.log(`[Firecrawl] Fetching: ${url}`);
    
    const response = await fetch(FIRECRAWL_API_URL, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${FIRECRAWL_API_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        url: url,
        formats: ['rawHtml', 'markdown'],
        onlyMainContent: false,
      }),
    });

    if (!response.ok) {
      throw new Error(`Firecrawl request failed: ${response.status}`);
    }

    const result = await response.json();
    console.log(`[Firecrawl] Success for ${url}`);
    return result;
  } catch (error) {
    console.error(`[Firecrawl] Error fetching ${url}:`, error);
    throw error;
  }
}

// Direct JSON fetch (for JSON endpoints that might work)
async function directJsonFetch(url: string): Promise<any> {
  try {
    const response = await fetch(url, {
      method: 'GET',
      headers: {
        'Accept': 'application/json',
      },
    });
    
    if (!response.ok) {
      throw new Error(`Direct fetch failed: ${response.status}`);
    }
    
    return await response.json();
  } catch (error) {
    console.warn(`[DirectFetch] Failed for ${url}, will use Firecrawl`);
    throw error;
  }
}

// Fetch Feodo C2 servers
export async function fetchFeodoTrackerData(): Promise<ThreatIndicator[]> {
  const url = 'https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json';
  
  try {
    // Try direct fetch first (some JSON endpoints work)
    let data;
    try {
      data = await directJsonFetch(url);
    } catch {
      // Fallback to Firecrawl
      const result = await firecrawlFetch(url);
      // Parse JSON from raw HTML or markdown
      const content = result.data?.rawHtml || result.data?.markdown || '';
      const jsonMatch = content.match(/\[[\s\S]*\]|\{[\s\S]*\}/);
      if (jsonMatch) {
        data = JSON.parse(jsonMatch[0]);
      } else {
        throw new Error('Could not parse Feodo data');
      }
    }

    // Handle { value: [...] } format
    const entries = Array.isArray(data) ? data : (data?.value || data?.data || []);
    
    return entries.map((entry: any, index: number) => ({
      id: `feodo-${index}-${Date.now()}`,
      indicator_type: 'ip' as const,
      value: entry.ip_address || entry.ip || '',
      threat_level: 'critical' as const,
      source: 'Feodo Tracker',
      tags: ['botnet', 'c2', entry.malware || 'unknown'].filter(Boolean),
      description: `Botnet C2 Server - ${entry.malware || 'Unknown malware'} - Port ${entry.port || 'N/A'}`,
      first_seen: entry.first_seen || new Date().toISOString(),
      last_seen: entry.last_online,
      confidence: 95,
      malware_family: entry.malware,
      raw_data: entry,
    }));
  } catch (error) {
    console.error('[FeodoTracker] Error:', error);
    return [];
  }
}

// Fetch URLhaus malicious URLs
export async function fetchURLhausData(): Promise<ThreatIndicator[]> {
  const url = 'https://urlhaus.abuse.ch/downloads/json_recent/';
  
  try {
    let data;
    try {
      data = await directJsonFetch(url);
    } catch {
      const result = await firecrawlFetch(url);
      const content = result.data?.rawHtml || result.data?.markdown || '';
      const jsonMatch = content.match(/\{[\s\S]*\}/);
      if (jsonMatch) {
        data = JSON.parse(jsonMatch[0]);
      } else {
        throw new Error('Could not parse URLhaus data');
      }
    }

    // URLhaus returns { "id": [entry], ... } format
    const entries = Object.values(data || {}).flat();
    
    return entries.map((entry: any, index: number) => {
      let host = 'unknown';
      try {
        host = entry.host || new URL(entry.url).hostname;
      } catch {}
      
      return {
        id: `urlhaus-${entry.id || index}-${Date.now()}`,
        indicator_type: 'url' as const,
        value: entry.url || '',
        threat_level: entry.url_status === 'online' ? 'critical' as const : 'high' as const,
        source: 'URLhaus',
        tags: Array.isArray(entry.tags) ? entry.tags : [entry.threat || 'malware'].filter(Boolean),
        description: `Malicious URL - ${entry.threat || 'malware'} - Host: ${host}`,
        first_seen: entry.dateadded || new Date().toISOString(),
        confidence: 85,
        raw_data: entry,
      };
    });
  } catch (error) {
    console.error('[URLhaus] Error:', error);
    return [];
  }
}

// Fetch ThreatFox IOCs
export async function fetchThreatFoxData(): Promise<ThreatIndicator[]> {
  const url = 'https://threatfox.abuse.ch/export/json/recent/';
  
  try {
    let data;
    try {
      data = await directJsonFetch(url);
    } catch {
      const result = await firecrawlFetch(url);
      const content = result.data?.rawHtml || result.data?.markdown || '';
      const jsonMatch = content.match(/\{[\s\S]*\}/);
      if (jsonMatch) {
        data = JSON.parse(jsonMatch[0]);
      } else {
        throw new Error('Could not parse ThreatFox data');
      }
    }

    // ThreatFox export returns { "id": [entry], ... } format
    const entries = Object.entries(data || {})
      .flatMap(([id, items]: [string, any]) => 
        (Array.isArray(items) ? items : [items]).map(item => ({ ...item, _id: id }))
      );
    
    return entries.map((entry: any, index: number) => {
      const iocType = entry.ioc_type || '';
      let indicatorType: 'ip' | 'domain' | 'url' | 'hash' = 'hash';
      if (iocType.includes('ip')) indicatorType = 'ip';
      else if (iocType.includes('domain')) indicatorType = 'domain';
      else if (iocType.includes('url')) indicatorType = 'url';
      
      const confidence = entry.confidence_level || 70;
      
      return {
        id: `threatfox-${entry._id || index}-${Date.now()}`,
        indicator_type: indicatorType,
        value: entry.ioc_value || entry.ioc || '',
        threat_level: confidence >= 90 ? 'critical' as const : 
                      confidence >= 70 ? 'high' as const : 
                      confidence >= 50 ? 'medium' as const : 'low' as const,
        source: 'ThreatFox',
        tags: [entry.malware, entry.threat_type, ...(entry.tags || [])].filter(Boolean),
        description: `${entry.malware_printable || entry.malware || 'Unknown'} - ${entry.threat_type || 'IOC'}`,
        first_seen: entry.first_seen_utc || entry.first_seen || new Date().toISOString(),
        last_seen: entry.last_seen_utc,
        confidence: confidence,
        malware_family: entry.malware_printable || entry.malware,
        raw_data: entry,
      };
    });
  } catch (error) {
    console.error('[ThreatFox] Error:', error);
    return [];
  }
}

// Fetch MalwareBazaar samples
export async function fetchMalwareBazaarData(): Promise<ThreatIndicator[]> {
  const url = 'https://bazaar.abuse.ch/export/txt/sha256/recent/';
  
  try {
    let text;
    try {
      const response = await fetch(url);
      text = await response.text();
    } catch {
      const result = await firecrawlFetch(url);
      text = result.data?.rawHtml || result.data?.markdown || '';
    }

    // Parse SHA256 hashes from text
    const hashes = text
      .split('\n')
      .map((line: string) => line.trim())
      .filter((line: string) => line && !line.startsWith('#') && /^[a-f0-9]{64}$/i.test(line));
    
    return hashes.map((hash: string, index: number) => ({
      id: `bazaar-${hash.slice(0, 16)}-${Date.now()}`,
      indicator_type: 'hash' as const,
      value: hash,
      threat_level: 'high' as const,
      source: 'MalwareBazaar',
      tags: ['malware', 'sha256', 'recent'],
      description: `Malware sample - SHA256 hash`,
      first_seen: new Date().toISOString(),
      confidence: 90,
      raw_data: { sha256: hash, download_url: `https://bazaar.abuse.ch/sample/${hash}/` },
    }));
  } catch (error) {
    console.error('[MalwareBazaar] Error:', error);
    return [];
  }
}

// Fetch all threat feeds
export async function fetchAllThreatFeeds(): Promise<ThreatFeedResult> {
  console.log('[ThreatService] Fetching all threat feeds...');
  
  const [feodoData, urlhausData, threatfoxData, bazaarData] = await Promise.all([
    fetchFeodoTrackerData(),
    fetchURLhausData(),
    fetchThreatFoxData(),
    fetchMalwareBazaarData(),
  ]);

  const allIndicators = [...feodoData, ...urlhausData, ...threatfoxData, ...bazaarData];
  
  // Calculate summary
  const byType: Record<string, number> = {};
  const bySource: Record<string, number> = {};
  const malwareFamilies: Record<string, number> = {};
  let criticalCount = 0;
  let highCount = 0;
  let mediumCount = 0;

  allIndicators.forEach(indicator => {
    byType[indicator.indicator_type] = (byType[indicator.indicator_type] || 0) + 1;
    bySource[indicator.source] = (bySource[indicator.source] || 0) + 1;
    
    if (indicator.malware_family) {
      malwareFamilies[indicator.malware_family] = (malwareFamilies[indicator.malware_family] || 0) + 1;
    }
    
    if (indicator.threat_level === 'critical') criticalCount++;
    else if (indicator.threat_level === 'high') highCount++;
    else if (indicator.threat_level === 'medium') mediumCount++;
  });

  const topMalware = Object.entries(malwareFamilies)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([name]) => name);

  const result: ThreatFeedResult = {
    indicators: allIndicators,
    summary: {
      total_threats: allIndicators.length,
      critical_count: criticalCount,
      high_count: highCount,
      medium_count: mediumCount,
      by_type: byType,
      by_source: bySource,
      top_malware: topMalware,
    },
    last_updated: new Date().toISOString(),
  };

  console.log(`[ThreatService] Loaded ${allIndicators.length} total indicators`);
  console.log(`[ThreatService] Sources: Feodo=${feodoData.length}, URLhaus=${urlhausData.length}, ThreatFox=${threatfoxData.length}, Bazaar=${bazaarData.length}`);
  
  return result;
}

// Search indicators by query
export async function searchThreatIndicators(query: string): Promise<ThreatIndicator[]> {
  const allData = await fetchAllThreatFeeds();
  const queryLower = query.toLowerCase();
  
  return allData.indicators.filter(indicator => 
    indicator.value.toLowerCase().includes(queryLower) ||
    indicator.description.toLowerCase().includes(queryLower) ||
    indicator.tags.some(tag => tag.toLowerCase().includes(queryLower)) ||
    (indicator.malware_family?.toLowerCase().includes(queryLower))
  );
}
