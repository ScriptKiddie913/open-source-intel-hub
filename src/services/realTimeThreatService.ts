// src/services/realTimeThreatService.ts
// Real-time threat intelligence aggregator with live data sources

export interface ThreatPoint {
  id: string;
  lat: number;
  lon: number;
  country: string;
  city: string;
  threatType: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  indicator: string;
  source: string;
  timestamp: string;
  count: number;
  metadata?: any;
}

export interface MalwareIntel {
  id: string;
  family: string;
  hash: string;
  firstSeen: string;
  lastSeen: string;
  samples: number;
  threatLevel: string;
  capabilities: string[];
  campaigns: string[];
  yaraRules?: string[];
}

// Geolocation helper with batching to avoid rate limits
const geoCache = new Map<string, { lat: number; lon: number; city: string; country: string }>();
const geoQueue: string[] = [];
let geoProcessing = false;

async function batchGeolocate(ips: string[]): Promise<void> {
  geoQueue.push(...ips.filter(ip => !geoCache.has(ip)));
  
  if (geoProcessing || geoQueue.length === 0) return;
  
  geoProcessing = true;
  
  while (geoQueue.length > 0) {
    const ip = geoQueue.shift()!;
    
    try {
      await new Promise(resolve => setTimeout(resolve, 350)); // Rate limit: ~3/sec
      
      const response = await fetch(`http://ip-api.com/json/${ip}?fields=status,country,city,lat,lon`);
      if (response.ok) {
        const data = await response.json();
        if (data.status === 'success') {
          geoCache.set(ip, {
            country: data.country,
            city: data.city,
            lat: data.lat,
            lon: data.lon,
          });
        }
      }
    } catch (e) {
      console.error(`Geo lookup failed for ${ip}:`, e);
    }
  }
  
  geoProcessing = false;
}

// Fetch live C2 servers from Feodo Tracker
async function fetchFeodoC2(): Promise<ThreatPoint[]> {
  try {
    const response = await fetch('https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json');
    if (!response.ok) return [];
    
    const data = await response.json();
    const ips = data.slice(0, 100).map((item: any) => item.ip_address);
    
    await batchGeolocate(ips);
    
    return data.slice(0, 100).map((item: any) => {
      const geo = geoCache.get(item.ip_address);
      return geo ? {
        id: `feodo-${item.ip_address}`,
        lat: geo.lat,
        lon: geo.lon,
        country: geo.country,
        city: geo.city,
        threatType: `Botnet C2: ${item.malware || 'Unknown'}`,
        severity: 'critical' as const,
        indicator: item.ip_address,
        source: 'Feodo Tracker',
        timestamp: item.first_seen,
        count: 1,
        metadata: { malware: item.malware, port: item.port },
      } : null;
    }).filter(Boolean) as ThreatPoint[];
  } catch (error) {
    console.error('Feodo fetch error:', error);
    return [];
  }
}

// Fetch malware URLs from URLhaus
async function fetchURLhausMalware(): Promise<ThreatPoint[]> {
  try {
    const response = await fetch('https://urlhaus.abuse.ch/downloads/json_recent/');
    if (!response.ok) return [];
    
    const data = await response.json();
    
    const points: ThreatPoint[] = [];
    
    for (const item of data.slice(0, 50)) {
      // Try to extract IP from URL
      const urlMatch = item.url.match(/https?:\/\/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
      
      if (urlMatch) {
        const ip = urlMatch[1];
        await batchGeolocate([ip]);
        const geo = geoCache.get(ip);
        
        if (geo) {
          points.push({
            id: `urlhaus-${item.id}`,
            lat: geo.lat,
            lon: geo.lon,
            country: geo.country,
            city: geo.city,
            threatType: item.threat || 'Malware Distribution',
            severity: 'high',
            indicator: item.url,
            source: 'URLhaus',
            timestamp: item.date_added,
            count: 1,
            metadata: { tags: item.tags, status: item.url_status },
          });
        }
      }
    }
    
    return points;
  } catch (error) {
    console.error('URLhaus fetch error:', error);
    return [];
  }
}

// Fetch live IOCs from ThreatFox
async function fetchThreatFoxIOCs(): Promise<ThreatPoint[]> {
  try {
    const response = await fetch('https://threatfox-api.abuse.ch/api/v1/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ query: 'get_iocs', days: 1 }),
    });
    
    if (!response.ok) return [];
    
    const data = await response.json();
    
    const ips = (data.data || [])
      .filter((item: any) => item.ioc_type === 'ip:port' || item.ioc_type === 'ip')
      .map((item: any) => item.ioc.split(':')[0])
      .slice(0, 50);
    
    await batchGeolocate(ips);
    
    return (data.data || [])
      .filter((item: any) => item.ioc_type === 'ip:port' || item.ioc_type === 'ip')
      .slice(0, 50)
      .map((item: any) => {
        const ip = item.ioc.split(':')[0];
        const geo = geoCache.get(ip);
        
        return geo ? {
          id: `threatfox-${item.id}`,
          lat: geo.lat,
          lon: geo.lon,
          country: geo.country,
          city: geo.city,
          threatType: item.malware_printable || item.threat_type || 'Unknown Threat',
          severity: item.confidence_level > 80 ? 'high' : 'medium' as const,
          indicator: item.ioc,
          source: 'ThreatFox',
          timestamp: item.first_seen,
          count: 1,
          metadata: { 
            threat_type: item.threat_type,
            tags: item.tags,
            confidence: item.confidence_level,
          },
        } : null;
      })
      .filter(Boolean) as ThreatPoint[];
  } catch (error) {
    console.error('ThreatFox fetch error:', error);
    return [];
  }
}

// Aggregate all threat sources
export async function fetchLiveThreatMap(): Promise<ThreatPoint[]> {
  try {
    const [feodo, urlhaus, threatfox] = await Promise.all([
      fetchFeodoC2(),
      fetchURLhausMalware(),
      fetchThreatFoxIOCs(),
    ]);
    
    const allPoints = [...feodo, ...urlhaus, ...threatfox];
    
    // Aggregate by location
    const aggregated = new Map<string, ThreatPoint>();
    
    allPoints.forEach(point => {
      const key = `${point.lat.toFixed(1)},${point.lon.toFixed(1)}`;
      if (aggregated.has(key)) {
        const existing = aggregated.get(key)!;
        existing.count++;
        existing.threatType = `Multiple Threats (${existing.count})`;
      } else {
        aggregated.set(key, { ...point });
      }
    });
    
    return Array.from(aggregated.values());
  } catch (error) {
    console.error('Live threat map error:', error);
    return [];
  }
}

// Fetch live malware intelligence
export async function fetchMalwareIntelligence(): Promise<MalwareIntel[]> {
  try {
    const response = await fetch('https://mb-api.abuse.ch/api/v1/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'query=get_recent&selector=100',
    });
    
    if (!response.ok) return [];
    
    const data = await response.json();
    
    const familyMap = new Map<string, MalwareIntel>();
    
    (data.data || []).forEach((sample: any) => {
      const family = sample.signature || 'Unknown';
      
      if (familyMap.has(family)) {
        const existing = familyMap.get(family)!;
        existing.samples++;
        existing.lastSeen = sample.first_seen;
      } else {
        familyMap.set(family, {
          id: `malware-${family}`,
          family,
          hash: sample.sha256_hash,
          firstSeen: sample.first_seen,
          lastSeen: sample.first_seen,
          samples: 1,
          threatLevel: sample.file_type?.includes('exe') ? 'critical' : 'high',
          capabilities: sample.tags || [],
          campaigns: [],
        });
      }
    });
    
    return Array.from(familyMap.values())
      .sort((a, b) => b.samples - a.samples)
      .slice(0, 20);
  } catch (error) {
    console.error('Malware intel error:', error);
    return [];
  }
}

// Export for use in components
export type { ThreatPoint, MalwareIntel };
