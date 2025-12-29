// Enhanced CVE and Threat Intelligence Service

import { cacheAPIResponse, getCachedData } from '@/lib/database';

export interface CVEData {
  id: string;
  description: string;
  published: string;
  modified: string;
  cvss: {
    score: number;
    severity: string;
    vector: string;
  };
  references: string[];
  cwe: string[];
  exploitAvailable: boolean;
  exploitDetails?: ExploitData;
}

export interface ExploitData {
  id: string;
  title: string;
  description: string;
  author: string;
  type: string;
  platform: string;
  date: string;
  edbId: string;
  cve?: string[];
  verified: boolean;
  sourceUrl: string;
  code?: string;
}

export interface ThreatFeed {
  id: string;
  type: 'malware' | 'phishing' | 'botnet' | 'c2' | 'exploit' | 'ransomware' | 'apt';
  indicator: string;
  indicatorType: 'ip' | 'domain' | 'url' | 'hash' | 'email';
  threat: string;
  confidence: number;
  firstSeen: string;
  lastSeen: string;
  source: string;
  tags: string[];
  location?: {
    country: string;
    city: string;
    lat: number;
    lon: number;
  };
}

export interface LiveAttack {
  id: string;
  timestamp: Date;
  sourceIp: string;
  sourceCountry: string;
  sourceLocation: { lat: number; lon: number };
  targetIp: string;
  targetCountry: string;
  targetLocation: { lat: number; lon: number };
  attackType: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  protocol: string;
  port?: number;
}

const CVE_CACHE_TTL = 240;
const EXPLOIT_CACHE_TTL = 360;
const THREAT_FEED_CACHE_TTL = 5; // 5 minutes for live data

// Get IP geolocation
async function getGeoLocation(ip: string): Promise<{ country: string; city: string; lat: number; lon: number } | null> {
  try {
    const response = await fetch(`http://ip-api.com/json/${ip}?fields=status,country,city,lat,lon`);
    if (!response.ok) return null;
    const data = await response.json();
    if (data.status === 'success') {
      return {
        country: data.country,
        city: data.city,
        lat: data.lat,
        lon: data.lon,
      };
    }
    return null;
  } catch {
    return null;
  }
}

// NVD API
export async function searchCVE(query: string, limit = 20): Promise<CVEData[]> {
  const cacheKey = `cve:search:${query}:${limit}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  try {
    const response = await fetch(
      `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${encodeURIComponent(query)}&resultsPerPage=${limit}`
    );

    if (!response.ok) throw new Error(`NVD API error: ${response.statusText}`);

    const data = await response.json();
    const cves: CVEData[] = [];

    for (const item of data.vulnerabilities || []) {
      const cve = item.cve;
      const metrics = cve.metrics?.cvssMetricV31?.[0] || cve.metrics?.cvssMetricV30?.[0] || cve.metrics?.cvssMetricV2?.[0];
      
      cves.push({
        id: cve.id,
        description: cve.descriptions?.find((d: any) => d.lang === 'en')?.value || 'No description',
        published: cve.published,
        modified: cve.lastModified,
        cvss: {
          score: metrics?.cvssData?.baseScore || 0,
          severity: metrics?.cvssData?.baseSeverity || 'UNKNOWN',
          vector: metrics?.cvssData?.vectorString || '',
        },
        references: (cve.references || []).map((r: any) => r.url).slice(0, 5),
        cwe: (cve.weaknesses || []).flatMap((w: any) => 
          w.description?.map((d: any) => d.value) || []
        ),
        exploitAvailable: false,
      });
    }

    await cacheAPIResponse(cacheKey, cves, CVE_CACHE_TTL);
    return cves;
  } catch (error) {
    console.error('CVE search error:', error);
    return [];
  }
}

export async function getCVEDetails(cveId: string): Promise<CVEData | null> {
  const cacheKey = `cve:details:${cveId}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  try {
    const response = await fetch(
      `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${cveId}`
    );

    if (!response.ok) return null;

    const data = await response.json();
    const cve = data.vulnerabilities?.[0]?.cve;
    
    if (!cve) return null;

    const metrics = cve.metrics?.cvssMetricV31?.[0] || cve.metrics?.cvssMetricV30?.[0] || cve.metrics?.cvssMetricV2?.[0];
    
    const cveData: CVEData = {
      id: cve.id,
      description: cve.descriptions?.find((d: any) => d.lang === 'en')?.value || 'No description',
      published: cve.published,
      modified: cve.lastModified,
      cvss: {
        score: metrics?.cvssData?.baseScore || 0,
        severity: metrics?.cvssData?.baseSeverity || 'UNKNOWN',
        vector: metrics?.cvssData?.vectorString || '',
      },
      references: (cve.references || []).map((r: any) => r.url),
      cwe: (cve.weaknesses || []).flatMap((w: any) => 
        w.description?.map((d: any) => d.value) || []
      ),
      exploitAvailable: false,
    };

    const exploit = await searchExploitDB(cveId);
    if (exploit.length > 0) {
      cveData.exploitAvailable = true;
      cveData.exploitDetails = exploit[0];
    }

    await cacheAPIResponse(cacheKey, cveData, CVE_CACHE_TTL);
    return cveData;
  } catch (error) {
    console.error('CVE details error:', error);
    return null;
  }
}

export async function getRecentCVEs(days = 7, limit = 50): Promise<CVEData[]> {
  const cacheKey = `cve:recent:${days}:${limit}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  try {
    const endDate = new Date();
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - days);

    const response = await fetch(
      `https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=${startDate.toISOString()}&pubEndDate=${endDate.toISOString()}&resultsPerPage=${limit}`
    );

    if (!response.ok) throw new Error('Failed to fetch recent CVEs');

    const data = await response.json();
    const cves: CVEData[] = [];

    for (const item of data.vulnerabilities || []) {
      const cve = item.cve;
      const metrics = cve.metrics?.cvssMetricV31?.[0] || cve.metrics?.cvssMetricV30?.[0] || cve.metrics?.cvssMetricV2?.[0];
      
      cves.push({
        id: cve.id,
        description: cve.descriptions?.find((d: any) => d.lang === 'en')?.value || 'No description',
        published: cve.published,
        modified: cve.lastModified,
        cvss: {
          score: metrics?.cvssData?.baseScore || 0,
          severity: metrics?.cvssData?.baseSeverity || 'UNKNOWN',
          vector: metrics?.cvssData?.vectorString || '',
        },
        references: (cve.references || []).map((r: any) => r.url).slice(0, 3),
        cwe: (cve.weaknesses || []).flatMap((w: any) => 
          w.description?.map((d: any) => d.value) || []
        ).slice(0, 2),
        exploitAvailable: false,
      });
    }

    await cacheAPIResponse(cacheKey, cves, CVE_CACHE_TTL);
    return cves;
  } catch (error) {
    console.error('Recent CVEs error:', error);
    return [];
  }
}

export async function searchExploitDB(query: string, limit = 20): Promise<ExploitData[]> {
  const cacheKey = `exploitdb:${query}:${limit}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  try {
    const response = await fetch(
      'https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv'
    );

    if (!response.ok) throw new Error('Failed to fetch ExploitDB feed');

    const csvData = await response.text();
    const lines = csvData.split('\n').slice(1);
    const exploits: ExploitData[] = [];

    for (const line of lines) {
      if (exploits.length >= limit) break;
      
      const match = line.match(/^"?([^"]*)"?,/);
      if (!match) continue;

      const parts = line.split(',');
      if (parts.length < 5) continue;

      const id = parts[0]?.replace(/"/g, '') || '';
      const title = parts[2]?.replace(/"/g, '') || '';
      const type = parts[4]?.replace(/"/g, '') || '';
      const platform = parts[5]?.replace(/"/g, '') || '';
      
      if (
        title.toLowerCase().includes(query.toLowerCase()) ||
        id.includes(query)
      ) {
        exploits.push({
          id: `edb-${id}`,
          title,
          description: title,
          author: parts[3]?.replace(/"/g, '') || 'Unknown',
          type,
          platform,
          date: parts[1]?.replace(/"/g, '') || '',
          edbId: id,
          verified: parts[6]?.includes('1') || false,
          sourceUrl: `https://www.exploit-db.com/exploits/${id}`,
        });
      }
    }

    await cacheAPIResponse(cacheKey, exploits, EXPLOIT_CACHE_TTL);
    return exploits;
  } catch (error) {
    console.error('ExploitDB search error:', error);
    return [];
  }
}

// Enhanced Live Threat Feeds with Geolocation
export async function getLiveThreatFeeds(): Promise<ThreatFeed[]> {
  const cacheKey = 'threats:live:feeds';
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const feeds: ThreatFeed[] = [];

  try {
    // Feodo Tracker (Botnet C2) with geolocation
    const feodoResponse = await fetch('https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json');
    if (feodoResponse.ok) {
      const feodoData = await feodoResponse.json();
      
      for (const item of feodoData.slice(0, 100)) {
        const geo = await getGeoLocation(item.ip_address);
        
        feeds.push({
          id: `feodo-${item.ip_address}`,
          type: 'botnet',
          indicator: item.ip_address,
          indicatorType: 'ip',
          threat: item.malware || 'Botnet C2',
          confidence: 95,
          firstSeen: item.first_seen,
          lastSeen: item.last_seen || item.first_seen,
          source: 'Feodo Tracker',
          tags: ['botnet', 'c2', item.malware?.toLowerCase() || ''].filter(Boolean),
          location: geo || undefined,
        });
      }
    }

    // URLhaus (Malware URLs)
    const urlhausResponse = await fetch('https://urlhaus.abuse.ch/downloads/json_recent/');
    if (urlhausResponse.ok) {
      const urlhausData = await urlhausResponse.json();
      for (const item of urlhausData.slice(0, 50)) {
        feeds.push({
          id: `urlhaus-${item.id}`,
          type: 'malware',
          indicator: item.url,
          indicatorType: 'url',
          threat: item.threat || 'Malware Distribution',
          confidence: 90,
          firstSeen: item.date_added,
          lastSeen: item.date_added,
          source: 'URLhaus',
          tags: item.tags || [],
        });
      }
    }

    // OpenPhish
    const openphishResponse = await fetch('https://openphish.com/feed.txt');
    if (openphishResponse.ok) {
      const openphishData = await openphishResponse.text();
      const urls = openphishData.split('\n').filter(Boolean).slice(0, 50);
      
      const now = new Date().toISOString();
      for (const url of urls) {
        feeds.push({
          id: `openphish-${Buffer.from(url).toString('base64').slice(0, 16)}`,
          type: 'phishing',
          indicator: url,
          indicatorType: 'url',
          threat: 'Phishing',
          confidence: 85,
          firstSeen: now,
          lastSeen: now,
          source: 'OpenPhish',
          tags: ['phishing'],
        });
      }
    }

    // ThreatFox (Recent IOCs)
    const threatfoxResponse = await fetch('https://threatfox-api.abuse.ch/api/v1/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ query: 'get_iocs', days: 1 }),
    });
    
    if (threatfoxResponse.ok) {
      const threatfoxData = await threatfoxResponse.json();
      
      for (const item of (threatfoxData.data || []).slice(0, 50)) {
        const isIp = item.ioc_type === 'ip:port' || item.ioc_type === 'ip';
        let geo = null;
        
        if (isIp) {
          const ip = item.ioc.split(':')[0];
          geo = await getGeoLocation(ip);
        }
        
        feeds.push({
          id: `threatfox-${item.id}`,
          type: item.threat_type?.includes('apt') ? 'apt' : 
                item.threat_type?.includes('ransomware') ? 'ransomware' : 'malware',
          indicator: item.ioc,
          indicatorType: isIp ? 'ip' : item.ioc_type.includes('domain') ? 'domain' : 'url',
          threat: item.malware_printable || item.threat_type || 'Unknown Threat',
          confidence: item.confidence_level || 80,
          firstSeen: item.first_seen,
          lastSeen: item.last_seen || item.first_seen,
          source: 'ThreatFox',
          tags: item.tags || [],
          location: geo || undefined,
        });
      }
    }

    await cacheAPIResponse(cacheKey, feeds, THREAT_FEED_CACHE_TTL);
    return feeds;
  } catch (error) {
    console.error('Live threat feeds error:', error);
    return feeds;
  }
}

export async function getMalwareHashes(limit = 50): Promise<ThreatFeed[]> {
  const cacheKey = `threats:malware:hashes:${limit}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  try {
    const response = await fetch('https://mb-api.abuse.ch/api/v1/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'query=get_recent&selector=100',
    });

    if (!response.ok) throw new Error('MalwareBazaar API error');

    const data = await response.json();
    const feeds: ThreatFeed[] = [];

    for (const sample of (data.data || []).slice(0, limit)) {
      feeds.push({
        id: `malware-${sample.sha256_hash}`,
        type: 'malware',
        indicator: sample.sha256_hash,
        indicatorType: 'hash',
        threat: sample.signature || 'Unknown Malware',
        confidence: 95,
        firstSeen: sample.first_seen,
        lastSeen: sample.first_seen,
        source: 'MalwareBazaar',
        tags: sample.tags || [],
      });
    }

    await cacheAPIResponse(cacheKey, feeds, THREAT_FEED_CACHE_TTL);
    return feeds;
  } catch (error) {
    console.error('Malware hashes error:', error);
    return [];
  }
}

// Generate simulated live attacks for visualization
export async function generateLiveAttacks(): Promise<LiveAttack[]> {
  const attacks: LiveAttack[] = [];
  
  // Common attack source countries
  const sources = [
    { country: 'China', lat: 35.8617, lon: 104.1954 },
    { country: 'Russia', lat: 61.5240, lon: 105.3188 },
    { country: 'United States', lat: 37.0902, lon: -95.7129 },
    { country: 'North Korea', lat: 40.3399, lon: 127.5101 },
    { country: 'Iran', lat: 32.4279, lon: 53.6880 },
    { country: 'Brazil', lat: -14.2350, lon: -51.9253 },
  ];
  
  // Common targets
  const targets = [
    { country: 'United States', lat: 37.0902, lon: -95.7129 },
    { country: 'United Kingdom', lat: 55.3781, lon: -3.4360 },
    { country: 'Germany', lat: 51.1657, lon: 10.4515 },
    { country: 'Japan', lat: 36.2048, lon: 138.2529 },
    { country: 'Australia', lat: -25.2744, lon: 133.7751 },
    { country: 'India', lat: 20.5937, lon: 78.9629 },
  ];
  
  const attackTypes = [
    'DDoS', 'SQL Injection', 'Brute Force', 'Malware', 
    'Ransomware', 'Phishing', 'Port Scan', 'Data Exfiltration'
  ];
  
  const protocols = ['TCP', 'UDP', 'HTTP', 'HTTPS', 'SSH', 'RDP'];
  const severities: Array<'critical' | 'high' | 'medium' | 'low'> = ['critical', 'high', 'medium', 'low'];
  
  for (let i = 0; i < 20; i++) {
    const source = sources[Math.floor(Math.random() * sources.length)];
    const target = targets[Math.floor(Math.random() * targets.length)];
    
    attacks.push({
      id: `attack-${Date.now()}-${i}`,
      timestamp: new Date(Date.now() - Math.random() * 60000),
      sourceIp: `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
      sourceCountry: source.country,
      sourceLocation: { lat: source.lat, lon: source.lon },
      targetIp: `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
      targetCountry: target.country,
      targetLocation: { lat: target.lat, lon: target.lon },
      attackType: attackTypes[Math.floor(Math.random() * attackTypes.length)],
      severity: severities[Math.floor(Math.random() * severities.length)],
      protocol: protocols[Math.floor(Math.random() * protocols.length)],
      port: Math.floor(Math.random() * 65535),
    });
  }
  
  return attacks.sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());
}

export function getSeverityColor(severity: string): string {
  const s = severity.toUpperCase();
  if (s === 'CRITICAL') return 'text-red-600';
  if (s === 'HIGH') return 'text-orange-500';
  if (s === 'MEDIUM') return 'text-yellow-500';
  if (s === 'LOW') return 'text-blue-500';
  return 'text-gray-500';
}

export function getSeverityBg(severity: string): string {
  const s = severity.toUpperCase();
  if (s === 'CRITICAL') return 'bg-red-500/20 border-red-500/50';
  if (s === 'HIGH') return 'bg-orange-500/20 border-orange-500/50';
  if (s === 'MEDIUM') return 'bg-yellow-500/20 border-yellow-500/50';
  if (s === 'LOW') return 'bg-blue-500/20 border-blue-500/50';
  return 'bg-gray-500/20 border-gray-500/50';
}
