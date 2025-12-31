// Enhanced CVE and Threat Intelligence Service
// Multi-source: NVD, CIRCL, CISA KEV, MITRE GitHub, Exploit-DB, Packet Storm, GitHub PoC

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
  kev?: KEVData; // CISA Known Exploited Vulnerabilities
  pocRepos?: GitHubPoC[];
  source: 'nvd' | 'circl' | 'mitre' | 'combined';
}

export interface KEVData {
  vendorProject: string;
  product: string;
  vulnerabilityName: string;
  dateAdded: string;
  shortDescription: string;
  requiredAction: string;
  dueDate: string;
  knownRansomwareCampaignUse: string;
}

export interface GitHubPoC {
  name: string;
  fullName: string;
  description: string;
  url: string;
  stars: number;
  forks: number;
  language: string;
  updatedAt: string;
}

export interface PacketStormEntry {
  title: string;
  link: string;
  description: string;
  pubDate: string;
  cve?: string;
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

const CORS_PROXY = 'https://api.allorigins.win/raw?url=';

// ============================================================================
// 1️⃣ NVD (NIST) — Official CVE Source
// ============================================================================

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

// NVD API - Primary source
export async function searchCVE(query: string, limit = 20): Promise<CVEData[]> {
  const cacheKey = `cve:search:${query}:${limit}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  try {
    // Try NVD first
    const nvdCVEs = await searchNVD(query, limit);
    if (nvdCVEs.length > 0) {
      await cacheAPIResponse(cacheKey, nvdCVEs, CVE_CACHE_TTL);
      return nvdCVEs;
    }
    
    // Fallback to CIRCL
    const circlCVEs = await searchCIRCL(query, limit);
    await cacheAPIResponse(cacheKey, circlCVEs, CVE_CACHE_TTL);
    return circlCVEs;
  } catch (error) {
    console.error('CVE search error:', error);
    return [];
  }
}

async function searchNVD(query: string, limit: number): Promise<CVEData[]> {
  try {
    const response = await fetch(
      `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${encodeURIComponent(query)}&resultsPerPage=${limit}`
    );

    if (!response.ok) throw new Error(`NVD API error: ${response.statusText}`);

    const data = await response.json();
    return parseNVDResponse(data);
  } catch (error) {
    console.error('NVD search error:', error);
    return [];
  }
}

function parseNVDResponse(data: any): CVEData[] {
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
      source: 'nvd',
    });
  }
  
  return cves;
}

// ============================================================================
// 2️⃣ CIRCL CVE Search — Fast, clean, no key needed
// ============================================================================

async function searchCIRCL(query: string, limit: number): Promise<CVEData[]> {
  try {
    // Check if query is a CVE ID
    if (query.toUpperCase().startsWith('CVE-')) {
      const response = await fetch(`https://cve.circl.lu/api/cve/${query.toUpperCase()}`);
      if (response.ok) {
        const data = await response.json();
        if (data) return [parseCIRCLCVE(data)];
      }
      return [];
    }
    
    // Try vendor/product search
    const response = await fetch(`https://cve.circl.lu/api/search/${encodeURIComponent(query)}`);
    if (!response.ok) throw new Error('CIRCL API error');
    
    const data = await response.json();
    return (data || []).slice(0, limit).map(parseCIRCLCVE);
  } catch (error) {
    console.error('CIRCL search error:', error);
    return [];
  }
}

function parseCIRCLCVE(cve: any): CVEData {
  return {
    id: cve.id || cve.cve,
    description: cve.summary || 'No description',
    published: cve.Published || cve.published,
    modified: cve.Modified || cve.modified,
    cvss: {
      score: cve.cvss || cve.cvss_score || 0,
      severity: getCVSSSeverity(cve.cvss || cve.cvss_score || 0),
      vector: cve.cvss_vector || '',
    },
    references: cve.references || [],
    cwe: cve.cwe ? [cve.cwe] : [],
    exploitAvailable: false,
    source: 'circl',
  };
}

function getCVSSSeverity(score: number): string {
  if (score >= 9.0) return 'CRITICAL';
  if (score >= 7.0) return 'HIGH';
  if (score >= 4.0) return 'MEDIUM';
  if (score > 0) return 'LOW';
  return 'UNKNOWN';
}

// Get latest CVEs from CIRCL (fast endpoint)
export async function getLatestCVEsFromCIRCL(limit = 30): Promise<CVEData[]> {
  const cacheKey = `cve:circl:latest:${limit}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;
  
  try {
    console.log('[CVE] Fetching latest from CIRCL...');
    const response = await fetch('https://cve.circl.lu/api/last');
    if (!response.ok) throw new Error('CIRCL latest API error');
    
    const data = await response.json();
    const cves = (data || []).slice(0, limit).map(parseCIRCLCVE);
    
    console.log(`[CVE] ✅ CIRCL returned ${cves.length} latest CVEs`);
    await cacheAPIResponse(cacheKey, cves, CVE_CACHE_TTL);
    return cves;
  } catch (error) {
    console.error('CIRCL latest error:', error);
    return [];
  }
}

// ============================================================================
// 3️⃣ CISA KEV Catalog — Actively Exploited (GOLD)
// ============================================================================

let kevCache: Map<string, KEVData> | null = null;
let kevCacheTime = 0;
const KEV_CACHE_DURATION = 3600000; // 1 hour

export async function getCISAKEV(): Promise<KEVData[]> {
  const cacheKey = 'cve:cisa:kev';
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;
  
  try {
    console.log('[CVE] Fetching CISA KEV catalog...');
    const response = await fetch('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json');
    if (!response.ok) throw new Error('CISA KEV API error');
    
    const data = await response.json();
    const vulnerabilities = data.vulnerabilities || [];
    
    // Build lookup cache
    kevCache = new Map();
    kevCacheTime = Date.now();
    
    const kevData: KEVData[] = vulnerabilities.map((v: any) => {
      const kev: KEVData = {
        vendorProject: v.vendorProject,
        product: v.product,
        vulnerabilityName: v.vulnerabilityName,
        dateAdded: v.dateAdded,
        shortDescription: v.shortDescription,
        requiredAction: v.requiredAction,
        dueDate: v.dueDate,
        knownRansomwareCampaignUse: v.knownRansomwareCampaignUse,
      };
      kevCache!.set(v.cveID, kev);
      return kev;
    });
    
    console.log(`[CVE] ✅ CISA KEV loaded ${kevData.length} actively exploited CVEs`);
    await cacheAPIResponse(cacheKey, kevData, 3600);
    return kevData;
  } catch (error) {
    console.error('CISA KEV error:', error);
    return [];
  }
}

export async function isKnownExploited(cveId: string): Promise<KEVData | null> {
  // Refresh cache if needed
  if (!kevCache || Date.now() - kevCacheTime > KEV_CACHE_DURATION) {
    await getCISAKEV();
  }
  return kevCache?.get(cveId.toUpperCase()) || null;
}

// ============================================================================
// 4️⃣ MITRE CVE GitHub Mirror — Raw CVE JSON (no rate limit)
// ============================================================================

export async function getCVEFromMITRE(cveId: string): Promise<CVEData | null> {
  try {
    // Parse CVE ID: CVE-2024-3094 -> 2024/3xxx/CVE-2024-3094.json
    const match = cveId.match(/CVE-(\d{4})-(\d+)/i);
    if (!match) return null;
    
    const year = match[1];
    const num = match[2];
    const prefix = num.slice(0, -3).padStart(1, '0') + 'xxx'; // e.g., 3094 -> 3xxx
    
    const url = `https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/${year}/${prefix}/CVE-${year}-${num}.json`;
    console.log(`[CVE] Fetching from MITRE GitHub: ${url}`);
    
    const response = await fetch(url);
    if (!response.ok) return null;
    
    const data = await response.json();
    const cna = data.containers?.cna;
    
    if (!cna) return null;
    
    return {
      id: cveId.toUpperCase(),
      description: cna.descriptions?.[0]?.value || 'No description',
      published: data.cveMetadata?.datePublished || '',
      modified: data.cveMetadata?.dateUpdated || '',
      cvss: {
        score: cna.metrics?.[0]?.cvssV3_1?.baseScore || cna.metrics?.[0]?.cvssV3_0?.baseScore || 0,
        severity: cna.metrics?.[0]?.cvssV3_1?.baseSeverity || 'UNKNOWN',
        vector: cna.metrics?.[0]?.cvssV3_1?.vectorString || '',
      },
      references: (cna.references || []).map((r: any) => r.url).slice(0, 10),
      cwe: (cna.problemTypes?.[0]?.descriptions || []).map((d: any) => d.cweId).filter(Boolean),
      exploitAvailable: false,
      source: 'mitre',
    };
  } catch (error) {
    console.error('MITRE GitHub error:', error);
    return null;
  }
}

// ============================================================================
// 5️⃣ Exploit-DB GitHub Mirror — PoCs without API
// ============================================================================

let exploitDBCache: ExploitData[] | null = null;
let exploitDBCacheTime = 0;

export async function loadExploitDBData(): Promise<ExploitData[]> {
  // Return cached if recent
  if (exploitDBCache && Date.now() - exploitDBCacheTime < 3600000) {
    return exploitDBCache;
  }
  
  try {
    console.log('[Exploit-DB] Loading CSV from GitHub...');
    const response = await fetch(
      'https://raw.githubusercontent.com/offensive-security/exploitdb/master/files_exploits.csv'
    );
    if (!response.ok) throw new Error('Failed to fetch ExploitDB');
    
    const csvData = await response.text();
    const lines = csvData.split('\n').slice(1);
    const exploits: ExploitData[] = [];
    
    for (const line of lines) {
      if (!line.trim()) continue;
      
      const parts = line.split(',');
      if (parts.length < 7) continue;
      
      const id = parts[0]?.replace(/"/g, '') || '';
      const title = parts[2]?.replace(/"/g, '') || '';
      
      exploits.push({
        id: `edb-${id}`,
        title,
        description: title,
        author: parts[3]?.replace(/"/g, '') || 'Unknown',
        type: parts[4]?.replace(/"/g, '') || '',
        platform: parts[5]?.replace(/"/g, '') || '',
        date: parts[1]?.replace(/"/g, '') || '',
        edbId: id,
        verified: parts[6]?.includes('1') || false,
        sourceUrl: `https://www.exploit-db.com/exploits/${id}`,
      });
    }
    
    exploitDBCache = exploits;
    exploitDBCacheTime = Date.now();
    console.log(`[Exploit-DB] ✅ Loaded ${exploits.length} exploits`);
    return exploits;
  } catch (error) {
    console.error('ExploitDB load error:', error);
    return exploitDBCache || [];
  }
}

export async function getCVEDetails(cveId: string): Promise<CVEData | null> {
  const cacheKey = `cve:details:${cveId}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  try {
    let cveData: CVEData | null = null;
    
    // Try NVD first (most authoritative)
    try {
      const response = await fetch(
        `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${cveId}`
      );

      if (response.ok) {
        const data = await response.json();
        const cve = data.vulnerabilities?.[0]?.cve;
        
        if (cve) {
          const metrics = cve.metrics?.cvssMetricV31?.[0] || cve.metrics?.cvssMetricV30?.[0] || cve.metrics?.cvssMetricV2?.[0];
          
          cveData = {
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
            source: 'nvd',
          };
        }
      }
    } catch (nvdError) {
      console.warn('NVD fallback, trying CIRCL:', nvdError);
    }
    
    // Fallback to CIRCL
    if (!cveData) {
      try {
        const response = await fetch(`https://cve.circl.lu/api/cve/${cveId}`);
        if (response.ok) {
          const data = await response.json();
          if (data) {
            cveData = parseCIRCLCVE(data);
          }
        }
      } catch {
        console.warn('CIRCL also failed, trying MITRE');
      }
    }
    
    // Fallback to MITRE GitHub
    if (!cveData) {
      cveData = await getCVEFromMITRE(cveId);
    }
    
    if (!cveData) return null;

    // Enrich with KEV data
    const kev = await isKnownExploited(cveId);
    if (kev) {
      cveData.kev = kev;
      cveData.exploitAvailable = true;
    }

    // Search for exploits
    const exploits = await searchExploitDB(cveId);
    if (exploits.length > 0) {
      cveData.exploitAvailable = true;
      cveData.exploitDetails = exploits[0];
    }
    
    // Search for GitHub PoCs
    const pocs = await searchGitHubPoC(cveId);
    if (pocs.length > 0) {
      cveData.exploitAvailable = true;
      cveData.pocRepos = pocs;
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
    // Try CIRCL first (faster, no rate limit)
    const circlCVEs = await getLatestCVEsFromCIRCL(limit);
    if (circlCVEs.length > 0) {
      await cacheAPIResponse(cacheKey, circlCVEs, CVE_CACHE_TTL);
      return circlCVEs;
    }
    
    // Fallback to NVD
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

// ============================================================================
// 6️⃣ Exploit-DB Search
// ============================================================================

export async function searchExploitDB(query: string, limit = 20): Promise<ExploitData[]> {
  const cacheKey = `exploitdb:${query}:${limit}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  try {
    // Load full ExploitDB data
    const allExploits = await loadExploitDBData();
    
    // Search in loaded data
    const queryLower = query.toLowerCase();
    const results = allExploits
      .filter(e => 
        e.title.toLowerCase().includes(queryLower) ||
        e.id.includes(query) ||
        e.edbId === query.replace('edb-', '')
      )
      .slice(0, limit);

    await cacheAPIResponse(cacheKey, results, EXPLOIT_CACHE_TTL);
    return results;
  } catch (error) {
    console.error('ExploitDB search error:', error);
    return [];
  }
}

// ============================================================================
// 7️⃣ Packet Storm RSS — Exploit Releases
// ============================================================================

export async function getPacketStormFeed(): Promise<PacketStormEntry[]> {
  const cacheKey = 'cve:packetstorm:feed';
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;
  
  try {
    console.log('[Packet Storm] Fetching RSS feed...');
    const response = await fetch(`${CORS_PROXY}${encodeURIComponent('https://packetstormsecurity.com/files/feed.xml')}`);
    if (!response.ok) throw new Error('Packet Storm fetch failed');
    
    const xml = await response.text();
    const entries: PacketStormEntry[] = [];
    
    // Parse XML manually (simple parsing)
    const itemMatches = xml.matchAll(/<item>([\s\S]*?)<\/item>/g);
    
    for (const match of itemMatches) {
      const item = match[1];
      const title = item.match(/<title>([\s\S]*?)<\/title>/)?.[1]?.trim() || '';
      const link = item.match(/<link>([\s\S]*?)<\/link>/)?.[1]?.trim() || '';
      const description = item.match(/<description>([\s\S]*?)<\/description>/)?.[1]?.trim() || '';
      const pubDate = item.match(/<pubDate>([\s\S]*?)<\/pubDate>/)?.[1]?.trim() || '';
      
      // Extract CVE if present
      const cveMatch = title.match(/CVE-\d{4}-\d+/i) || description.match(/CVE-\d{4}-\d+/i);
      
      entries.push({
        title: title.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&'),
        link,
        description: description.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&').substring(0, 300),
        pubDate,
        cve: cveMatch?.[0]?.toUpperCase(),
      });
      
      if (entries.length >= 30) break;
    }
    
    console.log(`[Packet Storm] ✅ Loaded ${entries.length} entries`);
    await cacheAPIResponse(cacheKey, entries, 1800);
    return entries;
  } catch (error) {
    console.error('Packet Storm error:', error);
    return [];
  }
}

// ============================================================================
// 8️⃣ GitHub PoC Search (NO KEY, LIMITED RATE)
// ============================================================================

export async function searchGitHubPoC(cveId: string): Promise<GitHubPoC[]> {
  const cacheKey = `cve:github:poc:${cveId}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;
  
  try {
    console.log(`[GitHub PoC] Searching for: ${cveId}`);
    const response = await fetch(
      `https://api.github.com/search/repositories?q=${encodeURIComponent(cveId + ' exploit')}&sort=stars&order=desc&per_page=10`,
      { headers: { 'User-Agent': 'OSINT-Hub/1.0' } }
    );
    
    if (!response.ok) {
      if (response.status === 403) {
        console.warn('[GitHub PoC] Rate limited');
      }
      return [];
    }
    
    const data = await response.json();
    const pocs: GitHubPoC[] = (data.items || []).map((repo: any) => ({
      name: repo.name,
      fullName: repo.full_name,
      description: repo.description || '',
      url: repo.html_url,
      stars: repo.stargazers_count,
      forks: repo.forks_count,
      language: repo.language || 'Unknown',
      updatedAt: repo.updated_at,
    }));
    
    console.log(`[GitHub PoC] ✅ Found ${pocs.length} repositories`);
    await cacheAPIResponse(cacheKey, pocs, 3600);
    return pocs;
  } catch (error) {
    console.error('GitHub PoC search error:', error);
    return [];
  }
}

// ============================================================================
// Combined: Get comprehensive CVE intelligence
// ============================================================================

export interface ComprehensiveCVEData extends CVEData {
  isKEV: boolean;
  kevData?: KEVData;
  exploits: ExploitData[];
  githubPoCs: GitHubPoC[];
  packetStormRefs: PacketStormEntry[];
}

export async function getComprehensiveCVEIntel(cveId: string): Promise<ComprehensiveCVEData | null> {
  try {
    console.log(`[CVE Intel] Getting comprehensive data for: ${cveId}`);
    
    // Fetch all data in parallel
    const [cveDetails, kev, exploits, pocs] = await Promise.all([
      getCVEDetails(cveId),
      isKnownExploited(cveId),
      searchExploitDB(cveId, 5),
      searchGitHubPoC(cveId),
    ]);
    
    if (!cveDetails) {
      console.warn(`[CVE Intel] No CVE data found for ${cveId}`);
      return null;
    }
    
    // Get Packet Storm references (filter by CVE)
    const psEntries = await getPacketStormFeed();
    const psRefs = psEntries.filter(e => e.cve === cveId.toUpperCase());
    
    return {
      ...cveDetails,
      isKEV: !!kev,
      kevData: kev || undefined,
      exploits,
      githubPoCs: pocs,
      packetStormRefs: psRefs,
      exploitAvailable: exploits.length > 0 || pocs.length > 0 || !!kev,
    };
  } catch (error) {
    console.error('Comprehensive CVE intel error:', error);
    return null;
  }
}

// ============================================================================
// Get trending/critical CVEs (combines KEV + recent high severity)
// ============================================================================

export async function getTrendingCVEs(limit = 20): Promise<CVEData[]> {
  const cacheKey = `cve:trending:${limit}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;
  
  try {
    // Get CISA KEV (actively exploited = highest priority)
    await getCISAKEV(); // Ensure cache is loaded
    
    // Get recent CVEs from CIRCL
    const recentCVEs = await getLatestCVEsFromCIRCL(50);
    
    // Enrich with KEV status and sort by severity + KEV
    const enriched = await Promise.all(
      recentCVEs.map(async (cve) => {
        const kev = await isKnownExploited(cve.id);
        return {
          ...cve,
          kev,
          exploitAvailable: !!kev,
          priorityScore: (kev ? 100 : 0) + (cve.cvss.score * 10),
        };
      })
    );
    
    // Sort by priority (KEV first, then CVSS score)
    enriched.sort((a, b) => b.priorityScore - a.priorityScore);
    
    const result = enriched.slice(0, limit);
    await cacheAPIResponse(cacheKey, result, CVE_CACHE_TTL);
    return result;
  } catch (error) {
    console.error('Trending CVEs error:', error);
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
