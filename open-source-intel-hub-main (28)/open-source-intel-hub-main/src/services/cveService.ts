// Enhanced CVE and Threat Intelligence Service
// Multi-source: NVD, CIRCL, CISA KEV, MITRE GitHub, Exploit-DB, Packet Storm, GitHub PoC

import { cacheAPIResponse, getCachedData } from '@/lib/database';
import { threatFeedsAPI } from '@/lib/api/threatFeeds';

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

// NVD API - Primary source
export async function searchCVE(query: string, limit = 20): Promise<CVEData[]> {
  const cacheKey = `cve:search:${query}:${limit}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const normalizedQuery = query.trim();
  
  try {
    // If it's a CVE ID, use specific lookup
    if (normalizedQuery.toUpperCase().startsWith('CVE-')) {
      const cveId = normalizedQuery.toUpperCase();
      console.log(`[CVE] Looking up specific CVE: ${cveId}`);
      
      // Try multiple sources for specific CVE
      let cve = await getCVEFromNVD(cveId);
      if (!cve) cve = await getCVEFromCIRCL(cveId);
      if (!cve) cve = await getCVEFromMITRE(cveId);
      
      if (cve) {
        await cacheAPIResponse(cacheKey, [cve], CVE_CACHE_TTL);
        return [cve];
      }
      return [];
    }
    
    // For keyword searches, use NVD (most reliable for keyword search)
    console.log(`[CVE] Searching NVD for keyword: ${normalizedQuery}`);
    const nvdCVEs = await searchNVD(normalizedQuery, limit);
    
    if (nvdCVEs.length > 0) {
      console.log(`[CVE] ✅ NVD found ${nvdCVEs.length} results`);
      await cacheAPIResponse(cacheKey, nvdCVEs, CVE_CACHE_TTL);
      return nvdCVEs;
    }
    
    // If NVD returns nothing, search ExploitDB for related exploits
    console.log(`[CVE] NVD returned 0 results, searching ExploitDB...`);
    const exploits = await searchExploitDB(normalizedQuery, limit);
    
    if (exploits.length > 0) {
      // Convert exploits to CVE-like format for display
      const exploitCVEs: CVEData[] = exploits.map(exp => ({
        id: exp.id,
        description: exp.title,
        published: exp.date,
        modified: exp.date,
        cvss: { score: 7.5, severity: 'HIGH', vector: '' },
        references: [exp.sourceUrl],
        cwe: [],
        exploitAvailable: true,
        exploitDetails: exp,
        source: 'combined' as const,
      }));
      
      console.log(`[CVE] ✅ ExploitDB found ${exploitCVEs.length} results`);
      await cacheAPIResponse(cacheKey, exploitCVEs, CVE_CACHE_TTL);
      return exploitCVEs;
    }
    
    // Last resort: Search GitHub for PoCs
    console.log(`[CVE] Searching GitHub for exploits...`);
    const pocs = await searchGitHubPoC(normalizedQuery);
    
    if (pocs.length > 0) {
      const pocCVEs: CVEData[] = pocs.slice(0, limit).map(poc => ({
        id: `github-${poc.name}`,
        description: poc.description || poc.name,
        published: poc.updatedAt,
        modified: poc.updatedAt,
        cvss: { score: 0, severity: 'UNKNOWN', vector: '' },
        references: [poc.url],
        cwe: [],
        exploitAvailable: true,
        pocRepos: [poc],
        source: 'combined' as const,
      }));
      
      console.log(`[CVE] ✅ GitHub found ${pocCVEs.length} results`);
      await cacheAPIResponse(cacheKey, pocCVEs, CVE_CACHE_TTL);
      return pocCVEs;
    }
    
    console.log(`[CVE] No results found for: ${normalizedQuery}`);
    return [];
  } catch (error) {
    console.error('CVE search error:', error);
    return [];
  }
}

// Get specific CVE from NVD
async function getCVEFromNVD(cveId: string): Promise<CVEData | null> {
  try {
    const response = await fetch(
      `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${cveId}`
    );
    if (!response.ok) return null;
    
    const data = await response.json();
    const cves = parseNVDResponse(data);
    return cves.length > 0 ? cves[0] : null;
  } catch {
    return null;
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
// Note: CIRCL now uses CVE JSON 5.0 format
// ============================================================================

async function searchCIRCL(query: string, limit: number): Promise<CVEData[]> {
  try {
    // Check if query is a CVE ID
    if (query.toUpperCase().startsWith('CVE-')) {
      const cve = await getCVEFromCIRCL(query.toUpperCase());
      return cve ? [cve] : [];
    }
    
    // For non-CVE queries, search NVD instead (CIRCL doesn't have good keyword search)
    return [];
  } catch (error) {
    console.error('CIRCL search error:', error);
    return [];
  }
}

// Parse single CVE from CIRCL (CVE JSON 5.0 format)
async function getCVEFromCIRCL(cveId: string): Promise<CVEData | null> {
  try {
    const response = await fetch(`https://cve.circl.lu/api/cve/${cveId}`);
    if (!response.ok) return null;
    
    const data = await response.json();
    return parseCVE5Format(data);
  } catch {
    return null;
  }
}

// Parse CVE JSON 5.0 format (used by CIRCL and MITRE)
function parseCVE5Format(data: any): CVEData | null {
  if (!data || !data.cveMetadata) return null;
  
  const cna = data.containers?.cna;
  const adp = Array.isArray(data.containers?.adp) ? data.containers.adp : [];
  
  // Get description from CNA
  let description = 'No description available';
  if (cna?.descriptions && Array.isArray(cna.descriptions)) {
    const engDesc = cna.descriptions.find((d: any) => d.lang === 'en' || !d.lang);
    description = engDesc?.value || cna.descriptions[0]?.value || description;
  }
  
  // Get CVSS from metrics
  let cvssScore = 0;
  let cvssSeverity = 'UNKNOWN';
  let cvssVector = '';
  
  if (cna?.metrics && Array.isArray(cna.metrics)) {
    for (const metric of cna.metrics) {
      const cvss = metric.cvssV3_1 || metric.cvssV3_0 || metric.cvssV31 || metric.cvssV30;
      if (cvss) {
        cvssScore = cvss.baseScore || 0;
        cvssSeverity = cvss.baseSeverity || getCVSSSeverity(cvssScore);
        cvssVector = cvss.vectorString || '';
        break;
      }
    }
  }
  
  // Check ADP for additional CVSS data
  if (cvssScore === 0 && adp.length > 0) {
    for (const adpEntry of adp) {
      if (adpEntry.metrics && Array.isArray(adpEntry.metrics)) {
        for (const metric of adpEntry.metrics) {
          const cvss = metric.cvssV3_1 || metric.cvssV3_0 || metric.cvssV31 || metric.cvssV30;
          if (cvss) {
            cvssScore = cvss.baseScore || 0;
            cvssSeverity = cvss.baseSeverity || getCVSSSeverity(cvssScore);
            cvssVector = cvss.vectorString || '';
            break;
          }
        }
      }
    }
  }
  
  // Get references
  const references: string[] = [];
  if (cna?.references && Array.isArray(cna.references)) {
    cna.references.slice(0, 10).forEach((ref: any) => {
      if (ref.url) references.push(ref.url);
    });
  }
  
  // Get CWE
  const cweIds: string[] = [];
  if (cna?.problemTypes && Array.isArray(cna.problemTypes)) {
    for (const pt of cna.problemTypes) {
      if (pt.descriptions && Array.isArray(pt.descriptions)) {
        for (const desc of pt.descriptions) {
          if (desc.cweId) cweIds.push(desc.cweId);
        }
      }
    }
  }
  
  return {
    id: data.cveMetadata.cveId,
    description,
    published: data.cveMetadata.datePublished || '',
    modified: data.cveMetadata.dateUpdated || '',
    cvss: {
      score: cvssScore,
      severity: cvssSeverity,
      vector: cvssVector,
    },
    references,
    cwe: cweIds,
    exploitAvailable: false,
    source: 'circl',
  };
}

function parseCIRCLCVE(cve: any): CVEData {
  // Handle both old format and new CVE 5.0 format
  if (cve.cveMetadata) {
    return parseCVE5Format(cve) || {
      id: cve.cveMetadata?.cveId || 'UNKNOWN',
      description: 'No description',
      published: '',
      modified: '',
      cvss: { score: 0, severity: 'UNKNOWN', vector: '' },
      references: [],
      cwe: [],
      exploitAvailable: false,
      source: 'circl',
    };
  }
  
  // Old format fallback
  return {
    id: cve.id || cve.cve,
    description: cve.summary || 'No description',
    published: cve.Published || cve.published || '',
    modified: cve.Modified || cve.modified || '',
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
    
    // Handle both array response and CVE 5.0 format
    const cves: CVEData[] = [];
    const items = Array.isArray(data) ? data : (data.value || []);
    
    for (const item of items.slice(0, limit)) {
      const parsed = parseCVE5Format(item);
      if (parsed) {
        cves.push(parsed);
      }
    }
    
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
        source: 'nvd',
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

export async function searchGitHubPoC(query: string, limit = 10): Promise<GitHubPoC[]> {
  const cacheKey = `cve:github:poc:${query}:${limit}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;
  
  try {
    // Build search query - add exploit/poc keywords if not already present
    let searchQuery = query;
    const queryLower = query.toLowerCase();
    if (!queryLower.includes('exploit') && !queryLower.includes('poc') && !queryLower.includes('vulnerability')) {
      searchQuery = `${query} exploit OR poc OR vulnerability`;
    }
    
    console.log(`[GitHub PoC] Searching for: ${searchQuery}`);
    const response = await fetch(
      `https://api.github.com/search/repositories?q=${encodeURIComponent(searchQuery)}&sort=stars&order=desc&per_page=${limit}`,
      { headers: { 'User-Agent': 'OSINT-Hub/1.0' } }
    );
    
    if (!response.ok) {
      if (response.status === 403) {
        console.warn('[GitHub PoC] Rate limited');
      } else {
        console.warn(`[GitHub PoC] API error: ${response.status}`);
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

export async function getLiveThreatFeeds(): Promise<ThreatFeed[]> {
  const cacheKey = 'threats:live:feeds';
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  try {
    const response = await threatFeedsAPI.fetchAllFeeds(7, 200);
    if (!response.success) {
      return [];
    }

    const feeds: ThreatFeed[] = [];
    const { sources, timestamp } = response;
    const fallbackTime = timestamp || new Date().toISOString();

    if (sources.feodo.success && sources.feodo.data?.length) {
      sources.feodo.data.slice(0, 100).forEach((item) => {
        feeds.push({
          id: `feodo-${item.ip_address}`,
          type: 'botnet',
          indicator: item.ip_address,
          indicatorType: 'ip',
          threat: item.malware || 'Botnet C2',
          confidence: 95,
          firstSeen: item.first_seen || item.last_online || fallbackTime,
          lastSeen: item.last_online || item.first_seen || fallbackTime,
          source: 'Feodo Tracker',
          tags: ['botnet', 'c2', item.malware?.toLowerCase() || ''].filter(Boolean),
        });
      });
    }

    if (sources.urlhaus.success && sources.urlhaus.data?.length) {
      sources.urlhaus.data.slice(0, 50).forEach((item) => {
        feeds.push({
          id: `urlhaus-${item.id || item.url}`,
          type: 'malware',
          indicator: item.url,
          indicatorType: 'url',
          threat: item.threat || 'Malware Distribution',
          confidence: 90,
          firstSeen: item.dateadded || fallbackTime,
          lastSeen: item.last_online || item.dateadded || fallbackTime,
          source: 'URLhaus',
          tags: item.tags || [],
        });
      });
    }

    if (sources.threatfox.success && sources.threatfox.data?.length) {
      sources.threatfox.data.slice(0, 50).forEach((item) => {
        const isIp = item.ioc_type === 'ip' || item.ioc_type === 'ip:port';
        const indicatorType: ThreatFeed['indicatorType'] =
          isIp ? 'ip' : item.ioc_type === 'url' ? 'url' : 'domain';

        const threatType = item.threat_type?.toLowerCase() || '';
        let type: ThreatFeed['type'] = 'malware';
        if (threatType.includes('apt')) type = 'apt';
        else if (threatType.includes('ransom')) type = 'ransomware';

        const tags = typeof item.tags === 'string'
          ? item.tags.split(',').map((t) => t.trim()).filter(Boolean)
          : item.tags || [];

        feeds.push({
          id: `threatfox-${item.id || item.ioc_value}`,
          type,
          indicator: item.ioc_value,
          indicatorType,
          threat: item.malware_printable || item.threat_type || 'Unknown Threat',
          confidence: item.confidence_level || 80,
          firstSeen: item.first_seen_utc || fallbackTime,
          lastSeen: item.last_seen_utc || item.first_seen_utc || fallbackTime,
          source: 'ThreatFox',
          tags,
        });
      });
    }

    if (sources.malwarebazaar.success && sources.malwarebazaar.data?.length) {
      sources.malwarebazaar.data.slice(0, 50).forEach((sample) => {
        feeds.push({
          id: `malwarebazaar-${sample.sha256_hash}`,
          type: 'malware',
          indicator: sample.sha256_hash,
          indicatorType: 'hash',
          threat: sample.signature || 'Unknown Malware',
          confidence: 95,
          firstSeen: sample.first_seen || fallbackTime,
          lastSeen: sample.last_seen || sample.first_seen || fallbackTime,
          source: 'MalwareBazaar',
          tags: sample.tags || [],
        });
      });
    }

    await cacheAPIResponse(cacheKey, feeds, THREAT_FEED_CACHE_TTL);
    return feeds;
  } catch (error) {
    console.error('Live threat feeds error:', error);
    return [];
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
