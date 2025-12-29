// src/services/cveService.ts
// CVE & Exploit Intelligence Service
// Real integration with NVD, ExploitDB, and other CVE sources

import { cacheAPIResponse, getCachedData } from '@/lib/database';

/* ============================================================================
   TYPES
============================================================================ */

export interface CVE {
  id:  string;
  description: string;
  published: string;
  modified: string;
  cvss: {
    version: string;
    score: number;
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
    vector: string;
  };
  cwe?:  string[];
  references:  Array<{
    url: string;
    source: string;
    tags: string[];
  }>;
  cpe?: string[];
  exploits: Exploit[];
  affected: Array<{
    vendor: string;
    product: string;
    versions: string[];
  }>;
}

export interface Exploit {
  id: string;
  title: string;
  description: string;
  author: string;
  type: string;
  platform: string;
  verified: boolean;
  cveId?: string;
  edbId?: string;
  date: string;
  url: string;
  code?: string;
  tags: string[];
  source: 'exploit-db' | 'github' | 'packetstorm' | 'metasploit';
}

export interface CVESearchParams {
  keyword?: string;
  cveId?: string;
  vendor?: string;
  product?:  string;
  year?: string;
  severity?: string;
  hasExploit?: boolean;
}

/* ============================================================================
   NVD CVE API - NATIONAL VULNERABILITY DATABASE
============================================================================ */

export async function searchCVEs(params: CVESearchParams): Promise<CVE[]> {
  const cacheKey = `cve:search:${JSON. stringify(params)}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const cves: CVE[] = [];

  try {
    let nvdUrl = 'https://services.nvd.nist.gov/rest/json/cves/2.0? ';
    
    if (params. cveId) {
      nvdUrl += `cveId=${params.cveId}`;
    } else if (params.keyword) {
      nvdUrl += `keywordSearch=${encodeURIComponent(params.keyword)}`;
    }
    
    if (params.severity) {
      nvdUrl += `&cvssV3Severity=${params.severity}`;
    }

    nvdUrl += '&resultsPerPage=50';

    const response = await fetch(nvdUrl);
    
    if (!response. ok) throw new Error('NVD API failed');

    const data = await response.json();

    for (const item of data.vulnerabilities || []) {
      const cve = item. cve;
      
      const cvssData = cve.metrics?.cvssMetricV31? .[0] || 
                       cve.metrics?.cvssMetricV30?.[0] || 
                       cve.metrics?.cvssMetricV2? .[0];

      const cvssScore = cvssData?.cvssData?.baseScore || 0;
      const cvssVector = cvssData?. cvssData?.vectorString || '';
      const severity = cvssData?.cvssData?.baseSeverity || 
                      (cvssScore >= 9.0 ? 'CRITICAL' : 
                       cvssScore >= 7.0 ? 'HIGH' : 
                       cvssScore >= 4.0 ? 'MEDIUM' :  'LOW');

      const affected = [];
      for (const config of cve.configurations || []) {
        for (const node of config.nodes || []) {
          for (const cpeMatch of node.cpeMatch || []) {
            const cpeUri = cpeMatch.criteria || '';
            const parts = cpeUri.split(': ');
            if (parts.length >= 5) {
              affected.push({
                vendor: parts[3],
                product: parts[4],
                versions: [parts[5] || '*'],
              });
            }
          }
        }
      }

      const exploits = await searchExploits(cve.id);

      cves.push({
        id: cve.id,
        description: cve.descriptions? .[0]?.value || 'No description available',
        published:  cve.published,
        modified: cve.lastModified,
        cvss: {
          version: cvssData?.cvssData?.version || '3.1',
          score: cvssScore,
          severity: severity as any,
          vector: cvssVector,
        },
        cwe: cve.weaknesses?.[0]?.description?. map((d: any) => d.value) || [],
        references: cve.references?. map((ref: any) => ({
          url: ref.url,
          source: ref.source || 'NVD',
          tags: ref.tags || [],
        })) || [],
        cpe: cve.configurations?.[0]?.nodes?.[0]?.cpeMatch?. map((m: any) => m.criteria) || [],
        exploits,
        affected,
      });
    }

    await cacheAPIResponse(cacheKey, cves, 3600);
    return cves;
  } catch (error) {
    console.error('CVE search error:', error);
    return [];
  }
}

export async function getCVEDetails(cveId: string): Promise<CVE | null> {
  const results = await searchCVEs({ cveId });
  return results[0] || null;
}

export async function searchExploits(cveId?: string, keyword?: string): Promise<Exploit[]> {
  const cacheKey = `exploits:${cveId || keyword || 'recent'}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const exploits:  Exploit[] = [];

  try {
    const edbUrl = 'https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits. csv';
    const response = await fetch(edbUrl);
    
    if (!response.ok) throw new Error('ExploitDB fetch failed');

    const csvText = await response.text();
    const lines = csvText.split('\n').slice(1);

    for (const line of lines.slice(0, 100)) {
      const parts = line. split(',');
      if (parts.length < 5) continue;

      const [id, file, description, date, author, type, platform] = parts;

      if (cveId && ! description.toLowerCase().includes(cveId.toLowerCase())) {
        continue;
      }

      if (keyword && !description.toLowerCase().includes(keyword.toLowerCase())) {
        continue;
      }

      exploits.push({
        id: `edb-${id}`,
        edbId: id,
        title: description. replace(/"/g, ''),
        description:  description.replace(/"/g, ''),
        author: author.replace(/"/g, ''),
        type: type.replace(/"/g, ''),
        platform: platform.replace(/"/g, ''),
        verified: true,
        cveId: extractCVEFromText(description),
        date: date,
        url: `https://www.exploit-db.com/exploits/${id}`,
        tags: [type.replace(/"/g, ''), platform.replace(/"/g, '')],
        source: 'exploit-db',
      });

      if (exploits.length >= 20) break;
    }

    await cacheAPIResponse(cacheKey, exploits, 3600);
    return exploits;
  } catch (error) {
    console.error('ExploitDB search error:', error);
    return [];
  }
}

export async function getExploitCode(edbId: string): Promise<string | null> {
  const cacheKey = `exploit:code:${edbId}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  try {
    const response = await fetch(`https://www.exploit-db.com/download/${edbId}`);
    
    if (!response.ok) return null;

    const code = await response.text();
    
    await cacheAPIResponse(cacheKey, code, 86400);
    return code;
  } catch (error) {
    console.error('Get exploit code error:', error);
    return null;
  }
}

export async function searchGitHubPOCs(cveId: string): Promise<Exploit[]> {
  const cacheKey = `github:poc:${cveId}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const pocs: Exploit[] = [];

  try {
    const response = await fetch(
      `https://api.github.com/search/repositories?q=${cveId}+poc+OR+exploit&sort=stars&order=desc`,
      {
        headers: {
          'Accept':  'application/vnd. github.v3+json',
          'User-Agent': 'OSINT-Platform',
        },
      }
    );

    if (!response.ok) throw new Error('GitHub search failed');

    const data = await response.json();

    for (const repo of data.items?. slice(0, 10) || []) {
      pocs.push({
        id: `github-${repo.id}`,
        title: repo.name,
        description: repo.description || 'No description',
        author:  repo.owner. login,
        type: 'POC',
        platform: 'Multiple',
        verified: false,
        cveId,
        date: repo.created_at,
        url: repo.html_url,
        tags: ['poc', 'github', ... repo.topics || []],
        source: 'github',
      });
    }

    await cacheAPIResponse(cacheKey, pocs, 3600);
    return pocs;
  } catch (error) {
    console.error('GitHub POC search error:', error);
    return [];
  }
}

export async function getRecentCVEs(days: number = 7, limit:  number = 50): Promise<CVE[]> {
  const cacheKey = `cve:recent:${days}:${limit}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  try {
    const endDate = new Date();
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - days);

    const nvdUrl = `https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=${startDate.toISOString()}&pubEndDate=${endDate.toISOString()}&resultsPerPage=${limit}`;

    const response = await fetch(nvdUrl);
    
    if (!response.ok) throw new Error('NVD API failed');

    const data = await response.json();
    const cves: CVE[] = [];

    for (const item of data.vulnerabilities || []) {
      const cve = item.cve;
      
      const cvssData = cve.metrics?.cvssMetricV31?.[0] || 
                       cve. metrics?.cvssMetricV30?.[0];

      const cvssScore = cvssData?.cvssData?.baseScore || 0;
      const severity = cvssData?.cvssData?.baseSeverity || 'LOW';

      cves.push({
        id: cve.id,
        description: cve.descriptions? .[0]?.value || '',
        published: cve.published,
        modified: cve.lastModified,
        cvss:  {
          version: '3.1',
          score: cvssScore,
          severity: severity as any,
          vector: cvssData?.cvssData?.vectorString || '',
        },
        cwe: cve.weaknesses? .[0]?.description?.map((d: any) => d.value) || [],
        references: cve.references?.map((ref: any) => ({
          url:  ref.url,
          source: ref.source || 'NVD',
          tags: ref. tags || [],
        })) || [],
        exploits: [],
        affected: [],
      });
    }

    await cacheAPIResponse(cacheKey, cves, 1800);
    return cves;
  } catch (error) {
    console.error('Recent CVEs error:', error);
    return [];
  }
}

function extractCVEFromText(text: string): string | undefined {
  const match = text.match(/CVE-\d{4}-\d{4,}/i);
  return match ? match[0]. toUpperCase() : undefined;
}

export function getSeverityColor(severity: string): string {
  switch (severity.toUpperCase()) {
    case 'CRITICAL': return 'text-red-500 border-red-500';
    case 'HIGH':  return 'text-orange-500 border-orange-500';
    case 'MEDIUM': return 'text-yellow-500 border-yellow-500';
    case 'LOW': return 'text-blue-500 border-blue-500';
    default:  return 'text-gray-500 border-gray-500';
  }
}
