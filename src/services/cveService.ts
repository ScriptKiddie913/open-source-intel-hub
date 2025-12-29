// src/services/cveService.ts
// CVE & Exploit Intelligence Service
// Real integration with NVD (NIST), ExploitDB, and public OSINT sources
// NO API KEYS REQUIRED

import { cacheAPIResponse, getCachedData } from '@/lib/database';

/* ============================================================================
   TYPES
============================================================================ */

export interface CVE {
  id: string;
  description: string;
  published: string;
  modified: string;
  cvss: {
    version: string;
    score: number;
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
    vector: string;
  };
  cwe?: string[];
  references: Array<{
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
  product?: string;
  year?: string;
  severity?: string;
  hasExploit?: boolean;
}

/* ============================================================================
   NVD – NATIONAL VULNERABILITY DATABASE (NO API KEY)
============================================================================ */

export async function searchCVEs(
  params: CVESearchParams
): Promise<CVE[]> {
  const cacheKey = `cve:search:${JSON.stringify(params)}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const results: CVE[] = [];

  try {
    let nvdUrl =
      'https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=50';

    if (params.cveId) {
      nvdUrl += `&cveId=${encodeURIComponent(params.cveId)}`;
    }

    if (params.keyword) {
      nvdUrl += `&keywordSearch=${encodeURIComponent(params.keyword)}`;
    }

    if (params.severity) {
      nvdUrl += `&cvssV3Severity=${params.severity.toUpperCase()}`;
    }

    const response = await fetch(nvdUrl);
    if (!response.ok) {
      throw new Error('NVD API request failed');
    }

    const data = await response.json();

    for (const entry of data.vulnerabilities || []) {
      const cve = entry.cve;

      const cvssMetric =
        cve.metrics?.cvssMetricV31?.[0] ||
        cve.metrics?.cvssMetricV30?.[0] ||
        cve.metrics?.cvssMetricV2?.[0];

      const cvssScore = cvssMetric?.cvssData?.baseScore ?? 0;
      const vector = cvssMetric?.cvssData?.vectorString ?? '';
      const severity =
        cvssMetric?.cvssData?.baseSeverity ||
        (cvssScore >= 9
          ? 'CRITICAL'
          : cvssScore >= 7
          ? 'HIGH'
          : cvssScore >= 4
          ? 'MEDIUM'
          : 'LOW');

      const affected: CVE['affected'] = [];

      for (const config of cve.configurations || []) {
        for (const node of config.nodes || []) {
          for (const match of node.cpeMatch || []) {
            const cpe = match.criteria;
            if (!cpe) continue;

            const parts = cpe.split(':');
            if (parts.length >= 6) {
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

      results.push({
        id: cve.id,
        description:
          cve.descriptions?.[0]?.value || 'No description available',
        published: cve.published,
        modified: cve.lastModified,
        cvss: {
          version: cvssMetric?.cvssData?.version || '3.1',
          score: cvssScore,
          severity: severity as any,
          vector,
        },
        cwe:
          cve.weaknesses?.[0]?.description?.map(
            (d: { value: string }) => d.value
          ) || [],
        references:
          cve.references?.map((ref: any) => ({
            url: ref.url,
            source: ref.source || 'NVD',
            tags: ref.tags || [],
          })) || [],
        cpe:
          cve.configurations?.[0]?.nodes?.[0]?.cpeMatch?.map(
            (m: any) => m.criteria
          ) || [],
        exploits,
        affected,
      });
    }

    await cacheAPIResponse(cacheKey, results, 3600);
    return results;
  } catch (error) {
    console.error('CVE search error:', error);
    return [];
  }
}

/* ============================================================================
   SINGLE CVE DETAILS
============================================================================ */

export async function getCVEDetails(
  cveId: string
): Promise<CVE | null> {
  const results = await searchCVEs({ cveId });
  return results[0] || null;
}

/* ============================================================================
   EXPLOIT SEARCH – EXPLOIT-DB (NO API KEY)
============================================================================ */

export async function searchExploits(
  cveId?: string,
  keyword?: string
): Promise<Exploit[]> {
  const cacheKey = `exploits:${cveId || keyword || 'recent'}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const exploits: Exploit[] = [];

  try {
    const response = await fetch(
      'https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv'
    );

    if (!response.ok) {
      throw new Error('ExploitDB CSV fetch failed');
    }

    const csv = await response.text();
    const lines = csv.split('\n').slice(1);

    for (const line of lines) {
      if (exploits.length >= 20) break;

      const parts = line.split(',');
      if (parts.length < 7) continue;

      const [
        id,
        file,
        description,
        date,
        author,
        type,
        platform,
      ] = parts.map((p) => p.replace(/"/g, '').trim());

      if (cveId && !description.toLowerCase().includes(cveId.toLowerCase())) {
        continue;
      }

      if (keyword && !description.toLowerCase().includes(keyword.toLowerCase())) {
        continue;
      }

      exploits.push({
        id: `edb-${id}`,
        edbId: id,
        title: description,
        description,
        author,
        type,
        platform,
        verified: true,
        cveId: extractCVEFromText(description),
        date,
        url: `https://www.exploit-db.com/exploits/${id}`,
        tags: [type, platform],
        source: 'exploit-db',
      });
    }

    await cacheAPIResponse(cacheKey, exploits, 3600);
    return exploits;
  } catch (error) {
    console.error('Exploit search error:', error);
    return [];
  }
}

/* ============================================================================
   EXPLOIT SOURCE CODE – EXPLOIT-DB
============================================================================ */

export async function getExploitCode(
  edbId: string
): Promise<string | null> {
  const cacheKey = `exploit:code:${edbId}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  try {
    const response = await fetch(
      `https://www.exploit-db.com/download/${edbId}`
    );

    if (!response.ok) return null;

    const code = await response.text();
    await cacheAPIResponse(cacheKey, code, 86400);
    return code;
  } catch (error) {
    console.error('Exploit code fetch error:', error);
    return null;
  }
}

/* ============================================================================
   GITHUB PROOF-OF-CONCEPT SEARCH (NO AUTH, RATE LIMITED)
============================================================================ */

export async function searchGitHubPOCs(
  cveId: string
): Promise<Exploit[]> {
  const cacheKey = `github:poc:${cveId}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const pocs: Exploit[] = [];

  try {
    const response = await fetch(
      `https://api.github.com/search/repositories?q=${encodeURIComponent(
        `${cveId} poc exploit`
      )}&sort=stars&order=desc`,
      {
        headers: {
          Accept: 'application/vnd.github.v3+json',
          'User-Agent': 'OSINT-Platform',
        },
      }
    );

    if (!response.ok) {
      throw new Error('GitHub search failed');
    }

    const data = await response.json();

    for (const repo of data.items?.slice(0, 10) || []) {
      pocs.push({
        id: `github-${repo.id}`,
        title: repo.name,
        description: repo.description || 'No description',
        author: repo.owner.login,
        type: 'POC',
        platform: 'Multiple',
        verified: false,
        cveId,
        date: repo.created_at,
        url: repo.html_url,
        tags: ['github', 'poc', ...(repo.topics || [])],
        source: 'github',
      });
    }

    await cacheAPIResponse(cacheKey, pocs, 3600);
    return pocs;
  } catch (error) {
    console.error('GitHub POC error:', error);
    return [];
  }
}

/* ============================================================================
   RECENT CVES
============================================================================ */

export async function getRecentCVEs(
  days: number = 7,
  limit: number = 50
): Promise<CVE[]> {
  const cacheKey = `cve:recent:${days}:${limit}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  try {
    const end = new Date();
    const start = new Date();
    start.setDate(start.getDate() - days);

    const url =
      `https://services.nvd.nist.gov/rest/json/cves/2.0` +
      `?pubStartDate=${start.toISOString()}` +
      `&pubEndDate=${end.toISOString()}` +
      `&resultsPerPage=${limit}`;

    const response = await fetch(url);
    if (!response.ok) {
      throw new Error('NVD recent CVEs failed');
    }

    const data = await response.json();
    const cves: CVE[] = [];

    for (const entry of data.vulnerabilities || []) {
      const cve = entry.cve;
      const metric = cve.metrics?.cvssMetricV31?.[0];

      cves.push({
        id: cve.id,
        description: cve.descriptions?.[0]?.value || '',
        published: cve.published,
        modified: cve.lastModified,
        cvss: {
          version: '3.1',
          score: metric?.cvssData?.baseScore || 0,
          severity:
            (metric?.cvssData?.baseSeverity as any) || 'LOW',
          vector: metric?.cvssData?.vectorString || '',
        },
        cwe:
          cve.weaknesses?.[0]?.description?.map(
            (d: any) => d.value
          ) || [],
        references:
          cve.references?.map((ref: any) => ({
            url: ref.url,
            source: ref.source || 'NVD',
            tags: ref.tags || [],
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

/* ============================================================================
   UTILITIES
============================================================================ */

function extractCVEFromText(text: string): string | undefined {
  const match = text.match(/CVE-\d{4}-\d{4,}/i);
  return match ? match[0].toUpperCase() : undefined;
}

export function getSeverityColor(severity: string): string {
  switch (severity.toUpperCase()) {
    case 'CRITICAL':
      return 'text-red-500 border-red-500';
    case 'HIGH':
      return 'text-orange-500 border-orange-500';
    case 'MEDIUM':
      return 'text-yellow-500 border-yellow-500';
    case 'LOW':
      return 'text-blue-500 border-blue-500';
    default:
      return 'text-gray-500 border-gray-500';
  }
}
