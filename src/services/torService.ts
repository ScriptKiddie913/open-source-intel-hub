// ============================================================================
// torService.ts
// VERCEL-SAFE DARK WEB / LEAK INTELLIGENCE
// Sources:
// 1. PSBDMP
// 2. Rentry
// 3. GitHub Code Search
// 4. paste.rs
// 5. dpaste.org
// 6. dark.fail
// ============================================================================

import { cacheAPIResponse, getCachedData } from '@/lib/database';

/* ============================================================================
   TYPES
============================================================================ */

export type RiskLevel = 'critical' | 'high' | 'medium' | 'low';

export interface LeakSignal {
  id: string;
  title: string;
  indicator: string;
  source:
    | 'psbdmp'
    | 'rentry'
    | 'github'
    | 'paste_rs'
    | 'dpaste'
    | 'darkfail';
  timestamp: string;
  url: string;
  context: string;
}

export interface DarkWebMarket {
  name: string;
  url: string;
  status: 'online' | 'offline' | 'unknown';
  lastChecked: string;
}

/* ============================================================================
   CONSTANTS
============================================================================ */

const TIMEOUTS = {
  FAST: 5000,
  NORMAL: 8000,
};

const USER_AGENT =
  'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36';

/* ============================================================================
   UTILS
============================================================================ */

function nowISO(): string {
  return new Date().toISOString();
}

function stripHtml(input: string): string {
  return input.replace(/<[^>]*>/g, '').trim();
}

async function fetchWithTimeout(
  url: string,
  timeout = 8000
): Promise<Response> {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeout);
  try {
    return await fetch(url, {
      signal: controller.signal,
      headers: { 'User-Agent': USER_AGENT },
    });
  } finally {
    clearTimeout(id);
  }
}

/* ============================================================================
   SOURCE 1 — PSBDMP (JSON, SAFE)
============================================================================ */

async function scanPsbdmp(indicator: string): Promise<LeakSignal[]> {
  try {
    const res = await fetchWithTimeout(
      `https://psbdmp.ws/api/search/${encodeURIComponent(indicator)}`,
      TIMEOUTS.NORMAL
    );
    if (!res.ok) return [];

    const data = await res.json();
    if (!Array.isArray(data?.data)) return [];

    return data.data.slice(0, 15).map((p: any) => ({
      id: `psbdmp-${p.id}`,
      title: 'Credential dump detected',
      indicator,
      source: 'psbdmp',
      timestamp: p.time || nowISO(),
      url: `https://pastebin.com/${p.id}`,
      context: 'Indexed credential dump (psbdmp)',
    }));
  } catch {
    return [];
  }
}

/* ============================================================================
   SOURCE 2 — RENTRY (JSON, SAFE)
============================================================================ */

async function scanRentry(indicator: string): Promise<LeakSignal[]> {
  try {
    const res = await fetchWithTimeout(
      `https://rentry.co/api/search?q=${encodeURIComponent(indicator)}`,
      TIMEOUTS.NORMAL
    );
    if (!res.ok) return [];

    const data = await res.json();
    if (!Array.isArray(data?.results)) return [];

    return data.results.slice(0, 15).map((r: any) => ({
      id: `rentry-${r.id}`,
      title: r.title || 'Rentry note',
      indicator,
      source: 'rentry',
      timestamp: r.created_at || nowISO(),
      url: `https://rentry.co/${r.id}`,
      context: 'Public Rentry note',
    }));
  } catch {
    return [];
  }
}

/* ============================================================================
   SOURCE 3 — GITHUB CODE SEARCH (SAFE)
============================================================================ */

async function scanGitHub(indicator: string): Promise<LeakSignal[]> {
  try {
    const res = await fetchWithTimeout(
      `https://api.github.com/search/code?q=${encodeURIComponent(
        indicator
      )}+in:file`,
      TIMEOUTS.NORMAL
    );
    if (!res.ok) return [];

    const data = await res.json();
    if (!Array.isArray(data?.items)) return [];

    return data.items.slice(0, 10).map((i: any) => ({
      id: `github-${i.sha}`,
      title: i.name,
      indicator,
      source: 'github',
      timestamp: nowISO(),
      url: i.html_url,
      context: `GitHub repository: ${i.repository?.full_name}`,
    }));
  } catch {
    return [];
  }
}

/* ============================================================================
   SOURCE 4 — paste.rs (HTML, SAFE)
============================================================================ */

async function scanPasteRs(indicator: string): Promise<LeakSignal[]> {
  try {
    const res = await fetchWithTimeout(
      'https://paste.rs/',
      TIMEOUTS.FAST
    );
    if (!res.ok) return [];

    const html = await res.text();
    if (!html.toLowerCase().includes(indicator.toLowerCase())) return [];

    return [
      {
        id: `paste_rs-${indicator}`,
        title: 'Possible paste.rs match',
        indicator,
        source: 'paste_rs',
        timestamp: nowISO(),
        url: 'https://paste.rs/',
        context: 'Public paste.rs content match',
      },
    ];
  } catch {
    return [];
  }
}

/* ============================================================================
   SOURCE 5 — dpaste.org (HTML, SAFE)
============================================================================ */

async function scanDPaste(indicator: string): Promise<LeakSignal[]> {
  try {
    const res = await fetchWithTimeout(
      'https://dpaste.org/',
      TIMEOUTS.FAST
    );
    if (!res.ok) return [];

    const html = await res.text();
    if (!html.toLowerCase().includes(indicator.toLowerCase())) return [];

    return [
      {
        id: `dpaste-${indicator}`,
        title: 'Possible dpaste match',
        indicator,
        source: 'dpaste',
        timestamp: nowISO(),
        url: 'https://dpaste.org/',
        context: 'Public dpaste content match',
      },
    ];
  } catch {
    return [];
  }
}

/* ============================================================================
   SOURCE 6 — dark.fail (HTML, SAFE)
============================================================================ */

export async function checkDarknetMarketStatus(): Promise<DarkWebMarket[]> {
  const cacheKey = 'darkfail:markets';
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  try {
    const res = await fetchWithTimeout(
      'https://dark.fail/',
      TIMEOUTS.NORMAL
    );
    if (!res.ok) return [];

    const html = await res.text();
    const markets: DarkWebMarket[] = [];

    Array.from(
      html.matchAll(
        /<h3>([^<]+)<\/h3>[\s\S]*?<code>([^<]+)<\/code>[\s\S]*?<span class="status ([^"]+)"/g
      )
    ).forEach(m => {
      markets.push({
        name: stripHtml(m[1]),
        url: stripHtml(m[2]),
        status: m[3].includes('online') ? 'online' : 'offline',
        lastChecked: nowISO(),
      });
    });

    await cacheAPIResponse(cacheKey, markets, 300);
    return markets;
  } catch {
    return [];
  }
}

/* ============================================================================
   AGGREGATOR — THIS IS WHAT YOUR UI USES
============================================================================ */

export async function searchDarkWebSignals(
  indicator: string
): Promise<LeakSignal[]> {
  const cacheKey = `signals:${indicator}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const results = (
    await Promise.allSettled([
      scanPsbdmp(indicator),
      scanRentry(indicator),
      scanGitHub(indicator),
      scanPasteRs(indicator),
      scanDPaste(indicator),
    ])
  )
    .filter(
      (r): r is PromiseFulfilledResult<LeakSignal[]> =>
        r.status === 'fulfilled'
    )
    .flatMap(r => r.value);

  await cacheAPIResponse(cacheKey, results, 120);
  return results;
}
