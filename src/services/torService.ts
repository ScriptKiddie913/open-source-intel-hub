// ============================================================================
// torService.ts
// REAL Dark Web Intelligence — Fully Functional, No Mock Data
// ============================================================================

import { cacheAPIResponse, getCachedData } from '@/lib/database';

/* ============================================================================
   TYPES
============================================================================ */

export type RiskLevel = 'critical' | 'high' | 'medium' | 'low';

export interface OnionSite {
  url:  string;
  title: string;
  description: string;
  category: string;
  riskLevel: RiskLevel;
  lastSeen: string;
  status: 'online' | 'offline' | 'unknown';
  tags: string[];
  discoveredFrom: string;
}

export interface LeakSignal {
  id: string;
  title: string;
  indicator: string;
  source: 
    | 'pastebin'
    | 'ghostbin'
    | 'rentry'
    | 'github_gist'
    | 'psbdmp'
    | 'intelx';
  timestamp: string;
  url: string;
  context:  string;
}

/* ============================================================================
   CONSTANTS
============================================================================ */

const TOR2WEB_PROXIES = [
  'onion. ws',
  'onion.pet',
  'onion.ly',
];

const ONION_REGEX = /([a-z2-7]{16,56}\.onion)/gi;

/* ============================================================================
   UTILITIES
============================================================================ */

function stripHtml(input: string): string {
  const div = document.createElement('div');
  div.innerHTML = input;
  return div.textContent || div.innerText || '';
}

function nowISO(): string {
  return new Date().toISOString();
}

function unique<T>(arr: T[]): T[] {
  return Array.from(new Set(arr));
}

/* ============================================================================
   RISK & TAGGING
============================================================================ */

function calculateRisk(text:  string): RiskLevel {
  const t = text.toLowerCase();

  if (
    t.includes('malware') ||
    t.includes('exploit') ||
    t.includes('ransom') ||
    t.includes('weapon') ||
    t.includes('drug') ||
    t.includes('child')
  ) {
    return 'critical';
  }

  if (
    t.includes('leak') ||
    t.includes('dump') ||
    t.includes('database') ||
    t.includes('hack') ||
    t.includes('breach')
  ) {
    return 'high';
  }

  if (
    t.includes('market') ||
    t.includes('forum') ||
    t.includes('selling')
  ) {
    return 'medium';
  }

  return 'low';
}

function extractTags(text: string): string[] {
  const keywords = [
    'market',
    'forum',
    'leak',
    'dump',
    'database',
    'malware',
    'exploit',
    'credentials',
    'phishing',
    'carding',
    'fraud',
    'drugs',
    'weapons',
    'breach',
    'ransomware',
  ];

  const lower = text. toLowerCase();
  return keywords.filter(k => lower.includes(k)).slice(0, 6);
}

function categorize(text: string): string {
  const t = text.toLowerCase();

  if (t.includes('market')) return 'Marketplace';
  if (t.includes('forum')) return 'Forum';
  if (t.includes('leak') || t.includes('dump') || t.includes('breach')) return 'Data Leak';
  if (t.includes('mail')) return 'Email Service';
  if (t.includes('hosting')) return 'Hosting';
  if (t.includes('directory')) return 'Directory';
  if (t.includes('wiki')) return 'Wiki/Info';

  return 'Unknown';
}

/* ============================================================================
   ONION DISCOVERY - AHMIA. FI (Real Tor Search Engine)
============================================================================ */

export async function discoverOnionSites(query: string): Promise<OnionSite[]> {
  const cacheKey = `onion:discover:${query}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const results: OnionSite[] = [];

  try {
    // Method 1: Ahmia.fi API (Real Tor search engine)
    const ahmiaUrl = `https://ahmia.fi/search/? q=${encodeURIComponent(query)}`;
    
    const response = await fetch(ahmiaUrl, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
      },
    });

    if (!response.ok) {
      console.error('Ahmia fetch failed:', response.statusText);
      return [];
    }

    const html = await response.text();

    // Extract onion addresses
    const onions = unique((html.match(ONION_REGEX) || [])).slice(0, 50);

    // Extract titles (from <h4> tags in Ahmia results)
    const titleMatches = Array.from(html.matchAll(/<h4[^>]*><a[^>]*>([^<]+)<\/a><\/h4>/gi));
    const titles = titleMatches.map(m => stripHtml(m[1]));

    // Extract descriptions (from <p> after h4)
    const descMatches = Array.from(html. matchAll(/<p class="result-[^"]*">([^<]+)<\/p>/gi));
    const descriptions = descMatches.map(m => stripHtml(m[1]));

    onions.forEach((onion, idx) => {
      const title = titles[idx] || 'Unknown Onion Service';
      const description = descriptions[idx] || 'No description available';
      const context = `${title} ${description}`.trim();

      results.push({
        url: onion,
        title,
        description,
        category: categorize(context),
        riskLevel: calculateRisk(context),
        lastSeen: nowISO(),
        status: 'unknown',
        tags: extractTags(context),
        discoveredFrom: 'ahmia',
      });
    });

    await cacheAPIResponse(cacheKey, results, 60);
    return results;
  } catch (error) {
    console.error('Onion discovery error:', error);
    return [];
  }
}

/* ============================================================================
   ONION UPTIME CHECK (Tor2Web Gateway)
============================================================================ */

export async function checkOnionUptime(
  onion: string
): Promise<{
  status: 'online' | 'offline';
  responseTime?:  number;
  checkedAt:  string;
}> {
  try {
    const host = onion.replace(/^https?:\/\//, '').replace(/\/$/, '');
    const proxy = TOR2WEB_PROXIES[0];
    const url = `https://${host}.${proxy}`;

    const start = Date.now();
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 15000);

    const response = await fetch(url, {
      method: 'HEAD',
      signal: controller.signal,
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
      },
    });

    clearTimeout(timeout);

    return {
      status: response.ok ? 'online' : 'offline',
      responseTime: Date.now() - start,
      checkedAt: nowISO(),
    };
  } catch (error) {
    return {
      status: 'offline',
      checkedAt: nowISO(),
    };
  }
}

/* ============================================================================
   PASTE & LEAK SIGNAL MONITORING
============================================================================ */

// Pastebin Recent Pastes
async function scanPastebin(indicator: string): Promise<LeakSignal[]> {
  const cacheKey = `pastebin:${indicator}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const signals:  LeakSignal[] = [];

  try {
    const response = await fetch('https://pastebin.com/archive', {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
      },
    });

    if (!response. ok) return [];

    const html = await response.text();

    // Extract paste links and titles
    const pasteMatches = Array.from(
      html.matchAll(/<a href="\/([A-Za-z0-9]{8})"[^>]*>([^<]+)<\/a>/g)
    ).slice(0, 50);

    pasteMatches. forEach(([_, pasteId, title]) => {
      const cleanTitle = stripHtml(title);
      if (cleanTitle. toLowerCase().includes(indicator.toLowerCase())) {
        signals.push({
          id: `pb-${pasteId}`,
          title: cleanTitle,
          indicator,
          source: 'pastebin',
          timestamp: nowISO(),
          url: `https://pastebin.com/${pasteId}`,
          context: 'Paste title match',
        });
      }
    });

    await cacheAPIResponse(cacheKey, signals, 30);
    return signals;
  } catch (error) {
    console.error('Pastebin scan error:', error);
    return [];
  }
}

// Psbdmp - Pastebin dump search
async function scanPsbdmp(indicator: string): Promise<LeakSignal[]> {
  const cacheKey = `psbdmp:${indicator}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const signals: LeakSignal[] = [];

  try {
    const response = await fetch(`https://psbdmp.ws/api/search/${encodeURIComponent(indicator)}`, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
      },
    });

    if (!response.ok) return [];

    const data = await response.json();

    if (data.data && Array.isArray(data.data)) {
      data.data.slice(0, 20).forEach((paste:  any) => {
        signals.push({
          id: `psbdmp-${paste. id}`,
          title: paste.text || 'Pastebin dump',
          indicator,
          source: 'psbdmp',
          timestamp: paste.time || nowISO(),
          url: `https://pastebin.com/${paste.id}`,
          context: 'Dump search match',
        });
      });
    }

    await cacheAPIResponse(cacheKey, signals, 30);
    return signals;
  } catch (error) {
    console.error('Psbdmp scan error:', error);
    return [];
  }
}

// GitHub Gists
async function scanGitHubGists(indicator: string): Promise<LeakSignal[]> {
  const cacheKey = `gists:${indicator}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const signals: LeakSignal[] = [];

  try {
    // Using GitHub's public search API
    const response = await fetch(
      `https://api.github.com/search/code?q=${encodeURIComponent(indicator)}+in:file+language:text`,
      {
        headers: {
          'Accept': 'application/vnd. github.v3+json',
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
        },
      }
    );

    if (!response.ok) return [];

    const data = await response.json();

    if (data.items) {
      data.items.slice(0, 20).forEach((item: any) => {
        signals.push({
          id: `gist-${item.sha}`,
          title: item.name || 'GitHub code match',
          indicator,
          source: 'github_gist',
          timestamp: nowISO(),
          url: item.html_url,
          context: `Found in ${item.repository.full_name}`,
        });
      });
    }

    await cacheAPIResponse(cacheKey, signals, 30);
    return signals;
  } catch (error) {
    console.error('GitHub Gist scan error:', error);
    return [];
  }
}

// Rentry public notes
async function scanRentry(indicator: string): Promise<LeakSignal[]> {
  const cacheKey = `rentry:${indicator}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const signals:  LeakSignal[] = [];

  try {
    const response = await fetch(
      `https://rentry.co/api/search? q=${encodeURIComponent(indicator)}`,
      {
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
        },
      }
    );

    if (!response. ok) return [];

    const data = await response.json();

    if (data.results && Array.isArray(data.results)) {
      data.results. slice(0, 20).forEach((result: any) => {
        signals.push({
          id: `rentry-${result.id}`,
          title: result.title || 'Rentry note',
          indicator,
          source: 'rentry',
          timestamp: result.created_at || nowISO(),
          url: `https://rentry.co/${result.id}`,
          context: 'Public note match',
        });
      });
    }

    await cacheAPIResponse(cacheKey, signals, 30);
    return signals;
  } catch (error) {
    console.error('Rentry scan error:', error);
    return [];
  }
}

// Ghostbin
async function scanGhostbin(indicator: string): Promise<LeakSignal[]> {
  const cacheKey = `ghostbin:${indicator}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const signals: LeakSignal[] = [];

  try {
    const response = await fetch('https://ghostbin.com/browse', {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
      },
    });

    if (!response. ok) return [];

    const html = await response.text();

    const pasteMatches = Array.from(
      html.matchAll(/<a href="\/paste\/([A-Za-z0-9]+)"[^>]*>([^<]+)<\/a>/g)
    ).slice(0, 30);

    pasteMatches. forEach(([_, pasteId, title]) => {
      const cleanTitle = stripHtml(title);
      if (cleanTitle.toLowerCase().includes(indicator.toLowerCase())) {
        signals.push({
          id: `gb-${pasteId}`,
          title: cleanTitle,
          indicator,
          source: 'ghostbin',
          timestamp: nowISO(),
          url: `https://ghostbin.com/paste/${pasteId}`,
          context: 'Ghostbin title match',
        });
      }
    });

    await cacheAPIResponse(cacheKey, signals, 30);
    return signals;
  } catch (error) {
    console.error('Ghostbin scan error:', error);
    return [];
  }
}

/* ============================================================================
   AGGREGATOR - COMBINE ALL SOURCES
============================================================================ */

export async function searchDarkWebSignals(indicator: string): Promise<LeakSignal[]> {
  const cacheKey = `signals:${indicator}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const results = (
    await Promise.allSettled([
      scanPastebin(indicator),
      scanPsbdmp(indicator),
      scanGitHubGists(indicator),
      scanRentry(indicator),
      scanGhostbin(indicator),
    ])
  )
    .filter((result): result is PromiseFulfilledResult<LeakSignal[]> => result.status === 'fulfilled')
    .flatMap(result => result.value);

  await cacheAPIResponse(cacheKey, results, 30);
  return results;
}

/* ============================================================================
   ADDITIONAL:  DARKNET MARKET STATUS CHECKER
============================================================================ */

export async function checkDarknetMarketStatus(): Promise<Array<{
  name: string;
  url: string;
  status: 'online' | 'offline' | 'unknown';
  lastChecked: string;
}>> {
  // Using public Tor status checkers like dark. fail
  try {
    const response = await fetch('https://dark.fail/', {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
      },
    });

    if (!response.ok) return [];

    const html = await response.text();
    const markets:  Array<{ name: string; url: string; status: 'online' | 'offline' | 'unknown'; lastChecked: string }> = [];

    // Parse dark.fail HTML for market status
    const marketMatches = Array.from(
      html.matchAll(/<div class="market"[^>]*>.*?<h3>([^<]+)<\/h3>.*?<code>([^<]+)<\/code>.*?<span class="status ([^"]+)">/gs)
    );

    marketMatches.forEach(([_, name, url, status]) => {
      markets.push({
        name: stripHtml(name),
        url: stripHtml(url),
        status:  status. includes('online') ? 'online' : 'offline',
        lastChecked: nowISO(),
      });
    });

    return markets;
  } catch (error) {
    console.error('Market status check error:', error);
    return [];
  }
}
